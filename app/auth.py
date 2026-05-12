from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User, LoginAttempt, SecurityAlert, BlockedIP
from app import db, limiter
from datetime import datetime, timedelta
import bleach

auth = Blueprint("auth", __name__)


def get_client_ip():
    return (
        request.headers.get("X-Forwarded-For", request.remote_addr)
        .split(",")[0]
        .strip()
    )


def is_ip_blocked(ip):
    # Check permanent block
    if BlockedIP.query.filter_by(ip_address=ip).first():
        return True
    return False


def get_ip_ban_seconds(ip):
    block_time = datetime.utcnow() - timedelta(minutes=15)
    first_fail = (
        LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip,
            LoginAttempt.success == False,
            LoginAttempt.timestamp > block_time,
        )
        .order_by(LoginAttempt.timestamp.asc())
        .first()
    )
    if first_fail:
        unblock_at = first_fail.timestamp + timedelta(minutes=15)
        secs = max(0, int((unblock_at - datetime.utcnow()).total_seconds()))
        return secs
    return 900


def is_ip_temp_banned(ip):
    block_time = datetime.utcnow() - timedelta(minutes=15)
    fail_count = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip,
        LoginAttempt.success == False,
        LoginAttempt.timestamp > block_time,
    ).count()
    return fail_count >= 5


def log_attempt(ip, username, success):
    attempt = LoginAttempt(ip_address=ip, username=username, success=success)
    db.session.add(attempt)

    if not success:
        block_time = datetime.utcnow() - timedelta(minutes=15)
        recent_fails = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip,
            LoginAttempt.success == False,
            LoginAttempt.timestamp > block_time,
        ).count()

        if recent_fails >= 5:
            alert = SecurityAlert(
                alert_type="brute_force",
                source_ip=ip,
                description=f"Brute force attack from {ip} — {recent_fails} failed attempts in 15 minutes",
                severity="high",
            )
            db.session.add(alert)
            db.session.commit()

            from app.notifications import send_alert

            send_alert(
                subject="BRUTE FORCE ATTACK",
                body=f"Multiple failed login attempts!\nIP: {ip}\nUsername tried: {username}\nAttempts: {recent_fails}",
            )
        else:
            db.session.commit()
    else:
        db.session.commit()


@auth.route("/", methods=["GET", "POST"])
@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    ip = get_client_ip()

    # Check permanent IP block
    if is_ip_blocked(ip):
        flash("BLOCKED:900", "danger")
        return render_template("login.html")

    # Check temporary IP ban
    if is_ip_temp_banned(ip):
        secs = get_ip_ban_seconds(ip)
        flash(f"BLOCKED:{secs}", "danger")
        return render_template("login.html")

    if request.method == "POST":
        username = bleach.clean(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please fill in all fields.", "danger")
            return render_template("login.html")

        if len(username) > 80 or len(password) > 200:
            flash("Invalid input.", "danger")
            return render_template("login.html")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            session.permanent = True
            log_attempt(ip, username, True)
            return redirect(url_for("main.dashboard"))
        else:
            log_attempt(ip, username, False)

            # Check ban status after logging
            if is_ip_temp_banned(ip):
                secs = get_ip_ban_seconds(ip)
                flash(f"BLOCKED:{secs}", "danger")
            else:
                block_time = datetime.utcnow() - timedelta(minutes=15)
                fail_count = LoginAttempt.query.filter(
                    LoginAttempt.ip_address == ip,
                    LoginAttempt.success == False,
                    LoginAttempt.timestamp > block_time,
                ).count()
                remaining = max(0, 5 - fail_count)
                flash(f"Invalid credentials. {remaining} attempts remaining.", "danger")

    return render_template("login.html")


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
