from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from app.models import (
    User,
    LoginAttempt,
    SecurityAlert,
    BlockedIP,
    TempBlockedIP,
)
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
    blocked = TempBlockedIP.query.filter_by(ip_address=ip).first()

    if not blocked:
        return 0

    seconds = int((blocked.blocked_until - datetime.utcnow()).total_seconds())

    return max(0, seconds)


def is_ip_temp_banned(ip):
    blocked = TempBlockedIP.query.filter_by(ip_address=ip).first()

    if not blocked:
        return False

    # expired
    if blocked.blocked_until < datetime.utcnow():
        db.session.delete(blocked)
        db.session.commit()
        return False

    return True


def log_attempt(ip, username, success):
    attempt = LoginAttempt(
        ip_address=ip,
        username=username,
        success=success,
    )
    db.session.add(attempt)

    if not success:
        block_time = datetime.utcnow() - timedelta(minutes=15)
        recent_fails = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip,
            LoginAttempt.success == False,
            LoginAttempt.timestamp > block_time,
        ).count()

        if recent_fails >= 5:
            existing_block = TempBlockedIP.query.filter_by(ip_address=ip).first()
            if not existing_block:
                blocked = TempBlockedIP(
                    ip_address=ip,
                    blocked_until=datetime.utcnow() + timedelta(minutes=15),
                )
                db.session.add(blocked)

            alert = SecurityAlert(
                alert_type="brute_force",
                source_ip=ip,
                description=f"Brute force attack from {ip}",
                severity="high",
            )
            db.session.add(alert)
            db.session.commit()

            from app.notifications import send_alert
            send_alert(
                subject="BRUTE FORCE ATTACK",
                body=(
                    f"Multiple failed login attempts\n"
                    f"IP: {ip}\nUsername: {username}"
                ),
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
