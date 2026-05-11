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
        return True, 0
    return False, 0


def log_attempt(ip, username, success):
    attempt = LoginAttempt(ip_address=ip, username=username, success=success)
    db.session.add(attempt)

    if not success:
        # Check user and update ban
        user = User.query.filter_by(username=username).first()
        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= 5:
                user.ban_until = datetime.utcnow() + timedelta(minutes=15)
                # Create security alert
                alert = SecurityAlert(
                    alert_type="brute_force",
                    source_ip=ip,
                    description=f"Multiple failed login attempts from {ip} — {user.failed_attempts} attempts",
                    severity="high",
                )
                db.session.add(alert)
                # Send notification
                from app.notifications import send_alert

                send_alert(
                    subject="BRUTE FORCE ATTACK",
                    body=f"Multiple failed login attempts!\nIP: {ip}\nUsername: {username}\nAttempts: {user.failed_attempts}",
                )
        else:
            # Unknown username — check by IP
            recent_fails = LoginAttempt.query.filter(
                LoginAttempt.ip_address == ip,
                LoginAttempt.success == False,
                LoginAttempt.timestamp > datetime.utcnow() - timedelta(minutes=15),
            ).count()

            if recent_fails >= 3:
                alert = SecurityAlert(
                    alert_type="brute_force",
                    source_ip=ip,
                    description=f"Multiple failed login attempts from {ip} — {recent_fails} attempts in last 15 minutes",
                    severity="high",
                )
                db.session.add(alert)

    db.session.commit()


@auth.route("/", methods=["GET", "POST"])
@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    ip = get_client_ip()

    # Check permanent IP block
    blocked, _ = is_ip_blocked(ip)
    if blocked:
        flash(f"BLOCKED:900", "danger")
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

        # Check if user is banned
        if user and user.is_banned():
            secs = user.get_ban_seconds()
            flash(f"BLOCKED:{secs}", "danger")
            return render_template("login.html")

        if user and user.check_password(password):
            # Reset failed attempts on success
            user.failed_attempts = 0
            user.ban_until = None
            db.session.commit()
            login_user(user)
            session.permanent = True
            log_attempt(ip, username, True)
            return redirect(url_for("main.dashboard"))
        else:
            log_attempt(ip, username, False)

            # Check ban status again after logging
            if user and user.is_banned():
                secs = user.get_ban_seconds()
                flash(f"BLOCKED:{secs}", "danger")
            else:
                remaining = max(0, 5 - (user.failed_attempts if user else 0))
                if remaining > 0:
                    flash(
                        f"Invalid credentials. {remaining} attempts remaining.",
                        "danger",
                    )
                else:
                    flash(f"BLOCKED:900", "danger")

    return render_template("login.html")


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
