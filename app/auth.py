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
    return request.remote_addr


def is_ip_blocked(ip):
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
                    f"Multiple failed login attempts\nIP: {ip}\nUsername: {username}"
                ),
            )
        else:
            db.session.commit()
    else:
        db.session.commit()


@auth.route("/", methods=["GET"])
@auth.route("/login", methods=["GET"])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    ip = get_client_ip()

    if is_ip_blocked(ip):
        flash("Access denied. Contact administrator.", "danger")
        return render_template("login.html")

    if is_ip_temp_banned(ip):
        blocked = TempBlockedIP.query.filter_by(ip_address=ip).first()
        if blocked:
            remaining_seconds = int(
                (blocked.blocked_until - datetime.utcnow()).total_seconds()
            )
            remaining_seconds = max(0, remaining_seconds)
        else:
            remaining_seconds = 0

        session.pop("_flashes", None)
        flash("Too many failed attempts. Access blocked.", "danger")
        return render_template("login.html", ban_seconds=remaining_seconds)

    return render_template("login.html")


@auth.route("/login", methods=["POST"])
@limiter.limit(
    "5 per minute"
)  # 5 attempts per minute - protection sa automated attacks
def login_submit():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    ip = get_client_ip()

    if is_ip_blocked(ip):
        flash("Access denied. Contact administrator.", "danger")
        return redirect(url_for("auth.login_page"))

    if is_ip_temp_banned(ip):
        secs = get_ip_ban_seconds(ip)
        flash(f"Too many failed attempts. Try again in {secs} seconds.", "danger")
        return redirect(url_for("auth.login_page"))

    username = bleach.clean(request.form.get("username", ""))
    password = request.form.get("password", "")

    if not username or not password:
        flash("Invalid credentials.", "danger")
        return redirect(url_for("auth.login_page"))

    if len(username) > 80 or len(password) > 200:
        flash("Invalid credentials.", "danger")
        return redirect(url_for("auth.login_page"))

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        login_user(user)
        session.permanent = True
        log_attempt(ip, username, True)
        return redirect(url_for("main.dashboard"))
    else:
        log_attempt(ip, username, False)

        if is_ip_temp_banned(ip):
            secs = get_ip_ban_seconds(ip)
            flash(f"Too many failed attempts. Try again in {secs} seconds.", "danger")
        else:
            block_time = datetime.utcnow() - timedelta(minutes=15)
            fail_count = LoginAttempt.query.filter(
                LoginAttempt.ip_address == ip,
                LoginAttempt.success == False,
                LoginAttempt.timestamp > block_time,
            ).count()
            remaining = max(0, 5 - fail_count)
            flash(f"Invalid credentials. {remaining} attempts remaining.", "danger")

        return redirect(url_for("auth.login_page"))


@auth.route("/logout")
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for("auth.login_page"))
