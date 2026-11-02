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
import redis
import os

auth = Blueprint("auth", __name__)


# ─── Redis client for atomic brute force counting ─────────────────────────────
# Uses the same REDIS_URL utilized by Flask-Limiter.
# Connection caching in global variables is avoided — redis.from_url()
# uses a built-in connection pool internally, making it safe for
# multi-worker (gunicorn) environments with automatic reconnection on crashes.
def get_redis():
    redis_url = os.environ.get("REDIS_URL", "")
    if not redis_url:
        return None
    try:
        return redis.from_url(redis_url, decode_responses=True)
    except Exception:
        return None


# ─── IP Helper ────────────────────────────────────────────────────────────────
# FIXED: Consistent usage of request.remote_addr across all routes.
# The ProxyFix middleware in __init__.py handles unwrapping X-Forwarded-For
# so request.remote_addr remains accurate even behind the Railway proxy.
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


# ─── Brute Force Counting ─────────────────────────────────────────────────────
# FIXED: Uses Redis INCR (atomic) for fail counting.
# If Redis is unavailable, it falls back to DB-based counting
# (safer than nothing, though Redis is preferred).

MAX_ATTEMPTS = 5
BLOCK_WINDOW_SECONDS = 15 * 60  # 15 minutes


def _redis_increment_fail(ip):
    """
    Atomically increments the fail counter for an IP in Redis.
    Returns the new count, or None if Redis is unavailable.
    """
    r = get_redis()
    if r is None:
        return None
    try:
        key = f"login_fail:{ip}"
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, BLOCK_WINDOW_SECONDS)
        results = pipe.execute()
        return results[0]  # new count after increment
    except Exception:
        return None


def _redis_reset_fails(ip):
    """Clears the fail counter on successful login."""
    r = get_redis()
    if r is None:
        return
    try:
        r.delete(f"login_fail:{ip}")
    except Exception:
        pass


def _db_count_recent_fails(ip):
    """Fallback: count recent fails from DB (non-atomic, but acts as a reliable fallback)."""
    block_time = datetime.utcnow() - timedelta(minutes=15)
    return LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip,
        LoginAttempt.success == False,
        LoginAttempt.timestamp > block_time,
    ).count()


def log_attempt(ip, username, success):
    attempt = LoginAttempt(
        ip_address=ip,
        username=username,
        success=success,
    )
    db.session.add(attempt)

    if not success:
        # FIXED: Try Redis first (atomic). If unavailable, fall back to DB.
        fail_count = _redis_increment_fail(ip)
        if fail_count is None:
            # No Redis — use DB fallback (non-atomic)
            db.session.commit()  # commit attempt first before counting
            fail_count = _db_count_recent_fails(ip)
        else:
            db.session.commit()

        if fail_count >= MAX_ATTEMPTS:
            existing_block = TempBlockedIP.query.filter_by(ip_address=ip).first()
            if not existing_block:
                blocked = TempBlockedIP(
                    ip_address=ip,
                    blocked_until=datetime.utcnow() + timedelta(minutes=15),
                )
                db.session.add(blocked)
            else:
                existing_block.blocked_until = max(
                    existing_block.blocked_until,
                    datetime.utcnow() + timedelta(minutes=15),
                )

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
                body=f"Multiple failed login attempts\nIP: {ip}\nUsername: {username}",
            )
    else:
        # Successful login — reset the fail counter
        _redis_reset_fails(ip)
        db.session.commit()


@auth.route("/", methods=["GET", "POST"])
@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per minute")
@limiter.limit("50 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    ip = get_client_ip()

    if is_ip_blocked(ip):
        flash("Access denied. Contact administrator.", "danger")
        return render_template("login.html")

    if request.method == "POST":
        if is_ip_temp_banned(ip):
            flash(
                "Too many failed attempts. Please wait before trying again.", "danger"
            )
            return redirect(url_for("auth.login"))

        username = bleach.clean(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("auth.login"))

        if len(username) > 80 or len(password) > 200:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("auth.login"))

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            session.permanent = False
            log_attempt(ip, username, True)

            from app.notifications import send_login_alert
            from flask import current_app

            send_login_alert(current_app._get_current_object(), username, ip)

            return redirect(url_for("main.dashboard"))
        else:
            log_attempt(ip, username, False)

            if is_ip_temp_banned(ip):
                flash(
                    "Too many failed attempts. Please wait before trying again.",
                    "danger",
                )
                return redirect(url_for("auth.login"))
            else:
                # FIXED: Omit remaining attempts count to prevent attackers
                # from enumerating rate-limiting states
                flash("Invalid credentials.", "danger")
                return redirect(url_for("auth.login"))

    if is_ip_temp_banned(ip):
        remaining_seconds = get_ip_ban_seconds(ip)
        return render_template("login.html", ban_seconds=remaining_seconds)

    return render_template("login.html")


@auth.route("/logout")
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for("auth.login"))