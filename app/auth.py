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


# ─── Redis client (para sa atomic brute force counting) ───────────────────────
# Ginagamit ang parehong REDIS_URL na ginagamit ng Flask-Limiter.
# Hindi na nag-cache ng connection sa global variable — redis.from_url()
# ay gumagamit ng built-in connection pool internally, kaya safe ito
# sa multi-worker (gunicorn) environments at mag-rereconnect kung mag-crash.
def get_redis():
    redis_url = os.environ.get("REDIS_URL", "")
    if not redis_url:
        return None
    try:
        return redis.from_url(redis_url, decode_responses=True)
    except Exception:
        return None


# ─── IP Helper ────────────────────────────────────────────────────────────────
# FIXED: Consistent na lang ang paggamit ng request.remote_addr sa lahat ng lugar.
# Ang ProxyFix middleware sa __init__.py ang bahala sa pag-unwrap ng X-Forwarded-For
# para maging tama ang request.remote_addr kahit nasa likod ng Railway proxy.
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
# FIXED: Gumagamit ng Redis INCR (atomic) para sa fail counting.
# Kung walang Redis, nag-fa-fallback sa dating DB-based counting
# (mas ligtas pa rin kaysa wala, pero mas mainam ang Redis).

MAX_ATTEMPTS = 5
BLOCK_WINDOW_SECONDS = 15 * 60  # 15 minuto


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
        return results[0]  # bagong count pagkatapos ng increment
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
    """Fallback: count recent fails from DB (non-atomic, pero may fallback pa rin)."""
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
        # FIXED: Subukan muna ang Redis (atomic). Kung wala, fallback sa DB.
        fail_count = _redis_increment_fail(ip)
        if fail_count is None:
            # Walang Redis — gamitin ang DB (hindi atomic pero may fallback)
            db.session.commit()  # i-save muna ang attempt bago mag-count
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
        # Successful login — i-reset ang fail counter
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
                # FIXED: Hindi na isinasama ang remaining attempts para
                # hindi ma-enumerate ng attacker ang state ng rate limiting
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
