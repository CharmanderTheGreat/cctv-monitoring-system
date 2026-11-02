from flask import Blueprint, request, render_template
from app.models import HoneypotLog, SecurityAlert
from app import db
from app.notifications import send_alert

network_core = Blueprint("network_core", __name__)


@network_core.route("/network_core")
@network_core.route("/network_core/config")
@network_core.route("/network_core/admin")
@network_core.route("/network_core/users")
@network_core.route("/network_core/database")
@network_core.route("/network_core/backup")
@network_core.route("/admin")
@network_core.route("/wp-admin")
@network_core.route("/phpmyadmin")
@network_core.route("/shell")
@network_core.route("/console")
def trap():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    path = request.path
    method = request.method
    user_agent = request.headers.get("User-Agent", "Unknown")

    log = HoneypotLog(ip_address=ip, path=path, method=method, user_agent=user_agent)
    db.session.add(log)

    alert = SecurityAlert(
        alert_type="network_core_triggered",
        source_ip=ip,
        description=f"Unauthorized access attempt to restricted path: {path} [{method}] from {ip}",
        severity="high",
    )
    db.session.add(alert)
    db.session.commit()

    # Send notification
    send_alert(
        subject="HONEYPOT TRIGGERED",
        body=f"Unauthorized access to {path}\nIP: {ip}\nMethod: {method}",
    )

    return render_template("404.html"), 404
