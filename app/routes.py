from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from app.notifications import send_alert
from app.models import (
    Camera,
    NetworkLog,
    SecurityAlert,
    AuditLog,
    HoneypotLog,
    LoginAttempt,
    BlockedIP,
)
from app import db, limiter
from datetime import datetime
import random
import bleach

main = Blueprint("main", __name__)


def log_action(action):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    audit = AuditLog(user=current_user.username, action=action, ip_address=ip)
    db.session.add(audit)
    db.session.commit()


@main.route("/dashboard")
@login_required
def dashboard():
    cameras = Camera.query.all()
    alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).all()
    logs = NetworkLog.query.order_by(NetworkLog.timestamp.desc()).all()
    unresolved_count = SecurityAlert.query.filter_by(is_resolved=False).count()
    log_action("Viewed dashboard")
    return render_template(
        "dashboard.html",
        cameras=cameras,
        alerts=alerts,
        logs=logs,
        unresolved_count=unresolved_count,
    )


@main.route("/audit")
@login_required
def audit():
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    honeypot_logs = HoneypotLog.query.order_by(HoneypotLog.timestamp.desc()).all()
    login_attempts = (
        LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(50).all()
    )
    return render_template(
        "audit.html",
        audit_logs=audit_logs,
        honeypot_logs=honeypot_logs,
        login_attempts=login_attempts,
    )


@main.route("/api/cameras")
@login_required
@limiter.limit("30 per minute")
def get_cameras():
    cameras = Camera.query.all()
    return jsonify(
        [
            {
                "id": c.id,
                "name": c.name,
                "ip_address": c.ip_address,
                "rtsp_url": c.rtsp_url,
                "location": c.location,
                "status": c.status,
            }
            for c in cameras
        ]
    )


@main.route("/api/cameras/add", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def add_camera():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    name = bleach.clean(data.get("name", ""))
    ip_address = bleach.clean(data.get("ip_address", ""))
    location = bleach.clean(data.get("location", ""))

    if not name or not ip_address or not location:
        return jsonify({"success": False, "error": "Missing fields"}), 400

    if len(name) > 100 or len(ip_address) > 50 or len(location) > 100:
        return jsonify({"success": False, "error": "Input too long"}), 400

    camera = Camera(
        name=name,
        ip_address=ip_address,
        rtsp_url=f"rtsp://{ip_address}:554/stream",
        location=location,
        status="active",
    )
    db.session.add(camera)
    db.session.commit()
    log_action(f"Added camera: {name} ({ip_address})")
    return jsonify({"success": True, "id": camera.id})


@main.route("/api/cameras/delete/<int:camera_id>", methods=["DELETE"])
@login_required
@limiter.limit("10 per minute")
def delete_camera(camera_id):
    camera = Camera.query.get_or_404(camera_id)
    log_action(f"Deleted camera: {camera.name} ({camera.ip_address})")
    db.session.delete(camera)
    db.session.commit()
    return jsonify({"success": True})


@main.route("/api/network/scan")
@login_required
@limiter.limit("10 per minute")
def scan_network():
    NetworkLog.query.delete()
    base_devices = [
        {
            "ip": "192.168.1.1",
            "mac": "AA:BB:CC:DD:EE:01",
            "hostname": "Router",
            "status": "active",
        },
        {
            "ip": "192.168.1.2",
            "mac": "AA:BB:CC:DD:EE:02",
            "hostname": "Switch",
            "status": "active",
        },
        {
            "ip": "192.168.1.10",
            "mac": "AA:BB:CC:DD:EE:10",
            "hostname": "PC-Admin",
            "status": "active",
        },
    ]

    cameras = Camera.query.all()
    for cam in cameras:
        base_devices.append(
            {
                "ip": cam.ip_address,
                "mac": "CC:TV:"
                + ":".join(["{:02x}".format(cam.id * i % 256) for i in range(1, 5)]),
                "hostname": cam.name,
                "status": cam.status,
            }
        )

    for device in base_devices:
        log = NetworkLog(
            ip_address=device["ip"],
            mac_address=device["mac"],
            hostname=device["hostname"],
            status=device["status"],
        )
        db.session.add(log)
    db.session.commit()
    log_action("Scanned network")
    return jsonify(base_devices)


@main.route("/api/alerts")
@login_required
@limiter.limit("30 per minute")
def get_alerts():
    alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).all()
    return jsonify(
        [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "source_ip": a.source_ip,
                "description": a.description,
                "severity": a.severity,
                "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "is_resolved": a.is_resolved,
            }
            for a in alerts
        ]
    )


@main.route("/api/alerts/simulate")
@login_required
@limiter.limit("20 per minute")
def simulate_alert():
    attack_types = [
        {
            "type": "port_scan",
            "desc": "Port scan detected from external IP",
            "severity": "high",
        },
        {
            "type": "brute_force",
            "desc": "Multiple failed login attempts detected",
            "severity": "high",
        },
        {
            "type": "suspicious_ip",
            "desc": "Connection from suspicious IP address",
            "severity": "medium",
        },
    ]
    attack = random.choice(attack_types)
    source_ip = f"192.168.1.{random.randint(100, 254)}"
    alert = SecurityAlert(
        alert_type=attack["type"],
        source_ip=source_ip,
        description=attack["desc"],
        severity=attack["severity"],
    )
    db.session.add(alert)
    db.session.commit()
    log_action(f"Simulated attack: {attack['type']}")

    # Send notification
    send_alert(
        subject=attack["type"].upper().replace("_", " "),
        body=f"{attack['desc']}\nSource IP: {source_ip}\nSeverity: {attack['severity'].upper()}",
    )

    return jsonify({"success": True, "alert": attack["type"]})


@main.route("/api/alerts/resolve/<int:alert_id>", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def resolve_alert(alert_id):
    alert = SecurityAlert.query.get_or_404(alert_id)
    alert.is_resolved = True
    db.session.commit()
    log_action(
        f"Resolved alert ID {alert_id}: {alert.alert_type} from {alert.source_ip}"
    )
    return jsonify({"success": True})


@main.route("/api/logs")
@login_required
@limiter.limit("30 per minute")
def get_logs():
    logs = NetworkLog.query.order_by(NetworkLog.timestamp.desc()).all()
    return jsonify(
        [
            {
                "id": l.id,
                "ip_address": l.ip_address,
                "mac_address": l.mac_address,
                "hostname": l.hostname,
                "status": l.status,
                "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for l in logs
        ]
    )


@main.route("/api/block-ip", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def block_ip():
    data = request.get_json()
    ip = bleach.clean(data.get("ip", ""))
    reason = bleach.clean(data.get("reason", "Manually blocked by admin"))

    if not ip:
        return jsonify({"success": False, "error": "No IP provided"}), 400

    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing:
        return jsonify({"success": False, "error": "IP already blocked"}), 400

    blocked = BlockedIP(ip_address=ip, reason=reason, blocked_by=current_user.username)
    db.session.add(blocked)
    db.session.commit()
    log_action(f"Blocked IP: {ip} — Reason: {reason}")
    return jsonify({"success": True})


@main.route("/api/unblock-ip", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def unblock_ip():
    data = request.get_json()
    ip = bleach.clean(data.get("ip", ""))

    blocked = BlockedIP.query.filter_by(ip_address=ip).first()
    if not blocked:
        return jsonify({"success": False, "error": "IP not found"}), 404

    db.session.delete(blocked)
    db.session.commit()
    log_action(f"Unblocked IP: {ip}")
    return jsonify({"success": True})


@main.route("/api/blocked-ips")
@login_required
def get_blocked_ips():
    blocked = BlockedIP.query.order_by(BlockedIP.timestamp.desc()).all()
    return jsonify(
        [
            {
                "id": b.id,
                "ip_address": b.ip_address,
                "reason": b.reason,
                "blocked_by": b.blocked_by,
                "timestamp": b.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for b in blocked
        ]
    )
