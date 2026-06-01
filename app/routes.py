# routes.py
from flask import (
    Blueprint,
    render_template,
    jsonify,
    request,
    Response,
    stream_with_context,
    abort,
)
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
from app import db, limiter, csrf
from datetime import datetime, timedelta
from pytz import timezone
from urllib.parse import urlparse
from functools import wraps
import bleach
import ipaddress
import hmac
import os
import cv2

# ============================================================
# HTTP MJPEG stream — uncomment this if using HTTP mode
import requests
# ============================================================

PH_TZ = timezone("Asia/Manila")
AGENT_KEY = os.environ.get("AGENT_KEY", "")


# ─── Role-Based Access Decorator ─────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


def validate_ip_address(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_rtsp_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme == "rtsp" and bool(parsed.netloc)
    except Exception:
        return False


def validate_http_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def cleanup_old_records():
    cutoff = datetime.utcnow() - timedelta(days=100)
    LoginAttempt.query.filter(LoginAttempt.timestamp < cutoff).delete()
    AuditLog.query.filter(AuditLog.timestamp < cutoff).delete()
    HoneypotLog.query.filter(HoneypotLog.timestamp < cutoff).delete()
    SecurityAlert.query.filter(SecurityAlert.timestamp < cutoff).delete()
    db.session.commit()


main = Blueprint("main", __name__)


def log_action(action):
    ip = request.remote_addr
    audit = AuditLog(user=current_user.username, action=action, ip_address=ip)
    db.session.add(audit)
    db.session.commit()


def convert_to_ph_time(dt):
    if dt is None:
        return None
    return dt.astimezone(PH_TZ)


# ─── Camera Streaming ─────────────────────────────────────────────────────────


# ============================================================
# MODE 1: RTSP streaming via OpenCV (default)
# Use this if your camera has a public RTSP URL
# e.g. rtsp://admin:pass@publicIP:554/stream
# ============================================================
"""
def generate_frames(source):
    cap = cv2.VideoCapture(source)
    if not cap.isOpened():
        return
    try:
        while True:
            success, frame = cap.read()
            if not success:
                break
            ret, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
            if not ret:
                break
            frame_bytes = buffer.tobytes()
            yield (
                b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + frame_bytes + b"\r\n"
            )
    finally:
        cap.release()
"""


# ============================================================
# MODE 2: HTTP MJPEG streaming (e.g. IP Webcam app)
# Use this if your camera gives an HTTP stream URL
# e.g. http://192.168.1.13:8080/video  or  https://xxxx.trycloudflare.com/video
# To activate: uncomment the function below + uncomment stream_http route
# Also uncomment: import requests at the top of this file
# ============================================================
def generate_frames_http(url):
    import requests

    while True:
        try:
            r = requests.get(url, stream=True, timeout=10, verify=False)
            buf = b""
            for chunk in r.iter_content(chunk_size=4096):
                buf += chunk
                start = buf.find(b"\xff\xd8")
                end = buf.find(b"\xff\xd9")
                if start != -1 and end != -1:
                    jpg = buf[start : end + 2]
                    buf = buf[end + 2 :]
                    yield (
                        b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + jpg + b"\r\n"
                    )
        except Exception as e:
            print(f"[HTTP stream error] {e}")
            break


@main.route("/api/cameras/stream/webcam")
@login_required
def stream_webcam():
    return jsonify({"error": "Webcam handled client-side"}), 400


# ============================================================
# MODE 1: RTSP stream route (default — active)
# ============================================================
"""@main.route("/api/cameras/stream/rtsp")
@login_required
def stream_rtsp():
    rtsp_url = request.args.get("url", "")

    if not rtsp_url:
        return jsonify({"error": "No URL provided"}), 400

    camera = Camera.query.filter_by(rtsp_url=rtsp_url).first()
    if not camera:
        return jsonify({"error": "Unknown stream — URL not registered"}), 403

    if not validate_rtsp_url(rtsp_url):
        return jsonify({"error": "Invalid RTSP URL"}), 400

    return Response(
        stream_with_context(generate_frames(rtsp_url)),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )
"""


# ============================================================
# MODE 2: HTTP MJPEG stream route
# To activate: uncomment the entire route below
# Also uncomment generate_frames_http() above
# In dashboard.html, switch img src to /api/cameras/stream/http?url=...
# ============================================================
#
#
@main.route("/api/cameras/stream/http")
@login_required
def stream_http():
    http_url = request.args.get("url", "")

    if not http_url:
        return jsonify({"error": "No URL provided"}), 400

    camera = Camera.query.filter_by(rtsp_url=http_url).first()
    if not camera:
        return jsonify({"error": "Unknown stream — URL not registered"}), 403

    if not validate_http_url(http_url):
        return jsonify({"error": "Invalid HTTP URL"}), 400

    return Response(
        stream_with_context(generate_frames_http(http_url)),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )


# ─── Dashboard ────────────────────────────────────────────────────────────────


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


# ─── Audit Log — ADMIN ONLY ───────────────────────────────────────────────────


@main.route("/audit")
@admin_required
@login_required
def audit():
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    honeypot_logs = HoneypotLog.query.order_by(HoneypotLog.timestamp.desc()).all()
    login_attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()

    for log in audit_logs:
        log.timestamp = convert_to_ph_time(log.timestamp)
    for log in honeypot_logs:
        log.timestamp = convert_to_ph_time(log.timestamp)
    for attempt in login_attempts:
        attempt.timestamp = convert_to_ph_time(attempt.timestamp)

    return render_template(
        "audit.html",
        audit_logs=audit_logs,
        honeypot_logs=honeypot_logs,
        login_attempts=login_attempts,
        current_user=current_user,
    )


# ─── Camera API ───────────────────────────────────────────────────────────────


@main.route("/api/cameras")
@login_required
@limiter.limit("60 per minute")
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
@admin_required
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

    if ip_address != "0.0.0.0" and not validate_ip_address(ip_address):
        return jsonify({"success": False, "error": "Invalid IP address format"}), 400

    existing_camera = Camera.query.filter_by(ip_address=ip_address).first()
    if existing_camera:
        return jsonify(
            {"success": False, "error": "Camera with this IP already exists"}
        ), 400

    # ── Accept custom RTSP or HTTP URL from frontend ──
    custom_rtsp = bleach.clean(data.get("rtsp_url", "")).strip()
    if ip_address == "0.0.0.0":
        rtsp_url = "webcam"
    elif custom_rtsp:
        rtsp_url = custom_rtsp
    else:
        rtsp_url = f"rtsp://{ip_address}:554/stream"

    camera = Camera(
        name=name,
        ip_address=ip_address,
        rtsp_url=rtsp_url,
        location=location,
        status="active",
    )
    db.session.add(camera)
    db.session.commit()
    log_action(f"Added camera: {name} ({ip_address})")
    return jsonify({"success": True, "id": camera.id})


@main.route("/api/cameras/delete/<int:camera_id>", methods=["DELETE"])
@admin_required
@login_required
@limiter.limit("10 per minute")
def delete_camera(camera_id):
    camera = Camera.query.get_or_404(camera_id)
    log_action(f"Deleted camera: {camera.name} ({camera.ip_address})")
    db.session.delete(camera)
    db.session.commit()
    return jsonify({"success": True})


# ─── Network Scan ─────────────────────────────────────────────────────────────


@main.route("/api/network/scan", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def scan_network():
    logs = NetworkLog.query.order_by(NetworkLog.timestamp.desc()).all()
    devices = [
        {
            "ip": l.ip_address,
            "hostname": l.hostname,
            "status": l.status,
        }
        for l in logs
    ]
    return jsonify(devices)


@main.route("/api/network/update", methods=["POST"])
@limiter.limit("10 per minute")
@csrf.exempt
def network_update():
    agent_key = request.headers.get("X-Agent-Key", "")

    if not AGENT_KEY or len(AGENT_KEY) < 32:
        return jsonify(
            {
                "success": False,
                "error": "Server misconfiguration: AGENT_KEY not set properly",
            }
        ), 500

    if not hmac.compare_digest(agent_key, AGENT_KEY):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    devices = data.get("devices", [])

    if not devices:
        return jsonify({"success": False, "error": "No devices provided"}), 400

    NetworkLog.query.delete()
    db.session.commit()

    saved = []
    for device in devices:
        ip = bleach.clean(str(device.get("ip", "")))
        hostname = bleach.clean(str(device.get("hostname", "Unknown")))
        mac = bleach.clean(str(device.get("mac", "N/A")))
        status = bleach.clean(str(device.get("status", "active")))

        if not validate_ip_address(ip):
            continue

        hostname = hostname[:100]
        mac = mac[:50]

        log = NetworkLog(
            ip_address=ip,
            mac_address=mac,
            hostname=hostname,
            status=status,
        )
        db.session.add(log)
        saved.append({"ip": ip, "hostname": hostname, "status": status})

    db.session.commit()
    cleanup_old_records()
    print(f"[Agent] Updated {len(saved)} network devices")
    return jsonify({"success": True, "saved": len(saved)})


# ─── Alerts ───────────────────────────────────────────────────────────────────


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
                "timestamp": convert_to_ph_time(a.timestamp).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "is_resolved": a.is_resolved,
            }
            for a in alerts
        ]
    )


@main.route("/api/alerts/resolve/<int:alert_id>", methods=["POST"])
@admin_required
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


# ─── Logs ─────────────────────────────────────────────────────────────────────


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
                "timestamp": convert_to_ph_time(l.timestamp).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            }
            for l in logs
        ]
    )


# ─── IP Blocking — ADMIN ONLY ────────────────────────────────────────────────


@main.route("/api/block-ip", methods=["POST"])
@admin_required
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
@admin_required
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
@admin_required
@login_required
@limiter.limit("30 per minute")
def get_blocked_ips():
    blocked = BlockedIP.query.order_by(BlockedIP.timestamp.desc()).all()
    return jsonify(
        [
            {
                "id": b.id,
                "ip_address": b.ip_address,
                "reason": b.reason,
                "blocked_by": b.blocked_by,
                "timestamp": convert_to_ph_time(b.timestamp).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            }
            for b in blocked
        ]
    )
