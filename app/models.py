from app import db, login_manager, bcrypt
from flask_login import UserMixin
from datetime import datetime


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ban_until = db.Column(db.DateTime, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)

    def set_password(self, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        self.password = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def is_banned(self):
        if self.ban_until and self.ban_until > datetime.utcnow():
            return True
        return False

    def get_ban_seconds(self):
        if self.ban_until and self.ban_until > datetime.utcnow():
            return max(0, int((self.ban_until - datetime.utcnow()).total_seconds()))
        return 0


class Camera(db.Model):
    __tablename__ = "cameras"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    rtsp_url = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(100))
    status = db.Column(db.String(20), default="active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class NetworkLog(db.Model):
    __tablename__ = "network_logs"
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50))
    mac_address = db.Column(db.String(50))
    hostname = db.Column(db.String(100))
    status = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50))
    source_ip = db.Column(db.String(50))
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_resolved = db.Column(db.Boolean, default=False)


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50))
    username = db.Column(db.String(80))
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80))
    action = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class HoneypotLog(db.Model):
    __tablename__ = "honeypot_logs"
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50))
    path = db.Column(db.String(200))
    method = db.Column(db.String(10))
    user_agent = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    reason = db.Column(db.String(200))
    blocked_by = db.Column(db.String(80))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class TempBlockedIP(db.Model):
    __tablename__ = "temp_blocked_ips"

    id = db.Column(db.Integer, primary_key=True)

    ip_address = db.Column(db.String(50), unique=True, nullable=False)

    blocked_until = db.Column(db.DateTime, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
