import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()


class Config:
    # Generate strong key: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-use-a-random-secret-key")

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "").replace(
        "postgres://", "postgresql://"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("RAILWAY_ENVIRONMENT") == "production"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)

    # CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Login
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_BLOCK_MINUTES = 15

    # Email
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    # Support multiple emails separated by comma
    ALERT_EMAIL = [
        e.strip() for e in os.environ.get("ALERT_EMAILS", "").split(",") if e.strip()
    ]

    # SMS (Semaphore)
    SEMAPHORE_API_KEY = os.environ.get("SEMAPHORE_API_KEY")
    SEMAPHORE_SENDER = os.environ.get("SEMAPHORE_SENDER")
    ALERT_PHONE = os.environ.get("ALERT_PHONE")

    # Database (for Railway)
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    }

    # Rate limiting
    RATELIMIT_DEFAULT = None
