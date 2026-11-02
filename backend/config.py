import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()


class Config:
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-use-a-random-secret-key")

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "").replace(
        "postgres://", "postgresql://"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("RAILWAY_ENVIRONMENT") == "production"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_BLOCK_MINUTES = 15

    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    ALERT_EMAIL = [
        e.strip() for e in os.environ.get("ALERT_EMAILS", "").split(",") if e.strip()
    ]

    SEMAPHORE_API_KEY = os.environ.get("SEMAPHORE_API_KEY")
    SEMAPHORE_SENDER = os.environ.get("SEMAPHORE_SENDER")
    ALERT_PHONE = os.environ.get("ALERT_PHONE")

    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    }

    RATELIMIT_DEFAULT = "100 per hour"
