import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "").replace(
        "postgres://", "postgresql://"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("RAILWAY_ENVIRONMENT") == "production"
    PERMANENT_SESSION_LIFETIME = 900

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
    ALERT_EMAIL = os.environ.get("ALERT_EMAIL")

    # SMS
    TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
    TWILIO_PHONE = os.environ.get("TWILIO_PHONE")
    ALERT_PHONE = os.environ.get("ALERT_PHONE")
    SEMAPHORE_API_KEY = os.environ.get("SEMAPHORE_API_KEY")
    SEMAPHORE_SENDER = os.environ.get("SEMAPHORE_SENDER")
