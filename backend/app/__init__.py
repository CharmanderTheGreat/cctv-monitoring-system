from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_talisman import Talisman
from flask_mail import Mail
from werkzeug.middleware.proxy_fix import ProxyFix
import os

# Initialize core Flask extensions
db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.environ.get("REDIS_URL", "memory://"),
    default_limits=["100 per hour", "20 per minute"],
)
csrf = CSRFProtect()
mail = Mail()


def create_app():
    # ─── FRONTEND TEMPLATE & STATIC PATH RESOLUTION ───────────────────────────
    # Traverse two directory levels up from backend/app/__init__.py to find the
    # root workspace folder (cctv-monitoring-system/):
    #   __file__            -> backend/app/__init__.py
    #   dirname(__file__)   -> backend/app/
    #   ..                  -> backend/
    #   ../..               -> root folder
    #
    # Then explicitly bind Flask's template and static directories to the
    # separated frontend/ directory to maintain clean architecture while
    # preserving server-side Jinja template rendering.
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    template_folder = os.path.join(base_dir, "frontend", "templates")
    static_folder = os.path.join(base_dir, "frontend", "static")

    app = Flask(
        __name__,
        template_folder=template_folder,
        static_folder=static_folder,
    )
    app.config.from_object("config.Config")

    # ─── PROXYFIX MIDDLEWARE ──────────────────────────────────────────────────
    # Required to correctly evaluate the X-Forwarded-For and X-Forwarded-Proto
    # headers supplied by reverse proxies (e.g., Railway or Nginx).
    # This guarantees that request.remote_addr reflects the genuine client IP
    # rather than the internal load balancer address for rate limiting and logging.
    #
    # x_for=1   -> Trusts 1 upstream reverse proxy layer (Railway)
    # x_proto=1 -> Correctly identifies incoming HTTPS schemes
    # x_host=1  -> Accurately reads the forwarded host domain
    #
    # WARNING: Do not increase x_for beyond the actual number of trusted reverse
    # proxy hops to prevent IP spoofing vulnerabilities.
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
    )

    # Initialize extensions with the application instance
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)

    # Inject the CSRF token into all Jinja templates automatically
    @app.context_processor
    def inject_csrf():
        return dict(csrf_token=generate_csrf)

    is_production = os.environ.get("RAILWAY_ENVIRONMENT") == "production"

    # Strict Content Security Policy (CSP) headers to mitigate XSS attacks
    csp = {
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-inline'",
        "style-src": "'self' 'unsafe-inline'",
        "img-src": "'self' data:",
    }
    Talisman(
        app,
        force_https=is_production,
        strict_transport_security=is_production,
        content_security_policy=csp,
        x_content_type_options=True,
        frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin",
    )

    # Define the default redirect endpoint for unauthenticated users
    login_manager.login_view = "auth.login"

    # Register modular blueprints
    from app.auth import auth as auth_blueprint
    from app.routes import main as main_blueprint
    from app.network_core import network_core as network_core_blueprint

    app.register_blueprint(auth_blueprint)
    app.register_blueprint(main_blueprint)
    app.register_blueprint(network_core_blueprint)

    # Ensure all defined SQLAlchemy models and tables exist on application start
    with app.app_context():
        from app import models

        db.create_all()

    # Register centralized HTTP exception handlers
    register_error_handlers(app)

    return app


def register_error_handlers(app):
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(429)
    def too_many_requests(e):
        return render_template("429.html"), 429