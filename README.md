# CCTV Monitoring & Network Administration System

A robust and production-ready CCTV monitoring and security management system developed as an academic project. Designed for real-time surveillance oversight, automated threat detection, brute-force mitigation, and comprehensive administrative controls.

## System Overview & Purpose

The CCTV Monitoring System is engineered to provide a centralized security dashboard for network administrators. Its primary objectives include:

* **Live Surveillance Oversight:** Real-time monitoring feed management and security status indicators.
* **Proactive Threat Mitigation:** Automated tracking of unauthorized login attempts, IP rate-limiting, and temporary IP bans to counter brute-force attacks.
* **Security Alerting:** Instant email notifications triggered upon detecting suspicious network activities or security breaches.
* **Access Control & RBAC:** Role-based access management ensuring strict separation between administrative privileges and standard viewers.

## Tech Stack & Architecture

### **Backend**

* **Framework:** Flask (Python) with Application Factory pattern and Blueprints (`auth`, `main`, `network_core`)
* **Database & ORM:** SQLite (local development) / PostgreSQL (production-ready via SQLAlchemy)
* **Security & Authentication:** 
  * `Flask-Login` for session management
  * `Flask-Bcrypt` for secure password hashing
  * `Flask-WTF` with built-in CSRF protection
  * `Flask-Talisman` for strict Content Security Policy (CSP) headers and HTTPS enforcement
  * `Flask-Limiter` integrated with `Redis` for atomic rate-limiting and brute-force tracking
* **Middleware:** `ProxyFix` for accurate client IP resolution behind reverse proxies (e.g., Railway, Nginx)
* **Utilities:** `Bleach` for input sanitization, `python-dotenv` for environment configuration

### **Frontend**

* **Templating:** Jinja2 server-side rendering
* **Styling:** Custom responsive dark-themed UI designed with CSS3 variables, glassmorphism elements, and interactive system status indicators
* **Scripting:** Vanilla JavaScript for dynamic countdown timers, client-side validation, and real-time interface updates

## Project Structure

```
cctv-monitoring-system/
│
├── backend/
│   ├── app/
│   │   ├── static/               # Frontend CSS, JS, and asset files
│   │   ├── templates/            # HTML templates (login.html, dashboard, errors)
│   │   ├── __init__.py           # Flask application factory and extension initialization
│   │   ├── auth.py               # Authentication blueprint, IP ban logic, and rate limiting
│   │   ├── models.py             # SQLAlchemy database models (User, LoginAttempt, TempBlockedIP)
│   │   ├── network_core.py       # Network monitoring and administration routes
│   │   ├── notifications.py      # Email alert dispatchers (Brevo/SMTP integration)
│   │   └── routes.py             # Core dashboard and general application routes
│   ├── venv/                     # Python virtual environment
│   ├── requirements.txt          # Project dependencies list
│   ├── run.py                    # Application entry point
│   └── Procfile                  # Cloud deployment configuration (Gunicorn)
│
├── frontend/
│   └── templates/                # Shared HTML layout templates
├── README.md                     # Project documentation and overview
└── SETUP.md                      # Detailed installation and execution guide
```

## Security Features Implemented

* **CSRF Protection:** Integrated via `Flask-WTF` safeguarding all state-changing forms.
* **Brute-Force Protection:** Tracks failed logins per IP address with automated temporary blacklisting (`TempBlockedIP`) and Redis atomic counters.
* **Input Sanitization:** Uses `Bleach` to clean user inputs and prevent XSS injections.
* **Security Headers:** Enforced via `Flask-Talisman` restricting resource loading and mitigating framing/clickjacking attacks.

## Contributors & Academic Context

* **Project Type:** Third-Year Bachelor of Science in Information Technology (BSIT) Academic Project
* **Repositories & Maintenance:** Managed under strict branch workflows (`feature/*` -> `dev` -> `main` with `CODEOWNERS` review protection).