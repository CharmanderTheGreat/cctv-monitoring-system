import datetime

from flask import current_app
import threading
import traceback
import pytz
import requests
import os


def send_email_alert(app, subject, body):
    def send():
        with app.app_context():
            try:
                # Read directly from os.environ para sigurado
                api_key = os.environ.get("BREVO_API_KEY") or app.config.get(
                    "BREVO_API_KEY"
                )
                recipients = app.config.get("ALERT_EMAIL", [])
                sender_email = app.config.get("MAIL_USERNAME")

                print(f"📧 Sending email via Brevo to: {recipients}")
                print(f"🔑 API Key present: {bool(api_key)}")
                print(f"📨 Sender: {sender_email}")

                if not api_key:
                    print("❌ BREVO_API_KEY not found anywhere!")
                    print(
                        f"Available env vars: {[k for k in os.environ.keys() if 'BREVO' in k or 'brevo' in k]}"
                    )
                    return

                if not recipients:
                    print("❌ No recipients configured!")
                    return

                if not sender_email:
                    print("❌ MAIL_USERNAME not set!")
                    return

                to_list = [{"email": email} for email in recipients]

                payload = {
                    "sender": {"name": "CCTV Monitor", "email": sender_email},
                    "to": to_list,
                    "subject": f"🚨 CCTV ALERT: {subject}",
                    "textContent": body,
                }

                response = requests.post(
                    "https://api.brevo.com/v3/smtp/email",
                    headers={
                        "accept": "application/json",
                        "api-key": api_key,
                        "content-type": "application/json",
                    },
                    json=payload,
                    timeout=15,
                )

                if response.status_code == 201:
                    print(f"✅ Email sent via Brevo: {subject}")
                else:
                    print(f"❌ Brevo error: {response.status_code} — {response.text}")

            except Exception as e:
                print(f"❌ Email error: {e}")
                traceback.print_exc()

    try:
        thread = threading.Thread(target=send)
        thread.daemon = True
        thread.start()
    except Exception as e:
        print(f"❌ Email thread error: {e}")


def send_sms_alert(app, body):
    def send():
        with app.app_context():
            try:
                response = requests.post(
                    "https://api.semaphore.co/api/v4/messages",
                    data={
                        "apikey": app.config["SEMAPHORE_API_KEY"],
                        "number": app.config["ALERT_PHONE"],
                        "message": f"CCTV ALERT: {body}",
                        "sendername": app.config["SEMAPHORE_SENDER"],
                    },
                )
                print(f"SMS status: {response.status_code}")
                print(f"SMS response: {response.text}")
            except Exception as e:
                print(f"❌ SMS error: {e}")

    try:
        thread = threading.Thread(target=send)
        thread.daemon = True
        thread.start()
    except Exception as e:
        print(f"❌ SMS thread error: {e}")


def send_alert(subject, body):
    app = current_app._get_current_object()
    send_email_alert(app, subject, body)
    send_sms_alert(app, f"{subject} — {body}")


def send_login_alert(app, username, ip):
    def send():
        with app.app_context():
            try:
                api_key = os.environ.get("BREVO_API_KEY") or app.config.get(
                    "BREVO_API_KEY"
                )
                recipients = app.config.get("ALERT_EMAIL", [])
                sender_email = app.config.get("MAIL_USERNAME")

                if not api_key or not recipients or not sender_email:
                    print("❌ Login alert config missing!")
                    return

                from datetime import datetime
                import pytz

                ph_tz = pytz.timezone("Asia/Manila")
                timestamp = datetime.now(ph_tz).strftime("%Y-%m-%d %H:%M:%S PHT")

                payload = {
                    "sender": {"name": "CCTV Monitor", "email": sender_email},
                    "to": [{"email": email} for email in recipients],
                    "subject": "🔐 CCTV Monitor: Successful Login",
                    "htmlContent": f"""
                        <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                            <h2 style="color: #00b8d4;">✅ Login Alert</h2>
                            <p>A user has successfully logged in to your CCTV Monitor system.</p>
                            <table style="width:100%; border-collapse:collapse;">
                                <tr><td style="padding:8px; color:#666;">Username</td>
                                    <td style="padding:8px;"><strong>{username}</strong></td></tr>
                                <tr style="background:#f9f9f9;"><td style="padding:8px; color:#666;">IP Address</td>
                                    <td style="padding:8px;"><strong>{ip}</strong></td></tr>
                                <tr><td style="padding:8px; color:#666;">Time</td>
                                    <td style="padding:8px;"><strong>{timestamp}</strong></td></tr>
                            </table>
                            <p style="color:#999; font-size:12px; margin-top:20px;">
                                If this wasn't you, secure your account immediately.
                            </p>
                        </div>
                    """,
                }

                response = requests.post(
                    "https://api.brevo.com/v3/smtp/email",
                    headers={
                        "accept": "application/json",
                        "api-key": api_key,
                        "content-type": "application/json",
                    },
                    json=payload,
                    timeout=15,
                )

                if response.status_code == 201:
                    print(f"✅ Login alert sent for user: {username} from {ip}")
                else:
                    print(
                        f"❌ Login alert Brevo error: {response.status_code} — {response.text}"
                    )

            except Exception as e:
                print(f"❌ Login alert error: {e}")

    try:
        thread = threading.Thread(target=send)
        thread.daemon = True
        thread.start()
    except Exception as e:
        print(f"❌ Login alert thread error: {e}")
