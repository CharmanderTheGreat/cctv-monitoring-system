from flask import current_app
import threading
import traceback
import requests


def send_email_alert(app, subject, body):
    def send():
        with app.app_context():
            try:
                api_key = app.config.get("BREVO_API_KEY")
                recipients = app.config.get("ALERT_EMAIL", [])
                sender_email = app.config.get("MAIL_USERNAME")

                print(f"📧 Sending email via Brevo to: {recipients}")

                if not api_key:
                    print("❌ BREVO_API_KEY not set in environment variables!")
                    return

                if not recipients:
                    print(
                        "❌ No recipients configured! Check ALERT_EMAILS in Railway Variables."
                    )
                    return

                if not sender_email:
                    print("❌ MAIL_USERNAME not set!")
                    return

                # Build recipients list for Brevo API
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
