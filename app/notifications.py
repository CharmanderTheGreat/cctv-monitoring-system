from flask import current_app
from flask_mail import Message
import threading
import requests


def send_email_alert(app, subject, body):
    def send():
        with app.app_context():
            from app import mail

            msg = Message(
                subject=f"🚨 CCTV ALERT: {subject}",
                sender=app.config["MAIL_USERNAME"],
                recipients=app.config["ALERT_EMAIL"],
                body=body,
            )
            mail.send(msg)

    try:
        thread = threading.Thread(target=send)
        thread.daemon = True
        thread.start()
    except Exception as e:
        print(f"Email error: {e}")


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
                print(f"SMS error: {e}")

    try:
        thread = threading.Thread(target=send)
        thread.daemon = True
        thread.start()
    except Exception as e:
        print(f"SMS thread error: {e}")


def send_alert(subject, body):
    app = current_app._get_current_object()
    send_email_alert(app, subject, body)
    send_sms_alert(app, f"{subject} — {body}")
