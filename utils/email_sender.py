# utils/email_sender.py
from flask_mail import Message
from extensions import mail

def send_email(to_email, otp):
    subject = "Your OTP for Placify - PlacementPrepAI"
    body = f"Your OTP is: {otp}\nIt is valid for 5 minutes."

    try:
        msg = Message(subject, recipients=[to_email])
        msg.body = body
        mail.send(msg)
        print(f"✅ OTP sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email to {to_email}:", e)
