import smtplib
import os
from dotenv import load_dotenv
from email.mime.text import MIMEText
from datetime import datetime

load_dotenv()

EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT"))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def send_otp_email(to_email, otp):
    msg = MIMEText(f"The OTP for your account verification is: {otp}")
    msg["Subject"] = "CyberVault OTP Verification"
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
            print(f"OTP sent to {to_email}")
    except Exception as e:
        print(f"Error sending OTP email: {e}")

def send_password_change_email(to_email, ip_address, user_agent):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    body = f"""
Hello,

Your CyberVault password was successfully changed.

🕒 Time       : {timestamp}
📍 IP Address : {ip_address}
💻 Device     : {user_agent}

If you did not initiate this change, please reset your password immediately or contact support.

— CyberVault Security Team
    """.strip()

    msg = MIMEText(body)
    msg["Subject"] = "CyberVault Security Alert: Password Changed"
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
            print(f"Password change alert sent to {to_email}")
    except Exception as e:
        print(f"Error sending password change email: {e}")
