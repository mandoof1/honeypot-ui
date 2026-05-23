import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self):
        self._settings = get_settings()

    def send_otp_email(self, to_email: str, otp_code: str, user_name: str = "") -> bool:
        settings = self._settings

        if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
            logger.warning(
                f"SMTP not configured. OTP for {to_email}: {otp_code} (logged only)"
            )
            return True

        subject = "HoneySentinel AI — Email Verification Code"
        body_html = self._build_otp_html(otp_code, user_name)
        body_text = (
            f"Hello {user_name},\n\n"
            f"Your HoneySentinel AI verification code is: {otp_code}\n\n"
            f"This code expires in 10 minutes.\n\n"
            f"If you did not request this, please ignore this email.\n"
        )

        msg = MIMEMultipart("alternative")
        msg["From"] = settings.ALERT_EMAIL_FROM or settings.SMTP_USER
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        try:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
                server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(msg["From"], [to_email], msg.as_string())
            logger.info(f"OTP email sent to {to_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to send OTP email to {to_email}: {e}")
            return False

    def send_password_reset_email(self, to_email: str, otp_code: str, user_name: str = "") -> bool:
        settings = self._settings

        if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
            logger.warning(
                f"SMTP not configured. Password reset OTP for {to_email}: {otp_code}"
            )
            return True

        subject = "HoneySentinel AI — Password Reset Code"
        body_html = self._build_reset_html(otp_code, user_name)
        body_text = (
            f"Hello {user_name},\n\n"
            f"Your password reset code is: {otp_code}\n\n"
            f"This code expires in 10 minutes.\n\n"
            f"If you did not request this, please ignore this email.\n"
        )

        msg = MIMEMultipart("alternative")
        msg["From"] = settings.ALERT_EMAIL_FROM or settings.SMTP_USER
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        try:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
                server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(msg["From"], [to_email], msg.as_string())
            logger.info(f"Password reset email sent to {to_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to send reset email to {to_email}: {e}")
            return False

    def _build_otp_html(self, otp_code: str, user_name: str) -> str:
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 0; }}
        .container {{ max-width: 480px; margin: 40px auto; background: #161b22; border: 1px solid #30363d; border-radius: 12px; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #1a3a4a, #0d1117); padding: 30px; text-align: center; border-bottom: 1px solid #30363d; }}
        .header h1 {{ color: #39d0d8; font-size: 22px; margin: 0; font-family: 'Courier New', monospace; }}
        .header p {{ color: #8b949e; font-size: 13px; margin: 8px 0 0; }}
        .body {{ padding: 30px; }}
        .body p {{ color: #c9d1d9; font-size: 15px; line-height: 1.6; margin: 0 0 20px; }}
        .otp-box {{ background: #0d1117; border: 2px solid #39d0d8; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }}
        .otp-code {{ font-family: 'Courier New', monospace; font-size: 36px; font-weight: bold; color: #39d0d8; letter-spacing: 8px; }}
        .footer {{ background: #0d1117; padding: 20px 30px; text-align: center; border-top: 1px solid #30363d; }}
        .footer p {{ color: #484f58; font-size: 12px; margin: 0; }}
        .warning {{ background: #3d1f00; border: 1px solid #e3692a; border-radius: 6px; padding: 12px; margin: 15px 0; }}
        .warning p {{ color: #e3692a; font-size: 13px; margin: 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#x1f6e1;&#xfe0f; HoneySentinel AI</h1>
            <p>Email Verification</p>
        </div>
        <div class="body">
            <p>Hello {user_name},</p>
            <p>Thank you for signing up for HoneySentinel AI. Please use the code below to verify your email address:</p>
            <div class="otp-box">
                <div class="otp-code">{otp_code}</div>
            </div>
            <p style="color: #8b949e; font-size: 13px;">This code expires in <strong style="color: #c9d1d9;">10 minutes</strong>.</p>
            <div class="warning">
                <p>&#x26a0;&#xfe0f; If you did not create an account, please ignore this email. Do not share this code with anyone.</p>
            </div>
        </div>
        <div class="footer">
            <p>&#x1f512; HoneySentinel AI — Cyber Threat Intelligence Platform</p>
        </div>
    </div>
</body>
</html>
"""

    def _build_reset_html(self, otp_code: str, user_name: str) -> str:
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 0; }}
        .container {{ max-width: 480px; margin: 40px auto; background: #161b22; border: 1px solid #30363d; border-radius: 12px; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #3d1f00, #0d1117); padding: 30px; text-align: center; border-bottom: 1px solid #30363d; }}
        .header h1 {{ color: #e3692a; font-size: 22px; margin: 0; font-family: 'Courier New', monospace; }}
        .body {{ padding: 30px; }}
        .body p {{ color: #c9d1d9; font-size: 15px; line-height: 1.6; margin: 0 0 20px; }}
        .otp-box {{ background: #0d1117; border: 2px solid #e3692a; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }}
        .otp-code {{ font-family: 'Courier New', monospace; font-size: 36px; font-weight: bold; color: #e3692a; letter-spacing: 8px; }}
        .footer {{ background: #0d1117; padding: 20px 30px; text-align: center; border-top: 1px solid #30363d; }}
        .footer p {{ color: #484f58; font-size: 12px; margin: 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#x1f511; HoneySentinel AI</h1>
            <p>Password Reset</p>
        </div>
        <div class="body">
            <p>Hello {user_name},</p>
            <p>Use the code below to reset your password:</p>
            <div class="otp-box">
                <div class="otp-code">{otp_code}</div>
            </div>
            <p style="color: #8b949e; font-size: 13px;">This code expires in <strong style="color: #c9d1d9;">10 minutes</strong>.</p>
        </div>
        <div class="footer">
            <p>&#x1f512; HoneySentinel AI — Cyber Threat Intelligence Platform</p>
        </div>
    </div>
</body>
</html>
"""


email_service = EmailService()
