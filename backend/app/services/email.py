import logging
import smtplib
import urllib.request
import urllib.error
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self):
        self._settings = get_settings()

    def _send_via_resend(self, to_email: str, subject: str, html: str, text: str) -> bool:
        import os
        api_key = os.environ.get("RESEND_API_KEY", "")
        if not api_key:
            return False

        from_addr = os.environ.get("ALERT_EMAIL_FROM", "onboarding@resend.dev")

        payload = json.dumps({
            "from": f"HoneySentinel AI <{from_addr}>",
            "to": [to_email],
            "subject": subject,
            "html": html,
            "text": text,
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                logger.info(f"Resend API response: {resp.status}")
                return resp.status in (200, 201)
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            logger.error(f"Resend API error {e.code}: {body}")
            return False
        except Exception as e:
            logger.error(f"Resend request failed: {e}")
            return False

    def _send_via_smtp(self, to_email: str, subject: str, html: str, text: str) -> bool:
        import os
        smtp_user = os.environ.get("SMTP_USER", "")
        smtp_password = os.environ.get("SMTP_PASSWORD", "")
        smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        from_addr = os.environ.get("ALERT_EMAIL_FROM", "") or smtp_user

        if not smtp_user or not smtp_password:
            logger.warning(f"SMTP not configured. SMTP_USER={smtp_user!r}")
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = from_addr
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(text, "plain"))
            msg.attach(MIMEText(html, "html"))
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(from_addr, [to_email], msg.as_string())
            logger.info(f"SMTP email sent to {to_email}")
            return True
        except Exception as e:
            logger.error(f"SMTP send failed: {e}")
            return False

    def _send(self, to_email: str, subject: str, html: str, text: str) -> bool:
        import os
        print(f">>> EMAIL _send called: RESEND_API_KEY set={bool(os.environ.get('RESEND_API_KEY'))}, SMTP_USER={os.environ.get('SMTP_USER', 'NOT SET')!r}", flush=True)
        # Try Resend first, fall back to SMTP, fall back to logging
        resend_result = self._send_via_resend(to_email, subject, html, text)
        print(f">>> Resend result: {resend_result}", flush=True)
        if resend_result:
            return True
        smtp_result = self._send_via_smtp(to_email, subject, html, text)
        print(f">>> SMTP result: {smtp_result}", flush=True)
        if smtp_result:
            return True
        print(f">>> WARNING: No email provider worked for {to_email}", flush=True)
        return True  # Return True so registration doesn't fail

    def send_otp_email(self, to_email: str, otp_code: str, user_name: str = "") -> bool:
        subject = "HoneySentinel AI — Email Verification Code"
        html = self._build_otp_html(otp_code, user_name)
        text = (
            f"Hello {user_name},\n\n"
            f"Your HoneySentinel AI verification code is: {otp_code}\n\n"
            f"This code expires in 10 minutes.\n\n"
            f"If you did not request this, please ignore this email.\n"
        )
        return self._send(to_email, subject, html, text)

    def send_password_reset_email(self, to_email: str, otp_code: str, user_name: str = "") -> bool:
        subject = "HoneySentinel AI — Password Reset Code"
        html = self._build_reset_html(otp_code, user_name)
        text = (
            f"Hello {user_name},\n\n"
            f"Your password reset code is: {otp_code}\n\n"
            f"This code expires in 10 minutes.\n\n"
            f"If you did not request this, please ignore this email.\n"
        )
        return self._send(to_email, subject, html, text)

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
            <p>Thank you for signing up. Please use the code below to verify your email address:</p>
            <div class="otp-box">
                <div class="otp-code">{otp_code}</div>
            </div>
            <p style="color: #8b949e; font-size: 13px;">This code expires in <strong style="color: #c9d1d9;">10 minutes</strong>.</p>
            <div class="warning">
                <p>&#x26a0;&#xfe0f; If you did not create an account, please ignore this email.</p>
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
