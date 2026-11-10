import html as html_escape
import logging
import os
import smtplib
import urllib.request
import urllib.error
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self):
        self._settings = get_settings()

    @property
    def configured(self) -> bool:
        """Whether any way of sending mail is set up at all.

        The same conditions the senders below check before they try. With
        none of them met, a verification or reset code can never arrive, and
        the flows that depend on one are refused up front rather than left
        to issue codes into the void.
        """
        if any(
            os.environ.get(name, "").strip()
            for name in ("BREVO_API_KEY", "SENDGRID_API_KEY", "RESEND_API_KEY")
        ):
            return True
        return bool(
            self._settings.SMTP_HOST
            and self._settings.SMTP_USER
            and self._settings.SMTP_PASSWORD
        )

    def _send_via_sendgrid(self, to_email: str, subject: str, html: str, text: str) -> bool:
        api_key = os.environ.get("SENDGRID_API_KEY", "")
        if not api_key:
            return False

        from_email = self._settings.ALERT_EMAIL_FROM

        payload = json.dumps({
            "personalizations": [{"to": [{"email": to_email}]}],
            "from": {"email": from_email, "name": "HoneySentinel AI"},
            "subject": subject,
            "content": [
                {"type": "text/plain", "value": text},
                {"type": "text/html", "value": html},
            ],
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.sendgrid.com/v3/mail/send",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status == 202
        except urllib.error.HTTPError as exc:
            logger.warning(
                "Email provider rejected the message: HTTP %s", exc.code
            )
            return False
        except Exception as exc:
            logger.warning("Email provider request failed: %s", exc)
            return False


    def _send_via_brevo(self, to_email: str, subject: str, html: str, text: str) -> bool:
        api_key = os.environ.get("BREVO_API_KEY", "")
        if not api_key:
            return False

        from_email = self._settings.ALERT_EMAIL_FROM

        payload = json.dumps({
            "sender": {"name": "HoneySentinel AI", "email": from_email},
            "to": [{"email": to_email}],
            "subject": subject,
            "htmlContent": html,
            "textContent": text,
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.brevo.com/v3/smtp/email",
            data=payload,
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status == 201
        except urllib.error.HTTPError as exc:
            logger.warning(
                "Email provider rejected the message: HTTP %s", exc.code
            )
            return False
        except Exception as exc:
            logger.warning("Email provider request failed: %s", exc)
            return False
    def _send_via_resend(self, to_email: str, subject: str, html: str, text: str) -> bool:
        api_key = os.environ.get("RESEND_API_KEY", "")
        if not api_key:
            return False

        from_addr = self._settings.ALERT_EMAIL_FROM or "onboarding@resend.dev"

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
                return resp.status in (200, 201)
        except urllib.error.HTTPError as exc:
            logger.warning(
                "Email provider rejected the message: HTTP %s", exc.code
            )
            return False
        except Exception as exc:
            logger.warning("Email provider request failed: %s", exc)
            return False

    def _send_via_smtp(self, to_email: str, subject: str, html: str, text: str) -> bool:
        import ssl

        smtp_user = self._settings.SMTP_USER
        smtp_password = self._settings.SMTP_PASSWORD
        smtp_host = self._settings.SMTP_HOST
        from_addr = self._settings.ALERT_EMAIL_FROM or smtp_user

        if not smtp_user or not smtp_password:
            return False

        msg = MIMEMultipart("alternative")
        msg["From"] = from_addr
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        # Try port 465 (SSL) first — more reliable on restricted networks
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, 465, context=context, timeout=15) as server:
                server.login(smtp_user, smtp_password)
                server.sendmail(from_addr, [to_email], msg.as_string())
            return True
        except Exception as exc:
            logger.warning("SMTP over 465 failed: %s", exc)

        # Fall back to port 587 (STARTTLS)
        try:
            with smtplib.SMTP(smtp_host, 587, timeout=15) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(from_addr, [to_email], msg.as_string())
            return True
        except Exception as exc:
            logger.warning("SMTP STARTTLS over 587 failed: %s", exc)
            return False

    def _send(self, to_email: str, subject: str, html: str, text: str) -> bool:

        providers = (
            ("Brevo", self._send_via_brevo),
            ("SendGrid", self._send_via_sendgrid),
            ("Resend", self._send_via_resend),
            ("SMTP", self._send_via_smtp),
        )
        for name, send in providers:
            if send(to_email, subject, html, text):
                logger.info("Email delivered via %s", name)
                return True

        # Returning True here (the previous behaviour) told the caller the
        # code had been delivered when nothing had been sent, so users waited
        # for an email that was never going to arrive.
        logger.error("No email provider accepted the message")
        return False

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
        user_name = html_escape.escape(user_name)
        return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:0}}
.container{{max-width:480px;margin:40px auto;background:#161b22;border:1px solid #30363d;border-radius:12px;overflow:hidden}}
.header{{background:linear-gradient(135deg,#1a3a4a,#0d1117);padding:30px;text-align:center;border-bottom:1px solid #30363d}}
.header h1{{color:#39d0d8;font-size:22px;margin:0;font-family:'Courier New',monospace}}
.header p{{color:#8b949e;font-size:13px;margin:8px 0 0}}
.body{{padding:30px}}
.body p{{color:#c9d1d9;font-size:15px;line-height:1.6;margin:0 0 20px}}
.otp-box{{background:#0d1117;border:2px solid #39d0d8;border-radius:8px;padding:20px;text-align:center;margin:20px 0}}
.otp-code{{font-family:'Courier New',monospace;font-size:36px;font-weight:bold;color:#39d0d8;letter-spacing:8px}}
.footer{{background:#0d1117;padding:20px 30px;text-align:center;border-top:1px solid #30363d}}
.footer p{{color:#484f58;font-size:12px;margin:0}}
.warning{{background:#3d1f00;border:1px solid #e3692a;border-radius:6px;padding:12px;margin:15px 0}}
.warning p{{color:#e3692a;font-size:13px;margin:0}}
</style></head>
<body>
<div class="container">
  <div class="header"><h1>&#x1f6e1;&#xfe0f; HoneySentinel AI</h1><p>Email Verification</p></div>
  <div class="body">
    <p>Hello {user_name},</p>
    <p>Thank you for signing up. Please use the code below to verify your email address:</p>
    <div class="otp-box"><div class="otp-code">{otp_code}</div></div>
    <p style="color:#8b949e;font-size:13px">This code expires in <strong style="color:#c9d1d9">10 minutes</strong>.</p>
    <div class="warning"><p>&#x26a0;&#xfe0f; If you did not create an account, please ignore this email.</p></div>
  </div>
  <div class="footer"><p>&#x1f512; HoneySentinel AI — Cyber Threat Intelligence Platform</p></div>
</div>
</body></html>"""

    def _build_reset_html(self, otp_code: str, user_name: str) -> str:
        user_name = html_escape.escape(user_name)
        return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:0}}
.container{{max-width:480px;margin:40px auto;background:#161b22;border:1px solid #30363d;border-radius:12px;overflow:hidden}}
.header{{background:linear-gradient(135deg,#3d1f00,#0d1117);padding:30px;text-align:center;border-bottom:1px solid #30363d}}
.header h1{{color:#e3692a;font-size:22px;margin:0;font-family:'Courier New',monospace}}
.body{{padding:30px}}
.body p{{color:#c9d1d9;font-size:15px;line-height:1.6;margin:0 0 20px}}
.otp-box{{background:#0d1117;border:2px solid #e3692a;border-radius:8px;padding:20px;text-align:center;margin:20px 0}}
.otp-code{{font-family:'Courier New',monospace;font-size:36px;font-weight:bold;color:#e3692a;letter-spacing:8px}}
.footer{{background:#0d1117;padding:20px 30px;text-align:center;border-top:1px solid #30363d}}
.footer p{{color:#484f58;font-size:12px;margin:0}}
</style></head>
<body>
<div class="container">
  <div class="header"><h1>&#x1f511; HoneySentinel AI</h1><p>Password Reset</p></div>
  <div class="body">
    <p>Hello {user_name},</p>
    <p>Use the code below to reset your password:</p>
    <div class="otp-box"><div class="otp-code">{otp_code}</div></div>
    <p style="color:#8b949e;font-size:13px">This code expires in <strong style="color:#c9d1d9">10 minutes</strong>.</p>
  </div>
  <div class="footer"><p>&#x1f512; HoneySentinel AI — Cyber Threat Intelligence Platform</p></div>
</div>
</body></html>"""


email_service = EmailService()
