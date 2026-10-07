"""Outbound notification for high-severity detections."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import logging
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict

import httpx

from app.core.config import get_settings
from app.schemas import AttackSeverity

settings = get_settings()
logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH": "#e3692a",
    "MEDIUM": "#f0ad4e",
    "LOW": "#3fb950",
}


def _esc(value) -> str:
    """Escape a value for inclusion in the HTML alert body.

    Everything in an alert - the IP, the detected tool names, the description -
    derives from attacker-controlled input. Interpolating it raw let an
    attacker inject markup and links into the SOC's inbox.
    """
    return html.escape("" if value is None else str(value), quote=True)


class AlertingService:
    async def send_alert(self, alert_data: Dict) -> bool:
        try:
            severity = AttackSeverity(alert_data.get("severity", "low"))
        except ValueError:
            severity = AttackSeverity.LOW

        # Channels come from the thresholds that matched. The severity gate
        # that used to live here silently overrode them: a rule configured to
        # notify on MEDIUM raised its alert and then had the notification
        # dropped one layer down, which is the hardest kind of setting to
        # debug — it does exactly half of what it says.
        channels = alert_data.get("channels")
        if channels is None:
            channels = {
                "email": severity in (AttackSeverity.HIGH, AttackSeverity.CRITICAL),
                "webhook": severity in (AttackSeverity.HIGH, AttackSeverity.CRITICAL),
            }

        if not (channels.get("email") or channels.get("webhook")):
            return True

        results = []
        if channels.get("email") and settings.ALERT_EMAIL_TO:
            results.append(await self._send_email(alert_data))
        if channels.get("webhook") and settings.WEBHOOK_URL:
            results.append(await self._send_webhook(alert_data))

        if not results:
            logger.debug(
                "High-severity alert raised but no notification channel is "
                "configured (set ALERT_EMAIL_TO and/or WEBHOOK_URL)"
            )
            return True
        return any(results)

    async def send_email(self, alert_data: Dict) -> bool:
        """Deliver one email; True on success. Used by the outbox dispatcher."""
        if not (settings.ALERT_EMAIL_TO and settings.SMTP_HOST):
            logger.debug("Email channel not configured; dropping notification")
            return False
        return await self._send_email(alert_data)

    async def send_webhook(self, alert_data: Dict) -> bool:
        """Deliver one webhook; True on success. Used by the outbox dispatcher."""
        if not settings.WEBHOOK_URL:
            return False
        return await self._send_webhook(alert_data)

    async def _send_email(self, alert_data: Dict) -> bool:
        # smtplib is synchronous; calling it inline blocked the event loop for
        # the full duration of the SMTP conversation.
        return await asyncio.to_thread(self._send_email_blocking, alert_data)

    def _send_email_blocking(self, alert_data: Dict) -> bool:
        try:
            msg = MIMEMultipart("alternative")
            severity = str(alert_data.get("severity", "unknown")).upper()
            msg["Subject"] = (
                f"[HoneySentinel] {severity} Alert: "
                f"{alert_data.get('title', '')}"
            )
            msg["From"] = settings.ALERT_EMAIL_FROM
            msg["To"] = settings.ALERT_EMAIL_TO
            msg.attach(MIMEText(self._format_email_body(alert_data), "html"))

            with smtplib.SMTP(
                settings.SMTP_HOST, settings.SMTP_PORT, timeout=20
            ) as server:
                server.starttls()
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.send_message(msg)

            logger.info("Alert email sent for: %s", alert_data.get("title"))
            return True
        except Exception as exc:
            logger.error("Failed to send alert email: %s", exc)
            return False

    async def _send_webhook(self, alert_data: Dict) -> bool:
        try:
            payload = {
                "source": "HoneySentinel",
                "event_type": (
                    "system_alert" if alert_data.get("kind") == "system"
                    else f"{alert_data.get('severity', 'high')}_severity_alert"
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": alert_data,
            }
            body = json.dumps(payload, default=str)
            headers = {"Content-Type": "application/json"}

            # Let the receiver verify the alert really came from us.
            secret = settings.WEBHOOK_SECRET
            if secret:
                headers["X-HoneySentinel-Signature"] = hmac.new(
                    secret.encode(), body.encode(), hashlib.sha256
                ).hexdigest()

            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    settings.WEBHOOK_URL, content=body, headers=headers
                )
                response.raise_for_status()

            logger.info("Alert webhook delivered")
            return True
        except Exception as exc:
            logger.error("Failed to send alert webhook: %s", exc)
            return False

    def _format_email_body(self, alert_data: Dict) -> str:
        severity = str(alert_data.get("severity", "unknown")).upper()
        color = SEVERITY_COLORS.get(severity, "#6b7280")

        geo = alert_data.get("geo") or {}
        geo_str = (
            f"{geo.get('city') or 'Unknown'}, "
            f"{geo.get('country_name') or geo.get('country') or 'Unknown'}"
        )

        techniques = alert_data.get("mitre_techniques") or []
        mitre_str = (
            ", ".join(
                f"{t.get('id', '')}: {t.get('name', '')}"
                for t in techniques
                if isinstance(t, dict)
            )
            or "N/A"
        )

        rows = [
            ("Severity", severity),
            ("Title", alert_data.get("title", "N/A")),
            ("Description", alert_data.get("description", "N/A")),
            ("Attacker IP", alert_data.get("attacker_ip", "N/A")),
            ("Location", geo_str),
            ("Attack Category", alert_data.get("attack_category", "N/A")),
            ("Attacker Profile", alert_data.get("attacker_profile", "N/A")),
            ("MITRE ATT&CK", mitre_str),
            (
                "Detected Tools",
                ", ".join(alert_data.get("detected_tools") or []) or "N/A",
            ),
            (
                "Timestamp",
                alert_data.get("timestamp")
                or datetime.now(timezone.utc).isoformat(),
            ),
        ]

        body_rows = "".join(
            f'<tr><td style="padding:5px 15px 5px 0;color:#8b949e;">{_esc(label)}:</td>'
            f'<td style="padding:5px;">{_esc(value)}</td></tr>'
            for label, value in rows
        )

        return f"""
        <html><body style="font-family: monospace; background: #0d1117; color: #e6edf3; padding: 20px;">
            <h2 style="color: {color};">HoneySentinel Alert</h2>
            <table style="border-collapse: collapse;">{body_rows}</table>
            <br>
            <p style="color: #8b949e; font-size: 12px;">This is an automated alert from HoneySentinel AI.</p>
        </body></html>
        """


alerting_service = AlertingService()
