from __future__ import annotations
import json
import smtplib
import httpx
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional
from app.core.config import get_settings
from app.schemas import AttackSeverity

settings = get_settings()
logger = logging.getLogger(__name__)


class AlertingService:
    async def send_alert(self, alert_data: Dict) -> bool:
        severity = alert_data.get("severity", "low")
        results = []

        if AttackSeverity(severity) in (AttackSeverity.HIGH, AttackSeverity.CRITICAL):
            if settings.ALERT_EMAIL_TO:
                results.append(await self._send_email(alert_data))
            if settings.WEBHOOK_URL:
                results.append(await self._send_webhook(alert_data))

        return any(results) if results else True

    async def _send_email(self, alert_data: Dict) -> bool:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[HoneySentinel] {alert_data.get('severity', 'UNKNOWN').upper()} Alert: {alert_data.get('title', '')}"
            msg["From"] = settings.ALERT_EMAIL_FROM
            msg["To"] = settings.ALERT_EMAIL_TO

            body = self._format_email_body(alert_data)
            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                server.starttls()
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(settings.ALERT_EMAIL_FROM, settings.ALERT_EMAIL_TO, msg.as_string())

            logger.info(f"Alert email sent for: {alert_data.get('title')}")
            return True
        except Exception as e:
            logger.error(f"Failed to send alert email: {e}")
            return False

    async def _send_webhook(self, alert_data: Dict) -> bool:
        try:
            payload = {
                "source": "HoneySentinel",
                "event_type": "high_severity_alert",
                "timestamp": datetime.utcnow().isoformat(),
                "data": alert_data,
            }
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    settings.WEBHOOK_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()

            logger.info(f"Alert webhook sent to {settings.WEBHOOK_URL}")
            return True
        except Exception as e:
            logger.error(f"Failed to send alert webhook: {e}")
            return False

    def _format_email_body(self, alert_data: Dict) -> str:
        severity = alert_data.get("severity", "unknown").upper()
        color = {"CRITICAL": "#f85149", "HIGH": "#e3692a", "MEDIUM": "#f0ad4e", "LOW": "#3fb950"}.get(severity, "#6b7280")

        geo = alert_data.get("geo", {})
        geo_str = f"{geo.get('city', 'Unknown')}, {geo.get('country_name', geo.get('country', 'Unknown'))}"

        mitre = alert_data.get("mitre_techniques", [])
        mitre_str = ", ".join([f"{t.get('id', '')}: {t.get('name', '')}" for t in mitre]) if mitre else "N/A"

        return f"""
        <html><body style="font-family: monospace; background: #0d1117; color: #e6edf3; padding: 20px;">
            <h2 style="color: {color};">HoneySentinel Alert</h2>
            <table style="border-collapse: collapse;">
                <tr><td style="padding: 5px 15px 5px 0; color: #8b949e;">Severity:</td>
                    <td style="padding: 5px; color: {color}; font-weight: bold;">{severity}</td></tr>
                <tr><td style="padding: 5px 15px 5px 0; color: #8b949e;">Title:</td>
                    <td style="padding: 5px;">{alert_data.get('title', 'N/A')}</td></tr>
                <tr><td style="padding: 5px 15px 5px 0; color: #8b949e;">Description:</td>
                    <td style="padding: 5px;">{alert_data.get('description', 'N/A')}</td></tr>
                <tr><td style="padding: 5px 15px 5px 0; color: #8b949e;">Attacker IP:</td>
                    <td style="padding: 5px;">{alert_data.get('attacker_ip', 'N/A')}</td></tr>
                <tr><td style="padding: 5px 15px 5px 0; color: #8b949e;">Location:</td>
                    <td style="padding: 5px;">{geo_str}</td></tr>
                <tr><td style="padding: 5px 15px 5px 0; color: #8b949e;">Attack Category:</td>
                    <td style="padding: 5px;">{alert_data.get('attack_category', 'N/A')}</td></tr>
                <tr><td style="padding: 5px 15px 5px 0; color: #8b949e;">Attacker Profile:</td>
                    <td style="padding: 5px;">{alert_data.get('attacker_profile', 'N/A')}</td></tr>
                <tr><td style="padding: 5px 15px 5px 0; color: #8b949e;">MITRE ATT&CK:</td>
                    <td style="padding: 5px;">{mitre_str}</td></tr>
                <tr><td style="padding: 5px 15px 5px 0; color: #8b949e;">Detected Tools:</td>
                    <td style="padding: 5px;">{', '.join(alert_data.get('detected_tools', [])) or 'N/A'}</td></tr>
                <tr><td style="padding: 5px 15px 5px 0; color: #8b949e;">Timestamp:</td>
                    <td style="padding: 5px;">{alert_data.get('timestamp', datetime.utcnow().isoformat())}</td></tr>
            </table>
            <br>
            <p style="color: #8b949e; font-size: 12px;">This is an automated alert from HoneySentinel AI.</p>
        </body></html>
        """


alerting_service = AlertingService()
