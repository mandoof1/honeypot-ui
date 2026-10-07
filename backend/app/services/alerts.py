"""Raising alerts: grouping, suppression, and handing delivery to the outbox.

Two kinds of alert share the table. A *session* alert is the pipeline's
verdict on one capture. A *system* alert is about the platform itself: an
engine that stopped reporting, a disk filling up. The second kind has no
session and used to have nowhere to live, so an engine could be down for a
day and the dashboard would simply show fewer sessions.

Grouping: the same address replaying the same script every few minutes used
to raise a fresh alert each time. Repeats inside the dedup window now bump the
open alert's occurrence count, and only a severity escalation re-notifies.

Delivery: email and webhook sends go to the outbox table, not to the network
from inside the ingest request. The dispatcher in the backend service retries
them with backoff and keeps the last error.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import (
    Alert,
    AlertStatus,
    AttackSeverity,
    HoneypotNode,
    HoneypotSession,
    NotificationOutbox,
)
from app.services.thresholds import SEVERITY_RANK, AlertDecision

logger = logging.getLogger(__name__)

OPEN_STATUSES = (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _channels(decision: Optional[AlertDecision]) -> List[str]:
    settings = get_settings()
    channels = []
    if decision is None or decision.email:
        if settings.ALERT_EMAIL_TO and settings.SMTP_HOST:
            channels.append("email")
    if decision is None or decision.webhook:
        if settings.WEBHOOK_URL:
            channels.append("webhook")
    return channels


def queue_notifications(db: AsyncSession, alert: Alert, payload: Dict, decision=None) -> int:
    """Add one outbox row per configured channel. Returns how many."""
    count = 0
    for channel in _channels(decision):
        db.add(
            NotificationOutbox(
                alert_id=alert.id,
                channel=channel,
                payload=payload,
                status="pending",
                attempts=0,
                next_attempt_at=_now(),
            )
        )
        count += 1
    return count


async def _open_alert(db: AsyncSession, dedup_key: str, window: timedelta) -> Optional[Alert]:
    since = _now() - window
    row = await db.execute(
        select(Alert)
        .where(
            Alert.dedup_key == dedup_key,
            Alert.status.in_(OPEN_STATUSES),
            Alert.last_seen_at >= since,
        )
        .order_by(Alert.id.desc())
        .limit(1)
    )
    return row.scalar_one_or_none()


async def raise_session_alert(
    db: AsyncSession,
    *,
    session: HoneypotSession,
    severity: AttackSeverity,
    category: str,
    confidence: float,
    profile: str,
    tools: List[str],
    mitre_result: Dict,
    geo: Dict,
    decision: AlertDecision,
    rule_reason: str = "",
) -> Dict:
    """Raise, fold, or suppress an alert for a freshly analysed session.

    Returns a small dict describing what happened, for the ingest response
    and the tests: ``{"action": "created"|"grouped"|"suppressed", ...}``.
    The session must already be flushed (it needs an id).
    """
    settings = get_settings()

    if settings.ALERT_SUPPRESS_SCANNERS and session.scanner_operator:
        return {"action": "suppressed", "reason": f"scanner:{session.scanner_operator}"}

    attacker_ip = session.attacker_ip
    dedup_key = f"ip:{attacker_ip}|{category}"[:160]
    window = timedelta(minutes=max(0, settings.ALERT_DEDUP_WINDOW_MINUTES))
    now = _now()

    existing = None
    if window.total_seconds() > 0:
        existing = await _open_alert(db, dedup_key, window)

    description = (
        f"Session classified as {category} with {confidence:.1%} confidence. "
        f"Profile: {profile}. "
        f"Tools: {', '.join(tools) if tools else 'none'}."
        + (f" Why: {rule_reason}." if rule_reason else "")
    )

    if existing is not None:
        existing.occurrences = (existing.occurrences or 1) + 1
        existing.last_seen_at = now
        escalated = SEVERITY_RANK[severity] > SEVERITY_RANK[existing.severity]
        if escalated:
            existing.severity = severity
            existing.description = description
            # Keep the MITRE view current when the newer session showed more.
            existing.mitre_tactics = mitre_result.get("tactic_ids", []) or existing.mitre_tactics
            existing.mitre_techniques = (
                mitre_result.get("techniques", []) or existing.mitre_techniques
            )
        await db.flush()
        result = {
            "action": "grouped",
            "alert_id": existing.id,
            "occurrences": existing.occurrences,
            "escalated": escalated,
        }
        if escalated:
            queue_notifications(
                db,
                existing,
                _session_payload(existing, session, geo, category, profile, tools, mitre_result, decision)
                | {"escalated_from": None},
                decision,
            )
        return result

    alert = Alert(
        session_id=session.id,
        kind="session",
        attacker_ip=attacker_ip,
        node_id=session.node_id,
        severity=severity,
        title=f"{category.title()} attack from {attacker_ip}",
        description=description,
        mitre_tactics=mitre_result.get("tactic_ids", []),
        mitre_techniques=mitre_result.get("techniques", []),
        occurrences=1,
        last_seen_at=now,
        dedup_key=dedup_key,
    )
    db.add(alert)
    await db.flush()

    queued = queue_notifications(
        db,
        alert,
        _session_payload(alert, session, geo, category, profile, tools, mitre_result, decision),
        decision,
    )
    return {"action": "created", "alert_id": alert.id, "notifications_queued": queued}


def _session_payload(alert, session, geo, category, profile, tools, mitre_result, decision) -> Dict:
    return {
        "alert_id": alert.id,
        "kind": "session",
        "severity": alert.severity.value,
        "title": alert.title,
        "description": alert.description,
        "attacker_ip": session.attacker_ip,
        "geo": geo,
        "attack_category": category,
        "attacker_profile": profile,
        "detected_tools": list(tools or []),
        "mitre_techniques": mitre_result.get("techniques", []),
        "timestamp": session.started_at.isoformat() if session.started_at else None,
        "session_uuid": session.session_uuid,
        "session_id": session.id,
        "occurrences": alert.occurrences,
        "matched_thresholds": list(getattr(decision, "matched", []) or []),
    }


async def raise_system_alert(
    db: AsyncSession,
    *,
    key: str,
    severity: AttackSeverity,
    title: str,
    description: str,
    node: Optional[HoneypotNode] = None,
    notify: bool = True,
) -> Optional[Alert]:
    """Open a system alert unless one with the same key is already open.

    Returns the new alert, or None when it was already open (so callers can
    tell "raised" from "still raised").
    """
    dedup_key = f"system:{key}"[:160]
    open_row = await db.execute(
        select(Alert)
        .where(Alert.dedup_key == dedup_key, Alert.status.in_(OPEN_STATUSES))
        .limit(1)
    )
    existing = open_row.scalar_one_or_none()
    if existing is not None:
        existing.last_seen_at = _now()
        existing.occurrences = (existing.occurrences or 1) + 1
        return None

    alert = Alert(
        session_id=None,
        kind="system",
        node_id=node.id if node else None,
        severity=severity,
        title=title[:500],
        description=description,
        mitre_tactics=[],
        mitre_techniques=[],
        occurrences=1,
        last_seen_at=_now(),
        dedup_key=dedup_key,
    )
    db.add(alert)
    await db.flush()
    if notify:
        queue_notifications(
            db,
            alert,
            {
                "alert_id": alert.id,
                "kind": "system",
                "severity": severity.value,
                "title": alert.title,
                "description": description,
                "node": node.name if node else None,
                "timestamp": _now().isoformat(),
            },
        )
    logger.warning("System alert raised: %s", title)
    return alert


async def resolve_system_alert(db: AsyncSession, key: str, note: str) -> int:
    """Resolve every open system alert with this key. Returns how many."""
    dedup_key = f"system:{key}"[:160]
    rows = (
        await db.execute(
            select(Alert).where(Alert.dedup_key == dedup_key, Alert.status.in_(OPEN_STATUSES))
        )
    ).scalars().all()
    for alert in rows:
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = _now()
        alert.notes = (f"{alert.notes}\n" if alert.notes else "") + note
    return len(rows)
