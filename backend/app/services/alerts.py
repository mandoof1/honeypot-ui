"""Raising alerts: grouping, suppression, and handing delivery to the outbox.

Two kinds of alert share the table. A *session* alert is the pipeline's
verdict on one capture. A *system* alert is about the platform itself: an
engine that stopped reporting, a disk filling up. The second kind has no
session and used to have nowhere to live, so an engine could be down for a
day and the dashboard would simply show fewer sessions.

Grouping: the same address replaying the same script every few minutes used
to raise a fresh alert each time. Repeats inside a fixed window are folded
into the open alert: counted, their session ids kept, and the alert updated
and re-notified when a repeat is more serious than what it was showing.

Delivery: email and webhook sends go to the outbox table, not to the network
from inside the ingest request. The dispatcher in the backend service retries
them with backoff and keeps the last error.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
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

#: Session ids remembered per alert. An address that replays one script for
#: days would otherwise grow the row without bound.
MAX_SESSION_IDS = 500

#: A later session takes over an alert at the same severity only when it
#: scores at least this much higher, so near-identical replays do not
#: re-notify.
LEAD_CHANGE_MARGIN = 1.0


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
    """The open alert of this group whose window is still running.

    The window is fixed from the alert's creation. It used to slide with
    every repeat (measured from ``last_seen_at``), so an address that kept
    coming back never opened a second alert however long it went on.
    """
    since = _now() - window
    row = await db.execute(
        select(Alert)
        .where(
            Alert.dedup_key == dedup_key,
            Alert.status.in_(OPEN_STATUSES),
            Alert.created_at >= since,
        )
        .order_by(Alert.id.desc())
        .limit(1)
    )
    return row.scalar_one_or_none()


async def _lead_score(db: AsyncSession, alert: Alert) -> float:
    """The severity score of the session an alert currently points at."""
    if alert.session_id is None:
        return 0.0
    signals = (
        await db.execute(select(HoneypotSession.signals).where(HoneypotSession.id == alert.session_id))
    ).scalar_one_or_none()
    try:
        return float((signals or {}).get("severity_score") or 0.0)
    except (TypeError, ValueError, AttributeError):
        return 0.0


def describe(category: str, profile: str, tools: List[str], rule_reason: str, source: str = "rules") -> str:
    """Why the alert exists, in the terms of what set the category.

    This used to quote a confidence percentage taken from the flow
    classifier even when the rules had replaced its verdict: "classified as
    exploitation with 97% confidence", where 97% was the forest's confidence
    that the session was benign.
    """
    layer = {
        "rules": "the rule layer",
        "triage": "the decision model's triage",
        "llm": "the language model's analysis",
    }.get(source, source)
    return (
        f"Session classified as {category} by {layer}. "
        + (f"Evidence: {rule_reason}. " if rule_reason else "")
        + f"Profile: {profile}. "
        f"Tools: {', '.join(tools) if tools else 'none'}."
    )


async def raise_session_alert(
    db: AsyncSession,
    *,
    session: HoneypotSession,
    severity: AttackSeverity,
    category: str,
    profile: str,
    tools: List[str],
    mitre_result: Dict,
    geo: Dict,
    decision: Optional[AlertDecision],
    rule_reason: str = "",
    confidence: float = 0.0,
    score: float = 0.0,
    source: str = "rules",
    group: str = "session",
    title: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict:
    """Raise, fold, or suppress an alert for an analysed session.

    One alert per source address and group inside a fixed window. A repeat
    is folded in: counted, and its session id kept. When the repeat is more
    serious than the session the alert was showing, the alert takes its
    severity, title, description and techniques and points at it, and the
    operator is notified again. An early brute-force alert no longer absorbs
    the compromise that follows it.

    ``group`` separates alerts that must not fold into the per-source one
    (a canary trigger, a honeytoken). ``score`` is the session's severity
    score, which orders sessions of equal severity. ``confidence`` is
    accepted for older callers and not used: the text states what set the
    category instead of a percentage.

    Returns a small dict describing what happened, for the ingest response
    and the tests: ``{"action": "created"|"grouped"|"suppressed", ...}``.
    The session must already be flushed (it needs an id).
    """
    settings = get_settings()

    # ``scanner_operator`` is only set when the session also behaved like a
    # scan (services/analysis.py): an address in a scanner's range that logs
    # in or runs commands is not labelled, and so is not suppressed here.
    if settings.ALERT_SUPPRESS_SCANNERS and session.scanner_operator:
        return {"action": "suppressed", "reason": f"scanner:{session.scanner_operator}"}

    attacker_ip = session.attacker_ip
    dedup_key = f"ip:{attacker_ip}|{group}"[:160]
    window = timedelta(minutes=max(0, settings.ALERT_DEDUP_WINDOW_MINUTES))
    now = _now()
    title = title or alert_title(category, attacker_ip)
    description = description or describe(category, profile, tools, rule_reason, source)

    lost_race = False
    for _ in range(3):
        existing = None
        if window.total_seconds() > 0:
            existing = await _open_alert(db, dedup_key, window)
        if existing is not None:
            return await _fold(
                db, existing, session, severity, score, title, description,
                category, profile, tools, mitre_result, geo, decision, now,
            )

        alert = Alert(
            session_id=session.id,
            kind="session",
            attacker_ip=attacker_ip,
            node_id=session.node_id,
            severity=severity,
            title=title[:500],
            description=description,
            mitre_tactics=mitre_result.get("tactic_ids", []),
            mitre_techniques=mitre_result.get("techniques", []),
            occurrences=1,
            last_seen_at=now,
            dedup_key=dedup_key,
            session_ids=[session.id],
            group_key=await _free_group_key(db, dedup_key, window, now, session.id, past_open=lost_race),
        )
        try:
            # A savepoint, so losing the race undoes only this insert and
            # not the session being ingested around it.
            async with db.begin_nested():
                db.add(alert)
                await db.flush()
        except IntegrityError:
            # Another ingest worker opened the same alert between the lookup
            # and the insert. Look again and fold into theirs.
            lost_race = True
            continue

        queued = queue_notifications(
            db,
            alert,
            _session_payload(alert, session, geo, category, profile, tools, mitre_result, decision),
            decision,
        )
        return {"action": "created", "alert_id": alert.id, "notifications_queued": queued}

    logger.warning("Could not open or join an alert for %s after three attempts", attacker_ip)
    return {"action": "failed", "reason": "concurrent alert creation"}


async def _free_group_key(
    db: AsyncSession, dedup_key: str, window: timedelta, now: datetime, session_id: int,
    past_open: bool = False,
) -> str:
    """The unique key a new alert of this group takes.

    Workers that reach this at the same moment compute the same key (the
    group and the clock-aligned window it falls in), and the unique index
    lets one insert win; the loser looks again and folds into the winner's
    alert. A key held by an *open* alert is therefore returned as it is: the
    insert is meant to collide. A key held by a closed alert — an analyst
    resolved it, and the source came back inside the same window — gets the
    next free suffix, so the new activity opens a new alert. ``past_open``
    is for the caller that already collided and still found nothing to fold
    into: it takes a suffix regardless.
    """
    seconds = int(window.total_seconds())
    if seconds <= 0:
        # Grouping is off: every session's alert stands alone.
        return f"{dedup_key}|s:{session_id}"[:200]
    base = f"{dedup_key}|w:{int(now.timestamp()) // seconds}"[:190]
    holders = dict(
        (
            await db.execute(
                select(Alert.group_key, Alert.status).where(Alert.group_key.like(base + "%"))
            )
        ).all()
    )
    if base not in holders:
        return base
    if not past_open:
        still_open = sorted(key for key, status in holders.items() if status in OPEN_STATUSES)
        if still_open:
            return still_open[-1]
    suffix = 2
    while f"{base}|r{suffix}" in holders:
        suffix += 1
    return f"{base}|r{suffix}"


async def _fold(
    db, existing: Alert, session, severity, score, title, description,
    category, profile, tools, mitre_result, geo, decision, now,
) -> Dict:
    existing.occurrences = (existing.occurrences or 1) + 1
    existing.last_seen_at = now
    ids = [i for i in (existing.session_ids or []) if isinstance(i, int)]
    if not ids and existing.session_id is not None:
        ids = [existing.session_id]
    if session.id not in ids:
        ids.append(session.id)
    # Reassigned, not appended in place: the ORM only writes a JSON column
    # back when it is given a new value.
    existing.session_ids = ids[-MAX_SESSION_IDS:]

    escalated = SEVERITY_RANK[severity] > SEVERITY_RANK[existing.severity]
    lead_changed = escalated
    if not escalated and severity == existing.severity and session.id != existing.session_id:
        lead_changed = score >= await _lead_score(db, existing) + LEAD_CHANGE_MARGIN

    if lead_changed:
        existing.severity = severity
        existing.title = title[:500]
        existing.description = description
        existing.session_id = session.id
        # Keep the MITRE view current when the newer session showed more.
        existing.mitre_tactics = mitre_result.get("tactic_ids", []) or existing.mitre_tactics
        existing.mitre_techniques = mitre_result.get("techniques", []) or existing.mitre_techniques
    await db.flush()

    if lead_changed:
        queue_notifications(
            db,
            existing,
            _session_payload(existing, session, geo, category, profile, tools, mitre_result, decision)
            | {"escalated": escalated, "lead_changed": True},
            decision,
        )
    return {
        "action": "grouped",
        "alert_id": existing.id,
        "occurrences": existing.occurrences,
        "escalated": escalated,
        "lead_changed": lead_changed,
    }


#: Alert titles per category. "Benign attack from ..." contradicted itself:
#: a session the classifier calls benign can still raise an alert on its
#: severity or anomaly score.
_TITLES = {
    "benign": "Suspicious activity from {ip}",
    "reconnaissance": "Reconnaissance from {ip}",
    "exploitation": "Exploitation attempt from {ip}",
    "exfiltration": "Data exfiltration from {ip}",
}


def alert_title(category: str, attacker_ip: str) -> str:
    template = _TITLES.get((category or "").lower(), "Suspicious activity from {ip}")
    return template.format(ip=attacker_ip)


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
        "session_ids": list(alert.session_ids or []),
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
