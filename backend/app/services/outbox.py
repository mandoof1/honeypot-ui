"""Delivering queued notifications with retries.

Rows arrive from services/alerts.py. This dispatcher, run by the scheduler in
the backend service, sends what is due, records the outcome, and backs off
on failure (1, 2, 4 … minutes, capped) until NOTIFICATION_MAX_ATTEMPTS.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import NotificationOutbox
from app.services.alerting import alerting_service

logger = logging.getLogger(__name__)

BATCH = 20
MAX_BACKOFF_MINUTES = 60


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def dispatch_due(db: AsyncSession) -> dict:
    """Send every due pending row once. Returns counts."""
    settings = get_settings()
    now = _now()
    rows = (
        await db.execute(
            select(NotificationOutbox)
            .where(
                NotificationOutbox.status == "pending",
                (NotificationOutbox.next_attempt_at.is_(None))
                | (NotificationOutbox.next_attempt_at <= now),
            )
            .order_by(NotificationOutbox.id.asc())
            .limit(BATCH)
        )
    ).scalars().all()

    sent = failed = retried = 0
    for row in rows:
        row.attempts = (row.attempts or 0) + 1
        try:
            if row.channel == "email":
                ok = await alerting_service.send_email(row.payload)
            elif row.channel == "webhook":
                ok = await alerting_service.send_webhook(row.payload)
            else:
                ok = False
                row.last_error = f"unknown channel {row.channel!r}"
        except Exception as exc:  # the senders already log; keep the reason
            ok = False
            row.last_error = str(exc)[:500]

        if ok:
            row.status = "sent"
            row.sent_at = _now()
            row.last_error = None
            sent += 1
        elif row.attempts >= settings.NOTIFICATION_MAX_ATTEMPTS:
            row.status = "failed"
            row.last_error = row.last_error or "delivery failed"
            failed += 1
        else:
            minutes = min(MAX_BACKOFF_MINUTES, 2 ** (row.attempts - 1))
            row.next_attempt_at = _now() + timedelta(minutes=minutes)
            row.last_error = row.last_error or "delivery failed"
            retried += 1
    if rows:
        await db.commit()
    return {"sent": sent, "failed": failed, "retried": retried}


async def prune(db: AsyncSession) -> int:
    """Drop delivered and dead rows older than the retention window."""
    days = get_settings().OUTBOX_RETENTION_DAYS
    if days <= 0:
        return 0
    cutoff = _now() - timedelta(days=days)
    result = await db.execute(
        delete(NotificationOutbox).where(
            NotificationOutbox.status.in_(["sent", "failed"]),
            NotificationOutbox.created_at < cutoff,
        )
    )
    await db.commit()
    return result.rowcount or 0


async def backlog(db: AsyncSession) -> dict:
    pending = (
        await db.execute(
            select(func.count(NotificationOutbox.id)).where(NotificationOutbox.status == "pending")
        )
    ).scalar() or 0
    dead = (
        await db.execute(
            select(func.count(NotificationOutbox.id)).where(NotificationOutbox.status == "failed")
        )
    ).scalar() or 0
    return {"pending": pending, "failed": dead}
