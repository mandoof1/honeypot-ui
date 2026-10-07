"""Background work for the single backend process.

Four loops, all started from the application lifespan when
BACKGROUND_WORKERS is on (the `backend` service; never the multi-worker
`ingest` service, which would run four copies of each):

* enrichment — drains the LLM queue (services/enrichment.py);
* outbox — delivers queued notifications (services/outbox.py);
* liveness — every minute, raises a system alert for an engine that stopped
  reporting or is running out of disk, and resolves it when it recovers;
* housekeeping — hourly: retention, orphaned payload samples, expired login
  codes, outbox pruning, and re-queueing payload analyses a restart left
  pending.

Every loop catches and logs its own exceptions with a traceback; a failing
tick must never take the API down with it.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import async_session_factory
from app.models import (
    AttackSeverity,
    AuditLog,
    HoneypotNode,
    HoneypotSession,
    PayloadSample,
    SessionArtifact,
)
from app.services import alerts as alert_service
from app.services import enrichment, outbox

logger = logging.getLogger(__name__)

LIVENESS_INTERVAL = 60
OUTBOX_INTERVAL = 20
HOUSEKEEPING_INTERVAL = 3600

_tasks: list[asyncio.Task] = []
_stop = asyncio.Event()
_started_at: Optional[datetime] = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    """SQLite hands back naive datetimes; Postgres aware ones. Compare in UTC."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def started_at() -> Optional[datetime]:
    return _started_at


async def start() -> None:
    global _started_at
    settings = get_settings()
    if not settings.BACKGROUND_WORKERS:
        logger.info("Background workers disabled in this process")
        return
    _stop.clear()
    _started_at = _now()
    _tasks.extend(
        [
            asyncio.create_task(enrichment.worker(_stop), name="enrichment-worker"),
            asyncio.create_task(_loop("outbox", OUTBOX_INTERVAL, _outbox_tick), name="outbox"),
            asyncio.create_task(_loop("liveness", LIVENESS_INTERVAL, liveness_tick), name="liveness"),
            asyncio.create_task(
                _loop("housekeeping", HOUSEKEEPING_INTERVAL, housekeeping_tick, run_immediately=False),
                name="housekeeping",
            ),
        ]
    )
    logger.info("Background workers started: enrichment, outbox, liveness, housekeeping")


async def stop() -> None:
    _stop.set()
    for task in _tasks:
        task.cancel()
    for task in _tasks:
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    _tasks.clear()


async def _loop(name: str, interval: float, tick, run_immediately: bool = True) -> None:
    if not run_immediately:
        await _sleep(interval)
    while not _stop.is_set():
        try:
            async with async_session_factory() as db:
                await tick(db)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Background task %s failed; continuing", name)
        await _sleep(interval)


async def _sleep(seconds: float) -> None:
    try:
        await asyncio.wait_for(_stop.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


async def _outbox_tick(db: AsyncSession) -> None:
    counts = await outbox.dispatch_due(db)
    if any(counts.values()):
        logger.info("Notification outbox: %s", counts)


# --------------------------------------------------------------------------
# Engine liveness

async def liveness_tick(db: AsyncSession, now: Optional[datetime] = None) -> dict:
    """Raise or resolve system alerts for every active node. Returns a summary."""
    settings = get_settings()
    now = now or _now()
    stale_after = timedelta(seconds=settings.NODE_OFFLINE_ALERT_SECONDS)
    nodes = (
        await db.execute(select(HoneypotNode).where(HoneypotNode.is_active.is_(True)))
    ).scalars().all()

    raised = resolved = 0
    for node in nodes:
        if node.last_heartbeat is None:
            # Registered by an engine that never sent a heartbeat (older
            # version) — nothing to judge.
            continue
        age = now - _aware(node.last_heartbeat)
        if age > stale_after and not node.offline_alerted:
            minutes = int(age.total_seconds() // 60)
            await alert_service.raise_system_alert(
                db,
                key=f"node_offline:{node.name}",
                severity=AttackSeverity.HIGH,
                title=f"Engine {node.name} stopped reporting",
                description=(
                    f"No heartbeat from honeypot engine '{node.name}' for {minutes} minute(s). "
                    f"Its decoys may be down, or it cannot reach the API. "
                    f"Last report: {node.last_heartbeat.isoformat()}."
                ),
                node=node,
            )
            node.offline_alerted = True
            raised += 1
        elif age <= stale_after and node.offline_alerted:
            await alert_service.resolve_system_alert(
                db, f"node_offline:{node.name}", f"Engine reported again at {now.isoformat()}."
            )
            node.offline_alerted = False
            resolved += 1

        status = node.last_status if isinstance(node.last_status, dict) else {}
        disk = status.get("disk") if isinstance(status.get("disk"), dict) else None
        if disk and disk.get("total_bytes"):
            free_fraction = float(disk.get("free_bytes") or 0) / float(disk["total_bytes"])
            key = f"node_disk:{node.name}"
            if free_fraction < settings.NODE_DISK_ALERT_FRACTION:
                if await alert_service.raise_system_alert(
                    db,
                    key=key,
                    severity=AttackSeverity.HIGH,
                    title=f"Engine {node.name} is low on disk",
                    description=(
                        f"{free_fraction:.1%} of {disk.get('path') or 'its data volume'} is free "
                        f"({int(disk.get('free_bytes') or 0) // (1024 * 1024)} MiB). Captured sessions "
                        f"and uploads stop being written when it fills."
                    ),
                    node=node,
                ):
                    raised += 1
            else:
                resolved += await alert_service.resolve_system_alert(
                    db, key, f"Disk back to {free_fraction:.0%} free."
                )
        spool = status.get("spool_pending")
        if isinstance(spool, int):
            key = f"node_spool:{node.name}"
            if spool >= 100:
                if await alert_service.raise_system_alert(
                    db,
                    key=key,
                    severity=AttackSeverity.MEDIUM,
                    title=f"Engine {node.name} has {spool} sessions waiting to be ingested",
                    description=(
                        "The engine captured sessions it could not deliver to the API and is "
                        "retrying from its local spool. Check the ingest service."
                    ),
                    node=node,
                ):
                    raised += 1
            elif spool == 0:
                resolved += await alert_service.resolve_system_alert(db, key, "Spool drained.")
    await db.commit()
    return {"nodes": len(nodes), "raised": raised, "resolved": resolved}


# --------------------------------------------------------------------------
# Housekeeping

async def housekeeping_tick(db: AsyncSession) -> dict:
    summary = {}
    summary["sessions_deleted"] = await purge_old_sessions(db)
    summary["samples_deleted"] = await purge_orphan_samples(db)
    summary["audit_deleted"] = await purge_old_audit(db)
    summary["outbox_pruned"] = await outbox.prune(db)
    summary["otp_cleaned"] = await _cleanup_otp(db)
    summary["payloads_requeued"] = await _requeue_pending_payloads(db)
    summary["refresh_tokens_pruned"] = await _prune_refresh_tokens(db)
    if any(summary.values()):
        logger.info("Housekeeping: %s", summary)
    return summary


async def purge_old_sessions(db: AsyncSession) -> int:
    """Delete sessions past SESSION_RETENTION_DAYS. 0 keeps everything.

    Alerts, indicators and artifacts cascade in the database (migration 008),
    so this is one statement rather than an ORM walk over every child row.
    """
    days = get_settings().SESSION_RETENTION_DAYS
    if days <= 0:
        return 0
    cutoff = _now() - timedelta(days=days)
    result = await db.execute(
        delete(HoneypotSession).where(HoneypotSession.started_at < cutoff)
    )
    await db.commit()
    return result.rowcount or 0


async def purge_orphan_samples(db: AsyncSession) -> int:
    """Samples no remaining session refers to (their sessions were retained out)."""
    if get_settings().SESSION_RETENTION_DAYS <= 0:
        return 0
    referenced = select(SessionArtifact.sample_id)
    result = await db.execute(
        delete(PayloadSample).where(PayloadSample.id.not_in(referenced))
    )
    await db.commit()
    return result.rowcount or 0


async def purge_old_audit(db: AsyncSession) -> int:
    days = get_settings().AUDIT_RETENTION_DAYS
    if days <= 0:
        return 0
    cutoff = _now() - timedelta(days=days)
    result = await db.execute(delete(AuditLog).where(AuditLog.created_at < cutoff))
    await db.commit()
    return result.rowcount or 0


async def _cleanup_otp(db: AsyncSession) -> int:
    from app.models import OTPVerification

    before = (await db.execute(select(func.count(OTPVerification.id)))).scalar() or 0
    await db.execute(delete(OTPVerification).where(OTPVerification.expires_at < _now()))
    await db.commit()
    after = (await db.execute(select(func.count(OTPVerification.id)))).scalar() or 0
    return max(0, before - after)


async def _prune_refresh_tokens(db: AsyncSession) -> int:
    """Expired rows, and revoked rows older than a week (kept briefly so a
    reuse attempt can still be recognised and audited)."""
    from app.models import RefreshToken

    now = _now()
    result = await db.execute(
        delete(RefreshToken).where(
            (RefreshToken.expires_at < now)
            | (RefreshToken.revoked_at.isnot(None)) & (RefreshToken.revoked_at < now - timedelta(days=7))
        )
    )
    await db.commit()
    return result.rowcount or 0


async def _requeue_pending_payloads(db: AsyncSession) -> int:
    """Samples a restart left in 'pending' never got their detached analysis."""
    from app.services import payload_enrichment

    ids = (
        await db.execute(
            select(PayloadSample.id).where(PayloadSample.analysis_status == "pending").limit(50)
        )
    ).scalars().all()
    if ids:
        payload_enrichment.schedule(list(ids))
    return len(ids)
