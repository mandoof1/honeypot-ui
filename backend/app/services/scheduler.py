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
  pending;
* models — hourly: fits the cluster model and the anomaly detector on the
  stored sessions once there are enough, refits them when due, and
  re-assigns the stored rows after each fit (ai/maintenance.py).

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
            asyncio.create_task(_models_loop(), name="models"),
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


# --------------------------------------------------------------------------
# Unsupervised models: fit when there is enough data, refit when due

MODELS_INTERVAL = 3600
#: The first look comes soon after start-up, so a deployment that already
#: holds enough sessions does not wait an hour for its first fit.
MODELS_FIRST_DELAY = 120


async def _models_loop() -> None:
    await _sleep(MODELS_FIRST_DELAY)
    await _loop("models", MODELS_INTERVAL, models_tick)


async def models_tick(db: AsyncSession) -> dict:
    """Fit or refit the cluster model and the anomaly detector if due.

    Both were manual commands only. Clustering reported "not fitted" on any
    deployment where nobody ran one, and the anomaly detector stayed on its
    synthetic bootstrap for good. The ingest workers pick a new model file
    up by its modification time; the stored rows are re-assigned here.
    """
    from app.ai import maintenance
    from app.ai.config import get_analysis_settings

    if not get_analysis_settings().MODEL_REFIT_ENABLED:
        return {}
    summary = {}
    clusters = await maintenance.maintain_clusters(db)
    if clusters:
        summary["clusters"] = {k: clusters[k] for k in ("k", "silhouette", "n", "backfilled")}
    anomaly = await maintenance.maintain_anomaly(db)
    if anomaly:
        summary["anomaly"] = {k: anomaly[k] for k in ("n", "contamination", "backfilled")}
    else:
        # Until a real fit exists, rows flagged by the bootstrap are cleared.
        cleared = await maintenance.mark_anomaly_uncalibrated(db)
        if cleared:
            summary["anomaly_flags_cleared"] = cleared
    if summary:
        logger.info("Models: %s", summary)
    return summary


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
        # Each node on its own: the status report is whatever that engine
        # sent, and one engine sending nonsense must not stop the check for
        # every other engine (a non-numeric disk figure used to do that, on
        # every tick, for as long as the report stayed stored).
        try:
            node_raised, node_resolved = await _check_node(db, node, now, stale_after, settings)
        except Exception:
            logger.exception("Liveness check failed for engine %s; continuing", node.name)
            continue
        raised += node_raised
        resolved += node_resolved
    await db.commit()
    return {"nodes": len(nodes), "raised": raised, "resolved": resolved}


def _number(value) -> Optional[float]:
    """A finite, non-negative number from an engine's report, or None."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    if number != number or number in (float("inf"), float("-inf")) or number < 0:
        return None
    return number


async def _check_node(
    db: AsyncSession, node: HoneypotNode, now: datetime, stale_after: timedelta, settings
) -> tuple[int, int]:
    """Raise or resolve one node's system alerts. Returns (raised, resolved)."""
    raised = resolved = 0
    if node.last_heartbeat is None:
        # Registered by an engine that never sent a heartbeat (older
        # version) — nothing to judge.
        return raised, resolved

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
    disk = status.get("disk") if isinstance(status.get("disk"), dict) else {}
    total_bytes = _number(disk.get("total_bytes"))
    free_bytes = _number(disk.get("free_bytes"))
    if total_bytes and free_bytes is not None:
        free_fraction = min(free_bytes / total_bytes, 1.0)
        key = f"node_disk:{node.name}"
        if free_fraction < settings.NODE_DISK_ALERT_FRACTION:
            if await alert_service.raise_system_alert(
                db,
                key=key,
                severity=AttackSeverity.HIGH,
                title=f"Engine {node.name} is low on disk",
                description=(
                    f"{free_fraction:.1%} of {str(disk.get('path') or 'its data volume')[:200]} is free "
                    f"({int(free_bytes) // (1024 * 1024)} MiB). Captured sessions "
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
    if isinstance(spool, int) and not isinstance(spool, bool):
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
    return raised, resolved


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

    from app.services.otp import OTP_RETENTION

    before = (await db.execute(select(func.count(OTPVerification.id)))).scalar() or 0
    # Kept a while past expiry: the per-account hourly cap on new codes is a
    # count of these rows, and deleting them at expiry reset it every hour.
    await db.execute(
        delete(OTPVerification).where(OTPVerification.expires_at < _now() - OTP_RETENTION)
    )
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
    """Samples a restart left in 'pending' never got their detached analysis.

    Only those with attempts left. A sample that has used them up is marked
    failed here: one whose result could never be stored was otherwise
    re-queued on every pass, for ever, and crowded the fifty-row window so
    that genuinely interrupted samples behind it were never reached.
    """
    from sqlalchemy import update

    from app.services import payload_enrichment

    max_attempts = max(1, get_settings().PAYLOAD_ANALYSIS_MAX_ATTEMPTS)
    await db.execute(
        update(PayloadSample)
        .where(
            PayloadSample.analysis_status == "pending",
            PayloadSample.analysis_attempts >= max_attempts,
        )
        .values(
            analysis_status="failed",
            analysed_at=_now(),
            analysis_error=func.coalesce(
                PayloadSample.analysis_error,
                f"gave up after {max_attempts} attempt(s)",
            ),
        )
    )
    await db.commit()

    ids = (
        await db.execute(
            select(PayloadSample.id)
            .where(
                PayloadSample.analysis_status == "pending",
                PayloadSample.analysis_attempts < max_attempts,
            )
            .order_by(PayloadSample.id)
            .limit(50)
        )
    ).scalars().all()
    if ids:
        payload_enrichment.schedule(list(ids))
    return len(ids)
