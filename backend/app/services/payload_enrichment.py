"""Stage 2 for uploaded files: reverse-engineer them, out of the ingest path.

Mirrors the Chimera enrichment split. The ingest path stores the file and
returns; this runs afterwards, decrypts the sample, analyses it in the
sandboxed subprocess, and writes the result plus the indicators found inside
it back onto every session that carried the file. A slow or failed analysis
degrades the depth of a session's record, never its capture.

The indicators a payload yields — the C2 it beacons to, the wallet it mines
to, the SSH key it plants — are attributed to each session the sample appeared
in, so the existing indicator feed and the session view surface them with no
special-casing. That includes sessions which arrive after the analysis: the
same loader dropped again next week gets the indicators already known for it.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import async_session_factory
from app.core.encryption import decrypt_bytes, payload_context
from app.core.sanitize import clean_json, clip
from app.models import IndicatorOfCompromise, PayloadSample, SessionArtifact
from app.payloads import sandbox
from app.payloads.analyzer import ANALYSER_VERSION

logger = logging.getLogger(__name__)

#: One analysis subprocess at a time by default. Each is CPU- and memory-bounded
#: already; this bounds how many run at once under a burst of new samples.
_semaphore = asyncio.Semaphore(1)
_pending: set[asyncio.Task] = set()
#: Samples queued or being analysed in this process, so the queue poll does
#: not start a second analysis of one that is already running.
_in_flight: set[int] = set()

#: Indicator kinds the analyser produces, mapped to how they are stored, with
#: the confidence and tags each carries into the shared feed.
_IOC_MAP = {
    "ips": ("ip", 0.9, ["payload", "c2"]),
    "domains": ("domain", 0.9, ["payload", "c2"]),
    "urls": ("url", 0.9, ["payload", "c2"]),
    "mining_pools": ("domain", 0.9, ["payload", "mining_pool"]),
    "wallets": ("wallet", 0.95, ["payload", "cryptocurrency"]),
    "ssh_keys": ("ssh_key", 0.95, ["payload", "persistence"]),
    "c2_channels": ("c2_channel", 0.9, ["payload", "operator_channel"]),
}

#: Column widths of payload_samples, for values taken from a report.
_FILE_KIND_CHARS = 32
_FILE_TYPE_CHARS = 128
_FAMILY_CHARS = 64
_VERSION_CHARS = 16


def schedule(sample_ids: list[int]) -> None:
    """Queue analysis for newly stored samples, if payload analysis is on."""
    settings = get_settings()
    if not sample_ids or not settings.PAYLOAD_ANALYSIS_ENABLED:
        return
    if settings.api_role == "ingest":
        # Not here. The ingest service runs several workers under a
        # supervisor process that holds every secret in its environment and
        # cannot be made unreadable to its children's siblings, and the
        # analysis child parses attacker bytes. The samples stay "pending"
        # and the dashboard API, one process that has made itself
        # non-dumpable, picks them up within PAYLOAD_QUEUE_INTERVAL seconds.
        return
    fresh = [sample_id for sample_id in sample_ids if sample_id not in _in_flight]
    if not fresh:
        return
    _in_flight.update(fresh)
    task = asyncio.create_task(_run_batch(fresh))
    _pending.add(task)
    task.add_done_callback(_pending.discard)


async def _run_batch(sample_ids: list[int]) -> None:
    for sample_id in sample_ids:
        try:
            async with _semaphore:
                async with async_session_factory() as db:
                    await analyse_sample(db, sample_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # detached: a failure here must reach nothing
            logger.warning("Payload analysis failed for sample %s: %s", sample_id, exc)
        finally:
            _in_flight.discard(sample_id)


async def analyse_sample(db: AsyncSession, sample_id: int) -> None:
    settings = get_settings()
    sample = (
        await db.execute(select(PayloadSample).where(PayloadSample.id == sample_id))
    ).scalar_one_or_none()
    if sample is None:
        return
    if sample.analysis_status == "complete":
        # Nothing to analyse, but a session that carried this file after it
        # was analysed has not been given its indicators yet.
        if isinstance(sample.analysis, dict):
            await _attribute_indicators(db, sample, sample.analysis)
            await db.commit()
        return
    if sample.content_encrypted is None or sample.analysis_status != "pending":
        return

    # Count the attempt before doing the work, in its own commit. Whatever
    # happens next (the process is killed, the result cannot be stored) the
    # attempt is on record, so a sample that can never be saved stops being
    # retried instead of being picked up again every hour.
    max_attempts = max(1, settings.PAYLOAD_ANALYSIS_MAX_ATTEMPTS)
    if (sample.analysis_attempts or 0) >= max_attempts:
        await _mark_failed(
            db, sample, f"gave up after {sample.analysis_attempts} attempt(s): "
            + (sample.analysis_error or "the result could not be stored"),
        )
        return
    await db.execute(
        update(PayloadSample)
        .where(PayloadSample.id == sample.id)
        .values(analysis_attempts=PayloadSample.analysis_attempts + 1)
    )
    await db.commit()
    await db.refresh(sample, attribute_names=["analysis_attempts"])

    try:
        content = decrypt_bytes(sample.content_encrypted, payload_context(sample.sha256))
    except ValueError:
        await _mark_failed(db, sample, "sample could not be decrypted")
        return

    result = await sandbox.run(
        content,
        timeout=settings.PAYLOAD_ANALYSIS_TIMEOUT,
        memory_mb=settings.PAYLOAD_ANALYSIS_MEMORY_MB,
    )
    if result["status"] != "complete":
        await _mark_failed(db, sample, result.get("error", "analysis failed"))
        return

    try:
        report = _store_report(sample, result["report"])
        await _attribute_indicators(db, sample, report)
        await db.commit()
    except SQLAlchemyError as exc:
        await db.rollback()
        await _record_store_failure(db, sample_id, exc, max_attempts)
        return
    logger.info(
        "Analysed sample %s: %s (%d indicators)",
        sample.sha256[:12], sample.file_kind, _as_int(report.get("indicator_count")),
    )


def _store_report(sample: PayloadSample, raw_report: dict) -> dict:
    """Put a report on the sample row in a form the database will accept.

    The report quotes the uploaded file: a NUL in a recovered string is
    refused by JSONB, and a label built from the file's own shebang line can
    be longer than its column. Either used to fail the commit and leave the
    sample pending. Returns the cleaned report.
    """
    report = clean_json(raw_report)
    file_type = report.get("file_type")
    family = report.get("family")

    sample.analysis = report
    sample.file_kind = clip(report.get("file_kind"), _FILE_KIND_CHARS)
    sample.file_type = clip(
        file_type.get("label") if isinstance(file_type, dict) else None,
        _FILE_TYPE_CHARS,
    )
    sample.family = clip(
        family.get("family") if isinstance(family, dict) else None, _FAMILY_CHARS
    )
    sample.analysis_status = "complete"
    sample.analyser_version = clip(
        report.get("analyser_version") or ANALYSER_VERSION, _VERSION_CHARS
    )
    sample.analysed_at = datetime.now(timezone.utc)
    sample.analysis_error = None
    return report


def _as_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


async def _record_store_failure(
    db: AsyncSession, sample_id: int, exc: Exception, max_attempts: int
) -> None:
    """A finished analysis could not be saved: note why, and stop eventually."""
    sample = (
        await db.execute(select(PayloadSample).where(PayloadSample.id == sample_id))
    ).scalar_one_or_none()
    if sample is None:
        return
    reason = f"result could not be stored: {type(exc).__name__}"
    logger.warning(
        "Analysis of sample %s could not be stored (attempt %s of %s): %s",
        sample.sha256[:12], sample.analysis_attempts, max_attempts, exc,
    )
    if (sample.analysis_attempts or 0) >= max_attempts:
        await _mark_failed(db, sample, reason)
        return
    # Left pending for the hourly re-queue, with the reason visible meanwhile.
    sample.analysis_error = reason
    await db.commit()


async def _attribute_indicators(db: AsyncSession, sample: PayloadSample, report: dict) -> None:
    """Write the payload's indicators onto every session that carried it.

    Only sessions not yet credited with this sample's indicators, so calling
    this again (a sample seen in a new session after its analysis) adds rows
    for the new session and none for the ones already done.
    """
    rows = list(_indicator_rows(report))

    artifacts = (
        await db.execute(
            select(SessionArtifact).where(
                SessionArtifact.sample_id == sample.id,
                SessionArtifact.iocs_recorded.is_(False),
            )
        )
    ).scalars().all()

    for artifact in artifacts:
        for ioc_type, value, confidence, tags in rows:
            db.add(IndicatorOfCompromise(
                session_id=artifact.session_id,
                ioc_type=ioc_type,
                value=value,
                confidence=confidence,
                tags=tags + [f"sample:{sample.sha256[:12]}"],
            ))
        # Marked even when the sample yielded nothing, so it is not looked at
        # again for this session.
        artifact.iocs_recorded = True


def _indicator_rows(report: dict):
    """Flatten the analyser's indicator groups into storable rows, deduped."""
    found = report.get("indicators")
    if not isinstance(found, dict):
        return
    seen: set[tuple[str, str]] = set()
    for group, (ioc_type, confidence, tags) in _IOC_MAP.items():
        items = found.get(group)
        if not isinstance(items, list):
            continue
        for item in items:
            value = _indicator_value(group, item)
            if not value:
                continue
            value = str(value)[:500]
            if (ioc_type, value) in seen:
                continue
            seen.add((ioc_type, value))
            yield ioc_type, value, confidence, list(tags)


def _indicator_value(group: str, item) -> str | None:
    if not isinstance(item, dict):
        return str(item) if item else None
    if group == "ssh_keys":
        return item.get("fingerprint")
    if group == "c2_channels":
        return item.get("indicator") or item.get("value")
    if group == "wallets":
        currency = item.get("currency", "")
        value = item.get("value", "")
        return f"{currency}:{value}" if currency else value
    return item.get("value")


async def _mark_failed(db: AsyncSession, sample: PayloadSample, error: str) -> None:
    sample.analysis_status = "failed"
    sample.analysis_error = clip(error, 500)
    sample.analysed_at = datetime.now(timezone.utc)
    await db.commit()
