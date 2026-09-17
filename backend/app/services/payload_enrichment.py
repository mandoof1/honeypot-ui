"""Stage 2 for uploaded files: reverse-engineer them, out of the ingest path.

Mirrors the Chimera enrichment split. The ingest path stores the file and
returns; this runs afterwards, decrypts the sample, analyses it in the
sandboxed subprocess, and writes the result plus the indicators found inside
it back onto every session that carried the file. A slow or failed analysis
degrades the depth of a session's record, never its capture.

The indicators a payload yields — the C2 it beacons to, the wallet it mines
to, the SSH key it plants — are attributed to each session the sample appeared
in, so the existing indicator feed and the session view surface them with no
special-casing.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import async_session_factory
from app.core.encryption import decrypt_bytes
from app.models import IndicatorOfCompromise, PayloadSample, SessionArtifact
from app.payloads import sandbox
from app.payloads.analyzer import ANALYSER_VERSION

logger = logging.getLogger(__name__)

#: One analysis subprocess at a time by default. Each is CPU- and memory-bounded
#: already; this bounds how many run at once under a burst of new samples.
_semaphore = asyncio.Semaphore(1)
_pending: set[asyncio.Task] = set()

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


def schedule(sample_ids: list[int]) -> None:
    """Queue analysis for newly stored samples, if payload analysis is on."""
    if not sample_ids or not get_settings().PAYLOAD_ANALYSIS_ENABLED:
        return
    task = asyncio.create_task(_run_batch(sample_ids))
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


async def analyse_sample(db: AsyncSession, sample_id: int) -> None:
    settings = get_settings()
    sample = (
        await db.execute(select(PayloadSample).where(PayloadSample.id == sample_id))
    ).scalar_one_or_none()
    if sample is None or sample.content_encrypted is None:
        return
    if sample.analysis_status == "complete":
        return

    try:
        content = decrypt_bytes(sample.content_encrypted)
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

    report = result["report"]
    sample.analysis = report
    sample.file_kind = report.get("file_kind")
    sample.file_type = (report.get("file_type") or {}).get("label")
    sample.family = (report.get("family") or {}).get("family")
    sample.analysis_status = "complete"
    sample.analyser_version = report.get("analyser_version", ANALYSER_VERSION)
    sample.analysed_at = datetime.now(timezone.utc)
    sample.analysis_error = None

    await _attribute_indicators(db, sample, report)
    await db.commit()
    logger.info(
        "Analysed sample %s: %s (%d indicators)",
        sample.sha256[:12], sample.file_kind, report.get("indicator_count", 0),
    )


async def _attribute_indicators(db: AsyncSession, sample: PayloadSample, report: dict) -> None:
    """Write the payload's indicators onto every session that carried it.

    Only sessions not yet credited with this sample's indicators, so a sample
    re-seen after analysis does not duplicate rows on sessions already updated.
    """
    rows = list(_indicator_rows(report))
    if not rows:
        # Still mark the artifacts done, so they are not reconsidered.
        pass

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
        artifact.iocs_recorded = True


def _indicator_rows(report: dict):
    """Flatten the analyser's indicator groups into storable rows, deduped."""
    found = report.get("indicators") or {}
    seen: set[tuple[str, str]] = set()
    for group, (ioc_type, confidence, tags) in _IOC_MAP.items():
        for item in found.get(group, []):
            value = _indicator_value(group, item)
            if not value:
                continue
            value = value[:500]
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
    sample.analysis_error = error[:500]
    sample.analysed_at = datetime.now(timezone.utc)
    await db.commit()
