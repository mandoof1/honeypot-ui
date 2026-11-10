"""Record the files a session uploaded, in the ingest path.

This runs synchronously while the session is being written, so it does no
analysis — it decodes the forwarded bytes, verifies them against the hash the
engine sent, stores each unique file once (encrypted), and links it to the
session. The expensive part, reverse-engineering the bytes, happens afterwards
in a detached stage (payload_enrichment), for the same reason Chimera does:
the ingest path owns the NFR-2 latency budget and must not block on it.

Recording is idempotent. The session itself is committed by the analysis
pipeline before this runs, so a failure here used to leave a stored session
with no artifacts, and the engine's retry was answered "duplicate" without
ever recording them. Calling this again for the same session now adds only
what is missing, which is what lets a retried ingest finish the job.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.encryption import encrypt_bytes, payload_context
from app.models import HoneypotSession, PayloadSample, SessionArtifact

logger = logging.getLogger(__name__)

#: An upload the engine could not forward arrives as metadata with no
#: content_b64; it is still linked, so its hash is never lost.
MAX_UPLOADS_PER_SESSION = 64


async def record_uploads(db: AsyncSession, session_id: int, uploads: list) -> list[int]:
    """Create sample and artifact rows for a session's uploads.

    Returns the ids of samples the detached stage should look at: new ones
    to analyse, and already-analysed ones whose indicators this session has
    not been given yet. Does not commit: it runs inside the caller's
    transaction. Safe to call again for the same session.
    """
    settings = get_settings()
    pending: list[int] = []
    seen: set[str] = set()

    # One recorder per session at a time. The engine resends a session whose
    # response it did not see, and the first attempt may still be in here; two
    # passes that each check "is this artifact linked yet" before either has
    # committed would both insert it. (SQLite has no row locks and ignores
    # this; it also has no concurrent writers.)
    await db.execute(
        select(HoneypotSession.id)
        .where(HoneypotSession.id == session_id)
        .with_for_update()
    )
    linked = set(
        (
            await db.execute(
                select(SessionArtifact.sample_id).where(
                    SessionArtifact.session_id == session_id
                )
            )
        ).scalars().all()
    )

    candidates = []
    for upload in uploads[:MAX_UPLOADS_PER_SESSION]:
        if not isinstance(upload, dict):
            continue
        sha256 = str(upload.get("sha256") or "").lower()
        if len(sha256) != 64 or sha256 in seen:
            continue
        seen.add(sha256)
        candidates.append((sha256, upload))

    # In hash order, so two sessions that carry the same pair of new files
    # insert them in the same order and cannot deadlock on each other.
    for sha256, upload in sorted(candidates, key=lambda item: item[0]):
        content = _decode(upload.get("content_b64"), sha256)
        sample, needs_analysis = await _upsert_sample(db, sha256, upload, content, settings)
        if sample is None:
            continue

        if sample.id not in linked:
            db.add(SessionArtifact(
                session_id=session_id,
                sample_id=sample.id,
                filename=str(upload.get("filename") or sha256)[:255],
                remote_path=str(upload.get("remote_path") or "")[:500] or None,
                source=str(upload.get("source") or "unknown")[:32],
                methods=[str(m)[:32] for m in (upload.get("methods") or [])][:8],
            ))
            linked.add(sample.id)

        if needs_analysis and sample.content_encrypted is not None:
            # New here, with its bytes: reverse-engineer it.
            pending.append(sample.id)
        elif sample.analysis_status == "complete":
            # Analysed when an earlier session carried it. The detached stage
            # does no analysis for it, only writes its known indicators onto
            # this session; before, a sample's indicators reached only the
            # sessions that existed when it was first analysed.
            pending.append(sample.id)

    return pending


def _decode(content_b64, sha256: str) -> bytes | None:
    if not content_b64 or not isinstance(content_b64, str):
        return None
    try:
        content = base64.b64decode(content_b64, validate=True)
    except (binascii.Error, ValueError):
        logger.warning("Upload %s carried undecodable content", sha256[:12])
        return None
    if hashlib.sha256(content).hexdigest() != sha256:
        # The engine's hash and its bytes disagree: keep neither, since we
        # cannot say which is right, but let the metadata row still be written.
        logger.warning("Upload %s failed its hash check; content dropped", sha256[:12])
        return None
    return content


def _insert_ignoring_conflict(db: AsyncSession):
    """The dialect's INSERT ... ON CONFLICT DO NOTHING for payload_samples."""
    if db.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    return insert(PayloadSample).on_conflict_do_nothing(index_elements=["sha256"])


def _upload_size(upload: dict, content: bytes | None) -> int:
    try:
        declared = int(upload.get("size") or 0)
    except (TypeError, ValueError):
        declared = 0
    # A 32-bit INTEGER column; a nonsense size must not fail the insert.
    declared = max(0, min(declared, 2_147_483_647))
    return declared or (len(content) if content else 0)


async def _upsert_sample(db, sha256, upload, content, settings):
    """Find or create the sample row. Returns (sample, needs_analysis).

    Insert-or-ignore, then read back. The select-then-insert this replaces
    lost a race: with four ingest workers, two sessions carrying the same new
    file both saw "no such sample", both inserted, and the loser's request
    died on the unique index after its session was already committed.
    """
    now = datetime.now(timezone.utc)
    by_hash = select(PayloadSample).where(PayloadSample.sha256 == sha256)

    # The usual case for a recurring file: it is already here, and nothing
    # needs encrypting or inserting.
    sample = (await db.execute(by_hash)).scalar_one_or_none()
    created = False
    encrypted = None
    if sample is None:
        encrypted = _maybe_encrypt(content, sha256, settings) if content is not None else None
        result = await db.execute(
            _insert_ignoring_conflict(db).values(
                sha256=sha256,
                sha1=hashlib.sha1(content).hexdigest() if content else "",
                md5=hashlib.md5(content).hexdigest() if content else "",
                size=_upload_size(upload, content),
                content_encrypted=encrypted,
                analysis_status="pending" if encrypted is not None else "metadata_only",
                analysis_attempts=0,
                first_seen=now,
                last_seen=now,
            )
        )
        created = bool(result.rowcount)
        sample = (await db.execute(by_hash)).scalar_one_or_none()
        if sample is None:
            # Only if the row was deleted between the two statements (retention).
            logger.warning("Sample %s vanished while being recorded", sha256[:12])
            return None, False
    if created:
        return sample, encrypted is not None

    sample.last_seen = now
    # A later capture may carry bytes an earlier metadata-only one lacked.
    if sample.content_encrypted is None and content is not None:
        sample.content_encrypted = _maybe_encrypt(content, sha256, settings)
        if sample.content_encrypted is not None and sample.analysis_status == "metadata_only":
            sample.analysis_status = "pending"
            return sample, True
    return sample, False


def _maybe_encrypt(content: bytes, sha256: str, settings) -> str | None:
    if len(content) > settings.PAYLOAD_MAX_STORE_BYTES:
        return None
    # Bound to the sample's hash, so the blob cannot be moved to another row.
    return encrypt_bytes(content, payload_context(sha256))
