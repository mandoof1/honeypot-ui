"""Record the files a session uploaded, in the ingest path.

This runs synchronously while the session is being written, so it does no
analysis — it decodes the forwarded bytes, verifies them against the hash the
engine sent, stores each unique file once (encrypted), and links it to the
session. The expensive part, reverse-engineering the bytes, happens afterwards
in a detached stage (payload_enrichment), for the same reason Chimera does:
the ingest path owns the NFR-2 latency budget and must not block on it.
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
from app.core.encryption import encrypt_bytes
from app.models import PayloadSample, SessionArtifact

logger = logging.getLogger(__name__)

#: An upload the engine could not forward arrives as metadata with no
#: content_b64; it is still linked, so its hash is never lost.
MAX_UPLOADS_PER_SESSION = 64


async def record_uploads(db: AsyncSession, session_id: int, uploads: list) -> list[int]:
    """Create sample and artifact rows for a session's uploads.

    Returns the ids of samples that need analysis, for the detached stage to
    pick up. Does not commit: it runs inside the ingest transaction.
    """
    settings = get_settings()
    pending: list[int] = []
    seen: set[str] = set()

    for upload in uploads[:MAX_UPLOADS_PER_SESSION]:
        if not isinstance(upload, dict):
            continue
        sha256 = str(upload.get("sha256") or "")
        if len(sha256) != 64 or sha256 in seen:
            continue
        seen.add(sha256)

        content = _decode(upload.get("content_b64"), sha256)
        sample, is_new = await _upsert_sample(db, sha256, upload, content, settings)
        if sample is None:
            continue
        await db.flush()

        db.add(SessionArtifact(
            session_id=session_id,
            sample_id=sample.id,
            filename=str(upload.get("filename") or sha256)[:255],
            remote_path=str(upload.get("remote_path") or "")[:500] or None,
            source=str(upload.get("source") or "unknown")[:32],
            methods=[str(m)[:32] for m in (upload.get("methods") or [])][:8],
        ))
        # Analyse when the sample is new and we actually have its bytes. A
        # sample seen before is either already analysed or already queued.
        if is_new and sample.content_encrypted is not None:
            pending.append(sample.id)

    return pending


def _decode(content_b64, sha256: str) -> bytes | None:
    if not content_b64:
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


async def _upsert_sample(db, sha256, upload, content, settings):
    now = datetime.now(timezone.utc)
    existing = (
        await db.execute(select(PayloadSample).where(PayloadSample.sha256 == sha256))
    ).scalar_one_or_none()

    if existing is not None:
        existing.last_seen = now
        # A later capture may carry bytes an earlier metadata-only one lacked.
        if existing.content_encrypted is None and content is not None:
            existing.content_encrypted = _maybe_encrypt(content, settings)
            if existing.content_encrypted is not None and existing.analysis_status == "metadata_only":
                existing.analysis_status = "pending"
                return existing, True
        return existing, False

    size = int(upload.get("size") or (len(content) if content else 0))
    encrypted = _maybe_encrypt(content, settings) if content is not None else None
    sample = PayloadSample(
        sha256=sha256,
        sha1=hashlib.sha1(content).hexdigest() if content else "",
        md5=hashlib.md5(content).hexdigest() if content else "",
        size=size,
        content_encrypted=encrypted,
        analysis_status="pending" if encrypted is not None else "metadata_only",
        first_seen=now,
        last_seen=now,
    )
    db.add(sample)
    return sample, encrypted is not None


def _maybe_encrypt(content: bytes, settings) -> str | None:
    if len(content) > settings.PAYLOAD_MAX_STORE_BYTES:
        return None
    return encrypt_bytes(content)
