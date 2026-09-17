"""Captured payloads and their static analysis.

The samples an attacker uploaded, unique by hash, with the reverse-engineering
report for each and the sessions it appeared in. This is a read surface over
what the ingest and enrichment stages produced; it runs no analysis itself.

The raw sample is downloadable by admins only, and always as
application/octet-stream marked non-executable, because it is live malware:
the point of keeping it is analysis, not redistribution.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.encryption import decrypt_bytes
from app.core.security import get_current_user, require_role
from app.core.sql import LIKE_ESCAPE, escape_like
from app.models import AuditLog, HoneypotSession, PayloadSample, SessionArtifact

router = APIRouter()

MAX_PAGE_SIZE = 100

#: Sort keys the list view accepts, mapped to columns, so a client cannot
#: order by an arbitrary attribute.
_SORT = {
    "last_seen": PayloadSample.last_seen,
    "first_seen": PayloadSample.first_seen,
    "size": PayloadSample.size,
}


@router.get("/")
async def list_payloads(
    page: int = Query(1, ge=1),
    page_size: int = Query(30, ge=1, le=MAX_PAGE_SIZE),
    file_kind: Optional[str] = None,
    family: Optional[str] = None,
    status: Optional[str] = Query(None, pattern="^(pending|complete|failed|metadata_only)$"),
    search: Optional[str] = None,
    sort: str = Query("last_seen", pattern="^(last_seen|first_seen|size)$"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Captured samples, newest first, with how widely each has been seen."""
    seen_count = (
        select(func.count(SessionArtifact.id))
        .where(SessionArtifact.sample_id == PayloadSample.id)
        .scalar_subquery()
    )
    query = select(PayloadSample, seen_count.label("sessions"))
    count_query = select(func.count(PayloadSample.id))

    filters = []
    if file_kind:
        filters.append(PayloadSample.file_kind == file_kind)
    if family:
        filters.append(PayloadSample.family == family)
    if status:
        filters.append(PayloadSample.analysis_status == status)
    if search:
        pattern = f"%{escape_like(search)}%"
        filters.append(
            PayloadSample.sha256.ilike(pattern, escape=LIKE_ESCAPE)
            | PayloadSample.family.ilike(pattern, escape=LIKE_ESCAPE)
            | PayloadSample.file_type.ilike(pattern, escape=LIKE_ESCAPE)
        )
    for clause in filters:
        query = query.where(clause)
        count_query = count_query.where(clause)

    total = (await db.execute(count_query)).scalar() or 0
    query = query.order_by(_SORT[sort].desc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(query)).all()

    return {
        "payloads": [_summary(sample, sessions) for sample, sessions in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/stats")
async def payload_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Counts by kind and by family, for the overview strip."""
    total = (await db.execute(select(func.count(PayloadSample.id)))).scalar() or 0
    by_kind = (
        await db.execute(
            select(PayloadSample.file_kind, func.count(PayloadSample.id))
            .group_by(PayloadSample.file_kind)
        )
    ).all()
    by_family = (
        await db.execute(
            select(PayloadSample.family, func.count(PayloadSample.id))
            .where(PayloadSample.family.isnot(None))
            .group_by(PayloadSample.family)
            .order_by(func.count(PayloadSample.id).desc())
            .limit(10)
        )
    ).all()
    pending = (
        await db.execute(
            select(func.count(PayloadSample.id))
            .where(PayloadSample.analysis_status == "pending")
        )
    ).scalar() or 0

    return {
        "total": total,
        "pending_analysis": pending,
        "by_kind": {kind or "unknown": count for kind, count in by_kind},
        "top_families": [{"family": fam, "count": count} for fam, count in by_family],
    }


@router.get("/{sha256}")
async def get_payload(
    sha256: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """One sample: its full analysis and every session it appeared in."""
    sample = (
        await db.execute(select(PayloadSample).where(PayloadSample.sha256 == sha256))
    ).scalar_one_or_none()
    if sample is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    appearances = (
        await db.execute(
            select(SessionArtifact, HoneypotSession)
            .join(HoneypotSession, SessionArtifact.session_id == HoneypotSession.id)
            .where(SessionArtifact.sample_id == sample.id)
            .order_by(SessionArtifact.captured_at.desc())
            .limit(200)
        )
    ).all()

    return {
        **_summary(sample, len(appearances)),
        "content_available": sample.content_encrypted is not None,
        "analysis_error": sample.analysis_error,
        "analysis": sample.analysis,
        "sessions": [
            {
                "session_id": session.id,
                "session_uuid": session.session_uuid,
                "attacker_ip": session.attacker_ip,
                "filename": artifact.filename,
                "remote_path": artifact.remote_path,
                "source": artifact.source,
                "methods": artifact.methods or [],
                "captured_at": artifact.captured_at.isoformat() if artifact.captured_at else None,
            }
            for artifact, session in appearances
        ],
    }


@router.get("/{sha256}/download")
async def download_payload(
    sha256: str,
    db: AsyncSession = Depends(get_db),
    # Raw malware. Admin only, and the download is audit-logged below.
    current_user: dict = Depends(require_role("admin")),
):
    sample = (
        await db.execute(select(PayloadSample).where(PayloadSample.sha256 == sha256))
    ).scalar_one_or_none()
    if sample is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    if sample.content_encrypted is None:
        raise HTTPException(status_code=404, detail="No content stored for this sample")

    try:
        content = decrypt_bytes(sample.content_encrypted)
    except ValueError:
        raise HTTPException(status_code=500, detail="Sample could not be decrypted")

    db.add(AuditLog(
        user_id=current_user["id"],
        action="payload_downloaded",
        resource_type="payload_sample",
        details={"sha256": sha256, "size": sample.size},
    ))
    await db.commit()

    # Named by hash and marked non-executable: the browser must never treat a
    # captured sample as anything but an opaque blob to hand to a tool.
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{sha256}.bin"',
            "X-Content-Type-Options": "nosniff",
        },
    )


def _summary(sample: PayloadSample, sessions: int) -> dict:
    analysis = sample.analysis or {}
    return {
        "sha256": sample.sha256,
        "sha1": sample.sha1 or None,
        "md5": sample.md5 or None,
        "size": sample.size,
        "file_kind": sample.file_kind,
        "file_type": sample.file_type,
        "family": sample.family,
        "analysis_status": sample.analysis_status,
        "summary": analysis.get("summary"),
        "notable": analysis.get("notable", []),
        "indicator_count": analysis.get("indicator_count", 0),
        "sessions_seen": sessions,
        "first_seen": sample.first_seen.isoformat() if sample.first_seen else None,
        "last_seen": sample.last_seen.isoformat() if sample.last_seen else None,
        "analysed_at": sample.analysed_at.isoformat() if sample.analysed_at else None,
    }
