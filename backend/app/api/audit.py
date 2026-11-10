"""Reading the audit log.

Every privileged action writes an audit row: sign-ins and failures, role
changes, exports, credential and transcript reads, engine control. Until now
the rows could only be read with a database client, so the record of who did
what was unavailable to the people responsible for the deployment.

Administrators only. The log names users, addresses and what each of them
looked at; it is as sensitive as the data it describes access to.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_role
from app.models import AuditLog, User
from app.schemas.operations import AuditLogEntry, AuditLogPage

router = APIRouter()

MAX_PAGE_SIZE = 200
#: Deepest row a request may page to. Further back than this is a job for
#: the ``since`` filter, not for an ever-larger OFFSET.
MAX_OFFSET = 100_000


@router.get("", response_model=AuditLogPage)
@router.get("/", response_model=AuditLogPage, include_in_schema=False)
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(0, ge=0, le=MAX_OFFSET),
    action: Optional[str] = Query(None, max_length=100, description="Exact action name"),
    user_id: Optional[int] = Query(None, ge=1),
    since: Optional[datetime] = Query(None, description="Only rows at or after this time"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    """Audit rows, newest first, with the acting user's email where known."""
    conditions = []
    if action:
        conditions.append(AuditLog.action == action)
    if user_id is not None:
        conditions.append(AuditLog.user_id == user_id)
    if since is not None:
        # A time without a zone is taken as UTC, like every other filter.
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        conditions.append(AuditLog.created_at >= since)

    total = (
        await db.execute(select(func.count(AuditLog.id)).where(*conditions))
    ).scalar() or 0

    rows = (
        await db.execute(
            select(AuditLog, User.email)
            .outerjoin(User, AuditLog.user_id == User.id)
            .where(*conditions)
            .order_by(desc(AuditLog.created_at), desc(AuditLog.id))
            .offset(offset)
            .limit(limit)
        )
    ).all()

    return AuditLogPage(
        items=[
            AuditLogEntry(
                id=entry.id,
                user_id=entry.user_id,
                user_email=email,
                action=entry.action,
                resource_type=entry.resource_type,
                resource_id=entry.resource_id,
                details=entry.details,
                ip_address=entry.ip_address,
                created_at=entry.created_at,
            )
            for entry, email in rows
        ],
        total=total,
    )
