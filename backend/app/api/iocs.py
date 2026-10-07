"""Indicators of compromise.

Every ingested session writes indicators — the attacker's address, hosts and
URLs its droppers reached for, offensive tools it used, hashes of what it
uploaded. The table filled up from the first session onward and no route ever
read it, so the most directly shareable output the system produces existed
only inside the database.

The aggregate view is the one that matters. A single session's indicators are
a footnote; the same C2 host appearing across forty sessions from thirty
addresses is the finding.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import Request, APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.sql import LIKE_ESCAPE, escape_like
from app.core.security import get_current_user
from app.models import HoneypotSession, IndicatorOfCompromise
from app.schemas import IndicatorOfCompromiseResponse

router = APIRouter()

#: Indicator types the pipeline emits. Anything else is a bug upstream, and
#: rejecting an unknown filter is more useful than silently returning nothing.
KNOWN_TYPES = {"ip", "domain", "url", "filename", "file_hash", "tool", "host",
               "file", "wallet", "ssh_key", "c2_channel"}

#: Cap on a single page. Analysts pulling a feed want the whole set, and the
#: export route below exists for that, so the paged view stays modest.
MAX_PAGE_SIZE = 200


@router.get("/")
async def list_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    ioc_type: Optional[str] = None,
    search: Optional[str] = None,
    min_sessions: int = Query(1, ge=1),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Indicators grouped by value, with how widely each has been seen.

    Grouped rather than listed row by row: the same URL recorded in eighty
    sessions is one indicator observed eighty times, and presenting it as
    eighty rows buries every other indicator underneath it.
    """
    if ioc_type and ioc_type not in KNOWN_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown indicator type {ioc_type!r}. "
                   f"Expected one of: {', '.join(sorted(KNOWN_TYPES))}",
        )

    grouped = (
        select(
            IndicatorOfCompromise.ioc_type,
            IndicatorOfCompromise.value,
            func.count(func.distinct(IndicatorOfCompromise.session_id)).label("sessions"),
            func.max(IndicatorOfCompromise.confidence).label("confidence"),
            func.min(IndicatorOfCompromise.first_seen).label("first_seen"),
            func.max(IndicatorOfCompromise.last_seen).label("last_seen"),
        )
        .group_by(IndicatorOfCompromise.ioc_type, IndicatorOfCompromise.value)
        .having(
            func.count(func.distinct(IndicatorOfCompromise.session_id)) >= min_sessions
        )
    )

    if ioc_type:
        grouped = grouped.where(IndicatorOfCompromise.ioc_type == ioc_type)
    if search:
        pattern = f"%{escape_like(search)}%"
        grouped = grouped.where(
            IndicatorOfCompromise.value.ilike(pattern, escape=LIKE_ESCAPE)
        )

    subquery = grouped.subquery()
    total = (await db.execute(select(func.count()).select_from(subquery))).scalar() or 0

    rows = (
        await db.execute(
            select(subquery)
            .order_by(desc(subquery.c.sessions), desc(subquery.c.last_seen))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()

    return {
        "indicators": [
            {
                "type": r.ioc_type,
                "value": r.value,
                "sessions": r.sessions,
                "confidence": r.confidence,
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/session/{session_id}", response_model=list[IndicatorOfCompromiseResponse])
async def list_session_iocs(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Everything one session produced."""
    exists = (
        await db.execute(
            select(HoneypotSession.id).where(HoneypotSession.id == session_id)
        )
    ).scalar_one_or_none()
    if exists is None:
        raise HTTPException(status_code=404, detail="Session not found")

    rows = (
        await db.execute(
            select(IndicatorOfCompromise)
            .where(IndicatorOfCompromise.session_id == session_id)
            .order_by(IndicatorOfCompromise.ioc_type, IndicatorOfCompromise.value)
        )
    ).scalars().all()
    return [IndicatorOfCompromiseResponse.model_validate(r) for r in rows]


async def feed_auth(request: Request) -> dict:
    """A user session, or the static feed token.

    A firewall or SIEM pulling the blocklist on a schedule cannot hold a
    user token that expires hourly. IOC_FEED_TOKEN, when set, is accepted in
    the X-Feed-Token header for this endpoint only.
    """
    import secrets

    from app.core.config import get_settings

    token = get_settings().IOC_FEED_TOKEN
    supplied = request.headers.get("X-Feed-Token", "")
    if token and supplied:
        try:
            if secrets.compare_digest(supplied, token):
                return {"id": None, "email": "feed-token", "role": "viewer"}
        except TypeError:
            pass
        raise HTTPException(status_code=401, detail="Invalid feed token")
    from fastapi.security.utils import get_authorization_scheme_param

    scheme, credentials = get_authorization_scheme_param(request.headers.get("Authorization", ""))
    if scheme.lower() != "bearer" or not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    from fastapi.security import HTTPAuthorizationCredentials

    return await get_current_user(HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials))


def _feed_exclusions(ioc_type: str, exclude_scanners: bool):
    """Rows a blocklist must not contain: research scanners, and (for ip)
    addresses that are private, loopback or tailnet — a consumer that blocks
    its own LAN because an analyst tested from it is worse than no feed."""
    from sqlalchemy import exists

    from app.models import HoneypotSession

    conditions = []
    if exclude_scanners:
        conditions.append(
            ~exists().where(
                HoneypotSession.id == IndicatorOfCompromise.session_id,
                HoneypotSession.scanner_operator.isnot(None),
            )
        )
    if ioc_type == "ip":
        for prefix in ("10.", "127.", "192.168.", "100.", "169.254.", "0.", "::1", "fe80:", "fd"):
            conditions.append(~IndicatorOfCompromise.value.like(f"{prefix}%"))
        for i in range(16, 32):
            conditions.append(~IndicatorOfCompromise.value.like(f"172.{i}.%"))
    return conditions


@router.get("/feed", response_class=PlainTextResponse)
async def ioc_feed(
    ioc_type: str = Query("ip", description="Indicator type to emit"),
    min_sessions: int = Query(2, ge=1),
    exclude_scanners: bool = Query(True, description="Leave out addresses of known research scanners"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(feed_auth),
):
    """A plain-text list, one indicator per line.

    This is the shape a blocklist consumer wants: pf tables, ipset, a Suricata
    dataset and a Splunk lookup all read one value per line and nothing else.
    Comments carry the provenance without breaking any of those parsers.

    ``min_sessions`` defaults to 2 deliberately. An address seen once may be a
    passing scan or a shared exit node, and a feed that blocks on a single
    observation will eventually block something it should not.
    """
    if ioc_type not in KNOWN_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown indicator type {ioc_type!r}. "
                   f"Expected one of: {', '.join(sorted(KNOWN_TYPES))}",
        )

    rows = (
        await db.execute(
            select(
                IndicatorOfCompromise.value,
                func.count(func.distinct(IndicatorOfCompromise.session_id)).label("n"),
            )
            .where(IndicatorOfCompromise.ioc_type == ioc_type)
            .where(*_feed_exclusions(ioc_type, exclude_scanners))
            .group_by(IndicatorOfCompromise.value)
            .having(
                func.count(func.distinct(IndicatorOfCompromise.session_id))
                >= min_sessions
            )
            .order_by(desc("n"))
            .limit(10_000)
        )
    ).all()

    now = datetime.now(timezone.utc)
    header = (
        f"# HoneySentinel indicator feed\n"
        f"# type={ioc_type} min_sessions={min_sessions} count={len(rows)}\n"
        f"# generated={now.isoformat()}\n"
    )
    body = header + "".join(f"{r.value}\n" for r in rows)
    filename = f"honeysentinel-{ioc_type}-{now.date().isoformat()}.txt"
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
