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

import ipaddress
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional

from fastapi import Request, APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import String, cast, desc, func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.sql import LIKE_ESCAPE, escape_like
from app.core.security import get_current_user
from app.models import HoneypotSession, IndicatorOfCompromise
from app.schemas import IndicatorOfCompromiseResponse

router = APIRouter()

#: Indicator types the pipeline emits. Anything else is a bug upstream, and
#: rejecting an unknown filter is more useful than silently returning nothing.
#: ``ip`` is an address that connected to a decoy (tagged ``attacker_ip``) or
#: one a dropper or payload reached for; ``referenced_ip`` is an address that
#: only appeared in text the attacker typed.
KNOWN_TYPES = {"ip", "referenced_ip", "domain", "url", "filename", "file_hash",
               "tool", "host", "file", "wallet", "ssh_key", "c2_channel"}

#: The tag the pipeline puts on a session's own source address.
ATTACKER_IP_TAG = "attacker_ip"

#: Most indicator rows returned for one session.
MAX_SESSION_INDICATORS = 2000

#: Cap on a single page. Analysts pulling a feed want the whole set, and the
#: export route below exists for that, so the paged view stays modest.
MAX_PAGE_SIZE = 200


@router.get("/")
async def list_iocs(
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    ioc_type: Optional[str] = Query(None, max_length=50),
    search: Optional[str] = Query(None, max_length=200),
    min_sessions: int = Query(1, ge=1, le=1_000_000),
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

    tags = await _tags_for(db, [(r.ioc_type, r.value) for r in rows])

    return {
        "indicators": [
            {
                "type": r.ioc_type,
                "value": r.value,
                "sessions": r.sessions,
                "confidence": r.confidence,
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
                # Every tag any occurrence carries. An `ip` row tagged
                # `attacker_ip` is a source address; one tagged only `c2_host`
                # is a machine a dropper reached for, and has no profile page.
                "tags": tags.get((r.ioc_type, r.value), []),
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


async def _tags_for(db: AsyncSession, pairs: list[tuple[str, str]]) -> dict[tuple[str, str], list[str]]:
    """The union of tags over every stored occurrence of each (type, value).

    One query for the page rather than a JSON aggregate in SQL, which
    PostgreSQL and SQLite spell differently. A page is at most MAX_PAGE_SIZE
    pairs.
    """
    if not pairs:
        return {}
    found = await db.execute(
        select(
            IndicatorOfCompromise.ioc_type,
            IndicatorOfCompromise.value,
            IndicatorOfCompromise.tags,
        ).where(
            tuple_(IndicatorOfCompromise.ioc_type, IndicatorOfCompromise.value).in_(pairs)
        )
    )
    merged: dict[tuple[str, str], set[str]] = {}
    for ioc_type, value, row_tags in found:
        if isinstance(row_tags, list):
            merged.setdefault((ioc_type, value), set()).update(str(t) for t in row_tags)
    return {key: sorted(values) for key, values in merged.items()}


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
            # A session carrying several analysed payloads can hold a few
            # thousand rows; nobody reads past the first couple of thousand.
            .limit(MAX_SESSION_INDICATORS)
        )
    ).scalars().all()
    return [IndicatorOfCompromiseResponse.model_validate(r) for r in rows]


async def feed_auth(request: Request, db: AsyncSession = Depends(get_db)) -> dict:
    """A user session, or the static feed token.

    A firewall or SIEM pulling the blocklist on a schedule cannot hold a
    user token that expires hourly. IOC_FEED_TOKEN, when set, is accepted in
    the X-Feed-Token header for this endpoint only.
    """
    import secrets

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

    # The database session has to be handed over explicitly. Called as a
    # plain function, get_current_user's own ``db=Depends(get_db)`` default
    # is never resolved, so a bearer-token request reached the user lookup
    # with a placeholder for a session and failed with a 500, unless that
    # user's state happened to be cached by an earlier request.
    return await get_current_user(
        HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials), db
    )


def _scanner_exclusion():
    """Leave out indicators that came from a known research scanner's session."""
    from sqlalchemy import exists

    return ~exists().where(
        HoneypotSession.id == IndicatorOfCompromise.session_id,
        HoneypotSession.scanner_operator.isnot(None),
    )


def _tagged(db: AsyncSession, tag: str):
    """Rows whose ``tags`` list contains ``tag``."""
    if db.get_bind().dialect.name == "postgresql":
        # JSONB containment; served by the GIN index on the column.
        return IndicatorOfCompromise.tags.contains([tag])
    # SQLite (the test database) stores the list as JSON text.
    return cast(IndicatorOfCompromise.tags, String).like(f'%"{tag}"%')


@lru_cache(maxsize=4)
def _allowlist(spec: str) -> tuple:
    """IOC_FEED_ALLOWLIST as networks. Entries that do not parse are skipped."""
    networks = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def blockable_address(value: str, allowlist: tuple = ()) -> Optional[str]:
    """``value`` in canonical form if it belongs in an address blocklist.

    It must parse as an IP address and be a global unicast one: anything
    private, loopback, link-local, carrier-grade NAT (which is where a
    tailnet lives), reserved, documentation or multicast is refused, and so
    is anything inside the operator's allowlist. A consumer that blocks its
    own LAN because an analyst tested from it is worse than no feed, and one
    that is handed a network or a hostname by a stored value is worse still,
    so nothing reaches the output that did not pass through ``ipaddress``.
    """
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if not address.is_global or address.is_multicast:
        return None
    if any(address.version == net.version and address in net for net in allowlist):
        return None
    return str(address)


def _feed_line(value: str) -> Optional[str]:
    """A non-address indicator as one feed line, or None if it cannot be one.

    The file is one value per line with ``#`` comments. A stored value that
    contains a line break would put a second, attacker-chosen entry into
    whatever reads it.
    """
    value = str(value).strip()
    if not value or value.startswith("#"):
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return None
    return value


@router.get("/feed", response_class=PlainTextResponse)
async def ioc_feed(
    ioc_type: str = Query("ip", description="Indicator type to emit"),
    min_sessions: int = Query(2, ge=1, le=1_000_000),
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

    The address feed (``ioc_type=ip``, the default) lists only addresses that
    themselves connected to a decoy: rows tagged ``attacker_ip``. An address
    that an attacker merely typed, or that a payload mentions, is not
    something this system saw attack anyone, and typing a victim's address
    into a honeypot must not be a way to have it blocked. Those are stored
    as ``referenced_ip`` and are never exported here.
    """
    if ioc_type not in KNOWN_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown indicator type {ioc_type!r}. "
                   f"Expected one of: {', '.join(sorted(KNOWN_TYPES))}",
        )
    if ioc_type == "referenced_ip":
        raise HTTPException(
            status_code=400,
            detail="Addresses that were only referenced in captured text are "
                   "not exported as a blocklist. Use ioc_type=ip for addresses "
                   "that connected to a decoy.",
        )

    conditions = [IndicatorOfCompromise.ioc_type == ioc_type]
    if ioc_type == "ip":
        conditions.append(_tagged(db, ATTACKER_IP_TAG))
    if exclude_scanners:
        conditions.append(_scanner_exclusion())

    rows = (
        await db.execute(
            select(
                IndicatorOfCompromise.value,
                func.count(func.distinct(IndicatorOfCompromise.session_id)).label("n"),
            )
            .where(*conditions)
            .group_by(IndicatorOfCompromise.value)
            .having(
                func.count(func.distinct(IndicatorOfCompromise.session_id))
                >= min_sessions
            )
            .order_by(desc("n"))
            .limit(10_000)
        )
    ).all()

    # Every line is rebuilt from a validated value; nothing is copied from
    # the table to the output as stored.
    lines: list[str] = []
    seen: set[str] = set()
    allowlist = _allowlist(get_settings().IOC_FEED_ALLOWLIST)
    for row in rows:
        if ioc_type == "ip":
            line = blockable_address(row.value, allowlist)
        else:
            line = _feed_line(row.value)
        if line is None or line in seen:
            continue
        seen.add(line)
        lines.append(line)

    now = datetime.now(timezone.utc)
    header = (
        f"# HoneySentinel indicator feed\n"
        f"# type={ioc_type} min_sessions={min_sessions} count={len(lines)}\n"
        f"# generated={now.isoformat()}\n"
    )
    body = header + "".join(f"{line}\n" for line in lines)
    filename = f"honeysentinel-{ioc_type}-{now.date().isoformat()}.txt"
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

