"""The dashboard's summary, live feed and trend series."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, literal_column, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import load_only

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import get_current_user
from app.models import AttackCategory, HoneypotSession
from app.schemas import DashboardStats
from app.schemas.operations import TrendPoint, TrendSeries
from app.services.analysis import dashboard_service

router = APIRouter()

#: Largest live-events page. The dashboard shows fifty.
MAX_LIVE_EVENTS = 200

#: Windows the trend series is offered for.
TREND_WINDOWS = (7, 30, 90)

_CATEGORIES = tuple(category.value for category in AttackCategory)


class _ShortCache:
    """Remember a computed response for a few seconds.

    The summary is a dozen aggregate queries over the whole sessions table,
    and every open dashboard asks for it again every few seconds. Nothing in
    it changes meaningfully in that time, so the answer is kept for
    DASHBOARD_CACHE_SECONDS and shared between everyone asking.

    In-process, like the rate limiter: the dashboard API runs as one process.
    Entries are whole-deployment aggregates, the same for every signed-in
    user, so sharing one between users leaks nothing.
    """

    def __init__(self) -> None:
        self._entries: Dict[str, Tuple[float, Any]] = {}
        self._locks: Dict[str, Tuple[asyncio.AbstractEventLoop, asyncio.Lock]] = {}

    def _lock(self, key: str) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        held = self._locks.get(key)
        if held is None or held[0] is not loop:
            held = (loop, asyncio.Lock())
            self._locks[key] = held
        return held[1]

    async def get(self, key: str, compute: Callable[[], Awaitable[Any]]) -> Any:
        ttl = get_settings().DASHBOARD_CACHE_SECONDS
        if ttl <= 0:
            return await compute()

        entry = self._entries.get(key)
        if entry is not None and entry[0] > time.monotonic():
            return entry[1]

        # One caller recomputes; the others wait for that result instead of
        # all running the same dozen queries the moment the entry expires.
        async with self._lock(key):
            entry = self._entries.get(key)
            if entry is not None and entry[0] > time.monotonic():
                return entry[1]
            value = await compute()
            self._entries[key] = (time.monotonic() + ttl, value)
            return value

    def clear(self) -> None:
        self._entries.clear()


summary_cache = _ShortCache()


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    return await summary_cache.get("stats", lambda: dashboard_service.get_stats(db))


@router.get("/live-events")
async def get_live_events(
    limit: int = Query(50, ge=1, le=MAX_LIVE_EVENTS),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """The most recent sessions, as the feed shows them.

    Only the columns the feed reads are fetched. The query used to select
    whole session rows, encrypted transcript and payload included, for
    however many rows the caller asked for, and ``limit`` had no upper bound.
    """
    rows = (
        await db.execute(
            select(HoneypotSession)
            .options(
                load_only(
                    HoneypotSession.id,
                    HoneypotSession.session_uuid,
                    HoneypotSession.protocol,
                    HoneypotSession.attacker_ip,
                    HoneypotSession.geo_country,
                    HoneypotSession.geo_country_name,
                    HoneypotSession.geo_lat,
                    HoneypotSession.geo_lon,
                    HoneypotSession.attack_category,
                    HoneypotSession.attack_confidence,
                    HoneypotSession.attacker_profile,
                    HoneypotSession.started_at,
                    # What the one severity definition reads
                    # (ai/verdict.stored_severity).
                    HoneypotSession.model_source,
                    HoneypotSession.detected_tools,
                    HoneypotSession.detected_intents,
                    HoneypotSession.signals,
                    raiseload=True,
                )
            )
            .order_by(desc(HoneypotSession.started_at), desc(HoneypotSession.id))
            .limit(limit)
        )
    ).scalars().all()

    return [
        {
            # The UI joins alerts to their source session by numeric id;
            # only the UUID was exposed, so the join never matched.
            "session_id": s.id,
            "session_uuid": s.session_uuid,
            "protocol": s.protocol,
            "attacker_ip": s.attacker_ip,
            "geo_country": s.geo_country,
            "geo_country_name": s.geo_country_name,
            "geo_lat": s.geo_lat,
            "geo_lon": s.geo_lon,
            "attack_category": s.attack_category.value if s.attack_category else None,
            # The feed's hands-on marker reads this; it was never sent.
            "attacker_profile": s.attacker_profile.value if s.attacker_profile else None,
            # One definition of severity, kept with the rest of the summary.
            "severity": dashboard_service._session_severity(s),
            "timestamp": s.started_at.isoformat(),
        }
        for s in rows
    ]


def _utc_day(db: AsyncSession):
    """A SQL expression for the UTC calendar day a session started on."""
    if db.get_bind().dialect.name == "postgresql":
        # timestamptz -> wall clock in UTC -> date. Without the explicit
        # zone the day boundary would follow the server's TimeZone setting.
        # The zone is written into the SQL rather than bound: as a bound
        # parameter it becomes a different placeholder in SELECT and in
        # GROUP BY, and PostgreSQL then refuses the query because the two
        # expressions no longer look alike.
        return func.date(
            func.timezone(literal_column("'UTC'"), HoneypotSession.started_at)
        )
    # SQLite (tests) stores the UTC wall-clock time as text.
    return func.date(HoneypotSession.started_at)


async def _trend_series(db: AsyncSession, days: int) -> TrendSeries:
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    first_day = today - timedelta(days=days - 1)

    day = _utc_day(db)
    rows = (
        await db.execute(
            select(day.label("day"), HoneypotSession.attack_category, func.count(HoneypotSession.id))
            .where(HoneypotSession.started_at >= first_day)
            .group_by(day, HoneypotSession.attack_category)
        )
    ).all()

    # Every day in the window gets an entry, so a chart drawn from this has
    # an honest gap for a quiet day rather than a line straight across it.
    points = {
        (first_day + timedelta(days=offset)).date().isoformat(): {
            "total": 0, **{category: 0 for category in _CATEGORIES},
        }
        for offset in range(days)
    }
    for day_value, category, count in rows:
        key = day_value if isinstance(day_value, str) else day_value.isoformat()
        point = points.get(key[:10])
        if point is None:
            continue  # a session stamped in the future
        point["total"] += count
        name = category.value if category is not None else None
        if name in point:
            point[name] += count

    return TrendSeries(
        series=[
            TrendPoint(t=f"{key}T00:00:00Z", **values)
            for key, values in sorted(points.items())
        ]
    )


@router.get("/trends", response_model=TrendSeries)
async def get_trends(
    days: int = Query(7, description="Window in days: 7, 30 or 90"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Sessions per UTC day over the last 7, 30 or 90 days, by category.

    ``total`` counts every session, including any without a category, so it
    can be larger than the four categories added together. The last entry is
    today so far.
    """
    if days not in TREND_WINDOWS:
        raise HTTPException(
            status_code=400,
            detail="days must be one of: " + ", ".join(str(d) for d in TREND_WINDOWS),
        )
    return await summary_cache.get(f"trends:{days}", lambda: _trend_series(db, days))
