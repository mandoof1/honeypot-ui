"""Explainable pivots on observed evidence; these are not actor attribution."""

from datetime import timedelta, timezone

from sqlalchemy import select, tuple_, or_

from app.models import HoneypotSession, IndicatorOfCompromise
from app.schemas import HoneypotSessionResponse

# Shared tool names and common filenames are too broad to imply a relation.
LINK_TYPES = ("domain", "url", "file_hash")
MAX_SEED_INDICATORS = 100


async def related_activity(db, anchor, window_days, limit, exclude_scanners):
    started = anchor.started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    window_start = started - timedelta(days=window_days)
    window_end = started + timedelta(days=window_days)
    ioc = IndicatorOfCompromise
    seed_rows = (await db.execute(
        select(ioc.ioc_type, ioc.value)
        .where(ioc.session_id == anchor.id, ioc.ioc_type.in_(LINK_TYPES), ioc.value != "")
        .distinct().order_by(ioc.ioc_type, ioc.value).limit(MAX_SEED_INDICATORS + 1)
    )).all()
    keys = [tuple(row) for row in seed_rows[:MAX_SEED_INDICATORS]]
    same_source = HoneypotSession.attacker_ip == anchor.attacker_ip if anchor.attacker_ip else False
    evidence_match = select(ioc.id).where(
        ioc.session_id == HoneypotSession.id,
        tuple_(ioc.ioc_type, ioc.value).in_(keys),
    ).exists()
    query = select(HoneypotSession).where(
        HoneypotSession.id != anchor.id,
        HoneypotSession.started_at >= window_start,
        HoneypotSession.started_at <= window_end,
        or_(same_source, evidence_match),
    )
    if exclude_scanners:
        query = query.where(HoneypotSession.scanner_operator.is_(None))
    rows = (await db.execute(query.order_by(
        HoneypotSession.started_at.desc(), HoneypotSession.id.desc(),
    ).limit(limit + 1))).scalars().all()
    selected = rows[:limit]
    shared = {}
    if selected and keys:
        matches = (await db.execute(select(ioc.session_id, ioc.ioc_type, ioc.value).where(
            ioc.session_id.in_([s.id for s in selected]),
            tuple_(ioc.ioc_type, ioc.value).in_(keys),
        ).distinct().order_by(ioc.ioc_type, ioc.value))).all()
        for session_id, kind, value in matches:
            shared.setdefault(session_id, []).append({"type": kind, "value": value})
    return {
        "session_id": anchor.id,
        "window_start": window_start, "window_end": window_end,
        "truncated": len(rows) > limit,
        "indicators_truncated": len(seed_rows) > MAX_SEED_INDICATORS,
        "matches": [{
            "session": HoneypotSessionResponse.from_model(s),
            "same_source_ip": bool(anchor.attacker_ip) and s.attacker_ip == anchor.attacker_ip,
            "shared_indicators": shared.get(s.id, [])[:5],
            "shared_indicator_count": len(shared.get(s.id, [])),
        } for s in selected],
    }
