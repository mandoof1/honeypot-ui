"""Stage 2: semantic enrichment, from a durable queue.

The analysis pipeline is deliberately two-stage. Stage 1 is synchronous and
fast: the Random Forest and the rule layer classify the session inside the
ingest request and the session is written. Stage 2 is this: the transcript is
read by the project's language model, which answers in minutes on the
server's CPU, so it cannot sit anywhere near the request.

The queue is the sessions table itself. Ingest marks a session ``pending``
when it is worth a model call (``initial_status``); a single worker in the
backend service claims the oldest pending row, runs the model, and stores the
answer on the row. That replaces the fire-and-forget asyncio tasks that lived
in the four ingest workers' memory, raced each other for one inference slot,
and vanished on every restart.

Identical transcripts are analysed once: bots replay one script from many
addresses, and the hash on the session row lets later copies reuse the first
answer.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm import ModelUnavailable, chimera
from app.core.database import async_session_factory
from app.core.encryption import decrypt_data
from app.models import HoneypotSession, IndicatorOfCompromise

logger = logging.getLogger(__name__)

#: How long the worker sleeps when the queue is empty, and when the model is
#: unreachable (so a restarting inference server is not hammered).
IDLE_SLEEP_SECONDS = 15
UNAVAILABLE_SLEEP_SECONDS = 60

MANUAL_PRIORITY = 10

_WEB = {"http", "https"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def initial_status(session: HoneypotSession, nlp_result: Dict, session_data: Dict) -> str:
    """Decide at ingest whether this session goes to the model.

    "none" when no model is configured; "skipped" for sessions that would
    waste minutes of inference (research scanners, empty sessions, plain web
    browsing with no attack indicators); "pending" otherwise.
    """
    if not chimera.enabled:
        return "none"
    if session.scanner_operator:
        return "skipped"
    commands = session_data.get("commands") or []
    if not commands:
        return "skipped"
    category = session.attack_category.value if session.attack_category else "benign"
    protocol = (session.protocol or "").lower()
    if protocol in _WEB:
        interesting = (
            category != "benign"
            or bool(nlp_result.get("web_attacks"))
            or bool(session_data.get("uploads"))
            or bool(nlp_result.get("tool_names"))
        )
        return "pending" if interesting else "skipped"
    if protocol == "ftp":
        return "pending" if (category != "benign" or len(commands) >= 3) else "skipped"
    return "pending"


async def request(db: AsyncSession, session: HoneypotSession) -> str:
    """Queue a session on an analyst's request, ahead of the backlog."""
    session.enrichment_status = "pending"
    session.enrichment_priority = MANUAL_PRIORITY
    session.enrichment_error = None
    await db.flush()
    return session.enrichment_status


async def reset_stale_running(db: AsyncSession) -> int:
    """Rows left ``running`` by a worker that died mid-call go back to pending."""
    result = await db.execute(
        update(HoneypotSession)
        .where(HoneypotSession.enrichment_status == "running")
        .values(enrichment_status="pending")
    )
    await db.commit()
    return result.rowcount or 0


async def pending_count(db: AsyncSession) -> int:
    from sqlalchemy import func

    return (
        await db.execute(
            select(func.count(HoneypotSession.id)).where(
                HoneypotSession.enrichment_status == "pending"
            )
        )
    ).scalar() or 0


async def claim_next(db: AsyncSession) -> Optional[HoneypotSession]:
    """Take the highest-priority, oldest pending session, or None.

    Single worker by design, so a plain select-then-update is enough; the
    status check in the UPDATE still makes a second worker harmless.
    """
    candidate = (
        await db.execute(
            select(HoneypotSession)
            .where(HoneypotSession.enrichment_status == "pending")
            .order_by(HoneypotSession.enrichment_priority.desc(), HoneypotSession.id.asc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if candidate is None:
        return None
    result = await db.execute(
        update(HoneypotSession)
        .where(
            HoneypotSession.id == candidate.id,
            HoneypotSession.enrichment_status == "pending",
        )
        .values(enrichment_status="running")
    )
    if not result.rowcount:
        return None
    await db.commit()
    await db.refresh(candidate)
    return candidate


async def process(db: AsyncSession, session: HoneypotSession) -> str:
    """Analyse one claimed session and store the outcome. Returns the status."""
    commands = _decrypt_commands(session)
    if not commands:
        session.enrichment_status = "skipped"
        session.enrichment_error = "no commands stored"
        await db.commit()
        return session.enrichment_status

    cached = await _cached_analysis(db, session)
    if cached is not None:
        _store(session, cached, reused_from=cached.get("_from_session"))
        await _replace_iocs(db, session, cached)
        await db.commit()
        logger.info("Session %s reused the analysis of session %s", session.id, cached.get("_from_session"))
        return session.enrichment_status

    try:
        analysis = await chimera.analyse(commands, protocol=session.protocol or "ssh")
    except ModelUnavailable as exc:
        # Not the session's fault: leave it queued and let the worker back off.
        session.enrichment_status = "pending"
        session.enrichment_error = f"model unavailable: {exc}"[:500]
        await db.commit()
        raise

    if analysis is None:
        session.enrichment_status = "failed"
        session.enrichment_error = "the model did not return a usable answer"
        session.enriched_at = _now()
        await db.commit()
        return session.enrichment_status

    _store(session, analysis)
    await _replace_iocs(db, session, analysis)
    await db.commit()
    logger.info(
        "Enriched session %s: %d technique(s), %d objective(s)",
        session.id,
        len(analysis["mitre_techniques"]),
        len(analysis["objectives"]),
    )
    return session.enrichment_status


async def run_once(db: AsyncSession) -> bool:
    """Claim and process one session. Returns False when the queue is empty."""
    session = await claim_next(db)
    if session is None:
        return False
    try:
        await process(db, session)
    except ModelUnavailable:
        raise
    except Exception as exc:
        logger.exception("Enrichment failed for session %s", session.id)
        try:
            session.enrichment_status = "failed"
            session.enrichment_error = str(exc)[:500]
            session.enriched_at = _now()
            await db.commit()
        except Exception:
            await db.rollback()
    return True


async def worker(stop: asyncio.Event) -> None:
    """Drain the queue forever; the scheduler runs this in the backend service."""
    if not chimera.enabled:
        logger.info("Enrichment worker idle: CHIMERA_URL is not set")
        return
    async with async_session_factory() as db:
        reset = await reset_stale_running(db)
    if reset:
        logger.info("Re-queued %d session(s) left running by a previous worker", reset)
    unavailable_streak = 0
    while not stop.is_set():
        try:
            async with async_session_factory() as db:
                did_work = await run_once(db)
            unavailable_streak = 0
        except ModelUnavailable as exc:
            unavailable_streak += 1
            if unavailable_streak in (1, 10, 100):
                logger.warning("Analysis model unavailable (%s); will retry", exc)
            did_work = False
            await _sleep(stop, UNAVAILABLE_SLEEP_SECONDS)
            continue
        except Exception:
            logger.exception("Enrichment worker iteration failed")
            did_work = False
        if not did_work:
            await _sleep(stop, IDLE_SLEEP_SECONDS)


async def _sleep(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


def _decrypt_commands(session: HoneypotSession) -> list[str]:
    if not session.raw_commands_encrypted:
        return []
    try:
        raw = decrypt_data(session.raw_commands_encrypted)
    except ValueError:
        logger.warning("Could not decrypt commands for session %s", session.id)
        return []
    return [line for line in raw.splitlines() if line.strip()]


async def _cached_analysis(db: AsyncSession, session: HoneypotSession) -> Optional[Dict]:
    """An earlier complete analysis of the identical transcript, if any."""
    if not session.transcript_sha256:
        return None
    row = (
        await db.execute(
            select(HoneypotSession)
            .where(
                HoneypotSession.transcript_sha256 == session.transcript_sha256,
                HoneypotSession.enrichment_status == "complete",
                HoneypotSession.id != session.id,
                HoneypotSession.enrichment.isnot(None),
            )
            .order_by(HoneypotSession.id.asc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None or not isinstance(row.enrichment, dict):
        return None
    cached = dict(row.enrichment)
    cached["_from_session"] = row.id
    # Rebuild the shape analyse() returns so storage is uniform.
    cached.setdefault("mitre_techniques", [])
    cached.setdefault("iocs", {"hosts": [], "urls": [], "files": []})
    return cached


def _store(session: HoneypotSession, analysis: Dict, reused_from: Optional[int] = None) -> None:
    _merge_techniques(session, analysis)
    session.enrichment = {
        "intent": analysis.get("intent", ""),
        "objectives": list(analysis.get("objectives") or []),
        "sophistication": analysis.get("sophistication", "unknown"),
        "confidence": analysis.get("confidence"),
        "model": analysis.get("model") or chimera.model_name,
        "mitre_techniques": list(analysis.get("mitre_techniques") or []),
        "iocs": analysis.get("iocs") or {"hosts": [], "urls": [], "files": []},
        "tokens": analysis.get("tokens"),
        "reused_from_session": reused_from,
        "analysed_at": _now().isoformat(),
    }
    session.enrichment_status = "complete"
    session.enrichment_error = None
    session.enriched_at = _now()
    session.enrichment_priority = 0


def _merge_techniques(session: HoneypotSession, analysis: Dict) -> None:
    """Add techniques the rule-based mapper missed, without displacing it.

    Union rather than replace: a hallucinated technique must not be able to
    remove a matched one. Techniques from an earlier model run are dropped
    first so a re-run does not accumulate.
    """
    existing = [
        t for t in (session.mitre_techniques or [])
        if isinstance(t, dict) and t.get("source") != "chimera"
    ]
    known = {t.get("id") for t in existing}
    tactics = list(session.mitre_tactics or [])

    from app.ai.mitre_mapper import mitre_mapper

    for technique in analysis.get("mitre_techniques") or []:
        if technique["id"] in known:
            continue
        # The canonical name when the id is known; the model's own label only
        # as a fallback (it named T1203 "Product Discovery" in production).
        name = mitre_mapper.technique_name(technique["id"]) or technique.get("name") or ""
        existing.append({"id": technique["id"], "name": name, "source": "chimera",
                         "confidence": analysis.get("confidence")})
        known.add(technique["id"])
        tactic = mitre_mapper.tactic_for_technique(technique["id"])
        if tactic and tactic not in tactics:
            tactics.append(tactic)

    session.mitre_techniques = existing
    session.mitre_tactics = tactics


async def _replace_iocs(db: AsyncSession, session: HoneypotSession, analysis: Dict) -> None:
    """Record the model's verified indicators, replacing any from an earlier run."""
    old = (
        await db.execute(
            select(IndicatorOfCompromise).where(
                IndicatorOfCompromise.session_id == session.id,
            )
        )
    ).scalars().all()
    for row in old:
        if isinstance(row.tags, list) and "chimera" in row.tags:
            await db.delete(row)

    existing_values = {
        (row.ioc_type, row.value) for row in old
        if not (isinstance(row.tags, list) and "chimera" in row.tags)
    }
    iocs = analysis.get("iocs") or {}
    confidence = analysis.get("confidence")
    for kind, values in (("hosts", iocs.get("hosts")), ("urls", iocs.get("urls")), ("files", iocs.get("files"))):
        for value in values or []:
            value = str(value).strip()[:500]
            if not value:
                continue
            ioc_type = _ioc_type(kind, value)
            if (ioc_type, value) in existing_values:
                continue
            existing_values.add((ioc_type, value))
            db.add(
                IndicatorOfCompromise(
                    session_id=session.id,
                    ioc_type=ioc_type,
                    value=value,
                    confidence=confidence,
                    tags=["chimera", "model"],
                )
            )


def _ioc_type(kind: str, value: str) -> str:
    """Use the pipeline's vocabulary (ip, domain, url, filename), not the model's."""
    import ipaddress

    if kind == "urls":
        return "url"
    if kind == "files":
        return "filename"
    host = value.split(":")[0]
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"
