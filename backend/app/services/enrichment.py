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

When a decision model is configured as well (DECIDER_URL, see ai/decider.py)
it goes first. Ingest marks the session ``triage`` instead of ``pending``;
the same worker triages it in seconds and only then routes it: on to the
language model, or skipped with the reason recorded. The decision model can
skip a session only when it is confident the session went no further than
information gathering *and* the rules agree, and it can send on a session
the rules would have skipped. After the language model answers, the decision
model checks each technique it named against the transcript.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.decider import DeciderUnavailable, decider
from app.ai.llm import ModelUnavailable, chimera
from app.core.config import get_settings
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

#: Monotonic time until which the decision model is treated as down, so a
#: stopped container is not called on every turn of the worker loop.
_decider_down_until = 0.0
#: The same for the language model, set by the worker loop.
_chimera_down_until = 0.0


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


def queue_at_ingest(session: HoneypotSession, nlp_result: Dict, session_data: Dict) -> None:
    """Set the session's stage-2 state at ingest.

    The rules' verdict (``initial_status``) stands on its own when there is
    no decision model. With one, every session with commands from an address
    that is not a known research scanner is triaged first, and the verdict
    is kept on the row for the triage step to weigh.
    """
    verdict = initial_status(session, nlp_result, session_data)
    session.enrichment_status = verdict
    session.triage_status = "none"
    if not decider.enabled or session.scanner_operator or not session_data.get("commands"):
        return
    session.triage_status = "pending"
    session.triage = {"rules_verdict": verdict}
    if chimera.enabled:
        session.enrichment_status = "triage"


def route_after_triage(
    rules_verdict: str, rules_category: str, triage: Dict
) -> Tuple[str, str]:
    """Where a triaged session goes next: ("pending" | "skipped", reason).

    Asymmetric on purpose. Skipping needs the decision model to be confident
    and the rules to have found nothing past reconnaissance, because a
    skipped session is never read by the language model unless an analyst
    asks. Escalating a session the rules skipped only needs a likely
    compromise: the cost of being wrong there is a few minutes of CPU.
    """
    settings = get_settings()
    p_low = float(triage.get("p_low") or 0.0)
    p_compromise = float(triage.get("p_compromise") or 0.0)
    if rules_verdict == "pending":
        if p_low >= settings.DECIDER_SKIP_THRESHOLD and rules_category in ("benign", "reconnaissance"):
            return "skipped", f"triage: information gathering at most ({p_low:.0%}), and the rules agree"
        return "pending", "the rules flagged it and triage did not rule it out"
    if p_compromise >= settings.DECIDER_ESCALATE_THRESHOLD:
        return "pending", f"triage: likely an attempted compromise ({p_compromise:.0%}) that the rules did not flag"
    return "skipped", "neither the rules nor triage found it worth reading"


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
    triage = await db.execute(
        update(HoneypotSession)
        .where(HoneypotSession.triage_status == "running")
        .values(triage_status="pending")
    )
    await db.commit()
    return (result.rowcount or 0) + (triage.rowcount or 0)


async def pending_count(db: AsyncSession) -> int:
    from sqlalchemy import func

    return (
        await db.execute(
            select(func.count(HoneypotSession.id)).where(
                HoneypotSession.enrichment_status == "pending"
            )
        )
    ).scalar() or 0


async def triage_pending_count(db: AsyncSession) -> int:
    from sqlalchemy import func

    return (
        await db.execute(
            select(func.count(HoneypotSession.id)).where(HoneypotSession.triage_status == "pending")
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


async def claim_next_triage(db: AsyncSession) -> Optional[HoneypotSession]:
    """Take the oldest session waiting on triage, or None."""
    candidate = (
        await db.execute(
            select(HoneypotSession)
            .where(HoneypotSession.triage_status == "pending")
            .order_by(HoneypotSession.id.asc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if candidate is None:
        return None
    result = await db.execute(
        update(HoneypotSession)
        .where(HoneypotSession.id == candidate.id, HoneypotSession.triage_status == "pending")
        .values(triage_status="running")
    )
    if not result.rowcount:
        return None
    await db.commit()
    await db.refresh(candidate)
    return candidate


async def process_triage(db: AsyncSession, session: HoneypotSession) -> str:
    """Triage one claimed session, then route it. Returns the triage status.

    Raises DeciderUnavailable after putting the row back, so the worker can
    stop calling a model that is down.
    """
    commands = _decrypt_commands(session)
    previous = session.triage if isinstance(session.triage, dict) else {}
    if not commands:
        _finish_triage(session, previous, None, "no commands stored")
        await db.commit()
        return session.triage_status

    result = await _cached_triage(db, session)
    reused_from = result.pop("_from_session", None) if result else None
    if result is None:
        try:
            result = await decider.triage(
                commands,
                protocol=session.protocol or "ssh",
                duration_seconds=session.duration_seconds,
                keystrokes=session.keystroke_count,
            )
        except DeciderUnavailable:
            session.triage_status = "pending"
            await db.commit()
            raise
    if result is None:
        _finish_triage(session, previous, None, "the decision model did not return a usable answer")
        await db.commit()
        return session.triage_status

    result["reused_from_session"] = reused_from
    _finish_triage(session, previous, result, None)
    await db.commit()
    logger.info(
        "Triaged session %s: %s, severity %.2f, %s -> %s",
        session.id, result["category"], result["severity"], result["operator"],
        session.triage.get("route"),
    )
    return session.triage_status


def _finish_triage(session: HoneypotSession, previous: Dict, result: Optional[Dict], error: Optional[str]) -> None:
    """Store the outcome and move the session on to its next stage.

    Without an answer the rules' verdict stands, exactly as if no decision
    model were configured. The route is only applied while the session is
    still waiting on triage: an analyst's "analyse now" in the meantime wins.
    """
    verdict = previous.get("rules_verdict") or "none"
    category = session.attack_category.value if session.attack_category else "benign"
    stored = {"rules_verdict": verdict}
    if result is None:
        route, reason = verdict, f"triage failed ({error}); the rules' verdict stands"
        session.triage_status = "failed"
    else:
        route, reason = route_after_triage(verdict, category, result)
        stored.update(result)
        stored["agrees_with_rules"] = result["category"] == category
        session.triage_status = "complete"
    stored["triaged_at"] = _now().isoformat()
    if error:
        stored["error"] = error
    if session.enrichment_status == "triage":
        stored["route"] = route
        stored["route_reason"] = reason
        session.enrichment_status = route
        if route == "skipped":
            session.enrichment_error = None
    else:
        # Not waiting on triage (an analyst queued it meanwhile, or it was
        # triaged after the fact): keep the recommendation, apply nothing.
        stored["suggested_route"] = route
        stored["route_reason"] = reason
    session.triage = stored
    session.triaged_at = _now()


async def _cached_triage(db: AsyncSession, session: HoneypotSession) -> Optional[Dict]:
    """An earlier triage of the identical transcript, if any."""
    if not session.transcript_sha256:
        return None
    row = (
        await db.execute(
            select(HoneypotSession)
            .where(
                HoneypotSession.transcript_sha256 == session.transcript_sha256,
                HoneypotSession.protocol == session.protocol,
                HoneypotSession.triage_status == "complete",
                HoneypotSession.id != session.id,
            )
            .order_by(HoneypotSession.id.asc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None or not isinstance(row.triage, dict) or "category" not in row.triage:
        return None
    keep = (
        "category", "category_probabilities", "severity", "severity_probabilities",
        "p_low", "p_compromise", "operator", "operator_probability", "model",
        "input_tokens", "ms",
    )
    cached = {k: row.triage.get(k) for k in keep}
    cached["_from_session"] = row.id
    return cached


async def bypass_stale_triage(db: AsyncSession) -> int:
    """Route sessions that have waited too long on an unreachable decision model.

    A stopped decision model must not hold the language model's queue
    hostage: past DECIDER_FALLBACK_SECONDS the rules' verdict decides.
    """
    cutoff = _now() - timedelta(seconds=get_settings().DECIDER_FALLBACK_SECONDS)
    rows = (
        await db.execute(
            select(HoneypotSession)
            .where(HoneypotSession.triage_status == "pending", HoneypotSession.created_at < cutoff)
            .order_by(HoneypotSession.id.asc())
            .limit(100)
        )
    ).scalars().all()
    for session in rows:
        previous = session.triage if isinstance(session.triage, dict) else {}
        _finish_triage(session, previous, None, "the decision model was unreachable")
    if rows:
        await db.commit()
        logger.warning("Decision model unreachable: routed %d session(s) on the rules alone", len(rows))
    return len(rows)


def _decider_ready() -> bool:
    return decider.enabled and time.monotonic() >= _decider_down_until


def _mark_decider_down(exc: Exception) -> None:
    global _decider_down_until
    if time.monotonic() >= _decider_down_until:
        logger.warning("Decision model unavailable (%s); will retry", exc)
    _decider_down_until = time.monotonic() + UNAVAILABLE_SLEEP_SECONDS


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

    analysis = await _check_techniques(session, commands, analysis)
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


async def _check_techniques(session: HoneypotSession, commands: list[str], analysis: Dict) -> Dict:
    """Ask the decision model whether the transcript shows each technique.

    Each technique gains ``support``, the probability that it does. Below
    DECIDER_SUPPORT_THRESHOLD it is marked unconfirmed, and removed only
    when DECIDER_DROP_UNCONFIRMED is set. A missing or unreachable decision
    model leaves the analysis as it was.
    """
    techniques = analysis.get("mitre_techniques") or []
    if not techniques or not _decider_ready():
        return analysis
    try:
        support = await decider.check_techniques(commands, session.protocol or "ssh", techniques)
    except DeciderUnavailable as exc:
        _mark_decider_down(exc)
        return analysis
    if not support:
        return analysis

    settings = get_settings()
    checked, dropped = [], []
    for technique in techniques:
        value = support.get(technique["id"])
        technique = {**technique, "support": value}
        if value is not None and value < settings.DECIDER_SUPPORT_THRESHOLD:
            technique["unconfirmed"] = True
            if settings.DECIDER_DROP_UNCONFIRMED:
                dropped.append(technique)
                continue
        checked.append(technique)
    analysis = {**analysis, "mitre_techniques": checked, "checked_by": decider.model_name}
    if dropped:
        analysis["dropped_techniques"] = dropped
        logger.info("Dropped %d technique(s) the transcript does not support", len(dropped))
    return analysis


async def run_once(db: AsyncSession) -> bool:
    """Do one unit of stage-2 work. Returns False when there was nothing to do.

    Triage first: it takes seconds, and the language model's queue depends
    on it. The two models never run at the same time, so each can be given
    most of the CPU.
    """
    if _decider_ready():
        triage_session = await claim_next_triage(db)
        if triage_session is not None:
            try:
                await process_triage(db, triage_session)
            except DeciderUnavailable as exc:
                _mark_decider_down(exc)
            except Exception as exc:
                logger.exception("Triage failed for session %s", triage_session.id)
                try:
                    previous = triage_session.triage if isinstance(triage_session.triage, dict) else {}
                    _finish_triage(triage_session, previous, None, str(exc)[:200])
                    await db.commit()
                except Exception:
                    await db.rollback()
            return True
    elif decider.enabled:
        await bypass_stale_triage(db)

    if not chimera.enabled or time.monotonic() < _chimera_down_until:
        return False
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
    if not chimera.enabled and not decider.enabled:
        logger.info("Enrichment worker idle: neither CHIMERA_URL nor DECIDER_URL is set")
        return
    async with async_session_factory() as db:
        reset = await reset_stale_running(db)
    if reset:
        logger.info("Re-queued %d session(s) left running by a previous worker", reset)
    global _chimera_down_until
    unavailable_streak = 0
    while not stop.is_set():
        try:
            async with async_session_factory() as db:
                did_work = await run_once(db)
            if time.monotonic() >= _chimera_down_until:
                unavailable_streak = 0
        except ModelUnavailable as exc:
            unavailable_streak += 1
            if unavailable_streak in (1, 10, 100):
                logger.warning("Analysis model unavailable (%s); will retry", exc)
            # Stop claiming language-model work for a while, but keep
            # triaging: the decision model is a separate server.
            _chimera_down_until = time.monotonic() + UNAVAILABLE_SLEEP_SECONDS
            did_work = False
            await _sleep(stop, IDLE_SLEEP_SECONDS if decider.enabled else UNAVAILABLE_SLEEP_SECONDS)
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
        "checked_by": analysis.get("checked_by"),
        "dropped_techniques": list(analysis.get("dropped_techniques") or []),
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
        entry = {"id": technique["id"], "name": name, "source": "chimera",
                 "confidence": analysis.get("confidence")}
        if technique.get("support") is not None:
            entry["support"] = technique["support"]
            entry["unconfirmed"] = bool(technique.get("unconfirmed"))
        existing.append(entry)
        known.add(technique["id"])
        tactic = mitre_mapper.tactic_for_technique(technique["id"])
        # An unconfirmed technique is still listed, but does not add a
        # tactic to the session's coverage on its own say-so.
        if tactic and tactic not in tactics and not entry.get("unconfirmed"):
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
