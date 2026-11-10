import json
import logging
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.ai.llm import chimera
from app.core.clientip import client_ip
from app.core.database import get_db
from app.core.dberrors import is_data_error
from app.core.sanitize import clean_json
from app.core.security import (
    EngineCredential,
    authorize_engine_for_node,
    get_current_user,
    require_role,
    verify_honeypot_token,
)
from app.models import Alert, AlertStatus, HoneypotSession, HoneypotNode, AuditLog
from app.core.encryption import decrypt_data, session_context
from app.schemas import (
    HoneypotSessionResponse,
    SessionListResponse,
    SessionTranscriptResponse,
    SessionCredentialsResponse,
    TranscriptEntry,
    CapturedCredential,
)
from app.schemas.ingest import SessionIngest
from app.api.export import FILE_EXTENSIONS, MEDIA_TYPES, _render, load_iocs
from app.services.session_filters import presence_flags, session_filters, without_blobs
from app.services.analysis import analysis_pipeline
from app.services import artifacts, enrichment, payload_enrichment

logger = logging.getLogger(__name__)
router = APIRouter()

#: Most recent sessions the per-address summary aggregates over. An address
#: that scans all day has tens of thousands; the summary used to load every
#: one of them, encrypted blobs included, on each request.
ATTACKER_SUMMARY_SESSIONS = 1000
#: Sessions whose stored credentials are decrypted to list usernames tried.
ATTACKER_SUMMARY_CREDENTIAL_SESSIONS = 200

_UNSTORABLE = (
    "The session could not be stored: the database rejected one of its values."
)


def _without_nul(value):
    """Escape what PostgreSQL cannot store, anywhere in a captured session.

    PostgreSQL text and JSONB cannot hold U+0000, and captures carry raw
    attacker bytes: a TLS ClientHello sent to the plain-HTTP decoy is full of
    them. Unescaped, the insert failed with a 500, and the engine re-sent the
    spooled session forever. Escaping keeps it visible that a NUL was there.
    Unpaired surrogates, which no UTF-8 encoder accepts, are replaced too.
    """
    return clean_json(value)


async def _store_or_422(db: AsyncSession, work):
    """Run a database write; turn "this value is unstorable" into a 422.

    The engine retries a 5xx for ever and files a 4xx under ``failed/``. A
    value the database will never accept must therefore not look like an
    outage. Anything that is not a data error (a lost connection, a deadlock)
    still propagates as a 500, because retrying those is right.
    """
    try:
        return await work()
    except DBAPIError as exc:
        await db.rollback()
        if not is_data_error(exc):
            raise
        logger.warning("Session rejected by the database as unstorable: %s", exc.orig)
        raise HTTPException(status_code=422, detail=_UNSTORABLE) from exc


@router.post("/ingest-internal")
async def ingest_session_from_honeypot(
    payload: SessionIngest,
    node_id: int = Query(1),
    db: AsyncSession = Depends(get_db),
    credential: EngineCredential = Depends(verify_honeypot_token),
):
    """Ingest a session from the honeypot engine (service-to-service)."""
    node_result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = node_result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Honeypot node not found")
    # The token must be the one for this node: with per-node tokens, one
    # engine cannot file sessions under another engine's name.
    authorize_engine_for_node(credential, node.name)
    session_data = _without_nul(payload.to_pipeline())
    uploads = session_data.get("uploads") or []

    # Idempotent on the engine's session id: the engine spools and resends
    # when the API was unreachable, and a resend must not become a second
    # session with a second alert.
    duplicate = await _existing_session(db, session_data.get("session_id"))
    if duplicate is not None:
        # The pipeline commits the session before the uploads are recorded.
        # If that second step failed the first time, this resend is the only
        # chance to record them; record_uploads adds only what is missing.
        async def record_missing():
            pending = await artifacts.record_uploads(db, duplicate.id, uploads)
            await db.commit()
            return pending

        pending_samples = await _store_or_422(db, record_missing)
        payload_enrichment.schedule(pending_samples)
        return {
            "session_id": duplicate.id,
            "session_uuid": duplicate.session_uuid,
            "duplicate": True,
            "ai_classification": {
                "category": duplicate.attack_category.value if duplicate.attack_category else "benign",
                "confidence": duplicate.attack_confidence,
            },
        }

    result = await _store_or_422(
        db, lambda: analysis_pipeline.process_session(db, session_data, node_id)
    )

    # Record uploaded files in the ingest transaction — storing bytes and
    # linking them, no analysis — so it stays within the latency budget. The
    # sample ids that need reverse-engineering are returned for stage 2.
    async def record_and_audit():
        pending = await artifacts.record_uploads(db, result["session_id"], uploads)
        db.add(
            AuditLog(
                user_id=None,
                action="session_ingested_honeypot",
                resource_type="session",
                resource_id=result["session_id"],
                details={
                    "category": result["ai_classification"]["category"],
                    "source": "honeypot_engine",
                    "uploads": len(uploads),
                },
            )
        )
        await db.commit()
        return pending

    pending_samples = await _store_or_422(db, record_and_audit)

    # Payload analysis runs detached, after the response: a slow parser
    # degrades the depth of analysis, never the capture. The LLM stage is
    # queued on the session row and drained by the backend's worker.
    payload_enrichment.schedule(pending_samples)

    result["uploads_recorded"] = len(uploads)
    return result


async def _existing_session(db: AsyncSession, engine_session_id) -> HoneypotSession | None:
    import uuid as _uuid

    if not engine_session_id:
        return None
    try:
        key = str(_uuid.UUID(str(engine_session_id)))
    except (ValueError, TypeError, AttributeError):
        return None
    return (
        await db.execute(
            without_blobs(select(HoneypotSession).where(HoneypotSession.session_uuid == key))
        )
    ).scalar_one_or_none()


@router.get("/attacker/{ip}")
async def attacker_summary(
    ip: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Everything recorded about one source address, aggregated.

    The session list could be filtered by address, but an analyst asking "who
    is this" needs the picture across sessions: first and last seen, what
    protocols and categories, which tools and techniques, how many credential
    attempts and uploads, and whether anything is still open about it.
    Usernames tried are listed; passwords are not (those stay behind the
    admin-only, audited credentials endpoint).

    The counts and first/last seen cover every session from the address. The
    breakdowns (tools, techniques, usernames) cover its most recent
    ATTACKER_SUMMARY_SESSIONS; ``aggregated_sessions`` says how many that was.
    """
    ip = ip.strip()[:45]
    from_address = HoneypotSession.attacker_ip == ip

    totals = (
        await db.execute(
            select(
                func.count(HoneypotSession.id),
                func.min(HoneypotSession.started_at),
                func.max(HoneypotSession.started_at),
            ).where(from_address)
        )
    ).one()
    session_count, first_seen, last_seen = totals
    if not session_count:
        raise HTTPException(status_code=404, detail="No sessions from this address")

    newest_first = (desc(HoneypotSession.started_at), desc(HoneypotSession.id))

    # Only the columns the breakdowns read, and no encrypted ones.
    rows = (
        await db.execute(
            select(
                HoneypotSession.protocol,
                HoneypotSession.attack_category,
                HoneypotSession.detected_tools,
                HoneypotSession.detected_intents,
                HoneypotSession.mitre_techniques,
                HoneypotSession.node_id,
                HoneypotSession.uploaded_files,
                HoneypotSession.network_events,
                HoneypotSession.scanner_operator,
            )
            .where(from_address)
            .order_by(*newest_first)
            .limit(ATTACKER_SUMMARY_SESSIONS)
        )
    ).all()

    protocols, categories, tools, intents = Counter(), Counter(), Counter(), Counter()
    techniques, nodes = {}, set()
    upload_count = 0
    diverted = False
    scanner_operator = None
    for row in rows:
        protocols[row.protocol or "unknown"] += 1
        categories[row.attack_category.value if row.attack_category else "unknown"] += 1
        for tool in row.detected_tools or []:
            tools[str(tool)] += 1
        for intent in row.detected_intents or []:
            intents[str(intent)] += 1
        for technique in row.mitre_techniques or []:
            if isinstance(technique, dict) and technique.get("id"):
                entry = techniques.setdefault(
                    technique["id"],
                    {"id": technique["id"], "name": technique.get("name") or "", "count": 0},
                )
                entry["count"] += 1
                if not entry["name"] and technique.get("name"):
                    entry["name"] = technique["name"]
        nodes.add(row.node_id)
        upload_count += len(row.uploaded_files or [])
        if any(
            isinstance(event, dict) and event.get("event_type") == "http_diversion"
            for event in (row.network_events or [])
        ):
            diverted = True
        scanner_operator = scanner_operator or row.scanner_operator

    usernames = Counter()
    credential_attempts = 0
    credential_rows = (
        await db.execute(
            select(HoneypotSession.id, HoneypotSession.credentials_encrypted)
            .where(from_address, HoneypotSession.credentials_encrypted.isnot(None))
            .order_by(*newest_first)
            .limit(ATTACKER_SUMMARY_CREDENTIAL_SESSIONS)
        )
    ).all()
    for session_id, blob in credential_rows:
        try:
            attempts = json.loads(
                decrypt_data(blob, session_context(session_id, "credentials_encrypted"))
            )
        except (ValueError, json.JSONDecodeError):
            attempts = []
        for attempt in attempts if isinstance(attempts, list) else []:
            if isinstance(attempt, dict):
                credential_attempts += 1
                if attempt.get("username"):
                    usernames[str(attempt["username"])[:64]] += 1

    node_names = []
    if nodes:
        node_names = (
            await db.execute(select(HoneypotNode.name).where(HoneypotNode.id.in_(nodes)))
        ).scalars().all()

    alert_total = (
        await db.execute(select(func.count(Alert.id)).where(Alert.attacker_ip == ip))
    ).scalar() or 0
    alert_open = (
        await db.execute(
            select(func.count(Alert.id)).where(
                Alert.attacker_ip == ip,
                Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED]),
            )
        )
    ).scalar() or 0

    recent = (
        await db.execute(
            without_blobs(select(HoneypotSession, *presence_flags()))
            .where(from_address)
            .order_by(*newest_first)
            .limit(20)
        )
    ).all()
    latest = recent[0][0]

    return {
        "ip": ip,
        "scanner_operator": scanner_operator,
        "geo": {
            "country": latest.geo_country,
            "country_name": latest.geo_country_name,
            "city": latest.geo_city,
            "lat": latest.geo_lat,
            "lon": latest.geo_lon,
        } if latest.geo_country else None,
        "first_seen": _isoformat(first_seen),
        "last_seen": _isoformat(last_seen),
        "session_count": session_count,
        "aggregated_sessions": len(rows),
        "alert_count": alert_total,
        "open_alert_count": alert_open,
        "protocols": dict(protocols),
        "categories": dict(categories),
        "nodes": sorted(node_names),
        "tools": [{"name": k, "count": v} for k, v in tools.most_common(20)],
        "intents": [{"name": k, "count": v} for k, v in intents.most_common(20)],
        "techniques": sorted(techniques.values(), key=lambda t: -t["count"])[:30],
        "credential_attempts": credential_attempts,
        "top_usernames": [{"username": k, "count": v} for k, v in usernames.most_common(10)],
        "upload_count": upload_count,
        "diverted": diverted,
        "sessions": [
            HoneypotSessionResponse.from_model(
                session, has_transcript=has_transcript, has_credentials=has_credentials
            )
            for session, has_transcript, has_credentials in recent
        ],
    }


def _isoformat(value) -> str | None:
    # SQLite hands an aggregate over a datetime column back as text.
    if value is None or isinstance(value, str):
        return value
    return value.isoformat()


@router.post("/{session_id}/enrich", status_code=202)
async def request_enrichment(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    """Queue (or re-queue) a session for the language model, ahead of the backlog."""
    if not chimera.enabled:
        raise HTTPException(status_code=400, detail="No analysis model is configured (CHIMERA_URL)")
    session = (
        await db.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
    ).scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.raw_commands_encrypted:
        raise HTTPException(status_code=400, detail="This session recorded no commands to analyse")
    if session.enrichment_status == "running":
        return {"session_id": session.id, "enrichment_status": "running"}
    status = await enrichment.request(db, session)
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="enrichment_requested",
            resource_type="session",
            resource_id=session.id,
        )
    )
    await db.commit()
    return {"session_id": session.id, "enrichment_status": status}


@router.get("/", response_model=SessionListResponse)
async def list_sessions(
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(20, ge=1, le=100),
    filters=Depends(session_filters),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = without_blobs(select(HoneypotSession, *presence_flags()))
    count_query = select(func.count(HoneypotSession.id))

    if filters is not None:
        query = query.where(filters)
        count_query = count_query.where(filters)

    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(HoneypotSession.started_at), desc(HoneypotSession.id)).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(query)).all()

    return SessionListResponse(
        sessions=[
            HoneypotSessionResponse.from_model(
                session, has_transcript=has_transcript, has_credentials=has_credentials
            )
            for session, has_transcript, has_credentials in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


async def _session_response(db: AsyncSession, condition) -> HoneypotSessionResponse:
    """One session for the detail view, without pulling its encrypted blobs."""
    row = (
        await db.execute(
            without_blobs(select(HoneypotSession, *presence_flags())).where(condition)
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Session not found")
    session, has_transcript, has_credentials = row
    return HoneypotSessionResponse.from_model(
        session, has_transcript=has_transcript, has_credentials=has_credentials
    )


@router.get("/{session_id}", response_model=HoneypotSessionResponse)
async def get_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    return await _session_response(db, HoneypotSession.id == session_id)


@router.get("/uuid/{session_uuid}", response_model=HoneypotSessionResponse)
async def get_session_by_uuid(
    session_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    return await _session_response(db, HoneypotSession.session_uuid == session_uuid[:64])


@router.get("/{session_id}/transcript", response_model=SessionTranscriptResponse)
async def get_session_transcript(
    session_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    # Analyst and above. The transcript is everything the attacker typed and
    # everything the decoy answered, passwords typed at prompts included; it
    # is the same evidence the exports carry, which are analyst-only too.
    current_user: dict = Depends(require_role("analyst")),
):
    """The commands the attacker ran and what the honeypot appeared to reply.

    The transcript has been captured and encrypted since the pipeline was
    written; nothing read it back out. It is the primary evidence a honeypot
    produces, and it lived in a column no endpoint touched.

    Kept off the session object and behind its own request on purpose: the
    list view returns hundreds of sessions and none of them need to carry a
    decrypted transcript, and separating it means the read can be audited.
    It is: every read writes a ``transcript_viewed`` audit row before the
    transcript is returned.
    """
    row = (
        await db.execute(
            select(
                HoneypotSession.id,
                HoneypotSession.session_uuid,
                HoneypotSession.transcript_encrypted,
                HoneypotSession.raw_commands_encrypted,
            ).where(HoneypotSession.id == session_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Session not found")

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="transcript_viewed",
            resource_type="session",
            resource_id=row.id,
            ip_address=client_ip(request),
        )
    )
    await db.commit()

    if not row.transcript_encrypted:
        # Sessions ingested before transcripts were carried still have the
        # command list, so fall back to it rather than showing nothing. The
        # outputs are genuinely absent, and the client shows them as such.
        if row.raw_commands_encrypted:
            try:
                commands = decrypt_data(
                    row.raw_commands_encrypted,
                    session_context(row.id, "raw_commands_encrypted"),
                ).splitlines()
            except ValueError:
                raise HTTPException(
                    status_code=422, detail="Stored transcript could not be decrypted"
                )
            return SessionTranscriptResponse(
                session_id=row.id,
                session_uuid=row.session_uuid,
                available=bool(commands),
                entries=[
                    TranscriptEntry(command=c) for c in commands if c.strip()
                ],
            )
        return SessionTranscriptResponse(
            session_id=row.id,
            session_uuid=row.session_uuid,
            available=False,
        )

    try:
        # The context makes a blob that was copied in from another column
        # (the admin-only credentials, say) fail here instead of being served.
        entries = json.loads(
            decrypt_data(
                row.transcript_encrypted,
                session_context(row.id, "transcript_encrypted"),
            )
        )
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="Stored transcript is malformed")
    except ValueError:
        raise HTTPException(
            status_code=422, detail="Stored transcript could not be decrypted"
        )
    if not isinstance(entries, list):
        raise HTTPException(status_code=422, detail="Stored transcript is malformed")

    return SessionTranscriptResponse(
        session_id=row.id,
        session_uuid=row.session_uuid,
        available=bool(entries),
        entries=[_transcript_entry(e) for e in entries if isinstance(e, dict)],
        truncated=len(entries) >= 500,
    )


def _transcript_entry(entry: dict) -> TranscriptEntry:
    """A stored transcript entry as a response row, tolerant of old shapes."""
    headers = entry.get("headers")
    return TranscriptEntry(
        command=str(entry.get("command") or ""),
        output=str(entry.get("output") or ""),
        exit_code=entry.get("exit_code") if isinstance(entry.get("exit_code"), int) else 0,
        timestamp=entry.get("timestamp") if isinstance(entry.get("timestamp"), (int, float)) else None,
        headers={str(k): str(v) for k, v in headers.items()} if isinstance(headers, dict) else None,
    )


@router.get("/{session_id}/credentials", response_model=SessionCredentialsResponse)
async def get_session_credentials(
    session_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    """Username/password pairs tried against the honeypot.

    Admin-only and audit-logged. These are live credentials in circulation
    against real hosts: whoever reads them can go and use them, so the read
    itself is an event worth recording.
    """
    row = (
        await db.execute(
            select(HoneypotSession.id, HoneypotSession.credentials_encrypted).where(
                HoneypotSession.id == session_id
            )
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Session not found")

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="credentials_viewed",
            resource_type="session",
            resource_id=row.id,
            ip_address=client_ip(request),
        )
    )
    await db.commit()

    if not row.credentials_encrypted:
        return SessionCredentialsResponse(session_id=row.id, available=False)

    try:
        rows = json.loads(
            decrypt_data(
                row.credentials_encrypted,
                session_context(row.id, "credentials_encrypted"),
            )
        )
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(
            status_code=422, detail="Stored credentials could not be read"
        )
    if not isinstance(rows, list):
        raise HTTPException(status_code=422, detail="Stored credentials could not be read")

    return SessionCredentialsResponse(
        session_id=row.id,
        available=bool(rows),
        credentials=[_credential(r) for r in rows if isinstance(r, dict)],
    )


def _credential(entry: dict) -> CapturedCredential:
    return CapturedCredential(
        username=str(entry.get("username") or ""),
        password=str(entry.get("password") or ""),
        success=entry.get("success") is True,
        timestamp=entry.get("timestamp") if isinstance(entry.get("timestamp"), (int, float)) else None,
    )


@router.post("/ingest")
async def ingest_session(
    payload: SessionIngest,
    node_id: int = Query(...),
    db: AsyncSession = Depends(get_db),
    # Admin only: this writes a session that is indistinguishable from a
    # capture and can raise alerts, so it is not an analyst capability.
    current_user: dict = Depends(require_role("admin")),
):
    node_result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = node_result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Honeypot node not found")

    session_data = _without_nul(payload.to_pipeline())
    result = await _store_or_422(
        db, lambda: analysis_pipeline.process_session(db, session_data, node_id)
    )

    audit = AuditLog(
        user_id=current_user["id"],
        action="session_ingested",
        resource_type="session",
        resource_id=result["session_id"],
        details={"category": result["ai_classification"]["category"]},
    )
    db.add(audit)
    await db.commit()

    return result


@router.post("/{session_id}/export")
async def export_session(
    session_id: int,
    format: str = Query("json", pattern="^(json|cef|stix)$"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    result = await db.execute(
        without_blobs(select(HoneypotSession).where(HoneypotSession.id == session_id))
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    content = _render(format, [session], await load_iocs(db, [session]))
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="session_exported",
            resource_type="session",
            resource_id=session.id,
            details={"format": format},
        )
    )
    await db.commit()
    return Response(
        content=content,
        media_type=MEDIA_TYPES[format],
        headers={
            "Content-Disposition": (
                f'attachment; filename="session_{session.session_uuid}'
                f'.{FILE_EXTENSIONS[format]}"'
            )
        },
    )
