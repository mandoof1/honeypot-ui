import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.ai.llm import chimera
from app.core.database import get_db
from app.core.security import get_current_user, require_role, verify_honeypot_token
from app.models import Alert, AlertStatus, HoneypotSession, HoneypotNode, AuditLog, IndicatorOfCompromise
from app.core.encryption import decrypt_data
from app.schemas import (
    HoneypotSessionResponse,
    SessionListResponse,
    SessionTranscriptResponse,
    SessionCredentialsResponse,
    TranscriptEntry,
    CapturedCredential,
)
from app.api.export import FILE_EXTENSIONS, MEDIA_TYPES, _render, load_iocs
from app.services.session_filters import session_filters
from app.services.analysis import analysis_pipeline
from app.services import artifacts, enrichment, payload_enrichment

router = APIRouter()


@router.post("/ingest-internal", dependencies=[Depends(verify_honeypot_token)])
async def ingest_session_from_honeypot(
    session_data: dict,
    node_id: int = Query(1),
    db: AsyncSession = Depends(get_db),
):
    """Ingest a session from the honeypot engine (service-to-service)."""
    node_result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = node_result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Honeypot node not found")

    # Idempotent on the engine's session id: the engine spools and resends
    # when the API was unreachable, and a resend must not become a second
    # session with a second alert.
    duplicate = await _existing_session(db, session_data.get("session_id"))
    if duplicate is not None:
        return {
            "session_id": duplicate.id,
            "session_uuid": duplicate.session_uuid,
            "duplicate": True,
            "ai_classification": {
                "category": duplicate.attack_category.value if duplicate.attack_category else "benign",
                "confidence": duplicate.attack_confidence,
            },
        }

    result = await analysis_pipeline.process_session(db, session_data, node_id)

    # Record uploaded files in the ingest transaction — storing bytes and
    # linking them, no analysis — so it stays within the latency budget. The
    # sample ids that need reverse-engineering are returned for stage 2.
    pending_samples = await artifacts.record_uploads(
        db, result["session_id"], session_data.get("uploads") or []
    )

    audit = AuditLog(
        user_id=None,
        action="session_ingested_honeypot",
        resource_type="session",
        resource_id=result["session_id"],
        details={
            "category": result["ai_classification"]["category"],
            "source": "honeypot_engine",
            "uploads": len(session_data.get("uploads") or []),
        },
    )
    db.add(audit)
    await db.commit()

    # Payload analysis runs detached, after the response: a slow parser
    # degrades the depth of analysis, never the capture. The LLM stage is
    # queued on the session row and drained by the backend's worker.
    payload_enrichment.schedule(pending_samples)

    result["uploads_recorded"] = len(session_data.get("uploads") or [])
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
        await db.execute(select(HoneypotSession).where(HoneypotSession.session_uuid == key))
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
    """
    ip = ip.strip()[:45]
    sessions = (
        await db.execute(
            select(HoneypotSession)
            .where(HoneypotSession.attacker_ip == ip)
            .order_by(desc(HoneypotSession.started_at), desc(HoneypotSession.id))
        )
    ).scalars().all()
    if not sessions:
        raise HTTPException(status_code=404, detail="No sessions from this address")

    from collections import Counter

    protocols, categories, tools, intents, techniques, nodes = (
        Counter(), Counter(), Counter(), Counter(), {}, set()
    )
    usernames = Counter()
    credential_attempts = upload_count = 0
    diverted = False
    for s in sessions:
        protocols[s.protocol or "unknown"] += 1
        categories[s.attack_category.value if s.attack_category else "unknown"] += 1
        for t in s.detected_tools or []:
            tools[str(t)] += 1
        for i in s.detected_intents or []:
            intents[str(i)] += 1
        for t in s.mitre_techniques or []:
            if isinstance(t, dict) and t.get("id"):
                entry = techniques.setdefault(t["id"], {"id": t["id"], "name": t.get("name") or "", "count": 0})
                entry["count"] += 1
                if not entry["name"] and t.get("name"):
                    entry["name"] = t["name"]
        nodes.add(s.node_id)
        upload_count += len(s.uploaded_files or [])
        if any(isinstance(e, dict) and e.get("event_type") == "http_diversion" for e in (s.network_events or [])):
            diverted = True
        if s.credentials_encrypted:
            try:
                rows = json.loads(decrypt_data(s.credentials_encrypted))
            except (ValueError, json.JSONDecodeError):
                rows = []
            for row in rows:
                if isinstance(row, dict):
                    credential_attempts += 1
                    if row.get("username"):
                        usernames[str(row["username"])[:64]] += 1

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

    latest = sessions[0]
    return {
        "ip": ip,
        "scanner_operator": next((s.scanner_operator for s in sessions if s.scanner_operator), None),
        "geo": {
            "country": latest.geo_country,
            "country_name": latest.geo_country_name,
            "city": latest.geo_city,
            "lat": latest.geo_lat,
            "lon": latest.geo_lon,
        } if latest.geo_country else None,
        "first_seen": min(s.started_at for s in sessions).isoformat(),
        "last_seen": max(s.started_at for s in sessions).isoformat(),
        "session_count": len(sessions),
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
        "sessions": [HoneypotSessionResponse.from_model(s) for s in sessions[:20]],
    }


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
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    filters=Depends(session_filters),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(HoneypotSession)
    count_query = select(func.count(HoneypotSession.id))

    if filters is not None:
        query = query.where(filters)
        count_query = count_query.where(filters)

    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(HoneypotSession.started_at), desc(HoneypotSession.id)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    sessions = result.scalars().all()

    return SessionListResponse(
        sessions=[HoneypotSessionResponse.from_model(s) for s in sessions],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{session_id}", response_model=HoneypotSessionResponse)
async def get_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return HoneypotSessionResponse.from_model(session)


@router.get("/uuid/{session_uuid}", response_model=HoneypotSessionResponse)
async def get_session_by_uuid(
    session_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.session_uuid == session_uuid))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return HoneypotSessionResponse.from_model(session)


@router.get("/{session_id}/transcript", response_model=SessionTranscriptResponse)
async def get_session_transcript(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """The commands the attacker ran and what the honeypot appeared to reply.

    The transcript has been captured and encrypted since the pipeline was
    written; nothing read it back out. It is the primary evidence a honeypot
    produces, and it lived in a column no endpoint touched.

    Kept off the session object and behind its own request on purpose: the
    list view returns hundreds of sessions and none of them need to carry a
    decrypted transcript, and separating it means the read can be audited.
    """
    session = (
        await db.execute(
            select(HoneypotSession).where(HoneypotSession.id == session_id)
        )
    ).scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if not session.transcript_encrypted:
        # Sessions ingested before transcripts were carried still have the
        # command list, so fall back to it rather than showing nothing. The
        # outputs are genuinely absent, and the client shows them as such.
        if session.raw_commands_encrypted:
            try:
                commands = decrypt_data(session.raw_commands_encrypted).splitlines()
            except ValueError:
                raise HTTPException(
                    status_code=422, detail="Stored transcript could not be decrypted"
                )
            return SessionTranscriptResponse(
                session_id=session.id,
                session_uuid=session.session_uuid,
                available=bool(commands),
                entries=[
                    TranscriptEntry(command=c) for c in commands if c.strip()
                ],
            )
        return SessionTranscriptResponse(
            session_id=session.id,
            session_uuid=session.session_uuid,
            available=False,
        )

    try:
        entries = json.loads(decrypt_data(session.transcript_encrypted))
    except ValueError:
        raise HTTPException(
            status_code=422, detail="Stored transcript could not be decrypted"
        )
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="Stored transcript is malformed")

    return SessionTranscriptResponse(
        session_id=session.id,
        session_uuid=session.session_uuid,
        available=bool(entries),
        entries=[TranscriptEntry(**e) for e in entries if isinstance(e, dict)],
        truncated=len(entries) >= 500,
    )


@router.get("/{session_id}/credentials", response_model=SessionCredentialsResponse)
async def get_session_credentials(
    session_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    """Username/password pairs tried against the honeypot.

    Admin-only and audit-logged, unlike everything else on a session. These
    are live credentials in circulation against real hosts: whoever reads them
    can go and use them, so the read itself is an event worth recording.
    """
    session = (
        await db.execute(
            select(HoneypotSession).where(HoneypotSession.id == session_id)
        )
    ).scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="credentials_viewed",
            resource_type="session",
            resource_id=session.id,
            ip_address=request.client.host if request.client else None,
        )
    )
    await db.commit()

    if not session.credentials_encrypted:
        return SessionCredentialsResponse(session_id=session.id, available=False)

    try:
        rows = json.loads(decrypt_data(session.credentials_encrypted))
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(
            status_code=422, detail="Stored credentials could not be read"
        )

    return SessionCredentialsResponse(
        session_id=session.id,
        available=bool(rows),
        credentials=[CapturedCredential(**r) for r in rows if isinstance(r, dict)],
    )


@router.post("/ingest")
async def ingest_session(
    session_data: dict,
    node_id: int = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    node_result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = node_result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Honeypot node not found")

    result = await analysis_pipeline.process_session(db, session_data, node_id)

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
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    content = _render(format, [session], await load_iocs(db, [session]))
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
