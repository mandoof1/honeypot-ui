import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.core.security import get_current_user, require_role, verify_honeypot_token
from app.models import HoneypotSession, HoneypotNode, AuditLog
from app.core.encryption import decrypt_data
from app.schemas import (
    HoneypotSessionResponse,
    SessionListResponse,
    SessionTranscriptResponse,
    SessionCredentialsResponse,
    TranscriptEntry,
    CapturedCredential,
    RelatedActivityResponse,
)
from app.api.export import FILE_EXTENSIONS, MEDIA_TYPES, _render
from app.services.session_filters import session_filters
from app.services.ingest import ingest_once
from app.services.related_activity import related_activity
from app.services import enrichment

router = APIRouter()


@router.get("/ingest-capabilities", dependencies=[Depends(verify_honeypot_token)])
async def ingest_capabilities():
    """Engines must verify this before enabling automatic retries."""
    return {"version": 1, "idempotent_capture": True}


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

    result = await ingest_once(db, session_data, node_id)
    if result["duplicate"]:
        return result

    audit = AuditLog(
        user_id=None,
        action="session_ingested_honeypot",
        resource_type="session",
        resource_id=result["session_id"],
        details={
            "category": result["ai_classification"]["category"],
            "source": "honeypot_engine",
        },
    )
    db.add(audit)
    await db.commit()

    # Stage 2 runs detached, after the response. It reads the stored
    # transcript and asks Chimera what the attacker was attempting; a slow or
    # absent model degrades the depth of analysis, never the capture.
    enrichment.schedule(result["session_id"])

    return result


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


@router.get("/{session_id}/related", response_model=RelatedActivityResponse)
async def get_related_activity(
    session_id: int,
    window_days: int = Query(7, ge=1, le=30),
    limit: int = Query(20, ge=1, le=50),
    exclude_scanners: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Newest sessions sharing an exact source IP, URL, domain or file hash.

    The time window extends before and after the selected session. Relations
    explain observed overlap, not proof of a common attacker or campaign.
    """
    anchor = (await db.execute(select(HoneypotSession).where(
        HoneypotSession.id == session_id,
    ))).scalar_one_or_none()
    if anchor is None:
        raise HTTPException(404, "Session not found")
    return await related_activity(db, anchor, window_days, limit, exclude_scanners)


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
        truncated=(any((session.capture_dropped or {}).get(k, 0) for k in (
            "commands", "command_characters", "output_characters",
        )) if session.capture_dropped is not None else len(entries) >= 500),
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

    result = await ingest_once(db, session_data, node_id)
    if result["duplicate"]:
        return result

    audit = AuditLog(
        user_id=current_user["id"],
        action="session_ingested",
        resource_type="session",
        resource_id=result["session_id"],
        details={"category": result["ai_classification"]["category"]},
    )
    db.add(audit)
    await db.commit()

    # Stage 2 runs detached, after the response. It reads the stored
    # transcript and asks Chimera what the attacker was attempting; a slow or
    # absent model degrades the depth of analysis, never the capture.
    enrichment.schedule(result["session_id"])

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

    content = _render(format, [session])
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
