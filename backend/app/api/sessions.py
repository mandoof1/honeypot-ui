from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
import json

from app.core.database import get_db
from app.core.security import get_current_user
from app.models import HoneypotSession, HoneypotNode, AuditLog, SessionStatus, AttackCategory, AttackerProfile
from app.schemas import HoneypotSessionResponse, SessionListResponse, SessionFilter
from app.services.analysis import analysis_pipeline
from app.services.report_generator import report_generator

router = APIRouter()

HONEYPOT_SERVICE_TOKEN = "honeypot-ingest-token-change-in-production"


def verify_honeypot_token(request: Request):
    token = request.headers.get("X-Honeypot-Token", "")
    if token != HONEYPOT_SERVICE_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid honeypot token")
    return True


@router.post("/ingest-internal")
async def ingest_session_from_honeypot(
    request: Request,
    session_data: dict,
    node_id: int = Query(1),
    db: AsyncSession = Depends(get_db),
):
    verify_honeypot_token(request)

    node_result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = node_result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Honeypot node not found")

    result = await analysis_pipeline.process_session(db, session_data, node_id)

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

    return result


@router.get("/", response_model=SessionListResponse)
async def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    attack_category: Optional[str] = None,
    attacker_profile: Optional[str] = None,
    country: Optional[str] = None,
    ip_address: Optional[str] = None,
    is_anomalous: Optional[bool] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(HoneypotSession).options()
    count_query = select(func.count(HoneypotSession.id))

    if status:
        query = query.where(HoneypotSession.status == SessionStatus(status))
        count_query = count_query.where(HoneypotSession.status == SessionStatus(status))
    if attack_category:
        query = query.where(HoneypotSession.attack_category == AttackCategory(attack_category))
        count_query = count_query.where(HoneypotSession.attack_category == AttackCategory(attack_category))
    if attacker_profile:
        query = query.where(HoneypotSession.attacker_profile == AttackerProfile(attacker_profile))
        count_query = count_query.where(HoneypotSession.attacker_profile == AttackerProfile(attacker_profile))
    if country:
        query = query.where(HoneypotSession.geo_country == country.upper())
        count_query = count_query.where(HoneypotSession.geo_country == country.upper())
    if ip_address:
        query = query.where(HoneypotSession.attacker_ip.ilike(f"%{ip_address}%"))
        count_query = count_query.where(HoneypotSession.attacker_ip.ilike(f"%{ip_address}%"))
    if is_anomalous is not None:
        query = query.where(HoneypotSession.is_anomalous == is_anomalous)
        count_query = count_query.where(HoneypotSession.is_anomalous == is_anomalous)
    if search:
        search_filter = (
            HoneypotSession.attacker_ip.ilike(f"%{search}%") |
            HoneypotSession.session_uuid.ilike(f"%{search}%") |
            (HoneypotSession.command_summary.ilike(f"%{search}%") if hasattr(HoneypotSession, 'command_summary') else False)
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(HoneypotSession.started_at)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    sessions = result.scalars().all()

    return SessionListResponse(
        sessions=[HoneypotSessionResponse.from_orm(s) for s in sessions],
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
    return HoneypotSessionResponse.from_orm(session)


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
    return HoneypotSessionResponse.from_orm(session)


@router.post("/ingest")
async def ingest_session(
    session_data: dict,
    node_id: int = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
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
    format: str = Query("json", regex="^(json|cef|stix)$"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    session_data = {
        "session_uuid": session.session_uuid,
        "protocol": "ssh",
        "attacker_ip": session.attacker_ip,
        "attacker_port": session.attacker_port,
        "geo": {
            "country": session.geo_country,
            "country_name": session.geo_country_name,
            "city": session.geo_city,
            "lat": session.geo_lat,
            "lon": session.geo_lon,
        },
        "started_at": session.started_at.isoformat(),
        "ended_at": session.ended_at.isoformat() if session.ended_at else None,
        "duration_seconds": session.duration_seconds,
        "status": session.status.value,
        "commands": [],
        "uploads": session.uploaded_files or [],
    }

    analysis = {
        "category": session.attack_category.value if session.attack_category else "unknown",
        "confidence": session.attack_confidence,
        "profile": session.attacker_profile.value if session.attacker_profile else "unknown",
        "profile_confidence": 0.8,
        "anomaly_score": session.anomaly_score,
        "is_anomalous": session.is_anomalous,
        "detected_tools": session.detected_tools or [],
        "detected_intents": session.detected_intents or [],
        "complexity_score": 0.5,
        "command_count": 0,
        "mitre": {
            "tactics": session.mitre_tactics or [],
            "techniques": session.mitre_techniques or [],
        },
        "iocs": [],
    }

    content = report_generator.generate_structured_report(session_data, analysis, format)
    media_type = {
        "json": "application/json",
        "cef": "text/plain",
        "stix": "application/json",
    }.get(format, "application/json")

    from fastapi.responses import Response
    return Response(content=content, media_type=media_type)
