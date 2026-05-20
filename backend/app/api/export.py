from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_user
from app.models import HoneypotSession
from app.services.report_generator import report_generator
from fastapi.responses import Response

router = APIRouter()


@router.post("/")
async def export_sessions(
    format: str = Query("json", regex="^(json|cef|stix)$"),
    session_ids: Optional[list[int]] = Query(None),
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(HoneypotSession)

    if session_ids:
        query = query.where(HoneypotSession.id.in_(session_ids))
    if date_from:
        query = query.where(HoneypotSession.started_at >= date_from)
    if date_to:
        query = query.where(HoneypotSession.started_at <= date_to)

    result = await db.execute(query)
    sessions = result.scalars().all()

    if not sessions:
        return Response(content="[]", media_type="application/json")

    if format == "cef":
        lines = []
        for session in sessions:
            session_data = _session_to_dict(session)
            analysis = _session_to_analysis(session)
            lines.append(report_generator.generate_cef_report(session_data, analysis))
        content = "\n".join(lines)
        media_type = "text/plain"
    elif format == "stix":
        from stix2 import Bundle
        all_objects = []
        for session in sessions:
            session_data = _session_to_dict(session)
            analysis = _session_to_analysis(session)
            bundle_str = report_generator.generate_stix_report(session_data, analysis)
            import json
            try:
                bundle_data = json.loads(bundle_str)
                all_objects.extend(bundle_data.get("objects", []))
            except json.JSONDecodeError:
                pass
        content = json.dumps({"type": "bundle", "id": "bundle--1", "objects": all_objects}, indent=2)
        media_type = "application/json"
    else:
        reports = []
        for session in sessions:
            session_data = _session_to_dict(session)
            analysis = _session_to_analysis(session)
            reports.append(json.loads(report_generator.generate_json_report(session_data, analysis)))
        import json
        content = json.dumps(reports, indent=2, default=str)
        media_type = "application/json"

    filename = f"honeysentinel_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{format}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

    return Response(content=content, media_type=media_type, headers=headers)


def _session_to_dict(session: HoneypotSession) -> dict:
    return {
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


def _session_to_analysis(session: HoneypotSession) -> dict:
    return {
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
