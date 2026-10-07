"""Bulk export of captured sessions in SIEM-friendly formats."""

from __future__ import annotations

import csv
import io
import json
from uuid import uuid4
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_role
from app.models import AuditLog, HoneypotSession
from app.services.report_generator import report_generator
from app.services.session_filters import session_filters

router = APIRouter()

#: A single export request should never be able to pull the entire dataset
#: into memory.
MAX_EXPORT_SESSIONS = 5000

MEDIA_TYPES = {
    "csv": "text/csv",
    "json": "application/json",
    "cef": "text/plain",
    "stix": "application/json",
}

FILE_EXTENSIONS = {"csv": "csv", "json": "json", "cef": "cef", "stix": "json"}


def _session_to_dict(session: HoneypotSession) -> dict:
    return {
        "session_uuid": session.session_uuid,
        "protocol": session.protocol or "unknown",
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
        "uploads": session.uploaded_files or [],
    }


def _session_to_analysis(session: HoneypotSession, iocs: list | None = None) -> dict:
    return {
        "iocs": iocs or [],
        "rule_reason": getattr(session, "rule_reason", None),
        "model_source": session.model_source,
        "enrichment": getattr(session, "enrichment", None),
        "category": (
            session.attack_category.value if session.attack_category else "unknown"
        ),
        "confidence": session.attack_confidence,
        "profile": (
            session.attacker_profile.value
            if session.attacker_profile
            else "unknown"
        ),
        "anomaly_score": session.anomaly_score,
        "is_anomalous": session.is_anomalous,
        "detected_tools": session.detected_tools or [],
        "detected_intents": session.detected_intents or [],
        "command_count": session.command_count or 0,
        "mitre": {
            "tactics": session.mitre_tactics or [],
            "techniques": session.mitre_techniques or [],
        },
    }


@router.post("/")
async def export_sessions(
    format: str = Query("json", pattern="^(json|csv|cef|stix)$"),
    session_ids: Optional[list[int]] = Query(None),
    filters=Depends(session_filters),
    db: AsyncSession = Depends(get_db),
    # Exports contain full attacker telemetry, so they are not a read-only
    # viewer capability.
    current_user: dict = Depends(require_role("analyst")),
):
    query = select(HoneypotSession)

    if session_ids:
        if len(session_ids) > MAX_EXPORT_SESSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"At most {MAX_EXPORT_SESSIONS} sessions per export",
            )
        query = query.where(HoneypotSession.id.in_(session_ids))
    if filters is not None:
        query = query.where(filters)

    query = query.order_by(HoneypotSession.started_at.desc(), HoneypotSession.id.desc()).limit(
        MAX_EXPORT_SESSIONS + 1
    )
    sessions = (await db.execute(query)).scalars().all()

    truncated = len(sessions) > MAX_EXPORT_SESSIONS
    sessions = sessions[:MAX_EXPORT_SESSIONS]
    content = _render(format, sessions, await load_iocs(db, sessions))

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="sessions_exported",
            resource_type="session",
            details={"format": format, "count": len(sessions), "truncated": truncated},
        )
    )
    await db.commit()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"honeysentinel_export_{stamp}.{FILE_EXTENSIONS[format]}"

    return Response(
        content=content,
        media_type=MEDIA_TYPES[format],
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Export-Count": str(len(sessions)),
            "X-Export-Truncated": str(truncated).lower(),
        },
    )


async def load_iocs(db: AsyncSession, sessions: list[HoneypotSession]) -> dict[int, list[dict]]:
    """Indicator rows for these sessions, keyed by session id.

    The JSON and STIX exports always wrote an empty indicator list, because
    nothing loaded the rows; the relationship cannot be lazy-loaded on an
    async session.
    """
    from app.models import IndicatorOfCompromise

    ids = [s.id for s in sessions]
    if not ids:
        return {}
    rows = (
        await db.execute(
            select(IndicatorOfCompromise).where(IndicatorOfCompromise.session_id.in_(ids))
        )
    ).scalars().all()
    grouped: dict[int, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row.session_id, []).append(
            {
                "type": row.ioc_type,
                "value": row.value,
                "confidence": row.confidence,
                "tags": row.tags or [],
                "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            }
        )
    return grouped


def _render(
    format: str,
    sessions: list[HoneypotSession],
    iocs_by_session: dict[int, list[dict]] | None = None,
) -> str:
    """Serialise sessions in the requested format.

    `import json` used to sit *inside* the branches of this function, which
    made `json` a function-local name everywhere — so the default JSON branch
    raised UnboundLocalError before reaching its own import, and every plain
    export returned a 500.
    """
    if format == "csv":
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["Session ID", "Source IP", "Protocol", "Country", "Started at",
                         "Status", "Category", "Anomalous", "Research scanner", "Commands",
                         "Command summary"])
        for session in sessions:
            values = [session.session_uuid, session.attacker_ip, session.protocol,
                      session.geo_country, session.started_at.isoformat(), session.status.value,
                      session.attack_category.value if session.attack_category else "unknown",
                      session.is_anomalous, session.scanner_operator, session.command_count,
                      session.command_summary]
            # Spreadsheet programs interpret attacker-controlled leading symbols as formulas.
            writer.writerow([_csv_cell(value) for value in values])
        return output.getvalue()

    iocs_by_session = iocs_by_session or {}
    pairs = [
        (_session_to_dict(session), _session_to_analysis(session, iocs_by_session.get(session.id)))
        for session in sessions
    ]

    if format == "cef":
        return "\n".join(
            report_generator.generate_cef_report(data, analysis)
            for data, analysis in pairs
        )

    if format == "stix":
        objects = []
        for data, analysis in pairs:
            try:
                bundle = json.loads(
                    report_generator.generate_stix_report(data, analysis)
                )
            except (json.JSONDecodeError, ValueError):
                continue
            objects.extend(bundle.get("objects", []))
        return json.dumps(
            {"type": "bundle", "id": f"bundle--{uuid4()}", "objects": objects}, indent=2
        )

    reports = [
        json.loads(report_generator.generate_json_report(data, analysis))
        for data, analysis in pairs
    ]
    return json.dumps(reports, indent=2, default=str)


def _csv_cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text
