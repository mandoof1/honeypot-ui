"""Bulk export of captured sessions in SIEM-friendly formats."""

from __future__ import annotations

import asyncio
import csv
import io
import json
from uuid import uuid4
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_role
from app.models import AuditLog, HoneypotSession
from app.services.report_generator import report_generator
from app.services.session_filters import session_filters
from app.services.pdf_report import generate_pdf_report, MAX_PDF_SESSIONS
from app.services.investigation_jobs import report_jobs, JobsFull
from app.services.investigation_narrative import NarrativeUnavailable, redact
from app.core.encryption import decrypt_data

router = APIRouter()

#: A single export request should never be able to pull the entire dataset
#: into memory.
MAX_EXPORT_SESSIONS = 5000
REPORT_SLOTS = asyncio.Semaphore(2)

MEDIA_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "csv": "text/csv",
    "json": "application/json",
    "cef": "text/plain",
    "stix": "application/json",
}

FILE_EXTENSIONS = {"docx": "docx", "pdf": "pdf", "csv": "csv", "json": "json", "cef": "cef", "stix": "json"}


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
        "command_summary": session.command_summary,
        "scanner_operator": session.scanner_operator,
        "enrichment_status": session.enrichment_status,
        "mitre": {
            "tactics": session.mitre_tactics or [],
            "techniques": session.mitre_techniques or [],
        },
    }


@router.post("/")
async def export_sessions(
    format: str = Query("json", pattern="^(json|csv|cef|stix|pdf|docx)$"),
    session_ids: Optional[list[int]] = Query(None),
    filters=Depends(session_filters),
    include_sensitive: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    # Exports contain full attacker telemetry, so they are not a read-only
    # viewer capability.
    current_user: dict = Depends(require_role("analyst")),
):
    limit = MAX_PDF_SESSIONS if format in {"pdf", "docx"} else MAX_EXPORT_SESSIONS
    query = select(HoneypotSession)

    if session_ids:
        if len(session_ids) > limit:
            raise HTTPException(
                status_code=400,
                detail=f"At most {limit} sessions per {format} export",
            )
        query = query.where(HoneypotSession.id.in_(session_ids))
    if filters is not None:
        query = query.where(filters)

    query = query.order_by(HoneypotSession.started_at.desc(), HoneypotSession.id.desc()).limit(
        limit + 1
    )
    sessions = (await db.execute(query)).scalars().all()

    truncated = len(sessions) > limit
    sessions = sessions[:limit]
    iocs = await load_iocs(db, sessions)
    if format in {"pdf", "docx"}:
        _sensitive_permission(current_user, include_sensitive)
        if not sessions:raise HTTPException(status_code=404,detail='No sessions match this investigation report.')
        records = _report_snapshot(sessions, iocs, include_sensitive)
        # Release the database connection while CPU-model inference is pending.
        await db.commit()
        try:
            job = report_jobs.submit(current_user["id"], records, include_sensitive)
            await asyncio.shield(job["task"])
            content = await report_jobs.render(job, format)
        except JobsFull as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except NarrativeUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    else:
        content = _render(format, sessions, iocs)

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="sessions_exported",
            resource_type="session",
            details={"format": format, "count": len(sessions), "truncated": truncated, "include_sensitive": include_sensitive if format in {"pdf", "docx"} else False},
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



def _sensitive_permission(user, include_sensitive):
    if include_sensitive and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only administrators can include original credential evidence.")


def _report_snapshot(sessions, iocs, include_sensitive=False):
    records=[]
    for session in sessions:
        data=_session_to_dict(session)
        analysis=_session_to_analysis(session, iocs.get(session.id))
        analysis['evidence_source']='stored command summary'
        captured=session.command_summary or ''
        if session.raw_commands_encrypted:
            try:
                captured=decrypt_data(session.raw_commands_encrypted)
                analysis['evidence_source']='decrypted captured commands/requests'
            except (ValueError,TypeError):
                analysis['evidence_error']='Captured commands could not be decrypted; the available stored summary is shown instead.'
        if len(captured)>100000:captured=captured[:100000]+'\n[captured activity shortened at 100000 characters]'
        analysis['evidence_commands']=captured if include_sensitive else redact(captured)
        if session.credentials_encrypted:
            try:
                from collections import Counter
                credentials=json.loads(decrypt_data(session.credentials_encrypted))
                if not isinstance(credentials,list):raise ValueError('Expected credential list')
                analysis['credentials_total']=len(credentials)
                analysis['credential_usernames']=dict(Counter(str(c.get('username',''))[:100] for c in credentials if isinstance(c,dict)))
                analysis['decoy_accepts']=sum(c.get('success') is True or c.get('accepted') is True for c in credentials if isinstance(c,dict))
                if include_sensitive:analysis['credentials']=[{k:str(c.get(k,''))[:1000] for k in ['username','password','success','accepted'] if k in c} for c in credentials[:100] if isinstance(c,dict)]
            except (ValueError,TypeError):analysis['credential_error']='Captured credential data could not be read.'
        records.append((data,analysis))
    return records


@router.post('/reports', status_code=202)
async def prepare_investigation_report(
    session_ids: Optional[list[int]] = Query(None),
    filters=Depends(session_filters),
    include_sensitive: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role('analyst')),
):
    _sensitive_permission(current_user,include_sensitive)
    if session_ids and len(session_ids)>MAX_PDF_SESSIONS:raise HTTPException(status_code=400,detail='At most 100 sessions per investigation report')
    query=select(HoneypotSession)
    if session_ids:query=query.where(HoneypotSession.id.in_(session_ids))
    if filters is not None:query=query.where(filters)
    query=query.order_by(HoneypotSession.started_at.desc(),HoneypotSession.id.desc()).limit(MAX_PDF_SESSIONS+1)
    sessions=(await db.execute(query)).scalars().all()
    truncated=len(sessions)>MAX_PDF_SESSIONS;sessions=sessions[:MAX_PDF_SESSIONS]
    if not sessions:raise HTTPException(status_code=404,detail='No sessions match this report. Change the filters or select a session.')
    iocs=await load_iocs(db,sessions)
    records=_report_snapshot(sessions,iocs,include_sensitive)
    try:job=report_jobs.submit(current_user['id'],records,include_sensitive)
    except JobsFull as exc:raise HTTPException(status_code=429,detail=str(exc)) from exc
    job['truncated']=truncated
    db.add(AuditLog(user_id=current_user['id'],action='ai_report_requested',resource_type='session',details={'report_id':job['id'],'count':len(sessions),'truncated':truncated,'include_sensitive':include_sensitive}))
    await db.commit()
    return report_jobs.status(job)


@router.get('/reports/{report_id}')
async def investigation_status(report_id: str, current_user: dict = Depends(require_role('analyst'))):
    try:job=report_jobs.owned(report_id,current_user['id'])
    except KeyError:raise HTTPException(status_code=404,detail='Report not found or expired. Generate it again.')
    _sensitive_permission(current_user,job['sensitive'])
    return report_jobs.status(job)


@router.get('/reports/{report_id}/download')
async def download_investigation_report(
    report_id: str,
    format: str = Query('pdf',pattern='^(pdf|docx)$'),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role('analyst')),
):
    try:job=report_jobs.owned(report_id,current_user['id'])
    except KeyError:raise HTTPException(status_code=404,detail='Report not found or expired. Generate it again.')
    _sensitive_permission(current_user,job['sensitive'])
    if job['status']!='complete':raise HTTPException(status_code=409,detail=job['error'] or 'The model is still writing this investigation.')
    content=await report_jobs.render(job,format)
    db.add(AuditLog(user_id=current_user['id'],action='ai_report_downloaded',resource_type='session',details={'report_id':job['id'],'format':format,'count':len(job['records']),'include_sensitive':job['sensitive'],'model':job['narrative']['model']}))
    await db.commit()
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    return Response(content=content,media_type=MEDIA_TYPES[format],headers={'Content-Disposition':f'attachment; filename="honeysentinel_investigation_{stamp}.{format}"','X-Export-Count':str(len(job['records'])),'X-Export-Truncated':str(bool(job.get('truncated'))).lower()})


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
) -> str | bytes:
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

    if format in {"pdf", "docx"}:
        return generate_pdf_report(pairs, output_format=format)

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
