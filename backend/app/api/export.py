"""Bulk export of captured sessions in SIEM-friendly formats."""

from __future__ import annotations

import asyncio
import csv
import io
import json
from collections import Counter
from uuid import uuid4
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clientip import client_ip
from app.core.database import get_db
from app.core.security import require_role
from app.models import AuditLog, HoneypotSession, IndicatorOfCompromise
from app.services.report_generator import report_generator
from app.services.session_filters import session_filters, without_blobs
from app.services.pdf_report import generate_pdf_report, MAX_PDF_SESSIONS
from app.services.investigation_jobs import report_jobs, JobsFull
from app.services.investigation_narrative import NarrativeUnavailable, redact
from app.core.encryption import decrypt_data, session_context

router = APIRouter()

#: A single export request should never be able to pull the entire dataset
#: into memory.
MAX_EXPORT_SESSIONS = 5000
#: Sessions read from the database, serialised and sent at a time. The
#: export used to load every selected row whole, encrypted transcript and
#: payload included, and build the entire file before sending a byte.
EXPORT_BATCH = 200

MEDIA_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "csv": "text/csv",
    "json": "application/json",
    "cef": "text/plain",
    "stix": "application/json",
}

FILE_EXTENSIONS = {
    "docx": "docx",
    "pdf": "pdf",
    "csv": "csv",
    "json": "json",
    "cef": "cef",
    "stix": "json",
}

#: What the tabular and SIEM formats read from a session. Selected by name,
#: as plain rows: no encrypted column is fetched, and nothing is held in the
#: ORM session between batches.
_EXPORT_COLUMNS = (
    HoneypotSession.id,
    HoneypotSession.session_uuid,
    HoneypotSession.protocol,
    HoneypotSession.attacker_ip,
    HoneypotSession.attacker_port,
    HoneypotSession.geo_country,
    HoneypotSession.geo_country_name,
    HoneypotSession.geo_city,
    HoneypotSession.geo_lat,
    HoneypotSession.geo_lon,
    HoneypotSession.started_at,
    HoneypotSession.ended_at,
    HoneypotSession.duration_seconds,
    HoneypotSession.status,
    HoneypotSession.uploaded_files,
    HoneypotSession.rule_reason,
    HoneypotSession.model_source,
    HoneypotSession.enrichment,
    HoneypotSession.enrichment_status,
    HoneypotSession.attack_category,
    HoneypotSession.attack_confidence,
    HoneypotSession.attacker_profile,
    HoneypotSession.anomaly_score,
    HoneypotSession.is_anomalous,
    HoneypotSession.detected_tools,
    HoneypotSession.detected_intents,
    HoneypotSession.command_count,
    HoneypotSession.command_summary,
    HoneypotSession.scanner_operator,
    HoneypotSession.mitre_tactics,
    HoneypotSession.mitre_techniques,
    HoneypotSession.fingerprints,
    HoneypotSession.signals,
)

_CSV_HEADER = [
    "Session ID", "Source IP", "Protocol", "Country", "Started at",
    "Status", "Category", "Anomalous", "Research scanner", "Commands",
    "Command summary",
]


def _session_to_dict(session) -> dict:
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
        # The client's handshake fingerprints and the analysis's derived flags.
        "fingerprints": getattr(session, "fingerprints", None),
        "signals": getattr(session, "signals", None),
    }


def _session_to_analysis(session, iocs: list | None = None) -> dict:
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
            session.attacker_profile.value if session.attacker_profile else "unknown"
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


def _selection(session_ids: Optional[list[int]], filters):
    """The WHERE clause shared by every export of a selection."""
    conditions = []
    if session_ids:
        conditions.append(HoneypotSession.id.in_(session_ids))
    if filters is not None:
        conditions.append(filters)
    return conditions


_NEWEST_FIRST = (HoneypotSession.started_at.desc(), HoneypotSession.id.desc())


async def _report_sessions(db: AsyncSession, session_ids, filters):
    """Sessions for an investigation report, with only the blobs it reads."""
    query = without_blobs(
        select(HoneypotSession),
        keep=(HoneypotSession.raw_commands_encrypted, HoneypotSession.credentials_encrypted),
    )
    query = query.where(*_selection(session_ids, filters))
    query = query.order_by(*_NEWEST_FIRST).limit(MAX_PDF_SESSIONS + 1)
    sessions = (await db.execute(query)).scalars().all()
    return sessions[:MAX_PDF_SESSIONS], len(sessions) > MAX_PDF_SESSIONS


@router.post("/")
async def export_sessions(
    request: Request,
    format: str = Query("json", pattern="^(json|csv|cef|stix|pdf|docx)$"),
    session_ids: Optional[list[int]] = Query(None),
    filters=Depends(session_filters),
    include_sensitive: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    # Exports contain full attacker telemetry, so they are not a read-only
    # viewer capability.
    current_user: dict = Depends(require_role("analyst")),
):
    is_report = format in {"pdf", "docx"}
    limit = MAX_PDF_SESSIONS if is_report else MAX_EXPORT_SESSIONS
    if session_ids and len(session_ids) > limit:
        raise HTTPException(
            status_code=400,
            detail=f"At most {limit} sessions per {format} export",
        )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"honeysentinel_export_{stamp}.{FILE_EXTENSIONS[format]}"

    if is_report:
        _sensitive_permission(current_user, include_sensitive)
        sessions, truncated = await _report_sessions(db, session_ids, filters)
        if not sessions:
            raise HTTPException(
                status_code=404, detail="No sessions match this investigation report."
            )
        iocs = await load_iocs(db, sessions)
        records = _report_snapshot(sessions, iocs, include_sensitive)
        count = len(sessions)
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
        body = Response(content=content, media_type=MEDIA_TYPES[format])
    else:
        # Ids first: a few thousand integers settle what is exported, how
        # many, and whether the selection was cut, before any row is read.
        ids = (
            await db.execute(
                select(HoneypotSession.id)
                .where(*_selection(session_ids, filters))
                .order_by(*_NEWEST_FIRST)
                .limit(limit + 1)
            )
        ).scalars().all()
        truncated = len(ids) > limit
        ids = list(ids[:limit])
        count = len(ids)
        body = StreamingResponse(
            _stream_export(db, format, ids), media_type=MEDIA_TYPES[format]
        )

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="sessions_exported",
            resource_type="session",
            ip_address=client_ip(request),
            details={
                "format": format,
                "count": count,
                "truncated": truncated,
                "include_sensitive": include_sensitive if is_report else False,
            },
        )
    )
    await db.commit()

    body.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    body.headers["X-Export-Count"] = str(count)
    body.headers["X-Export-Truncated"] = str(truncated).lower()
    return body


def _sensitive_permission(user, include_sensitive):
    if include_sensitive and user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only administrators can include original credential evidence.",
        )


def _report_snapshot(sessions, iocs, include_sensitive=False):
    """The evidence a report is written from, fixed at the moment of asking.

    Without ``include_sensitive`` (administrators only) every piece of
    captured text is passed through ``redact``: the decrypted commands, and
    also the stored summary, which for a shell session is the commands
    themselves and used to go into the record as it was.
    """
    records = []
    for session in sessions:
        data = _session_to_dict(session)
        analysis = _session_to_analysis(session, iocs.get(session.id))
        if not include_sensitive:
            analysis["command_summary"] = redact(session.command_summary or "") or None
        analysis["evidence_source"] = "stored command summary"
        captured = session.command_summary or ""
        if session.raw_commands_encrypted:
            try:
                captured = decrypt_data(
                    session.raw_commands_encrypted,
                    session_context(session.id, "raw_commands_encrypted"),
                )
                analysis["evidence_source"] = "decrypted captured commands/requests"
            except (ValueError, TypeError):
                analysis["evidence_error"] = (
                    "Captured commands could not be decrypted; the available stored summary is shown instead."
                )
        if len(captured) > 100000:
            captured = (
                captured[:100000]
                + "\n[captured activity shortened at 100000 characters]"
            )
        analysis["evidence_commands"] = (
            captured if include_sensitive else redact(captured)
        )
        if session.credentials_encrypted:
            try:
                credentials = json.loads(
                    decrypt_data(
                        session.credentials_encrypted,
                        session_context(session.id, "credentials_encrypted"),
                    )
                )
                if not isinstance(credentials, list):
                    raise ValueError("Expected credential list")
                analysis["credentials_total"] = len(credentials)
                analysis["credential_usernames"] = dict(
                    Counter(
                        str(c.get("username", ""))[:100]
                        for c in credentials
                        if isinstance(c, dict)
                    )
                )
                analysis["decoy_accepts"] = sum(
                    c.get("success") is True or c.get("accepted") is True
                    for c in credentials
                    if isinstance(c, dict)
                )
                if include_sensitive:
                    analysis["credentials"] = [
                        {
                            k: str(c.get(k, ""))[:1000]
                            for k in ["username", "password", "success", "accepted"]
                            if k in c
                        }
                        for c in credentials[:100]
                        if isinstance(c, dict)
                    ]
            except (ValueError, TypeError):
                analysis["credential_error"] = (
                    "Captured credential data could not be read."
                )
        records.append((data, analysis))
    return records


_REPORT_GONE = "Report not found or expired. Generate it again."


def _owned_report(report_id: str, current_user: dict) -> dict:
    """The caller's own report job, or 404.

    The same 404 for an id that never existed, one that belongs to someone
    else, one that expired, and one that was lost when the API restarted
    (jobs are held in memory): in every case the thing to do is generate
    the report again, and none of them should say whose it was.
    """
    try:
        job = report_jobs.owned(report_id, current_user["id"])
    except KeyError:
        raise HTTPException(status_code=404, detail=_REPORT_GONE)
    # Checked again on every read, not only when the job was made: a user
    # who has since lost the admin role must not collect a report that
    # contains original credentials.
    _sensitive_permission(current_user, job["sensitive"])
    return job


@router.post("/reports", status_code=202)
async def prepare_investigation_report(
    request: Request,
    session_ids: Optional[list[int]] = Query(None),
    filters=Depends(session_filters),
    include_sensitive: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    _sensitive_permission(current_user, include_sensitive)
    if session_ids and len(session_ids) > MAX_PDF_SESSIONS:
        raise HTTPException(
            status_code=400, detail="At most 100 sessions per investigation report"
        )
    sessions, truncated = await _report_sessions(db, session_ids, filters)
    if not sessions:
        raise HTTPException(
            status_code=404,
            detail="No sessions match this report. Change the filters or select a session.",
        )
    iocs = await load_iocs(db, sessions)
    records = _report_snapshot(sessions, iocs, include_sensitive)
    try:
        job = report_jobs.submit(current_user["id"], records, include_sensitive)
    except JobsFull as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    job["truncated"] = truncated
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="ai_report_requested",
            resource_type="session",
            ip_address=client_ip(request),
            details={
                "report_id": job["id"],
                "count": len(sessions),
                "truncated": truncated,
                "include_sensitive": include_sensitive,
            },
        )
    )
    await db.commit()
    return report_jobs.status(job)


@router.get("/reports/{report_id}")
async def investigation_status(
    report_id: str, current_user: dict = Depends(require_role("analyst"))
):
    # Not audited: the page polls this every few seconds while the model
    # writes. The request and each download are what the audit log records.
    return report_jobs.status(_owned_report(report_id, current_user))


@router.get("/reports/{report_id}/download")
async def download_investigation_report(
    report_id: str,
    request: Request,
    format: str = Query("pdf", pattern="^(pdf|docx)$"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    job = _owned_report(report_id, current_user)
    if job["status"] != "complete":
        raise HTTPException(
            status_code=409,
            detail=job["error"] or "The model is still writing this investigation.",
        )
    content = await report_jobs.render(job, format)
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="ai_report_downloaded",
            resource_type="session",
            ip_address=client_ip(request),
            details={
                "report_id": job["id"],
                "format": format,
                "count": len(job["records"]),
                "include_sensitive": job["sensitive"],
                "model": job["narrative"]["model"],
            },
        )
    )
    await db.commit()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        content=content,
        media_type=MEDIA_TYPES[format],
        headers={
            "Content-Disposition": f'attachment; filename="honeysentinel_investigation_{stamp}.{format}"',
            "X-Export-Count": str(len(job["records"])),
            "X-Export-Truncated": str(bool(job.get("truncated"))).lower(),
        },
    )


async def load_iocs(db: AsyncSession, sessions: list) -> dict[int, list[dict]]:
    """Indicator rows for these sessions, keyed by session id.

    The JSON and STIX exports always wrote an empty indicator list, because
    nothing loaded the rows; the relationship cannot be lazy-loaded on an
    async session.
    """
    ids = [s.id for s in sessions]
    if not ids:
        return {}
    rows = (
        await db.execute(
            select(
                IndicatorOfCompromise.session_id,
                IndicatorOfCompromise.ioc_type,
                IndicatorOfCompromise.value,
                IndicatorOfCompromise.confidence,
                IndicatorOfCompromise.tags,
                IndicatorOfCompromise.first_seen,
            ).where(IndicatorOfCompromise.session_id.in_(ids))
        )
    ).all()
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


def _csv_rows(sessions) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    for session in sessions:
        values = [
            session.session_uuid, session.attacker_ip, session.protocol,
            session.geo_country, session.started_at.isoformat(), session.status.value,
            session.attack_category.value if session.attack_category else "unknown",
            session.is_anomalous, session.scanner_operator, session.command_count,
            session.command_summary,
        ]
        # Spreadsheet programs interpret attacker-controlled leading symbols as formulas.
        writer.writerow([_csv_cell(value) for value in values])
    return output.getvalue()


def _csv_header() -> str:
    output = io.StringIO(newline="")
    csv.writer(output).writerow(_CSV_HEADER)
    return output.getvalue()


def _stix_objects(data: dict, analysis: dict) -> list[dict]:
    try:
        bundle = json.loads(report_generator.generate_stix_report(data, analysis))
    except (json.JSONDecodeError, ValueError):
        return []
    return bundle.get("objects", [])


def _json_report(data: dict, analysis: dict) -> dict:
    return json.loads(report_generator.generate_json_report(data, analysis))


def _pairs(sessions, iocs_by_session: dict) -> list[tuple[dict, dict]]:
    return [
        (_session_to_dict(session), _session_to_analysis(session, iocs_by_session.get(session.id)))
        for session in sessions
    ]


async def _stream_export(db: AsyncSession, format: str, ids: list[int]) -> AsyncIterator[str]:
    """Serialise the selected sessions a batch at a time.

    Each format is produced as a whole, valid document (a JSON array, one
    STIX bundle, one CSV with a single header) while only EXPORT_BATCH
    sessions are in memory at once.
    """
    if format == "json":
        yield "[\n"
    elif format == "stix":
        yield '{\n  "type": "bundle",\n  "id": "bundle--%s",\n  "objects": [\n' % uuid4()
    elif format == "csv":
        yield _csv_header()

    first = True
    for start in range(0, len(ids), EXPORT_BATCH):
        chunk = ids[start:start + EXPORT_BATCH]
        rows = (
            await db.execute(
                select(*_EXPORT_COLUMNS).where(HoneypotSession.id.in_(chunk))
            )
        ).all()
        # Back into the order the selection was made in.
        by_id = {row.id: row for row in rows}
        sessions = [by_id[i] for i in chunk if i in by_id]

        if format == "csv":
            yield _csv_rows(sessions)
            continue

        for data, analysis in _pairs(sessions, await load_iocs(db, sessions)):
            if format == "cef":
                items = [report_generator.generate_cef_report(data, analysis)]
                separator = "\n"
            elif format == "stix":
                items = [json.dumps(obj, indent=2) for obj in _stix_objects(data, analysis)]
                separator = ",\n"
            else:
                items = [json.dumps(_json_report(data, analysis), indent=2, default=str)]
                separator = ",\n"
            for item in items:
                yield item if first else separator + item
                first = False

    if format == "json":
        yield "\n]\n"
    elif format == "stix":
        yield "\n  ]\n}\n"


def _render(
    format: str,
    sessions: list,
    iocs_by_session: dict[int, list[dict]] | None = None,
) -> str | bytes:
    """Serialise sessions in the requested format, in one piece.

    For a handful of sessions (the single-session export). The bulk export
    streams instead; see ``_stream_export``.

    `import json` used to sit *inside* the branches of this function, which
    made `json` a function-local name everywhere — so the default JSON branch
    raised UnboundLocalError before reaching its own import, and every plain
    export returned a 500.
    """
    if format == "csv":
        return _csv_header() + _csv_rows(sessions)

    pairs = _pairs(sessions, iocs_by_session or {})

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
            objects.extend(_stix_objects(data, analysis))
        return json.dumps(
            {"type": "bundle", "id": f"bundle--{uuid4()}", "objects": objects}, indent=2
        )

    reports = [_json_report(data, analysis) for data, analysis in pairs]
    return json.dumps(reports, indent=2, default=str)


def _csv_cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text
