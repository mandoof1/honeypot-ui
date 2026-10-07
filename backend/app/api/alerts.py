from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models import Alert, AlertStatus, AttackSeverity, AuditLog, User
from app.schemas import AlertResponse, AlertListResponse, AlertUpdate, AlertBulkUpdate

router = APIRouter()

#: Which transitions are meaningful. Anything else is rejected rather than
#: silently leaving stale timestamps behind (resolved → new used to keep its
#: resolved_at).
_TRANSITIONS = {
    AlertStatus.NEW: {AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.ACKNOWLEDGED: {AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE, AlertStatus.NEW},
    AlertStatus.RESOLVED: {AlertStatus.NEW, AlertStatus.ACKNOWLEDGED},
    AlertStatus.FALSE_POSITIVE: {AlertStatus.NEW, AlertStatus.ACKNOWLEDGED},
}


def _parse_enum(enum_cls, value: str, field: str):
    try:
        return enum_cls(value)
    except ValueError:
        allowed = ", ".join(member.value for member in enum_cls)
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field} {value!r}. Expected one of: {allowed}",
        )


def _to_response(alert: Alert, names: dict | None = None) -> AlertResponse:
    data = AlertResponse.model_validate(alert)
    if names and alert.assigned_to_id in names:
        data.assigned_to_name = names[alert.assigned_to_id]
    return data


async def _assignee_names(db: AsyncSession, alerts) -> dict:
    ids = {a.assigned_to_id for a in alerts if a.assigned_to_id}
    if not ids:
        return {}
    rows = (await db.execute(select(User.id, User.name, User.email).where(User.id.in_(ids)))).all()
    return {row.id: (row.name or row.email) for row in rows}


def _apply_status(alert: Alert, new_status: AlertStatus) -> None:
    now = datetime.now(timezone.utc)
    if new_status == alert.status:
        return
    if new_status not in _TRANSITIONS.get(alert.status, set()):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot move an alert from {alert.status.value} to {new_status.value}",
        )
    alert.status = new_status
    if new_status == AlertStatus.ACKNOWLEDGED:
        alert.acknowledged_at = alert.acknowledged_at or now
        alert.resolved_at = None
    elif new_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
        alert.resolved_at = now
    elif new_status == AlertStatus.NEW:
        alert.acknowledged_at = None
        alert.resolved_at = None


@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    kind: Optional[str] = Query(None, pattern="^(session|system)$"),
    attacker_ip: Optional[str] = Query(None, max_length=45),
    assigned_to_id: Optional[int] = None,
    since: Optional[datetime] = None,
    session_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    conditions = []
    if severity:
        conditions.append(Alert.severity == _parse_enum(AttackSeverity, severity, "severity"))
    if status:
        conditions.append(Alert.status == _parse_enum(AlertStatus, status, "status"))
    if kind:
        conditions.append(Alert.kind == kind)
    if attacker_ip:
        conditions.append(Alert.attacker_ip == attacker_ip.strip())
    if assigned_to_id is not None:
        conditions.append(Alert.assigned_to_id == assigned_to_id)
    if since is not None:
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        conditions.append(Alert.created_at >= since)
    if session_id is not None:
        conditions.append(Alert.session_id == session_id)

    query = select(Alert)
    count_query = select(func.count(Alert.id))
    for condition in conditions:
        query = query.where(condition)
        count_query = count_query.where(condition)

    total = (await db.execute(count_query)).scalar() or 0

    query = (
        query.order_by(desc(Alert.last_seen_at), desc(Alert.created_at), desc(Alert.id))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    alerts = (await db.execute(query)).scalars().all()
    names = await _assignee_names(db, alerts)

    return AlertListResponse(
        alerts=[_to_response(a, names) for a in alerts],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats")
async def alert_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    new_q = select(func.count(Alert.id)).where(Alert.status == AlertStatus.NEW)
    new_count = (await db.execute(new_q)).scalar() or 0

    ack_q = select(func.count(Alert.id)).where(Alert.status == AlertStatus.ACKNOWLEDGED)
    ack_count = (await db.execute(ack_q)).scalar() or 0

    resolved_q = select(func.count(Alert.id)).where(Alert.status.in_([AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]))
    resolved_count = (await db.execute(resolved_q)).scalar() or 0

    severity_q = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    severity_result = await db.execute(severity_q)
    severity_dist = {s.value: c for s, c in severity_result.all()}

    system_open_q = select(func.count(Alert.id)).where(
        Alert.kind == "system", Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED])
    )
    system_open = (await db.execute(system_open_q)).scalar() or 0

    return {
        "new": new_count,
        "acknowledged": ack_count,
        "resolved": resolved_count,
        "by_severity": severity_dist,
        "system_open": system_open,
    }


@router.post("/bulk", response_model=AlertListResponse)
async def bulk_update(
    payload: AlertBulkUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    """Move several alerts to one status in a single request."""
    alerts = (
        await db.execute(select(Alert).where(Alert.id.in_(payload.ids)))
    ).scalars().all()
    new_status = AlertStatus(payload.status)
    changed = []
    for alert in alerts:
        if new_status == alert.status or new_status not in _TRANSITIONS.get(alert.status, set()):
            continue
        _apply_status(alert, new_status)
        changed.append(alert)
    if changed:
        db.add(
            AuditLog(
                user_id=current_user["id"],
                action="alerts_bulk_updated",
                resource_type="alert",
                details={"ids": [a.id for a in changed], "status": new_status.value},
            )
        )
        await db.commit()
    names = await _assignee_names(db, alerts)
    return AlertListResponse(
        alerts=[_to_response(a, names) for a in alerts],
        total=len(changed),
        page=1,
        page_size=len(alerts) or 1,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return _to_response(alert, await _assignee_names(db, [alert]))


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    update_data: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    changes = {}

    if update_data.assigned_to_id is not None:
        assignee = await db.execute(
            select(User.id).where(User.id == update_data.assigned_to_id)
        )
        if assignee.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=400, detail="Assigned user does not exist"
            )
        alert.assigned_to_id = update_data.assigned_to_id
        changes["assigned_to_id"] = update_data.assigned_to_id
    elif update_data.unassign:
        alert.assigned_to_id = None
        changes["assigned_to_id"] = None

    if update_data.status is not None:
        _apply_status(alert, AlertStatus(update_data.status))
        changes["status"] = alert.status.value

    if update_data.notes is not None:
        alert.notes = update_data.notes.strip() or None
        changes["notes"] = "updated"

    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to update")

    audit = AuditLog(
        user_id=current_user["id"],
        action="alert_updated",
        resource_type="alert",
        resource_id=alert.id,
        details=changes,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(alert)

    return _to_response(alert, await _assignee_names(db, [alert]))
