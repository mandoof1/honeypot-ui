from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.security import get_current_user
from app.models import Alert, HoneypotSession, AuditLog, AlertStatus, AttackSeverity
from app.schemas import AlertResponse, AlertListResponse, AlertUpdate

router = APIRouter()


@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(Alert)
    count_query = select(func.count(Alert.id))

    if severity:
        query = query.where(Alert.severity == AttackSeverity(severity))
        count_query = count_query.where(Alert.severity == AttackSeverity(severity))
    if status:
        query = query.where(Alert.status == AlertStatus(status))
        count_query = count_query.where(Alert.status == AlertStatus(status))

    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(Alert.created_at)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return AlertListResponse(
        alerts=[
            AlertResponse(
                id=a.id,
                session_id=a.session_id,
                severity=a.severity,
                title=a.title,
                description=a.description,
                status=a.status,
                assigned_to_id=a.assigned_to_id,
                auto_generated=a.auto_generated,
                mitre_tactics=a.mitre_tactics or [],
                mitre_techniques=a.mitre_techniques or [],
                created_at=a.created_at,
                updated_at=a.updated_at,
            )
            for a in alerts
        ],
        total=total,
        page=page,
        page_size=page_size,
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

    return AlertResponse(
        id=alert.id,
        session_id=alert.session_id,
        severity=alert.severity,
        title=alert.title,
        description=alert.description,
        status=alert.status,
        assigned_to_id=alert.assigned_to_id,
        auto_generated=alert.auto_generated,
        mitre_tactics=alert.mitre_tactics or [],
        mitre_techniques=alert.mitre_techniques or [],
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    update_data: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if update_data.status is not None:
        alert.status = AlertStatus(update_data.status)
        if update_data.status == AlertStatus.ACKNOWLEDGED:
            alert.acknowledged_at = datetime.now(timezone.utc)
        elif update_data.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            alert.resolved_at = datetime.now(timezone.utc)

    if update_data.assigned_to_id is not None:
        alert.assigned_to_id = update_data.assigned_to_id

    audit = AuditLog(
        user_id=current_user["id"],
        action="alert_updated",
        resource_type="alert",
        resource_id=alert.id,
        details={"status": alert.status.value},
    )
    db.add(audit)
    await db.commit()
    await db.refresh(alert)

    return AlertResponse(
        id=alert.id,
        session_id=alert.session_id,
        severity=alert.severity,
        title=alert.title,
        description=alert.description,
        status=alert.status,
        assigned_to_id=alert.assigned_to_id,
        auto_generated=alert.auto_generated,
        mitre_tactics=alert.mitre_tactics or [],
        mitre_techniques=alert.mitre_techniques or [],
        created_at=alert.created_at,
        updated_at=alert.updated_at,
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

    return {
        "new": new_count,
        "acknowledged": ack_count,
        "resolved": resolved_count,
        "by_severity": severity_dist,
    }
