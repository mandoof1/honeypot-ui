from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models import AlertThreshold, AuditLog, HoneypotNode, HoneypotMode
from app.schemas import (
    AlertThresholdCreate, AlertThresholdUpdate, AlertThresholdResponse,
    SystemConfig,
)

router = APIRouter()


@router.get("/thresholds", response_model=list[AlertThresholdResponse])
async def list_thresholds(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(AlertThreshold).order_by(AlertThreshold.name))
    thresholds = result.scalars().all()
    return [
        AlertThresholdResponse(
            id=t.id, name=t.name, min_severity=t.min_severity,
            anomaly_score_threshold=t.anomaly_score_threshold,
            email_enabled=t.email_enabled, webhook_enabled=t.webhook_enabled,
            is_active=t.is_active, created_at=t.created_at, updated_at=t.updated_at,
        )
        for t in thresholds
    ]


@router.post("/thresholds", response_model=AlertThresholdResponse, status_code=201)
async def create_threshold(
    threshold_data: AlertThresholdCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    threshold = AlertThreshold(**threshold_data.model_dump())
    db.add(threshold)

    audit = AuditLog(
        user_id=current_user["id"],
        action="threshold_created",
        resource_type="alert_threshold",
        resource_id=threshold.id,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(threshold)

    return AlertThresholdResponse(
        id=threshold.id, name=threshold.name, min_severity=threshold.min_severity,
        anomaly_score_threshold=threshold.anomaly_score_threshold,
        email_enabled=threshold.email_enabled, webhook_enabled=threshold.webhook_enabled,
        is_active=threshold.is_active, created_at=threshold.created_at, updated_at=threshold.updated_at,
    )


@router.patch("/thresholds/{threshold_id}", response_model=AlertThresholdResponse)
async def update_threshold(
    threshold_id: int,
    update_data: AlertThresholdUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    result = await db.execute(select(AlertThreshold).where(AlertThreshold.id == threshold_id))
    threshold = result.scalar_one_or_none()
    if not threshold:
        raise HTTPException(status_code=404, detail="Threshold not found")

    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(threshold, key, value)

    audit = AuditLog(
        user_id=current_user["id"],
        action="threshold_updated",
        resource_type="alert_threshold",
        resource_id=threshold.id,
        details=update_dict,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(threshold)

    return AlertThresholdResponse(
        id=threshold.id, name=threshold.name, min_severity=threshold.min_severity,
        anomaly_score_threshold=threshold.anomaly_score_threshold,
        email_enabled=threshold.email_enabled, webhook_enabled=threshold.webhook_enabled,
        is_active=threshold.is_active, created_at=threshold.created_at, updated_at=threshold.updated_at,
    )


@router.delete("/thresholds/{threshold_id}", status_code=204)
async def delete_threshold(
    threshold_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    result = await db.execute(select(AlertThreshold).where(AlertThreshold.id == threshold_id))
    threshold = result.scalar_one_or_none()
    if not threshold:
        raise HTTPException(status_code=404, detail="Threshold not found")

    audit = AuditLog(
        user_id=current_user["id"],
        action="threshold_deleted",
        resource_type="alert_threshold",
        resource_id=threshold.id,
    )
    db.add(audit)
    await db.delete(threshold)
    await db.commit()


@router.get("/system")
async def get_system_config(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    nodes_result = await db.execute(select(HoneypotNode).where(HoneypotNode.is_active == True))
    nodes = nodes_result.scalars().all()

    modes = set(n.mode.value for n in nodes)
    global_mode = "mixed" if len(modes) > 1 else (modes.pop() if modes else "active")

    return {
        "honeypot_mode": global_mode,
        "active_nodes": len(nodes),
        "protocols": list(set(n.protocol for n in nodes)),
    }


@router.patch("/system")
async def update_system_config(
    config: SystemConfig,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    if config.honeypot_mode:
        mode = HoneypotMode(config.honeypot_mode)
        result = await db.execute(select(HoneypotNode))
        nodes = result.scalars().all()
        for node in nodes:
            node.mode = mode

        audit = AuditLog(
            user_id=current_user["id"],
            action="system_config_updated",
            resource_type="system",
            details={"honeypot_mode": mode.value},
        )
        db.add(audit)
        await db.commit()

    return {"status": "updated", "message": "System configuration updated"}
