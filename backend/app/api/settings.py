import logging

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
logger = logging.getLogger(__name__)


def _to_response(t: AlertThreshold) -> AlertThresholdResponse:
    return AlertThresholdResponse.model_validate(t)


@router.get("/thresholds", response_model=list[AlertThresholdResponse])
async def list_thresholds(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(AlertThreshold).order_by(AlertThreshold.name))
    thresholds = result.scalars().all()
    return [
        _to_response(t)
        for t in thresholds
    ]


@router.post("/thresholds", response_model=AlertThresholdResponse, status_code=201)
async def create_threshold(
    threshold_data: AlertThresholdCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    existing = await db.execute(
        select(AlertThreshold).where(AlertThreshold.name == threshold_data.name)
    )
    if existing.scalar_one_or_none():
        # The column is unique; without this check the insert raised an
        # IntegrityError that surfaced as a 500.
        raise HTTPException(
            status_code=409, detail="A threshold with that name already exists"
        )

    threshold = AlertThreshold(**threshold_data.model_dump())
    db.add(threshold)
    await db.flush()  # populate threshold.id for the audit row

    audit = AuditLog(
        user_id=current_user["id"],
        action="threshold_created",
        resource_type="alert_threshold",
        resource_id=threshold.id,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(threshold)

    return _to_response(threshold)


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

    return _to_response(threshold)


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
    nodes_result = await db.execute(select(HoneypotNode).where(HoneypotNode.is_active.is_(True)))
    nodes = nodes_result.scalars().all()

    modes = set(n.mode.value for n in nodes)
    global_mode = "mixed" if len(modes) > 1 else (modes.pop() if modes else "active")

    from app.ai.decider import decider
    from app.ai.llm import chimera
    from app.core.config import get_settings

    cfg = get_settings()
    return {
        "honeypot_mode": global_mode,
        "active_nodes": len(nodes),
        "protocols": list(set(n.protocol for n in nodes)),
        # Read-only view of the deployment's operational settings, so the
        # page can say what the platform will actually do.
        "enrichment": {"configured": chimera.enabled, "model": chimera.model_name if chimera.enabled else None},
        "triage": {
            "configured": decider.enabled,
            "model": decider.model_name if decider.enabled else None,
            "skip_threshold": cfg.DECIDER_SKIP_THRESHOLD,
            "escalate_threshold": cfg.DECIDER_ESCALATE_THRESHOLD,
            "triage_rule_skipped": cfg.DECIDER_TRIAGE_RULE_SKIPPED,
            "support_threshold": cfg.DECIDER_SUPPORT_THRESHOLD,
            "drop_unconfirmed": cfg.DECIDER_DROP_UNCONFIRMED,
        },
        "retention": {
            "sessions_days": cfg.SESSION_RETENTION_DAYS,
            "audit_days": cfg.AUDIT_RETENTION_DAYS,
        },
        "alerting": {
            "dedup_window_minutes": cfg.ALERT_DEDUP_WINDOW_MINUTES,
            "suppress_scanners": cfg.ALERT_SUPPRESS_SCANNERS,
            "email_configured": bool(cfg.ALERT_EMAIL_TO and cfg.SMTP_HOST),
            "webhook_configured": bool(cfg.WEBHOOK_URL),
        },
        "security": {
            "login_lockout_threshold": cfg.LOGIN_LOCKOUT_THRESHOLD,
            "login_lockout_minutes": cfg.LOGIN_LOCKOUT_MINUTES,
        },
    }


@router.patch("/system")
async def update_system_config(
    config: SystemConfig,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    if config.honeypot_mode:
        mode = HoneypotMode(config.honeypot_mode.value)
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

    # The node rows are the record; the engine is what actually answers
    # attackers. Saving used to change only the rows, so the dashboard could
    # say "passive" while the engine kept emulating. Push it, and say plainly
    # when that was not possible — the engine also adopts the stored mode
    # whenever it registers, so an unreachable engine catches up on restart.
    engine_applied = None
    if config.honeypot_mode:
        from app.api.honeypot import _engine_request

        try:
            await _engine_request("POST", "/mode", {"mode": config.honeypot_mode.value})
            engine_applied = True
        except HTTPException as exc:
            engine_applied = False
            logger.warning("Mode saved but not applied to the engine: %s", exc.detail)

    return {
        "status": "updated",
        "message": "System configuration updated",
        "honeypot_mode": config.honeypot_mode.value if config.honeypot_mode else None,
        "engine_applied": engine_applied,
    }
