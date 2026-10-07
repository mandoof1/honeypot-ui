from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import get_current_user, require_role, verify_honeypot_token
from app.models import AuditLog, HoneypotNode, HoneypotSession
from app.schemas import (
    HoneypotNodeCreate,
    HoneypotNodeUpdate,
    HoneypotNodeResponse,
    NodeHeartbeat,
)
from app.services import alerts as alert_service

router = APIRouter()

#: Keys of the engine's status report that are kept. Anything else it sends
#: is dropped rather than stored and shown unreviewed.
_STATUS_KEYS = {
    "running", "mode", "protocols", "protocols_bound", "active_sessions",
    "total_sessions", "open_connections", "blocked_ips", "refused_connections",
    "isolation", "uptime_seconds", "spool_pending", "spool_bytes", "ingest",
    "disk", "anti_fingerprinting", "adaptive_response", "version",
    "node_registered",
}


def _heartbeat_age(node: HoneypotNode) -> Optional[int]:
    if node.last_heartbeat is None:
        return None
    beat = node.last_heartbeat
    if beat.tzinfo is None:
        beat = beat.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - beat).total_seconds()))


def _to_response(node: HoneypotNode) -> HoneypotNodeResponse:
    age = _heartbeat_age(node)
    stale_after = get_settings().NODE_STALE_SECONDS
    return HoneypotNodeResponse(
        id=node.id,
        name=node.name,
        protocol=node.protocol,
        ip_address=node.ip_address,
        port=node.port,
        mode=node.mode,
        is_active=node.is_active,
        location_lat=node.location_lat,
        location_lon=node.location_lon,
        last_heartbeat=node.last_heartbeat,
        created_at=node.created_at,
        online=bool(node.is_active and age is not None and age <= stale_after),
        heartbeat_age_seconds=age,
        version=getattr(node, "version", None),
        status=node.last_status if isinstance(node.last_status, dict) else None,
    )


def _clean_status(status: dict) -> dict:
    clean = {}
    for key in _STATUS_KEYS:
        if key in status:
            value = status[key]
            if isinstance(value, (dict, list)):
                # Bounded: the report is small, but it comes over the wire.
                if len(str(value)) > 4000:
                    continue
            clean[key] = value
    return clean


@router.get("/", response_model=list[HoneypotNodeResponse])
async def list_nodes(
    active_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(HoneypotNode)
    if active_only:
        query = query.where(HoneypotNode.is_active.is_(True))
    query = query.order_by(HoneypotNode.name)

    result = await db.execute(query)
    nodes = result.scalars().all()
    return [
        _to_response(n)
        for n in nodes
    ]


@router.post("/", response_model=HoneypotNodeResponse, status_code=201)
async def create_node(
    node_data: HoneypotNodeCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    node = HoneypotNode(**node_data.model_dump())
    db.add(node)
    await db.flush()  # populate node.id before referencing it in the audit row

    audit = AuditLog(
        user_id=current_user["id"],
        action="node_created",
        resource_type="honeypot_node",
        resource_id=node.id,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(node)

    return _to_response(node)


@router.post(
    "/register-internal",
    response_model=HoneypotNodeResponse,
    dependencies=[Depends(verify_honeypot_token)],
)
async def register_node_internal(
    node_data: HoneypotNodeCreate,
    db: AsyncSession = Depends(get_db),
):
    """Register (or refresh) the calling honeypot engine as a node.

    Service-to-service: authenticated with the shared ingest token rather than
    a user JWT. The engine previously POSTed to the admin-only create endpoint
    with no credentials, so registration always failed and it silently
    defaulted to node id 1.
    """
    result = await db.execute(
        select(HoneypotNode).where(HoneypotNode.name == node_data.name)
    )
    node = result.scalar_one_or_none()

    if node is None:
        node = HoneypotNode(**node_data.model_dump())
        db.add(node)
    else:
        node.protocol = node_data.protocol
        node.ip_address = node_data.ip_address
        node.port = node_data.port
        node.is_active = True

    node.last_heartbeat = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(node)
    return _to_response(node)


@router.post("/heartbeat-internal", dependencies=[Depends(verify_honeypot_token)])
async def node_heartbeat(
    beat: NodeHeartbeat,
    db: AsyncSession = Depends(get_db),
):
    """The engine's periodic liveness report.

    Until this existed ``last_heartbeat`` was written once, at registration,
    so the dashboard could not tell a running engine from one that died a day
    ago. The engine posts every minute; the response carries the stored mode
    so an operator's change in Settings reaches a running engine without a
    restart. 404 tells the engine to register again.
    """
    node = None
    if beat.node_id:
        node = (
            await db.execute(select(HoneypotNode).where(HoneypotNode.id == beat.node_id))
        ).scalar_one_or_none()
    if node is None or node.name != beat.name:
        node = (
            await db.execute(select(HoneypotNode).where(HoneypotNode.name == beat.name))
        ).scalar_one_or_none()
    if node is None:
        raise HTTPException(status_code=404, detail="Node not registered")

    node.last_heartbeat = datetime.now(timezone.utc)
    node.is_active = True
    status = _clean_status(beat.status or {})
    node.last_status = status
    version = beat.version or status.get("version")
    if version:
        node.version = str(version)[:32]
    if node.offline_alerted:
        await alert_service.resolve_system_alert(
            db, f"node_offline:{node.name}", f"Engine reported again at {node.last_heartbeat.isoformat()}."
        )
        node.offline_alerted = False
    await db.commit()
    return {"id": node.id, "mode": node.mode.value, "name": node.name}


@router.get("/{node_id}", response_model=HoneypotNodeResponse)
async def get_node(
    node_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    return _to_response(node)


@router.patch("/{node_id}", response_model=HoneypotNodeResponse)
async def update_node(
    node_id: int,
    update_data: HoneypotNodeUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(node, key, value)

    node.last_heartbeat = datetime.now(timezone.utc)

    audit = AuditLog(
        user_id=current_user["id"],
        action="node_updated",
        resource_type="honeypot_node",
        resource_id=node.id,
        details=update_dict,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(node)

    return _to_response(node)


@router.delete("/{node_id}", status_code=204)
async def delete_node(
    node_id: int,
    force: bool = Query(
        False, description="Also delete every session captured by this node"
    ),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    session_count = (
        await db.execute(
            select(func.count(HoneypotSession.id)).where(
                HoneypotSession.node_id == node_id
            )
        )
    ).scalar() or 0
    if session_count and not force:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Node has {session_count} captured session(s). Deactivate it "
                f"instead, or pass force=true to delete the sessions with it."
            ),
        )

    audit = AuditLog(
        user_id=current_user["id"],
        action="node_deleted",
        resource_type="honeypot_node",
        resource_id=node.id,
    )
    db.add(audit)
    await db.delete(node)
    await db.commit()
