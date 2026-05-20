from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models import HoneypotNode, AuditLog, HoneypotMode
from app.schemas import HoneypotNodeCreate, HoneypotNodeUpdate, HoneypotNodeResponse

router = APIRouter()


@router.get("/", response_model=list[HoneypotNodeResponse])
async def list_nodes(
    active_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(HoneypotNode)
    if active_only:
        query = query.where(HoneypotNode.is_active == True)
    query = query.order_by(HoneypotNode.name)

    result = await db.execute(query)
    nodes = result.scalars().all()
    return [
        HoneypotNodeResponse(
            id=n.id, name=n.name, protocol=n.protocol, ip_address=n.ip_address,
            port=n.port, mode=n.mode, is_active=n.is_active,
            location_lat=n.location_lat, location_lon=n.location_lon,
            last_heartbeat=n.last_heartbeat, created_at=n.created_at,
        )
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

    audit = AuditLog(
        user_id=current_user["id"],
        action="node_created",
        resource_type="honeypot_node",
        resource_id=node.id,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(node)

    return HoneypotNodeResponse(
        id=node.id, name=node.name, protocol=node.protocol, ip_address=node.ip_address,
        port=node.port, mode=node.mode, is_active=node.is_active,
        location_lat=node.location_lat, location_lon=node.location_lon,
        last_heartbeat=node.last_heartbeat, created_at=node.created_at,
    )


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

    return HoneypotNodeResponse(
        id=node.id, name=node.name, protocol=node.protocol, ip_address=node.ip_address,
        port=node.port, mode=node.mode, is_active=node.is_active,
        location_lat=node.location_lat, location_lon=node.location_lon,
        last_heartbeat=node.last_heartbeat, created_at=node.created_at,
    )


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

    return HoneypotNodeResponse(
        id=node.id, name=node.name, protocol=node.protocol, ip_address=node.ip_address,
        port=node.port, mode=node.mode, is_active=node.is_active,
        location_lat=node.location_lat, location_lon=node.location_lon,
        last_heartbeat=node.last_heartbeat, created_at=node.created_at,
    )


@router.delete("/{node_id}", status_code=204)
async def delete_node(
    node_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    audit = AuditLog(
        user_id=current_user["id"],
        action="node_deleted",
        resource_type="honeypot_node",
        resource_id=node.id,
    )
    db.add(audit)
    await db.delete(node)
    await db.commit()
