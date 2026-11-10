from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.database import get_db
from app.core.sanitize import clean_json
from app.core.security import (
    EngineCredential,
    authorize_engine_for_node,
    get_current_user,
    require_role,
    verify_honeypot_token,
)
from app.models import AttackSeverity, AuditLog, HoneypotNode, HoneypotSession
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


def _to_response(node: HoneypotNode, stored_sessions: Optional[int] = None) -> HoneypotNodeResponse:
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
        stored_sessions=stored_sessions,
    )


async def _stored_session_counts(db: AsyncSession, node_ids) -> dict:
    """Sessions in the database per engine, in one query."""
    if not node_ids:
        return {}
    rows = await db.execute(
        select(HoneypotSession.node_id, func.count(HoneypotSession.id))
        .where(HoneypotSession.node_id.in_(list(node_ids)))
        .group_by(HoneypotSession.node_id)
    )
    return {node_id: count for node_id, count in rows.all()}


def _clean_status(status: dict) -> dict:
    clean = {}
    for key in _STATUS_KEYS:
        if key in status:
            value = status[key]
            if isinstance(value, (dict, list)):
                # Bounded: the report is small, but it comes over the wire.
                if len(str(value)) > 4000:
                    continue
            elif isinstance(value, str):
                value = value[:200]
            clean[key] = value
    # Stored as JSONB, which refuses a NUL anywhere inside it.
    return clean_json(clean)


def _isolation_failures(isolation: dict) -> list[str]:
    """Names of the self-checks an engine reported as failing."""
    last_check = isolation.get("last_check")
    if not isinstance(last_check, dict):
        return []
    return sorted(
        str(name)[:64]
        for name, passed in last_check.items()
        if passed is False and name != "overall_secure"
    )[:12]


async def _track_isolation(db: AsyncSession, node: HoneypotNode, status: dict) -> None:
    """Raise or resolve the system alert for an engine's isolation self-check.

    Every engine checks, at start and on request, that it sits where it is
    meant to: on an internal network, with no route out, a read-only root
    and no spare capabilities. The verdict travels in the heartbeat and was
    shown on the node's page, where nobody was looking at 3 a.m. An engine
    that says it is not contained now opens a system alert like an engine
    that stops reporting does.
    """
    isolation = status.get("isolation")
    if not isinstance(isolation, dict):
        return
    key = f"node_isolation:{node.name}"

    if isolation.get("overall_secure") is False:
        failures = _isolation_failures(isolation)
        if failures:
            detail = "Failing checks: " + ", ".join(failures) + "."
        elif isolation.get("isolation_enabled") is False:
            detail = "Isolation checks are switched off on the engine (HONEYPOT_ENABLE_ISOLATION)."
        else:
            detail = "The heartbeat did not say which check failed."
        # Deduplicated by key: one open alert however many heartbeats repeat
        # the verdict, re-raised if someone resolves it while it still holds.
        await alert_service.raise_system_alert(
            db,
            key=key,
            severity=AttackSeverity.CRITICAL,
            title=f"Engine {node.name} reports it is not isolated",
            description=(
                f"Honeypot engine '{node.name}' reported that its own isolation "
                f"check did not pass. {detail} Until this is fixed, a decoy that "
                f"is compromised may be able to reach other systems."
            ),
            node=node,
        )
        return

    if isolation.get("overall_secure") is True:
        # One indexed lookup per heartbeat, and almost always a no-op. Not
        # conditional on the previous report: that would leave the alert open
        # if a single heartbeat in between arrived without the section.
        await alert_service.resolve_system_alert(
            db, key, "Engine reported its isolation checks passing again."
        )


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
    counts = await _stored_session_counts(db, [n.id for n in nodes])
    return [
        _to_response(n, counts.get(n.id, 0))
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


async def _node_named(db: AsyncSession, name: str) -> Optional[HoneypotNode]:
    """The node an engine means by its name.

    Names are not unique in the schema (an administrator can create two nodes
    called the same thing), so this takes the oldest rather than failing with
    a 500 on the second.
    """
    return (
        await db.execute(
            select(HoneypotNode)
            .where(HoneypotNode.name == name)
            .order_by(HoneypotNode.id)
            .limit(1)
        )
    ).scalars().first()


@router.post("/register-internal", response_model=HoneypotNodeResponse)
async def register_node_internal(
    node_data: HoneypotNodeCreate,
    db: AsyncSession = Depends(get_db),
    credential: EngineCredential = Depends(verify_honeypot_token),
):
    """Register (or refresh) the calling honeypot engine as a node.

    Service-to-service: authenticated with an engine token rather than a user
    JWT. The engine previously POSTed to the admin-only create endpoint with
    no credentials, so registration always failed and it silently defaulted
    to node id 1.

    The token must be the one for the name being registered: a node with its
    own entry in HONEYPOT_NODE_TOKENS can only be registered with that
    token, and that token registers no other name.
    """
    authorize_engine_for_node(credential, node_data.name)
    node = await _node_named(db, node_data.name)

    if node is None:
        node = HoneypotNode(**node_data.model_dump())
        db.add(node)
    else:
        node.protocol = node_data.protocol
        node.ip_address = node_data.ip_address
        node.port = node_data.port
        # is_active is left alone. An engine re-registers every time it
        # starts, and that used to switch a node an administrator had
        # deactivated straight back on.

    node.last_heartbeat = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(node)
    return _to_response(node)


@router.post("/heartbeat-internal")
async def node_heartbeat(
    beat: NodeHeartbeat,
    db: AsyncSession = Depends(get_db),
    credential: EngineCredential = Depends(verify_honeypot_token),
):
    """The engine's periodic liveness report.

    Until this existed ``last_heartbeat`` was written once, at registration,
    so the dashboard could not tell a running engine from one that died a day
    ago. The engine posts every minute; the response carries the stored mode
    so an operator's change in Settings reaches a running engine without a
    restart. 404 tells the engine to register again.

    A heartbeat records that the engine is alive. It does not make the node
    active: that flag is the administrator's, and every heartbeat used to
    overwrite it, so a deactivated node came back within a minute.
    """
    # Checked against the name the engine claims before anything is looked
    # up, so a token for one node cannot even probe for another.
    authorize_engine_for_node(credential, beat.name)

    node = None
    if beat.node_id:
        node = (
            await db.execute(select(HoneypotNode).where(HoneypotNode.id == beat.node_id))
        ).scalar_one_or_none()
    if node is None or node.name != beat.name:
        node = await _node_named(db, beat.name)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not registered")

    node.last_heartbeat = datetime.now(timezone.utc)
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
    await _track_isolation(db, node, status)
    await db.commit()
    return {
        "id": node.id,
        "mode": node.mode.value,
        "name": node.name,
        # So an engine can tell it has been switched off in the console.
        "is_active": bool(node.is_active),
    }


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

    counts = await _stored_session_counts(db, [node.id])
    return _to_response(node, counts.get(node.id, 0))


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

    # last_heartbeat is not touched: only the engine's own reports count as
    # a heartbeat. Stamping it here made renaming or deactivating a dead
    # engine show it as online for the next three minutes.

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
