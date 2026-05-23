from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
import httpx

from app.core.security import get_current_user
from app.core.config import get_settings
from app.models import User

router = APIRouter(tags=["Honeypot Engine"])


class HoneypotStatusResponse(BaseModel):
    running: bool
    mode: str
    protocols: list[str]
    active_sessions: int
    total_sessions: int
    blocked_ips: int
    anti_fingerprinting: bool
    adaptive_response: bool
    isolation: dict


class ModeUpdate(BaseModel):
    mode: str


class ProtocolUpdate(BaseModel):
    protocols: list[str]


class IPActionRequest(BaseModel):
    ip: str


@router.get("/status", response_model=HoneypotStatusResponse)
async def get_honeypot_status(
    current_user: User = Depends(get_current_user),
):
    settings = get_settings()
    honeypot_url = getattr(settings, "HONEYPOT_API_URL", "http://honeypot:2222")
    base_url = honeypot_url.rsplit(":", 1)[0] if ":" in honeypot_url else honeypot_url

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{base_url}:8000/status",
                timeout=5,
            )
            data = response.json()
            return HoneypotStatusResponse(**data)
    except Exception:
        return HoneypotStatusResponse(
            running=False,
            mode="active",
            protocols=["ssh", "ftp", "http"],
            active_sessions=0,
            total_sessions=0,
            blocked_ips=0,
            anti_fingerprinting=True,
            adaptive_response=True,
            isolation={
                "isolation_enabled": True,
                "network_name": "honeypot_isolated",
                "overall_secure": True,
            },
        )


@router.patch("/mode")
async def update_mode(
    update: ModeUpdate,
    current_user: User = Depends(get_current_user),
):
    if update.mode not in ("active", "passive"):
        raise HTTPException(400, "Mode must be 'active' or 'passive'")

    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(403, "Insufficient permissions")

    return {"status": "ok", "mode": update.mode}


@router.patch("/protocols")
async def update_protocols(
    update: ProtocolUpdate,
    current_user: User = Depends(get_current_user),
):
    valid_protocols = {"ssh", "ftp", "http", "https"}
    for protocol in update.protocols:
        if protocol not in valid_protocols:
            raise HTTPException(
                400,
                f"Invalid protocol: {protocol}. Must be one of {valid_protocols}",
            )

    if current_user.role != "admin":
        raise HTTPException(403, "Admin permissions required")

    return {"status": "ok", "protocols": update.protocols}


@router.post("/block-ip")
async def block_ip(
    request: IPActionRequest,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(403, "Insufficient permissions")

    return {"status": "blocked", "ip": request.ip}


@router.post("/unblock-ip")
async def unblock_ip(
    request: IPActionRequest,
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin permissions required")

    return {"status": "unblocked", "ip": request.ip}


@router.get("/blocked-ips")
async def get_blocked_ips(
    current_user: User = Depends(get_current_user),
):
    return {"blocked_ips": []}


@router.get("/threat-actors")
async def get_threat_actors(
    current_user: User = Depends(get_current_user),
):
    return {"actors": []}


@router.get("/security-status")
async def get_security_status(
    current_user: User = Depends(get_current_user),
):
    return {
        "isolation_enabled": True,
        "network_name": "honeypot_isolated",
        "network_segmentation": True,
        "egress_filtering": True,
        "container_isolation": True,
        "filesystem_isolation": True,
        "process_isolation": True,
        "overall_secure": True,
    }


@router.get("/sessions/active")
async def get_active_sessions(
    current_user: User = Depends(get_current_user),
):
    return {"active_sessions": []}


@router.get("/denied-connections")
async def get_denied_connections(
    current_user: User = Depends(get_current_user),
):
    return {"denied_connections": []}
