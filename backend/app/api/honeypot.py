"""Proxy routes onto the honeypot engine's control API.

Every route here used to return hardcoded placeholder data: /status invented a
"running" engine, /block-ip replied `{"status": "blocked"}` without blocking
anything, and /security-status asserted `overall_secure: true` unconditionally.
They now proxy to the engine and report honestly when it is unreachable.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.core.config import get_settings
from app.core.security import get_current_user, require_role

logger = logging.getLogger(__name__)
router = APIRouter()

ENGINE_TIMEOUT = 5.0
VALID_PROTOCOLS = {"ssh", "ftp", "http", "https"}


class CaptureDeliveryStatus(BaseModel):
    available: bool = True
    pending: Optional[int] = None
    retrying: int = 0
    oldest_pending_seconds: Optional[int] = None
    max_attempts: int = 0
    capture_errors: int = 0
    last_error: Optional[str] = None


class HoneypotStatusResponse(BaseModel):
    reachable: bool
    running: bool = False
    mode: Optional[str] = None
    protocols: list[str] = Field(default_factory=list)
    active_sessions: int = 0
    total_sessions: int = 0
    blocked_ips: int = 0
    anti_fingerprinting: bool = False
    adaptive_response: bool = False
    isolation: dict = Field(default_factory=dict)
    node_id: Optional[int] = None
    delivery: Optional[CaptureDeliveryStatus] = None
    #: Populated when the engine could not be reached.
    detail: Optional[str] = None


class ModeUpdate(BaseModel):
    mode: str

    @field_validator("mode")
    @classmethod
    def _known_mode(cls, value: str) -> str:
        if value not in ("active", "passive"):
            raise ValueError("mode must be 'active' or 'passive'")
        return value


class IPActionRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        import ipaddress

        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("ip must be a valid IPv4 or IPv6 address")
        return value


async def _engine_request(
    method: str, path: str, json_body: Optional[dict] = None
) -> Any:
    settings = get_settings()
    url = f"{settings.HONEYPOT_CONTROL_URL.rstrip('/')}{path}"
    try:
        async with httpx.AsyncClient(timeout=ENGINE_TIMEOUT) as client:
            response = await client.request(
                method,
                url,
                json=json_body,
                headers={"X-Honeypot-Token": settings.HONEYPOT_INGEST_TOKEN},
            )
    except httpx.HTTPError as exc:
        logger.warning("Honeypot engine unreachable at %s: %s", url, exc)
        raise HTTPException(
            status_code=503,
            detail="Honeypot engine is unreachable",
        )

    if response.status_code == 401:
        raise HTTPException(
            status_code=502,
            detail=(
                "Honeypot engine rejected the control token; backend and "
                "engine HONEYPOT_INGEST_TOKEN values do not match"
            ),
        )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"Honeypot engine returned HTTP {response.status_code}",
        )
    return response.json()


@router.get("/status", response_model=HoneypotStatusResponse)
async def get_honeypot_status(current_user: dict = Depends(get_current_user)):
    """Report live engine state, or say plainly that it is unreachable."""
    try:
        data = await _engine_request("GET", "/status")
    except HTTPException as exc:
        return HoneypotStatusResponse(
            reachable=False, running=False, detail=str(exc.detail)
        )
    return HoneypotStatusResponse(reachable=True, **data)


@router.get("/security-status")
async def get_security_status(current_user: dict = Depends(get_current_user)):
    try:
        return await _engine_request("GET", "/security-status")
    except HTTPException as exc:
        return {
            "reachable": False,
            "overall_secure": False,
            "detail": str(exc.detail),
        }


@router.get("/blocked-ips")
async def get_blocked_ips(current_user: dict = Depends(get_current_user)):
    return await _engine_request("GET", "/blocked-ips")


@router.get("/denied-connections")
async def get_denied_connections(
    current_user: dict = Depends(get_current_user),
):
    return await _engine_request("GET", "/denied-connections")


@router.get("/threat-actors")
async def get_threat_actors(current_user: dict = Depends(get_current_user)):
    return await _engine_request("GET", "/threat-actors")


@router.get("/sessions/active")
async def get_active_sessions(current_user: dict = Depends(get_current_user)):
    return await _engine_request("GET", "/sessions/active")


@router.patch("/mode")
async def update_mode(
    update: ModeUpdate,
    current_user: dict = Depends(require_role("admin")),
):
    return await _engine_request("POST", "/mode", {"mode": update.mode})


@router.post("/block-ip")
async def block_ip(
    payload: IPActionRequest,
    current_user: dict = Depends(require_role("analyst")),
):
    return await _engine_request("POST", "/block-ip", {"ip": payload.ip})


@router.post("/unblock-ip")
async def unblock_ip(
    payload: IPActionRequest,
    current_user: dict = Depends(require_role("admin")),
):
    return await _engine_request("POST", "/unblock-ip", {"ip": payload.ip})
