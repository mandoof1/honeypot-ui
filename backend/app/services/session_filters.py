"""One filter contract for the session browser and all export formats."""
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import HTTPException, Query
from sqlalchemy import select
from app.core.sql import LIKE_ESCAPE, escape_like
from app.models import HoneypotSession, SessionStatus, AttackCategory, AttackerProfile

def _parse_enum(enum_cls, value: str, field: str):
    """Map a query-string value onto an enum, or raise 400.

    Passing the raw value to the enum constructor made an unknown filter
    value raise ValueError, which surfaced to the client as a 500.
    """
    try:
        return enum_cls(value)
    except ValueError:
        allowed = ", ".join(member.value for member in enum_cls)
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field} {value!r}. Expected one of: {allowed}",
        )


def session_filters(
    status: Optional[str] = None,
    attack_category: Optional[str] = None,
    attacker_profile: Optional[str] = None,
    country: Optional[str] = None,
    ip_address: Optional[str] = None,
    is_anomalous: Optional[bool] = None,
    exclude_scanners: Annotated[bool, Query(description=(
        "Hide sessions attributed to research scanners such as Censys, Shodan and "
        "Shadowserver. Sessions remain recorded; included by default."
    ))] = False,
    search: Optional[str] = None,
    protocol: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
):
    query = select(HoneypotSession)
    if status:
        parsed = _parse_enum(SessionStatus, status, "status")
        query = query.where(HoneypotSession.status == parsed)
    if attack_category:
        parsed = _parse_enum(AttackCategory, attack_category, "attack_category")
        query = query.where(HoneypotSession.attack_category == parsed)
    if attacker_profile:
        parsed = _parse_enum(
            AttackerProfile, attacker_profile, "attacker_profile"
        )
        query = query.where(HoneypotSession.attacker_profile == parsed)
    if country:
        query = query.where(HoneypotSession.geo_country == country.upper())
    if ip_address:
        pattern = f"%{escape_like(ip_address)}%"
        query = query.where(HoneypotSession.attacker_ip.ilike(pattern, escape=LIKE_ESCAPE))
    if is_anomalous is not None:
        query = query.where(HoneypotSession.is_anomalous == is_anomalous)
    if exclude_scanners:
        # A honeypot on a public address is scanned continuously by
        # organisations that are not attacking it; counting their probes as
        # attacks makes every figure incomparable.
        scanner_filter = HoneypotSession.scanner_operator.is_(None)
        query = query.where(scanner_filter)
    if search:
        pattern = f"%{escape_like(search)}%"
        search_filter = (
            HoneypotSession.attacker_ip.ilike(pattern, escape=LIKE_ESCAPE)
            | HoneypotSession.session_uuid.ilike(pattern, escape=LIKE_ESCAPE)
            | HoneypotSession.command_summary.ilike(pattern, escape=LIKE_ESCAPE)
        )
        query = query.where(search_filter)

    if protocol:
        protocol = protocol.lower()
        if protocol not in {"ssh", "ftp", "telnet", "http", "https"}:
            raise HTTPException(400, "Invalid protocol. Expected ssh, ftp, telnet, http or https")
        query = query.where(HoneypotSession.protocol == protocol)
    # Interpret timezone-free API timestamps as UTC, consistently across hosts.
    if date_from:
        date_from = date_from.replace(tzinfo=timezone.utc) if date_from.tzinfo is None else date_from.astimezone(timezone.utc)
    if date_to:
        date_to = date_to.replace(tzinfo=timezone.utc) if date_to.tzinfo is None else date_to.astimezone(timezone.utc)
    if date_from and date_to and date_from > date_to:
        raise HTTPException(400, "Start date must be before end date")
    if date_from:
        query = query.where(HoneypotSession.started_at >= date_from)
    if date_to:
        query = query.where(HoneypotSession.started_at <= date_to)
    return query.whereclause
