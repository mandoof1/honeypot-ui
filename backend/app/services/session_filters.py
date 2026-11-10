"""One filter contract for the session browser and all export formats."""
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import defer
from app.core.sql import LIKE_ESCAPE, escape_like
from app.models import HoneypotSession, SessionStatus, AttackCategory, AttackerProfile

#: The encrypted columns of a session. Each can run to megabytes (a captured
#: payload, a long transcript) and no list, search or export-by-summary ever
#: reads them, yet ``select(HoneypotSession)`` fetched all four for every row:
#: a page of a hundred sessions could pull hundreds of megabytes through the
#: API process to show a table.
SESSION_BLOB_COLUMNS = (
    HoneypotSession.raw_commands_encrypted,
    HoneypotSession.raw_payloads_encrypted,
    HoneypotSession.transcript_encrypted,
    HoneypotSession.credentials_encrypted,
)


def without_blobs(query, keep=()):
    """Leave the encrypted columns out of a session query.

    ``keep`` names any that the caller does need. The others raise if they
    are touched instead of loading lazily, which an async session cannot do
    anyway; the error then names the column rather than the event loop.
    """
    kept = {column.key for column in keep}
    options = [
        defer(column, raiseload=True)
        for column in SESSION_BLOB_COLUMNS
        if column.key not in kept
    ]
    return query.options(*options)


def presence_flags():
    """has_transcript / has_credentials, computed by the database.

    The session response says whether a transcript and credentials exist.
    With the blobs deferred that cannot be read off the row, so the query
    asks for the two booleans directly.
    """
    return (
        HoneypotSession.transcript_encrypted.isnot(None).label("has_transcript"),
        HoneypotSession.credentials_encrypted.isnot(None).label("has_credentials"),
    )


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
