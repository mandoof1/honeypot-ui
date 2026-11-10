"""Response models for the operator-facing views: audit log, trends, sign-in."""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel


class AuditLogEntry(BaseModel):
    id: int
    #: Null for actions the system took itself (an ingested session).
    user_id: Optional[int] = None
    user_email: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[int] = None
    details: Optional[Any] = None
    ip_address: Optional[str] = None
    created_at: Optional[datetime] = None


class AuditLogPage(BaseModel):
    items: List[AuditLogEntry]
    #: Rows matching the filters, not just the ones on this page.
    total: int


class TrendPoint(BaseModel):
    #: Start of the UTC day, ISO 8601 with a Z suffix.
    t: str
    #: Every session that started that day, including uncategorised ones, so
    #: it can exceed the sum of the four categories.
    total: int = 0
    benign: int = 0
    reconnaissance: int = 0
    exploitation: int = 0
    exfiltration: int = 0


class TrendSeries(BaseModel):
    bucket: str = "day"
    timezone: str = "UTC"
    #: One entry per day, oldest first, days with no sessions included.
    series: List[TrendPoint]


class AuthCapabilities(BaseModel):
    """What the sign-in pages can offer on this deployment.

    Public, because the console needs it before anyone is signed in: with no
    mail provider configured, signing up or resetting a password by emailed
    code can never complete, and the pages should not offer it.
    """

    email_delivery: bool
    self_registration: bool
    password_reset: bool
    mfa: bool = True
