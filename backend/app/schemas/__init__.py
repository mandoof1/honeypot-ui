from __future__ import annotations
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class UserRole(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


class HoneypotMode(str, Enum):
    ACTIVE = "active"
    PASSIVE = "passive"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    TERMINATED = "terminated"


class AttackSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCategory(str, Enum):
    BENIGN = "benign"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    EXFILTRATION = "exfiltration"


class AttackerProfile(str, Enum):
    SCRIPT_KIDDIE = "script_kiddie"
    AUTOMATED_BOT = "automated_bot"
    SKILLED_ATTACKER = "skilled_attacker"
    APT = "apt"
    UNKNOWN = "unknown"


class AlertStatusEnum(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class MitreTechnique(BaseModel):
    """A single mapped ATT&CK technique.

    The pipeline stores technique objects, but the response models declared
    List[str], so every session carrying a technique failed response
    validation with a 500.
    """

    id: str
    name: str
    source: Optional[str] = None
    confidence: Optional[float] = None
    #: For a technique the language model named: the decision model's
    #: probability that the transcript shows it, and whether that fell below
    #: the confirmation threshold.
    support: Optional[float] = None
    unconfirmed: Optional[bool] = None


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    sub: str
    exp: datetime
    role: str


class UserCreate(BaseModel):
    """Self-service registration payload.

    Deliberately has no `role` field: it used to accept one, so anyone could
    register themselves as an administrator. Roles are assigned by an admin
    through the user-management endpoint.
    """

    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)
    name: Optional[str] = Field(None, max_length=255)


class AdminUserCreate(UserCreate):
    role: UserRole = UserRole.ANALYST


class UserRoleUpdate(BaseModel):
    role: UserRole


class UserAdminUpdate(BaseModel):
    is_active: Optional[bool] = None
    name: Optional[str] = Field(None, max_length=255)


class AdminPasswordReset(BaseModel):
    new_password: str = Field(..., min_length=12, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    # Optional: only required once the account has enrolled an authenticator.
    totp_code: Optional[str] = None


class UserResponse(BaseModel):
    id: int
    email: str
    name: Optional[str]
    role: UserRole
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime]
    #: Lets the UI offer enrolment or removal of an authenticator.
    totp_enabled: bool = False

    class Config:
        from_attributes = True


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6)
    purpose: str = "email_verification"


class OTPResendRequest(BaseModel):
    email: EmailStr
    purpose: str = "email_verification"


class MFACodeRequest(BaseModel):
    """A six-digit authenticator code, or a single-use recovery code."""

    code: str = Field(..., min_length=6, max_length=32)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6)
    new_password: str = Field(..., min_length=12, max_length=128)


class RegisterResponse(BaseModel):
    message: str
    email: str
    requires_verification: bool


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=12, max_length=128)


class HoneypotNodeCreate(BaseModel):
    name: str
    protocol: str
    ip_address: str
    port: int
    mode: HoneypotMode = HoneypotMode.ACTIVE
    location_lat: Optional[float] = None
    location_lon: Optional[float] = None


class HoneypotNodeUpdate(BaseModel):
    name: Optional[str] = None
    mode: Optional[HoneypotMode] = None
    is_active: Optional[bool] = None


class HoneypotNodeResponse(BaseModel):
    id: int
    name: str
    protocol: str
    ip_address: str
    port: int
    mode: HoneypotMode
    is_active: bool
    location_lat: Optional[float]
    location_lon: Optional[float]
    last_heartbeat: Optional[datetime]
    created_at: datetime
    #: Liveness, derived from the heartbeat age against NODE_STALE_SECONDS.
    online: bool = False
    heartbeat_age_seconds: Optional[int] = None
    version: Optional[str] = None
    #: The engine's last status report: mode, bound protocols, active
    #: sessions, spool depth, disk space.
    status: Optional[dict] = None


class NodeHeartbeat(BaseModel):
    node_id: Optional[int] = None
    name: str
    status: dict = {}
    version: Optional[str] = None


class SessionEnrichment(BaseModel):
    intent: Optional[str] = None
    objectives: List[str] = []
    sophistication: Optional[str] = None
    confidence: Optional[float] = None
    model: Optional[str] = None
    analysed_at: Optional[str] = None
    reused_from_session: Optional[int] = None
    error: Optional[str] = None
    #: The decision model that checked the techniques, when one did, and
    #: the techniques it removed (only with DECIDER_DROP_UNCONFIRMED).
    checked_by: Optional[str] = None
    dropped_techniques: List[MitreTechnique] = []

    class Config:
        from_attributes = True


class SessionTriage(BaseModel):
    """The decision model's triage of a session, next to the rules' verdict."""

    category: Optional[str] = None
    category_probabilities: Optional[Dict[str, float]] = None
    #: Expected level on the 0-3 scale, and the distribution behind it.
    severity: Optional[float] = None
    severity_probabilities: Optional[Dict[str, float]] = None
    p_low: Optional[float] = None
    p_compromise: Optional[float] = None
    operator: Optional[str] = None
    operator_probability: Optional[float] = None
    agrees_with_rules: Optional[bool] = None
    rules_verdict: Optional[str] = None
    #: What triage did with the session: "pending" (sent to the language
    #: model) or "skipped", and why.
    route: Optional[str] = None
    #: Set instead of ``route`` when the session was not waiting on triage
    #: (analysed on request meanwhile, or triaged after the fact).
    suggested_route: Optional[str] = None
    route_reason: Optional[str] = None
    model: Optional[str] = None
    ms: Optional[float] = None
    reused_from_session: Optional[int] = None
    triaged_at: Optional[str] = None
    error: Optional[str] = None


class GeoInfo(BaseModel):
    country: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None


class ClusterAssignment(BaseModel):
    """Where the unsupervised model placed this session.

    ``fitted`` is false until enough sessions exist to fit at all, and the UI
    is expected to say so rather than showing cluster 0 for everything.
    """

    fitted: bool = False
    cluster: Optional[int] = None
    distance: Optional[float] = None
    is_outlier: Optional[bool] = None


class TranscriptEntry(BaseModel):
    command: str
    output: str = ""
    exit_code: int = 0
    timestamp: Optional[float] = None


class SessionTranscriptResponse(BaseModel):
    session_id: int
    session_uuid: str
    #: False when the session predates transcript capture or held no commands,
    #: so the client can distinguish "nothing recorded" from "empty session".
    available: bool
    entries: List[TranscriptEntry] = []
    truncated: bool = False


class CapturedCredential(BaseModel):
    username: str
    password: str
    success: bool
    timestamp: Optional[float] = None


class SessionCredentialsResponse(BaseModel):
    session_id: int
    available: bool
    credentials: List[CapturedCredential] = []


class NetworkEvent(BaseModel):
    event_type: str
    url: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    filename: Optional[str] = None
    path: Optional[str] = None
    source_url: Optional[str] = None
    piped_to_shell: Optional[bool] = None
    bytes: Optional[int] = None
    #: Always false — the honeypot records the intent and never performs the
    #: retrieval or the execution. Surfaced so a reader of the UI is never in
    #: doubt about whether the payload actually ran.
    fetched: Optional[bool] = None
    executed: Optional[bool] = None
    #: http_diversion: why the client was handed to the decoy application,
    #: and when it first was (epoch seconds).
    reason: Optional[str] = None
    since: Optional[float] = None
    at: Optional[float] = None


class HoneypotSessionResponse(BaseModel):
    id: int
    session_uuid: str
    node_id: int
    protocol: Optional[str] = None
    attacker_ip: str
    attacker_port: Optional[int]
    geo: Optional[GeoInfo] = None
    status: SessionStatus
    started_at: datetime
    ended_at: Optional[datetime]
    duration_seconds: Optional[float]
    attack_category: Optional[AttackCategory]
    attack_confidence: Optional[float]
    attacker_profile: Optional[AttackerProfile]
    anomaly_score: Optional[float]
    is_anomalous: bool
    command_count: int = 0
    detected_tools: Optional[List[str]]
    detected_intents: Optional[List[str]]
    mitre_tactics: Optional[List[str]]
    mitre_techniques: Optional[List[MitreTechnique]]
    uploaded_files: Optional[List[str]]
    #: Whether the verdict above came from a model trained on real traffic or
    #: from the synthetic bootstrap. Presenting a confidence figure without
    #: this is the difference between a measurement and a decoration.
    model_source: Optional[str] = None
    command_summary: Optional[str] = None
    cluster: Optional[ClusterAssignment] = None
    keystroke_count: int = 0
    network_events: List[NetworkEvent] = []
    #: True when the transcript is stored and can be fetched from
    #: /sessions/{id}/transcript, so the UI can hide the control rather than
    #: offer a request that returns nothing.
    has_transcript: bool = False
    has_credentials: bool = False
    #: Set when the address belongs to a research scanner (Censys, Shodan,
    #: Shadowserver). The session is still real data about what the internet
    #: does to an exposed host; it is just not an attacker.
    scanner_operator: Optional[str] = None
    #: The full class distribution behind attack_confidence.
    class_probabilities: Optional[dict] = None
    #: Wall-clock analysis time in milliseconds, against NFR-2's 200 ms budget.
    analysis_ms: Optional[float] = None
    #: Why the rule layer chose the category, when model_source is "rules".
    rule_reason: Optional[str] = None
    #: Stage-2 state: not_configured, pending, running, complete, failed, skipped.
    enrichment_status: str = "not_configured"
    enrichment: Optional[SessionEnrichment] = None
    #: Decision-model triage: not_configured, pending, running, complete,
    #: failed, or skipped (never a candidate: no commands, or a scanner).
    triage_status: str = "not_configured"
    triage: Optional[SessionTriage] = None
    created_at: datetime

    class Config:
        from_attributes = True

    @staticmethod
    def _enrichment_status(obj) -> str:
        from app.ai.llm import chimera

        raw = getattr(obj, "enrichment_status", None) or "none"
        if raw == "none":
            return "not_configured" if not chimera.enabled else "skipped"
        return raw

    @staticmethod
    def _triage_status(obj) -> str:
        from app.ai.decider import decider

        raw = getattr(obj, "triage_status", None) or "none"
        if raw == "none":
            return "not_configured" if not decider.enabled else "skipped"
        return raw

    @staticmethod
    def _triage(obj):
        data = getattr(obj, "triage", None)
        if not isinstance(data, dict) or ("category" not in data and "error" not in data):
            return None
        return SessionTriage(**{k: v for k, v in data.items() if k in SessionTriage.model_fields})

    @staticmethod
    def _enrichment(obj):
        data = getattr(obj, "enrichment", None)
        error = getattr(obj, "enrichment_error", None)
        if not isinstance(data, dict) and not error:
            return None
        data = data if isinstance(data, dict) else {}
        return SessionEnrichment(
            intent=data.get("intent"),
            objectives=[str(o) for o in (data.get("objectives") or [])],
            sophistication=data.get("sophistication"),
            confidence=data.get("confidence"),
            model=data.get("model"),
            analysed_at=data.get("analysed_at"),
            reused_from_session=data.get("reused_from_session"),
            error=error,
            checked_by=data.get("checked_by"),
            dropped_techniques=[
                MitreTechnique(**{k: v for k, v in t.items() if k in MitreTechnique.model_fields})
                for t in (data.get("dropped_techniques") or [])
                if isinstance(t, dict) and t.get("id")
            ],
        )

    @classmethod
    def from_model(cls, obj):
        return cls(
            id=obj.id,
            session_uuid=obj.session_uuid,
            node_id=obj.node_id,
            protocol=obj.protocol,
            attacker_ip=obj.attacker_ip,
            attacker_port=obj.attacker_port,
            geo=GeoInfo(
                country=obj.geo_country,
                country_name=obj.geo_country_name,
                city=obj.geo_city,
                lat=obj.geo_lat,
                lon=obj.geo_lon,
            ) if obj.geo_country else None,
            status=obj.status,
            started_at=obj.started_at,
            ended_at=obj.ended_at,
            duration_seconds=obj.duration_seconds,
            attack_category=obj.attack_category,
            attack_confidence=obj.attack_confidence,
            attacker_profile=obj.attacker_profile,
            anomaly_score=obj.anomaly_score,
            is_anomalous=obj.is_anomalous,
            command_count=obj.command_count or 0,
            detected_tools=obj.detected_tools or [],
            detected_intents=obj.detected_intents or [],
            mitre_tactics=obj.mitre_tactics or [],
            mitre_techniques=obj.mitre_techniques or [],
            uploaded_files=obj.uploaded_files or [],
            model_source=obj.model_source,
            command_summary=obj.command_summary,
            cluster=ClusterAssignment(
                fitted=obj.cluster_id is not None,
                cluster=obj.cluster_id,
                distance=obj.cluster_distance,
                is_outlier=obj.cluster_is_outlier,
            ),
            keystroke_count=obj.keystroke_count or 0,
            network_events=[
                NetworkEvent(**{k: v for k, v in e.items() if k in NetworkEvent.model_fields})
                for e in (obj.network_events or [])
                if isinstance(e, dict) and e.get("event_type")
            ],
            has_transcript=bool(obj.transcript_encrypted),
            has_credentials=bool(obj.credentials_encrypted),
            scanner_operator=obj.scanner_operator,
            class_probabilities=obj.class_probabilities,
            analysis_ms=obj.analysis_ms,
            rule_reason=getattr(obj, "rule_reason", None),
            enrichment_status=cls._enrichment_status(obj),
            enrichment=cls._enrichment(obj),
            triage_status=cls._triage_status(obj),
            triage=cls._triage(obj),
            created_at=obj.created_at,
        )


class SessionListResponse(BaseModel):
    sessions: List[HoneypotSessionResponse]
    total: int
    page: int
    page_size: int


class AlertResponse(BaseModel):
    id: int
    #: Null for system alerts.
    session_id: Optional[int] = None
    kind: str = "session"
    attacker_ip: Optional[str] = None
    node_id: Optional[int] = None
    severity: AttackSeverity
    title: str
    description: Optional[str]
    status: AlertStatusEnum
    assigned_to_id: Optional[int]
    assigned_to_name: Optional[str] = None
    auto_generated: bool
    mitre_tactics: Optional[List[str]]
    mitre_techniques: Optional[List[MitreTechnique]]
    notes: Optional[str] = None
    occurrences: int = 1
    last_seen_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: Optional[AlertStatusEnum] = None
    assigned_to_id: Optional[int] = None
    #: Clear the assignee. A null assigned_to_id cannot express this, because
    #: an omitted field and an explicit null look the same to the handler.
    unassign: bool = False
    notes: Optional[str] = Field(None, max_length=4000)


class AlertBulkUpdate(BaseModel):
    ids: List[int] = Field(..., min_length=1, max_length=200)
    status: AlertStatusEnum


class AlertListResponse(BaseModel):
    alerts: List[AlertResponse]
    total: int
    page: int
    page_size: int


class IndicatorOfCompromiseResponse(BaseModel):
    id: int
    session_id: int
    ioc_type: str
    value: str
    confidence: Optional[float]
    first_seen: datetime
    last_seen: datetime
    tags: Optional[List[str]]

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_sessions: int
    sessions_today: int
    active_sessions: int
    high_severity_alerts: int
    active_honeypots: int
    unique_threat_origins: int
    unique_countries: int
    attack_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    sessions_by_hour: Dict[str, int]
    top_attacker_ips: List[Dict[str, Any]]
    top_tools_detected: List[Dict[str, Any]]


class LiveSessionEvent(BaseModel):
    session_id: int
    session_uuid: str
    protocol: Optional[str] = None
    attacker_ip: str
    geo_country: Optional[str]
    geo_country_name: Optional[str] = None
    geo_lat: Optional[float]
    geo_lon: Optional[float]
    attack_category: Optional[str]
    severity: str
    timestamp: datetime


class AlertThresholdCreate(BaseModel):
    name: str
    min_severity: AttackSeverity = AttackSeverity.MEDIUM
    anomaly_score_threshold: float = 0.6
    email_enabled: bool = True
    webhook_enabled: bool = False


class AlertThresholdUpdate(BaseModel):
    name: Optional[str] = None
    min_severity: Optional[AttackSeverity] = None
    anomaly_score_threshold: Optional[float] = None
    email_enabled: Optional[bool] = None
    webhook_enabled: Optional[bool] = None
    is_active: Optional[bool] = None


class AlertThresholdResponse(BaseModel):
    id: int
    name: str
    min_severity: AttackSeverity
    anomaly_score_threshold: float
    email_enabled: bool
    webhook_enabled: bool
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class ExportFormat(str, Enum):
    JSON = "json"
    CEF = "cef"
    STIX = "stix"


class RefreshRequest(BaseModel):
    refresh_token: str


class ExportRequest(BaseModel):
    format: ExportFormat
    session_ids: Optional[List[int]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None


class WebhookConfig(BaseModel):
    url: str
    enabled: bool = True
    secret: Optional[str] = None


class EmailConfig(BaseModel):
    smtp_host: str
    smtp_port: int = 587
    smtp_user: str
    smtp_password: str
    from_email: str
    to_email: str


class SystemConfig(BaseModel):
    honeypot_mode: Optional[HoneypotMode] = None
    alert_email: Optional[EmailConfig] = None
    alert_webhook: Optional[WebhookConfig] = None
    rate_limit_per_minute: Optional[int] = None
