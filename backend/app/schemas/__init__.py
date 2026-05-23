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


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    sub: str
    exp: datetime
    role: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: Optional[str] = None
    role: UserRole = UserRole.ANALYST


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    name: Optional[str]
    role: UserRole
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6)
    purpose: str = "email_verification"


class OTPResendRequest(BaseModel):
    email: EmailStr
    purpose: str = "email_verification"


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6)
    new_password: str = Field(..., min_length=8)


class RegisterResponse(BaseModel):
    message: str
    email: str
    requires_verification: bool


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


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

    class Config:
        from_attributes = True


class GeoInfo(BaseModel):
    country: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None


class HoneypotSessionResponse(BaseModel):
    id: int
    session_uuid: str
    node_id: int
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
    detected_tools: Optional[List[str]]
    detected_intents: Optional[List[str]]
    mitre_tactics: Optional[List[str]]
    mitre_techniques: Optional[List[str]]
    uploaded_files: Optional[List[str]]
    created_at: datetime

    class Config:
        from_attributes = True

    @classmethod
    def from_orm(cls, obj):
        return cls(
            id=obj.id,
            session_uuid=obj.session_uuid,
            node_id=obj.node_id,
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
            detected_tools=obj.detected_tools or [],
            detected_intents=obj.detected_intents or [],
            mitre_tactics=obj.mitre_tactics or [],
            mitre_techniques=obj.mitre_techniques or [],
            uploaded_files=obj.uploaded_files or [],
            created_at=obj.created_at,
        )


class SessionListResponse(BaseModel):
    sessions: List[HoneypotSessionResponse]
    total: int
    page: int
    page_size: int


class SessionFilter(BaseModel):
    status: Optional[SessionStatus] = None
    attack_category: Optional[AttackCategory] = None
    attacker_profile: Optional[AttackerProfile] = None
    severity: Optional[AttackSeverity] = None
    country: Optional[str] = None
    ip_address: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    is_anomalous: Optional[bool] = None
    search: Optional[str] = None


class AlertResponse(BaseModel):
    id: int
    session_id: int
    severity: AttackSeverity
    title: str
    description: Optional[str]
    status: AlertStatusEnum
    assigned_to_id: Optional[int]
    auto_generated: bool
    mitre_tactics: Optional[List[str]]
    mitre_techniques: Optional[List[str]]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: Optional[AlertStatusEnum] = None
    assigned_to_id: Optional[int] = None


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
    session_uuid: str
    attacker_ip: str
    geo_country: Optional[str]
    geo_lat: Optional[float]
    geo_lon: Optional[float]
    attack_category: Optional[str]
    severity: str
    timestamp: datetime


class AlertThresholdCreate(BaseModel):
    name: str
    min_severity: AttackSeverity = AttackSeverity.MEDIUM
    anomaly_score_threshold: float = 0.7
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
