from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, JSON, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
import enum
import uuid
from app.core.database import Base


class UserRole(str, enum.Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


class HoneypotMode(str, enum.Enum):
    ACTIVE = "active"
    PASSIVE = "passive"


class SessionStatus(str, enum.Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    TERMINATED = "terminated"


class AttackSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCategory(str, enum.Enum):
    BENIGN = "benign"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    EXFILTRATION = "exfiltration"


class AttackerProfile(str, enum.Enum):
    SCRIPT_KIDDIE = "script_kiddie"
    AUTOMATED_BOT = "automated_bot"
    SKILLED_ATTACKER = "skilled_attacker"
    APT = "apt"
    UNKNOWN = "unknown"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    name = Column(String(255), nullable=True)
    role = Column(SAEnum(UserRole), default=UserRole.ANALYST, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True), nullable=True)

    alerts = relationship("Alert", back_populates="user", foreign_keys="Alert.assigned_to_id")
    audit_logs = relationship("AuditLog", back_populates="user")
    otp_verifications = relationship("OTPVerification", back_populates="user")


class HoneypotNode(Base):
    __tablename__ = "honeypot_nodes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    protocol = Column(String(50), nullable=False)
    ip_address = Column(String(45), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    mode = Column(SAEnum(HoneypotMode), default=HoneypotMode.ACTIVE, nullable=False)
    is_active = Column(Boolean, default=True)
    location_lat = Column(Float, nullable=True)
    location_lon = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)

    sessions = relationship("HoneypotSession", back_populates="node")


class HoneypotSession(Base):
    __tablename__ = "honeypot_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_uuid = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True)
    node_id = Column(Integer, ForeignKey("honeypot_nodes.id"), nullable=False)
    attacker_ip = Column(String(45), nullable=False, index=True)
    attacker_port = Column(Integer, nullable=True)
    geo_country = Column(String(3), nullable=True)
    geo_country_name = Column(String(100), nullable=True)
    geo_city = Column(String(100), nullable=True)
    geo_lat = Column(Float, nullable=True)
    geo_lon = Column(Float, nullable=True)
    status = Column(SAEnum(SessionStatus), default=SessionStatus.ACTIVE, nullable=False)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # AI Analysis results
    attack_category = Column(SAEnum(AttackCategory), nullable=True)
    attack_confidence = Column(Float, nullable=True)
    attacker_profile = Column(SAEnum(AttackerProfile), nullable=True)
    anomaly_score = Column(Float, nullable=True)
    is_anomalous = Column(Boolean, default=False)

    # NLP results
    detected_tools = Column(JSON, nullable=True)
    detected_intents = Column(JSON, nullable=True)
    command_summary = Column(Text, nullable=True)

    # MITRE ATT&CK
    mitre_tactics = Column(JSON, nullable=True)
    mitre_techniques = Column(JSON, nullable=True)

    # Raw data (encrypted)
    raw_commands_encrypted = Column(Text, nullable=True)
    raw_payloads_encrypted = Column(Text, nullable=True)
    network_packets_summary = Column(JSON, nullable=True)

    # Uploaded files
    uploaded_files = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    node = relationship("HoneypotNode", back_populates="sessions")
    alerts = relationship("Alert", back_populates="session")
    iocs = relationship("IndicatorOfCompromise", back_populates="session")


class IndicatorOfCompromise(Base):
    __tablename__ = "indicators_of_compromise"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("honeypot_sessions.id"), nullable=False)
    ioc_type = Column(String(50), nullable=False)
    value = Column(String(500), nullable=False, index=True)
    confidence = Column(Float, nullable=True)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    tags = Column(JSON, nullable=True)

    session = relationship("HoneypotSession", back_populates="iocs")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("honeypot_sessions.id"), nullable=False)
    severity = Column(SAEnum(AttackSeverity), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(SAEnum(AlertStatus), default=AlertStatus.NEW, nullable=False)
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    auto_generated = Column(Boolean, default=True)
    mitre_tactics = Column(JSON, nullable=True)
    mitre_techniques = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    session = relationship("HoneypotSession", back_populates="alerts")
    user = relationship("User", back_populates="alerts", foreign_keys=[assigned_to_id])


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="audit_logs")


class AlertThreshold(Base):
    __tablename__ = "alert_thresholds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    min_severity = Column(SAEnum(AttackSeverity), default=AttackSeverity.MEDIUM)
    anomaly_score_threshold = Column(Float, default=0.7)
    email_enabled = Column(Boolean, default=True)
    webhook_enabled = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class OTPVerification(Base):
    __tablename__ = "otp_verifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    otp_code = Column(String(6), nullable=False)
    purpose = Column(String(50), nullable=False, default="email_verification")
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(String(45), nullable=True)

    user = relationship("User", back_populates="otp_verifications")
