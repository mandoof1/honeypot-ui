from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Enum as SAEnum, JSON, Index
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
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


def _jsonb():
    """A JSONB column that still builds on SQLite.

    Production is PostgreSQL and these columns are JSONB: it stores parsed,
    which is what makes the GIN indexes and ``@>`` containment queries in
    migration 003 possible. SQLite has no JSONB type at all, so the model
    metadata could not be compiled against it — which broke every test in the
    suite that creates tables, since the fixtures run on SQLite.

    ``with_variant`` keeps one model definition serving both: JSONB where it
    exists, plain JSON where it does not.
    """
    return JSONB().with_variant(JSON(), "sqlite")


def _pg_enum(enum_cls):
    """A Postgres ENUM column that persists the member *value*, not its name.

    SQLAlchemy's default for ``Enum(SomeEnum)`` is to store ``member.name`` —
    so ``UserRole.ADMIN`` would be written as ``ADMIN``. Every migration in
    this project creates the Postgres type from the lowercase *values*
    (``'viewer', 'analyst', 'admin'``), and the server defaults, the JSON the
    API returns and the filters the dashboard sends are all lowercase too.

    The two never matched, which made the deployed application unusable:
    every INSERT was rejected by Postgres because ``ANALYST`` is not a label
    of type ``userrole``, so registration always failed with a 500 and the
    users table stayed empty; and any row written out-of-band raised
    ``LookupError: 'admin' is not among the defined enum values`` when the ORM
    read it back, so login 500'd as well.

    Pinning ``values_callable`` makes the ORM agree with the schema that is
    already deployed, so no data migration is needed.
    """
    return SAEnum(
        enum_cls,
        name=enum_cls.__name__.lower(),
        values_callable=lambda cls: [member.value for member in cls],
    )


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    name = Column(String(255), nullable=True)
    role = Column(_pg_enum(UserRole), default=UserRole.ANALYST, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True), nullable=True)

    # TOTP second factor. The secret is encrypted at rest with the same
    # AES-256-GCM used for captured commands; recovery codes are hashed,
    # because both are password-equivalent if the database is read.
    totp_secret_encrypted = Column(Text, nullable=True)
    totp_enabled = Column(Boolean, default=False, nullable=False)
    totp_recovery_hashes = Column(_jsonb(), nullable=True)
    totp_enrolled_at = Column(DateTime(timezone=True), nullable=True)

    alerts = relationship("Alert", back_populates="user", foreign_keys="Alert.assigned_to_id")
    audit_logs = relationship("AuditLog", back_populates="user")
    otp_verifications = relationship(
        "OTPVerification", back_populates="user", cascade="all, delete-orphan"
    )


class HoneypotNode(Base):
    __tablename__ = "honeypot_nodes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    protocol = Column(String(50), nullable=False)
    ip_address = Column(String(45), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    mode = Column(_pg_enum(HoneypotMode), default=HoneypotMode.ACTIVE, nullable=False)
    is_active = Column(Boolean, default=True)
    location_lat = Column(Float, nullable=True)
    location_lon = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)

    sessions = relationship(
        "HoneypotSession", back_populates="node", cascade="all, delete-orphan"
    )


class HoneypotSession(Base):
    __tablename__ = "honeypot_sessions"
    __table_args__ = (Index("ix_sessions_started_id", "started_at", "id"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_uuid = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True)
    ingest_digest = Column(String(64), nullable=True)
    capture_dropped = Column(_jsonb(), nullable=True)
    node_id = Column(Integer, ForeignKey("honeypot_nodes.id"), nullable=False)
    #: Protocol the session was captured on. The engine reports this, but it
    #: was previously discarded and every export claimed "ssh".
    protocol = Column(String(20), nullable=True)
    attacker_ip = Column(String(45), nullable=False, index=True)
    attacker_port = Column(Integer, nullable=True)
    geo_country = Column(String(3), nullable=True)
    geo_country_name = Column(String(100), nullable=True)
    geo_city = Column(String(100), nullable=True)
    geo_lat = Column(Float, nullable=True)
    geo_lon = Column(Float, nullable=True)
    status = Column(_pg_enum(SessionStatus), default=SessionStatus.ACTIVE, nullable=False)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # AI Analysis results
    attack_category = Column(_pg_enum(AttackCategory), nullable=True)
    attack_confidence = Column(Float, nullable=True)
    attacker_profile = Column(_pg_enum(AttackerProfile), nullable=True)
    anomaly_score = Column(Float, nullable=True)
    is_anomalous = Column(Boolean, default=False)

    # NLP results
    detected_tools = Column(_jsonb(), nullable=True)
    detected_intents = Column(_jsonb(), nullable=True)
    command_summary = Column(Text, nullable=True)
    command_count = Column(Integer, default=0, nullable=False)

    # MITRE ATT&CK
    #: List of tactic id strings, e.g. ["TA0001"].
    mitre_tactics = Column(_jsonb(), nullable=True)
    #: List of technique objects, e.g. [{"id": "T1110", "name": "Brute Force"}].
    mitre_techniques = Column(_jsonb(), nullable=True)

    # Provenance of the verdict above. The classifier already reports whether
    # it is running on a trained model or on synthetic bootstrap data; that
    # answer used to be discarded at the ingest boundary, so the UI could not
    # tell an analyst how much the confidence figure was worth.
    model_source = Column(String(32), nullable=True)

    # Behavioural cluster, from the unsupervised model that runs beside the
    # rule-based profile. Null until enough sessions exist to fit.
    cluster_id = Column(Integer, nullable=True, index=True)
    cluster_distance = Column(Float, nullable=True)
    cluster_is_outlier = Column(Boolean, nullable=True)

    # Raw data (encrypted)
    raw_commands_encrypted = Column(Text, nullable=True)
    raw_payloads_encrypted = Column(Text, nullable=True)
    #: Command/output pairs in order, as encrypted JSON. Separate from
    #: raw_commands_encrypted, which stays a newline-joined command list
    #: because the enrichment and clustering paths read it that way.
    transcript_encrypted = Column(Text, nullable=True)
    #: Username/password pairs the attacker tried, as encrypted JSON. These
    #: are credentials in active use against the internet and are the single
    #: most sensitive thing the honeypot holds, so they are never stored in
    #: the clear and never returned by a list endpoint.
    credentials_encrypted = Column(Text, nullable=True)
    network_packets_summary = Column(_jsonb(), nullable=True)
    #: Retrieval and execution events the emulator observed: the C2 URLs a
    #: dropper reached for and the payloads it tried to run.
    network_events = Column(_jsonb(), nullable=True)

    #: Which research organisation this address belongs to, when it belongs to
    #: one. Censys, Shodan and Shadowserver scan every public address
    #: continuously; counting their probes as attacks makes every figure the
    #: project reports incomparable with anything.
    scanner_operator = Column(String(50), nullable=True, index=True)

    #: Full class distribution, not just the winning label and its probability.
    #: A session at 0.34/0.33/0.33 and one at 0.98/0.01/0.01 are different
    #: findings and were being stored identically.
    class_probabilities = Column(_jsonb(), nullable=True)

    #: Wall-clock analysis time. NFR-2 sets a 200 ms budget; it was measured
    #: per session, logged when exceeded, and then discarded, so the
    #: requirement could never be evidenced over real traffic.
    analysis_ms = Column(Float, nullable=True)
    keystroke_count = Column(Integer, default=0, nullable=False, server_default="0")

    # Uploaded files
    uploaded_files = Column(_jsonb(), nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    node = relationship("HoneypotNode", back_populates="sessions")
    alerts = relationship(
        "Alert", back_populates="session", cascade="all, delete-orphan"
    )
    iocs = relationship(
        "IndicatorOfCompromise",
        back_populates="session",
        cascade="all, delete-orphan",
    )


class IndicatorOfCompromise(Base):
    __tablename__ = "indicators_of_compromise"
    __table_args__ = (Index("ix_ioc_session_type_value", "session_id", "ioc_type", "value"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("honeypot_sessions.id"), nullable=False)
    ioc_type = Column(String(50), nullable=False)
    value = Column(String(500), nullable=False, index=True)
    confidence = Column(Float, nullable=True)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    tags = Column(_jsonb(), nullable=True)

    session = relationship("HoneypotSession", back_populates="iocs")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("honeypot_sessions.id"), nullable=False)
    severity = Column(_pg_enum(AttackSeverity), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(_pg_enum(AlertStatus), default=AlertStatus.NEW, nullable=False)
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    auto_generated = Column(Boolean, default=True)
    mitre_tactics = Column(_jsonb(), nullable=True)
    mitre_techniques = Column(_jsonb(), nullable=True)
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
    details = Column(_jsonb(), nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="audit_logs")


class AlertThreshold(Base):
    __tablename__ = "alert_thresholds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    min_severity = Column(_pg_enum(AttackSeverity), default=AttackSeverity.MEDIUM)
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
    # HMAC-SHA256 hex digest of the code, never the code itself.
    otp_code = Column(String(64), nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    purpose = Column(String(50), nullable=False, default="email_verification")
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(String(45), nullable=True)

    user = relationship("User", back_populates="otp_verifications")
