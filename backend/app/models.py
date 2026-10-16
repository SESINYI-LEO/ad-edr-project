"""ORM models - the 12 classes from the Chapter 3 class diagram (+ AgentCommand for response delivery)."""
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, Enum, Float, ForeignKey, Integer, String, Table, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _enum(e):
    return Enum(e, native_enum=False, length=30, values_callable=lambda x: [m.value for m in x])


class Role(str, enum.Enum):
    ADMINISTRATOR = "administrator"
    ANALYST = "analyst"


class Criticality(str, enum.Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"


class EndpointStatus(str, enum.Enum):
    ONLINE = "online"; OFFLINE = "offline"; ISOLATED = "isolated"


class Severity(str, enum.Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"


class TicketStatus(str, enum.Enum):
    NEW = "new"
    PRIORITISED = "prioritised"
    UNDER_INVESTIGATION = "under_investigation"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"; INVESTIGATING = "investigating"; CONTAINED = "contained"; RESOLVED = "resolved"; CLOSED = "closed"


class AuthStatus(str, enum.Enum):
    PENDING = "pending"; VERIFIED = "verified"; FAILED = "failed"; EXPIRED = "expired"


class BackupStatus(str, enum.Enum):
    UNVERIFIED = "unverified"; VERIFIED = "verified"; CORRUPT = "corrupt"


def _pk():
    return mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


class SystemUser(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = _pk()
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), default="")
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(_enum(Role), default=Role.ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    biometric_template_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)  # protected reference, never raw data
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[uuid.UUID] = _pk()
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality: Mapped[Criticality] = mapped_column(_enum(Criticality), default=Criticality.MEDIUM)
    status: Mapped[EndpointStatus] = mapped_column(_enum(EndpointStatus), default=EndpointStatus.ONLINE)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ADUser(Base):
    __tablename__ = "ad_users"
    id: Mapped[uuid.UUID] = _pk()
    sid: Mapped[str] = mapped_column(String(184), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(150), index=True)
    department: Mapped[str | None] = mapped_column(String(150), nullable=True)
    groups: Mapped[list] = mapped_column(JSON, default=list)
    privilege: Mapped[str] = mapped_column(String(30), default="standard")  # standard|elevated|admin|domain_admin
    last_synced: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"
    id: Mapped[uuid.UUID] = _pk()
    endpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("endpoints.id"), index=True)
    ad_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("ad_users.id"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(30), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    registry_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    remote_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remote_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_sid: Mapped[str | None] = mapped_column(String(184), nullable=True)
    dedupe_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    raw_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    endpoint = relationship("Endpoint")
    ad_user = relationship("ADUser")


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[uuid.UUID] = _pk()
    name: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_type: Mapped[str] = mapped_column(String(30))
    severity: Mapped[Severity] = mapped_column(_enum(Severity))
    mitre_technique: Mapped[str | None] = mapped_column(String(20), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    logic: Mapped[dict] = mapped_column(JSON)
    threshold_count: Mapped[int] = mapped_column(Integer, default=1)      # >1 => correlation rule
    window_seconds: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


alert_events = Table(
    "alert_events", Base.metadata,
    Column("alert_id", Uuid(as_uuid=True), ForeignKey("alerts.id"), primary_key=True),
    Column("event_id", Uuid(as_uuid=True), ForeignKey("telemetry_events.id"), primary_key=True),
)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[uuid.UUID] = _pk()
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detection_rules.id"), index=True)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("endpoints.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(_enum(Severity))
    mitre_technique: Mapped[str | None] = mapped_column(String(20), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    rule = relationship("DetectionRule")
    endpoint = relationship("Endpoint")
    events = relationship("TelemetryEvent", secondary=alert_events)
    ticket = relationship("Ticket", back_populates="alert", uselist=False)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[uuid.UUID] = _pk()
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[IncidentStatus] = mapped_column(_enum(IncidentStatus), default=IncidentStatus.OPEN)
    notes: Mapped[str] = mapped_column(Text, default="")
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("endpoints.id"), nullable=True)
    opened_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    endpoint = relationship("Endpoint")
    tickets = relationship("Ticket", back_populates="incident")
    reports = relationship("IncidentReport", back_populates="incident")


class Ticket(Base):
    __tablename__ = "tickets"
    id: Mapped[uuid.UUID] = _pk()
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id"), unique=True)  # alert -> 0..1 ticket
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    priority_score: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[Severity] = mapped_column(_enum(Severity), default=Severity.LOW)
    status: Mapped[TicketStatus] = mapped_column(_enum(TicketStatus), default=TicketStatus.NEW)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    alert = relationship("Alert", back_populates="ticket")
    incident = relationship("Incident", back_populates="tickets")
    assignee = relationship("SystemUser")


class IncidentReport(Base):
    __tablename__ = "incident_reports"
    id: Mapped[uuid.UUID] = _pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), index=True)
    generated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    incident = relationship("Incident", back_populates="reports")


class AuthTransaction(Base):
    __tablename__ = "auth_transactions"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    purpose: Mapped[str] = mapped_column(String(60))
    status: Mapped[AuthStatus] = mapped_column(_enum(AuthStatus), default=AuthStatus.PENDING)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditEntry(Base):
    __tablename__ = "audit_entries"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(150), nullable=True)
    action: Mapped[str] = mapped_column(String(120), index=True)
    outcome: Mapped[str] = mapped_column(String(20), default="success")
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class Backup(Base):
    __tablename__ = "backups"
    id: Mapped[uuid.UUID] = _pk()
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    filename: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[BackupStatus] = mapped_column(_enum(BackupStatus), default=BackupStatus.UNVERIFIED)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AgentCommand(Base):
    """Approved response action queued for delivery to an endpoint agent."""
    __tablename__ = "agent_commands"
    id: Mapped[uuid.UUID] = _pk()
    endpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("endpoints.id"), index=True)
    action: Mapped[str] = mapped_column(String(60))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|done|failed
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
