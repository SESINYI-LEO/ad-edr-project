"""ORM models: the twelve classes of the Chapter 3 class diagram plus supporting tables."""
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Table, Text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Naive UTC timestamp, used consistently across PostgreSQL and SQLite."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


alert_events = Table(
    "alert_events", Base.metadata,
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", ForeignKey("telemetry_events.id", ondelete="CASCADE"), primary_key=True),
)


class ADIdentity(Base):
    """Cached Active Directory identity (SID, groups, department, privilege level)."""
    __tablename__ = "ad_identities"
    id: Mapped[int] = mapped_column(primary_key=True)
    sid: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    sam_account_name: Mapped[str] = mapped_column(String(128), index=True)
    display_name: Mapped[str | None] = mapped_column(String(256))
    department: Mapped[str | None] = mapped_column(String(128))
    groups: Mapped[list] = mapped_column(JSON, default=list)
    privilege_level: Mapped[str] = mapped_column(String(16), default="standard")  # standard|elevated|admin
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_synced: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SystemUser(Base):
    """A person who uses the dashboard (Security Administrator or Security Analyst)."""
    __tablename__ = "system_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(128))
    password_hash: Mapped[str | None] = mapped_column(String(256))
    auth_source: Mapped[str] = mapped_column(String(8), default="local")  # local|ad
    role: Mapped[str] = mapped_column(String(16))                        # admin|analyst
    status: Mapped[str] = mapped_column(String(16), default="active")    # active|disabled
    identity_id: Mapped[int | None] = mapped_column(ForeignKey("ad_identities.id"))
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    identity = relationship("ADIdentity")


class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    os_version: Mapped[str | None] = mapped_column(String(128))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1 (low) .. 5 (crown jewels)
    status: Mapped[str] = mapped_column(String(16), default="online")  # online|isolated (offline is derived)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    api_key_hash: Mapped[str] = mapped_column(String(64))
    registered_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    identity_id: Mapped[int | None] = mapped_column(ForeignKey("ad_identities.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    process_name: Mapped[str | None] = mapped_column(String(260))
    parent_process: Mapped[str | None] = mapped_column(String(260))
    command_line: Mapped[str | None] = mapped_column(Text)
    user_name: Mapped[str | None] = mapped_column(String(256))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    attribution: Mapped[str | None] = mapped_column(String(24))  # resolved|cached|system|unattributed|directory_error
    identity = relationship("ADIdentity")


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    rule_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(10))
    attack_technique_id: Mapped[str] = mapped_column(String(16))
    attack_tactic: Mapped[str] = mapped_column(String(48))
    confidence: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("system_users.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.rule_id"), index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    identity_id: Mapped[int | None] = mapped_column(ForeignKey("ad_identities.id"))
    user_name: Mapped[str | None] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(10))
    confidence: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="new")  # new|acknowledged|closed
    summary: Mapped[str] = mapped_column(String(400))
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    first_event_time: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    rule = relationship("DetectionRule")
    endpoint = relationship("Endpoint")
    identity = relationship("ADIdentity")
    events = relationship("TelemetryEvent", secondary=alert_events, order_by="TelemetryEvent.timestamp")
    ticket = relationship("Ticket", back_populates="alert", uselist=False)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|contained|closed
    notes: Mapped[list] = mapped_column(JSON, default=list)
    owner_id: Mapped[int] = mapped_column(ForeignKey("system_users.id"))
    opened_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime)
    owner = relationship("SystemUser")
    tickets = relationship("Ticket", back_populates="incident")
    actions = relationship("ResponseAction", back_populates="incident")


class Ticket(Base):
    __tablename__ = "tickets"
    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), unique=True)
    priority: Mapped[str] = mapped_column(String(10), index=True)  # Critical|High|Medium|Low
    priority_score: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(24), default="New", index=True)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("system_users.id"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    alert = relationship("Alert", back_populates="ticket")
    assignee = relationship("SystemUser")
    incident = relationship("Incident", back_populates="tickets")


class DeviceCredential(Base):
    """Public key of an enrolled authenticator device. The biometric never leaves the device."""
    __tablename__ = "device_credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("system_users.id"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    public_key_pem: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class BiometricVerification(Base):
    __tablename__ = "biometric_verifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("system_users.id"), index=True)
    purpose: Mapped[str] = mapped_column(String(160))
    nonce: Mapped[str] = mapped_column(String(64))        # carried in the QR code (non-secret transaction value)
    challenge: Mapped[str] = mapped_column(String(64))    # revealed to the device only after a valid scan
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|qr_validated|verified|failed|expired
    device_id: Mapped[int | None] = mapped_column(ForeignKey("device_credentials.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime)


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(32))
    target: Mapped[str | None] = mapped_column(String(128))
    requested_by: Mapped[int] = mapped_column(ForeignKey("system_users.id"))
    verification_id: Mapped[int] = mapped_column(ForeignKey("biometric_verifications.id"), unique=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime)
    outcome: Mapped[str | None] = mapped_column(String(200))
    incident = relationship("Incident", back_populates="actions")


class AuditLog(Base):
    """Append-only, hash-chained audit trail."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer)
    actor: Mapped[str] = mapped_column(String(128))
    action_type: Mapped[str] = mapped_column(String(48), index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    outcome: Mapped[str] = mapped_column(String(16))  # success|denied|failure
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


class Backup(Base):
    __tablename__ = "backups"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[int] = mapped_column(Integer)
    location: Mapped[str] = mapped_column(String(400))
    checksum: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="complete")  # complete|restored|corrupt
