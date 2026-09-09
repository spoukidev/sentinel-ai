from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, now, uid


class Identity:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class Tenant:
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)


class Organization(Identity, Base):
    __tablename__ = "organizations"
    name: Mapped[str] = mapped_column(String(120))


class User(Identity, Base):
    __tablename__ = "users"
    email: Mapped[str] = mapped_column(String(254), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(Text)


class OrganizationMember(Identity, Tenant, Base):
    __tablename__ = "organization_members"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), unique=True)
    role: Mapped[str] = mapped_column(String(20))


class AuthSession(Identity, Base):
    __tablename__ = "sessions"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Asset(Identity, Tenant, Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("organization_id", "hostname"),)
    hostname: Mapped[str] = mapped_column(String(120))
    ip_address: Mapped[str] = mapped_column(String(45))
    operating_system: Mapped[str] = mapped_column(String(80))
    asset_type: Mapped[str] = mapped_column(String(30))
    owner: Mapped[str] = mapped_column(String(120))
    department: Mapped[str] = mapped_column(String(80))
    criticality: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="active")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class SecurityEvent(Identity, Tenant, Base):
    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint("organization_id", "fingerprint"),
        Index("ix_event_window", "organization_id", "timestamp", "hostname"),
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    source: Mapped[str] = mapped_column(String(30))
    category: Mapped[str] = mapped_column(String(40))
    event_type: Mapped[str] = mapped_column(String(80))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    username: Mapped[str] = mapped_column(String(120))
    hostname: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(80))
    outcome: Mapped[str] = mapped_column(String(30))
    raw_event: Mapped[str] = mapped_column(Text)
    parsed_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    fingerprint: Mapped[str] = mapped_column(String(64))


class DetectionRule(Identity, Tenant, Base):
    __tablename__ = "detection_rules"
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(String(30))
    conditions: Mapped[list] = mapped_column(JSON)
    threshold: Mapped[int] = mapped_column(Integer)
    window_seconds: Mapped[int] = mapped_column(Integer)
    tactic: Mapped[str] = mapped_column(String(80))
    technique: Mapped[str] = mapped_column(String(20))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    recommended_response: Mapped[str] = mapped_column(Text)


class Alert(Identity, Tenant, Base):
    __tablename__ = "alerts"
    __table_args__ = (UniqueConstraint("organization_id", "dedup_key"),)
    title: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[int] = mapped_column(Integer, default=80)
    status: Mapped[str] = mapped_column(String(30), default="new")
    source: Mapped[str] = mapped_column(String(30))
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"))
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    username: Mapped[str] = mapped_column(String(120))
    hostname: Mapped[str] = mapped_column(String(120))
    tactic: Mapped[str] = mapped_column(String(80))
    technique: Mapped[str] = mapped_column(String(20))
    risk_score: Mapped[int] = mapped_column(Integer)
    assignee: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    dedup_key: Mapped[str] = mapped_column(String(64))
    false_positive_reason: Mapped[str] = mapped_column(Text, default="")


class AlertEvidence(Identity, Base):
    __tablename__ = "alert_evidence"
    __table_args__ = (UniqueConstraint("alert_id", "event_id"),)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"))
    event_id: Mapped[str] = mapped_column(ForeignKey("security_events.id"))


class AlertNote(Identity, Base):
    __tablename__ = "alert_notes"
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)


class AlertStatusHistory(Identity, Base):
    __tablename__ = "alert_status_history"
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    previous: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30))


class AuditLog(Identity, Tenant, Base):
    __tablename__ = "audit_logs"
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(80))
    target_type: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[str] = mapped_column(String(120))
    safe_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
