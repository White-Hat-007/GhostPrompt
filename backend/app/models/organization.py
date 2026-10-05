"""
Organization Model

Multi-tenant organization with settings, quotas, and isolation.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)

    # Subscription & Billing
    plan = Column(String(50), default="starter")  # starter, pro, enterprise
    stripe_customer_id = Column(String(255), nullable=True)
    billing_email = Column(String(255), nullable=True)
    subscription_status = Column(String(50), default="active") # active, past_due, canceled
    subscription_interval = Column(String(20), nullable=True) # monthly, quarterly, biannual, yearly
    subscription_end_date = Column(DateTime(timezone=True), nullable=True)

    # Quotas
    max_requests_per_day = Column(Integer, default=1000)
    max_users = Column(Integer, default=5)
    max_api_keys = Column(Integer, default=10)

    # Settings
    settings = Column(JSON, default=dict)
    firewall_mode = Column(String(20), default="enforce")
    threat_score_threshold = Column(Integer, default=70)

    # Security
    allowed_models = Column(JSON, default=list)
    blocked_domains = Column(JSON, default=list)
    ip_allowlist = Column(JSON, default=list)

    # Service Ownership (cortex.io pattern)
    service_owner_email = Column(String(255), nullable=True)
    service_owner_team = Column(String(255), nullable=True)
    escalation_contacts = Column(JSON, default=list)  # [{email, role, priority}]
    sla_tier = Column(String(50), default="standard")  # standard, premium, enterprise
    oncall_integration = Column(String(255), nullable=True)  # PagerDuty/OpsGenie schedule ID

    # Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    suspended_at = Column(DateTime(timezone=True), nullable=True)
    suspension_reason = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="organization", cascade="all, delete-orphan")
    scan_events = relationship("ScanEvent", back_populates="organization", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Organization(id={self.id}, name='{self.name}', plan='{self.plan}')>"
