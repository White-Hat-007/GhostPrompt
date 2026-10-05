"""
Audit Log Model

Comprehensive audit trail for compliance and forensics.
Every significant action is logged immutably.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, DateTime, ForeignKey, Text, JSON, Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Actor
    user_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    user_email = Column(String(255), nullable=True)
    api_key_prefix = Column(String(12), nullable=True)
    source_ip = Column(String(45), nullable=True)

    # Action
    action = Column(String(100), nullable=False, index=True)
    # Actions: user.login, user.logout, user.create, user.update, user.delete,
    #          apikey.create, apikey.revoke, policy.create, policy.update,
    #          scan.block, scan.flag, org.update, settings.change, export.create

    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(255), nullable=True)

    # Details
    description = Column(Text, nullable=True)
    changes = Column(JSON, default=dict)
    # Format: {"field": {"old": "...", "new": "..."}}

    event_metadata = Column(JSON, default=dict)
    # Additional context: user agent, geo, etc.

    # Status
    status = Column(String(20), default="success")
    # Status: success, failure, error

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    organization = relationship("Organization", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_org_created", "organization_id", "created_at"),
        Index("ix_audit_logs_org_action", "organization_id", "action"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog(action='{self.action}', user='{self.user_email}')>"
