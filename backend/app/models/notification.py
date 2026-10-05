"""
In-App User Notifications — Database Model

Lightweight notification system for security-critical events that
users need to see (role changes, permission downgrades, etc).

These are NOT audit log entries (admin-only). These are user-facing
alerts that appear in the notification bell on the dashboard.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from app.core.database import Base


class UserNotification(Base):
    """A notification visible to a specific user."""
    __tablename__ = "user_notifications"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    organization_id = Column(PG_UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True)

    # Notification content
    title = Column(String(256), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="info")  # info, warning, critical
    category = Column(String(64), nullable=False, default="system")  # system, role_change, security

    # State
    is_read = Column(Boolean, default=False, nullable=False)
    dismissed = Column(Boolean, default=False, nullable=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    read_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_user_notification_user", "user_id"),
        Index("ix_user_notification_unread", "user_id", "is_read"),
    )
