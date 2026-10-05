"""
API Key Model

Scoped API keys with usage tracking and rate limit configuration.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Key details
    name = Column(String(255), nullable=False)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    key_prefix = Column(String(15), nullable=False)  # First 8 chars for identification
    environment = Column(String(50), default="PRODUCTION") # DEV, QA, STAGING, PRODUCTION, etc.

    # Permissions
    scopes = Column(JSON, default=["scan"])  # scan, admin, read, write
    allowed_models = Column(JSON, default=list)
    allowed_ips = Column(JSON, default=list)

    # Rate limiting
    rate_limit_per_minute = Column(Integer, default=60)
    rate_limit_per_day = Column(Integer, default=10000)

    # Usage
    total_requests = Column(Integer, default=0)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    last_used_ip = Column(String(45), nullable=True)

    # Status
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    organization = relationship("Organization", back_populates="api_keys")

    def __repr__(self) -> str:
        return f"<APIKey(id={self.id}, prefix='{self.key_prefix}...')>"
