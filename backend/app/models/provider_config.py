"""
Provider Config Model

Stores API keys and configuration for third-party AI providers.
API keys are encrypted at rest.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.core.encryption import decrypt_data, encrypt_data


class ProviderConfig(Base):
    __tablename__ = "provider_configs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    provider_id = Column(String(50), nullable=False)  # e.g., 'openai', 'anthropic'
    _api_key_encrypted = Column("api_key", String, nullable=True)
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationship
    organization = relationship("Organization", backref="provider_configs")

    # Compound index for fast lookups
    __table_args__ = (
        Index('ix_org_provider', 'organization_id', 'provider_id', unique=True),
    )

    @property
    def api_key(self):
        return decrypt_data(self._api_key_encrypted)

    @api_key.setter
    def api_key(self, value):
        self._api_key_encrypted = encrypt_data(value)

    def to_dict(self, mask_key=True):
        data = {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "provider_id": self.provider_id,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        
        if mask_key and self.api_key:
            key_len = len(self.api_key)
            if key_len > 8:
                data["api_key"] = f"{self.api_key[:4]}...{self.api_key[-4:]}"
            else:
                data["api_key"] = "***"
        elif not mask_key:
            data["api_key"] = self.api_key
        else:
            data["api_key"] = None
            
        return data
