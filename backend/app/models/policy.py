"""
Policy & Policy Rule Models

Configurable security policies with rule-based threat detection.
Organizations can create custom policies to enforce specific security rules.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Boolean, Integer, Float, DateTime,
    ForeignKey, Text, JSON,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base


class Policy(Base):
    __tablename__ = "policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Policy type
    policy_type = Column(String(50), default="custom")
    # Types: default, strict, permissive, custom, compliance

    # Scope
    applies_to = Column(JSON, default=["all"])
    # Can target: all, specific models, endpoints, users

    # Priority (higher = evaluated first)
    priority = Column(Integer, default=100)

    # Status
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)

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
    organization = relationship("Organization", back_populates="policies")
    rules = relationship("PolicyRule", back_populates="policy", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Policy(id={self.id}, name='{self.name}', type='{self.policy_type}')>"


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id = Column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Rule configuration
    rule_type = Column(String(50), nullable=False)
    # Types: prompt_injection, jailbreak, pii_detection, keyword_block,
    #        regex_match, output_filter, token_limit, rate_limit,
    #        model_restriction, content_policy, custom

    # Detection settings
    detector = Column(String(100), nullable=False)
    # Which detector to use: ml_classifier, pattern_matcher, regex, semantic

    threshold = Column(Float, default=0.7)
    # Confidence threshold for ML-based detections

    # Rule parameters (detector-specific)
    parameters = Column(JSON, default=dict)
    # Examples:
    # {"patterns": ["ignore previous", "system prompt"]}
    # {"pii_types": ["email", "ssn", "credit_card"]}
    # {"max_tokens": 4096}
    # {"blocked_keywords": ["hack", "exploit"]}

    # Action on match
    action = Column(String(20), default="block")
    # Actions: block, flag, sanitize, log, alert

    # Severity
    severity = Column(String(20), default="medium")
    # Severity: low, medium, high, critical

    # Status
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=100)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    policy = relationship("Policy", back_populates="rules")

    def __repr__(self) -> str:
        return f"<PolicyRule(id={self.id}, type='{self.rule_type}', action='{self.action}')>"
