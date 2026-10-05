"""
Scan Event Model

Records every prompt/response inspection with threat analysis results.
This is the core telemetry table for the AI Firewall.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Boolean, Integer, Float, DateTime,
    ForeignKey, Text, JSON, Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Request metadata
    request_id = Column(String(64), unique=True, nullable=False, index=True)
    api_key_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    source_ip = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)

    # AI model info
    model_provider = Column(String(50), nullable=True)  # openai, anthropic, google, ollama
    model_name = Column(String(100), nullable=True)  # gpt-4, claude-3, etc.
    model_endpoint = Column(String(512), nullable=True)

    # Scan direction
    scan_type = Column(String(20), nullable=False, default="prompt")  # prompt, output, rag, agent

    # Content (stored encrypted in production)
    prompt_text = Column(Text, nullable=True)
    prompt_length = Column(Integer, nullable=True)
    output_text = Column(Text, nullable=True)
    output_length = Column(Integer, nullable=True)

    # Threat analysis results
    threat_level = Column(String(20), default="safe")  # safe, low, medium, high, critical
    threat_score = Column(Float, default=0.0)  # 0.0 - 1.0
    threat_categories = Column(JSON, default=list)  # List of detected threat types

    # Detection details
    detections = Column(JSON, default=list)
    # Each detection: {
    #   "detector": "prompt_injection",
    #   "confidence": 0.95,
    #   "matched_pattern": "...",
    #   "description": "..."
    # }

    # Action taken
    action = Column(String(20), default="allowed")  # allowed, blocked, sanitized, flagged
    action_reason = Column(Text, nullable=True)
    
    # Optional metadata (like attacker profiling)
    event_metadata = Column(JSON, default=dict)

    # Policy
    policy_id = Column(UUID(as_uuid=True), nullable=True)
    policy_rules_triggered = Column(JSON, default=list)

    # Performance
    scan_duration_ms = Column(Float, nullable=True)
    total_latency_ms = Column(Float, nullable=True)

    # Token usage
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    total_tokens = Column(Integer, nullable=True)

    # Status
    is_blocked = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    organization = relationship("Organization", back_populates="scan_events")

    # Composite indexes for analytics queries
    __table_args__ = (
        Index("ix_scan_events_org_created", "organization_id", "created_at"),
        Index("ix_scan_events_org_threat", "organization_id", "threat_level"),
        Index("ix_scan_events_org_action", "organization_id", "action"),
        Index("ix_scan_events_org_model", "organization_id", "model_provider", "model_name"),
    )

    def __repr__(self) -> str:
        return f"<ScanEvent(id={self.id}, threat={self.threat_level}, action={self.action})>"
