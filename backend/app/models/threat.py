"""
Threat Intelligence Models

Attack signatures, semantic fingerprints, and threat events
for the threat intelligence engine.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Boolean, Integer, Float, DateTime,
    Text, JSON, Index,
)
from sqlalchemy.dialects.postgresql import UUID
from pgvector.sqlalchemy import Vector
from app.core.database import Base


class ThreatSignature(Base):
    """Known attack patterns and signatures for detection."""
    __tablename__ = "threat_signatures"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Signature identity
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=False, index=True)
    # Categories: prompt_injection, jailbreak, encoded_payload,
    #             obfuscation, rag_poisoning, agent_hijack,
    #             data_exfiltration, model_extraction

    # Detection method
    detection_type = Column(String(50), nullable=False)
    # Types: pattern, regex, semantic, ml_classifier

    # Pattern data
    patterns = Column(JSON, default=list)
    # List of pattern strings or regex patterns

    regex_patterns = Column(JSON, default=list)
    # Compiled regex patterns

    # Semantic embedding for similarity matching
    embedding_text = Column(Text, nullable=True)
    # The text used to generate the semantic embedding
    
    embedding = Column(Vector(384), nullable=True)
    # 384-dimensional vector for all-MiniLM-L6-v2 embeddings

    # Metadata
    severity = Column(String(20), default="medium")
    confidence_weight = Column(Float, default=1.0)
    false_positive_rate = Column(Float, default=0.0)

    # Source
    source = Column(String(100), default="builtin")
    # Sources: builtin, community, research, custom

    # MITRE-like classification
    attack_technique = Column(String(100), nullable=True)
    attack_tactic = Column(String(100), nullable=True)

    # Status
    is_active = Column(Boolean, default=True)
    version = Column(Integer, default=1)

    # Statistics
    total_matches = Column(Integer, default=0)
    last_matched_at = Column(DateTime(timezone=True), nullable=True)

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

    def __repr__(self) -> str:
        return f"<ThreatSignature(name='{self.name}', category='{self.category}')>"


class ThreatEvent(Base):
    """Aggregated threat intelligence events for analytics."""
    __tablename__ = "threat_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Event type
    event_type = Column(String(50), nullable=False, index=True)
    # Types: attack_detected, attack_blocked, anomaly, new_pattern,
    #        signature_update, policy_violation

    # Classification
    threat_category = Column(String(100), nullable=False)
    threat_level = Column(String(20), nullable=False)
    threat_score = Column(Float, default=0.0)

    # Source info
    source_ip = Column(String(45), nullable=True)
    source_org_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    source_api_key_prefix = Column(String(12), nullable=True)

    # Attack details
    attack_vector = Column(Text, nullable=True)
    attack_payload_hash = Column(String(64), nullable=True, index=True)
    matched_signatures = Column(JSON, default=list)

    # Context
    model_targeted = Column(String(100), nullable=True)
    details = Column(JSON, default=dict)

    # Response
    action_taken = Column(String(20), nullable=True)
    was_blocked = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_threat_events_category_created", "threat_category", "created_at"),
        Index("ix_threat_events_level_created", "threat_level", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<ThreatEvent(type='{self.event_type}', level='{self.threat_level}')>"
