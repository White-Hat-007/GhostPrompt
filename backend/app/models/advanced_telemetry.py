import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class MultimodalThreat(Base):
    __tablename__ = "multimodal_threats"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_event_id = Column(UUID(as_uuid=True), ForeignKey("scan_events.id", ondelete="CASCADE"), nullable=False, index=True)
    media_type = Column(String(50)) # image, audio, video, pdf
    media_hash = Column(String(128), index=True)
    extracted_text = Column(Text, nullable=True)
    steganography_confidence = Column(Float, default=0.0)
    ocr_confidence = Column(Float, default=0.0)
    threat_level = Column(String(20), default="safe")
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class RAGTrustScore(Base):
    __tablename__ = "rag_trust_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_event_id = Column(UUID(as_uuid=True), ForeignKey("scan_events.id", ondelete="CASCADE"), nullable=False, index=True)
    source_uri = Column(Text, nullable=False) # URL or File path
    content_hash = Column(String(128))
    trust_score = Column(Float, default=1.0) # 1.0 is trusted, 0.0 is malicious
    sanitized_content = Column(Text, nullable=True)
    detected_injections = Column(JSON, default=list)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class DependencyReputation(Base):
    __tablename__ = "dependency_reputation"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    package_name = Column(String(255), index=True, nullable=False)
    ecosystem = Column(String(50), nullable=False) # npm, pypi
    is_hallucinated = Column(Boolean, default=False)
    is_malicious = Column(Boolean, default=False)
    reputation_score = Column(Float, default=0.0)
    verified_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class TokenAnalytics(Base):
    __tablename__ = "token_analytics"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_event_id = Column(UUID(as_uuid=True), ForeignKey("scan_events.id", ondelete="CASCADE"), nullable=False, unique=True)
    estimated_complexity = Column(Float, default=0.0)
    dos_risk_score = Column(Float, default=0.0)
    is_recursive_loop = Column(Boolean, default=False)
    budget_exceeded = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
