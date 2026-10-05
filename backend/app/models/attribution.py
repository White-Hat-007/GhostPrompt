"""
Threat Attribution Models

Advanced attacker profiling, campaign correlation, and entity graph models
for the Threat Attribution Engine.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class ThreatActor(Base):
    """Correlated threat actor profile built from telemetry."""
    __tablename__ = "threat_actors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Identity
    actor_id = Column(String(64), nullable=False, unique=True, index=True)
    alias = Column(String(255), nullable=True)
    actor_type = Column(String(50), default="unknown")
    # Types: individual, bot, swarm, apt_group, coordinated, unknown

    # Attribution confidence
    confidence_score = Column(Float, default=0.0)
    attribution_method = Column(String(100), nullable=True)

    # Fingerprints
    ip_addresses = Column(JSON, default=list)
    asn_list = Column(JSON, default=list)
    user_agents = Column(JSON, default=list)
    browser_fingerprints = Column(JSON, default=list)

    # Network attribution
    is_vpn = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    is_cloud_provider = Column(Boolean, default=False)
    hosting_provider = Column(String(255), nullable=True)

    # Behavioral fingerprint
    typing_cadence_ms = Column(Float, nullable=True)
    avg_prompt_interval_s = Column(Float, nullable=True)
    attack_sophistication = Column(String(20), default="medium")
    # low, medium, high, nation_state
    preferred_attack_types = Column(JSON, default=list)
    semantic_fingerprint = Column(JSON, default=dict)
    jailbreak_lineage = Column(JSON, default=list)

    # Geographic
    primary_country = Column(String(100), nullable=True)
    primary_city = Column(String(255), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    timezone_offset = Column(String(10), nullable=True)

    # Activity
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    total_requests = Column(Integer, default=0)
    total_attacks = Column(Integer, default=0)
    total_blocked = Column(Integer, default=0)

    # Campaign links
    campaign_ids = Column(JSON, default=list)

    # Risk
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="low")

    # Status
    is_active = Column(Boolean, default=True)
    is_watchlisted = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_threat_actors_org_risk", "organization_id", "risk_score"),
    )


class ThreatCampaign(Base):
    """Correlated attack campaign linking multiple actors and events."""
    __tablename__ = "threat_campaigns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    campaign_id = Column(String(64), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Classification
    campaign_type = Column(String(50), default="unknown")
    # Types: coordinated_prompt, bot_swarm, distributed, apt, opportunistic, unknown
    threat_family = Column(String(100), nullable=True)
    threat_cluster = Column(String(100), nullable=True)

    # Scope
    actor_ids = Column(JSON, default=list)
    ip_addresses = Column(JSON, default=list)
    attack_types = Column(JSON, default=list)
    target_models = Column(JSON, default=list)

    # Timeline
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Metrics
    total_events = Column(Integer, default=0)
    total_actors = Column(Integer, default=0)
    total_ips = Column(Integer, default=0)
    success_rate = Column(Float, default=0.0)

    # Severity
    severity = Column(String(20), default="medium")
    risk_score = Column(Float, default=0.0)

    # Status
    status = Column(String(20), default="active")
    # active, dormant, resolved, escalated

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class AttackCluster(Base):
    """Groups of related attacks forming an attack family."""
    __tablename__ = "attack_clusters"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    cluster_id = Column(String(64), nullable=False, unique=True, index=True)
    family_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Classification
    attack_category = Column(String(100), nullable=False)
    variant_count = Column(Integer, default=0)
    payload_hashes = Column(JSON, default=list)

    # Patterns
    common_patterns = Column(JSON, default=list)
    semantic_centroid = Column(JSON, default=dict)
    evolution_timeline = Column(JSON, default=list)

    # Metrics
    total_occurrences = Column(Integer, default=0)
    block_rate = Column(Float, default=0.0)
    avg_threat_score = Column(Float, default=0.0)

    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class AttributionProfile(Base):
    """Detailed attribution telemetry for a single session or request."""
    __tablename__ = "attribution_profiles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Link to scan
    scan_event_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    threat_actor_id = Column(UUID(as_uuid=True), nullable=True, index=True)

    # Request layer
    ip_address = Column(String(45), nullable=True)
    asn = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)
    geolocation = Column(JSON, default=dict)
    is_vpn = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    is_cloud = Column(Boolean, default=False)

    # HTTP layer
    headers_hash = Column(String(64), nullable=True)
    user_agent = Column(Text, nullable=True)
    accept_language = Column(String(255), nullable=True)
    timezone_header = Column(String(50), nullable=True)
    request_order_hash = Column(String(64), nullable=True)

    # Browser fingerprinting
    canvas_hash = Column(String(64), nullable=True)
    webgl_hash = Column(String(64), nullable=True)
    screen_resolution = Column(String(20), nullable=True)
    browser_features = Column(JSON, default=dict)
    timezone_consistency = Column(Boolean, default=True)

    # Behavioral layer
    typing_pattern_hash = Column(String(64), nullable=True)
    prompt_cadence_ms = Column(Float, nullable=True)
    session_duration_s = Column(Float, nullable=True)
    attack_timing = Column(JSON, default=dict)

    # AI layer
    attack_categories = Column(JSON, default=list)
    attack_sophistication = Column(String(20), nullable=True)
    attack_objectives = Column(JSON, default=list)
    semantic_fingerprint_hash = Column(String(64), nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_attribution_org_created", "organization_id", "created_at"),
    )


class ModelIntegrityEvent(Base):
    """Training integrity and model health monitoring events."""
    __tablename__ = "model_integrity_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Event classification
    event_type = Column(String(50), nullable=False, index=True)
    # Types: poisoning_detected, sleeper_trigger, alignment_shift,
    #        fine_tune_anomaly, drift_detected, activation_anomaly

    # Model info
    model_name = Column(String(255), nullable=True)
    model_provider = Column(String(100), nullable=True)
    model_version = Column(String(100), nullable=True)

    # Risk scoring
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="low")
    confidence = Column(Float, default=0.0)

    # Details
    description = Column(Text, nullable=True)
    indicators = Column(JSON, default=list)
    anomaly_data = Column(JSON, default=dict)

    # Response
    action_taken = Column(String(50), nullable=True)
    was_mitigated = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_model_integrity_org_type", "organization_id", "event_type"),
    )


class GroomingTimeline(Base):
    """Long-horizon semantic grooming tracking across sessions."""
    __tablename__ = "grooming_timelines"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Session tracking
    session_id = Column(String(128), nullable=False, index=True)
    actor_id = Column(String(64), nullable=True, index=True)

    # Classification
    grooming_type = Column(String(50), nullable=False)
    # Types: trust_building, semantic_drift, progressive_manipulation,
    #        authority_establishment, rapport_exploitation

    # Risk
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="low")
    stage = Column(String(50), default="initial")
    # Stages: initial, establishing, escalating, exploiting, exfiltrating

    # Timeline data
    interaction_count = Column(Integer, default=0)
    manipulation_indicators = Column(JSON, default=list)
    semantic_drift_vector = Column(JSON, default=list)
    trust_score_history = Column(JSON, default=list)

    # Duration
    first_interaction = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_interaction = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    span_days = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class ExfiltrationEvent(Base):
    """Covert channel and side-effect exfiltration detection events."""
    __tablename__ = "exfiltration_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Classification
    channel_type = Column(String(50), nullable=False)
    # Types: timing_channel, response_length, token_encoding, tool_sequence,
    #        repeated_structure, api_timing

    # Detection
    confidence_score = Column(Float, default=0.0)
    severity = Column(String(20), default="medium")
    description = Column(Text, nullable=True)

    # Evidence
    indicators = Column(JSON, default=list)
    timing_data = Column(JSON, default=dict)
    payload_hash = Column(String(64), nullable=True)

    # Source
    source_ip = Column(String(45), nullable=True)
    session_id = Column(String(128), nullable=True)
    actor_id = Column(String(64), nullable=True)

    # Response
    action_taken = Column(String(50), nullable=True)
    was_blocked = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class AdversarialMediaEvent(Base):
    """Multimodal adversarial attack detection events."""
    __tablename__ = "adversarial_media_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Media type
    media_type = Column(String(50), nullable=False)
    # Types: image, audio, video, document, multimodal

    # Attack type
    attack_type = Column(String(100), nullable=False)
    # Types: adversarial_patch, latent_perturbation, audio_noise,
    #        image_overlay, steganography, multimodal_evasion

    # Detection
    confidence_score = Column(Float, default=0.0)
    severity = Column(String(20), default="medium")
    description = Column(Text, nullable=True)

    # Fingerprint
    attack_fingerprint = Column(String(128), nullable=True, index=True)
    payload_hash = Column(String(64), nullable=True)
    detection_method = Column(String(100), nullable=True)

    # Evidence
    indicators = Column(JSON, default=list)
    event_metadata = Column(JSON, default=dict)

    # Response
    action_taken = Column(String(50), nullable=True)
    was_blocked = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class TokenizerThreat(Base):
    """Tokenizer vulnerability and anomaly registry."""
    __tablename__ = "tokenizer_threats"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Threat type
    threat_type = Column(String(100), nullable=False)
    # Types: unknown_split, unicode_edge, byte_anomaly, boundary_exploit,
    #        normalization_divergence, homoglyph_novel, bidi_novel

    # Details
    description = Column(Text, nullable=True)
    affected_tokenizer = Column(String(100), nullable=True)
    affected_models = Column(JSON, default=list)

    # Evidence
    sample_input = Column(Text, nullable=True)
    expected_tokens = Column(JSON, default=list)
    actual_tokens = Column(JSON, default=list)
    anomaly_score = Column(Float, default=0.0)

    # Severity
    severity = Column(String(20), default="medium")
    exploitability = Column(String(20), default="theoretical")
    # theoretical, demonstrated, weaponized

    # Status
    status = Column(String(20), default="new")
    # new, investigating, confirmed, mitigated, false_positive

    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
