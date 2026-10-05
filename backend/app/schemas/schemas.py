"""
Pydantic Schemas for API Request/Response Models

All API contracts are defined here with full validation.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.services.firewall.detectors.attacker_profiler import AttackerProfile

# ============================================================
# Auth Schemas
# ============================================================

class LoginRequest(BaseModel):
    email: str
    password: str = Field(..., min_length=8, max_length=128)


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str | None = Field(None, max_length=255)
    organization_name: str = Field(..., min_length=2, max_length=255)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


# ============================================================
# User Schemas
# ============================================================

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    username: str
    full_name: str | None
    role: str
    organization_id: UUID
    organization_plan: str = "starter"
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: str | None = Field(None, pattern=r"^(owner|admin|analyst|viewer)$")


# ============================================================
# Role Schemas
# ============================================================

class RoleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    is_builtin: bool
    permissions: dict
    organization_id: UUID | None

class RoleCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=64)
    description: str | None = None
    permissions: dict = Field(default_factory=dict)

class RoleUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=64)
    description: str | None = None
    permissions: dict | None = None


# ============================================================
# Organization Schemas
# ============================================================

class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    plan: str
    max_requests_per_day: int
    max_users: int
    firewall_mode: str
    is_active: bool
    created_at: datetime


class OrganizationUpdate(BaseModel):
    name: str | None = Field(None, max_length=255)
    firewall_mode: str | None = Field(None, pattern=r"^(enforce|monitor|disabled)$")
    threat_score_threshold: int | None = Field(None, ge=0, le=100)
    settings: dict | None = None


# ============================================================
# Scan Schemas
# ============================================================

class ScanRequest(BaseModel):
    """Request to scan a prompt or output through the AI Firewall."""
    prompt: str = Field(..., max_length=100000)
    model: str | None = None
    provider: str | None = None
    context: dict | None = None
    scan_type: str = Field(default="prompt", pattern=r"^(prompt|output|rag|agent)$")
    metadata: dict | None = None
    media_payloads: list[str] | None = None
    rag_context: str | None = None


class DetectionResult(BaseModel):
    detector: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    category: str
    description: str
    matched_content: str | None = None
    raw_content: str | None = Field(None, exclude=True)
    severity: str = "medium"


class ScanResponse(BaseModel):
    """Result of a firewall scan."""
    request_id: str
    threat_level: str  # safe, low, medium, high, critical
    threat_score: float
    action: str  # allowed, blocked, sanitized, flagged
    detections: list[DetectionResult] = []
    sanitized_prompt: str | None = None
    prompt: str | None = None
    scan_duration_ms: float
    dlp_mappings: dict[str, str] = {}
    metadata: dict = {}


class ScanEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    request_id: str
    scan_type: str
    model_provider: str | None
    model_name: str | None
    threat_level: str
    threat_score: float
    action: str
    detections: list
    is_blocked: bool
    scan_duration_ms: float | None
    created_at: datetime
    attacker_profile: AttackerProfile | None = None
    event_metadata: dict | None = None


# ============================================================
# Policy Schemas
# ============================================================

class PolicyRuleCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = None
    rule_type: str
    detector: str
    threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    parameters: dict = {}
    action: str = Field(default="block", pattern=r"^(block|flag|sanitize|log|alert)$")
    severity: str = Field(default="medium", pattern=r"^(low|medium|high|critical)$")
    is_active: bool = True
    priority: int = Field(default=100, ge=1, le=1000)


class PolicyCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = None
    policy_type: str = "custom"
    applies_to: list[str] = ["all"]
    priority: int = Field(default=100, ge=1, le=1000)
    rules: list[PolicyRuleCreate] = []


class PolicyUpdate(BaseModel):
    name: str | None = Field(None, max_length=255)
    description: str | None = None
    policy_type: str | None = None
    applies_to: list[str] | None = None
    priority: int | None = Field(None, ge=1, le=1000)
    is_active: bool | None = None
    rules: list[PolicyRuleCreate] | None = None


class PolicyRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    rule_type: str
    detector: str
    threshold: float
    parameters: dict
    action: str
    severity: str
    is_active: bool
    priority: int


class PolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    policy_type: str
    applies_to: list
    priority: int
    is_active: bool
    rules: list[PolicyRuleResponse] = []
    created_at: datetime


# ============================================================
# API Key Schemas
# ============================================================

class APIKeyCreate(BaseModel):
    name: str = Field(..., max_length=255)
    scopes: list[str] = ["scan"]
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10000)
    rate_limit_per_day: int = Field(default=10000, ge=1, le=1000000)


class APIKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    key_prefix: str
    scopes: list
    rate_limit_per_minute: int
    rate_limit_per_day: int
    total_requests: int
    is_active: bool
    last_used_at: datetime | None
    created_at: datetime


class APIKeyCreatedResponse(APIKeyResponse):
    """Includes the full key — only shown once at creation."""
    api_key: str


# ============================================================
# Analytics Schemas
# ============================================================

class DashboardStats(BaseModel):
    total_scans: int
    blocked_attacks: int
    threat_events: int
    active_policies: int
    scans_today: int
    blocks_today: int
    avg_threat_score: float
    top_threat_categories: list[dict]
    recent_attacks: list[dict]
    scans_over_time: list[dict]
    threat_level_distribution: dict


class ThreatTimelineEntry(BaseModel):
    timestamp: datetime
    count: int
    threat_level: str


# ============================================================
# Gateway Schemas
# ============================================================

class GatewayRequest(BaseModel):
    """Proxied request through the AI Gateway."""
    model: str
    messages: list[dict]
    provider: str | None = None
    temperature: float | None = Field(None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(None, ge=1, le=128000)
    stream: bool = False
    metadata: dict | None = None


class GatewayResponse(BaseModel):
    """Response from the AI Gateway."""
    id: str
    model: str
    provider: str
    choices: list[dict]
    usage: dict
    scan_result: ScanResponse | None = None
    output_scan_result: ScanResponse | None = None


# ============================================================
# Pagination
# ============================================================

class PaginatedResponse(BaseModel):
    items: list[Any] = []
    total: int
    page: int
    page_size: int
    total_pages: int
