"""
GhostPrompt RBAC — Role & Permission Models

Hierarchical, granular, resource-scoped permission system.
Hierarchy: Platform (Super-Admin) → Organization → Workspace → Team → User.

Built-in roles + custom role support.
"""

from enum import Enum
from typing import Optional
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Boolean, DateTime, ForeignKey, JSON, Text, Integer,
    UniqueConstraint, Index,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, ARRAY
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


# ── Permission Actions ──────────────────────────────────────────────────
class Action(str, Enum):
    VIEW = "view"
    CREATE = "create"
    EDIT = "edit"
    DELETE = "delete"
    EXECUTE = "execute"
    MANAGE = "manage"  # full CRUD + admin actions


# ── Resources ───────────────────────────────────────────────────────────
class Resource(str, Enum):
    # Core
    DASHBOARD = "dashboard"
    SCAN = "scan"
    INCIDENTS = "incidents"
    POLICIES = "policies"
    API_KEYS = "api_keys"

    # Security
    RED_TEAM = "red_team"
    CYBERMAP = "cybermap"
    ATTRIBUTION = "attribution"
    THREAT_INTEL = "threat_intel"

    # Platform
    PROVIDERS = "providers"
    ROUTING = "routing"
    CACHING = "caching"
    KEY_VAULT = "key_vault"
    PROMPT_STUDIO = "prompt_studio"
    MCP_GATEWAY = "mcp_gateway"
    OBSERVABILITY = "observability"

    # ML
    CUSTOM_MODELS = "custom_models"
    ADAPTIVE_ML = "adaptive_ml"
    FEDERATED_INTEL = "federated_intel"

    # Admin
    MEMBERS = "members"
    ROLES = "roles"
    SETTINGS = "settings"
    BILLING = "billing"
    INTEGRATIONS = "integrations"
    COMPLIANCE = "compliance"
    AUDIT_LOG = "audit_log"

    # Super-admin
    ORGANIZATIONS = "organizations"
    PLATFORM_ADMIN = "platform_admin"
    FEATURE_FLAGS = "feature_flags"


# ── Built-in Role Definitions ──────────────────────────────────────────
# Format: { "resource.action": True/False }
# Missing = denied (default-deny)

BUILTIN_ROLES: dict[str, dict] = {
    "super_admin": {
        "_description": "Platform-wide super administrator (founder)",
        "_all": True,  # special: grants everything
    },
    "org_owner": {
        "_description": "Organization owner — full access within org",
        "dashboard.view": True, "dashboard.manage": True,
        "scan.view": True, "scan.create": True, "scan.execute": True,
        "incidents.view": True, "incidents.edit": True, "incidents.delete": True,
        "policies.view": True, "policies.create": True, "policies.edit": True, "policies.delete": True,
        "api_keys.view": True, "api_keys.create": True, "api_keys.edit": True, "api_keys.delete": True,
        "red_team.view": True, "red_team.execute": True, "red_team.manage": True,
        "cybermap.view": True, "attribution.view": True, "threat_intel.view": True,
        "providers.view": True, "providers.manage": True,
        "routing.view": True, "routing.manage": True,
        "caching.view": True, "caching.manage": True,
        "key_vault.view": True, "key_vault.manage": True,
        "prompt_studio.view": True, "prompt_studio.manage": True,
        "mcp_gateway.view": True, "mcp_gateway.manage": True,
        "observability.view": True, "observability.manage": True,
        "custom_models.view": True, "custom_models.manage": True,
        "adaptive_ml.view": True, "adaptive_ml.manage": True,
        "federated_intel.view": True, "federated_intel.manage": True,
        "members.view": True, "members.manage": True,
        "roles.view": True, "roles.manage": True,
        "settings.view": True, "settings.manage": True,
        "billing.view": True, "billing.manage": True,
        "integrations.view": True, "integrations.manage": True,
        "compliance.view": True, "compliance.manage": True,
        "audit_log.view": True,
    },
    "org_admin": {
        "_description": "Organization administrator — full access except billing & danger zone",
        "dashboard.view": True, "dashboard.manage": True,
        "scan.view": True, "scan.create": True, "scan.execute": True,
        "incidents.view": True, "incidents.edit": True,
        "policies.view": True, "policies.create": True, "policies.edit": True,
        "api_keys.view": True, "api_keys.create": True, "api_keys.edit": True,
        "red_team.view": True, "red_team.execute": True,
        "cybermap.view": True, "attribution.view": True, "threat_intel.view": True,
        "providers.view": True, "providers.manage": True,
        "routing.view": True, "routing.manage": True,
        "caching.view": True, "caching.manage": True,
        "key_vault.view": True, "key_vault.manage": True,
        "prompt_studio.view": True, "prompt_studio.manage": True,
        "mcp_gateway.view": True, "mcp_gateway.manage": True,
        "observability.view": True, "observability.manage": True,
        "custom_models.view": True, "custom_models.manage": True,
        "adaptive_ml.view": True, "adaptive_ml.manage": True,
        "federated_intel.view": True, "federated_intel.manage": True,
        "members.view": True, "members.manage": True,
        "roles.view": True,
        "settings.view": True, "settings.edit": True,
        "integrations.view": True, "integrations.manage": True,
        "compliance.view": True,
        "audit_log.view": True,
    },
    "security_analyst": {
        "_description": "Security analyst — view + interact with security features",
        "dashboard.view": True,
        "scan.view": True, "scan.create": True, "scan.execute": True,
        "incidents.view": True, "incidents.edit": True,
        "policies.view": True,
        "red_team.view": True, "red_team.execute": True,
        "cybermap.view": True, "attribution.view": True, "threat_intel.view": True,
        "observability.view": True,
        "custom_models.view": True,
        "adaptive_ml.view": True,
        "federated_intel.view": True,
        "audit_log.view": True,
    },
    "developer": {
        "_description": "Developer — API access, scanning, observability",
        "dashboard.view": True,
        "scan.view": True, "scan.create": True, "scan.execute": True,
        "incidents.view": True,
        "policies.view": True,
        "api_keys.view": True, "api_keys.create": True,
        "providers.view": True,
        "routing.view": True,
        "caching.view": True,
        "key_vault.view": True,
        "prompt_studio.view": True, "prompt_studio.create": True, "prompt_studio.edit": True,
        "mcp_gateway.view": True,
        "observability.view": True,
        "integrations.view": True,
    },
    "billing_viewer": {
        "_description": "Billing viewer — read-only billing access",
        "dashboard.view": True,
        "billing.view": True,
    },
    "read_only": {
        "_description": "Read-only observer",
        "dashboard.view": True,
        "scan.view": True,
        "incidents.view": True,
        "policies.view": True,
        "cybermap.view": True,
        "observability.view": True,
        "audit_log.view": True,
    },
}


# ── Database Models ─────────────────────────────────────────────────────

class Role(Base):
    """Role definition — built-in or custom per-org."""
    __tablename__ = "roles"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(PG_UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True)
    name = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    is_builtin = Column(Boolean, default=False, nullable=False)
    permissions = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_role_org_name"),
        Index("ix_role_org", "organization_id"),
    )


class UserRole(Base):
    """Maps users to roles within an organization."""
    __tablename__ = "user_roles"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    organization_id = Column(PG_UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    role_id = Column(PG_UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    assigned_by = Column(PG_UUID(as_uuid=True), nullable=True)
    assigned_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", "role_id", name="uq_user_org_role"),
        Index("ix_user_role_user", "user_id"),
        Index("ix_user_role_org", "organization_id"),
    )
