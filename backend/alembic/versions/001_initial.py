"""Initial schema

Revision ID: 001_initial
Revises:
Create Date: 2025-01-01
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON, UUID

from alembic import op

revision: str = "001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Extensions
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # Organizations
    op.create_table(
        "organizations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), unique=True, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("plan", sa.String(50), server_default="free"),
        sa.Column("stripe_customer_id", sa.String(255), nullable=True),
        sa.Column("billing_email", sa.String(255), nullable=True),
        sa.Column("max_requests_per_day", sa.Integer, server_default="1000"),
        sa.Column("max_users", sa.Integer, server_default="5"),
        sa.Column("max_api_keys", sa.Integer, server_default="10"),
        sa.Column("settings", JSON, server_default="{}"),
        sa.Column("firewall_mode", sa.String(20), server_default="enforce"),
        sa.Column("threat_score_threshold", sa.Integer, server_default="70"),
        sa.Column("allowed_models", JSON, server_default="[]"),
        sa.Column("blocked_domains", JSON, server_default="[]"),
        sa.Column("ip_allowlist", JSON, server_default="[]"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("is_verified", sa.Boolean, server_default="false"),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suspension_reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_organizations_name", "organizations", ["name"])
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)

    # Users
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("username", sa.String(100), unique=True, nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("avatar_url", sa.Text, nullable=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), server_default="viewer"),
        sa.Column("sso_provider", sa.String(50), nullable=True),
        sa.Column("sso_subject_id", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("is_verified", sa.Boolean, server_default="false"),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_ip", sa.String(45), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean, server_default="false"),
        sa.Column("mfa_secret", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_organization_id", "users", ["organization_id"])

    # API Keys
    op.create_table(
        "api_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("key_hash", sa.String(64), unique=True, nullable=False),
        sa.Column("key_prefix", sa.String(12), nullable=False),
        sa.Column("scopes", JSON, server_default='["scan"]'),
        sa.Column("allowed_models", JSON, server_default="[]"),
        sa.Column("allowed_ips", JSON, server_default="[]"),
        sa.Column("rate_limit_per_minute", sa.Integer, server_default="60"),
        sa.Column("rate_limit_per_day", sa.Integer, server_default="10000"),
        sa.Column("total_requests", sa.Integer, server_default="0"),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_ip", sa.String(45), nullable=True),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)
    op.create_index("ix_api_keys_organization_id", "api_keys", ["organization_id"])

    # Scan Events
    op.create_table(
        "scan_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("request_id", sa.String(64), unique=True, nullable=False),
        sa.Column("api_key_id", UUID(as_uuid=True), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("model_provider", sa.String(50), nullable=True),
        sa.Column("model_name", sa.String(100), nullable=True),
        sa.Column("model_endpoint", sa.String(512), nullable=True),
        sa.Column("scan_type", sa.String(20), nullable=False, server_default="prompt"),
        sa.Column("prompt_text", sa.Text, nullable=True),
        sa.Column("prompt_length", sa.Integer, nullable=True),
        sa.Column("output_text", sa.Text, nullable=True),
        sa.Column("output_length", sa.Integer, nullable=True),
        sa.Column("threat_level", sa.String(20), server_default="safe"),
        sa.Column("threat_score", sa.Float, server_default="0.0"),
        sa.Column("threat_categories", JSON, server_default="[]"),
        sa.Column("detections", JSON, server_default="[]"),
        sa.Column("action", sa.String(20), server_default="allowed"),
        sa.Column("action_reason", sa.Text, nullable=True),
        sa.Column("policy_id", UUID(as_uuid=True), nullable=True),
        sa.Column("policy_rules_triggered", JSON, server_default="[]"),
        sa.Column("scan_duration_ms", sa.Float, nullable=True),
        sa.Column("total_latency_ms", sa.Float, nullable=True),
        sa.Column("prompt_tokens", sa.Integer, nullable=True),
        sa.Column("completion_tokens", sa.Integer, nullable=True),
        sa.Column("total_tokens", sa.Integer, nullable=True),
        sa.Column("is_blocked", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scan_events_request_id", "scan_events", ["request_id"], unique=True)
    op.create_index("ix_scan_events_organization_id", "scan_events", ["organization_id"])
    op.create_index("ix_scan_events_created_at", "scan_events", ["created_at"])
    op.create_index("ix_scan_events_org_created", "scan_events", ["organization_id", "created_at"])
    op.create_index("ix_scan_events_org_threat", "scan_events", ["organization_id", "threat_level"])
    op.create_index("ix_scan_events_org_action", "scan_events", ["organization_id", "action"])

    # Policies
    op.create_table(
        "policies",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("policy_type", sa.String(50), server_default="custom"),
        sa.Column("applies_to", JSON, server_default='["all"]'),
        sa.Column("priority", sa.Integer, server_default="100"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("is_default", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_policies_organization_id", "policies", ["organization_id"])

    # Policy Rules
    op.create_table(
        "policy_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("policy_id", UUID(as_uuid=True), sa.ForeignKey("policies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("rule_type", sa.String(50), nullable=False),
        sa.Column("detector", sa.String(100), nullable=False),
        sa.Column("threshold", sa.Float, server_default="0.7"),
        sa.Column("parameters", JSON, server_default="{}"),
        sa.Column("action", sa.String(20), server_default="block"),
        sa.Column("severity", sa.String(20), server_default="medium"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("priority", sa.Integer, server_default="100"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_policy_rules_policy_id", "policy_rules", ["policy_id"])

    # Threat Signatures
    op.create_table(
        "threat_signatures",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("detection_type", sa.String(50), nullable=False),
        sa.Column("patterns", JSON, server_default="[]"),
        sa.Column("regex_patterns", JSON, server_default="[]"),
        sa.Column("embedding_text", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), server_default="medium"),
        sa.Column("confidence_weight", sa.Float, server_default="1.0"),
        sa.Column("false_positive_rate", sa.Float, server_default="0.0"),
        sa.Column("source", sa.String(100), server_default="builtin"),
        sa.Column("attack_technique", sa.String(100), nullable=True),
        sa.Column("attack_tactic", sa.String(100), nullable=True),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("version", sa.Integer, server_default="1"),
        sa.Column("total_matches", sa.Integer, server_default="0"),
        sa.Column("last_matched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_threat_signatures_name", "threat_signatures", ["name"], unique=True)
    op.create_index("ix_threat_signatures_category", "threat_signatures", ["category"])

    # Threat Events
    op.create_table(
        "threat_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("threat_category", sa.String(100), nullable=False),
        sa.Column("threat_level", sa.String(20), nullable=False),
        sa.Column("threat_score", sa.Float, server_default="0.0"),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("source_org_id", UUID(as_uuid=True), nullable=True),
        sa.Column("source_api_key_prefix", sa.String(12), nullable=True),
        sa.Column("attack_vector", sa.Text, nullable=True),
        sa.Column("attack_payload_hash", sa.String(64), nullable=True),
        sa.Column("matched_signatures", JSON, server_default="[]"),
        sa.Column("model_targeted", sa.String(100), nullable=True),
        sa.Column("event_metadata", JSON, server_default="{}"),
        sa.Column("action_taken", sa.String(20), nullable=True),
        sa.Column("was_blocked", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_threat_events_event_type", "threat_events", ["event_type"])
    op.create_index("ix_threat_events_created_at", "threat_events", ["created_at"])
    op.create_index("ix_threat_events_source_org_id", "threat_events", ["source_org_id"])

    # Audit Logs
    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("user_email", sa.String(255), nullable=True),
        sa.Column("api_key_prefix", sa.String(12), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("changes", JSON, server_default="{}"),
        sa.Column("event_metadata", JSON, server_default="{}"),
        sa.Column("status", sa.String(20), server_default="success"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_logs_organization_id", "audit_logs", ["organization_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_org_created", "audit_logs", ["organization_id", "created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("threat_events")
    op.drop_table("threat_signatures")
    op.drop_table("policy_rules")
    op.drop_table("policies")
    op.drop_table("scan_events")
    op.drop_table("api_keys")
    op.drop_table("users")
    op.drop_table("organizations")
