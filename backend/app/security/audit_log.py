"""
Security Audit Logger

Centralized audit logging for all security-sensitive actions.
Every entry includes: who, what, when, where, outcome.

Attack vectors prevented:
- Undetected insider threats
- Compliance violations
- Post-incident forensics gaps

Never logs:
- Passwords, tokens, API keys, session IDs
- Full PII beyond what's strictly required
- Raw request bodies (may contain secrets)
"""

from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger("security.audit")


class AuditAction:
    """Constants for audit log action types."""
    # Auth
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGOUT = "auth.logout"
    REGISTER = "auth.register"
    PASSWORD_RESET_REQUEST = "auth.password_reset.request"
    PASSWORD_RESET_COMPLETE = "auth.password_reset.complete"
    EMAIL_VERIFIED = "auth.email.verified"
    TOKEN_REFRESH = "auth.token.refresh"

    # User management
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_ROLE_CHANGED = "user.role_changed"
    USER_ACTIVATED = "user.activated"
    USER_DEACTIVATED = "user.deactivated"

    # Organization
    ORG_CREATED = "org.created"
    ORG_DELETED = "org.deleted"
    ORG_PLAN_CHANGED = "org.plan_changed"

    # API Keys
    API_KEY_CREATED = "apikey.created"
    API_KEY_DELETED = "apikey.deleted"
    API_KEY_USED = "apikey.used"

    # Admin / Super Admin
    SUPERADMIN_ACTION = "superadmin.action"
    ADMIN_ACTION = "admin.action"

    # RBAC / Roles
    ROLE_CREATED = "role.created"
    ROLE_UPDATED = "role.updated"
    ROLE_DELETED = "role.deleted"
    ROLE_ASSIGNED = "role.assigned"

    # Security events
    RATE_LIMIT_TRIGGERED = "security.rate_limit"
    ACCOUNT_LOCKOUT = "security.account_lockout"
    SUSPICIOUS_ACTIVITY = "security.suspicious"
    AUTHORIZATION_FAILURE = "security.authz_failure"


def audit_log(
    action: str,
    actor_id: str | None = None,
    actor_email: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    outcome: str = "success",
) -> None:
    """
    Write a structured audit log entry.
    
    All audit entries are written at INFO level to the security.audit
    logger namespace, which can be routed to a separate tamper-evident
    log store in production.
    """
    # Sanitize: never include sensitive fields
    safe_details = {}
    if details:
        SENSITIVE_KEYS = {"password", "token", "api_key", "secret", "key", "authorization"}
        for k, v in details.items():
            if k.lower() in SENSITIVE_KEYS:
                safe_details[k] = "[REDACTED]"
            else:
                safe_details[k] = v

    logger.info(
        "audit_event",
        action=action,
        actor_id=actor_id,
        actor_email=_mask_email(actor_email) if actor_email else None,
        ip=ip_address,
        user_agent=_truncate(user_agent, 200) if user_agent else None,
        resource_type=resource_type,
        resource_id=resource_id,
        details=safe_details or None,
        outcome=outcome,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _mask_email(email: str) -> str:
    """Mask email for logging: 'user@example.com' → 'us***@ex***.com'"""
    if not email or "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    masked_local = local[:2] + "***" if len(local) > 2 else "***"
    parts = domain.rsplit(".", 1)
    masked_domain = parts[0][:2] + "***" if len(parts[0]) > 2 else "***"
    return f"{masked_local}@{masked_domain}.{parts[1] if len(parts) > 1 else '***'}"


def _truncate(s: str, max_len: int) -> str:
    """Truncate string for safe logging."""
    return s[:max_len] + "..." if len(s) > max_len else s
