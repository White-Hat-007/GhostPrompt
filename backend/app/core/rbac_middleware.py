"""
GhostPrompt RBAC Enforcement Middleware

Applies permission checks to API routes via FastAPI dependencies.
This is registered in main.py to enforce RBAC across all protected endpoints.

Permission matrix:
    scan.*          → scanning endpoints
    policies.*      → firewall policies
    analytics.*     → analytics/dashboards
    training.*      → model training
    redteam.*       → red team operations
    federation.*    → federated intel
    billing.*       → billing/subscriptions
    settings.*      → org settings
    admin.*         → super-admin operations
    audit.*         → audit log access
"""

from fastapi import Depends, HTTPException, Request, status

from app.core.logging import get_logger
from app.core.security import get_current_user

logger = get_logger("rbac.middleware")

# Route prefix → required permission mapping
# Routes not in this map default to authenticated-only (no specific permission)
ROUTE_PERMISSIONS: dict[str, str] = {
    # Scan — core functionality
    "POST /api/v1/scan": "scan.execute",
    "POST /api/v1/scan/batch": "scan.execute",

    # Policies
    "GET /api/v1/policies": "policies.view",
    "POST /api/v1/policies": "policies.manage",
    "PUT /api/v1/policies": "policies.manage",
    "DELETE /api/v1/policies": "policies.manage",

    # Analytics
    "GET /api/v1/analytics": "analytics.view",
    "GET /api/v1/analytics/export": "analytics.export",

    # Training
    "POST /api/v1/training/start": "training.manage",
    "POST /api/v1/training/datasets/upload": "training.manage",
    "GET /api/v1/training/jobs": "training.view",
    "GET /api/v1/training/gpu-status": "training.view",
    "GET /api/v1/training/datasets": "training.view",

    # Red Team
    "POST /api/v1/enterprise/red-team": "redteam.execute",
    "GET /api/v1/enterprise/red-team": "redteam.view",

    # Federation
    "GET /api/v1/federation/status": "federation.view",
    "POST /api/v1/federation/contribute": "federation.manage",
    "POST /api/v1/federation/opt-in": "federation.manage",
    "GET /api/v1/federation/intel": "federation.view",
    "GET /api/v1/federation/network": "federation.view",

    # Adaptive ML
    "GET /api/v1/adaptive-ml/status": "ml.view",
    "POST /api/v1/adaptive-ml/approve": "ml.manage",
    "POST /api/v1/adaptive-ml/reject": "ml.manage",
    "POST /api/v1/adaptive-ml/settings": "ml.manage",
    "POST /api/v1/adaptive-ml/toggle-auto-tune": "ml.manage",

    # Billing
    "GET /api/v1/billing/status": "billing.view",
    "GET /api/v1/billing/usage": "billing.view",
    "POST /api/v1/billing/checkout": "billing.manage",
    "POST /api/v1/billing/subscribe": "billing.manage",

    # Audit
    "GET /api/v1/audit/events": "audit.view",
    "GET /api/v1/audit/export": "audit.export",

    # Settings
    "GET /api/v1/settings": "settings.view",
    "PUT /api/v1/settings": "settings.manage",
    "POST /api/v1/settings": "settings.manage",

    # Super-admin
    "GET /api/v1/superadmin": "admin.manage",
    "POST /api/v1/superadmin": "admin.manage",
}

# Roles → built-in permissions (used if DB roles not yet seeded)
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "super_admin": {"_all"},
    "owner": {
        "scan.execute", "scan.view",
        "policies.view", "policies.manage",
        "analytics.view", "analytics.export",
        "training.view", "training.manage",
        "redteam.view", "redteam.execute",
        "federation.view", "federation.manage",
        "ml.view", "ml.manage",
        "billing.view", "billing.manage",
        "audit.view", "audit.export",
        "settings.view", "settings.manage",
    },
    "admin": {
        "scan.execute", "scan.view",
        "policies.view", "policies.manage",
        "analytics.view", "analytics.export",
        "training.view", "training.manage",
        "redteam.view", "redteam.execute",
        "federation.view",
        "ml.view", "ml.manage",
        "billing.view",
        "audit.view",
        "settings.view",
    },
    "analyst": {
        "scan.execute", "scan.view",
        "analytics.view", "analytics.export",
        "redteam.view",
        "federation.view",
        "ml.view",
        "audit.view",
    },
    "viewer": {
        "scan.view",
        "analytics.view",
        "federation.view",
        "ml.view",
    },
}


def check_route_permission(request: Request, current_user: dict) -> bool:
    """
    Check if the current user has permission for the requested route.
    Returns True if allowed, raises HTTPException if denied.
    """
    method = request.method
    path = request.url.path

    # Build the route key
    route_key = f"{method} {path}"

    # Find matching permission (prefix match for parameterized routes)
    required_permission = None
    for pattern, perm in ROUTE_PERMISSIONS.items():
        pattern_method, pattern_path = pattern.split(" ", 1)
        if method == pattern_method and path.startswith(pattern_path):
            required_permission = perm
            break

    # No permission mapping → allow (authenticated is enough)
    if not required_permission:
        return True

    # Super-admin → always allowed (single source of truth)
    from app.core.permissions import is_super_admin
    if is_super_admin(current_user):
        return True

    # Check role-based permissions
    role = current_user.get("role", "viewer")
    role_perms = ROLE_PERMISSIONS.get(role, set())

    if "_all" in role_perms:
        return True

    if required_permission in role_perms:
        return True

    # Check resource.manage covers resource.* actions
    resource = required_permission.split(".")[0]
    if f"{resource}.manage" in role_perms:
        return True

    logger.warning(
        "rbac_denied",
        user=current_user.get("email"),
        role=role,
        route=route_key,
        required=required_permission,
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Permission denied: {required_permission} (your role: {role})",
    )


async def rbac_middleware_dependency(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """FastAPI dependency to enforce RBAC on every authenticated route."""
    # Skip for public endpoints
    public_prefixes = [
        "/api/v1/auth/",
        "/api/v1/scan/test",
        "/api/v1/health",
        "/docs",
        "/redoc",
        "/openapi.json",
    ]
    for prefix in public_prefixes:
        if request.url.path.startswith(prefix):
            return current_user

    check_route_permission(request, current_user)
    return current_user
