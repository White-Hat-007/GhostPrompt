"""
GhostPrompt RBAC — Permission Enforcement

FastAPI dependency that checks permissions on every endpoint.
Default-deny: if a permission isn't explicitly granted, it's denied.

Usage:
    @router.get("/policies", dependencies=[Depends(require_permission("policies.view"))])
    async def list_policies(...): ...
"""

from typing import Optional
from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.role import Role, UserRole, BUILTIN_ROLES

logger = get_logger("rbac")
settings = get_settings()


def is_super_admin(user: dict) -> bool:
    """
    Single source of truth for super-admin resolution.
    
    Checks:
    1. NOT an impersonation token (impersonated sessions cannot escalate)
    2. Email matches the configured SUPERADMIN_EMAIL (founder account)
    3. OR role is explicitly 'super_admin'
    
    ALL code that needs to check super-admin status MUST call this function.
    Do NOT scatter `email == settings.SUPERADMIN_EMAIL` checks elsewhere.
    """
    # Impersonation tokens can never be super-admin — prevents escalation
    if user.get("is_impersonation"):
        return False

    email = user.get("email", "")
    role = user.get("role", "")
    return email == settings.SUPERADMIN_EMAIL or role == "super_admin"


async def get_user_permissions(
    user_id: str,
    org_id: str,
    db: AsyncSession,
) -> dict[str, bool]:
    """
    Resolve the effective permission set for a user within an organization.
    Merges all assigned roles (union of grants).
    """
    # Super-admin check (by email)
    result = await db.execute(
        select(UserRole, Role)
        .join(Role, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id, UserRole.organization_id == org_id)
    )
    rows = result.all()

    merged: dict[str, bool] = {}
    for user_role, role in rows:
        perms = role.permissions or {}

        # Built-in super_admin grants everything
        if perms.get("_all"):
            return {"_all": True}

        for key, val in perms.items():
            if key.startswith("_"):
                continue
            if val:
                merged[key] = True

    return merged


def has_permission(permissions: dict[str, bool], required: str) -> bool:
    """Check if a permission set includes the required permission."""
    # Super-admin bypass
    if permissions.get("_all"):
        return True

    # Direct check
    if permissions.get(required):
        return True

    # Check 'manage' covers all actions on a resource
    resource = required.split(".")[0] if "." in required else required
    if permissions.get(f"{resource}.manage"):
        return True

    return False


def require_permission(permission: str):
    """
    FastAPI dependency factory for permission-gated endpoints.

    Usage:
        @router.get("/", dependencies=[Depends(require_permission("policies.view"))])
    """
    async def _check(
        current_user: dict = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        user_id = current_user.get("user_id")
        org_id = current_user.get("org_id")

        # Super-admin bypass (single source of truth)
        if is_super_admin(current_user):
            return current_user

        # Legacy role-based shortcut for existing endpoints during migration
        role = current_user.get("role", "")
        if role in ("admin", "owner", "super_admin"):
            return current_user

        if not user_id or not org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        # Resolve permissions from DB
        permissions = await get_user_permissions(user_id, org_id, db)

        if not has_permission(permissions, permission):
            logger.warning(
                "permission_denied",
                user_id=str(user_id),
                org_id=str(org_id),
                permission=permission,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}",
            )

        return current_user

    return _check


def require_super_admin():
    """Dependency that requires super-admin (founder) access."""
    async def _check(
        current_user: dict = Depends(get_current_user),
    ):
        if not is_super_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Super-admin access required",
            )
        return current_user

    return _check


async def seed_builtin_roles(db: AsyncSession, org_id: str) -> None:
    """Seed built-in roles for an organization if they don't exist."""
    for role_name, perms in BUILTIN_ROLES.items():
        existing = await db.execute(
            select(Role).where(
                Role.organization_id == org_id,
                Role.name == role_name,
                Role.is_builtin == True,
            )
        )
        if existing.scalar_one_or_none():
            continue

        description = perms.pop("_description", f"Built-in {role_name} role")
        role = Role(
            organization_id=org_id,
            name=role_name,
            description=description,
            is_builtin=True,
            permissions={k: v for k, v in perms.items()},
        )
        db.add(role)

    await db.flush()
    logger.info("seeded_builtin_roles", org_id=org_id)
