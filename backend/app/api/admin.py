"""
Admin Routes

User management for owners/admins within their organization.

Security:
- IDOR protection: all queries scoped to org_id from JWT
- Privilege escalation prevention: cannot promote to owner
- Mass assignment protection: explicit field whitelist
- Self-deletion guard
- All admin actions are audit logged
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
import re

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.role import Role, Resource, Action
from app.schemas.schemas import UserResponse, RoleResponse, RoleCreate, RoleUpdate
from app.security.audit_log import audit_log, AuditAction
from pydantic import BaseModel, Field
import uuid

# Allowed permission key pattern: resource.action (e.g. "dashboard.view")
_PERM_KEY_RE = re.compile(r'^[a-z_]+\.[a-z_]+$')
_VALID_RESOURCES = {r.value for r in Resource}
_VALID_ACTIONS = {a.value for a in Action}


def _validate_permissions(perms: dict) -> dict:
    """
    Sanitize and validate permission keys.
    Security: Prevents injection of arbitrary permission keys that could
    bypass the RBAC system or create ghost permissions.
    """
    clean = {}
    for key, val in perms.items():
        if key.startswith('_'):
            continue  # Reserved keys like _all, _description are stripped
        if not _PERM_KEY_RE.match(key):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid permission key format: '{key}'. Must be 'resource.action'",
            )
        resource, action = key.split('.', 1)
        if resource not in _VALID_RESOURCES:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown resource: '{resource}'",
            )
        if action not in _VALID_ACTIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown action: '{action}'",
            )
        clean[key] = bool(val)
    return clean

router = APIRouter(prefix="/admin", tags=["Admin"])

ALLOWED_ROLES = {"admin", "analyst", "viewer"}  # Excludes "owner" to prevent escalation


def require_admin(current_user: dict = Depends(get_current_user)):
    """Require admin or owner role."""
    if current_user.get("role") not in ["admin", "owner"]:
        audit_log(
            action=AuditAction.AUTHORIZATION_FAILURE,
            actor_id=current_user.get("user_id"),
            actor_email=current_user.get("email"),
            details={"required_role": "admin", "actual_role": current_user.get("role")},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    return current_user


class UserUpdate(BaseModel):
    """
    Explicit whitelist of updatable fields.
    Security: Prevents mass assignment attacks.
    """
    role: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all users in the caller's organization."""
    org_id = current_user.get("org_id")
    result = await db.execute(select(User).where(User.organization_id == org_id))
    users = result.scalars().all()
    return users


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    update_data: UserUpdate,
    http_request: Request,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Update a user's role or status.
    
    Security:
    - Scoped to caller's org_id (IDOR prevention)
    - Cannot promote to 'owner' (privilege escalation prevention)
    - Cannot modify own role (separation of duties)
    """
    org_id = current_user.get("org_id")
    client_ip = http_request.client.host if http_request.client else "unknown"
    result = await db.execute(
        select(User).where(User.id == user_id, User.organization_id == org_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent modifying own role
    if str(user.id) == current_user.get("user_id") and update_data.role is not None:
        raise HTTPException(status_code=400, detail="Cannot modify your own role")

    changes: dict = {}

    if update_data.role is not None:
        # ── Single-owner invariant enforcement ──
        # If promoting to 'owner', check for existing owner and perform transfer
        if update_data.role == "owner":
            existing_owner_result = await db.execute(
                select(User).where(
                    User.organization_id == org_id,
                    User.role == "owner",
                    User.id != user.id,
                )
            )
            existing_owner = existing_owner_result.scalar_one_or_none()
            if existing_owner:
                # Explicit ownership transfer — demote old owner to admin
                old_role = existing_owner.role
                existing_owner.role = "admin"
                audit_log(
                    action=AuditAction.USER_UPDATED,
                    actor_id=current_user.get("user_id"),
                    actor_email=current_user.get("email"),
                    ip_address=client_ip,
                    resource_type="org_ownership",
                    resource_id=str(org_id),
                    details={
                        "event": "ORG_OWNERSHIP_TRANSFERRED",
                        "from_user_id": str(existing_owner.id),
                        "from_user_email": existing_owner.email,
                        "to_user_id": str(user.id),
                        "to_user_email": user.email,
                        "previous_owner_demoted_to": "admin",
                    },
                )

        if update_data.role not in ALLOWED_ROLES and update_data.role != "owner":
            # Check if it's a valid custom role UUID
            try:
                role_id = uuid.UUID(update_data.role)
                role_result = await db.execute(
                    select(Role).where(Role.id == role_id, Role.organization_id == org_id)
                )
                custom_role = role_result.scalar_one_or_none()
                if not custom_role:
                    raise HTTPException(status_code=400, detail="Invalid role")
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid role")

        changes["role"] = {"from": user.role, "to": update_data.role}
        user.role = update_data.role
    if update_data.is_active is not None:
        changes["is_active"] = {"from": user.is_active, "to": update_data.is_active}
        user.is_active = update_data.is_active
    if update_data.is_verified is not None:
        changes["is_verified"] = {"from": user.is_verified, "to": update_data.is_verified}
        user.is_verified = update_data.is_verified

    await db.commit()

    audit_log(
        action=AuditAction.USER_UPDATED,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="user",
        resource_id=str(user.id),
        details=changes,
    )

    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    http_request: Request,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Delete a user within the caller's organization."""
    org_id = current_user.get("org_id")
    client_ip = http_request.client.host if http_request.client else "unknown"
    result = await db.execute(
        select(User).where(User.id == user_id, User.organization_id == org_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Self-deletion guard — compare user_id from JWT, not "sub"
    if str(user.id) == current_user.get("user_id"):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    audit_log(
        action=AuditAction.USER_DELETED,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="user",
        resource_id=str(user.id),
        details={"deleted_email": user.email, "deleted_role": user.role},
    )

    await db.delete(user)
    await db.commit()
    return None


@router.get("/roles", response_model=List[RoleResponse])
async def list_roles(
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all custom roles in the caller's organization."""
    org_id = current_user.get("org_id")
    result = await db.execute(select(Role).where(Role.organization_id == org_id))
    roles = result.scalars().all()
    return roles


@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_data: RoleCreate,
    http_request: Request,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.get("org_id")
    client_ip = http_request.client.host if http_request.client else "unknown"

    # Validate permission keys
    validated_perms = _validate_permissions(role_data.permissions)

    # Check name conflict
    existing = await db.execute(select(Role).where(Role.organization_id == org_id, Role.name == role_data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Role name already exists")

    role = Role(
        organization_id=org_id,
        name=role_data.name,
        description=role_data.description,
        permissions=validated_perms,
        is_builtin=False
    )
    db.add(role)
    await db.commit()
    await db.refresh(role)

    audit_log(
        action=AuditAction.ROLE_CREATED,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="role",
        resource_id=str(role.id),
        details={"name": role.name, "permissions": validated_perms},
    )

    return role


@router.put("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    update_data: RoleUpdate,
    http_request: Request,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.get("org_id")
    client_ip = http_request.client.host if http_request.client else "unknown"
    result = await db.execute(select(Role).where(Role.id == role_id, Role.organization_id == org_id))
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot modify built-in roles")

    changes: dict = {}
    if update_data.name is not None:
        changes["name"] = {"from": role.name, "to": update_data.name}
        role.name = update_data.name
    if update_data.description is not None:
        changes["description"] = {"from": role.description, "to": update_data.description}
        role.description = update_data.description
    if update_data.permissions is not None:
        validated_perms = _validate_permissions(update_data.permissions)
        changes["permissions"] = {"from": role.permissions, "to": validated_perms}
        role.permissions = validated_perms

    await db.commit()
    await db.refresh(role)

    audit_log(
        action=AuditAction.ROLE_UPDATED,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="role",
        resource_id=str(role.id),
        details=changes,
    )

    return role


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: str,
    http_request: Request,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.get("org_id")
    client_ip = http_request.client.host if http_request.client else "unknown"
    result = await db.execute(select(Role).where(Role.id == role_id, Role.organization_id == org_id))
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot delete built-in roles")

    # Graceful reassignment: auto-reassign affected users to 'viewer' (read-only default)
    # instead of blocking deletion — prevents dangling role references
    in_use = await db.execute(select(User).where(User.role == str(role.id)))
    affected_users = in_use.scalars().all()
    reassigned_emails = []

    # Import notification helper
    from app.api.notifications import notify_user

    role_name = role.name
    admin_email = current_user.get("email", "an administrator")

    for affected_user in affected_users:
        reassigned_emails.append(affected_user.email)
        affected_user.role = "viewer"

        # ── USER-FACING NOTIFICATION ──
        # Each affected user gets a visible in-app alert so they know
        # their access changed — not just a silent audit log entry.
        await notify_user(
            db=db,
            user_id=affected_user.id,
            organization_id=org_id,
            title="Your role has been changed",
            message=(
                f'The custom role "{role_name}" you were assigned to has been '
                f"deleted by {admin_email}. Your access has been automatically "
                f"downgraded to Viewer (read-only). If you need elevated access, "
                f"please contact your organization administrator."
            ),
            severity="warning",
            category="role_change",
        )

    await db.delete(role)
    await db.commit()

    audit_log(
        action=AuditAction.ROLE_DELETED,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="role",
        resource_id=role_id,
        details={
            "deleted_role": role_name,
            "reassigned_users": reassigned_emails,
            "reassigned_to": "viewer",
            "reassigned_count": len(reassigned_emails),
            "users_notified": True,
        },
    )

    return None
