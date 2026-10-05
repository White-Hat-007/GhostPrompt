"""
Global Super Admin Routes

Platform-wide management for the GhostPrompt system owner.

Security:
- Super admin email loaded from env config (not hardcoded)
- All actions audit logged
- Role whitelist prevents invalid role assignment
- Self-deletion guard
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.core.database import get_db
from app.core.config import get_settings
from app.core.security import get_current_user
from app.models.user import User
from app.models.organization import Organization
from app.schemas.schemas import UserResponse
from app.security.audit_log import audit_log, AuditAction
from pydantic import BaseModel, Field

settings = get_settings()
router = APIRouter(prefix="/superadmin", tags=["Super Admin"])

VALID_ROLES = {"owner", "admin", "analyst", "viewer"}


def require_superadmin(current_user: dict = Depends(get_current_user)):
    """
    The system owner has full global access.
    Security: Email is loaded from settings, not hardcoded.
    """
    if current_user.get("email") != settings.SUPERADMIN_EMAIL:
        audit_log(
            action=AuditAction.AUTHORIZATION_FAILURE,
            actor_id=current_user.get("user_id"),
            actor_email=current_user.get("email"),
            details={"attempted_resource": "superadmin"},
            outcome="denied",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super Admin privileges required."
        )
    return current_user


@router.get("/organizations")
async def list_organizations(
    current_user: dict = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """List all organizations on the platform."""
    result = await db.execute(select(Organization))
    orgs = result.scalars().all()
    return orgs


@router.delete("/organizations/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    org_id: str,
    http_request: Request,
    current_user: dict = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """Delete an organization and all its data (cascades)."""
    client_ip = http_request.client.host if http_request.client else "unknown"
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    audit_log(
        action=AuditAction.ORG_DELETED,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="organization",
        resource_id=str(org.id),
        details={"org_name": org.name, "org_slug": org.slug},
    )

    await db.delete(org)
    await db.commit()
    return None


@router.get("/users")
async def list_all_users(
    current_user: dict = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """List all users across all organizations."""
    result = await db.execute(
        select(User, Organization.name).join(
            Organization, User.organization_id == Organization.id
        )
    )
    rows = result.all()
    
    users = []
    for user, org_name in rows:
        user_dict = {
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "organization": org_name,
            "created_at": user.created_at.isoformat() if user.created_at else None
        }
        users.append(user_dict)
    return users


class SuperAdminUserUpdate(BaseModel):
    """Explicit whitelist of updatable fields with validation."""
    role: Optional[str] = Field(None, pattern=r"^(owner|admin|analyst|viewer)$")
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None


@router.put("/users/{user_id}")
async def superadmin_update_user(
    user_id: str,
    update_data: SuperAdminUserUpdate,
    http_request: Request,
    current_user: dict = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """Update any user on the platform."""
    client_ip = http_request.client.host if http_request.client else "unknown"
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    changes = {}
    if update_data.role is not None:
        if update_data.role not in VALID_ROLES:
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
        action=AuditAction.SUPERADMIN_ACTION,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="user",
        resource_id=str(user.id),
        details={"action": "update_user", "changes": changes},
    )

    return {"status": "success"}


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def superadmin_delete_user(
    user_id: str,
    http_request: Request,
    current_user: dict = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """Delete any user on the platform."""
    client_ip = http_request.client.host if http_request.client else "unknown"
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Self-deletion guard
    if str(user.id) == current_user.get("user_id"):
        raise HTTPException(status_code=400, detail="Cannot delete your own super admin account")

    audit_log(
        action=AuditAction.SUPERADMIN_ACTION,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="user",
        resource_id=str(user.id),
        details={"action": "delete_user", "deleted_email": user.email},
    )

    await db.delete(user)
    await db.commit()
    return None
