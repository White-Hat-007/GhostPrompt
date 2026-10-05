"""
API Key Management Routes

For users to manage their GhostPrompt proxy credentials.

Security:
- API keys are hashed (SHA-256) before storage
- Raw key is shown ONCE at creation, never again
- Keys are scoped per organization
- Creation is rate limited to 5/day per user
- All key operations are audit logged
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Depends
from app.core.permissions import require_permission
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from datetime import datetime, timezone
import secrets
import hashlib

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.rate_limit import limiter
from app.models.api_key import APIKey
from app.security.audit_log import audit_log, AuditAction
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api-keys", tags=["API Keys"], dependencies=[Depends(require_permission("api_keys.manage"))])


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    environment: str = Field(default="PRODUCTION", max_length=50)


from uuid import UUID

class ApiKeyResponse(BaseModel):
    id: UUID
    name: str
    key_prefix: str
    environment: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None

    class Config:
        from_attributes = True


@router.get("", response_model=List[ApiKeyResponse])
async def list_api_keys(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all API keys for the current organization."""
    org_id = current_user.get("org_id")
    result = await db.execute(select(APIKey).where(APIKey.organization_id == org_id))
    return result.scalars().all()


@router.post("", response_model=dict)
@limiter.limit("5/day")
async def create_api_key(
    payload: ApiKeyCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new API key. Only returns the full key once.
    
    Security: The raw key is hashed with SHA-256 before storage.
    The raw key is returned ONCE in the response and never stored.
    """
    org_id = current_user.get("org_id")
    client_ip = request.client.host if request.client else "unknown"
    
    # Check limit (enterprise limit: 50 keys max per org)
    result = await db.execute(select(APIKey).where(APIKey.organization_id == org_id))
    keys = result.scalars().all()
    if len(keys) >= 50:
        raise HTTPException(
            status_code=400,
            detail="Maximum of 50 API keys allowed per organization."
        )
        
    # Generate key: gp-sk-[32 random bytes hex]
    raw_key = f"gp-sk-{secrets.token_hex(32)}"
    key_prefix = f"gp-sk-...{raw_key[-4:]}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    api_key = APIKey(
        organization_id=org_id,
        name=payload.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        environment=payload.environment,
        is_active=True
    )
    db.add(api_key)
    await db.commit()

    audit_log(
        action=AuditAction.API_KEY_CREATED,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="api_key",
        resource_id=str(api_key.id),
        details={"name": payload.name, "environment": payload.environment},
    )
    
    return {
        "id": str(api_key.id),
        "name": api_key.name,
        "key": raw_key,
        "message": "Please copy this key now. You will not be able to see it again."
    }


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    key_id: str,
    http_request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete an API key."""
    org_id = current_user.get("org_id")
    client_ip = http_request.client.host if http_request.client else "unknown"
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.organization_id == org_id)
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    audit_log(
        action=AuditAction.API_KEY_DELETED,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="api_key",
        resource_id=str(api_key.id),
        details={"name": api_key.name},
    )
        
    await db.delete(api_key)
    await db.commit()
    return None


@router.post("/rotate-all", status_code=status.HTTP_200_OK)
async def rotate_all_api_keys(
    http_request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete all API keys for the current organization."""
    org_id = current_user.get("org_id")
    client_ip = http_request.client.host if http_request.client else "unknown"
    
    result = await db.execute(
        select(APIKey).where(APIKey.organization_id == org_id)
    )
    keys = result.scalars().all()
    
    for key in keys:
        await db.delete(key)
        
    await db.commit()
    
    audit_log(
        action=AuditAction.API_KEY_DELETED,
        actor_id=current_user.get("user_id"),
        actor_email=current_user.get("email"),
        ip_address=client_ip,
        resource_type="organization",
        resource_id=str(org_id),
        details={"message": f"Rotated (deleted) all {len(keys)} API keys."},
    )
    
    return {"status": "success", "message": f"Rotated {len(keys)} API keys"}
