from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
import datetime
from app.core.database import get_db
from app.core.security import require_plan
from app.models.provider_config import ProviderConfig

router = APIRouter(
    prefix="/providers",
    tags=["AI Providers"],
    dependencies=[Depends(require_plan("starter"))]
)

class ProviderConfigRequest(BaseModel):
    provider_id: str
    api_key: str
    is_active: bool = True

class ProviderConfigResponse(BaseModel):
    provider_id: str
    api_key: str | None
    is_active: bool
    configured: bool

@router.get("", response_model=Dict[str, List[ProviderConfigResponse]])
async def get_providers(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_plan("starter"))
):
    """Get all configured providers for the organization."""
    result = await db.execute(
        select(ProviderConfig)
        .where(ProviderConfig.organization_id == current_user.organization_id)
    )
    configs = result.scalars().all()
    
    # Return masked representation
    return {
        "providers": [
            {
                "provider_id": c.provider_id,
                "api_key": c.to_dict(mask_key=True).get("api_key"),
                "is_active": c.is_active,
                "configured": True,
            }
            for c in configs
        ]
    }

@router.post("", response_model=ProviderConfigResponse)
async def update_provider(
    payload: ProviderConfigRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_plan("starter"))
):
    """Update or create a provider configuration."""
    if not payload.api_key:
        raise HTTPException(status_code=400, detail="API key is required")
        
    result = await db.execute(
        select(ProviderConfig)
        .where(
            ProviderConfig.organization_id == current_user.organization_id,
            ProviderConfig.provider_id == payload.provider_id
        )
    )
    config = result.scalar_one_or_none()
    
    if config:
        config.api_key = payload.api_key
        config.is_active = payload.is_active
        config.updated_at = datetime.datetime.now(datetime.timezone.utc)
    else:
        config = ProviderConfig(
            organization_id=current_user.organization_id,
            provider_id=payload.provider_id,
            is_active=payload.is_active
        )
        config.api_key = payload.api_key
        db.add(config)
        
    await db.commit()
    
    return {
        "provider_id": config.provider_id,
        "api_key": config.to_dict(mask_key=True).get("api_key"),
        "is_active": config.is_active,
        "configured": True,
    }
