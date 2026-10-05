from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.permissions import require_permission
from app.models.user import User
from app.models.api_key import APIKey
from app.core.logging import get_logger
from app.security.audit_log import audit_log, AuditAction
from pydantic import BaseModel

from app.core.config import get_settings

settings = get_settings()
logger = get_logger("killswitch")
router = APIRouter(
    prefix="/killswitch",
    tags=["Incident Response"],
    dependencies=[Depends(require_permission("incidents.manage"))],
)

class KillswitchRequest(BaseModel):
    reason: str
    confirmation: str

@router.post("/activate")
async def activate_killswitch(
    payload: KillswitchRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Layer 16: Incident Response & Disaster Recovery.
    Instantly disables ALL API keys across the entire platform.
    Requires superadmin privileges and explicit confirmation.
    """
    # Security: Verify superadmin by email, not role (role "superadmin" doesn't exist in JWT)
    if current_user.get("email") != settings.SUPERADMIN_EMAIL:
        audit_log(
            action=AuditAction.AUTHORIZATION_FAILURE,
            actor_id=current_user.get("user_id"),
            actor_email=current_user.get("email"),
            ip_address=request.client.host if request.client else "unknown",
            details={"attempted_resource": "killswitch"},
            outcome="denied",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the platform super admin can trigger the killswitch.")
        
    if payload.confirmation != "I_CONFIRM_PLATFORM_SHUTDOWN":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid confirmation string.")
        
    client_ip = request.client.host if request.client else "unknown"
    
    logger.critical("KILLSWITCH_ACTIVATED", user_id=current_user["user_id"], reason=payload.reason, ip=client_ip)
    
    # Disable all API keys
    await db.execute(update(APIKey).values(is_active=False))
    await db.commit()
    
    audit_log(
        action=AuditAction.SECURITY_EVENT,
        actor_id=current_user["user_id"],
        actor_email=current_user.get("email", "unknown"),
        ip_address=client_ip,
        resource_type="platform",
        resource_id="global",
        outcome="killswitch_activated",
        details={"reason": payload.reason}
    )
    
    return {"status": "success", "message": "Killswitch activated. All API keys disabled."}
