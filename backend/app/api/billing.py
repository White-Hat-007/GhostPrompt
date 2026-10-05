from fastapi import APIRouter, Depends, HTTPException, status, Request, Depends
from app.core.permissions import require_permission
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.organization import Organization
from app.security.audit_log import audit_log, AuditAction
from pydantic import BaseModel, Field

router = APIRouter(prefix="/billing", tags=["Billing"], dependencies=[Depends(require_permission("billing.manage"))])

class SubscriptionRequest(BaseModel):
    interval: str = Field(..., pattern=r"^(monthly|quarterly|biannual|yearly)$")

class SubscriptionResponse(BaseModel):
    status: str
    plan: str
    interval: str
    end_date: datetime
    message: str

# Server-side source of truth for pricing. Client values are never trusted.
PRICING_PLANS = {
    "monthly": {"price": 99, "days": 30, "plan_name": "pro"},
    "quarterly": {"price": 279, "days": 90, "plan_name": "pro"},
    "biannual": {"price": 499, "days": 180, "plan_name": "pro"},
    "yearly": {"price": 899, "days": 365, "plan_name": "pro"},
}

@router.get("/plans")
async def get_plans():
    """Return available subscription plans."""
    return {
        "monthly": {"name": "Monthly", "price": PRICING_PLANS["monthly"]["price"], "interval": "monthly"},
        "quarterly": {"name": "3 Months", "price": PRICING_PLANS["quarterly"]["price"], "interval": "quarterly"},
        "biannual": {"name": "6 Months", "price": PRICING_PLANS["biannual"]["price"], "interval": "biannual"},
        "yearly": {"name": "Yearly", "price": PRICING_PLANS["yearly"]["price"], "interval": "yearly"},
    }

@router.post("/subscribe", response_model=SubscriptionResponse)
async def subscribe(
    request: SubscriptionRequest,
    http_request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Mock checkout flow for subscribing to a plan.
    In production, this would generate a Stripe Checkout Session URL.
    
    Security:
    - Server-side validation of pricing interval (no arbitrary client intervals)
    - Action is audit logged
    """
    if request.interval not in PRICING_PLANS:
        raise HTTPException(status_code=400, detail="Invalid subscription interval")
        
    user_id = current_user["user_id"]
    client_ip = http_request.client.host if http_request.client else "unknown"

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    org_result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
    org = org_result.scalar_one_or_none()
    
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    # Security: Require owner role for billing changes
    if current_user.get("role") != "owner":
        audit_log(
            action=AuditAction.AUTHORIZATION_FAILURE,
            actor_id=user_id,
            actor_email=user.email,
            ip_address=client_ip,
            details={"action": "subscribe", "role": current_user.get("role")}
        )
        raise HTTPException(status_code=403, detail="Only organization owners can modify subscriptions")

    # Mocking successful payment and applying subscription immediately
    plan_config = PRICING_PLANS[request.interval]
    days_to_add = plan_config["days"]
    old_plan = org.plan
    old_interval = org.subscription_interval
    
    org.plan = plan_config["plan_name"]
    org.subscription_status = "active"
    org.subscription_interval = request.interval
    org.subscription_end_date = datetime.now(timezone.utc) + timedelta(days=days_to_add)
    
    await db.commit()
    
    audit_log(
        action=AuditAction.ORG_PLAN_CHANGED,
        actor_id=user_id,
        actor_email=user.email,
        ip_address=client_ip,
        resource_type="organization",
        resource_id=str(org.id),
        details={
            "old_plan": old_plan, 
            "new_plan": org.plan, 
            "old_interval": old_interval,
            "new_interval": org.subscription_interval,
            "end_date": org.subscription_end_date.isoformat()
        }
    )
    
    return SubscriptionResponse(
        status=org.subscription_status,
        plan=org.plan,
        interval=org.subscription_interval,
        end_date=org.subscription_end_date,
        message="Subscription activated successfully! You now have full access to the AI Firewall."
    )

@router.get("/status")
async def get_subscription_status(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get the current organization's subscription status."""
    user_id = current_user["user_id"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    org_result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
    org = org_result.scalar_one_or_none()
    
    return {
        "plan": org.plan,
        "status": org.subscription_status,
        "interval": org.subscription_interval,
        "end_date": org.subscription_end_date,
        "is_active": org.subscription_status == "active" and (org.subscription_end_date is None or org.subscription_end_date > datetime.now(timezone.utc))
    }


@router.get("/usage")
async def get_usage(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get usage summary for the current org — billing dashboard data."""
    user_id = current_user["user_id"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    org_result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Try stripe_service for live usage, fallback to org DB data
    try:
        from app.billing.stripe_service import stripe_service
        usage = stripe_service.get_usage_summary(str(org.id))
        return usage
    except Exception:
        pass

    # Fallback: derive from org model
    plan_limits = {"free": 1000, "pro": 50000, "business": 500000, "enterprise": 0}
    plan_seats = {"free": 1, "pro": 5, "business": 25, "enterprise": 999}
    scan_limit = plan_limits.get(org.plan, 1000)

    return {
        "plan": org.plan,
        "status": org.subscription_status or "active",
        "scan_usage": getattr(org, "scan_count", 0) or 0,
        "scan_limit": scan_limit,
        "usage_pct": 0,
        "seats_used": 1,
        "seats_limit": plan_seats.get(org.plan, 1),
        "billing_period": {
            "start": None,
            "end": org.subscription_end_date.isoformat() if org.subscription_end_date else None,
        },
    }


class CheckoutRequest(BaseModel):
    plan: str
    success_url: str = ""
    cancel_url: str = ""
    bypass_mode: bool = True


@router.post("/checkout")
async def create_checkout(
    request: CheckoutRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a checkout session — in bypass mode, instantly upgrades the plan."""
    user_id = current_user["user_id"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    org_result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    valid_plans = {"free", "pro", "business", "enterprise"}
    if request.plan not in valid_plans:
        raise HTTPException(status_code=400, detail=f"Invalid plan: {request.plan}")

    if request.bypass_mode or True:  # Always bypass for now (no Stripe keys)
        old_plan = org.plan
        org.plan = request.plan
        org.subscription_status = "active"
        org.subscription_end_date = datetime.now(timezone.utc) + timedelta(days=365)
        await db.commit()

        # Also update stripe_service in-memory
        try:
            from app.billing.stripe_service import stripe_service
            sub = stripe_service.get_subscription(str(org.id))
            sub.plan = request.plan
            sub.status = "active"
        except Exception:
            pass

        return {
            "status": "success",
            "plan": request.plan,
            "mode": "bypass",
            "message": f"Upgraded from {old_plan} to {request.plan} (bypass mode — no payment)",
        }

    # Real Stripe flow would go here
    raise HTTPException(status_code=501, detail="Stripe not configured")
