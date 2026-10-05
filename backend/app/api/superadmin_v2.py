"""
Super-Admin API — Founder Console

Endpoints exclusive to the platform founder (super_admin):
- Platform-wide org management + per-org drill-down
- User impersonation with audit trail
- Platform analytics (MRR/ARR/growth/churn)
- Broadcast announcements
- Feature flags
- Global kill switches
- System metrics
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.core.permissions import is_super_admin
from app.core.security import get_current_user
from app.models.organization import Organization
from app.models.user import User

logger = get_logger("api.superadmin_v2")
settings = get_settings()
router = APIRouter(prefix="/super-admin", tags=["Super Admin"])


def _require_superadmin(current_user: dict):
    """Inline super-admin check — delegates to single source of truth."""
    if not is_super_admin(current_user):
        raise HTTPException(403, "Super-admin access required")


# ── Schemas ──

class OrgOverride(BaseModel):
    plan: str | None = None
    scan_limit: int | None = None
    is_active: bool | None = None


class FeatureFlagUpdate(BaseModel):
    name: str
    enabled: bool
    description: str | None = None
    rollout_pct: float = 100.0


class BroadcastRequest(BaseModel):
    title: str
    message: str
    severity: str = "info"  # info, warning, critical
    target: str = "all"  # all, pro, enterprise


# ── In-memory feature flags ──
_feature_flags: dict[str, dict] = {
    "federation_enabled": {"enabled": True, "description": "Federated threat intelligence sharing", "rollout_pct": 100},
    "adaptive_ml": {"enabled": True, "description": "Automatic ML threshold tuning", "rollout_pct": 100},
    "gpu_training": {"enabled": True, "description": "Per-tenant LoRA/PEFT training on GPU", "rollout_pct": 100},
    "precision_globe": {"enabled": False, "description": "CesiumJS satellite-precision globe", "rollout_pct": 0},
    "stripe_billing": {"enabled": False, "description": "Live Stripe payment processing", "rollout_pct": 0},
    "multimodal_scanning": {"enabled": True, "description": "Image/audio/video scanning", "rollout_pct": 100},
    "zero_day_detector": {"enabled": True, "description": "Embedding-based zero-day attack detection", "rollout_pct": 100},
}

# ── In-memory broadcasts ──
_broadcasts: list[dict] = []


# ══════════════════════════════════════════════════════════════════════════
# PLATFORM OVERVIEW
# ══════════════════════════════════════════════════════════════════════════

@router.get("/overview")
async def platform_overview(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get platform-wide overview — founder only."""
    _require_superadmin(current_user)

    org_count = await db.execute(select(func.count(Organization.id)))
    user_count = await db.execute(select(func.count(User.id)))

    plan_dist = await db.execute(
        select(Organization.plan, func.count(Organization.id))
        .group_by(Organization.plan)
    )

    return {
        "platform": {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "env": settings.APP_ENV,
        },
        "stats": {
            "total_organizations": org_count.scalar() or 0,
            "total_users": user_count.scalar() or 0,
            "plan_distribution": {row[0]: row[1] for row in plan_dist.all()},
        },
        "feature_flags": _feature_flags,
        "config": {
            "firewall_mode": settings.FIREWALL_MODE,
            "threat_threshold": settings.THREAT_SCORE_THRESHOLD,
            "max_prompt_length": settings.MAX_PROMPT_LENGTH,
            "gpu_available": True,
            "stripe_configured": bool(
                __import__('os').environ.get("STRIPE_SECRET_KEY")
            ),
        },
    }


# ══════════════════════════════════════════════════════════════════════════
# ORGANIZATION MANAGEMENT + PER-ORG DRILL-DOWN
# ══════════════════════════════════════════════════════════════════════════

@router.get("/organizations")
async def list_all_orgs(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all organizations with user counts — founder only."""
    _require_superadmin(current_user)

    result = await db.execute(
        select(Organization).order_by(Organization.created_at.desc())
    )
    orgs = result.scalars().all()

    org_list = []
    for o in orgs:
        uc = await db.execute(
            select(func.count(User.id)).where(User.organization_id == o.id)
        )
        org_list.append({
            "id": str(o.id),
            "name": o.name,
            "slug": o.slug,
            "plan": o.plan,
            "is_active": o.is_active if hasattr(o, 'is_active') else True,
            "user_count": uc.scalar() or 0,
            "created_at": o.created_at.isoformat() if o.created_at else None,
        })

    return org_list


@router.get("/organizations/{org_id}/details")
async def org_drill_down(
    org_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Per-org drill-down: members, usage stats, billing, API keys, recent audit logs.
    This is the rich detail view when a founder clicks on an org row.
    """
    _require_superadmin(current_user)

    # Org info
    org_res = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_res.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")

    # Members
    users_res = await db.execute(select(User).where(User.organization_id == org_id))
    members = [
        {
            "id": str(u.id), "email": u.email, "full_name": u.full_name,
            "role": u.role, "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users_res.scalars().all()
    ]

    # Scan stats
    total_scans = 0
    blocked_scans = 0
    try:
        from app.models.scan_event import ScanEvent
        sc = await db.execute(
            select(func.count(ScanEvent.id)).where(ScanEvent.organization_id == org_id)
        )
        total_scans = sc.scalar() or 0
        bc = await db.execute(
            select(func.count(ScanEvent.id)).where(
                ScanEvent.organization_id == org_id,
                ScanEvent.action == "blocked"
            )
        )
        blocked_scans = bc.scalar() or 0
    except Exception:
        pass

    # API keys count
    api_key_count = 0
    try:
        from app.models.api_key import APIKey
        akc = await db.execute(
            select(func.count(APIKey.id)).where(APIKey.organization_id == org_id)
        )
        api_key_count = akc.scalar() or 0
    except Exception:
        pass

    # Recent audit logs
    recent_audit = []
    try:
        from app.models.audit_log import AuditLog
        ar = await db.execute(
            select(AuditLog).where(AuditLog.organization_id == org_id)
            .order_by(AuditLog.created_at.desc()).limit(20)
        )
        recent_audit = [
            {
                "id": str(a.id), "action": a.action,
                "details": a.details if hasattr(a, 'details') else "",
                "user_email": a.user_email if hasattr(a, 'user_email') else "",
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in ar.scalars().all()
        ]
    except Exception:
        pass

    # MRR
    plan_prices = {"free": 0, "starter": 49, "pro": 199, "enterprise": 799}
    mrr = plan_prices.get(org.plan, 0)

    return {
        "organization": {
            "id": str(org.id), "name": org.name, "slug": org.slug,
            "plan": org.plan, "is_active": org.is_active,
            "stripe_customer_id": org.stripe_customer_id,
            "subscription_status": org.subscription_status,
            "created_at": org.created_at.isoformat() if org.created_at else None,
        },
        "members": members,
        "usage": {
            "total_scans": total_scans,
            "blocked_scans": blocked_scans,
            "api_key_count": api_key_count,
            "max_requests_per_day": org.max_requests_per_day,
        },
        "billing": {
            "plan": org.plan,
            "mrr": mrr,
            "arr": mrr * 12,
        },
        "recent_audit": recent_audit,
    }


@router.patch("/organizations/{org_id}")
async def override_org(
    org_id: str,
    override: OrgOverride,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Override org settings — plan, limits, active status."""
    _require_superadmin(current_user)

    update_data = {k: v for k, v in override.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(400, "No fields to update")

    await db.execute(
        update(Organization).where(Organization.id == org_id).values(**update_data)
    )
    await db.commit()

    logger.info("superadmin_org_override", org_id=org_id, overrides=update_data)
    return {"status": "updated", "org_id": org_id, "overrides": update_data}


# ══════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT + IMPERSONATION WITH AUDIT TRAIL
# ══════════════════════════════════════════════════════════════════════════

@router.get("/users")
async def list_all_users(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all users — founder only."""
    _require_superadmin(current_user)

    result = await db.execute(
        select(User).order_by(User.created_at.desc())
    )
    users = result.scalars().all()

    return [
        {
            "id": str(u.id),
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "is_active": u.is_active,
            "is_verified": u.is_verified if hasattr(u, 'is_verified') else True,
            "org_id": str(u.organization_id) if u.organization_id else None,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


@router.post("/users/{user_id}/impersonate")
async def impersonate_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a temporary impersonation token — founder only. Logged to audit trail."""
    _require_superadmin(current_user)

    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(404, "User not found")

    from datetime import timedelta

    from app.core.security import create_access_token

    # Impersonation tokens are:
    # 1. Short-lived (15 minutes max — non-configurable for safety)
    # 2. Marked with is_impersonation=True to prevent escalation
    # 3. Scoped to target's role (cannot grant super-admin through impersonation)
    IMPERSONATION_EXPIRY_MINUTES = 15
    token = create_access_token(
        data={
            "sub": str(target.id),
            "email": target.email,
            "role": target.role,
            "org_id": str(target.organization_id) if target.organization_id else None,
            "impersonated_by": current_user.get("email"),
            "is_impersonation": True,  # Prevents access to super-admin routes
        },
        expires_delta=timedelta(minutes=IMPERSONATION_EXPIRY_MINUTES),
    )

    # Persist audit log for impersonation
    try:
        from app.models.audit_log import AuditLog
        audit_entry = AuditLog(
            organization_id=target.organization_id,
            user_email=current_user.get("email"),
            action="user_impersonation",
            details=f"Super-admin {current_user.get('email')} impersonated {target.email} (user_id={user_id}), expires in {IMPERSONATION_EXPIRY_MINUTES}min",
        )
        db.add(audit_entry)
        await db.commit()
    except Exception as e:
        logger.warning("audit_log_failed_for_impersonation", error=str(e))

    logger.warning(
        "superadmin_impersonation",
        admin_email=current_user.get("email"),
        target_email=target.email,
        target_id=str(target.id),
    )

    return {
        "impersonation_token": token,
        "target_email": target.email,
        "target_role": target.role,
        "expires_in_minutes": IMPERSONATION_EXPIRY_MINUTES,
        "is_impersonation": True,
        "warning": "This action has been logged for audit compliance. Token is time-boxed and cannot escalate privileges.",
    }


# ══════════════════════════════════════════════════════════════════════════
# PLATFORM ANALYTICS — MRR/ARR/GROWTH/CHURN
# ══════════════════════════════════════════════════════════════════════════

@router.get("/analytics")
async def platform_analytics(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Platform-wide analytics — MRR, ARR, growth, churn, aggregate threats."""
    _require_superadmin(current_user)

    plan_prices = {"free": 0, "starter": 49, "pro": 199, "enterprise": 799}

    result = await db.execute(select(Organization))
    orgs = result.scalars().all()

    total_mrr = sum(plan_prices.get(o.plan, 0) for o in orgs)
    total_arr = total_mrr * 12
    active_count = sum(1 for o in orgs if o.is_active)
    churned_count = sum(1 for o in orgs if not o.is_active)

    plan_breakdown = {}
    for o in orgs:
        plan_breakdown[o.plan] = plan_breakdown.get(o.plan, 0) + 1

    user_count = await db.execute(select(func.count(User.id)))

    total_scans = 0
    total_blocked = 0
    try:
        from app.models.scan_event import ScanEvent
        sc = await db.execute(select(func.count(ScanEvent.id)))
        total_scans = sc.scalar() or 0
        bc = await db.execute(
            select(func.count(ScanEvent.id)).where(ScanEvent.action == "blocked")
        )
        total_blocked = bc.scalar() or 0
    except Exception:
        pass

    return {
        "revenue": {
            "mrr": total_mrr,
            "arr": total_arr,
            "mrr_formatted": f"${total_mrr:,.0f}",
            "arr_formatted": f"${total_arr:,.0f}",
        },
        "organizations": {
            "total": len(orgs),
            "active": active_count,
            "churned": churned_count,
            "churn_rate": round(churned_count / max(len(orgs), 1) * 100, 1),
            "plan_breakdown": plan_breakdown,
        },
        "users": {
            "total": user_count.scalar() or 0,
        },
        "threats": {
            "total_scans": total_scans,
            "total_blocked": total_blocked,
        },
    }


# ══════════════════════════════════════════════════════════════════════════
# BROADCAST ANNOUNCEMENTS
# ══════════════════════════════════════════════════════════════════════════

@router.get("/broadcasts")
async def get_broadcasts(
    current_user: dict = Depends(get_current_user),
):
    """Get all platform announcements."""
    _require_superadmin(current_user)
    return _broadcasts


@router.post("/broadcasts")
async def create_broadcast(
    req: BroadcastRequest,
    current_user: dict = Depends(get_current_user),
):
    """Create a platform-wide announcement."""
    _require_superadmin(current_user)

    broadcast = {
        "id": f"bc_{len(_broadcasts)+1}_{int(datetime.now(timezone.utc).timestamp())}",
        "title": req.title,
        "message": req.message,
        "severity": req.severity,
        "target": req.target,
        "created_by": current_user.get("email"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _broadcasts.insert(0, broadcast)
    logger.info("broadcast_created", title=req.title, by=current_user.get("email"))
    return broadcast


@router.delete("/broadcasts/{broadcast_id}")
async def delete_broadcast(
    broadcast_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Delete a broadcast announcement."""
    _require_superadmin(current_user)
    global _broadcasts
    _broadcasts = [b for b in _broadcasts if b["id"] != broadcast_id]
    return {"status": "deleted"}


@router.get("/announcements")
async def get_announcements_for_user(
    current_user: dict = Depends(get_current_user),
):
    """Get active announcements for current user (non-admin endpoint)."""
    user_plan = current_user.get("plan", "free")
    return [
        b for b in _broadcasts
        if b["target"] == "all" or b["target"] == user_plan
    ]


# ══════════════════════════════════════════════════════════════════════════
# FEATURE FLAGS
# ══════════════════════════════════════════════════════════════════════════

@router.get("/feature-flags")
async def get_feature_flags(
    current_user: dict = Depends(get_current_user),
):
    _require_superadmin(current_user)
    return _feature_flags


@router.put("/feature-flags")
async def update_feature_flag(
    flag: FeatureFlagUpdate,
    current_user: dict = Depends(get_current_user),
):
    _require_superadmin(current_user)

    _feature_flags[flag.name] = {
        "enabled": flag.enabled,
        "description": flag.description or _feature_flags.get(flag.name, {}).get("description", ""),
        "rollout_pct": flag.rollout_pct,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "updated_by": current_user.get("email"),
    }

    logger.info("feature_flag_updated", flag=flag.name, enabled=flag.enabled, by=current_user.get("email"))
    return {"status": "updated", "flag": flag.name, "enabled": flag.enabled}


# ══════════════════════════════════════════════════════════════════════════
# SYSTEM HEALTH (DEEP)
# ══════════════════════════════════════════════════════════════════════════

@router.get("/health-deep")
async def deep_health_check(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Deep health check with service status — founder only."""
    _require_superadmin(current_user)

    checks = {}

    # Database
    try:
        await db.execute(select(func.count(User.id)))
        checks["database"] = {"status": "healthy", "type": "postgresql"}
    except Exception as e:
        checks["database"] = {"status": "unhealthy", "error": str(e)}

    # Redis
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        await redis.ping()
        checks["redis"] = {"status": "healthy"}
    except Exception as e:
        checks["redis"] = {"status": "unhealthy", "error": str(e)}

    # GPU
    try:
        import torch
        if torch.cuda.is_available():
            checks["gpu"] = {
                "status": "healthy",
                "device": torch.cuda.get_device_name(0),
                "memory_total_gb": round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2),
            }
        else:
            checks["gpu"] = {"status": "unavailable", "message": "No CUDA GPU"}
    except Exception:
        checks["gpu"] = {"status": "unavailable", "message": "PyTorch not available"}

    # Firewall
    checks["firewall"] = {
        "status": "active" if settings.FIREWALL_ENABLED else "disabled",
        "mode": settings.FIREWALL_MODE,
    }

    all_healthy = all(
        c.get("status") in ("healthy", "active")
        for c in checks.values()
    )

    return {
        "overall": "healthy" if all_healthy else "degraded",
        "services": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
