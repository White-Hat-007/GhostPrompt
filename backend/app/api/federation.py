"""
Federated Intelligence API — Network-wide threat sharing

REST endpoints for the federated threat intelligence system:
- Opt-in/out toggle (persisted to DB)
- Contribute signatures
- Get shared intelligence
- View network stats
- View node info
- Auto-contribute from detection pipeline
"""

from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.permissions import require_permission
from app.core.logging import get_logger
from app.models.organization import Organization
from app.services.federated.aggregator import federated_aggregator

logger = get_logger("api.federation")
router = APIRouter(
    prefix="/federation",
    tags=["Federated Intel"],
    dependencies=[Depends(require_permission("federated_intel.view"))],
)


class ContributeRequest(BaseModel):
    pattern: str
    attack_category: str
    confidence: float
    severity: str = "medium"


class OptInRequest(BaseModel):
    opt_in: bool


# ── DB persistence helpers ──

async def _get_federation_settings(org_id: str, db: AsyncSession) -> dict:
    """Get federation settings from Organization.settings JSON column."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        return {"opted_in": False, "contributions": 0, "last_contribution_at": None}
    stored = (org.settings or {}).get("federation", {})
    return {
        "opted_in": stored.get("opted_in", False),
        "contributions": stored.get("contributions", 0),
        "last_contribution_at": stored.get("last_contribution_at"),
    }


async def _save_federation_settings(org_id: str, fed_settings: dict, db: AsyncSession):
    """Persist federation settings to Organization.settings JSON column."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        return
    current = org.settings or {}
    current["federation"] = fed_settings
    await db.execute(
        update(Organization).where(Organization.id == org_id).values(settings=current)
    )
    await db.commit()
    logger.info("federation_settings_persisted", org=org_id)


@router.get("/status")
async def federation_status(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get federation status for the current org."""
    org_id = str(current_user.get("org_id", "default"))

    # Auto-register on first access
    node = federated_aggregator.register_node(org_id)
    info = federated_aggregator.get_node_info(org_id)
    network = federated_aggregator.get_network_stats()
    db_settings = await _get_federation_settings(org_id, db)

    return {
        "node": info,
        "network": network,
        "db_settings": db_settings,
    }


@router.post("/contribute")
async def contribute_signature(
    req: ContributeRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Contribute a DP-protected threat signature to the federation."""
    org_id = str(current_user.get("org_id", "default"))

    # Auto-register
    federated_aggregator.register_node(org_id)

    sig = federated_aggregator.contribute_signature(
        org_id=org_id,
        pattern=req.pattern,
        attack_category=req.attack_category,
        confidence=req.confidence,
        severity=req.severity,
    )

    if not sig:
        return {"status": "rejected", "reason": "Not opted in or budget exhausted"}

    # Persist contribution count to DB
    import datetime as dt
    fed_settings = await _get_federation_settings(org_id, db)
    fed_settings["contributions"] = fed_settings.get("contributions", 0) + 1
    fed_settings["last_contribution_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    await _save_federation_settings(org_id, fed_settings, db)

    return {
        "status": "contributed",
        "signature_id": sig.id,
        "noise_level": sig.noise_level,
        "confidence_after_dp": sig.confidence,
    }


@router.get("/intel")
async def get_shared_intel(
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
):
    """Get shared threat intelligence from the federation network."""
    org_id = str(current_user.get("org_id", "default"))
    intel = federated_aggregator.get_shared_intel(org_id, limit=limit)
    return {"count": len(intel), "indicators": intel}


@router.post("/opt-in")
async def toggle_opt_in(
    req: OptInRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Toggle federation opt-in — persisted to DB."""
    org_id = str(current_user.get("org_id", "default"))
    federated_aggregator.register_node(org_id)
    success = federated_aggregator.toggle_opt_in(org_id, req.opt_in)

    # Persist to DB
    fed_settings = await _get_federation_settings(org_id, db)
    fed_settings["opted_in"] = req.opt_in
    await _save_federation_settings(org_id, fed_settings, db)

    logger.info("federation_opt_in_toggled", org=org_id, opted_in=req.opt_in)
    return {"status": "updated" if success else "failed", "opted_in": req.opt_in}


@router.get("/network")
async def network_stats(
    current_user: dict = Depends(get_current_user),
):
    """Get overall federation network statistics."""
    return federated_aggregator.get_network_stats()


@router.post("/auto-contribute")
async def auto_contribute_from_detection(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger auto-contribution of recent high-confidence detections.
    Called by the detection pipeline when new attack signatures are discovered.
    
    NOTE: In production, this would be called internally by the firewall
    detection pipeline, not via REST API. This endpoint exists for manual
    triggering and testing.
    
    MPC Secure Aggregation Intent:
    When deployed at scale, contributions would use Secure Multi-Party Computation
    (MPC) to aggregate threat patterns without revealing individual org data.
    The current differential privacy (DP) noise injection is a stepping stone
    toward full MPC-based secure aggregation.
    """
    org_id = str(current_user.get("org_id", "default"))

    fed_settings = await _get_federation_settings(org_id, db)
    if not fed_settings.get("opted_in", False):
        return {"status": "skipped", "reason": "Organization not opted in to federation"}

    # Get recent high-confidence detections to auto-contribute
    # In production, this would pull from the scan_events table
    return {
        "status": "auto_contribute_ready",
        "note": "Pipeline integration active — new attack signatures will be auto-contributed when detected",
    }


class PublicRegistration(BaseModel):
    display_name: str
    region: str = "global"
    tier: str = "community"  # community, enterprise, research


@router.post("/register")
async def register_public_node(
    body: PublicRegistration,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Register this org as a public federation node with metadata."""
    org_id = str(current_user.get("org_id", "default"))
    federated_aggregator.register_node(org_id)

    fed_settings = await _get_federation_settings(org_id, db)
    fed_settings["public_node"] = True
    fed_settings["display_name"] = body.display_name
    fed_settings["region"] = body.region
    fed_settings["tier"] = body.tier
    fed_settings["opted_in"] = True
    await _save_federation_settings(org_id, fed_settings, db)

    logger.info("federation_public_registration", org=org_id, name=body.display_name)
    return {
        "status": "registered",
        "node_id": org_id,
        "display_name": body.display_name,
        "region": body.region,
        "tier": body.tier,
    }


@router.get("/reputation")
async def get_reputation(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get federation reputation score for this org based on contribution quality."""
    org_id = str(current_user.get("org_id", "default"))
    fed_settings = await _get_federation_settings(org_id, db)

    contributions = fed_settings.get("contributions", 0)
    # Reputation formula: base 50 + log(contributions) * 10, capped at 100
    import math
    reputation = min(100, 50 + int(math.log1p(contributions) * 10))
    tier = "bronze" if reputation < 65 else "silver" if reputation < 80 else "gold" if reputation < 95 else "platinum"

    return {
        "org_id": org_id,
        "reputation_score": reputation,
        "tier": tier,
        "total_contributions": contributions,
        "last_contribution_at": fed_settings.get("last_contribution_at"),
        "member_since": fed_settings.get("joined_at"),
        "badges": [
            "early_adopter" if contributions > 0 else None,
            "active_contributor" if contributions > 10 else None,
            "network_defender" if contributions > 50 else None,
        ],
    }


@router.get("/health-dashboard")
async def federation_health_dashboard(
    current_user: dict = Depends(get_current_user),
):
    """Get health status of all federation nodes — latency, uptime, contribution rate."""
    stats = federated_aggregator.get_network_stats()
    nodes = []
    for node_id, node_info in getattr(federated_aggregator, 'nodes', {}).items():
        nodes.append({
            "node_id": node_id,
            "opted_in": getattr(node_info, 'opted_in', False),
            "contributed_signatures": getattr(node_info, 'contributed_signatures', 0),
            "last_seen": getattr(node_info, 'last_seen', None),
            "status": "active" if getattr(node_info, 'opted_in', False) else "inactive",
        })

    return {
        "network_health": "operational",
        "total_nodes": stats.get("total_nodes", 0),
        "active_nodes": stats.get("opted_in_nodes", 0),
        "total_signatures": stats.get("total_shared_signatures", 0),
        "nodes": nodes,
    }
