"""
Threat Attribution API

Endpoints for the Threat Attribution Engine:
- Threat Actor profiles
- Campaign correlation
- Attack clusters
- Attribution telemetry
- Model integrity monitoring
- Grooming detection
- Covert channel analytics
- Adversarial media events
- Tokenizer threats
"""

from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc, case

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.attribution import (
    ThreatActor, ThreatCampaign, AttackCluster, AttributionProfile,
    ModelIntegrityEvent, GroomingTimeline, ExfiltrationEvent,
    AdversarialMediaEvent, TokenizerThreat,
)
from app.models.scan_event import ScanEvent
from app.core.permissions import require_permission

router = APIRouter(
    prefix="/attribution",
    tags=["Threat Attribution"],
    dependencies=[Depends(require_permission("attribution.view"))],
)


# ─── THREAT ACTORS ────────────────────────────────────────────
@router.get("/actors")
async def list_threat_actors(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=200),
    risk_level: str = Query(None),
):
    """List all correlated threat actors for the organization."""
    org_id = current_user.get("org_id")
    q = select(ThreatActor).where(ThreatActor.organization_id == org_id)
    if risk_level:
        q = q.where(ThreatActor.risk_level == risk_level)
    q = q.order_by(desc(ThreatActor.risk_score)).limit(limit)
    result = await db.execute(q)
    actors = result.scalars().all()
    return [{
        "id": str(a.id),
        "actor_id": a.actor_id,
        "alias": a.alias,
        "actor_type": a.actor_type,
        "confidence_score": a.confidence_score,
        "risk_score": a.risk_score,
        "risk_level": a.risk_level,
        "primary_country": a.primary_country,
        "primary_city": a.primary_city,
        "latitude": a.latitude,
        "longitude": a.longitude,
        "total_requests": a.total_requests,
        "total_attacks": a.total_attacks,
        "total_blocked": a.total_blocked,
        "is_vpn": a.is_vpn,
        "is_tor": a.is_tor,
        "is_proxy": a.is_proxy,
        "attack_sophistication": a.attack_sophistication,
        "preferred_attack_types": a.preferred_attack_types,
        "ip_addresses": a.ip_addresses,
        "first_seen": a.first_seen.isoformat() if a.first_seen else None,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "is_watchlisted": a.is_watchlisted,
        "campaign_ids": a.campaign_ids,
    } for a in actors]


@router.get("/actors/stats")
async def actor_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate threat actor statistics."""
    org_id = current_user.get("org_id")
    result = await db.execute(
        select(
            func.count(ThreatActor.id).label("total"),
            func.count(case((ThreatActor.risk_level == "critical", 1))).label("critical"),
            func.count(case((ThreatActor.risk_level == "high", 1))).label("high"),
            func.count(case((ThreatActor.is_tor == True, 1))).label("tor_users"),
            func.count(case((ThreatActor.is_vpn == True, 1))).label("vpn_users"),
            func.count(case((ThreatActor.actor_type == "bot", 1))).label("bots"),
            func.count(case((ThreatActor.actor_type == "swarm", 1))).label("swarms"),
            func.avg(ThreatActor.risk_score).label("avg_risk"),
        ).where(ThreatActor.organization_id == org_id)
    )
    row = result.one()
    return {
        "total_actors": row.total,
        "critical_actors": row.critical,
        "high_risk_actors": row.high,
        "tor_users": row.tor_users,
        "vpn_users": row.vpn_users,
        "bot_actors": row.bots,
        "swarm_actors": row.swarms,
        "avg_risk_score": round(float(row.avg_risk or 0), 2),
    }


# ─── CAMPAIGNS ────────────────────────────────────────────────
@router.get("/campaigns")
async def list_campaigns(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    status: str = Query(None),
    limit: int = Query(50, le=200),
):
    """List all threat campaigns."""
    org_id = current_user.get("org_id")
    q = select(ThreatCampaign).where(ThreatCampaign.organization_id == org_id)
    if status:
        q = q.where(ThreatCampaign.status == status)
    q = q.order_by(desc(ThreatCampaign.last_seen)).limit(limit)
    result = await db.execute(q)
    campaigns = result.scalars().all()
    return [{
        "id": str(c.id),
        "campaign_id": c.campaign_id,
        "name": c.name,
        "description": c.description,
        "campaign_type": c.campaign_type,
        "threat_family": c.threat_family,
        "severity": c.severity,
        "risk_score": c.risk_score,
        "total_events": c.total_events,
        "total_actors": c.total_actors,
        "total_ips": c.total_ips,
        "attack_types": c.attack_types,
        "status": c.status,
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_seen": c.last_seen.isoformat() if c.last_seen else None,
    } for c in campaigns]


@router.get("/campaigns/stats")
async def campaign_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Campaign summary stats."""
    org_id = current_user.get("org_id")
    result = await db.execute(
        select(
            func.count(ThreatCampaign.id).label("total"),
            func.count(case((ThreatCampaign.status == "active", 1))).label("active"),
            func.count(case((ThreatCampaign.severity == "critical", 1))).label("critical"),
            func.sum(ThreatCampaign.total_events).label("total_events"),
        ).where(ThreatCampaign.organization_id == org_id)
    )
    row = result.one()
    return {
        "total_campaigns": row.total,
        "active_campaigns": row.active,
        "critical_campaigns": row.critical,
        "total_campaign_events": int(row.total_events or 0),
    }


# ─── ATTACK CLUSTERS ─────────────────────────────────────────
@router.get("/clusters")
async def list_clusters(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=200),
):
    """List all attack clusters / families."""
    org_id = current_user.get("org_id")
    result = await db.execute(
        select(AttackCluster)
        .where(AttackCluster.organization_id == org_id)
        .order_by(desc(AttackCluster.total_occurrences))
        .limit(limit)
    )
    clusters = result.scalars().all()
    return [{
        "id": str(c.id),
        "cluster_id": c.cluster_id,
        "family_name": c.family_name,
        "attack_category": c.attack_category,
        "variant_count": c.variant_count,
        "total_occurrences": c.total_occurrences,
        "block_rate": c.block_rate,
        "avg_threat_score": c.avg_threat_score,
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_seen": c.last_seen.isoformat() if c.last_seen else None,
    } for c in clusters]


# ─── MODEL INTEGRITY ─────────────────────────────────────────
@router.get("/model-integrity")
async def list_model_integrity(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    event_type: str = Query(None),
    limit: int = Query(50, le=200),
):
    """List model integrity events (poisoning, drift, alignment shifts)."""
    org_id = current_user.get("org_id")
    q = select(ModelIntegrityEvent).where(ModelIntegrityEvent.organization_id == org_id)
    if event_type:
        q = q.where(ModelIntegrityEvent.event_type == event_type)
    q = q.order_by(desc(ModelIntegrityEvent.created_at)).limit(limit)
    result = await db.execute(q)
    events = result.scalars().all()
    return [{
        "id": str(e.id),
        "event_type": e.event_type,
        "model_name": e.model_name,
        "model_provider": e.model_provider,
        "risk_score": e.risk_score,
        "risk_level": e.risk_level,
        "confidence": e.confidence,
        "description": e.description,
        "indicators": e.indicators,
        "action_taken": e.action_taken,
        "was_mitigated": e.was_mitigated,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    } for e in events]


@router.get("/model-integrity/stats")
async def model_integrity_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Model integrity summary."""
    org_id = current_user.get("org_id")
    result = await db.execute(
        select(
            func.count(ModelIntegrityEvent.id).label("total"),
            func.count(case((ModelIntegrityEvent.event_type == "poisoning_detected", 1))).label("poisoning"),
            func.count(case((ModelIntegrityEvent.event_type == "drift_detected", 1))).label("drift"),
            func.count(case((ModelIntegrityEvent.event_type == "sleeper_trigger", 1))).label("sleeper"),
            func.count(case((ModelIntegrityEvent.event_type == "alignment_shift", 1))).label("alignment"),
            func.count(case((ModelIntegrityEvent.event_type == "fine_tune_anomaly", 1))).label("fine_tune"),
            func.avg(ModelIntegrityEvent.risk_score).label("avg_risk"),
        ).where(ModelIntegrityEvent.organization_id == org_id)
    )
    row = result.one()
    return {
        "total_events": row.total,
        "poisoning_events": row.poisoning,
        "drift_events": row.drift,
        "sleeper_triggers": row.sleeper,
        "alignment_shifts": row.alignment,
        "fine_tune_anomalies": row.fine_tune,
        "avg_risk_score": round(float(row.avg_risk or 0), 2),
    }


# ─── GROOMING DETECTION ──────────────────────────────────────
@router.get("/grooming")
async def list_grooming(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=200),
):
    """List long-horizon grooming timelines."""
    org_id = current_user.get("org_id")
    result = await db.execute(
        select(GroomingTimeline)
        .where(GroomingTimeline.organization_id == org_id)
        .order_by(desc(GroomingTimeline.risk_score))
        .limit(limit)
    )
    timelines = result.scalars().all()
    return [{
        "id": str(g.id),
        "session_id": g.session_id,
        "actor_id": g.actor_id,
        "grooming_type": g.grooming_type,
        "risk_score": g.risk_score,
        "risk_level": g.risk_level,
        "stage": g.stage,
        "interaction_count": g.interaction_count,
        "span_days": g.span_days,
        "manipulation_indicators": g.manipulation_indicators,
        "trust_score_history": g.trust_score_history,
        "first_interaction": g.first_interaction.isoformat() if g.first_interaction else None,
        "last_interaction": g.last_interaction.isoformat() if g.last_interaction else None,
    } for g in timelines]


# ─── EXFILTRATION ─────────────────────────────────────────────
@router.get("/exfiltration")
async def list_exfiltration(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=200),
):
    """List covert channel detection events."""
    org_id = current_user.get("org_id")
    result = await db.execute(
        select(ExfiltrationEvent)
        .where(ExfiltrationEvent.organization_id == org_id)
        .order_by(desc(ExfiltrationEvent.created_at))
        .limit(limit)
    )
    events = result.scalars().all()
    return [{
        "id": str(e.id),
        "channel_type": e.channel_type,
        "confidence_score": e.confidence_score,
        "severity": e.severity,
        "description": e.description,
        "indicators": e.indicators,
        "source_ip": e.source_ip,
        "session_id": e.session_id,
        "action_taken": e.action_taken,
        "was_blocked": e.was_blocked,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    } for e in events]


# ─── ADVERSARIAL MEDIA ────────────────────────────────────────
@router.get("/adversarial-media")
async def list_adversarial_media(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=200),
):
    """List adversarial media detection events."""
    org_id = current_user.get("org_id")
    result = await db.execute(
        select(AdversarialMediaEvent)
        .where(AdversarialMediaEvent.organization_id == org_id)
        .order_by(desc(AdversarialMediaEvent.created_at))
        .limit(limit)
    )
    events = result.scalars().all()
    return [{
        "id": str(e.id),
        "media_type": e.media_type,
        "attack_type": e.attack_type,
        "confidence_score": e.confidence_score,
        "severity": e.severity,
        "description": e.description,
        "attack_fingerprint": e.attack_fingerprint,
        "detection_method": e.detection_method,
        "action_taken": e.action_taken,
        "was_blocked": e.was_blocked,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    } for e in events]


# ─── TOKENIZER THREATS ────────────────────────────────────────
@router.get("/tokenizer-threats")
async def list_tokenizer_threats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=200),
):
    """List tokenizer vulnerability registry entries."""
    org_id = current_user.get("org_id")
    result = await db.execute(
        select(TokenizerThreat)
        .where(TokenizerThreat.organization_id == org_id)
        .order_by(desc(TokenizerThreat.anomaly_score))
        .limit(limit)
    )
    threats = result.scalars().all()
    return [{
        "id": str(t.id),
        "threat_type": t.threat_type,
        "description": t.description,
        "affected_tokenizer": t.affected_tokenizer,
        "affected_models": t.affected_models,
        "anomaly_score": t.anomaly_score,
        "severity": t.severity,
        "exploitability": t.exploitability,
        "status": t.status,
        "first_seen": t.first_seen.isoformat() if t.first_seen else None,
        "last_seen": t.last_seen.isoformat() if t.last_seen else None,
    } for t in threats]


# ─── UNIFIED DASHBOARD STATS ─────────────────────────────────
@router.get("/dashboard")
async def attribution_dashboard(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unified attribution dashboard data."""
    org_id = current_user.get("org_id")

    # Threat actors
    actors_result = await db.execute(
        select(func.count(ThreatActor.id)).where(ThreatActor.organization_id == org_id)
    )
    # Campaigns
    campaigns_result = await db.execute(
        select(func.count(ThreatCampaign.id)).where(ThreatCampaign.organization_id == org_id)
    )
    # Clusters
    clusters_result = await db.execute(
        select(func.count(AttackCluster.id)).where(AttackCluster.organization_id == org_id)
    )
    # Model integrity
    integrity_result = await db.execute(
        select(func.count(ModelIntegrityEvent.id)).where(ModelIntegrityEvent.organization_id == org_id)
    )
    # Grooming
    grooming_result = await db.execute(
        select(func.count(GroomingTimeline.id)).where(GroomingTimeline.organization_id == org_id)
    )
    # Exfiltration
    exfil_result = await db.execute(
        select(func.count(ExfiltrationEvent.id)).where(ExfiltrationEvent.organization_id == org_id)
    )
    # Adversarial media
    media_result = await db.execute(
        select(func.count(AdversarialMediaEvent.id)).where(AdversarialMediaEvent.organization_id == org_id)
    )
    # Tokenizer threats
    tokenizer_result = await db.execute(
        select(func.count(TokenizerThreat.id)).where(TokenizerThreat.organization_id == org_id)
    )

    return {
        "threat_actors": actors_result.scalar() or 0,
        "active_campaigns": campaigns_result.scalar() or 0,
        "attack_clusters": clusters_result.scalar() or 0,
        "model_integrity_events": integrity_result.scalar() or 0,
        "grooming_timelines": grooming_result.scalar() or 0,
        "exfiltration_events": exfil_result.scalar() or 0,
        "adversarial_media_events": media_result.scalar() or 0,
        "tokenizer_threats": tokenizer_result.scalar() or 0,
    }


# ─── TRACEBACK — Full Kill Chain Forensics ────────────────────
@router.get("/traceback/{actor_id}")
async def traceback_threat_actor(
    actor_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Full kill-chain traceback for a threat actor.

    Returns the actor profile, all associated campaigns, clusters,
    scan events, grooming timelines, and geo-origin data — everything
    needed for the dual-pin globe and traceback UI.
    """
    org_id = current_user.get("org_id")

    # Actor profile
    actor_result = await db.execute(
        select(ThreatActor).where(
            and_(ThreatActor.id == actor_id, ThreatActor.organization_id == org_id)
        )
    )
    actor = actor_result.scalar_one_or_none()
    if not actor:
        raise HTTPException(404, "Threat actor not found")

    # Associated campaigns
    campaigns_result = await db.execute(
        select(ThreatCampaign).where(
            and_(ThreatCampaign.organization_id == org_id)
        ).order_by(desc(ThreatCampaign.created_at)).limit(20)
    )
    campaigns = [
        {
            "id": str(c.id), "name": c.name, "status": c.status,
            "technique_count": c.technique_count, "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in campaigns_result.scalars().all()
    ]

    # Associated scan events (latest 50)
    scans_result = await db.execute(
        select(ScanEvent).where(
            and_(ScanEvent.organization_id == org_id, ScanEvent.is_blocked == True)
        ).order_by(desc(ScanEvent.created_at)).limit(50)
    )
    scan_events = []
    for s in scans_result.scalars().all():
        scan_events.append({
            "id": str(s.id),
            "prompt_preview": (s.prompt_text or "")[:120],
            "action": s.action,
            "threat_score": s.threat_score,
            "threat_level": s.threat_level,
            "categories": s.categories or [],
            "ip_address": s.ip_address,
            "geo_country": getattr(s, "geo_country", None),
            "geo_city": getattr(s, "geo_city", None),
            "geo_lat": getattr(s, "geo_lat", None),
            "geo_lon": getattr(s, "geo_lon", None),
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })

    # Grooming timelines
    grooming_result = await db.execute(
        select(GroomingTimeline).where(
            GroomingTimeline.organization_id == org_id
        ).order_by(desc(GroomingTimeline.created_at)).limit(10)
    )
    grooming_items = [
        {
            "id": str(g.id), "phase": g.phase, "technique": g.technique,
            "risk_score": g.risk_score, "created_at": g.created_at.isoformat() if g.created_at else None,
        }
        for g in grooming_result.scalars().all()
    ]

    return {
        "actor": {
            "id": str(actor.id),
            "name": actor.name,
            "sophistication": actor.sophistication,
            "confidence_score": actor.confidence_score,
            "attack_count": actor.attack_count,
            "first_seen": actor.first_seen.isoformat() if actor.first_seen else None,
            "last_seen": actor.last_seen.isoformat() if actor.last_seen else None,
            "origin_country": getattr(actor, "origin_country", None),
            "origin_lat": getattr(actor, "origin_lat", None),
            "origin_lon": getattr(actor, "origin_lon", None),
        },
        "campaigns": campaigns,
        "scan_events": scan_events,
        "grooming_timeline": grooming_items,
        "kill_chain": {
            "reconnaissance": len([s for s in scan_events if "oracle" in str(s.get("categories", []))]),
            "weaponization": len([s for s in scan_events if "encoded" in str(s.get("categories", []))]),
            "delivery": len([s for s in scan_events if "injection" in str(s.get("categories", []))]),
            "exploitation": len([s for s in scan_events if "jailbreak" in str(s.get("categories", []))]),
            "exfiltration": len([s for s in scan_events if "pii" in str(s.get("categories", []))]),
        },
    }


@router.get("/geo-origins")
async def get_geo_origins(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    days: int = Query(default=30, ge=1, le=365),
):
    """
    Get geographic origins of threats for dual-pin globe visualization.

    Returns attacker origin → target pairs with coordinates for
    animated arc rendering on the CesiumJS/MapLibre globe.
    """
    org_id = current_user.get("org_id")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Get scan events with geo data
    result = await db.execute(
        select(ScanEvent).where(
            and_(
                ScanEvent.organization_id == org_id,
                ScanEvent.is_blocked == True,
                ScanEvent.created_at >= cutoff,
            )
        ).order_by(desc(ScanEvent.created_at)).limit(200)
    )

    origins = []
    for s in result.scalars().all():
        ip = s.ip_address or "unknown"
        geo_lat = getattr(s, "geo_lat", None)
        geo_lon = getattr(s, "geo_lon", None)
        geo_country = getattr(s, "geo_country", None)

        origins.append({
            "id": str(s.id),
            "source": {
                "ip": ip,
                "lat": geo_lat or 0,
                "lon": geo_lon or 0,
                "country": geo_country or "Unknown",
            },
            "target": {
                "lat": 37.7749,  # Default: your data center
                "lon": -122.4194,
                "label": "GhostPrompt HQ",
            },
            "threat_level": s.threat_level,
            "threat_score": s.threat_score,
            "categories": s.categories or [],
            "timestamp": s.created_at.isoformat() if s.created_at else None,
        })

    return {
        "total_origins": len(origins),
        "origins": origins,
        "period_days": days,
    }

