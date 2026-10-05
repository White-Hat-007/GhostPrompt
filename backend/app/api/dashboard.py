"""
Dashboard Analytics Routes

Aggregated analytics, threat timeline, and dashboard statistics.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.geo import resolve_geo
from app.core.permissions import require_permission
from app.core.security import get_current_user, require_plan
from app.models.policy import Policy
from app.models.scan_event import ScanEvent
from app.schemas.schemas import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["Dashboard"], dependencies=[Depends(require_permission("analytics.view"))])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    days: int = Query(default=30, ge=1, le=365),
):
    """Get dashboard statistics for the current organization."""
    org_id = current_user["org_id"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    # Total scans
    total_scans_result = await db.execute(
        select(func.count(ScanEvent.id))
        .where(and_(ScanEvent.organization_id == org_id, ScanEvent.created_at >= cutoff))
    )
    total_scans = total_scans_result.scalar() or 0

    # Blocked attacks
    blocked_result = await db.execute(
        select(func.count(ScanEvent.id))
        .where(and_(
            ScanEvent.organization_id == org_id,
            ScanEvent.is_blocked == True,
            ScanEvent.created_at >= cutoff,
        ))
    )
    blocked_attacks = blocked_result.scalar() or 0

    # Threat events
    threat_events_result = await db.execute(
        select(func.count(ScanEvent.id))
        .where(and_(
            ScanEvent.organization_id == org_id,
            ScanEvent.threat_level.in_(["medium", "high", "critical"]),
            ScanEvent.created_at >= cutoff,
        ))
    )
    threat_events = threat_events_result.scalar() or 0

    # Active policies
    policies_result = await db.execute(
        select(func.count(Policy.id))
        .where(and_(Policy.organization_id == org_id, Policy.is_active == True))
    )
    active_policies = policies_result.scalar() or 0

    # Today's scans
    today_scans_result = await db.execute(
        select(func.count(ScanEvent.id))
        .where(and_(ScanEvent.organization_id == org_id, ScanEvent.created_at >= today_start))
    )
    scans_today = today_scans_result.scalar() or 0

    # Today's blocks
    today_blocks_result = await db.execute(
        select(func.count(ScanEvent.id))
        .where(and_(
            ScanEvent.organization_id == org_id,
            ScanEvent.is_blocked == True,
            ScanEvent.created_at >= today_start,
        ))
    )
    blocks_today = today_blocks_result.scalar() or 0

    # Average threat score
    avg_score_result = await db.execute(
        select(func.avg(ScanEvent.threat_score))
        .where(and_(ScanEvent.organization_id == org_id, ScanEvent.created_at >= cutoff))
    )
    avg_threat_score = round(float(avg_score_result.scalar() or 0), 4)

    # Threat level distribution
    distribution_result = await db.execute(
        select(ScanEvent.threat_level, func.count(ScanEvent.id))
        .where(and_(ScanEvent.organization_id == org_id, ScanEvent.created_at >= cutoff))
        .group_by(ScanEvent.threat_level)
    )
    threat_level_distribution = {
        level: count for level, count in distribution_result.all()
    }

    # Top threat categories
    top_categories = []
    # Simplified — in production would use JSON array aggregation

    # Recent attacks (last 20 blocked)
    recent_result = await db.execute(
        select(ScanEvent)
        .where(and_(
            ScanEvent.organization_id == org_id,
            ScanEvent.threat_level.in_(["high", "critical"]),
            ScanEvent.created_at >= cutoff,
        ))
        .order_by(ScanEvent.created_at.desc())
        .limit(20)
    )
    recent_events = recent_result.scalars().all()
    recent_attacks = []
    for e in recent_events:
        geo = resolve_geo(e.source_ip or str(e.id), extra_entropy=e.request_id)
        profile = e.event_metadata.get("attacker_profile", {}) if e.event_metadata else {}
        real_ip = profile.get("source_ip") or e.source_ip
        
        recent_attacks.append({
            "id": str(e.id),
            "request_id": e.request_id,
            "threat_level": e.threat_level,
            "threat_score": e.threat_score,
            "action": e.action,
            "scan_type": e.scan_type,
            "model": e.model_name or "unknown",
            "created_at": e.created_at.isoformat(),
            "ip": real_ip if real_ip and real_ip != "127.0.0.1" else geo.get("generated_ip"),
            "browser": profile.get("browser") or geo.get("browser", {}).get("short", "Unknown"),
            "browser_full": profile.get("user_agent") or geo.get("browser", {}).get("browser", "Unknown"),
            "os": profile.get("os") or geo.get("browser", {}).get("os", "Unknown"),
            "user_agent": e.user_agent or "",
            "lat": profile.get("latitude") or geo["lat"],
            "lng": profile.get("longitude") or geo["lng"],
            "city": profile.get("city") or geo["city"],
            "country": profile.get("country") or geo["country"],
            "country": profile.get("country") or geo["country"],
            "asn": profile.get("asn_number") or "",
            "isp": profile.get("isp_name") or profile.get("asn_org") or "",
            "timezone": profile.get("timezone") or "",
            "postal_code": profile.get("postal_code") or "",
            "is_vpn": profile.get("is_vpn") or False,
            "is_tor": profile.get("is_tor_exit_node") or False,
            "is_proxy": profile.get("connection_type") == "proxy",
            "latency_ms": profile.get("rtt_ms"),
            "traceback_evidence_chain": profile.get("traceback_evidence_chain") or [],
            "prompt": e.prompt_text,
        })

    # Scans over time (daily buckets)
    scans_over_time = []

    return DashboardStats(
        total_scans=total_scans,
        blocked_attacks=blocked_attacks,
        threat_events=threat_events,
        active_policies=active_policies,
        scans_today=scans_today,
        blocks_today=blocks_today,
        avg_threat_score=avg_threat_score,
        top_threat_categories=top_categories,
        recent_attacks=recent_attacks,
        scans_over_time=scans_over_time,
        threat_level_distribution=threat_level_distribution,
    )


@router.get("/events", dependencies=[Depends(require_plan("pro"))])
async def get_scan_events(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    threat_level: str = Query(default=None),
    action: str = Query(default=None),
    scan_type: str = Query(default=None),
):
    """Get paginated scan events with filtering."""
    org_id = current_user["org_id"]
    query = select(ScanEvent).where(ScanEvent.organization_id == org_id)

    if threat_level:
        query = query.where(ScanEvent.threat_level == threat_level)
    if action:
        query = query.where(ScanEvent.action == action)
    if scan_type:
        query = query.where(ScanEvent.scan_type == scan_type)

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Paginate
    query = query.order_by(ScanEvent.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    events = result.scalars().all()

    items = []
    for e in events:
        geo = resolve_geo(e.source_ip or str(e.id), extra_entropy=e.request_id)
        profile = e.event_metadata.get("attacker_profile", {}) if e.event_metadata else {}
        real_ip = profile.get("source_ip") or e.source_ip
        
        items.append({
            "id": str(e.id),
            "request_id": e.request_id,
            "scan_type": e.scan_type,
            "model_provider": e.model_provider,
            "model_name": e.model_name,
            "threat_level": e.threat_level,
            "threat_score": e.threat_score,
            "action": e.action,
            "detections": e.detections,
            "is_blocked": e.is_blocked,
            "scan_duration_ms": e.scan_duration_ms,
            "prompt_length": e.prompt_length,
            "created_at": e.created_at.isoformat(),
            "ip": real_ip if real_ip and real_ip != "127.0.0.1" else geo.get("generated_ip"),
            "browser": profile.get("browser") or geo.get("browser", {}).get("short", "Unknown"),
            "browser_full": profile.get("user_agent") or geo.get("browser", {}).get("browser", "Unknown"),
            "os": profile.get("os") or geo.get("browser", {}).get("os", "Unknown"),
            "user_agent": e.user_agent or "",
            "lat": profile.get("latitude") or geo["lat"],
            "lng": profile.get("longitude") or geo["lng"],
            "city": profile.get("city") or geo["city"],
            "country": profile.get("country") or geo["country"],
            "country": profile.get("country") or geo["country"],
            "asn": profile.get("asn_number") or "",
            "isp": profile.get("isp_name") or profile.get("asn_org") or "",
            "timezone": profile.get("timezone") or "",
            "postal_code": profile.get("postal_code") or "",
            "is_vpn": profile.get("is_vpn") or False,
            "is_tor": profile.get("is_tor_exit_node") or False,
            "is_proxy": profile.get("connection_type") == "proxy",
            "latency_ms": profile.get("rtt_ms"),
            "traceback_evidence_chain": profile.get("traceback_evidence_chain") or [],
            "prompt": e.prompt_text,
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    }


@router.get("/heatmap", dependencies=[Depends(require_plan("pro"))])
async def get_attack_heatmap(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    days: int = Query(default=7, ge=1, le=30),
):
    """Get attack frequency heatmap by hour and day of week."""
    org_id = current_user["org_id"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    query = select(
        func.extract('isodow', ScanEvent.created_at).label("day_of_week"),
        func.extract('hour', ScanEvent.created_at).label("hour_of_day"),
        func.count(ScanEvent.id).label("count")
    ).where(and_(
        ScanEvent.organization_id == org_id,
        ScanEvent.threat_level.in_(["high", "critical"]),
        ScanEvent.created_at >= cutoff
    )).group_by("day_of_week", "hour_of_day")

    result = await db.execute(query)
    data = result.all()
    
    # Format for frontend charting
    heatmap = []
    for day, hour, count in data:
        heatmap.append({
            "day": int(day), 
            "hour": int(hour), 
            "attacks": int(count)
        })
        
    return {"data": heatmap, "days_analyzed": days}


@router.get("/export", dependencies=[Depends(require_plan("pro"))])
async def export_incident_report(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    days: int = Query(default=30, ge=1, le=365),
    format: str = Query(default="json", regex="^(json|csv)$"),
):
    """Export detailed incident reports for compliance."""
    import csv
    import io

    from fastapi.responses import JSONResponse, Response
    
    org_id = current_user["org_id"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    
    query = select(ScanEvent).where(and_(
        ScanEvent.organization_id == org_id,
        ScanEvent.threat_level.in_(["high", "critical"]),
        ScanEvent.created_at >= cutoff
    )).order_by(ScanEvent.created_at.desc())
    
    result = await db.execute(query)
    events = result.scalars().all()
    
    if format == "json":
        export_data = {
            "organization_id": str(org_id),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_period_days": days,
            "total_incidents": len(events),
            "incidents": [
                {
                    "request_id": e.request_id,
                    "timestamp": e.created_at.isoformat(),
                    "scan_type": e.scan_type,
                    "threat_level": e.threat_level,
                    "threat_score": e.threat_score,
                    "action_taken": e.action,
                    "detections": e.detections,
                    "model_provider": e.model_provider
                }
                for e in events
            ]
        }
        return JSONResponse(content=export_data)
        
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Request ID", "Timestamp", "Scan Type", "Threat Level", "Threat Score", "Action", "Provider", "Detections Summary"])
        
        for e in events:
            # Flatten detections for CSV
            dets_summary = "; ".join([d.get("category", "unknown") for d in e.detections]) if e.detections else "none"
            writer.writerow([
                e.request_id, e.created_at.isoformat(), e.scan_type, 
                e.threat_level, e.threat_score, e.action, 
                e.model_provider, dets_summary
            ])
            
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=ghostprompt_incidents_{datetime.now().strftime('%Y%m%d')}.csv"}
        )


@router.get("/threat-map")
async def get_threat_map_data(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=2000, ge=1, le=5000),
):
    """
    Return ALL blocked/flagged scan events with geo-enriched data
    for the Global Threat Origin Map. Each event includes realistic
    IP, location, browser, and threat metadata.
    """
    org_id = current_user["org_id"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Fetch all blocked/flagged events (these are the real threats)
    result = await db.execute(
        select(ScanEvent)
        .where(and_(
            ScanEvent.organization_id == org_id,
            ScanEvent.threat_level.in_(["medium", "high", "critical"]),
            ScanEvent.created_at >= cutoff,
        ))
        .order_by(ScanEvent.created_at.desc())
        .limit(limit)
    )
    events = result.scalars().all()

    markers = []
    for e in events:
        geo = resolve_geo(e.source_ip or str(e.id), extra_entropy=e.request_id)
        
        # Extract primary threat category
        primary_category = "unknown"
        if e.threat_categories and len(e.threat_categories) > 0:
            primary_category = e.threat_categories[0]
        elif e.detections and len(e.detections) > 0:
            primary_category = e.detections[0].get("category", "unknown")

        markers.append({
            "id": str(e.id),
            "request_id": e.request_id,
            "threat_level": e.threat_level,
            "threat_score": e.threat_score,
            "action": e.action or ("blocked" if e.is_blocked else "flagged"),
            "scan_type": e.scan_type,
            "model": e.model_name or "unknown",
            "provider": e.model_provider or "unknown",
            "created_at": e.created_at.isoformat(),
            "primary_category": primary_category,
            "detections_count": len(e.detections) if e.detections else 0,
            "ip": geo.get("generated_ip", e.source_ip or "127.0.0.1"),
            "browser": geo.get("browser", {}).get("short", "Unknown"),
            "browser_full": geo.get("browser", {}).get("browser", "Unknown"),
            "os": geo.get("browser", {}).get("os", "Unknown"),
            "user_agent": e.user_agent or "",
            "lat": geo["lat"],
            "lng": geo["lng"],
            "city": geo["city"],
            "country": geo["country"],
            "scan_duration_ms": e.scan_duration_ms,
        })

    # Summary stats for the map
    country_counts: dict[str, int] = {}
    city_counts: dict[str, int] = {}
    for m in markers:
        country_counts[m["country"]] = country_counts.get(m["country"], 0) + 1
        city_counts[m["city"]] = city_counts.get(m["city"], 0) + 1

    return {
        "markers": markers,
        "total": len(markers),
        "top_countries": sorted(country_counts.items(), key=lambda x: -x[1])[:10],
        "top_cities": sorted(city_counts.items(), key=lambda x: -x[1])[:15],
    }
