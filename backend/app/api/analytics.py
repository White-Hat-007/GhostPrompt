"""
Analytics API — Time-Series Datewise Dashboard

Professional datewise analytics endpoints supporting:
- Global date-range queries (today/7d/30d/MTD/QTD/YTD/custom)
- Time-bucketed aggregations (hour/day/week/month)
- Period-over-period comparisons
- Top techniques, countries, actors
- CSV/JSON export
"""

from datetime import datetime, timedelta, timezone, date
from typing import Optional, Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Depends
from app.core.permissions import require_permission
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text, case, and_, extract
from pydantic import BaseModel

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.logging import get_logger
from app.models.scan_event import ScanEvent

logger = get_logger("analytics")
router = APIRouter(prefix="/analytics", tags=["Analytics"], dependencies=[Depends(require_permission("analytics.view"))])


# ── Schemas ──────────────────────────────────────────────────────────────

class TimeSeriesBucket(BaseModel):
    timestamp: str
    scans: int = 0
    blocked: int = 0
    flagged: int = 0
    allowed: int = 0


class SeverityTrend(BaseModel):
    timestamp: str
    safe: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class TopItem(BaseModel):
    name: str
    count: int
    percentage: float = 0.0


class PeriodComparison(BaseModel):
    current: int
    previous: int
    delta: int
    delta_pct: float


class AnalyticsSummary(BaseModel):
    total_scans: int
    total_blocked: int
    total_flagged: int
    total_allowed: int
    avg_threat_score: float
    avg_latency_ms: float
    block_rate: float
    scans_delta: Optional[PeriodComparison] = None
    blocked_delta: Optional[PeriodComparison] = None


class AnalyticsResponse(BaseModel):
    summary: AnalyticsSummary
    time_series: list[TimeSeriesBucket]
    severity_trend: list[SeverityTrend]
    top_techniques: list[TopItem]
    top_categories: list[TopItem]


# ── Helpers ──────────────────────────────────────────────────────────────

def parse_date_range(
    preset: Optional[str],
    start: Optional[str],
    end: Optional[str],
) -> tuple[datetime, datetime]:
    """Parse a date range from preset or custom start/end."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    if preset:
        match preset:
            case "today":
                return today_start, now
            case "yesterday":
                return today_start - timedelta(days=1), today_start
            case "7d":
                return now - timedelta(days=7), now
            case "30d":
                return now - timedelta(days=30), now
            case "mtd":
                return today_start.replace(day=1), now
            case "qtd":
                quarter_start_month = ((now.month - 1) // 3) * 3 + 1
                return today_start.replace(month=quarter_start_month, day=1), now
            case "ytd":
                return today_start.replace(month=1, day=1), now
            case "1y":
                return now - timedelta(days=365), now
            case _:
                return now - timedelta(days=7), now

    if start and end:
        return (
            datetime.fromisoformat(start).replace(tzinfo=timezone.utc),
            datetime.fromisoformat(end).replace(tzinfo=timezone.utc),
        )

    return now - timedelta(days=7), now


def get_bucket_interval(
    granularity: str,
    range_start: datetime,
    range_end: datetime,
) -> str:
    """Return Postgres date_trunc interval string."""
    match granularity:
        case "hour":
            return "hour"
        case "day":
            return "day"
        case "week":
            return "week"
        case "month":
            return "month"
        case "auto":
            delta = (range_end - range_start).total_seconds()
            if delta <= 86400 * 2:
                return "hour"
            elif delta <= 86400 * 60:
                return "day"
            elif delta <= 86400 * 180:
                return "week"
            else:
                return "month"
        case _:
            return "day"


# ── Endpoints ────────────────────────────────────────────────────────────

@router.get("", response_model=AnalyticsResponse)
async def get_analytics(
    request: Request,
    preset: Optional[str] = Query(None, description="Date preset: today|yesterday|7d|30d|mtd|qtd|ytd|1y"),
    start: Optional[str] = Query(None, description="Custom start date (ISO 8601)"),
    end: Optional[str] = Query(None, description="Custom end date (ISO 8601)"),
    granularity: str = Query("auto", description="Bucket size: hour|day|week|month|auto"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get comprehensive analytics for the current organization."""
    org_id = current_user.get("org_id")
    range_start, range_end = parse_date_range(preset, start, end)
    interval = get_bucket_interval(granularity, range_start, range_end)

    # Build org filter — if no org_id (superadmin), show ALL data
    org_filters = [
        ScanEvent.created_at >= range_start,
        ScanEvent.created_at <= range_end,
    ]
    if org_id:
        org_filters.append(ScanEvent.organization_id == org_id)

    org_filter_sql = "AND organization_id = :org_id" if org_id else ""

    # ── Summary stats ──
    summary_q = await db.execute(
        select(
            func.count(ScanEvent.id).label("total"),
            func.count(case((ScanEvent.action == "blocked", 1))).label("blocked"),
            func.count(case((ScanEvent.action == "flagged", 1))).label("flagged"),
            func.count(case((ScanEvent.action == "allowed", 1))).label("allowed"),
            func.coalesce(func.avg(ScanEvent.threat_score), 0).label("avg_score"),
            func.coalesce(func.avg(ScanEvent.scan_duration_ms), 0).label("avg_latency"),
        ).where(*org_filters)
    )
    row = summary_q.one()
    total = row.total or 0

    # ── Previous period for comparison ──
    period_length = range_end - range_start
    prev_start = range_start - period_length
    prev_end = range_start

    prev_filters = [
        ScanEvent.created_at >= prev_start,
        ScanEvent.created_at <= prev_end,
    ]
    if org_id:
        prev_filters.append(ScanEvent.organization_id == org_id)

    prev_q = await db.execute(
        select(
            func.count(ScanEvent.id).label("total"),
            func.count(case((ScanEvent.action == "blocked", 1))).label("blocked"),
        ).where(*prev_filters)
    )
    prev_row = prev_q.one()

    def make_comparison(current: int, previous: int) -> PeriodComparison:
        delta = current - previous
        delta_pct = ((delta / previous) * 100) if previous > 0 else (100.0 if current > 0 else 0.0)
        return PeriodComparison(current=current, previous=previous, delta=delta, delta_pct=round(delta_pct, 1))

    summary = AnalyticsSummary(
        total_scans=total,
        total_blocked=row.blocked or 0,
        total_flagged=row.flagged or 0,
        total_allowed=row.allowed or 0,
        avg_threat_score=round(float(row.avg_score), 3),
        avg_latency_ms=round(float(row.avg_latency), 1),
        block_rate=round((row.blocked / total) * 100, 1) if total > 0 else 0,
        scans_delta=make_comparison(total, prev_row.total or 0),
        blocked_delta=make_comparison(row.blocked or 0, prev_row.blocked or 0),
    )

    # ── Time series (action breakdown) ──
    ts_q = await db.execute(
        select(
            func.date_trunc(interval, ScanEvent.created_at).label("bucket"),
            func.count(ScanEvent.id).label("total"),
            func.count(case((ScanEvent.action == "blocked", 1))).label("blocked"),
            func.count(case((ScanEvent.action == "flagged", 1))).label("flagged"),
            func.count(case((ScanEvent.action == "allowed", 1))).label("allowed"),
        ).where(*org_filters).group_by("bucket").order_by("bucket")
    )
    time_series = [
        TimeSeriesBucket(
            timestamp=r.bucket.isoformat() if r.bucket else "",
            scans=r.total,
            blocked=r.blocked,
            flagged=r.flagged,
            allowed=r.allowed,
        )
        for r in ts_q.all()
    ]

    # ── Severity trend ──
    sev_q = await db.execute(
        select(
            func.date_trunc(interval, ScanEvent.created_at).label("bucket"),
            func.count(case((ScanEvent.threat_level == "safe", 1))).label("safe"),
            func.count(case((ScanEvent.threat_level == "low", 1))).label("low"),
            func.count(case((ScanEvent.threat_level == "medium", 1))).label("medium"),
            func.count(case((ScanEvent.threat_level == "high", 1))).label("high"),
            func.count(case((ScanEvent.threat_level == "critical", 1))).label("critical"),
        ).where(*org_filters).group_by("bucket").order_by("bucket")
    )
    severity_trend = [
        SeverityTrend(
            timestamp=r.bucket.isoformat() if r.bucket else "",
            safe=r.safe, low=r.low, medium=r.medium, high=r.high, critical=r.critical,
        )
        for r in sev_q.all()
    ]

    # ── Top techniques (from threat_categories JSON array column) ──
    cat_q = await db.execute(
        text(f"""
            SELECT elem::text AS category, COUNT(*) as cnt
            FROM scan_events,
                 LATERAL jsonb_array_elements_text(threat_categories::jsonb) AS elem
            WHERE created_at >= :start
              AND created_at <= :end
              AND threat_categories IS NOT NULL
              AND jsonb_typeof(threat_categories::jsonb) = 'array'
              AND jsonb_array_length(threat_categories::jsonb) > 0
              {org_filter_sql}
            GROUP BY elem
            ORDER BY cnt DESC
            LIMIT 15
        """),
        {"org_id": str(org_id) if org_id else None, "start": range_start, "end": range_end},
    )
    cat_rows = cat_q.all()
    total_cats = sum(r.cnt for r in cat_rows) if cat_rows else 1

    top_techniques = [
        TopItem(name=r.category, count=r.cnt, percentage=round((r.cnt / total_cats) * 100, 1))
        for r in cat_rows
    ]

    # ── Top categories (simplified grouping) ──
    top_categories = top_techniques[:10]

    return AnalyticsResponse(
        summary=summary,
        time_series=time_series,
        severity_trend=severity_trend,
        top_techniques=top_techniques,
        top_categories=top_categories,
    )


@router.get("/export")
async def export_analytics(
    request: Request,
    format: Literal["csv", "json"] = Query("json"),
    preset: Optional[str] = Query("7d"),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export scan events as CSV or JSON for the given date range."""
    from fastapi.responses import StreamingResponse
    import csv
    import io

    org_id = current_user.get("org_id")
    range_start, range_end = parse_date_range(preset, start, end)

    export_filters = [
        ScanEvent.created_at >= range_start,
        ScanEvent.created_at <= range_end,
    ]
    if org_id:
        export_filters.append(ScanEvent.organization_id == org_id)

    events_q = await db.execute(
        select(ScanEvent)
        .where(*export_filters)
        .order_by(ScanEvent.created_at.desc())
        .limit(10000)
    )
    events = events_q.scalars().all()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "timestamp", "request_id", "threat_level", "threat_score",
            "action", "scan_type", "model", "categories", "latency_ms",
        ])
        for e in events:
            writer.writerow([
                e.created_at.isoformat() if e.created_at else "",
                e.request_id, e.threat_level, e.threat_score,
                e.action, e.scan_type, e.model_name,
                ";".join(e.threat_categories or []),
                e.scan_duration_ms,
            ])
        output.seek(0)
        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=ghostprompt_analytics_{range_start.date()}.csv"},
        )

    # JSON export
    return {
        "range": {"start": range_start.isoformat(), "end": range_end.isoformat()},
        "count": len(events),
        "events": [
            {
                "timestamp": e.created_at.isoformat() if e.created_at else None,
                "request_id": e.request_id,
                "threat_level": e.threat_level,
                "threat_score": e.threat_score,
                "action": e.action,
                "categories": e.threat_categories,
                "latency_ms": e.scan_duration_ms,
            }
            for e in events
        ],
    }


@router.get("/drilldown")
async def analytics_drilldown(
    category: str = Query(..., description="Category or technique name to drill into"),
    preset: str = Query(default="7d"),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Drill-down into a specific threat category or technique.

    Returns the individual scan events that contributed to
    a particular category's count in the analytics dashboard,
    with full forensic detail for each event.
    """
    org_id = current_user.get("org_id")

    # Calculate date range
    now = datetime.now(timezone.utc)
    range_map = {
        "today": timedelta(days=0), "yesterday": timedelta(days=1),
        "7d": timedelta(days=7), "30d": timedelta(days=30),
        "mtd": timedelta(days=now.day - 1), "qtd": timedelta(days=90),
        "ytd": timedelta(days=now.timetuple().tm_yday - 1), "1y": timedelta(days=365),
    }
    delta = range_map.get(preset, timedelta(days=7))
    range_start = now - delta if preset != "today" else now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Filter by category name (check threat_categories array)
    # Using LIKE for broad matching since categories are stored as arrays
    result = await db.execute(
        select(ScanEvent).where(
            and_(
                ScanEvent.organization_id == org_id,
                ScanEvent.created_at >= range_start,
                ScanEvent.threat_categories.contains([category]) if hasattr(ScanEvent.threat_categories, 'contains')
                else text(f"threat_categories::text LIKE '%{category}%'"),
            )
        ).order_by(ScanEvent.created_at.desc()).limit(limit)
    )

    events = result.scalars().all()

    return {
        "category": category,
        "period": preset,
        "total_events": len(events),
        "events": [
            {
                "id": str(e.id),
                "timestamp": e.created_at.isoformat() if e.created_at else None,
                "request_id": e.request_id,
                "prompt_preview": (e.prompt_text or "")[:150],
                "threat_level": e.threat_level,
                "threat_score": e.threat_score,
                "action": e.action,
                "categories": e.threat_categories or [],
                "model": e.model_name,
                "latency_ms": e.scan_duration_ms,
                "ip_address": e.ip_address,
            }
            for e in events
        ],
    }



@router.get("/export/pdf")
async def export_analytics_pdf(
    request: Request,
    preset: Optional[str] = Query("7d"),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export analytics as an elite dark-themed PDF report."""
    from fastapi.responses import Response
    import os

    org_id = current_user.get("org_id")
    range_start, range_end = parse_date_range(preset, start, end)

    # Gather analytics data
    filters = [
        ScanEvent.created_at >= range_start,
        ScanEvent.created_at <= range_end,
    ]
    if org_id:
        filters.append(ScanEvent.organization_id == org_id)

    # Summary
    total = (await db.execute(select(func.count(ScanEvent.id)).where(*filters))).scalar() or 0
    blocked = (await db.execute(select(func.count(ScanEvent.id)).where(*filters, ScanEvent.action == "blocked"))).scalar() or 0
    flagged = (await db.execute(select(func.count(ScanEvent.id)).where(*filters, ScanEvent.action == "flagged"))).scalar() or 0
    allowed = total - blocked - flagged
    avg_score = (await db.execute(select(func.avg(ScanEvent.threat_score)).where(*filters))).scalar() or 0
    avg_latency = (await db.execute(select(func.avg(ScanEvent.scan_duration_ms)).where(*filters))).scalar() or 0

    # Top categories
    events_q = await db.execute(select(ScanEvent.threat_categories).where(*filters))
    cat_counts: dict[str, int] = {}
    for (cats,) in events_q.all():
        for c in cats or []:
            cat_counts[c] = cat_counts.get(c, 0) + 1
    top_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:15]

    # Top models
    model_q = await db.execute(
        select(ScanEvent.model_name, func.count(ScanEvent.id))
        .where(*filters)
        .group_by(ScanEvent.model_name)
        .order_by(func.count(ScanEvent.id).desc())
        .limit(10)
    )
    top_models = model_q.all()

    # Severity distribution
    sev_q = await db.execute(
        select(ScanEvent.threat_level, func.count(ScanEvent.id))
        .where(*filters)
        .group_by(ScanEvent.threat_level)
    )
    severity_dist = dict(sev_q.all())

    # Generate PDF
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor, Color
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        return Response(content=b"reportlab not installed", status_code=500)

    import io
    buffer = io.BytesIO()

    BG = HexColor("#0A0E14")
    CARD = HexColor("#111827")
    CYAN = HexColor("#06B6D4")
    GREEN = HexColor("#10B981")
    AMBER = HexColor("#F59E0B")
    RED = HexColor("#EF4444")
    WHITE = HexColor("#F9FAFB")
    G300 = HexColor("#D1D5DB")
    G400 = HexColor("#9CA3AF")
    G500 = HexColor("#6B7280")
    G600 = HexColor("#4B5563")

    _base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    _img = os.path.normpath(os.path.join(_base, "..", "frontend", "public", "bg", "hacker.jpg"))
    _has_bg = os.path.isfile(_img)

    def _page_bg(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(BG)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        if _has_bg:
            try:
                canvas.drawImage(_img, 0, 0, width=w, height=h, preserveAspectRatio=True, anchor='c', mask='auto')
            except Exception:
                pass
        canvas.setFillColor(BG)
        canvas.saveState()
        canvas.setFillAlpha(0.88)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        canvas.restoreState()
        canvas.setStrokeColor(CYAN)
        canvas.setLineWidth(0.5)
        canvas.line(40, h - 35, w - 40, h - 35)
        canvas.line(40, 35, w - 40, 35)
        canvas.setFont("Courier-Bold", 7)
        canvas.setFillColor(G500)
        canvas.drawString(45, h - 28, "GHOSTPROMPT")
        canvas.setFont("Courier", 6)
        canvas.drawString(120, h - 28, "// ANALYTICS REPORT")
        canvas.setFont("Courier", 6)
        canvas.setFillColor(G600)
        canvas.drawRightString(w - 45, 22, f"Page {doc.page}")
        canvas.restoreState()

    def _cover_bg(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(BG)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        if _has_bg:
            try:
                canvas.drawImage(_img, 0, 0, width=w, height=h, preserveAspectRatio=True, anchor='c', mask='auto')
            except Exception:
                pass
        canvas.setFillColor(BG)
        canvas.saveState()
        canvas.setFillAlpha(0.78)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        canvas.restoreState()
        canvas.setStrokeColor(Color(0, 1, 1, alpha=0.03))
        canvas.setLineWidth(0.3)
        for y in range(0, int(h), 4):
            canvas.line(0, y, w, y)
        canvas.setStrokeColor(CYAN)
        canvas.setLineWidth(0.8)
        canvas.line(40, h - 35, w - 40, h - 35)
        canvas.line(40, 35, w - 40, 35)

        canvas.restoreState()

    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=45, rightMargin=45, topMargin=55, bottomMargin=50)
    els = []

    s_h1 = ParagraphStyle("AH1", fontName="Helvetica-Bold", fontSize=16, textColor=CYAN, spaceBefore=20, spaceAfter=10)
    s_h2 = ParagraphStyle("AH2", fontName="Courier-Bold", fontSize=11, textColor=HexColor("#4C6EF5"), spaceBefore=14, spaceAfter=6)
    s_body = ParagraphStyle("AB", fontName="Helvetica", fontSize=9, textColor=G300, spaceAfter=4, leading=13)
    s_mono = ParagraphStyle("AM", fontName="Courier", fontSize=8, textColor=G400, spaceAfter=3, leading=11)
    s_big = ParagraphStyle("ABIG", fontName="Helvetica-Bold", fontSize=48, textColor=GREEN, alignment=TA_CENTER, spaceAfter=20, leading=56)

    # ── Cover ──
    els.append(Spacer(1, 100))
    els.append(HRFlowable(width="60%", thickness=0.5, color=CYAN, spaceAfter=20))
    # Cover branding: > GHOST_PROMPT (matching website logo)
    els.append(Paragraph(
        '<font name="Courier-Bold" size="12" color="#6B7280">&gt; </font>'
        '<font name="Helvetica-Bold" size="32" color="#F9FAFB">GHOST</font>'
        '<font name="Helvetica-Bold" size="32" color="#06B6D4">_PROMPT</font>',
        ParagraphStyle("A_CoverTitle", fontName="Helvetica-Bold", fontSize=32,
                       textColor=CYAN, alignment=TA_CENTER, spaceAfter=20, leading=38)
    ))
    els.append(Paragraph("Threat Analytics Report", ParagraphStyle("CS", fontName="Courier", fontSize=10, textColor=G400, alignment=TA_CENTER, spaceAfter=20)))
    els.append(Spacer(1, 40))

    meta = [
        ["PERIOD", f"{range_start.strftime('%Y-%m-%d')} — {range_end.strftime('%Y-%m-%d')}"],
        ["PRESET", preset.upper()],
        ["GENERATED", datetime.now(timezone.utc).isoformat()],
        ["CLASSIFICATION", "CONFIDENTIAL"],
    ]
    meta_table = Table(meta, colWidths=[120, 350])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), CARD),
        ('TEXTCOLOR', (0, 0), (0, -1), G500),
        ('TEXTCOLOR', (1, 0), (1, -1), G300),
        ('FONTNAME', (0, 0), (-1, -1), 'Courier'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 0.3, G600),
    ]))
    els.append(meta_table)
    els.append(PageBreak())

    # ── Executive Summary ──
    els.append(Paragraph("EXECUTIVE SUMMARY", s_h1))
    block_rate = round((blocked / total * 100), 1) if total else 0
    els.append(Paragraph(f"{block_rate}%", s_big))
    els.append(Paragraph("Block Rate", ParagraphStyle("BL", fontName="Courier", fontSize=9, textColor=G400, alignment=TA_CENTER, spaceAfter=20)))

    summary_data = [
        ["METRIC", "VALUE"],
        ["Total Scans", f"{total:,}"],
        ["Blocked", f"{blocked:,}"],
        ["Flagged", f"{flagged:,}"],
        ["Allowed", f"{allowed:,}"],
        ["Average Threat Score", f"{avg_score:.2f}"],
        ["Average Latency", f"{avg_latency:.0f} ms"],
        ["Block Rate", f"{block_rate}%"],
    ]
    st = Table(summary_data, colWidths=[250, 220])
    st.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor("#1F2937")),
        ('BACKGROUND', (0, 1), (-1, -1), CARD),
        ('TEXTCOLOR', (0, 0), (-1, 0), CYAN),
        ('TEXTCOLOR', (0, 1), (-1, -1), G300),
        ('FONTNAME', (0, 0), (-1, 0), 'Courier-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.3, G600),
    ]))
    els.append(st)
    els.append(Spacer(1, 20))

    # ── Severity Distribution ──
    els.append(Paragraph("SEVERITY DISTRIBUTION", s_h2))
    sev_colors = {"safe": GREEN, "low": HexColor("#60A5FA"), "medium": HexColor("#FBBF24"), "high": HexColor("#F97316"), "critical": RED}
    sev_data = [["LEVEL", "COUNT", "PERCENTAGE"]]
    for level in ["critical", "high", "medium", "low", "safe"]:
        cnt = severity_dist.get(level, 0)
        pct = round(cnt / total * 100, 1) if total else 0
        sev_data.append([level.upper(), str(cnt), f"{pct}%"])
    svt = Table(sev_data, colWidths=[150, 150, 170])
    styles_list = [
        ('BACKGROUND', (0, 0), (-1, 0), HexColor("#1F2937")),
        ('BACKGROUND', (0, 1), (-1, -1), CARD),
        ('TEXTCOLOR', (0, 0), (-1, 0), CYAN),
        ('TEXTCOLOR', (0, 1), (-1, -1), G300),
        ('FONTNAME', (0, 0), (-1, 0), 'Courier-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.3, G600),
    ]
    for i, level in enumerate(["critical", "high", "medium", "low", "safe"], 1):
        styles_list.append(('TEXTCOLOR', (0, i), (0, i), sev_colors.get(level, G300)))
    svt.setStyle(TableStyle(styles_list))
    els.append(svt)
    els.append(Spacer(1, 20))

    # ── Top Threat Categories ──
    if top_cats:
        els.append(Paragraph("TOP THREAT CATEGORIES", s_h2))
        tc_data = [["#", "CATEGORY", "COUNT", "% OF TOTAL"]]
        for i, (cat, cnt) in enumerate(top_cats, 1):
            pct = round(cnt / total * 100, 1) if total else 0
            tc_data.append([str(i), cat.replace("_", " ").title(), str(cnt), f"{pct}%"])
        tct = Table(tc_data, colWidths=[30, 220, 100, 120])
        tct.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor("#1F2937")),
            ('BACKGROUND', (0, 1), (-1, -1), CARD),
            ('TEXTCOLOR', (0, 0), (-1, 0), CYAN),
            ('TEXTCOLOR', (0, 1), (0, -1), G400),
            ('TEXTCOLOR', (1, 1), (-1, -1), G300),
            ('FONTNAME', (0, 0), (-1, 0), 'Courier-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.3, G600),
        ]))
        els.append(tct)
        els.append(Spacer(1, 20))

    # ── Top Models ──
    if top_models:
        els.append(Paragraph("TOP MODELS BY SCAN VOLUME", s_h2))
        m_data = [["MODEL", "SCANS"]]
        for mname, mcnt in top_models:
            m_data.append([mname or "unknown", str(mcnt)])
        mt = Table(m_data, colWidths=[350, 120])
        mt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor("#1F2937")),
            ('BACKGROUND', (0, 1), (-1, -1), CARD),
            ('TEXTCOLOR', (0, 0), (-1, 0), CYAN),
            ('TEXTCOLOR', (0, 1), (-1, -1), G300),
            ('FONTNAME', (0, 0), (-1, 0), 'Courier-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.3, G600),
        ]))
        els.append(mt)

    # Footer
    els.append(Spacer(1, 40))
    els.append(HRFlowable(width="100%", thickness=0.3, color=G600, spaceAfter=10))
    els.append(Paragraph(
        "Generated by GhostPrompt AI Runtime Security Platform. Data is confidential.",
        ParagraphStyle("FT", fontName="Courier", fontSize=5.5, textColor=G600, alignment=TA_CENTER),
    ))

    doc.build(els, onFirstPage=_cover_bg, onLaterPages=_page_bg)
    pdf_bytes = buffer.getvalue()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="ghostprompt_analytics_{range_start.date()}.pdf"',
        },
    )
