"""
GhostPrompt — Compliance Frameworks API

Endpoints for all 9 compliance frameworks:
  NIST AI RMF, ISO 42001, SOC 2 Type II, PCI DSS, GDPR, EU AI Act,
  HIPAA, CCPA/CPRA, DPDPA (India 2023).

Integrates with existing enterprise compliance infrastructure.

IMPORTANT: GhostPrompt generates compliance evidence. It is NOT itself
certified under any framework. These endpoints produce evidence to support
your organization's own certification or alignment efforts.
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

from app.core.config import get_settings
from app.core.security import get_current_user, require_plan
from app.core.permissions import require_permission
from app.core.logging import get_logger
from app.compliance.unified_engine import (
    unified_compliance_engine, ALL_FRAMEWORK_IDS, FRAMEWORK_REGISTRY
)
from app.compliance.signing_engine import signing_engine

settings = get_settings()
logger = get_logger("compliance_frameworks")
router = APIRouter(
    prefix="/compliance-frameworks",
    tags=["Compliance Frameworks"],
    dependencies=[Depends(require_permission("compliance.view"))],
)

# ── Framework display names for PDF titles ──
FRAMEWORK_TITLES = {
    "nist-ai-rmf": "NIST AI RMF 1.0 Alignment Report",
    "iso-42001": "ISO/IEC 42001:2023 Readiness Report",
    "soc2-type2": "SOC 2 Type II Technical Control Evidence",
    "pci-dss": "PCI DSS v4.0 Technical Control Evidence",
    "gdpr": "GDPR Technical Control Mapping Report",
    "eu-ai-act": "EU AI Act Alignment Report",
    "hipaa": "HIPAA Technical Safeguards Alignment Report",
    "ccpa": "CCPA/CPRA Technical Control Mapping Report",
    "dpdpa": "DPDPA (India 2023) Technical Control Mapping Report",
}

def _url_to_id(framework_url: str) -> str:
    """Convert URL-safe framework name to internal ID."""
    return framework_url.replace("-", "_")

def _id_to_url(framework_id: str) -> str:
    """Convert internal framework ID to URL-safe name."""
    return framework_id.replace("_", "-")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NIST AI RMF 1.0
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@router.get("/nist-ai-rmf", dependencies=[Depends(require_plan("pro"))])
async def get_nist_ai_rmf_report(
    current_user: dict = Depends(get_current_user),
):
    """
    Generate NIST AI RMF 1.0 alignment report.

    Returns full subcategory-level mapping with evidence sources,
    alignment status, and gap remediation suggestions.

    Note: This report documents GhostPrompt's technical control mapping.
    It is NOT a NIST certification.
    """
    tenant_id = str(current_user["org_id"])
    logger.info("nist_ai_rmf_report_generated", tenant_id=tenant_id)
    return unified_compliance_engine.generate_nist_report(tenant_id)


@router.get("/nist-ai-rmf/summary", dependencies=[Depends(require_plan("pro"))])
async def get_nist_ai_rmf_summary(
    current_user: dict = Depends(get_current_user),
):
    """Get NIST AI RMF alignment score summary."""
    from app.compliance.nist_ai_rmf import get_nist_summary
    return get_nist_summary()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ISO/IEC 42001:2023
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@router.get("/iso-42001", dependencies=[Depends(require_plan("pro"))])
async def get_iso_42001_report(
    current_user: dict = Depends(get_current_user),
):
    """
    Generate ISO/IEC 42001:2023 readiness report.

    Returns full clause-level mapping with evidence sources,
    readiness status, and gap remediation suggestions.

    Note: This report documents GhostPrompt's technical control mapping.
    It is NOT an ISO certification.
    """
    tenant_id = str(current_user["org_id"])
    logger.info("iso_42001_report_generated", tenant_id=tenant_id)
    return unified_compliance_engine.generate_iso_report(tenant_id)


@router.get("/iso-42001/summary", dependencies=[Depends(require_plan("pro"))])
async def get_iso_42001_summary(
    current_user: dict = Depends(get_current_user),
):
    """Get ISO 42001 readiness score summary."""
    from app.compliance.iso_42001 import get_iso_summary
    return get_iso_summary()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INDIVIDUAL FRAMEWORK REPORTS (7 new frameworks)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@router.get("/report/{framework_id}", dependencies=[Depends(require_plan("pro"))])
async def get_framework_report(
    framework_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Generate a compliance report for any of the 9 supported frameworks.

    Supported framework IDs: nist-ai-rmf, iso-42001, soc2-type2, pci-dss,
    gdpr, eu-ai-act, hipaa, ccpa, dpdpa.
    """
    internal_id = _url_to_id(framework_id)
    tenant_id = str(current_user["org_id"])

    if internal_id not in ALL_FRAMEWORK_IDS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework: {framework_id}. Supported: {[_id_to_url(f) for f in ALL_FRAMEWORK_IDS]}"
        )

    logger.info(f"{internal_id}_report_generated", tenant_id=tenant_id)
    return unified_compliance_engine.generate_any_report(internal_id, tenant_id)


@router.get("/report/{framework_id}/summary", dependencies=[Depends(require_plan("pro"))])
async def get_framework_summary(
    framework_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get alignment score summary for any framework."""
    internal_id = _url_to_id(framework_id)
    tenant_id = str(current_user["org_id"])

    if internal_id == "nist_ai_rmf":
        from app.compliance.nist_ai_rmf import get_nist_summary
        return get_nist_summary()
    elif internal_id == "iso_42001":
        from app.compliance.iso_42001 import get_iso_summary
        return get_iso_summary()
    elif internal_id in FRAMEWORK_REGISTRY:
        snapshot = unified_compliance_engine.generate_framework_snapshot(internal_id, tenant_id)
        return {
            "framework": snapshot.framework_name,
            "overall_score": snapshot.overall_score,
            "total_controls": snapshot.total_controls,
            "satisfied": snapshot.satisfied,
            "partial": snapshot.partial,
            "gap": snapshot.gap,
            "not_applicable": snapshot.not_applicable,
        }
    else:
        raise HTTPException(status_code=400, detail=f"Unknown framework: {framework_id}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CROSS-FRAMEWORK GOVERNANCE (all 9)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@router.get("/summary", dependencies=[Depends(require_plan("pro"))])
async def get_cross_framework_summary(
    current_user: dict = Depends(get_current_user),
):
    """
    Cross-framework governance maturity summary.

    Returns alignment/readiness scores across all 9 supported frameworks
    with an overall governance maturity index.
    """
    tenant_id = str(current_user["org_id"])
    return unified_compliance_engine.get_cross_framework_summary(tenant_id)


@router.get("/gaps", dependencies=[Depends(require_plan("pro"))])
async def get_all_gaps(
    current_user: dict = Depends(get_current_user),
):
    """
    Get all compliance gaps across all 9 frameworks with
    specific remediation suggestions.
    """
    tenant_id = str(current_user["org_id"])
    return unified_compliance_engine.get_all_gaps(tenant_id)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# REPORT DOWNLOADS (JSON + PDF)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@router.get("/download/{framework}", dependencies=[Depends(require_plan("pro"))])
async def download_report(
    framework: str,
    format: str = Query(default="json", regex="^(json|pdf|csv)$"),
    current_user: dict = Depends(get_current_user),
):
    """
    Download a compliance report in JSON, PDF, or CSV format.

    Supported frameworks: nist-ai-rmf, iso-42001, soc2-type2, pci-dss,
                          gdpr, eu-ai-act, hipaa, ccpa, dpdpa
    Supported formats: json, pdf, csv

    All formats include HMAC-SHA256 signatures for tamper evidence.
    PDF, CSV, and JSON for a single call all derive from one ComplianceSnapshot.
    """
    internal_id = _url_to_id(framework)
    tenant_id = str(current_user["org_id"])
    org_name = current_user.get("org_name", "Organization")
    title = FRAMEWORK_TITLES.get(framework, f"{framework} Compliance Report")

    if internal_id not in ALL_FRAMEWORK_IDS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework: {framework}. Supported: {[_id_to_url(f) for f in ALL_FRAMEWORK_IDS]}"
        )

    # Generate the report (single snapshot for consistency)
    report = unified_compliance_engine.generate_any_report(internal_id, tenant_id)
    logger.info(f"compliance_download_{internal_id}_{format}", tenant_id=tenant_id)

    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    safe_name = framework.replace('-', '_')

    if format == "json":
        filename = f"ghostprompt_{safe_name}_{ts}.json"
        return JSONResponse(
            content=report,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-GhostPrompt-Report-HMAC": report.get("hmac_signature", ""),
            },
        )

    if format == "csv":
        csv_content = unified_compliance_engine.generate_csv(internal_id, tenant_id)
        filename = f"ghostprompt_{safe_name}_{ts}.csv"
        return PlainTextResponse(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    # ── PDF Generation ──
    if format == "pdf":
        pdf_bytes = _generate_pdf_report(report, title, framework, org_name)
        from fastapi.responses import Response
        filename = f"ghostprompt_{safe_name}_{ts}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-GhostPrompt-Report-HMAC": report.get("hmac_signature", ""),
            },
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# REPORT VERIFICATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@router.post("/verify")
async def verify_report(payload: dict):
    """
    Verify the integrity of an exported compliance report.

    Accepts a JSON report payload and verifies its HMAC-SHA256 signature.
    Returns {valid: true/false, tampered: true/false}.

    For CSV verification, POST the raw CSV content as {"csv": "...content..."}.
    """
    if "csv" in payload:
        is_valid = signing_engine.verify_csv(payload["csv"])
        return {
            "valid": is_valid,
            "tampered": not is_valid,
            "format": "csv",
            "verification_method": "HMAC-SHA256",
        }

    # JSON payload verification
    is_valid = signing_engine.verify_payload(payload)
    return {
        "valid": is_valid,
        "tampered": not is_valid,
        "format": "json",
        "report_id": payload.get("report_id", "unknown"),
        "framework": payload.get("framework", "unknown"),
        "generated_at": payload.get("generated_at", "unknown"),
        "verification_method": "HMAC-SHA256",
    }


def _generate_pdf_report(report: dict, title: str, framework: str, org_name: str) -> bytes:
    """
    Generate an elite dark-themed PDF compliance report.
    Professional, hacker-aesthetic, Mr. Robot inspired.
    Dark backgrounds, hacker.jpg overlay, cyan/green accents, monospace typography.
    """
    import io
    import os

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import inch, mm
        from reportlab.lib.colors import HexColor, Color
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable, KeepTogether, Image,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    except ImportError:
        return _generate_fallback_pdf(report, title, framework, org_name)

    # ── Color Palette ──
    BG_DARK = HexColor("#0A0E14")
    BG_CARD = HexColor("#111827")
    BG_SURFACE = HexColor("#1F2937")
    CYAN = HexColor("#06B6D4")
    GREEN = HexColor("#10B981")
    AMBER = HexColor("#F59E0B")
    RED = HexColor("#EF4444")
    VIOLET = HexColor("#8B5CF6")
    WHITE = HexColor("#F9FAFB")
    GRAY_300 = HexColor("#D1D5DB")
    GRAY_400 = HexColor("#9CA3AF")
    GRAY_500 = HexColor("#6B7280")
    GRAY_600 = HexColor("#4B5563")
    GHOST_BLUE = HexColor("#4C6EF5")

    # Resolve hacker background image path
    _base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    _hacker_img = os.path.join(_base, "..", "frontend", "public", "bg", "hacker.jpg")
    _hacker_img = os.path.normpath(_hacker_img)
    _has_bg = os.path.isfile(_hacker_img)

    buffer = io.BytesIO()

    def _page_bg(canvas, doc):
        """Draw dark background with hacker image overlay and footer on every page."""
        canvas.saveState()
        w, h = A4

        # Layer 1: Full dark base
        canvas.setFillColor(BG_DARK)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)

        # Layer 2: Hacker background image (blended under dark overlay)
        if _has_bg:
            try:
                canvas.drawImage(_hacker_img, 0, 0, width=w, height=h,
                                 preserveAspectRatio=True, anchor='c', mask='auto')
            except Exception:
                pass

        # Layer 3: Dark overlay to dim the image — ensures text readability
        canvas.setFillColor(BG_DARK)
        canvas.saveState()
        canvas.setFillAlpha(0.88)  # 88% opaque = background subtly visible
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        canvas.restoreState()

        # Top accent line
        canvas.setStrokeColor(CYAN)
        canvas.setLineWidth(0.5)
        canvas.line(40, h - 35, w - 40, h - 35)
        # Bottom accent line
        canvas.line(40, 35, w - 40, 35)
        # Header branding
        canvas.setFont("Courier-Bold", 7)
        canvas.setFillColor(GRAY_500)
        canvas.drawString(45, h - 28, "GHOSTPROMPT")
        canvas.setFont("Courier", 6)
        canvas.drawString(120, h - 28, "// AI RUNTIME SECURITY PLATFORM")
        # Page number
        canvas.setFont("Courier", 6)
        canvas.setFillColor(GRAY_600)
        canvas.drawRightString(w - 45, 22, f"Page {doc.page}")
        # HMAC watermark
        hmac_sig = report.get("hmac_signature", "")
        if hmac_sig:
            canvas.setFont("Courier", 5)
            canvas.setFillColor(HexColor("#374151"))
            canvas.drawString(45, 22, f"HMAC-SHA256: {hmac_sig[:40]}...")
        canvas.restoreState()

    def _cover_page_bg(canvas, doc):
        """Cover page gets a stronger background image."""
        canvas.saveState()
        w, h = A4

        # Layer 1: Full dark base
        canvas.setFillColor(BG_DARK)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)

        # Layer 2: Hacker background image — stronger on cover
        if _has_bg:
            try:
                canvas.drawImage(_hacker_img, 0, 0, width=w, height=h,
                                 preserveAspectRatio=True, anchor='c', mask='auto')
            except Exception:
                pass

        # Layer 3: Dark overlay — image visible but text fully readable
        canvas.setFillColor(BG_DARK)
        canvas.saveState()
        canvas.setFillAlpha(0.78)  # 78% opaque = image clearly visible on cover
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        canvas.restoreState()

        # Decorative scan lines (hacker aesthetic)
        canvas.setStrokeColor(Color(0, 1, 1, alpha=0.03))
        canvas.setLineWidth(0.3)
        for y in range(0, int(h), 4):
            canvas.line(0, y, w, y)

        # Top accent line
        canvas.setStrokeColor(CYAN)
        canvas.setLineWidth(0.8)
        canvas.line(40, h - 35, w - 40, h - 35)
        # Bottom accent line
        canvas.line(40, 35, w - 40, 35)

        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=45, rightMargin=45, topMargin=55, bottomMargin=50,
    )

    styles = getSampleStyleSheet()
    elements = []

    # ── Custom Styles ──
    s_title_ghost = ParagraphStyle("GP_TitleGhost", fontName="Helvetica-Bold", fontSize=28, textColor=WHITE, alignment=TA_CENTER, spaceAfter=0)
    s_title_prompt = ParagraphStyle("GP_TitlePrompt", fontName="Helvetica-Bold", fontSize=28, textColor=CYAN, alignment=TA_CENTER, spaceAfter=6)
    s_subtitle = ParagraphStyle("GP_Subtitle", fontName="Courier", fontSize=10, textColor=GRAY_400, alignment=TA_CENTER, spaceAfter=20)
    s_h1 = ParagraphStyle("GP_H1", fontName="Helvetica-Bold", fontSize=16, textColor=CYAN, spaceBefore=20, spaceAfter=10)
    s_h2 = ParagraphStyle("GP_H2", fontName="Courier-Bold", fontSize=11, textColor=GHOST_BLUE, spaceBefore=14, spaceAfter=6)
    s_body = ParagraphStyle("GP_Body", fontName="Helvetica", fontSize=9, textColor=GRAY_300, spaceAfter=4, leading=13)
    s_mono = ParagraphStyle("GP_Mono", fontName="Courier", fontSize=8, textColor=GRAY_400, spaceAfter=3, leading=11)
    s_small = ParagraphStyle("GP_Small", fontName="Courier", fontSize=6.5, textColor=GRAY_500, spaceAfter=2, leading=9)
    s_disclaimer = ParagraphStyle("GP_Disc", fontName="Courier", fontSize=7, textColor=AMBER, alignment=TA_CENTER, spaceAfter=10, spaceBefore=10)
    s_score_big = ParagraphStyle("GP_ScoreBig", fontName="Helvetica-Bold", fontSize=48, textColor=GREEN, alignment=TA_CENTER, spaceAfter=20, leading=56)
    s_score_label = ParagraphStyle("GP_ScoreLabel", fontName="Courier", fontSize=9, textColor=GRAY_400, alignment=TA_CENTER, spaceAfter=20)

    # ═══════════════════════════════════════════════════
    # COVER PAGE
    # ═══════════════════════════════════════════════════
    elements.append(Spacer(1, 100))

    # Decorative top line
    elements.append(HRFlowable(width="60%", thickness=0.5, color=CYAN, spaceAfter=20))

    # Cover branding: > GHOST_PROMPT (matching website logo)
    elements.append(Paragraph(
        '<font name="Courier-Bold" size="12" color="#6B7280">&gt; </font>'
        '<font name="Helvetica-Bold" size="32" color="#F9FAFB">GHOST</font>'
        '<font name="Helvetica-Bold" size="32" color="#06B6D4">_PROMPT</font>',
        ParagraphStyle("GP_CoverTitle", fontName="Helvetica-Bold", fontSize=32,
                       textColor=CYAN, alignment=TA_CENTER, spaceAfter=20, leading=38)
    ))
    elements.append(Paragraph("AI Runtime Security &amp; Operations Platform", s_subtitle))
    elements.append(Spacer(1, 40))

    # Report title
    report_title_style = ParagraphStyle("RT", fontName="Helvetica-Bold", fontSize=20, textColor=WHITE, alignment=TA_CENTER, spaceAfter=6)
    elements.append(Paragraph(title, report_title_style))
    elements.append(HRFlowable(width="40%", thickness=0.3, color=GRAY_600, spaceBefore=10, spaceAfter=20))

    # Cover metadata table
    cover_data = [
        ["ORGANIZATION", org_name],
        ["FRAMEWORK", report.get("framework", framework)],
        ["GENERATED", report.get("generated_at", "N/A")],
        ["REPORT ID", report.get("report_id", "N/A")],
        ["CLASSIFICATION", "CONFIDENTIAL"],
    ]
    cover_table = Table(cover_data, colWidths=[140, 320])
    cover_table.setStyle(TableStyle([
        ("TEXTCOLOR", (0, 0), (0, -1), GRAY_500),
        ("TEXTCOLOR", (1, 0), (1, -1), WHITE),
        ("FONTNAME", (0, 0), (0, -1), "Courier"),
        ("FONTNAME", (1, 0), (1, -1), "Courier-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, HexColor("#1F2937")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    elements.append(cover_table)

    elements.append(Spacer(1, 30))
    elements.append(Paragraph(
        "⚠ DISCLAIMER: This report documents GhostPrompt's technical control mapping. "
        "It is evidence to support your organization's own risk management program or "
        "certification efforts — NOT a certification itself.",
        s_disclaimer,
    ))

    elements.append(PageBreak())

    # ═══════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════
    elements.append(Paragraph("EXECUTIVE SUMMARY", s_h1))
    elements.append(HRFlowable(width="100%", thickness=0.3, color=HexColor("#1F2937"), spaceAfter=12))

    score_key = "overall_alignment_score" if "overall_alignment_score" in report else (
        "overall_readiness_score" if "overall_readiness_score" in report else "overall_score"
    )
    score = report.get(score_key, 0)

    elements.append(Paragraph(f"{score}%", s_score_big))
    elements.append(Paragraph("OVERALL ALIGNMENT SCORE", s_score_label))

    # Score breakdown table
    satisfied = report.get("satisfied", 0)
    partial = report.get("partial", 0)
    gap = report.get("gap", 0)
    not_applicable = report.get("not_applicable", 0)
    total = report.get("total_subcategories", report.get("total_requirements", report.get("total_controls", 0)))

    stats_data = [
        ["TOTAL CONTROLS", "SATISFIED", "PARTIAL", "GAPS", "N/A"],
        [str(total), str(satisfied), str(partial), str(gap), str(not_applicable)],
    ]
    stats_table = Table(stats_data, colWidths=[100, 100, 100, 100, 100])
    stats_table.setStyle(TableStyle([
        ("TEXTCOLOR", (0, 0), (-1, 0), GRAY_500),
        ("TEXTCOLOR", (0, 1), (0, 1), WHITE),
        ("TEXTCOLOR", (1, 1), (1, 1), GREEN),
        ("TEXTCOLOR", (2, 1), (2, 1), AMBER),
        ("TEXTCOLOR", (3, 1), (3, 1), RED),
        ("FONTNAME", (0, 0), (-1, 0), "Courier"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7),
        ("FONTSIZE", (0, 1), (-1, 1), 18),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LINEBELOW", (0, 0), (-1, 0), 0.3, HexColor("#374151")),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 16))

    elements.append(PageBreak())

    # ═══════════════════════════════════════════════════
    # DETAILED BREAKDOWN
    # ═══════════════════════════════════════════════════
    elements.append(Paragraph("DETAILED CONTROL MAPPING", s_h1))
    elements.append(HRFlowable(width="100%", thickness=0.3, color=HexColor("#1F2937"), spaceAfter=8))

    sections = report.get("functions") or report.get("clauses") or report.get("sections") or {}
    for section_name, section_data in sections.items():
        section_desc = section_data.get("description", section_data.get("title", ""))
        section_score = section_data.get("score", 0)

        # Section header
        score_color = "#10B981" if section_score >= 95 else "#F59E0B" if section_score >= 70 else "#EF4444"
        elements.append(Paragraph(
            f'<font color="#06B6D4">▸</font> {section_name} — {section_desc}'
            f'  <font color="{score_color}" size="10">[{section_score}%]</font>',
            s_h2,
        ))

        items = section_data.get("subcategories") or section_data.get("requirements") or section_data.get("controls") or {}
        for item_id, item_data in items.items():
            status = item_data.get("status", "UNKNOWN")
            if status == "SATISFIED":
                icon, s_color = "✓", "#10B981"
            elif status == "PARTIAL":
                icon, s_color = "◐", "#F59E0B"
            elif status == "NOT_APPLICABLE":
                icon, s_color = "—", "#6B7280"
            else:
                icon, s_color = "✗", "#EF4444"

            # Control title (if present)
            ctrl_title = item_data.get("title", "")
            title_str = f' — <font color="#D1D5DB"><b>{ctrl_title}</b></font>' if ctrl_title else ""

            # Control row
            elements.append(Paragraph(
                f'<font color="{s_color}">{icon}</font> '
                f'<font color="#818CF8"><b>{item_id}</b></font>{title_str}',
                s_body,
            ))
            # Requirement text
            elements.append(Paragraph(
                f'<font color="#9CA3AF">{item_data.get("requirement", "")}</font>',
                s_small,
            ))

            # Gap note (if any)
            gap_note = item_data.get("gap_note", "")
            if gap_note:
                elements.append(Paragraph(
                    f'<font color="#374151">│</font>  <font color="#FCD34D">⚠</font> {gap_note}',
                    s_small,
                ))

            # Evidence bullets
            for ev in item_data.get("evidence_sources", []):
                elements.append(Paragraph(
                    f'<font color="#374151">│</font>  <font color="#6B7280">▪</font> {ev}',
                    s_small,
                ))

        elements.append(Spacer(1, 6))

    # ═══════════════════════════════════════════════════
    # GAP REMEDIATION APPENDIX
    # ═══════════════════════════════════════════════════
    gaps = report.get("gaps", [])
    if gaps:
        elements.append(PageBreak())
        elements.append(Paragraph("GAP REMEDIATION APPENDIX", s_h1))
        elements.append(HRFlowable(width="100%", thickness=0.3, color=HexColor("#1F2937"), spaceAfter=8))
        elements.append(Paragraph(
            f'<font color="#F59E0B">{len(gaps)}</font> control(s) require remediation action:',
            s_body,
        ))
        elements.append(Spacer(1, 8))

        for gap in gaps:
            elements.append(Paragraph(
                f'<font color="#F59E0B">◐</font> '
                f'<font color="#818CF8"><b>{gap.get("id", "")}</b></font> — '
                f'{gap.get("requirement", "")}',
                s_body,
            ))
            if gap.get("remediation"):
                elements.append(Paragraph(
                    f'<font color="#374151">│</font>  <font color="#FCD34D">→</font> {gap["remediation"]}',
                    s_mono,
                ))
            elements.append(Spacer(1, 4))

    # ── Final HMAC Attestation ──
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="80%", thickness=0.3, color=GRAY_600, spaceAfter=8))
    hmac_sig = report.get("hmac_signature", "N/A")
    elements.append(Paragraph(
        f'HMAC-SHA256: {hmac_sig}',
        ParagraphStyle("HMAC_Final", fontName="Courier", fontSize=5.5, textColor=GRAY_500, alignment=TA_CENTER),
    ))
    elements.append(Paragraph(
        "This report is digitally signed for tamper evidence. Verify integrity via /api/v1/compliance-frameworks/verify.",
        ParagraphStyle("HMAC_Note", fontName="Courier", fontSize=5.5, textColor=GRAY_600, alignment=TA_CENTER),
    ))

    doc.build(elements, onFirstPage=_cover_page_bg, onLaterPages=_page_bg)
    return buffer.getvalue()


def _generate_fallback_pdf(report: dict, title: str, framework: str, org_name: str) -> bytes:
    """Fallback text report when reportlab is not installed."""
    import io

    lines = []
    lines.append(f"{'='*70}")
    lines.append(f"GHOSTPROMPT — {title}")
    lines.append(f"{'='*70}")
    lines.append(f"Organization: {org_name}")
    lines.append(f"Framework: {report.get('framework', framework)}")
    lines.append(f"Generated: {report.get('generated_at', 'N/A')}")
    lines.append(f"Report ID: {report.get('report_id', 'N/A')}")
    lines.append("")
    lines.append("DISCLAIMER: This report documents GhostPrompt's technical control")
    lines.append("mapping. It is NOT a certification. GhostPrompt is not NIST or ISO certified.")
    lines.append(f"{'─'*70}")
    lines.append("")

    score_key = "overall_alignment_score" if "overall_alignment_score" in report else (
        "overall_readiness_score" if "overall_readiness_score" in report else "overall_score"
    )
    lines.append(f"OVERALL SCORE: {report.get(score_key, 0)}%")
    total = report.get('total_subcategories', report.get('total_requirements', report.get('total_controls', 0)))
    lines.append(f"Total: {total} | Satisfied: {report.get('satisfied', 0)} | Partial: {report.get('partial', 0)} | Gaps: {report.get('gap', 0)} | N/A: {report.get('not_applicable', 0)}")
    lines.append("")

    sections = report.get("functions") or report.get("clauses") or report.get("sections") or {}
    for sec_name, sec_data in sections.items():
        lines.append(f"{'─'*70}")
        lines.append(f"  {sec_name}: {sec_data.get('description', sec_data.get('title', ''))}")
        lines.append(f"  Score: {sec_data.get('score', 0)}%")
        lines.append("")

        items = sec_data.get("subcategories") or sec_data.get("requirements") or sec_data.get("controls") or {}
        for item_id, item_data in items.items():
            status = item_data.get("status", "UNKNOWN")
            icon = "[✓]" if status == "SATISFIED" else "[◐]" if status == "PARTIAL" else "[—]" if status == "NOT_APPLICABLE" else "[✗]"
            ctrl_title = item_data.get("title", "")
            title_suffix = f" — {ctrl_title}" if ctrl_title else ""
            lines.append(f"  {icon} {item_id}{title_suffix}")
            lines.append(f"       {item_data.get('requirement', '')}")
            gap_note = item_data.get("gap_note", "")
            if gap_note:
                lines.append(f"       ⚠ {gap_note}")
            for ev in item_data.get("evidence_sources", []):
                lines.append(f"       • {ev}")
        lines.append("")

    gaps = report.get("gaps", [])
    if gaps:
        lines.append(f"{'='*70}")
        lines.append("GAP REMEDIATION APPENDIX")
        lines.append(f"{'='*70}")
        for gap in gaps:
            lines.append(f"  [◐] {gap.get('id', '')}: {gap.get('requirement', '')}")
            if gap.get("remediation"):
                lines.append(f"       → {gap['remediation']}")
        lines.append("")

    lines.append(f"{'─'*70}")
    lines.append(f"HMAC-SHA256: {report.get('hmac_signature', 'N/A')[:32]}…")
    lines.append("This report is digitally signed for tamper evidence.")

    return "\n".join(lines).encode("utf-8")

