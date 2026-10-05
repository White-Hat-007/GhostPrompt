"""
Model Security API Routes

Endpoints for model weight scanning, hallucination detection,
and model security analytics.
"""

import os
import uuid
import time
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Form
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.core.logging import get_logger
from app.services.firewall.detectors.hallucination_detector import hallucination_engine
from app.services.firewall.detectors.model_weight_scanner import ModelWeightScanner, ModelScanResult

from app.core.security import require_plan

settings = get_settings()
logger = get_logger("api.model_security")
# Public router — stats/read-only endpoints (no plan gate)
router = APIRouter(
    prefix="/model-security",
    tags=["Model Security"],
)

# Enterprise-gated router — scan/write endpoints
enterprise_router = APIRouter(
    prefix="/model-security",
    tags=["Model Security"],
    dependencies=[Depends(require_plan("enterprise"))]
)

# Initialize singleton instances
weight_scanner = ModelWeightScanner()

_initialized = False

async def _ensure_initialized():
    global _initialized
    if not _initialized:
        # The HallucinationEngine has lazy initialization per layer, so we just init the layer 0 here
        await hallucination_engine.layer_0_structural.initialize()
        await weight_scanner.initialize()
        _initialized = True


# ═══════════════════════════════════════════════════════════════════
#  Hallucination Detection Endpoints
# ═══════════════════════════════════════════════════════════════════

class HallucinationScanRequest(BaseModel):
    """Request to scan LLM output for hallucinations."""
    output_text: str = Field(..., max_length=50000, description="The LLM-generated output text to analyze")
    input_text: Optional[str] = Field(None, max_length=50000, description="The original input prompt (for context)")
    context_documents: Optional[list[str]] = Field(None, description="Optional RAG context documents for grounding verification")
    policy_tier: Optional[str] = Field(None, description="FAST, STANDARD, THOROUGH, MAXIMUM, or ADAPTIVE")
    model: Optional[str] = Field(None, description="The model that generated the output")
    provider: Optional[str] = Field(None, description="The model provider")


class HallucinationScanResponse(BaseModel):
    """Result of hallucination scanning."""
    request_id: str
    hallucination_score: float
    risk_level: str  # safe, low, medium, high, critical
    is_hallucinated: bool
    detections: list[dict]
    signals_found: int
    categories: list[str]
    scan_duration_ms: float
    policy_tier_used: str = ""
    layer_results: dict = {}
    model: Optional[str] = None
    recommendations: list[str] = []
    # Forensic Intelligence fields
    forensic_report: Optional[dict] = None
    issues: list[dict] = []
    verification_checklist: dict = {}
    category_distribution: dict = {}
    highlight_ranges: list[dict] = []
    forensic_summary: str = ""


@router.post("/hallucination/scan", response_model=HallucinationScanResponse)
@limiter.limit("30/minute")
async def scan_hallucination(payload: HallucinationScanRequest, request: Request):
    """
    Scan LLM output for hallucination indicators.
    
    Analyzes the response text for:
    - Confidence hedging & uncertainty markers
    - Self-contradictions within the response
    - Fabricated citations (fake DOIs, URLs, papers)
    - Statistical anomalies (implausible numbers)
    - Entity fabrication signals
    - Generation collapse / repetition drift
    """
    await _ensure_initialized()
    start = time.perf_counter()
    request_id = f"hall_{uuid.uuid4().hex[:12]}"

    
    # Run multi-layer hallucination detection
    ml_results = await hallucination_engine.detect_multi_layer(
        payload.output_text,
        input_text=payload.input_text,
        context_documents=payload.context_documents,
        policy_tier=payload.policy_tier
    )
    
    layer_0 = ml_results.get("layer_0_structural", {"detections": []})
    hall_score = ml_results.get("final_score", 0.0)
    is_hallucinated = ml_results.get("is_hallucination", False)
    
    # Extract structural detections for compatibility
    all_detections = layer_0["detections"]
    categories = list(set(d["category"] for d in all_detections))

    # Risk level
    if hall_score >= 0.8:
        risk_level = "critical"
    elif hall_score >= 0.6:
        risk_level = "high"
    elif hall_score >= 0.35:
        risk_level = "medium"
    elif hall_score >= 0.1:
        risk_level = "low"
    else:
        risk_level = "safe"

    # Recommendations
    recommendations = []
    
    if any("hedging" in c for c in categories):
        recommendations.append("The model shows high uncertainty. Consider rephrasing the question or using a more capable model.")
    if any("contradiction" in c for c in categories):
        recommendations.append("Self-contradictions detected. Cross-reference claims with authoritative sources.")
    if any("citation" in c for c in categories):
        recommendations.append("Citations may be fabricated. Verify all referenced papers, DOIs, and URLs independently.")
    if any("statistical" in c for c in categories):
        recommendations.append("Statistical claims appear implausible. Validate all numbers against reliable data sources.")
    if any("entity" in c for c in categories):
        recommendations.append("Named entities (people, organizations) may be fabricated. Verify their existence.")
    if any("repetition" in c for c in categories):
        recommendations.append("Generation collapse detected. The model may need a lower temperature or different prompt.")
    if any("elicitation" in c for c in categories):
        recommendations.append("The input prompt appears designed to force hallucination. Block this input.")
        
    for name, res in ml_results.get("layer_results", {}).items():
        if res.get("is_hallucination"):
            recommendations.append(f"Layer {name} flagged potential hallucination.")

    if not recommendations and risk_level == "safe":
        recommendations.append("No significant hallucination signals detected. Output appears reliable.")

    # Extract forensic analysis
    forensic = ml_results.get("forensic_analysis", {})
    forensic_issues = forensic.get("issues", [])
    
    # Merge forensic recommendations with layer recommendations
    for rec in forensic.get("recommendations", []):
        if rec not in recommendations:
            recommendations.append(rec)

    duration = (time.perf_counter() - start) * 1000

    return HallucinationScanResponse(
        request_id=request_id,
        hallucination_score=round(hall_score, 4),
        risk_level=risk_level,
        is_hallucinated=is_hallucinated,
        detections=all_detections,
        signals_found=len(all_detections) + len(forensic_issues),
        categories=categories,
        scan_duration_ms=round(duration, 2),
        policy_tier_used=ml_results["policy_tier_used"],
        layer_results=ml_results.get("layer_results", {}),
        model=payload.model,
        recommendations=recommendations,
        forensic_report=forensic,
        issues=forensic_issues,
        verification_checklist=forensic.get("verification_checklist", {}),
        category_distribution=forensic.get("category_distribution", {}),
        highlight_ranges=forensic.get("highlight_ranges", []),
        forensic_summary=forensic.get("summary", ""),
    )


@router.get("/hallucination/stats")
async def hallucination_stats():
    """Get hallucination detection statistics and demo data."""
    return {
        "total_outputs_scanned": 12847,
        "hallucinations_detected": 1893,
        "hallucination_rate": 14.7,
        "avg_hallucination_score": 0.32,
        "category_breakdown": {
            "fabricated_citation": 487,
            "self_contradiction": 312,
            "excessive_hedging": 289,
            "statistical_anomaly": 267,
            "entity_fabrication": 231,
            "repetition_drift": 184,
            "elicitation_attempt": 123,
        },
        "severity_distribution": {
            "critical": 89,
            "high": 412,
            "medium": 823,
            "low": 569,
        },
        "model_breakdown": {
            "gpt-4": {"scanned": 4123, "hallucinated": 287, "rate": 6.9},
            "gpt-3.5-turbo": {"scanned": 3456, "hallucinated": 621, "rate": 17.9},
            "claude-3-sonnet": {"scanned": 2345, "hallucinated": 328, "rate": 14.0},
            "llama-3-70b": {"scanned": 1567, "hallucinated": 312, "rate": 19.9},
            "mistral-7b": {"scanned": 1356, "hallucinated": 345, "rate": 25.4},
        },
        "trend_data": [
            {"date": "2025-05-24", "scanned": 1823, "hallucinated": 267},
            {"date": "2025-05-25", "scanned": 1945, "hallucinated": 289},
            {"date": "2025-05-26", "scanned": 2012, "hallucinated": 312},
            {"date": "2025-05-27", "scanned": 1876, "hallucinated": 278},
            {"date": "2025-05-28", "scanned": 2134, "hallucinated": 321},
            {"date": "2025-05-29", "scanned": 1987, "hallucinated": 245},
            {"date": "2025-05-30", "scanned": 1070, "hallucinated": 181},
        ],
    }


# ═══════════════════════════════════════════════════════════════════
#  Model Weight Scanning Endpoints
# ═══════════════════════════════════════════════════════════════════

@enterprise_router.post("/weight-scan/upload")
@limiter.limit("5/minute")
async def scan_model_upload(
    request: Request,
    file: UploadFile = File(..., description="Model file to scan"),
):
    """
    Upload and scan a model file for security threats.
    
    Detects:
    - Pickle exploits (arbitrary code execution)
    - Embedded scripts (hidden malware)
    - Network callbacks (data exfiltration)
    - Trojan signatures (known backdoors)
    - Dangerous module imports
    - Metadata poisoning
    - File size anomalies
    """
    await _ensure_initialized()

    # Validate file size (max 500MB for upload scan)
    max_size = 500 * 1024 * 1024
    content = await file.read()
    if len(content) > max_size:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum upload size is 500MB."
        )

    result = await weight_scanner.scan_bytes(content, filename=file.filename or "uploaded_model")

    return {
        "request_id": f"wscan_{uuid.uuid4().hex[:12]}",
        "scan_result": result.model_dump(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@enterprise_router.post("/weight-scan/path")
@limiter.limit("10/minute")
async def scan_model_path(
    request: Request,
    file_path: str = Form(..., description="Path to the model file on the server"),
):
    """Scan a model file by its server path."""
    await _ensure_initialized()

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Model file not found at specified path")

    result = await weight_scanner.scan_file(file_path)

    return {
        "request_id": f"wscan_{uuid.uuid4().hex[:12]}",
        "scan_result": result.model_dump(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/weight-scan/stats")
async def weight_scan_stats():
    """Get model weight scanning statistics and demo data."""
    return {
        "total_models_scanned": 2847,
        "threats_found": 342,
        "clean_models": 2505,
        "threat_rate": 12.0,
        "avg_scan_duration_ms": 245.8,
        "format_breakdown": {
            "pytorch": {"scanned": 1234, "threats": 187, "rate": 15.2},
            "safetensors": {"scanned": 876, "threats": 12, "rate": 1.4},
            "onnx": {"scanned": 345, "threats": 67, "rate": 19.4},
            "tensorflow": {"scanned": 234, "threats": 45, "rate": 19.2},
            "gguf": {"scanned": 158, "threats": 31, "rate": 19.6},
        },
        "threat_category_breakdown": {
            "pickle_exploit": 145,
            "embedded_script": 67,
            "dangerous_import": 54,
            "network_callback": 38,
            "trojan_signature": 21,
            "metadata_poisoning": 12,
            "size_anomaly": 5,
        },
        "severity_distribution": {
            "critical": 98,
            "high": 134,
            "medium": 78,
            "low": 32,
        },
        "recent_scans": [
            {
                "file_name": "llama-3-8b-instruct.safetensors",
                "format": "safetensors",
                "file_size_gb": 15.6,
                "risk_level": "safe",
                "threats": 0,
                "scan_time": "2025-05-30T08:23:41Z",
                "parameters": "8B",
                "hash": "a3f2b1c9d4e5f6a7b8c9d0e1f2a3b4c5",
            },
            {
                "file_name": "suspicious_model.pt",
                "format": "pytorch",
                "file_size_gb": 2.3,
                "risk_level": "critical",
                "threats": 4,
                "scan_time": "2025-05-30T07:12:33Z",
                "parameters": "1.2B",
                "hash": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
            },
            {
                "file_name": "mistral-7b-v0.2.gguf",
                "format": "gguf",
                "file_size_gb": 4.1,
                "risk_level": "safe",
                "threats": 0,
                "scan_time": "2025-05-30T06:45:12Z",
                "parameters": "7B",
                "hash": "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3",
            },
            {
                "file_name": "backdoored_classifier.pkl",
                "format": "pickle",
                "file_size_gb": 0.8,
                "risk_level": "critical",
                "threats": 7,
                "scan_time": "2025-05-30T05:33:21Z",
                "parameters": "350M",
                "hash": "c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
            },
            {
                "file_name": "gpt2-medium.onnx",
                "format": "onnx",
                "file_size_gb": 1.4,
                "risk_level": "low",
                "threats": 1,
                "scan_time": "2025-05-30T04:21:09Z",
                "parameters": "345M",
                "hash": "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6",
            },
        ],
        "trend_data": [
            {"date": "2025-05-24", "scanned": 412, "threats": 49},
            {"date": "2025-05-25", "scanned": 387, "threats": 52},
            {"date": "2025-05-26", "scanned": 445, "threats": 43},
            {"date": "2025-05-27", "scanned": 398, "threats": 56},
            {"date": "2025-05-28", "scanned": 467, "threats": 48},
            {"date": "2025-05-29", "scanned": 423, "threats": 51},
            {"date": "2025-05-30", "scanned": 315, "threats": 43},
        ],
    }
