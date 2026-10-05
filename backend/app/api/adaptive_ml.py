"""
Adaptive ML API — Real Drift Monitoring & Threshold Management

REST endpoints for the adaptive ML drift daemon:
- Get detector baselines
- Record scores for drift monitoring
- Approve/reject threshold changes
- Toggle auto-tune
- View change history
- Analyst feedback loop
- Settings persisted to Organization.settings DB column
"""


from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.logging import get_logger
from app.core.permissions import require_permission
from app.core.security import get_current_user
from app.ml.adaptive.drift_daemon import drift_daemon
from app.models.organization import Organization

logger = get_logger("api.adaptive_ml")
router = APIRouter(
    prefix="/adaptive-ml",
    tags=["Adaptive ML"],
    dependencies=[Depends(require_permission("adaptive_ml.view"))],
)


class RecordScoreRequest(BaseModel):
    detector_name: str
    score: float


class ApproveRequest(BaseModel):
    change_id: str


class AutoTuneToggle(BaseModel):
    enabled: bool


class SensitivityUpdate(BaseModel):
    detection_sensitivity: float | None = None
    auto_tune_aggressiveness: float | None = None
    min_confidence: float | None = None


class FeedbackRequest(BaseModel):
    scan_id: str
    detector_name: str
    verdict: str  # "correct", "false_positive", "false_negative"
    notes: str | None = None


# ── DB-persisted settings helpers ──

DEFAULT_ADAPTIVE_SETTINGS = {
    "auto_tune": True,
    "detection_sensitivity": 75,
    "auto_tune_aggressiveness": 60,
    "min_confidence": 40,
}


async def _get_org_adaptive_settings(org_id: str, db: AsyncSession) -> dict:
    """Get adaptive ML settings from Organization.settings JSON column."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        return dict(DEFAULT_ADAPTIVE_SETTINGS)
    stored = (org.settings or {}).get("adaptive_ml", {})
    return {**DEFAULT_ADAPTIVE_SETTINGS, **stored}


async def _save_org_adaptive_settings(org_id: str, adaptive_settings: dict, db: AsyncSession):
    """Persist adaptive ML settings to Organization.settings JSON column."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        return
    current = org.settings or {}
    current["adaptive_ml"] = adaptive_settings
    await db.execute(
        update(Organization).where(Organization.id == org_id).values(settings=current)
    )
    await db.commit()
    logger.info("adaptive_ml_settings_persisted", org=org_id)


# ── In-memory analyst feedback store (per-org) ──
_feedback_store: dict[str, list[dict]] = {}


@router.get("/status")
async def adaptive_ml_status(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get adaptive ML status with all detector baselines."""
    org_id = str(current_user.get("org_id", "default"))
    baselines = drift_daemon.get_baselines(org_id)
    pending = drift_daemon.get_pending(org_id)
    changes = drift_daemon.get_changes(org_id)
    org_settings = await _get_org_adaptive_settings(org_id, db)

    # Calculate summary stats from baselines
    if baselines:
        avg_threshold = sum(b["current_threshold"] for b in baselines) / len(baselines)
        drifting = sum(1 for b in baselines if b["drift_detected"])
        total_samples = sum(b["sample_count"] for b in baselines)
    else:
        avg_threshold = 0.70
        drifting = 0
        total_samples = 0

    # Feedback stats
    feedback = _feedback_store.get(org_id, [])
    feedback_summary = {
        "total": len(feedback),
        "correct": sum(1 for f in feedback if f["verdict"] == "correct"),
        "false_positives": sum(1 for f in feedback if f["verdict"] == "false_positive"),
        "false_negatives": sum(1 for f in feedback if f["verdict"] == "false_negative"),
    }

    return {
        "baselines": baselines,
        "pending_approvals": pending,
        "recent_changes": changes[-20:],
        "summary": {
            "total_detectors": len(baselines),
            "avg_threshold": round(avg_threshold, 4),
            "drifting_detectors": drifting,
            "total_samples": total_samples,
            "pending_approvals": len(pending),
            "total_changes": len(changes),
        },
        "settings": org_settings,
        "feedback_summary": feedback_summary,
    }


@router.post("/record-score")
async def record_score(
    req: RecordScoreRequest,
    current_user: dict = Depends(get_current_user),
):
    """Record a detection score for drift monitoring."""
    org_id = str(current_user.get("org_id", "default"))
    drift_daemon.record_score(org_id, req.detector_name, req.score)
    return {"status": "recorded", "detector": req.detector_name}


@router.post("/approve")
async def approve_change(
    req: ApproveRequest,
    current_user: dict = Depends(get_current_user),
):
    """Approve a pending threshold change."""
    approver = current_user.get("email", "unknown")
    success = drift_daemon.approve_change(req.change_id, approver)
    if not success:
        raise HTTPException(404, "Change not found or already processed")
    return {"status": "approved", "change_id": req.change_id}


@router.post("/reject")
async def reject_change(
    req: ApproveRequest,
    current_user: dict = Depends(get_current_user),
):
    """Reject a pending threshold change."""
    success = drift_daemon.reject_change(req.change_id)
    if not success:
        raise HTTPException(404, "Change not found or already processed")
    return {"status": "rejected", "change_id": req.change_id}


@router.post("/settings")
async def update_settings(
    req: SensitivityUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update adaptive ML sensitivity settings — persisted to DB."""
    org_id = str(current_user.get("org_id", "default"))
    s = await _get_org_adaptive_settings(org_id, db)

    if req.detection_sensitivity is not None:
        s["detection_sensitivity"] = max(0, min(100, req.detection_sensitivity))
    if req.auto_tune_aggressiveness is not None:
        s["auto_tune_aggressiveness"] = max(0, min(100, req.auto_tune_aggressiveness))
    if req.min_confidence is not None:
        s["min_confidence"] = max(0, min(100, req.min_confidence))

    await _save_org_adaptive_settings(org_id, s, db)
    return {"status": "updated", "settings": s}


@router.post("/toggle-auto-tune")
async def toggle_auto_tune(
    req: AutoTuneToggle,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Toggle auto-tune on/off — persisted to DB."""
    org_id = str(current_user.get("org_id", "default"))
    s = await _get_org_adaptive_settings(org_id, db)
    s["auto_tune"] = req.enabled
    await _save_org_adaptive_settings(org_id, s, db)
    return {"status": "updated", "auto_tune": req.enabled}


@router.get("/history")
async def change_history(
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
):
    """Get threshold change history."""
    org_id = str(current_user.get("org_id", "default"))
    changes = drift_daemon.get_changes(org_id)
    return {"changes": changes[-limit:], "total": len(changes)}


@router.post("/feedback")
async def analyst_feedback(
    req: FeedbackRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Analyst feedback loop — submit verdict on a detection result.
    This feeds back into the drift daemon to improve thresholds.
    """
    org_id = str(current_user.get("org_id", "default"))
    email = current_user.get("email", "unknown")

    feedback_entry = {
        "scan_id": req.scan_id,
        "detector_name": req.detector_name,
        "verdict": req.verdict,
        "notes": req.notes,
        "analyst_email": email,
        "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }

    if org_id not in _feedback_store:
        _feedback_store[org_id] = []
    _feedback_store[org_id].append(feedback_entry)

    # If false_positive, nudge the detector's threshold up (less sensitive)
    # If false_negative, nudge it down (more sensitive)
    if req.verdict == "false_positive":
        drift_daemon.record_score(org_id, req.detector_name, 0.0)  # Low score = benign
        logger.info("feedback_false_positive", detector=req.detector_name, analyst=email)
    elif req.verdict == "false_negative":
        drift_daemon.record_score(org_id, req.detector_name, 1.0)  # High score = attack
        logger.info("feedback_false_negative", detector=req.detector_name, analyst=email)

    return {"status": "feedback_recorded", "verdict": req.verdict, "detector": req.detector_name}


@router.get("/feedback")
async def get_feedback(
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
):
    """Get analyst feedback history."""
    org_id = str(current_user.get("org_id", "default"))
    feedback = _feedback_store.get(org_id, [])
    return {"feedback": feedback[-limit:], "total": len(feedback)}
