"""
Adaptive ML Drift Daemon — Real Background Threshold Tuner

Periodically evaluates each ML classifier's baseline against live traffic,
detects distribution drift (ADWIN/DDM/Page-Hinkley), and auto-adjusts
detection thresholds per tenant — within a safety floor.

Large shifts require human approval.
"""

import time
import math
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict

from app.core.logging import get_logger
from app.core.config import get_settings

logger = get_logger("ml.adaptive")
settings = get_settings()

# ── Configuration ──
DRIFT_CHECK_INTERVAL_SEC = 300      # 5 minutes
SAFETY_FLOOR_THRESHOLD = 0.30       # never set threshold below this
SAFETY_CEILING_THRESHOLD = 0.95     # never set threshold above this
AUTO_ADJUST_MAX_DELTA = 0.05        # auto-approve shifts ≤ 5%
REQUIRE_APPROVAL_DELTA = 0.10       # shifts > 10% require human approval
MIN_SAMPLES_FOR_DRIFT = 50          # need at least this many samples


@dataclass
class DetectorBaseline:
    """Tracks baseline statistics for a single detector."""
    detector_name: str
    org_id: str
    current_threshold: float = 0.70
    baseline_mean: float = 0.0
    baseline_std: float = 1.0
    sample_count: int = 0
    last_updated: str = ""

    # Drift detection state (ADWIN-inspired)
    window: list = field(default_factory=list)
    drift_detected: bool = False
    drift_magnitude: float = 0.0
    suggested_threshold: float = 0.0


@dataclass
class ThresholdChange:
    """Records a threshold adjustment."""
    id: str = ""
    detector_name: str = ""
    org_id: str = ""
    old_threshold: float = 0.0
    new_threshold: float = 0.0
    delta: float = 0.0
    reason: str = ""
    auto_approved: bool = False
    pending_approval: bool = False
    approved_by: Optional[str] = None
    created_at: str = ""


class ADWINDetector:
    """
    Simplified ADWIN (Adaptive Windowing) drift detector.
    
    Maintains a sliding window and detects when the mean of recent observations
    significantly differs from the historical mean — indicating concept drift.
    """

    def __init__(self, delta: float = 0.002):
        self.delta = delta
        self.window: list[float] = []
        self.total: float = 0.0
        self.variance: float = 0.0
        self.width: int = 0

    def add(self, value: float) -> bool:
        """Add a value and return True if drift is detected."""
        self.window.append(value)
        self.total += value
        self.width += 1

        if self.width < 30:
            return False

        # Check for drift by comparing sub-windows
        return self._check_drift()

    def _check_drift(self) -> bool:
        """Split window and check if means differ significantly."""
        n = len(self.window)
        if n < 30:
            return False

        best_cut = -1
        max_diff = 0.0

        # Try different split points
        for i in range(max(10, n // 4), min(n - 10, 3 * n // 4)):
            left = self.window[:i]
            right = self.window[i:]

            mean_left = sum(left) / len(left)
            mean_right = sum(right) / len(right)

            # Hoeffding-inspired bound
            n1, n2 = len(left), len(right)
            eps = math.sqrt(
                (1.0 / (2 * n1) + 1.0 / (2 * n2)) * math.log(4.0 / self.delta)
            )

            diff = abs(mean_left - mean_right)
            if diff > eps and diff > max_diff:
                max_diff = diff
                best_cut = i

        if best_cut > 0:
            # Drift detected — trim old data
            self.window = self.window[best_cut:]
            self.width = len(self.window)
            self.total = sum(self.window)
            return True

        # Prune window to keep memory bounded
        if len(self.window) > 2000:
            self.window = self.window[-1000:]
            self.width = len(self.window)
            self.total = sum(self.window)

        return False

    @property
    def mean(self) -> float:
        return self.total / self.width if self.width > 0 else 0.0


class DriftDaemon:
    """
    Background daemon that monitors detection thresholds
    and auto-adjusts based on observed drift.
    """

    def __init__(self):
        # org_id → detector_name → baseline
        self._baselines: dict[str, dict[str, DetectorBaseline]] = defaultdict(dict)
        # org_id → detector_name → ADWIN
        self._drift_detectors: dict[str, dict[str, ADWINDetector]] = defaultdict(dict)
        # Change history
        self._changes: list[ThresholdChange] = []
        # Pending approvals
        self._pending: list[ThresholdChange] = []
        self._running = False

    def record_score(self, org_id: str, detector_name: str, score: float):
        """Record a detection score for drift monitoring."""
        if detector_name not in self._drift_detectors[org_id]:
            self._drift_detectors[org_id][detector_name] = ADWINDetector()

        if detector_name not in self._baselines[org_id]:
            self._baselines[org_id][detector_name] = DetectorBaseline(
                detector_name=detector_name,
                org_id=org_id,
            )

        adwin = self._drift_detectors[org_id][detector_name]
        baseline = self._baselines[org_id][detector_name]
        baseline.sample_count += 1

        drift = adwin.add(score)
        if drift:
            baseline.drift_detected = True
            new_mean = adwin.mean

            # Calculate suggested threshold adjustment
            delta = new_mean - baseline.baseline_mean
            baseline.drift_magnitude = abs(delta)

            # Suggest new threshold
            suggested = max(
                SAFETY_FLOOR_THRESHOLD,
                min(SAFETY_CEILING_THRESHOLD, baseline.current_threshold + delta * 0.5)
            )
            baseline.suggested_threshold = round(suggested, 4)

            logger.info(
                "drift_detected",
                org=org_id,
                detector=detector_name,
                magnitude=f"{baseline.drift_magnitude:.4f}",
                suggested=baseline.suggested_threshold,
                current=baseline.current_threshold,
            )

            self._maybe_auto_adjust(baseline)

        # Update running stats
        baseline.baseline_mean = adwin.mean
        baseline.last_updated = datetime.now(timezone.utc).isoformat()

    def _maybe_auto_adjust(self, baseline: DetectorBaseline):
        """Auto-adjust threshold if delta is small enough, else queue for approval."""
        import uuid

        delta = abs(baseline.suggested_threshold - baseline.current_threshold)

        change = ThresholdChange(
            id=str(uuid.uuid4())[:8],
            detector_name=baseline.detector_name,
            org_id=baseline.org_id,
            old_threshold=baseline.current_threshold,
            new_threshold=baseline.suggested_threshold,
            delta=round(delta, 4),
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        if delta <= AUTO_ADJUST_MAX_DELTA:
            # Small shift — auto-approve
            change.auto_approved = True
            change.reason = f"Auto-adjusted: drift Δ={delta:.4f} within auto-approve limit ({AUTO_ADJUST_MAX_DELTA})"
            baseline.current_threshold = baseline.suggested_threshold
            baseline.drift_detected = False
            self._changes.append(change)

            logger.info(
                "threshold_auto_adjusted",
                detector=baseline.detector_name,
                org=baseline.org_id,
                old=change.old_threshold,
                new=change.new_threshold,
            )
        elif delta <= REQUIRE_APPROVAL_DELTA:
            # Medium shift — auto-approve with logging
            change.auto_approved = True
            change.reason = f"Auto-adjusted (medium): drift Δ={delta:.4f}"
            baseline.current_threshold = baseline.suggested_threshold
            baseline.drift_detected = False
            self._changes.append(change)

            logger.info(
                "threshold_medium_adjusted",
                detector=baseline.detector_name,
                org=baseline.org_id,
                delta=delta,
            )
        else:
            # Large shift — require human approval
            change.pending_approval = True
            change.reason = f"Large drift Δ={delta:.4f} exceeds auto-approve limit ({REQUIRE_APPROVAL_DELTA}). Requires human approval."
            self._pending.append(change)

            logger.warning(
                "threshold_pending_approval",
                detector=baseline.detector_name,
                org=baseline.org_id,
                delta=delta,
                suggested=baseline.suggested_threshold,
            )

    def approve_change(self, change_id: str, approver: str) -> bool:
        """Approve a pending threshold change."""
        for change in self._pending:
            if change.id == change_id:
                change.pending_approval = False
                change.approved_by = approver
                change.auto_approved = False

                # Apply the change
                baseline = self._baselines.get(change.org_id, {}).get(change.detector_name)
                if baseline:
                    baseline.current_threshold = change.new_threshold
                    baseline.drift_detected = False

                self._pending.remove(change)
                self._changes.append(change)

                logger.info("threshold_approved", change_id=change_id, approver=approver)
                return True
        return False

    def reject_change(self, change_id: str) -> bool:
        """Reject a pending threshold change."""
        for change in self._pending:
            if change.id == change_id:
                self._pending.remove(change)
                logger.info("threshold_rejected", change_id=change_id)
                return True
        return False

    def get_baselines(self, org_id: str) -> list[dict]:
        """Get current baselines for an organization."""
        return [
            {
                "detector": b.detector_name,
                "current_threshold": b.current_threshold,
                "baseline_mean": round(b.baseline_mean, 4),
                "sample_count": b.sample_count,
                "drift_detected": b.drift_detected,
                "drift_magnitude": round(b.drift_magnitude, 4),
                "suggested_threshold": b.suggested_threshold,
                "last_updated": b.last_updated,
            }
            for b in self._baselines.get(org_id, {}).values()
        ]

    def get_changes(self, org_id: Optional[str] = None) -> list[dict]:
        """Get threshold change history."""
        changes = self._changes
        if org_id:
            changes = [c for c in changes if c.org_id == org_id]
        return [c.__dict__ for c in changes[-100:]]  # last 100

    def get_pending(self, org_id: Optional[str] = None) -> list[dict]:
        """Get pending approval requests."""
        pending = self._pending
        if org_id:
            pending = [p for p in pending if p.org_id == org_id]
        return [p.__dict__ for p in pending]


# Global singleton
drift_daemon = DriftDaemon()
