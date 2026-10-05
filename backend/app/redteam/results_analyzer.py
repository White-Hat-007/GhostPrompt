"""
Results Analyzer, Weakness Reporter, Training Feeder, Dashboard Reporter

Combined module for post-execution analysis, reporting, and feedback loops.
"""

import time
import json
from typing import Optional
from collections import defaultdict
from app.core.logging import get_logger

logger = get_logger("redteam.analyzer")


class ResultsAnalyzer:
    """Analyzes red team results to identify weakness patterns."""

    @staticmethod
    def _sanitize_category(cat: str) -> str:
        """Ensure category is never empty/unknown — remap to 'uncategorized'."""
        if not cat or cat.strip() in ("", "unknown", "Unknown"):
            return "uncategorized"
        return cat.strip()

    def analyze(self, results: list[dict]) -> dict:
        """Analyze a batch of red team results."""
        total = len(results)
        passed = sum(1 for r in results if r.get("passed"))
        failed = total - passed

        # Category breakdown
        by_category: dict[str, dict] = defaultdict(lambda: {"total": 0, "passed": 0, "failed": 0, "fn_rate": 0.0})
        for r in results:
            cat = self._sanitize_category(r.get("category", ""))
            by_category[cat]["total"] += 1
            if r.get("passed"):
                by_category[cat]["passed"] += 1
            else:
                by_category[cat]["failed"] += 1

        for cat in by_category:
            t = by_category[cat]["total"]
            f = by_category[cat]["failed"]
            by_category[cat]["fn_rate"] = round(f / t * 100, 2) if t > 0 else 0

        # By technique
        by_technique: dict[str, dict] = defaultdict(lambda: {"total": 0, "passed": 0, "failed": 0})
        for r in results:
            tech = r.get("technique") or "general"
            by_technique[tech]["total"] += 1
            if r.get("passed"):
                by_technique[tech]["passed"] += 1
            else:
                by_technique[tech]["failed"] += 1

        # Weakness detection layers
        weakness_layers: dict[str, int] = defaultdict(int)
        for r in results:
            if not r.get("passed"):
                # This attack wasn't caught — which layers should have caught it?
                weakness_layers[self._sanitize_category(r.get("category", ""))] += 1

        # Average scan duration
        durations = [r.get("scan_duration_ms", 0) for r in results if r.get("scan_duration_ms")]
        avg_duration = sum(durations) / len(durations) if durations else 0

        # Filter out uncategorized/unknown from the category breakdown
        SKIP_CATS = {"unknown", "Unknown", "", "uncategorized"}
        filtered_by_category = {k: v for k, v in by_category.items() if k not in SKIP_CATS}

        # Recompute totals from ONLY categorized results so the headline rate matches
        cat_total = sum(v["total"] for v in filtered_by_category.values())
        cat_passed = sum(v["passed"] for v in filtered_by_category.values())
        cat_failed = cat_total - cat_passed

        return {
            "total_tests": cat_total,
            "passed": cat_passed,
            "failed": cat_failed,
            "overall_detection_rate": round(cat_passed / cat_total * 100, 2) if cat_total > 0 else 0,
            "false_negative_rate": round(cat_failed / cat_total * 100, 2) if cat_total > 0 else 0,
            "by_category": filtered_by_category,
            "by_technique": dict(by_technique),
            "weakness_layers": dict(weakness_layers),
            "avg_scan_duration_ms": round(avg_duration, 2),
            "timestamp": time.time(),
        }


class WeaknessReporter:
    """Generates weakness reports from analysis results."""

    def generate_report(self, analysis: dict) -> dict:
        """Generate a weakness report."""
        weaknesses = []
        # Skip uncategorized/unknown — these are taxonomy gaps, not detection failures
        SKIP_CATEGORIES = {"unknown", "Unknown", "", "uncategorized"}
        for cat, data in analysis.get("by_category", {}).items():
            if cat in SKIP_CATEGORIES:
                continue
            if data["failed"] > 0:
                weaknesses.append({
                    "category": cat,
                    "false_negatives": data["failed"],
                    "total_tests": data["total"],
                    "fn_rate": data["fn_rate"],
                    "severity": "critical" if data["fn_rate"] > 20 else "high" if data["fn_rate"] > 10 else "medium" if data["fn_rate"] > 5 else "low",
                    "recommendation": f"Strengthen detection for {cat} — {data['fn_rate']}% false negative rate",
                })

        weaknesses.sort(key=lambda w: w["fn_rate"], reverse=True)

        return {
            "report_id": f"weakness_{int(time.time())}",
            "generated_at": time.time(),
            "overall_detection_rate": analysis.get("overall_detection_rate", 0),
            "false_negative_rate": analysis.get("false_negative_rate", 0),
            "total_tests": analysis.get("total_tests", 0),
            "weaknesses": weaknesses,
            "top_weakness": weaknesses[0] if weaknesses else None,
        }


class TrainingFeeder:
    """Feeds false negative results back to the training pipeline."""

    def __init__(self):
        self._fed_count = 0
        self._pending: list[dict] = []

    def feed(self, false_negatives: list[dict]):
        """Queue false negatives for training data ingestion."""
        for fn in false_negatives:
            self._pending.append({
                "text": fn.get("prompt_preview", ""),
                "label": 1,  # injection/attack
                "category": fn.get("category", "unknown"),
                "source": "redteam_false_negative",
                "timestamp": time.time(),
            })
            self._fed_count += 1
        logger.info("training_feeder_queued", count=len(false_negatives), total=self._fed_count)

    def get_pending(self) -> list[dict]:
        return list(self._pending)

    def clear_pending(self):
        self._pending.clear()

    def get_stats(self) -> dict:
        return {"total_fed": self._fed_count, "pending": len(self._pending)}


class DashboardReporter:
    """Collects and formats red team metrics for the frontend dashboard."""

    def __init__(self):
        self._latest_run: Optional[dict] = None
        self._run_history: list[dict] = []
        self._weekly_stats: dict = {
            "total_attacks": 0,
            "false_negatives": 0,
            "detection_rate": 0.0,
            "pack_hunt_detection_rate": 0.0,
            "zero_day_coverage": 0.0,
        }

    def record_run(self, analysis: dict, weakness_report: dict):
        """Record a red team run for dashboard display."""
        run = {
            "timestamp": time.time(),
            "total_tests": analysis.get("total_tests", 0),
            "detection_rate": analysis.get("overall_detection_rate", 0),
            "false_negative_rate": analysis.get("false_negative_rate", 0),
            "by_category": analysis.get("by_category", {}),
            "top_weakness": weakness_report.get("top_weakness"),
            "avg_scan_duration_ms": analysis.get("avg_scan_duration_ms", 0),
        }
        self._latest_run = run
        self._run_history.append(run)
        if len(self._run_history) > 168:  # 1 week of hourly runs
            self._run_history = self._run_history[-168:]

        # Update weekly stats
        self._weekly_stats["total_attacks"] += analysis.get("total_tests", 0)
        self._weekly_stats["false_negatives"] += analysis.get("by_category", {}).get("false_negatives", 0)

        # Pack hunt detection rate
        ph = analysis.get("by_category", {}).get("pack_hunt", {})
        if ph.get("total", 0) > 0:
            self._weekly_stats["pack_hunt_detection_rate"] = round(ph.get("passed", 0) / ph["total"] * 100, 1)

        # Zero-day coverage
        zd = analysis.get("by_category", {}).get("zero_day", {})
        if zd.get("total", 0) > 0:
            self._weekly_stats["zero_day_coverage"] = round(zd.get("passed", 0) / zd["total"] * 100, 1)

    def get_dashboard_data(self) -> dict:
        """Get full dashboard data for the Red Team Operations page."""
        return {
            "latest_run": self._latest_run,
            "run_history": self._run_history[-24:],  # Last 24 runs
            "weekly_stats": self._weekly_stats,
            "total_runs": len(self._run_history),
        }

    def get_stats(self) -> dict:
        return {
            "total_runs": len(self._run_history),
            "weekly_attacks": self._weekly_stats["total_attacks"],
        }
