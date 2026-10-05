"""
Daily Threat Briefing — AI-Generated Security Summary

Scheduled job that generates a daily threat briefing from the last 24h
of telemetry data. Delivered to dashboard + optionally email/Slack.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass, field

from app.core.logging import get_logger

logger = get_logger("daily_briefing")


@dataclass
class DailyBriefing:
    """A generated daily threat briefing."""
    id: str = field(default_factory=lambda: f"brief-{uuid.uuid4().hex[:10]}")
    org_id: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    period_start: str = ""
    period_end: str = ""

    # Summary stats
    total_scans: int = 0
    total_blocked: int = 0
    total_alerts: int = 0
    unique_source_ips: int = 0
    unique_models_used: int = 0

    # Threat breakdown
    severity_distribution: dict = field(default_factory=dict)
    top_attack_categories: list[dict] = field(default_factory=list)
    top_source_ips: list[dict] = field(default_factory=list)
    top_models_targeted: list[dict] = field(default_factory=list)

    # AI-generated narrative
    executive_summary: str = ""
    key_findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    trend_analysis: str = ""

    # Delivery status
    delivered_to_dashboard: bool = True
    delivered_to_email: bool = False
    delivered_to_slack: bool = False


# ── Briefing store ──
_briefings: dict[str, list[DailyBriefing]] = {}  # org_id -> briefings


class DailyBriefingService:
    """Generates and manages daily threat briefings."""

    async def generate_briefing(self, org_id: str) -> DailyBriefing:
        """Generate a daily threat briefing from the last 24h telemetry."""
        now = datetime.now(timezone.utc)
        period_start = now - timedelta(hours=24)

        # Collect telemetry data (in production this queries the scan_events table)
        stats = await self._collect_telemetry(org_id, period_start, now)

        briefing = DailyBriefing(
            org_id=org_id,
            period_start=period_start.isoformat(),
            period_end=now.isoformat(),
            **stats,
        )

        # Generate AI narrative
        briefing.executive_summary = self._generate_executive_summary(stats)
        briefing.key_findings = self._generate_key_findings(stats)
        briefing.recommendations = self._generate_recommendations(stats)
        briefing.trend_analysis = self._generate_trend_analysis(stats)

        # Store
        if org_id not in _briefings:
            _briefings[org_id] = []
        _briefings[org_id].insert(0, briefing)
        # Keep last 30 briefings
        _briefings[org_id] = _briefings[org_id][:30]

        logger.info("briefing_generated", org=org_id, total_scans=stats["total_scans"])
        return briefing

    async def get_latest_briefing(self, org_id: str) -> Optional[dict]:
        """Get the most recent briefing for an org."""
        briefs = _briefings.get(org_id, [])
        if not briefs:
            # Auto-generate on first access
            brief = await self.generate_briefing(org_id)
            return self._serialize(brief)
        return self._serialize(briefs[0])

    async def list_briefings(self, org_id: str, limit: int = 10) -> list[dict]:
        return [self._serialize(b) for b in _briefings.get(org_id, [])[:limit]]

    async def _collect_telemetry(self, org_id: str, start: datetime, end: datetime) -> dict:
        """Collect telemetry stats from scan events."""
        # In production this would be:
        #   SELECT count(*), sum(is_blocked::int), ...
        #   FROM scan_events WHERE org_id = :org_id AND created_at BETWEEN :start AND :end
        # For now, return realistic demo data
        import random
        total = random.randint(1200, 5000)
        blocked = random.randint(int(total * 0.02), int(total * 0.08))
        alerts = random.randint(blocked, blocked + 50)

        return {
            "total_scans": total,
            "total_blocked": blocked,
            "total_alerts": alerts,
            "unique_source_ips": random.randint(50, 300),
            "unique_models_used": random.randint(3, 12),
            "severity_distribution": {
                "safe": total - alerts,
                "low": random.randint(10, 50),
                "medium": random.randint(5, 30),
                "high": random.randint(3, 15),
                "critical": random.randint(0, 5),
            },
            "top_attack_categories": [
                {"category": "prompt_injection", "count": random.randint(10, 50)},
                {"category": "jailbreak_attempt", "count": random.randint(5, 30)},
                {"category": "data_exfiltration", "count": random.randint(3, 20)},
                {"category": "hallucination", "count": random.randint(2, 15)},
                {"category": "pii_exposure", "count": random.randint(1, 10)},
            ],
            "top_source_ips": [
                {"ip": f"203.0.113.{random.randint(1, 254)}", "count": random.randint(50, 200), "geo": "Unknown"}
                for _ in range(5)
            ],
            "top_models_targeted": [
                {"model": "gpt-4o", "provider": "openai", "count": random.randint(200, 1000)},
                {"model": "claude-3-5-sonnet", "provider": "anthropic", "count": random.randint(100, 500)},
                {"model": "gemini-2.5-pro", "provider": "google", "count": random.randint(50, 300)},
            ],
        }

    def _generate_executive_summary(self, stats: dict) -> str:
        total = stats["total_scans"]
        blocked = stats["total_blocked"]
        block_rate = (blocked / total * 100) if total else 0
        critical = stats["severity_distribution"].get("critical", 0)
        high = stats["severity_distribution"].get("high", 0)

        summary = (
            f"Over the past 24 hours, GhostPrompt processed {total:,} AI interactions "
            f"across {stats['unique_models_used']} models from {stats['unique_source_ips']} unique sources. "
            f"{blocked:,} requests ({block_rate:.1f}%) were blocked by the AI firewall. "
        )
        if critical > 0:
            summary += f"⚠️ {critical} critical-severity events were detected requiring immediate review. "
        if high > 0:
            summary += f"{high} high-severity events were flagged for investigation."
        return summary

    def _generate_key_findings(self, stats: dict) -> list[str]:
        findings = []
        cats = stats.get("top_attack_categories", [])
        if cats:
            top = cats[0]
            findings.append(f"🔍 Most prevalent attack vector: {top['category'].replace('_', ' ').title()} ({top['count']} incidents)")
        if stats["total_blocked"] > 0:
            findings.append(f"🛡️ AI Firewall blocked {stats['total_blocked']:,} malicious requests automatically")
        critical = stats["severity_distribution"].get("critical", 0)
        if critical > 0:
            findings.append(f"🚨 {critical} critical-severity event(s) detected — review recommended")
        ips = stats.get("top_source_ips", [])
        if ips and ips[0]["count"] > 100:
            findings.append(f"📍 High-volume source: {ips[0]['ip']} made {ips[0]['count']} requests — possible automated attack")
        findings.append(f"📊 {stats['unique_models_used']} different AI models were used across your organization")
        return findings

    def _generate_recommendations(self, stats: dict) -> list[str]:
        recs = []
        critical = stats["severity_distribution"].get("critical", 0)
        if critical > 0:
            recs.append("Review and triage all critical-severity incidents from the past 24h")
        cats = stats.get("top_attack_categories", [])
        if cats and cats[0]["count"] > 20:
            recs.append(f"Consider tightening detection policies for {cats[0]['category'].replace('_', ' ')} attacks")
        if stats["total_blocked"] > stats["total_scans"] * 0.05:
            recs.append("Block rate exceeds 5% — review if legitimate traffic is being impacted")
        recs.append("Ensure all AI endpoints are routed through GhostPrompt proxy for full visibility")
        return recs

    def _generate_trend_analysis(self, stats: dict) -> str:
        total = stats["total_scans"]
        blocked = stats["total_blocked"]
        return (
            f"Daily scan volume of {total:,} indicates {'heavy' if total > 3000 else 'moderate' if total > 1000 else 'light'} "
            f"AI usage across your organization. "
            f"The block rate of {(blocked/total*100) if total else 0:.1f}% is "
            f"{'within normal range' if blocked/total < 0.05 else 'elevated — investigate source IPs'}."
        )

    def _serialize(self, b: DailyBriefing) -> dict:
        return {
            "id": b.id, "org_id": b.org_id, "generated_at": b.generated_at,
            "period_start": b.period_start, "period_end": b.period_end,
            "total_scans": b.total_scans, "total_blocked": b.total_blocked,
            "total_alerts": b.total_alerts, "unique_source_ips": b.unique_source_ips,
            "unique_models_used": b.unique_models_used,
            "severity_distribution": b.severity_distribution,
            "top_attack_categories": b.top_attack_categories,
            "top_source_ips": b.top_source_ips,
            "top_models_targeted": b.top_models_targeted,
            "executive_summary": b.executive_summary,
            "key_findings": b.key_findings,
            "recommendations": b.recommendations,
            "trend_analysis": b.trend_analysis,
        }


# Singleton
daily_briefing_service = DailyBriefingService()
