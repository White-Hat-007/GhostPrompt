"""
BIOC (Behavioral Indicator of Compromise) Push-to-Policy Engine

When campaign_detector identifies a coordinated attack pattern,
auto-generates a temporary high-sensitivity policy rule and pushes
it live across all tenant policies matching that attack signature.

Inspired by Palo Alto Cortex XSIAM's proactive correlation-rule push.
"""

import uuid
import time
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict

from app.core.logging import get_logger

logger = get_logger("bioc_engine")


@dataclass
class BIOCRule:
    """A temporary behavioral indicator pushed into live policy."""
    id: str = field(default_factory=lambda: f"bioc-{uuid.uuid4().hex[:12]}")
    name: str = ""
    description: str = ""
    source_campaign_id: Optional[str] = None
    attack_categories: list[str] = field(default_factory=list)
    pattern_signatures: list[str] = field(default_factory=list)
    
    # Policy override
    sensitivity_boost: float = 0.3   # Lower threat threshold by this amount
    force_block: bool = False         # Auto-block matching patterns
    
    # Lifecycle
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str = ""
    ttl_seconds: int = 3600           # Default 1 hour
    is_active: bool = True
    auto_generated: bool = True
    
    # Scope
    target_org_ids: list[str] = field(default_factory=list)  # Empty = all orgs
    applied_to_count: int = 0


# ── Active BIOC Rules Store (production: Redis/DB) ──
_active_bioc_rules: dict[str, BIOCRule] = {}


class BIOCEngine:
    """
    Generates and manages temporary high-sensitivity policy rules
    in response to detected coordinated attack campaigns.
    """

    async def on_campaign_detected(
        self,
        campaign_id: str,
        attack_categories: list[str],
        pattern_signatures: list[str],
        severity: str = "high",
        affected_org_ids: Optional[list[str]] = None,
    ) -> BIOCRule:
        """
        Called by campaign_detector when a coordinated attack pattern is identified.
        Auto-generates a BIOC rule and pushes it live.
        """
        # Determine TTL based on severity
        ttl = {
            "critical": 7200,   # 2 hours
            "high": 3600,       # 1 hour
            "medium": 1800,     # 30 minutes
        }.get(severity, 3600)

        now = datetime.now(timezone.utc)
        rule = BIOCRule(
            name=f"Auto-BIOC: {', '.join(attack_categories[:3])} campaign",
            description=(
                f"Temporary high-sensitivity rule auto-generated from campaign {campaign_id}. "
                f"Detected coordinated attack patterns across {len(affected_org_ids or [])} organizations."
            ),
            source_campaign_id=campaign_id,
            attack_categories=attack_categories,
            pattern_signatures=pattern_signatures[:20],  # Cap stored signatures
            sensitivity_boost=0.4 if severity == "critical" else 0.3,
            force_block=severity == "critical",
            ttl_seconds=ttl,
            expires_at=(now + timedelta(seconds=ttl)).isoformat(),
            target_org_ids=affected_org_ids or [],
        )

        _active_bioc_rules[rule.id] = rule

        logger.info(
            "bioc_rule_activated",
            rule_id=rule.id,
            campaign_id=campaign_id,
            categories=attack_categories,
            ttl_seconds=ttl,
            force_block=rule.force_block,
        )
        return rule

    async def check_bioc_rules(
        self,
        org_id: str,
        threat_categories: list[str],
        threat_score: float,
    ) -> Optional[dict]:
        """
        Check if any active BIOC rules apply to this scan event.
        Returns modified policy overrides if a rule matches, else None.
        """
        now = datetime.now(timezone.utc)
        expired = []

        for rule_id, rule in _active_bioc_rules.items():
            if not rule.is_active:
                continue

            # Check expiry
            try:
                if now > datetime.fromisoformat(rule.expires_at):
                    expired.append(rule_id)
                    continue
            except (ValueError, TypeError):
                pass

            # Check scope
            if rule.target_org_ids and org_id not in rule.target_org_ids:
                continue

            # Check category match
            if not any(cat in rule.attack_categories for cat in threat_categories):
                continue

            # Match found — return policy override
            rule.applied_to_count += 1
            return {
                "bioc_rule_id": rule.id,
                "bioc_rule_name": rule.name,
                "sensitivity_boost": rule.sensitivity_boost,
                "adjusted_threshold": max(0.1, threat_score - rule.sensitivity_boost),
                "force_block": rule.force_block,
                "campaign_id": rule.source_campaign_id,
                "expires_at": rule.expires_at,
            }

        # Clean up expired rules
        for rule_id in expired:
            _active_bioc_rules[rule_id].is_active = False
            logger.info("bioc_rule_expired", rule_id=rule_id)

        return None

    async def deactivate_rule(self, rule_id: str) -> bool:
        """Manually deactivate a BIOC rule."""
        if rule_id in _active_bioc_rules:
            _active_bioc_rules[rule_id].is_active = False
            logger.info("bioc_rule_deactivated", rule_id=rule_id, manual=True)
            return True
        return False

    async def get_active_rules(self) -> list[dict]:
        """Get all currently active BIOC rules."""
        now = datetime.now(timezone.utc)
        result = []
        for rule in _active_bioc_rules.values():
            if not rule.is_active:
                continue
            try:
                if now > datetime.fromisoformat(rule.expires_at):
                    rule.is_active = False
                    continue
            except (ValueError, TypeError):
                pass
            result.append({
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "campaign_id": rule.source_campaign_id,
                "attack_categories": rule.attack_categories,
                "sensitivity_boost": rule.sensitivity_boost,
                "force_block": rule.force_block,
                "created_at": rule.created_at,
                "expires_at": rule.expires_at,
                "applied_to_count": rule.applied_to_count,
                "target_org_count": len(rule.target_org_ids),
            })
        return result


# Singleton
bioc_engine = BIOCEngine()
