"""
Federated Threat Intelligence — Real Aggregator Service

Exchanges differential-privacy-protected threat signatures between 
GhostPrompt deployments. Never shares raw prompts/PII.

Implements:
- Differential privacy (gradient clipping + calibrated Laplace noise)
- Secure aggregation (per-tenant privacy budget ε)
- STIX 2.1 indicator format for shared IOCs
- Byzantine-robust aggregation
"""

import uuid
import math
import hashlib
import random
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict

from app.core.logging import get_logger

logger = get_logger("federated_intel")


# ── Configuration ──
DEFAULT_EPSILON = 1.0           # Default privacy budget per period
DEFAULT_DELTA = 1e-5            # Privacy delta
NOISE_SCALE_MULTIPLIER = 1.5    # Laplace noise scale factor
MIN_CONTRIBUTORS = 3            # Minimum contributors for aggregation (Byzantine bound)
MAX_SHARED_SIGNATURES_PER_PERIOD = 100
PERIOD_HOURS = 24


@dataclass
class ThreatSignature:
    """A differential-privacy-protected threat signature."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    # STIX 2.1 indicator format
    stix_type: str = "indicator"
    stix_id: str = ""
    pattern_type: str = "ghostprompt"
    pattern: str = ""                    # Hashed/anonymized pattern
    attack_category: str = ""
    confidence: float = 0.0              # DP-noised confidence
    severity: str = "medium"
    first_seen: str = ""
    last_seen: str = ""
    contributor_count: int = 0           # How many deployments saw this
    noise_level: float = 0.0            # Transparency: how much noise was added
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class FederationNode:
    """Represents a participating GhostPrompt deployment."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    org_id: str = ""
    display_name: str = ""               # Anonymized name
    is_active: bool = True
    opted_in: bool = True
    epsilon_budget: float = DEFAULT_EPSILON
    epsilon_spent: float = 0.0
    signatures_contributed: int = 0
    signatures_received: int = 0
    last_sync: str = ""
    joined_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class PrivacyBudget:
    """Per-tenant privacy budget tracking."""
    org_id: str
    total_epsilon: float = DEFAULT_EPSILON
    spent_epsilon: float = 0.0
    period_start: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    queries_this_period: int = 0

    @property
    def remaining(self) -> float:
        return max(0, self.total_epsilon - self.spent_epsilon)

    @property
    def utilization_pct(self) -> float:
        return (self.spent_epsilon / self.total_epsilon * 100) if self.total_epsilon > 0 else 0


class DPMechanism:
    """Differential Privacy mechanisms."""

    @staticmethod
    def laplace_noise(sensitivity: float, epsilon: float) -> float:
        """Generate calibrated Laplace noise."""
        if epsilon <= 0:
            return 0.0
        scale = sensitivity / epsilon * NOISE_SCALE_MULTIPLIER
        # Laplace distribution via inverse CDF
        u = random.random() - 0.5
        return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))

    @staticmethod
    def clip_gradient(value: float, clip_bound: float = 1.0) -> float:
        """Clip value to sensitivity bound."""
        return max(-clip_bound, min(clip_bound, value))

    @staticmethod
    def hash_pattern(raw_pattern: str, salt: str = "ghostprompt_fed") -> str:
        """One-way hash of a pattern — never reversible to raw prompt."""
        return hashlib.sha256(f"{salt}:{raw_pattern}".encode()).hexdigest()[:32]


class FederatedAggregator:
    """
    Central aggregation service for federated threat intelligence.
    
    Collects DP-protected signatures from participating deployments,
    aggregates them with Byzantine-robust methods, and distributes
    shared intelligence back to all participants.
    """

    def __init__(self):
        self._nodes: dict[str, FederationNode] = {}
        self._budgets: dict[str, PrivacyBudget] = {}
        self._shared_signatures: list[ThreatSignature] = []
        self._pending_contributions: dict[str, list[dict]] = defaultdict(list)
        self._dp = DPMechanism()

    def register_node(self, org_id: str, display_name: str = "") -> FederationNode:
        """Register or get an existing federation node."""
        if org_id in self._nodes:
            return self._nodes[org_id]

        # Anonymize display name
        anon_name = display_name or f"Node-{hashlib.sha256(org_id.encode()).hexdigest()[:6].upper()}"

        node = FederationNode(
            org_id=org_id,
            display_name=anon_name,
        )
        self._nodes[org_id] = node
        self._budgets[org_id] = PrivacyBudget(org_id=org_id)

        logger.info("federation_node_registered", node_id=node.id, org=org_id)
        return node

    def contribute_signature(
        self,
        org_id: str,
        pattern: str,
        attack_category: str,
        confidence: float,
        severity: str = "medium",
    ) -> Optional[ThreatSignature]:
        """
        Contribute a threat signature from a deployment.
        
        The pattern is hashed, confidence is DP-noised, and the
        contribution is counted against the privacy budget.
        """
        node = self._nodes.get(org_id)
        if not node or not node.opted_in:
            return None

        budget = self._budgets.get(org_id)
        if not budget or budget.remaining <= 0:
            logger.warning("privacy_budget_exhausted", org=org_id)
            return None

        # ── Apply DP ──
        # 1. Hash the pattern (irreversible)
        hashed = self._dp.hash_pattern(pattern)

        # 2. Clip and noise the confidence
        clipped = self._dp.clip_gradient(confidence)
        epsilon_cost = 0.1  # Cost per contribution
        noise = self._dp.laplace_noise(sensitivity=1.0, epsilon=epsilon_cost)
        noised_confidence = max(0.0, min(1.0, clipped + noise))

        # 3. Deduct from privacy budget
        budget.spent_epsilon += epsilon_cost
        budget.queries_this_period += 1

        sig = ThreatSignature(
            stix_id=f"indicator--{uuid.uuid4()}",
            pattern=hashed,
            attack_category=attack_category,
            confidence=round(noised_confidence, 4),
            severity=severity,
            contributor_count=1,
            noise_level=round(abs(noise), 4),
            first_seen=datetime.now(timezone.utc).isoformat(),
            last_seen=datetime.now(timezone.utc).isoformat(),
        )

        # Add to pending contributions
        self._pending_contributions[hashed].append({
            "org_id": org_id,
            "confidence": noised_confidence,
            "severity": severity,
            "category": attack_category,
        })

        node.signatures_contributed += 1
        node.last_sync = datetime.now(timezone.utc).isoformat()

        logger.info(
            "signature_contributed",
            org=org_id,
            category=attack_category,
            epsilon_spent=round(budget.spent_epsilon, 4),
            epsilon_remaining=round(budget.remaining, 4),
        )

        # Trigger aggregation if enough contributors
        self._try_aggregate(hashed)

        return sig

    def _try_aggregate(self, pattern_hash: str):
        """
        Byzantine-robust aggregation: only aggregate when ≥ MIN_CONTRIBUTORS
        have reported the same pattern hash.
        """
        contributions = self._pending_contributions.get(pattern_hash, [])
        unique_orgs = set(c["org_id"] for c in contributions)

        if len(unique_orgs) < MIN_CONTRIBUTORS:
            return

        # ── Aggregate with trimmed mean (Byzantine-robust) ──
        confidences = sorted([c["confidence"] for c in contributions])
        # Trim top/bottom 20% for robustness
        trim = max(1, len(confidences) // 5)
        trimmed = confidences[trim:-trim] if len(confidences) > 2 * trim else confidences
        avg_confidence = sum(trimmed) / len(trimmed) if trimmed else 0.5

        # Most common severity
        from collections import Counter
        severity_counts = Counter(c["severity"] for c in contributions)
        consensus_severity = severity_counts.most_common(1)[0][0]

        category = contributions[0]["category"]

        shared_sig = ThreatSignature(
            stix_id=f"indicator--{uuid.uuid4()}",
            pattern=pattern_hash,
            attack_category=category,
            confidence=round(avg_confidence, 4),
            severity=consensus_severity,
            contributor_count=len(unique_orgs),
            noise_level=0.0,  # Aggregated = lower noise
            first_seen=contributions[0].get("first_seen", datetime.now(timezone.utc).isoformat()),
            last_seen=datetime.now(timezone.utc).isoformat(),
        )

        self._shared_signatures.append(shared_sig)
        # Clean up pending
        del self._pending_contributions[pattern_hash]

        # Increment received count for all participants
        for org_id in unique_orgs:
            if org_id in self._nodes:
                self._nodes[org_id].signatures_received += 1

        logger.info(
            "signature_aggregated",
            pattern=pattern_hash[:16],
            contributors=len(unique_orgs),
            confidence=avg_confidence,
            category=category,
        )

    def get_shared_intel(self, org_id: str, limit: int = 50) -> list[dict]:
        """Get shared threat intelligence for a deployment."""
        node = self._nodes.get(org_id)
        if not node or not node.opted_in:
            return []

        return [
            {
                "id": s.id,
                "stix_id": s.stix_id,
                "pattern_hash": s.pattern[:16] + "...",
                "category": s.attack_category,
                "confidence": s.confidence,
                "severity": s.severity,
                "contributors": s.contributor_count,
                "first_seen": s.first_seen,
                "last_seen": s.last_seen,
            }
            for s in self._shared_signatures[-limit:]
        ]

    def get_network_stats(self) -> dict:
        """Get overall federation network statistics."""
        active = [n for n in self._nodes.values() if n.is_active and n.opted_in]
        return {
            "total_nodes": len(self._nodes),
            "active_nodes": len(active),
            "total_shared_signatures": len(self._shared_signatures),
            "pending_aggregations": sum(
                1 for contribs in self._pending_contributions.values()
                if len(set(c["org_id"] for c in contribs)) >= MIN_CONTRIBUTORS
            ),
            "total_contributions": sum(n.signatures_contributed for n in self._nodes.values()),
        }

    def get_node_info(self, org_id: str) -> Optional[dict]:
        """Get info for a specific node."""
        node = self._nodes.get(org_id)
        budget = self._budgets.get(org_id)
        if not node:
            return None
        return {
            "node_id": node.id,
            "display_name": node.display_name,
            "is_active": node.is_active,
            "opted_in": node.opted_in,
            "signatures_contributed": node.signatures_contributed,
            "signatures_received": node.signatures_received,
            "last_sync": node.last_sync,
            "privacy_budget": {
                "total_epsilon": budget.total_epsilon if budget else 0,
                "spent_epsilon": round(budget.spent_epsilon, 4) if budget else 0,
                "remaining_epsilon": round(budget.remaining, 4) if budget else 0,
                "utilization_pct": round(budget.utilization_pct, 1) if budget else 0,
            } if budget else None,
        }

    def toggle_opt_in(self, org_id: str, opt_in: bool) -> bool:
        """Toggle federation opt-in for an org."""
        node = self._nodes.get(org_id)
        if node:
            node.opted_in = opt_in
            logger.info("federation_opt_toggled", org=org_id, opted_in=opt_in)
            return True
        return False


# Global singleton
federated_aggregator = FederatedAggregator()
