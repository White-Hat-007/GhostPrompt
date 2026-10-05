"""
GhostPrompt Budget & Cost Controls

Hard budget limits, soft alerts, token rate limiting per tenant/workspace/key/user.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BudgetConfig:
    entity_id: str  # tenant_id, workspace_id, key_id, or user_id
    entity_type: str  # tenant, workspace, key, user
    monthly_cap_usd: float = 0  # 0 = unlimited
    current_spend_usd: float = 0.0
    tpm_limit: int = 0  # tokens per minute, 0 = unlimited
    rpm_limit: int = 0  # requests per minute, 0 = unlimited
    burst_factor: float = 1.5
    alert_thresholds: list = field(default_factory=lambda: [50, 75, 90, 100])
    alerts_sent: set = field(default_factory=set)
    last_reset: float = field(default_factory=time.time)

    # Rate tracking
    _minute_tokens: list = field(default_factory=list)  # [(timestamp, tokens)]
    _minute_requests: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "monthly_cap_usd": self.monthly_cap_usd,
            "current_spend_usd": round(self.current_spend_usd, 6),
            "utilization_pct": round(self.current_spend_usd / max(self.monthly_cap_usd, 0.01) * 100, 1) if self.monthly_cap_usd > 0 else 0,
            "tpm_limit": self.tpm_limit,
            "rpm_limit": self.rpm_limit,
        }


class CostController:
    """Budget enforcement and cost controls."""

    def __init__(self):
        self._budgets: dict[str, BudgetConfig] = {}
        self._alerts: list[dict] = []

    def set_budget(self, entity_id: str, entity_type: str, monthly_cap: float = 0,
                   tpm_limit: int = 0, rpm_limit: int = 0) -> dict:
        key = f"{entity_type}:{entity_id}"
        self._budgets[key] = BudgetConfig(
            entity_id=entity_id, entity_type=entity_type,
            monthly_cap_usd=monthly_cap, tpm_limit=tpm_limit, rpm_limit=rpm_limit,
        )
        return self._budgets[key].to_dict()

    def check_budget(self, entity_id: str, entity_type: str) -> dict:
        key = f"{entity_type}:{entity_id}"
        budget = self._budgets.get(key)
        if not budget:
            return {"allowed": True, "remaining_tokens": -1, "remaining_requests": -1}
        # Hard budget check
        if budget.monthly_cap_usd > 0 and budget.current_spend_usd >= budget.monthly_cap_usd:
            return {"allowed": False, "error": "Monthly spend cap exceeded", "code": 402}
        return {"allowed": True, "budget": budget.to_dict()}

    def check_rate_limit(self, entity_id: str, entity_type: str, tokens: int = 0) -> dict:
        key = f"{entity_type}:{entity_id}"
        budget = self._budgets.get(key)
        if not budget:
            return {"allowed": True}
        now = time.time()
        cutoff = now - 60
        # Clean old entries
        budget._minute_tokens = [(t, tk) for t, tk in budget._minute_tokens if t > cutoff]
        budget._minute_requests = [t for t in budget._minute_requests if t > cutoff]
        # TPM check
        if budget.tpm_limit > 0:
            current_tpm = sum(tk for _, tk in budget._minute_tokens)
            burst_limit = int(budget.tpm_limit * budget.burst_factor)
            if current_tpm + tokens > burst_limit:
                return {
                    "allowed": False,
                    "error": "Token rate limit exceeded",
                    "code": 429,
                    "headers": {
                        "X-RateLimit-Remaining-Tokens": max(0, burst_limit - current_tpm),
                        "X-RateLimit-Reset": int(cutoff + 60),
                    },
                }
        # RPM check
        if budget.rpm_limit > 0:
            current_rpm = len(budget._minute_requests)
            if current_rpm >= int(budget.rpm_limit * budget.burst_factor):
                return {
                    "allowed": False,
                    "error": "Request rate limit exceeded",
                    "code": 429,
                    "headers": {
                        "X-RateLimit-Remaining-Requests": max(0, int(budget.rpm_limit * budget.burst_factor) - current_rpm),
                        "X-RateLimit-Reset": int(cutoff + 60),
                    },
                }
        return {"allowed": True}

    def record_usage(self, entity_id: str, entity_type: str, tokens: int, cost_usd: float):
        key = f"{entity_type}:{entity_id}"
        budget = self._budgets.get(key)
        if not budget:
            return
        now = time.time()
        budget.current_spend_usd += cost_usd
        budget._minute_tokens.append((now, tokens))
        budget._minute_requests.append(now)
        # Check alert thresholds
        if budget.monthly_cap_usd > 0:
            pct = (budget.current_spend_usd / budget.monthly_cap_usd) * 100
            for threshold in budget.alert_thresholds:
                if pct >= threshold and threshold not in budget.alerts_sent:
                    budget.alerts_sent.add(threshold)
                    self._alerts.append({
                        "type": "budget_alert",
                        "entity_id": entity_id,
                        "entity_type": entity_type,
                        "threshold_pct": threshold,
                        "current_spend": round(budget.current_spend_usd, 4),
                        "monthly_cap": budget.monthly_cap_usd,
                        "timestamp": now,
                    })

    def get_budget(self, entity_id: str, entity_type: str) -> dict | None:
        key = f"{entity_type}:{entity_id}"
        budget = self._budgets.get(key)
        return budget.to_dict() if budget else None

    def get_all_budgets(self, entity_type: str = None) -> list[dict]:
        budgets = self._budgets.values()
        if entity_type:
            budgets = [b for b in budgets if b.entity_type == entity_type]
        return [b.to_dict() for b in budgets]

    def get_alerts(self, entity_id: str = None) -> list[dict]:
        if entity_id:
            return [a for a in self._alerts if a["entity_id"] == entity_id]
        return self._alerts

    def reset_monthly(self):
        """Call at start of each billing period."""
        for budget in self._budgets.values():
            budget.current_spend_usd = 0.0
            budget.alerts_sent.clear()
            budget.last_reset = time.time()

    def get_forecast(self, entity_id: str, entity_type: str) -> dict:
        key = f"{entity_type}:{entity_id}"
        budget = self._budgets.get(key)
        if not budget or budget.monthly_cap_usd == 0:
            return {"forecast": "unlimited"}
        days_elapsed = max(1, (time.time() - budget.last_reset) / 86400)
        daily_rate = budget.current_spend_usd / days_elapsed
        projected_monthly = daily_rate * 30
        days_until_cap = (budget.monthly_cap_usd - budget.current_spend_usd) / max(daily_rate, 0.001)
        return {
            "daily_rate_usd": round(daily_rate, 4),
            "projected_monthly_usd": round(projected_monthly, 2),
            "days_until_cap": round(days_until_cap, 1),
            "will_exceed": projected_monthly > budget.monthly_cap_usd,
        }


# Singleton
cost_controller = CostController()
