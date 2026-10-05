"""
GhostPrompt Virtual Key Vault

Virtual key system: customers never see real provider API keys.
Real keys stored encrypted (AES-256). Virtual keys resolve at request time.
Per-key: scopes, spend caps, IP allowlisting, usage tracking.
"""

import ipaddress
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

from app.core.encryption import decrypt_data as decrypt_value
from app.core.encryption import encrypt_data as encrypt_value


class KeyScope(str, Enum):
    READ = "read"       # No tool calls
    WRITE = "write"     # Full access
    ADMIN = "admin"     # Key management


@dataclass
class VirtualKeyUsage:
    tokens_consumed: int = 0
    cost_usd: float = 0.0
    request_count: int = 0
    error_count: int = 0
    total_latency_ms: float = 0.0
    daily_cost: dict = field(default_factory=lambda: defaultdict(float))
    last_used_at: float = 0

    def record(self, tokens: int, cost: float, latency_ms: float, error: bool):
        self.tokens_consumed += tokens
        self.cost_usd += cost
        self.request_count += 1
        if error:
            self.error_count += 1
        self.total_latency_ms += latency_ms
        self.last_used_at = time.time()
        day = time.strftime("%Y-%m-%d")
        self.daily_cost[day] += cost

    def to_dict(self) -> dict:
        return {
            "tokens_consumed": self.tokens_consumed,
            "cost_usd": round(self.cost_usd, 6),
            "request_count": self.request_count,
            "error_count": self.error_count,
            "error_rate": round(self.error_count / max(self.request_count, 1), 4),
            "avg_latency_ms": round(self.total_latency_ms / max(self.request_count, 1), 1),
            "last_used_at": self.last_used_at,
        }


@dataclass
class VirtualKey:
    virtual_key: str  # gp_vk_...
    tenant_id: str
    user_id: str | None = None
    name: str = ""
    provider: str = "openai"
    encrypted_real_key: str = ""
    allowed_models: list = field(default_factory=list)
    scope: KeyScope = KeyScope.WRITE
    monthly_spend_cap_usd: float = 0  # 0 = unlimited
    ip_allowlist: list = field(default_factory=list)  # CIDR ranges
    geo_allowlist: list = field(default_factory=list)  # country codes
    is_active: bool = True
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0  # 0 = never
    grace_period_key: str | None = None  # Old key during rotation
    grace_expires_at: float = 0
    usage: VirtualKeyUsage = field(default_factory=VirtualKeyUsage)

    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        return time.time() > self.expires_at


class KeyVault:
    """Virtual Key management system."""

    def __init__(self):
        self._keys: dict[str, VirtualKey] = {}
        self._tenant_keys: dict[str, list[str]] = defaultdict(list)
        self._alerts: list[dict] = []

    def _generate_virtual_key(self) -> str:
        return f"gp_vk_{uuid.uuid4().hex[:24]}"

    def create_key(self, tenant_id: str, provider: str, real_api_key: str,
                   name: str = "", user_id: str = None, allowed_models: list = None,
                   scope: KeyScope = KeyScope.WRITE, monthly_cap: float = 0,
                   ip_allowlist: list = None, expires_in_days: int = 0) -> dict:
        vk = self._generate_virtual_key()
        encrypted = encrypt_value(real_api_key)
        expires_at = time.time() + (expires_in_days * 86400) if expires_in_days > 0 else 0
        key = VirtualKey(
            virtual_key=vk, tenant_id=tenant_id, user_id=user_id,
            name=name or f"{provider}-key", provider=provider,
            encrypted_real_key=encrypted,
            allowed_models=allowed_models or [],
            scope=scope, monthly_spend_cap_usd=monthly_cap,
            ip_allowlist=ip_allowlist or [],
            expires_at=expires_at,
        )
        self._keys[vk] = key
        self._tenant_keys[tenant_id].append(vk)
        return {"virtual_key": vk, "name": name, "provider": provider, "scope": scope.value}

    def resolve_key(self, virtual_key: str, client_ip: str = None, model: str = None) -> dict:
        """Resolve virtual key to real provider key. Returns error dict if validation fails."""
        key = self._keys.get(virtual_key)
        if not key:
            return {"error": "Invalid virtual key", "code": 401}
        if not key.is_active:
            return {"error": "Virtual key is revoked", "code": 403}
        if key.is_expired():
            return {"error": "Virtual key has expired", "code": 403}
        # IP allowlist check
        if key.ip_allowlist and client_ip:
            allowed = False
            for cidr in key.ip_allowlist:
                try:
                    if ipaddress.ip_address(client_ip) in ipaddress.ip_network(cidr, strict=False):
                        allowed = True
                        break
                except ValueError:
                    continue
            if not allowed:
                return {"error": "IP not in allowlist", "code": 403}
        # Model check
        if key.allowed_models and model and model not in key.allowed_models:
            return {"error": f"Model {model} not allowed for this key", "code": 403}
        # Spend cap check
        if key.monthly_spend_cap_usd > 0 and key.usage.cost_usd >= key.monthly_spend_cap_usd:
            return {"error": "Monthly spend cap exceeded", "code": 402}
        # Scope check
        real_key = decrypt_value(key.encrypted_real_key)
        return {
            "provider": key.provider,
            "real_key": real_key,
            "scope": key.scope.value,
            "tenant_id": key.tenant_id,
        }

    def record_usage(self, virtual_key: str, tokens: int, cost: float, latency_ms: float, error: bool = False):
        key = self._keys.get(virtual_key)
        if key:
            key.usage.record(tokens, cost, latency_ms, error)
            # Alert at spend thresholds
            if key.monthly_spend_cap_usd > 0:
                pct = key.usage.cost_usd / key.monthly_spend_cap_usd
                for threshold in [0.5, 0.75, 0.9, 1.0]:
                    if pct >= threshold and (pct - (cost / max(key.monthly_spend_cap_usd, 0.01))) < threshold:
                        self._alerts.append({
                            "type": "spend_alert",
                            "virtual_key": virtual_key,
                            "threshold_pct": threshold * 100,
                            "current_spend": key.usage.cost_usd,
                            "cap": key.monthly_spend_cap_usd,
                            "timestamp": time.time(),
                        })

    def rotate_key(self, virtual_key: str, new_real_key: str, grace_period_hours: int = 24) -> dict:
        key = self._keys.get(virtual_key)
        if not key:
            return {"error": "Key not found"}
        key.grace_period_key = key.encrypted_real_key
        key.grace_expires_at = time.time() + (grace_period_hours * 3600)
        key.encrypted_real_key = encrypt_value(new_real_key)
        return {"status": "rotated", "grace_period_hours": grace_period_hours}

    def revoke_key(self, virtual_key: str) -> dict:
        key = self._keys.get(virtual_key)
        if not key:
            return {"error": "Key not found"}
        key.is_active = False
        return {"status": "revoked"}

    def list_keys(self, tenant_id: str) -> list[dict]:
        vks = self._tenant_keys.get(tenant_id, [])
        result = []
        for vk in vks:
            key = self._keys.get(vk)
            if key:
                result.append({
                    "virtual_key": vk,
                    "name": key.name,
                    "provider": key.provider,
                    "scope": key.scope.value,
                    "is_active": key.is_active,
                    "allowed_models": key.allowed_models,
                    "monthly_cap_usd": key.monthly_spend_cap_usd,
                    "usage": key.usage.to_dict(),
                    "created_at": key.created_at,
                    "ip_allowlist": key.ip_allowlist,
                })
        return result

    def get_key_usage(self, virtual_key: str) -> dict | None:
        key = self._keys.get(virtual_key)
        return key.usage.to_dict() if key else None

    def get_alerts(self, tenant_id: str = None) -> list[dict]:
        if tenant_id:
            return [a for a in self._alerts if self._keys.get(a.get("virtual_key", ""), VirtualKey(virtual_key="", tenant_id="")).tenant_id == tenant_id]
        return self._alerts


# Singleton
key_vault = KeyVault()
