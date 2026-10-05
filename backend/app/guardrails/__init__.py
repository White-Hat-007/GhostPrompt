"""
GhostPrompt Network-Level Guardrails

IP controls, request validation, outbound content controls.
"""

import re
import time
import ipaddress
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict


# Known Tor exit nodes (sample — in production, load from a feed)
TOR_EXIT_NODES = {"185.220.101.1", "185.220.101.2", "185.220.101.3"}

# Known datacenter IP ranges (sample)
DATACENTER_CIDRS = ["104.16.0.0/12", "172.64.0.0/13"]

# Malicious URL patterns
MALICIOUS_URL_PATTERNS = [
    r'https?://bit\.ly/', r'https?://tinyurl\.com/', r'https?://t\.co/',
    r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/',  # raw IP URLs
]

# Profanity list (minimal sample)
PROFANITY_WORDS = {"fuck", "shit", "damn", "ass", "bitch", "crap"}


@dataclass
class TenantNetworkConfig:
    tenant_id: str
    ip_allowlist: list = field(default_factory=list)
    ip_denylist: list = field(default_factory=list)
    country_allowlist: list = field(default_factory=list)
    country_denylist: list = field(default_factory=list)
    block_tor: bool = False
    block_vpn: bool = False
    block_datacenter: bool = False
    max_request_size_bytes: int = 1_048_576
    required_headers: list = field(default_factory=list)
    profanity_filter: bool = False
    profanity_strictness: str = "medium"  # low, medium, strict
    toxic_content_threshold: float = 0.7
    block_malicious_urls: bool = True

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "ip_allowlist": self.ip_allowlist,
            "ip_denylist": self.ip_denylist,
            "country_allowlist": self.country_allowlist,
            "country_denylist": self.country_denylist,
            "block_tor": self.block_tor,
            "block_vpn": self.block_vpn,
            "max_request_size_bytes": self.max_request_size_bytes,
            "profanity_filter": self.profanity_filter,
            "block_malicious_urls": self.block_malicious_urls,
        }


class NetworkGuardrails:
    """Network-level guardrails for inbound/outbound traffic."""

    def __init__(self):
        self._tenant_configs: dict[str, TenantNetworkConfig] = {}
        self._ip_reputation_cache: dict[str, float] = {}
        self._blocked_requests: list[dict] = []
        self._max_blocked = 10000

    def get_config(self, tenant_id: str) -> TenantNetworkConfig:
        if tenant_id not in self._tenant_configs:
            self._tenant_configs[tenant_id] = TenantNetworkConfig(tenant_id=tenant_id)
        return self._tenant_configs[tenant_id]

    def update_config(self, tenant_id: str, **kwargs) -> dict:
        config = self.get_config(tenant_id)
        for k, v in kwargs.items():
            if hasattr(config, k):
                setattr(config, k, v)
        return config.to_dict()

    # ── Inbound Request Validation ──
    def validate_request(self, tenant_id: str, client_ip: str, content_type: str = "",
                        content_length: int = 0, headers: dict = None, country: str = "") -> dict:
        config = self.get_config(tenant_id)
        # IP denylist
        if config.ip_denylist:
            for cidr in config.ip_denylist:
                try:
                    if ipaddress.ip_address(client_ip) in ipaddress.ip_network(cidr, strict=False):
                        return self._block("IP in denylist", client_ip, tenant_id)
                except ValueError:
                    continue
        # IP allowlist (if set, only these IPs allowed)
        if config.ip_allowlist:
            allowed = False
            for cidr in config.ip_allowlist:
                try:
                    if ipaddress.ip_address(client_ip) in ipaddress.ip_network(cidr, strict=False):
                        allowed = True
                        break
                except ValueError:
                    continue
            if not allowed:
                return self._block("IP not in allowlist", client_ip, tenant_id)
        # Tor blocking
        if config.block_tor and client_ip in TOR_EXIT_NODES:
            return self._block("Tor exit node blocked", client_ip, tenant_id)
        # Datacenter blocking
        if config.block_datacenter:
            for cidr in DATACENTER_CIDRS:
                try:
                    if ipaddress.ip_address(client_ip) in ipaddress.ip_network(cidr, strict=False):
                        return self._block("Datacenter IP blocked", client_ip, tenant_id)
                except ValueError:
                    continue
        # Country checks
        if config.country_allowlist and country and country.upper() not in [c.upper() for c in config.country_allowlist]:
            return self._block(f"Country {country} not in allowlist", client_ip, tenant_id)
        if config.country_denylist and country and country.upper() in [c.upper() for c in config.country_denylist]:
            return self._block(f"Country {country} in denylist", client_ip, tenant_id)
        # Request size
        if content_length > config.max_request_size_bytes:
            return self._block(f"Request too large: {content_length} bytes", client_ip, tenant_id)
        # Content-Type
        if content_type and "application/json" not in content_type and "multipart/form-data" not in content_type:
            return self._block(f"Invalid Content-Type: {content_type}", client_ip, tenant_id)
        # Required headers
        if config.required_headers and headers:
            for h in config.required_headers:
                if h.lower() not in {k.lower() for k in headers}:
                    return self._block(f"Missing required header: {h}", client_ip, tenant_id)
        # IP reputation
        rep = self._ip_reputation_cache.get(client_ip, 0)
        if rep > 80:
            return self._block(f"IP reputation score too high: {rep}", client_ip, tenant_id)
        return {"allowed": True}

    # ── Outbound Content Controls ──
    def inspect_output(self, tenant_id: str, content: str) -> dict:
        config = self.get_config(tenant_id)
        issues = []
        # Malicious URL check
        if config.block_malicious_urls:
            for pattern in MALICIOUS_URL_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    issues.append({"type": "malicious_url", "severity": "high", "description": "Response contains suspicious URL"})
                    break
        # Profanity filter
        if config.profanity_filter:
            words = set(content.lower().split())
            found = words & PROFANITY_WORDS
            if found:
                issues.append({"type": "profanity", "severity": "medium", "description": f"Profanity detected: {len(found)} words"})
        # Check for potential malware signatures
        malware_sigs = ["<script>", "eval(", "exec(", "base64_decode", "fromCharCode"]
        for sig in malware_sigs:
            if sig.lower() in content.lower():
                issues.append({"type": "malware_signature", "severity": "critical", "description": f"Potential malware: {sig}"})
        return {
            "passed": len(issues) == 0,
            "issues": issues,
            "content_length": len(content),
        }

    def set_ip_reputation(self, ip: str, score: float):
        self._ip_reputation_cache[ip] = score

    def _block(self, reason: str, ip: str, tenant_id: str) -> dict:
        entry = {"reason": reason, "ip": ip, "tenant_id": tenant_id, "timestamp": time.time()}
        self._blocked_requests.append(entry)
        if len(self._blocked_requests) > self._max_blocked:
            self._blocked_requests = self._blocked_requests[-self._max_blocked // 2:]
        return {"allowed": False, "error": reason, "code": 403}

    def get_blocked_requests(self, tenant_id: str = None, limit: int = 50) -> list[dict]:
        logs = self._blocked_requests
        if tenant_id:
            logs = [l for l in logs if l["tenant_id"] == tenant_id]
        return list(reversed(logs))[:limit]


# Singleton
network_guardrails = NetworkGuardrails()
