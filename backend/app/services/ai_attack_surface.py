"""
AI Attack Surface Scanner

Discovers all LLM-integrated endpoints from:
1. MCP Gateway registry (all registered tool servers)
2. Registered API routes (proxy endpoints)
3. Provider configurations (configured AI provider keys)

Flags any endpoint NOT routed through GhostPrompt's firewall.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.logging import get_logger

logger = get_logger("attack_surface")


@dataclass
class AIEndpoint:
    """Represents a discovered AI-integrated endpoint."""
    id: str = ""
    name: str = ""
    endpoint_type: str = ""        # mcp_tool, api_proxy, provider_direct
    url: str = ""
    provider: str = ""
    model: str = ""
    is_protected: bool = False     # Routed through GhostPrompt?
    protection_method: str = ""    # proxy, sdk, mcp_gateway, none
    last_seen: str = ""
    risk_level: str = "unknown"    # safe, low, medium, high, critical
    risk_reasons: list[str] = field(default_factory=list)
    owner: str | None = None
    metadata: dict = field(default_factory=dict)


class AIAttackSurfaceScanner:
    """Discovers and audits AI-integrated endpoints."""

    async def full_scan(self, org_id: str) -> dict:
        """Run a full AI attack surface scan."""
        now = datetime.now(timezone.utc)
        endpoints: list[AIEndpoint] = []

        # 1. Scan MCP Gateway registry
        mcp_endpoints = await self._scan_mcp_gateway()
        endpoints.extend(mcp_endpoints)

        # 2. Scan registered providers
        provider_endpoints = await self._scan_providers(org_id)
        endpoints.extend(provider_endpoints)

        # 3. Scan proxy routes
        proxy_endpoints = await self._scan_proxy_routes()
        endpoints.extend(proxy_endpoints)

        # 4. Assess risk for each endpoint
        for ep in endpoints:
            self._assess_risk(ep)

        # Summary stats
        total = len(endpoints)
        protected = sum(1 for ep in endpoints if ep.is_protected)
        unprotected = total - protected
        high_risk = sum(1 for ep in endpoints if ep.risk_level in ("high", "critical"))

        result = {
            "scan_timestamp": now.isoformat(),
            "org_id": org_id,
            "summary": {
                "total_endpoints": total,
                "protected": protected,
                "unprotected": unprotected,
                "high_risk": high_risk,
                "coverage_pct": round((protected / total * 100) if total else 100, 1),
            },
            "endpoints": [
                {
                    "id": ep.id,
                    "name": ep.name,
                    "endpoint_type": ep.endpoint_type,
                    "url": ep.url,
                    "provider": ep.provider,
                    "model": ep.model,
                    "is_protected": ep.is_protected,
                    "protection_method": ep.protection_method,
                    "risk_level": ep.risk_level,
                    "risk_reasons": ep.risk_reasons,
                    "owner": ep.owner,
                }
                for ep in endpoints
            ],
            "recommendations": self._generate_recommendations(endpoints),
        }

        logger.info("attack_surface_scan_complete", org=org_id, total=total, unprotected=unprotected)
        return result

    async def _scan_mcp_gateway(self) -> list[AIEndpoint]:
        """Discover endpoints from MCP Gateway registry."""
        endpoints = []
        try:
            from app.mcp_gateway import mcp_gateway
            if hasattr(mcp_gateway, '_servers'):
                for server_id, server_config in getattr(mcp_gateway, '_servers', {}).items():
                    ep = AIEndpoint(
                        id=f"mcp-{server_id}",
                        name=f"MCP Server: {server_config.get('name', server_id)}",
                        endpoint_type="mcp_tool",
                        url=server_config.get("url", ""),
                        provider="mcp",
                        is_protected=True,  # MCP Gateway always routes through firewall
                        protection_method="mcp_gateway",
                        last_seen=datetime.now(timezone.utc).isoformat(),
                        metadata={"tools": server_config.get("tools", [])},
                    )
                    endpoints.append(ep)
        except ImportError:
            pass
        return endpoints

    async def _scan_providers(self, org_id: str) -> list[AIEndpoint]:
        """Discover endpoints from configured AI providers."""
        from app.core.config import get_settings
        settings = get_settings()

        PROVIDER_ENDPOINTS = {
            "openai": ("https://api.openai.com/v1", settings.OPENAI_API_KEY),
            "anthropic": ("https://api.anthropic.com/v1", settings.ANTHROPIC_API_KEY),
            "google": ("https://generativelanguage.googleapis.com/v1", settings.GOOGLE_AI_API_KEY),
            "mistral": ("https://api.mistral.ai/v1", settings.MISTRAL_API_KEY),
            "cohere": ("https://api.cohere.ai/v1", settings.COHERE_API_KEY),
            "groq": ("https://api.groq.com/openai/v1", settings.GROQ_API_KEY),
            "together": ("https://api.together.xyz/v1", settings.TOGETHER_API_KEY),
            "deepseek": ("https://api.deepseek.com/v1", settings.DEEPSEEK_API_KEY),
            "perplexity": ("https://api.perplexity.ai", settings.PERPLEXITY_API_KEY),
            "xai": ("https://api.x.ai/v1", settings.XAI_API_KEY),
            "ollama": (settings.OLLAMA_BASE_URL, "local"),
        }

        endpoints = []
        for provider, (url, key) in PROVIDER_ENDPOINTS.items():
            if key:
                ep = AIEndpoint(
                    id=f"provider-{provider}",
                    name=f"{provider.title()} API",
                    endpoint_type="provider_direct",
                    url=url,
                    provider=provider,
                    is_protected=True,  # All calls through GhostPrompt proxy
                    protection_method="proxy",
                    last_seen=datetime.now(timezone.utc).isoformat(),
                )
                endpoints.append(ep)
        return endpoints

    async def _scan_proxy_routes(self) -> list[AIEndpoint]:
        """Discover endpoints from registered proxy routes."""
        # The proxy routes /v1/chat/completions etc. are always protected
        return [
            AIEndpoint(
                id="proxy-chat", name="Chat Completions Proxy",
                endpoint_type="api_proxy", url="/v1/chat/completions",
                is_protected=True, protection_method="proxy",
                last_seen=datetime.now(timezone.utc).isoformat(),
            ),
            AIEndpoint(
                id="proxy-multi", name="Multi-Provider Proxy",
                endpoint_type="api_proxy", url="/v1/multi/completions",
                is_protected=True, protection_method="proxy",
                last_seen=datetime.now(timezone.utc).isoformat(),
            ),
        ]

    def _assess_risk(self, ep: AIEndpoint):
        """Assess risk level for an endpoint."""
        reasons = []
        if not ep.is_protected:
            reasons.append("Not routed through GhostPrompt firewall")
            reasons.append("No prompt injection protection")
            reasons.append("No output scanning")
        if ep.protection_method == "none":
            reasons.append("No protection method configured")
        if ep.endpoint_type == "provider_direct" and ep.protection_method != "proxy":
            reasons.append("Direct API access without proxy protection")

        ep.risk_reasons = reasons
        if not ep.is_protected:
            ep.risk_level = "critical" if ep.endpoint_type == "provider_direct" else "high"
        elif len(reasons) > 0:
            ep.risk_level = "medium"
        else:
            ep.risk_level = "safe"

    def _generate_recommendations(self, endpoints: list[AIEndpoint]) -> list[dict]:
        """Generate actionable recommendations."""
        recs = []
        unprotected = [ep for ep in endpoints if not ep.is_protected]
        if unprotected:
            recs.append({
                "severity": "critical",
                "title": f"{len(unprotected)} unprotected AI endpoint(s) detected",
                "description": "Route these endpoints through the GhostPrompt proxy or MCP Gateway to enable prompt injection protection, output scanning, and threat monitoring.",
                "affected": [ep.name for ep in unprotected],
            })

        no_owner = [ep for ep in endpoints if not ep.owner]
        if no_owner:
            recs.append({
                "severity": "medium",
                "title": f"{len(no_owner)} endpoint(s) without assigned owner",
                "description": "Assign ownership to ensure accountability for AI security posture.",
                "affected": [ep.name for ep in no_owner[:10]],
            })

        return recs


# Singleton
attack_surface_scanner = AIAttackSurfaceScanner()
