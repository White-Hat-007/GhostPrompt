"""
AI Service Catalog — cortex.io-Inspired Service Discovery & Readiness Scoring

Auto-discovers AI services from MCP Gateway + registered LLM endpoints.
Generates an AI Readiness Scorecard for each service:
  - Policy assigned?
  - Compliance framework mapped?
  - Owner assigned?
  - Routed through GhostPrompt?
  - Hallucination detection enabled?
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.logging import get_logger

logger = get_logger("service_catalog")


@dataclass
class AIService:
    """Represents a cataloged AI service."""
    id: str = field(default_factory=lambda: f"svc-{uuid.uuid4().hex[:10]}")
    name: str = ""
    description: str = ""
    service_type: str = ""      # llm_proxy, mcp_tool, agent, embedding, fine_tuned
    provider: str = ""
    model: str = ""
    endpoint: str = ""
    owner_team: str = ""
    owner_email: str = ""
    
    # Readiness scorecard
    has_policy: bool = False
    has_compliance_framework: bool = False
    has_owner: bool = False
    is_routed_through_gp: bool = False
    has_hallucination_detection: bool = False
    has_output_scanning: bool = False
    has_rate_limiting: bool = False
    has_audit_logging: bool = False
    
    # Metadata
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = ""
    last_activity: str | None = None
    request_count_24h: int = 0
    org_id: str = ""
    tags: list[str] = field(default_factory=list)
    status: str = "active"  # active, deprecated, pending_review


# ── In-memory catalog (production: PostgreSQL) ──
_catalog: dict[str, AIService] = {}


class AIServiceCatalog:
    """AI Service Catalog with readiness scoring."""

    def _compute_readiness_score(self, svc: AIService) -> dict:
        """Compute readiness score (0-100) with per-criterion breakdown."""
        criteria = {
            "policy_assigned": (svc.has_policy, 20),
            "compliance_mapped": (svc.has_compliance_framework, 15),
            "owner_assigned": (svc.has_owner, 15),
            "routed_through_ghostprompt": (svc.is_routed_through_gp, 20),
            "hallucination_detection": (svc.has_hallucination_detection, 10),
            "output_scanning": (svc.has_output_scanning, 10),
            "rate_limiting": (svc.has_rate_limiting, 5),
            "audit_logging": (svc.has_audit_logging, 5),
        }
        
        total = 0
        breakdown = {}
        for key, (met, weight) in criteria.items():
            earned = weight if met else 0
            total += earned
            breakdown[key] = {"met": met, "weight": weight, "earned": earned}
        
        grade = "A" if total >= 90 else "B" if total >= 75 else "C" if total >= 60 else "D" if total >= 40 else "F"
        
        return {"score": total, "max_score": 100, "grade": grade, "breakdown": breakdown}

    async def discover_services(self, org_id: str) -> list[dict]:
        """Auto-discover AI services and populate the catalog."""
        discovered = []

        # 1. Discover from configured providers
        from app.core.config import get_settings
        settings = get_settings()
        
        provider_map = {
            "openai": (settings.OPENAI_API_KEY, "GPT-4o, GPT-4o-mini"),
            "anthropic": (settings.ANTHROPIC_API_KEY, "Claude 3.5 Sonnet"),
            "google": (settings.GOOGLE_AI_API_KEY, "Gemini 2.5 Pro"),
            "groq": (settings.GROQ_API_KEY, "LLaMA 3, Mixtral"),
            "together": (settings.TOGETHER_API_KEY, "Open-source models"),
            "deepseek": (settings.DEEPSEEK_API_KEY, "DeepSeek R1"),
            "mistral": (settings.MISTRAL_API_KEY, "Mistral Large"),
            "xai": (settings.XAI_API_KEY, "Grok"),
        }
        
        for provider, (key, models) in provider_map.items():
            if key:
                svc_id = f"svc-{provider}-{org_id[:8]}"
                if svc_id not in _catalog:
                    svc = AIService(
                        id=svc_id,
                        name=f"{provider.title()} LLM Proxy",
                        description=f"Models: {models}",
                        service_type="llm_proxy",
                        provider=provider,
                        model=models.split(",")[0].strip(),
                        endpoint="/v1/chat/completions",
                        is_routed_through_gp=True,
                        has_output_scanning=True,
                        has_hallucination_detection=True,
                        has_rate_limiting=True,
                        has_audit_logging=True,
                        org_id=org_id,
                        tags=["auto-discovered", "llm"],
                    )
                    _catalog[svc_id] = svc
                discovered.append(svc_id)

        # 2. Discover from MCP Gateway
        try:
            from app.mcp_gateway import mcp_gateway
            if hasattr(mcp_gateway, '_servers'):
                for sid, sconfig in getattr(mcp_gateway, '_servers', {}).items():
                    svc_id = f"svc-mcp-{sid}"
                    if svc_id not in _catalog:
                        svc = AIService(
                            id=svc_id,
                            name=f"MCP: {sconfig.get('name', sid)}",
                            description=f"MCP tool server with {len(sconfig.get('tools', []))} tools",
                            service_type="mcp_tool",
                            provider="mcp",
                            endpoint=sconfig.get("url", ""),
                            is_routed_through_gp=True,
                            has_output_scanning=True,
                            org_id=org_id,
                            tags=["auto-discovered", "mcp"],
                        )
                        _catalog[svc_id] = svc
                    discovered.append(svc_id)
        except ImportError:
            pass

        logger.info("services_discovered", org=org_id, count=len(discovered))
        return [self._serialize(svc_id) for svc_id in discovered if svc_id in _catalog]

    async def list_services(self, org_id: str) -> list[dict]:
        """List all cataloged services for an org."""
        return [
            self._serialize(svc_id)
            for svc_id, svc in _catalog.items()
            if svc.org_id == org_id
        ]

    async def get_service(self, service_id: str) -> dict | None:
        svc = _catalog.get(service_id)
        return self._serialize(service_id) if svc else None

    async def update_service(self, service_id: str, data: dict) -> dict | None:
        svc = _catalog.get(service_id)
        if not svc:
            return None
        for k in ["name", "description", "owner_team", "owner_email", "tags", "status",
                   "has_policy", "has_compliance_framework", "has_owner",
                   "has_hallucination_detection", "has_output_scanning",
                   "has_rate_limiting", "has_audit_logging"]:
            if k in data:
                setattr(svc, k, data[k])
        if data.get("owner_team") or data.get("owner_email"):
            svc.has_owner = True
        svc.updated_at = datetime.now(timezone.utc).isoformat()
        return self._serialize(service_id)

    async def get_org_scorecard(self, org_id: str) -> dict:
        """Get aggregate readiness scorecard across all org services."""
        services = [svc for svc in _catalog.values() if svc.org_id == org_id]
        if not services:
            return {"total_services": 0, "avg_score": 0, "grade": "N/A", "services": []}
        
        scores = []
        service_cards = []
        for svc in services:
            card = self._compute_readiness_score(svc)
            scores.append(card["score"])
            service_cards.append({"id": svc.id, "name": svc.name, **card})
        
        avg = sum(scores) / len(scores)
        grade = "A" if avg >= 90 else "B" if avg >= 75 else "C" if avg >= 60 else "D" if avg >= 40 else "F"
        
        return {
            "total_services": len(services),
            "avg_score": round(avg, 1),
            "grade": grade,
            "services": service_cards,
        }

    def _serialize(self, svc_id: str) -> dict:
        svc = _catalog[svc_id]
        readiness = self._compute_readiness_score(svc)
        return {
            "id": svc.id, "name": svc.name, "description": svc.description,
            "service_type": svc.service_type, "provider": svc.provider,
            "model": svc.model, "endpoint": svc.endpoint,
            "owner_team": svc.owner_team, "owner_email": svc.owner_email,
            "status": svc.status, "tags": svc.tags,
            "created_at": svc.created_at, "updated_at": svc.updated_at,
            "last_activity": svc.last_activity,
            "request_count_24h": svc.request_count_24h,
            "readiness": readiness,
        }


# Singleton
ai_service_catalog = AIServiceCatalog()
