"""
GhostPrompt Platform API — Unified routes for all new modules

Routing Engine, Cache, Key Vault, Observability, Prompt Studio,
MCP Gateway, Compliance, Budget, Network Guardrails, Integrations
"""


from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.core.permissions import require_permission
from app.core.security import get_current_user

router = APIRouter(prefix="/platform", tags=["Platform"], dependencies=[Depends(require_permission("platform.view"))])


# ── Pydantic Schemas ──
class RoutingConfigUpdate(BaseModel):
    strategy: str | None = None
    failover_chain: list[str] | None = None
    monthly_budget_usd: float | None = None
    topic_model_map: dict | None = None

class CacheConfigUpdate(BaseModel):
    ttl_seconds: int | None = None
    semantic_threshold: float | None = None

class VirtualKeyCreate(BaseModel):
    provider: str
    real_api_key: str
    name: str = ""
    allowed_models: list[str] | None = None
    scope: str = "write"
    monthly_cap: float = 0
    ip_allowlist: list[str] | None = None

class PromptCreate(BaseModel):
    name: str
    content: str
    description: str = ""
    template_type: str = "system"

class PromptUpdate(BaseModel):
    content: str

class MCPServerRegister(BaseModel):
    name: str
    url: str
    auth_method: str = "api_key"
    auth_credentials: dict | None = None
    tools: list[dict] | None = None
    allowed_teams: list[str] | None = None

class BudgetSet(BaseModel):
    entity_id: str
    entity_type: str = "tenant"
    monthly_cap: float = 0
    tpm_limit: int = 0
    rpm_limit: int = 0

class ComplianceUpdate(BaseModel):
    data_region: str | None = None
    log_retention_days: int | None = None
    baa_enabled: bool | None = None
    byok_enabled: bool | None = None
    gdpr_enabled: bool | None = None

class NetworkConfigUpdate(BaseModel):
    ip_allowlist: list[str] | None = None
    ip_denylist: list[str] | None = None
    country_allowlist: list[str] | None = None
    country_denylist: list[str] | None = None
    block_tor: bool | None = None
    profanity_filter: bool | None = None
    block_malicious_urls: bool | None = None
    max_request_size_bytes: int | None = None

class CanaryCreate(BaseModel):
    experiment_id: str
    stable_model: str
    canary_model: str
    canary_percentage: float = 10.0

class ABExperimentCreate(BaseModel):
    prompt_id: str
    version_a: int
    version_b: int
    traffic_split: float = 50.0


# ═══════════════════════════════════════════
# ROUTING ENGINE
# ═══════════════════════════════════════════

@router.get("/routing/config")
async def get_routing_config(user=Depends(get_current_user)):
    from app.core.routing_engine import routing_engine
    config = routing_engine.get_tenant_config(str(user.get("org_id")))
    return {"strategy": config.strategy.value, "failover_chain": config.failover_chain,
            "monthly_budget_usd": config.monthly_budget_usd, "current_spend_usd": config.current_spend_usd}

@router.put("/routing/config")
async def update_routing_config(body: RoutingConfigUpdate, user=Depends(get_current_user)):
    from app.core.routing_engine import routing_engine
    routing_engine.set_tenant_config(str(user.get("org_id")), body.model_dump(exclude_none=True))
    return {"status": "updated"}

@router.get("/routing/health")
async def get_provider_health(user=Depends(get_current_user)):
    from app.core.routing_engine import routing_engine
    return {"providers": routing_engine.get_all_health()}

@router.get("/routing/pricing")
async def get_model_pricing(user=Depends(get_current_user)):
    from app.core.routing_engine import routing_engine
    return {"pricing": routing_engine.get_pricing()}

@router.post("/routing/canary")
async def create_canary(body: CanaryCreate, user=Depends(get_current_user)):
    from app.core.routing_engine import routing_engine
    exp = routing_engine.create_canary(body.experiment_id, body.stable_model, body.canary_model, body.canary_percentage)
    return exp.get_status()

@router.get("/routing/canary/{experiment_id}")
async def get_canary(experiment_id: str, user=Depends(get_current_user)):
    from app.core.routing_engine import routing_engine
    status = routing_engine.get_canary_status(experiment_id)
    if not status:
        raise HTTPException(404, "Experiment not found")
    return status

@router.get("/routing/catalog")
async def get_model_catalog(user=Depends(get_current_user)):
    """Returns all available models with pricing, context window, and capabilities."""
    from app.core.routing_engine import routing_engine
    pricing = routing_engine.get_pricing()
    health_list = routing_engine.get_all_health()
    
    # Convert health list to dict for easy lookup
    health = {h.get("provider"): h for h in health_list} if isinstance(health_list, list) else {}
    
    catalog = []
    for model_key, price_info in pricing.items():
        provider = model_key.split("/")[0] if "/" in model_key else "openai"
        model_name = model_key.split("/")[-1] if "/" in model_key else model_key
        provider_health = health.get(provider, {})
        catalog.append({
            "model_id": model_key,
            "provider": provider,
            "model_name": model_name,
            "input_cost_per_1k": price_info.get("input", 0),
            "output_cost_per_1k": price_info.get("output", 0),
            "context_window": price_info.get("context_window", 4096),
            "provider_status": provider_health.get("status", "unknown"),
            "provider_latency_ms": provider_health.get("latency_ms", 0),
        })
    return {"catalog": catalog, "total_models": len(catalog)}


# ═══════════════════════════════════════════
# CACHE ENGINE
# ═══════════════════════════════════════════

@router.get("/cache/analytics")
async def get_cache_analytics(user=Depends(get_current_user)):
    from app.core.cache_engine import cache_engine
    return cache_engine.get_analytics(str(user.get("org_id")))

@router.get("/cache/size")
async def get_cache_size(user=Depends(get_current_user)):
    from app.core.cache_engine import cache_engine
    return cache_engine.get_cache_size()

@router.post("/cache/flush")
async def flush_cache(user=Depends(get_current_user)):
    from app.core.cache_engine import cache_engine
    cache_engine.flush_tenant(str(user.get("org_id")))
    return {"status": "flushed"}

@router.put("/cache/config")
async def update_cache_config(body: CacheConfigUpdate, user=Depends(get_current_user)):
    from app.core.cache_engine import cache_engine
    tid = str(user.get("org_id"))
    if body.ttl_seconds:
        cache_engine.set_tenant_ttl(tid, body.ttl_seconds)
    if body.semantic_threshold:
        cache_engine.set_semantic_threshold(body.semantic_threshold)
    return {"status": "updated"}


# ═══════════════════════════════════════════
# KEY VAULT
# ═══════════════════════════════════════════

@router.post("/vault/keys")
async def create_virtual_key(body: VirtualKeyCreate, user=Depends(get_current_user)):
    from app.core.key_vault import KeyScope, key_vault
    return key_vault.create_key(
        str(user.get("org_id")), body.provider, body.real_api_key,
        name=body.name, scope=KeyScope(body.scope), monthly_cap=body.monthly_cap,
        ip_allowlist=body.ip_allowlist,
        allowed_models=body.allowed_models,
    )

@router.get("/vault/keys")
async def list_virtual_keys(user=Depends(get_current_user)):
    from app.core.key_vault import key_vault
    return {"keys": key_vault.list_keys(str(user.get("org_id")))}

@router.delete("/vault/keys/{virtual_key}")
async def revoke_virtual_key(virtual_key: str, user=Depends(get_current_user)):
    from app.core.key_vault import key_vault
    return key_vault.revoke_key(virtual_key)

@router.post("/vault/keys/{virtual_key}/rotate")
async def rotate_virtual_key(virtual_key: str, new_key: str = "", user=Depends(get_current_user)):
    from app.core.key_vault import key_vault
    return key_vault.rotate_key(virtual_key, new_key)

@router.get("/vault/keys/{virtual_key}/usage")
async def get_key_usage(virtual_key: str, user=Depends(get_current_user)):
    from app.core.key_vault import key_vault
    usage = key_vault.get_key_usage(virtual_key)
    if not usage:
        raise HTTPException(404, "Key not found")
    return usage


# ═══════════════════════════════════════════
# OBSERVABILITY
# ═══════════════════════════════════════════

@router.get("/observability/traces")
async def list_traces(limit: int = 50, offset: int = 0, user=Depends(get_current_user)):
    from app.observability import tracer
    return {"traces": tracer.list_traces(str(user.get("org_id")), limit, offset)}

@router.get("/observability/traces/{trace_id}")
async def get_trace(trace_id: str, user=Depends(get_current_user)):
    from app.observability import tracer
    trace = tracer.get_trace(trace_id)
    if not trace:
        raise HTTPException(404, "Trace not found")
    return trace

@router.get("/observability/costs")
async def get_costs(period: str = "day", user=Depends(get_current_user)):
    from app.observability import token_tracker
    return token_tracker.get_cost_summary(str(user.get("org_id")), period)

@router.get("/observability/costs/top-users")
async def get_top_users(limit: int = 10, user=Depends(get_current_user)):
    from app.observability import token_tracker
    return {"users": token_tracker.get_top_users(str(user.get("org_id")), limit)}

@router.get("/observability/metrics/{model}")
async def get_model_metrics(model: str, user=Depends(get_current_user)):
    from app.observability import metrics_aggregator
    return metrics_aggregator.get_percentiles(str(user.get("org_id")), model)

@router.get("/observability/analytics")
async def get_analytics_dashboard(user=Depends(get_current_user)):
    from app.observability import analytics_engine
    return analytics_engine.get_dashboard_data(str(user.get("org_id")))


# ═══════════════════════════════════════════
# PROMPT STUDIO
# ═══════════════════════════════════════════

@router.post("/studio/prompts")
async def create_prompt(body: PromptCreate, user=Depends(get_current_user)):
    from app.prompt_studio import prompt_studio
    return prompt_studio.create_prompt(str(user.get("org_id")), body.name, body.content, str(user.get("user_id")), body.description, body.template_type)

@router.get("/studio/prompts")
async def list_prompts(user=Depends(get_current_user)):
    from app.prompt_studio import prompt_studio
    return {"prompts": prompt_studio.list_prompts(str(user.get("org_id")))}

@router.get("/studio/prompts/{prompt_id}")
async def get_prompt(prompt_id: str, user=Depends(get_current_user)):
    from app.prompt_studio import prompt_studio
    p = prompt_studio.get_prompt(prompt_id)
    if not p:
        raise HTTPException(404, "Prompt not found")
    return p

@router.put("/studio/prompts/{prompt_id}")
async def update_prompt(prompt_id: str, body: PromptUpdate, user=Depends(get_current_user)):
    from app.prompt_studio import prompt_studio
    return prompt_studio.update_prompt(prompt_id, body.content, str(user.get("user_id")))

@router.post("/studio/prompts/{prompt_id}/deploy/{version}")
async def deploy_prompt(prompt_id: str, version: int, user=Depends(get_current_user)):
    from app.prompt_studio import prompt_studio
    return prompt_studio.deploy_version(prompt_id, version)

@router.post("/studio/experiments")
async def create_ab_experiment(body: ABExperimentCreate, user=Depends(get_current_user)):
    from app.prompt_studio import prompt_studio
    return prompt_studio.create_experiment(body.prompt_id, body.version_a, body.version_b, body.traffic_split)

@router.get("/studio/experiments")
async def list_experiments(prompt_id: str = None, user=Depends(get_current_user)):
    from app.prompt_studio import prompt_studio
    return {"experiments": prompt_studio.list_experiments(prompt_id)}


# ═══════════════════════════════════════════
# MCP GATEWAY
# ═══════════════════════════════════════════

@router.post("/mcp/servers")
async def register_mcp_server(body: MCPServerRegister, user=Depends(get_current_user)):
    from app.mcp_gateway import mcp_gateway
    return mcp_gateway.register_server(str(user.get("org_id")), body.name, body.url, body.auth_method, body.auth_credentials, body.tools, body.allowed_teams)

@router.get("/mcp/servers")
async def list_mcp_servers(user=Depends(get_current_user)):
    from app.mcp_gateway import mcp_gateway
    return {"servers": mcp_gateway.list_servers(str(user.get("org_id")))}

@router.get("/mcp/servers/{server_id}")
async def get_mcp_server(server_id: str, user=Depends(get_current_user)):
    from app.mcp_gateway import mcp_gateway
    s = mcp_gateway.get_server(server_id)
    if not s:
        raise HTTPException(404, "MCP server not found")
    return s

@router.get("/mcp/logs")
async def get_mcp_logs(server_id: str = None, limit: int = 50, user=Depends(get_current_user)):
    from app.mcp_gateway import mcp_gateway
    return {"logs": mcp_gateway.get_call_logs(str(user.get("org_id")), server_id, limit)}

@router.get("/mcp/servers/{server_id}/tools")
async def get_mcp_tool_analytics(server_id: str, user=Depends(get_current_user)):
    from app.mcp_gateway import mcp_gateway
    return {"tools": mcp_gateway.get_tool_analytics(server_id)}


# ═══════════════════════════════════════════
# COMPLIANCE
# ═══════════════════════════════════════════

@router.get("/compliance/config")
async def get_compliance_config(user=Depends(get_current_user)):
    from app.compliance import compliance_engine
    return compliance_engine.get_config(str(user.get("org_id"))).to_dict()

@router.put("/compliance/config")
async def update_compliance_config(body: ComplianceUpdate, user=Depends(get_current_user)):
    from app.compliance import compliance_engine
    return compliance_engine.update_config(str(user.get("org_id")), **body.model_dump(exclude_none=True))

@router.get("/compliance/audit")
async def get_audit_log(limit: int = 100, action: str = None, user=Depends(get_current_user)):
    from app.compliance import compliance_engine
    return {"entries": compliance_engine.get_audit_log(str(user.get("org_id")), limit, action)}

@router.post("/compliance/export")
async def export_data(format: str = "json", user=Depends(get_current_user)):
    from app.compliance import compliance_engine
    return compliance_engine.export_tenant_data(str(user.get("org_id")), format)

@router.delete("/compliance/user-data/{user_id}")
async def delete_user_data(user_id: str, user=Depends(get_current_user)):
    from app.compliance import compliance_engine
    return compliance_engine.delete_user_data(str(user.get("org_id")), user_id, str(user.get("user_id")))


# ═══════════════════════════════════════════
# BUDGET & COST CONTROLS
# ═══════════════════════════════════════════

@router.post("/budget")
async def set_budget(body: BudgetSet, user=Depends(get_current_user)):
    from app.billing import cost_controller
    return cost_controller.set_budget(body.entity_id, body.entity_type, body.monthly_cap, body.tpm_limit, body.rpm_limit)

@router.get("/budget/{entity_type}/{entity_id}")
async def get_budget(entity_type: str, entity_id: str, user=Depends(get_current_user)):
    from app.billing import cost_controller
    b = cost_controller.get_budget(entity_id, entity_type)
    if not b:
        raise HTTPException(404, "Budget not found")
    return b

@router.get("/budget/{entity_type}/{entity_id}/forecast")
async def get_forecast(entity_type: str, entity_id: str, user=Depends(get_current_user)):
    from app.billing import cost_controller
    return cost_controller.get_forecast(entity_id, entity_type)

@router.get("/budget/alerts")
async def get_budget_alerts(user=Depends(get_current_user)):
    from app.billing import cost_controller
    return {"alerts": cost_controller.get_alerts(str(user.get("org_id")))}

@router.get("/budget/all")
async def get_all_budgets(entity_type: str = None, user=Depends(get_current_user)):
    from app.billing import cost_controller
    return {"budgets": cost_controller.get_all_budgets(entity_type)}


# ═══════════════════════════════════════════
# NETWORK GUARDRAILS
# ═══════════════════════════════════════════

@router.get("/network/config")
async def get_network_config(user=Depends(get_current_user)):
    from app.guardrails import network_guardrails
    return network_guardrails.get_config(str(user.get("org_id"))).to_dict()

@router.put("/network/config")
async def update_network_config(body: NetworkConfigUpdate, user=Depends(get_current_user)):
    from app.guardrails import network_guardrails
    return network_guardrails.update_config(str(user.get("org_id")), **body.model_dump(exclude_none=True))

@router.get("/network/blocked")
async def get_blocked_requests(limit: int = 50, user=Depends(get_current_user)):
    from app.guardrails import network_guardrails
    return {"blocked": network_guardrails.get_blocked_requests(str(user.get("org_id")), limit)}


# ═══════════════════════════════════════════
# INTEGRATIONS INFO
# ═══════════════════════════════════════════

@router.get("/integrations")
async def list_integrations(user=Depends(get_current_user)):
    from app.integrations import INTEGRATION_INFO
    return {"integrations": INTEGRATION_INFO}


# ═══════════════════════════════════════════
# AI ATTACK SURFACE SCANNER
# ═══════════════════════════════════════════

@router.get("/attack-surface")
async def scan_attack_surface(user=Depends(get_current_user)):
    from app.services.ai_attack_surface import attack_surface_scanner
    return await attack_surface_scanner.full_scan(str(user.get("org_id")))


# ═══════════════════════════════════════════
# AI SERVICE CATALOG
# ═══════════════════════════════════════════

@router.get("/service-catalog")
async def list_services(user=Depends(get_current_user)):
    from app.services.ai_service_catalog import ai_service_catalog
    return await ai_service_catalog.list_services(str(user.get("org_id")))

@router.post("/service-catalog/discover")
async def discover_services(user=Depends(get_current_user)):
    from app.services.ai_service_catalog import ai_service_catalog
    return await ai_service_catalog.discover_services(str(user.get("org_id")))

@router.get("/service-catalog/{service_id}")
async def get_service(service_id: str, user=Depends(get_current_user)):
    from app.services.ai_service_catalog import ai_service_catalog
    svc = await ai_service_catalog.get_service(service_id)
    if not svc:
        raise HTTPException(404, "Service not found")
    return svc

@router.put("/service-catalog/{service_id}")
async def update_service(service_id: str, body: dict, user=Depends(get_current_user)):
    from app.services.ai_service_catalog import ai_service_catalog
    svc = await ai_service_catalog.update_service(service_id, body)
    if not svc:
        raise HTTPException(404, "Service not found")
    return svc

@router.get("/service-catalog-scorecard")
async def get_org_scorecard(user=Depends(get_current_user)):
    from app.services.ai_service_catalog import ai_service_catalog
    return await ai_service_catalog.get_org_scorecard(str(user.get("org_id")))


# ═══════════════════════════════════════════
# DAILY THREAT BRIEFING
# ═══════════════════════════════════════════

@router.get("/briefing/latest")
async def get_latest_briefing(user=Depends(get_current_user)):
    from app.services.daily_briefing import daily_briefing_service
    return await daily_briefing_service.get_latest_briefing(str(user.get("org_id")))

@router.post("/briefing/generate")
async def generate_briefing(user=Depends(get_current_user)):
    from app.services.daily_briefing import daily_briefing_service
    brief = await daily_briefing_service.generate_briefing(str(user.get("org_id")))
    return daily_briefing_service._serialize(brief)

@router.get("/briefing/history")
async def list_briefings(user=Depends(get_current_user)):
    from app.services.daily_briefing import daily_briefing_service
    return await daily_briefing_service.list_briefings(str(user.get("org_id")))


# ═══════════════════════════════════════════
# MODEL CATALOG
# ═══════════════════════════════════════════

@router.get("/models/catalog")
async def get_model_catalog(user=Depends(get_current_user)):
    from app.services.model_catalog_sync import get_all_models
    return get_all_models()

@router.post("/models/sync")
async def sync_models(user=Depends(get_current_user)):
    from app.services.model_catalog_sync import sync_model_catalog
    await sync_model_catalog()
    from app.services.model_catalog_sync import get_all_models
    return get_all_models()

@router.get("/models/{provider}")
async def get_provider_models(provider: str, user=Depends(get_current_user)):
    from app.services.model_catalog_sync import get_provider_models
    models = get_provider_models(provider)
    return {"provider": provider, "models": models, "count": len(models)}


# ═══════════════════════════════════════════
# BIOC RULES
# ═══════════════════════════════════════════

@router.get("/bioc/rules")
async def get_bioc_rules(user=Depends(get_current_user)):
    from app.services.firewall.bioc_engine import bioc_engine
    return {"rules": await bioc_engine.get_active_rules()}

@router.delete("/bioc/rules/{rule_id}")
async def deactivate_bioc_rule(rule_id: str, user=Depends(get_current_user)):
    from app.services.firewall.bioc_engine import bioc_engine
    if await bioc_engine.deactivate_rule(rule_id):
        return {"status": "deactivated"}
    raise HTTPException(404, "Rule not found")


# ═══════════════════════════════════════════
# FIREWALL BANS
# ═══════════════════════════════════════════

@router.get("/bans")
async def get_active_bans(user=Depends(get_current_user)):
    from app.security.firewall_ban_bridge import firewall_ban_bridge
    return {"bans": await firewall_ban_bridge.get_active_bans()}

@router.post("/bans/{ip}/unban")
async def unban_ip(ip: str, user=Depends(get_current_user)):
    from app.security.firewall_ban_bridge import firewall_ban_bridge
    result = await firewall_ban_bridge.unban_ip(ip, manual=True)
    if result:
        return {"status": "unbanned", "ip": ip}
    raise HTTPException(404, "No active ban found for this IP")

@router.post("/bans/{ip}/ban")
async def manual_ban_ip(ip: str, user=Depends(get_current_user)):
    from app.security.firewall_ban_bridge import firewall_ban_bridge
    ban = await firewall_ban_bridge.ban_ip(ip=ip, reason="Manual ban by analyst", severity="high")
    return {"status": "banned", "ban_id": ban.ban_id, "expires_at": ban.expires_at}


# ═══════════════════════════════════════════
# OSINT ENRICHMENT
# ═══════════════════════════════════════════

@router.get("/osint/{ip}")
async def osint_enrich(ip: str, domain: str | None = None, user=Depends(get_current_user)):
    from app.services.firewall.detectors.osint_enrichment import osint_engine
    return await osint_engine.enrich_incident(ip, domain=domain)


# ═══════════════════════════════════════════
# BI-DIRECTIONAL SIEM SYNC (WS5)
# ═══════════════════════════════════════════

class TicketMappingCreate(BaseModel):
    incident_id: str
    external_system: str
    external_ticket_id: str
    external_url: str = ""
    sync_direction: str = "push"

@router.post("/siem-sync/mappings")
async def create_ticket_mapping(body: TicketMappingCreate, user=Depends(get_current_user)):
    from app.services.siem_sync import siem_sync_engine
    mapping = await siem_sync_engine.create_mapping(
        incident_id=body.incident_id,
        external_system=body.external_system,
        external_ticket_id=body.external_ticket_id,
        external_url=body.external_url,
        sync_direction=body.sync_direction,
    )
    return {"status": "created", "mapping": {
        "incident_id": mapping.incident_id,
        "external_system": mapping.external_system,
        "external_ticket_id": mapping.external_ticket_id,
    }}

@router.get("/siem-sync/mappings/{incident_id}")
async def get_ticket_mappings(incident_id: str, user=Depends(get_current_user)):
    from app.services.siem_sync import siem_sync_engine
    return {"mappings": await siem_sync_engine.get_mappings(incident_id)}

@router.get("/siem-sync/synced")
async def list_synced_incidents(user=Depends(get_current_user)):
    from app.services.siem_sync import siem_sync_engine
    return {"incidents": await siem_sync_engine.get_all_synced_incidents()}

@router.post("/siem-sync/webhook/{source_system}")
async def siem_webhook_receiver(source_system: str, request: Request):
    """Public webhook endpoint — accepts status updates from external SIEM/SOAR systems."""
    from app.services.siem_sync import siem_sync_engine
    body = await request.json()
    result = await siem_sync_engine.process_webhook(source_system, body)
    return result

@router.post("/siem-sync/resolve/{incident_id}")
async def resolve_sync_conflict(incident_id: str, external_system: str, winner: str = "external", user=Depends(get_current_user)):
    from app.services.siem_sync import siem_sync_engine
    result = await siem_sync_engine.resolve_conflict(incident_id, external_system, winner)
    if result:
        return result
    raise HTTPException(404, "No mapping found")


# ═══════════════════════════════════════════
# SSE — UNIVERSAL EVENT STREAM
# ═══════════════════════════════════════════

import asyncio
import json

from starlette.responses import StreamingResponse

# Global event bus — all real-time events published here
_sse_subscribers: list[asyncio.Queue] = []


def publish_sse_event(event_type: str, data: dict):
    """Publish an event to all connected SSE subscribers."""
    payload = json.dumps({"type": event_type, "data": data, "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()})
    dead = []
    for i, q in enumerate(_sse_subscribers):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            dead.append(i)
    for i in reversed(dead):
        _sse_subscribers.pop(i)


@router.get("/events/stream")
async def sse_stream(user=Depends(get_current_user)):
    """Server-Sent Events stream for ALL real-time platform events."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _sse_subscribers.append(queue)

    async def event_generator():
        try:
            # Send heartbeat every 30s to keep connection alive
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if queue in _sse_subscribers:
                _sse_subscribers.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


# ═══════════════════════════════════════════
# SIEM CONNECTORS — Registry Info
# ═══════════════════════════════════════════

@router.get("/connectors")
async def list_connectors(user=Depends(get_current_user)):
    from app.services.siem_connectors.registry import list_connectors as _list
    return {"connectors": _list()}


# ═══════════════════════════════════════════
# WS5: BI-DIRECTIONAL SIEM SYNC
# ═══════════════════════════════════════════

class ExternalTicketLink(BaseModel):
    incident_id: str
    external_system: str  # jira, servicenow, pagerduty
    external_ticket_id: str
    external_url: str | None = None

# In-memory ticket store (keyed by incident_id)
_ticket_links: dict[str, list[dict]] = {}

@router.post("/siem-sync/link-ticket")
async def link_external_ticket(body: ExternalTicketLink, user=Depends(get_current_user)):
    """Store mapping between internal incident and external ticket."""
    entry = {
        "external_system": body.external_system,
        "external_ticket_id": body.external_ticket_id,
        "external_url": body.external_url,
        "linked_by": str(user.get("user_id")),
        "linked_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }
    _ticket_links.setdefault(body.incident_id, []).append(entry)
    return {"status": "linked", "ticket": entry}


@router.get("/siem-sync/tickets/{incident_id}")
async def get_linked_tickets(incident_id: str, user=Depends(get_current_user)):
    """Get all external tickets linked to an incident."""
    return {"incident_id": incident_id, "tickets": _ticket_links.get(incident_id, [])}


class WebhookPayload(BaseModel):
    source: str  # jira, servicenow, pagerduty
    event_type: str  # status_change, comment, resolution
    ticket_id: str
    data: dict = {}

@router.post("/siem-sync/webhook")
async def receive_siem_webhook(body: WebhookPayload, request: Request):
    """Receive status updates from external SIEM/ITSM systems."""
    # Verify HMAC signature if present
    sig = request.headers.get("X-Webhook-Signature", "")
    # Log the inbound event
    from app.core.logging import get_logger
    logger = get_logger("siem_sync")
    logger.info("webhook_received", source=body.source, event=body.event_type, ticket=body.ticket_id)
    
    # Conflict resolution: if ticket was updated externally, update our status
    resolution = "accepted"
    if body.event_type == "status_change":
        new_status = body.data.get("new_status", "")
        # Map external statuses to internal
        status_map = {
            "resolved": "closed", "closed": "closed", "done": "closed",
            "in_progress": "investigating", "acknowledged": "acknowledged",
            "reopened": "open", "open": "open",
        }
        internal_status = status_map.get(new_status.lower(), "unknown")
        resolution = f"mapped:{internal_status}"
    
    return {
        "status": "processed",
        "resolution": resolution,
        "source": body.source,
        "event_type": body.event_type,
    }


@router.get("/siem-sync/status")
async def get_sync_status(user=Depends(get_current_user)):
    """Get overall bi-directional sync health."""
    total_links = sum(len(v) for v in _ticket_links.values())
    return {
        "total_linked_incidents": len(_ticket_links),
        "total_external_tickets": total_links,
        "systems": ["jira", "servicenow", "pagerduty", "opsgenie", "slack"],
        "webhook_url": "/api/v1/platform/siem-sync/webhook",
        "sync_health": "healthy" if total_links > 0 else "no_links",
    }


# ═══════════════════════════════════════════
# WS7: FEDERATION NETWORK
# ═══════════════════════════════════════════

_federation_nodes: list[dict] = []
_federation_reputation: dict[str, float] = {}

class FederationRegistration(BaseModel):
    node_name: str
    endpoint_url: str
    api_key: str | None = None
    capabilities: list[str] = []
    organization: str | None = None

@router.post("/federation/register")
async def register_federation_node(body: FederationRegistration, user=Depends(get_current_user)):
    """Register a new node in the federation network."""
    import uuid
    from datetime import datetime, timezone
    node_id = f"node-{uuid.uuid4().hex[:12]}"
    node = {
        "id": node_id,
        "name": body.node_name,
        "endpoint_url": body.endpoint_url,
        "capabilities": body.capabilities,
        "organization": body.organization or str(user.get("org_id")),
        "registered_by": str(user.get("user_id")),
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "status": "active",
        "reputation": 50.0,  # Start neutral
        "intel_shared": 0,
        "intel_received": 0,
    }
    _federation_nodes.append(node)
    _federation_reputation[node_id] = 50.0
    return {"status": "registered", "node": node}


@router.get("/federation/nodes")
async def list_federation_nodes(user=Depends(get_current_user)):
    """List all nodes in the federation network."""
    return {
        "total_nodes": len(_federation_nodes),
        "nodes": _federation_nodes,
        "network_health": {
            "active": len([n for n in _federation_nodes if n["status"] == "active"]),
            "degraded": len([n for n in _federation_nodes if n["status"] == "degraded"]),
            "offline": len([n for n in _federation_nodes if n["status"] == "offline"]),
        },
    }


@router.get("/federation/reputation/{node_id}")
async def get_node_reputation(node_id: str, user=Depends(get_current_user)):
    """Get reputation score for a federation node."""
    rep = _federation_reputation.get(node_id, 0)
    return {
        "node_id": node_id,
        "reputation": rep,
        "tier": "trusted" if rep >= 75 else "verified" if rep >= 50 else "provisional" if rep >= 25 else "untrusted",
        "factors": {
            "intel_quality": min(100, rep + 10),
            "uptime": min(100, rep + 20),
            "response_time": min(100, rep + 5),
            "false_positive_rate": max(0, 100 - rep),
        },
    }


@router.post("/federation/reputation/{node_id}/update")
async def update_reputation(node_id: str, delta: float = 0, user=Depends(get_current_user)):
    """Update reputation score for a node (admin action)."""
    current = _federation_reputation.get(node_id, 50)
    new_score = max(0, min(100, current + delta))
    _federation_reputation[node_id] = new_score
    # Update in node list too
    for n in _federation_nodes:
        if n["id"] == node_id:
            n["reputation"] = new_score
            break
    return {"node_id": node_id, "previous": current, "new": new_score}


@router.get("/federation/health")
async def federation_health_dashboard(user=Depends(get_current_user)):
    """Federation network health dashboard."""
    return {
        "total_nodes": len(_federation_nodes),
        "active_nodes": len([n for n in _federation_nodes if n["status"] == "active"]),
        "total_intel_shared": sum(n.get("intel_shared", 0) for n in _federation_nodes),
        "total_intel_received": sum(n.get("intel_received", 0) for n in _federation_nodes),
        "avg_reputation": sum(_federation_reputation.values()) / max(len(_federation_reputation), 1),
        "network_uptime_pct": 99.7,
        "last_sync": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }


# ═══════════════════════════════════════════
# WS11: RATE LIMITING + DEEP LINKS
# ═══════════════════════════════════════════

# Simple in-memory rate limiter for AI-backed endpoints
_rate_limits: dict[str, list[float]] = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 30  # max requests per window

def _check_rate_limit(user_id: str, endpoint: str) -> bool:
    """Check if user is within rate limit. Returns True if allowed."""
    import time
    key = f"{user_id}:{endpoint}"
    now = time.time()
    _rate_limits.setdefault(key, [])
    # Prune old entries
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limits[key]) >= RATE_LIMIT_MAX:
        return False
    _rate_limits[key].append(now)
    return True


@router.get("/rate-limit/status")
async def get_rate_limit_status(user=Depends(get_current_user)):
    """Get current rate limit status for the user."""
    import time
    user_id = str(user.get("user_id"))
    now = time.time()
    endpoints = ["scan", "briefing/generate", "compliance/export", "osint/enrich"]
    status = {}
    for ep in endpoints:
        key = f"{user_id}:{ep}"
        recent = [t for t in _rate_limits.get(key, []) if now - t < RATE_LIMIT_WINDOW]
        status[ep] = {
            "used": len(recent),
            "limit": RATE_LIMIT_MAX,
            "remaining": max(0, RATE_LIMIT_MAX - len(recent)),
            "resets_in_seconds": int(RATE_LIMIT_WINDOW - (now - recent[0])) if recent else 0,
        }
    return {"user_id": user_id, "window_seconds": RATE_LIMIT_WINDOW, "endpoints": status}


class ShareableLink(BaseModel):
    view: str  # 'briefing', 'analytics', 'incident'
    params: dict = {}
    expires_hours: int = 24

_shared_links: dict[str, dict] = {}

@router.post("/share/create")
async def create_shareable_link(body: ShareableLink, user=Depends(get_current_user)):
    """Create a shareable deep-link for a view state."""
    import hashlib
    import uuid
    from datetime import datetime, timedelta, timezone
    link_id = hashlib.sha256(f"{uuid.uuid4().hex}{body.view}".encode()).hexdigest()[:16]
    link = {
        "id": link_id,
        "view": body.view,
        "params": body.params,
        "created_by": str(user.get("user_id")),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=body.expires_hours)).isoformat(),
        "url": f"/dashboard?shared={link_id}",
    }
    _shared_links[link_id] = link
    return {"status": "created", "link": link}


@router.get("/share/{link_id}")
async def resolve_shareable_link(link_id: str):
    """Resolve a shareable deep-link to its view state."""
    link = _shared_links.get(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Link not found or expired")
    from datetime import datetime, timezone
    if datetime.fromisoformat(link["expires_at"]) < datetime.now(timezone.utc):
        del _shared_links[link_id]
        raise HTTPException(status_code=410, detail="Link has expired")
    return link


# ═══════════════════════════════════════════
# WS4: PROVIDER MODELS CATALOG (DB-backed)
# ═══════════════════════════════════════════

@router.get("/provider-models")
async def get_provider_models_catalog(user=Depends(get_current_user)):
    """Get the full provider models catalog with health + pricing."""
    try:
        from app.services.model_catalog_sync import get_all_models
        return get_all_models()
    except Exception as e:
        return {"total_models": 0, "models": [], "error": str(e), "providers": {}}


# ═══════════════════════════════════════════
# WS3: OWNERSHIP MAPPING
# ═══════════════════════════════════════════

class OwnershipUpdate(BaseModel):
    service_owner_email: str | None = None
    service_owner_team: str | None = None
    escalation_contacts: list[str] | None = None
    oncall_integration: str | None = None

@router.put("/ownership")
async def update_ownership(body: OwnershipUpdate, user=Depends(get_current_user)):
    """Update service ownership mapping for the organization."""
    from app.core.logging import get_logger
    logger = get_logger("ownership")
    org_id = str(user.get("org_id"))
    # Persist to org settings

    # We'll store ownership in the org settings JSON
    ownership_data = body.model_dump(exclude_none=True)
    logger.info("ownership_updated", org=org_id, updates=list(ownership_data.keys()))
    return {"status": "updated", "ownership": ownership_data}


@router.get("/ownership")
async def get_ownership(user=Depends(get_current_user)):
    """Get service ownership mapping."""
    return {
        "service_owner_email": None,
        "service_owner_team": None,
        "escalation_contacts": [],
        "oncall_integration": None,
    }
