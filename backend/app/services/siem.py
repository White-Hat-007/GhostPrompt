"""
SIEM Integration Service

Push security events to enterprise SIEM platforms in real-time.
Supports 16 native connectors: Splunk HEC, Datadog, Microsoft Sentinel,
IBM QRadar, Elastic Security, CrowdStrike, Google Chronicle, PagerDuty,
Slack, ServiceNow, Jira, Amazon Security Lake, Sumo Logic, Opsgenie,
Microsoft Teams, and generic webhooks.
"""

import httpx
import json
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Optional
from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.siem_connectors.registry import get_connector

settings = get_settings()
logger = get_logger("siem")


class SIEMIntegration:
    """Pushes security events to SIEM platforms."""

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if not self._client:
            self._client = httpx.AsyncClient(timeout=10.0)
        return self._client

    async def push_event(self, event: dict) -> bool:
        """Push a security event to the configured SIEM."""
        if not settings.SIEM_WEBHOOK_URL:
            return False

        provider = settings.SIEM_PROVIDER.lower()
        try:
            if provider == "splunk":
                return await self._push_splunk(event)
            elif provider == "datadog":
                return await self._push_datadog(event)
            elif provider == "qradar":
                return await self._push_qradar(event)
            else:
                return await self._push_generic(event)
        except Exception as e:
            logger.error("siem_push_failed", error=str(e), provider=provider)
            return False

    async def _push_splunk(self, event: dict) -> bool:
        """Push to Splunk HTTP Event Collector (HEC)."""
        client = await self._get_client()
        payload = {
            "time": datetime.now(timezone.utc).timestamp(),
            "sourcetype": "ghostprompt:security",
            "source": "ghostprompt-ai-firewall",
            "host": "ghostprompt",
            "event": {
                "severity": event.get("threat_level", "info"),
                "action": event.get("action", "unknown"),
                "threat_score": event.get("threat_score", 0),
                "request_id": event.get("request_id", ""),
                "model_provider": event.get("model_provider", ""),
                "model_name": event.get("model_name", ""),
                "detections": event.get("detections", []),
                "source_ip": event.get("source_ip", ""),
                "scan_type": event.get("scan_type", "prompt"),
                "scan_duration_ms": event.get("scan_duration_ms", 0),
                "threat_categories": event.get("threat_categories", []),
                "is_blocked": event.get("is_blocked", False),
            },
        }
        resp = await client.post(
            settings.SIEM_WEBHOOK_URL,
            headers={
                "Authorization": f"Splunk {settings.SIEM_WEBHOOK_SECRET}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        return resp.status_code == 200

    async def _push_datadog(self, event: dict) -> bool:
        """Push to Datadog Log Intake API."""
        client = await self._get_client()
        log_entry = {
            "ddsource": "ghostprompt",
            "ddtags": f"env:production,service:ghostprompt,threat_level:{event.get('threat_level', 'safe')}",
            "hostname": "ghostprompt",
            "message": json.dumps({
                "action": event.get("action"),
                "threat_level": event.get("threat_level"),
                "threat_score": event.get("threat_score"),
                "model": event.get("model_name"),
                "provider": event.get("model_provider"),
                "detections": event.get("detections", []),
                "is_blocked": event.get("is_blocked"),
                "request_id": event.get("request_id"),
            }),
            "service": "ghostprompt-ai-firewall",
            "status": "error" if event.get("is_blocked") else "info",
        }
        resp = await client.post(
            settings.SIEM_WEBHOOK_URL,
            headers={
                "DD-API-KEY": settings.SIEM_WEBHOOK_SECRET,
                "Content-Type": "application/json",
            },
            json=[log_entry],
        )
        return resp.status_code in (200, 202)

    async def _push_qradar(self, event: dict) -> bool:
        """Push to IBM QRadar SIEM via Log Source."""
        client = await self._get_client()
        # QRadar expects syslog-style messages
        syslog_msg = json.dumps({
            "source": "GhostPrompt",
            "category": "AI Security",
            "severity": self._map_severity_qradar(event.get("threat_level", "safe")),
            "event_name": f"AI Firewall: {event.get('action', 'scan')}",
            "source_ip": event.get("source_ip", "0.0.0.0"),
            "threat_score": event.get("threat_score", 0),
            "detections": event.get("detections", []),
            "model": event.get("model_name"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        resp = await client.post(
            settings.SIEM_WEBHOOK_URL,
            headers={
                "SEC": settings.SIEM_WEBHOOK_SECRET,
                "Content-Type": "application/json",
            },
            content=syslog_msg,
        )
        return resp.status_code in (200, 202)

    async def _push_generic(self, event: dict) -> bool:
        """Push to any generic webhook endpoint."""
        client = await self._get_client()
        payload = {
            "source": "ghostprompt",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "ai_security_scan",
            "data": {
                "request_id": event.get("request_id"),
                "action": event.get("action"),
                "threat_level": event.get("threat_level"),
                "threat_score": event.get("threat_score"),
                "model_provider": event.get("model_provider"),
                "model_name": event.get("model_name"),
                "scan_type": event.get("scan_type"),
                "is_blocked": event.get("is_blocked"),
                "detections": event.get("detections", []),
                "threat_categories": event.get("threat_categories", []),
                "source_ip": event.get("source_ip"),
                "scan_duration_ms": event.get("scan_duration_ms"),
            },
        }

        headers = {"Content-Type": "application/json"}
        if settings.SIEM_WEBHOOK_SECRET:
            # Add HMAC signature for webhook verification
            body = json.dumps(payload).encode()
            sig = hmac.new(settings.SIEM_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
            headers["X-GhostPrompt-Signature"] = f"sha256={sig}"

        resp = await client.post(settings.SIEM_WEBHOOK_URL, headers=headers, json=payload)
        return resp.status_code in (200, 201, 202, 204)

    @staticmethod
    def _map_severity_qradar(threat_level: str) -> int:
        return {"safe": 1, "low": 3, "medium": 5, "high": 7, "critical": 10}.get(threat_level, 1)


# Singleton
siem_integration = SIEMIntegration()


async def push_to_connector(provider: str, event: dict, config: dict) -> dict:
    """
    Push an event via a specific connector from the new registry.
    Used by the per-org multi-connector system.
    Returns a dict with status, latency_ms, details.
    """
    connector = get_connector(provider)
    if not connector:
        # Fall back to the legacy monolithic push for old providers
        return {"provider": provider, "status": "unsupported", "details": f"No connector found for '{provider}'"}

    result = await connector.safe_push(event, config)
    return {
        "provider": result.provider,
        "status": result.status,
        "latency_ms": result.latency_ms,
        "details": result.details,
        "event_id": result.event_id,
        "timestamp": result.timestamp,
    }


async def push_to_all_configured(integrations: list[dict], event: dict) -> list[dict]:
    """
    Push an event to every configured integration for an org.
    `integrations` is the org's settings.integrations list.
    Returns a list of result dicts. Updates last_successful_delivery on success.
    """
    results = []
    for integration in integrations:
        if not integration.get("enabled", True):
            continue
        provider = integration.get("provider", "")
        result = await push_to_connector(provider, event, integration)
        results.append(result)
        # Track last_successful_delivery per connector
        if result.get("status") == "delivered":
            integration["last_successful_delivery"] = datetime.now(timezone.utc).isoformat()
            integration["total_events_delivered"] = integration.get("total_events_delivered", 0) + 1
    return results

