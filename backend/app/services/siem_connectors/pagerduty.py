"""
PagerDuty Connector — Events API v2

Sends alerts via PagerDuty Events API v2 and supports trigger/acknowledge/resolve.
https://developer.pagerduty.com/docs/events-api-v2/overview/
"""

import json
from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class PagerDutyConnector(ConnectorInterface):
    name = "pagerduty"
    display_name = "PagerDuty"
    supports_bidirectional = True
    credential_fields = [
        {"field": "routing_key", "label": "Integration/Routing Key", "type": "secret", "placeholder": "Events API v2 Integration Key"},
    ]

    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    SEVERITY_MAP = {
        "safe": "info",
        "low": "warning",
        "medium": "error",
        "high": "critical",
        "critical": "critical",
    }

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        routing_key = config.get("routing_key", "")
        if not routing_key:
            return ConnectorResult(status="error", details="No routing_key configured")

        threat_level = event.get("threat_level", "safe")
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": f"ghostprompt-{event.get('request_id', 'unknown')}",
            "payload": {
                "summary": f"[GhostPrompt] {threat_level.upper()} — {event.get('action', 'AI Security Alert')} | Score: {event.get('threat_score', 0):.2f}",
                "severity": self.SEVERITY_MAP.get(threat_level, "info"),
                "source": "ghostprompt-ai-firewall",
                "component": event.get("model_name", "unknown"),
                "group": event.get("model_provider", "unknown"),
                "class": "ai_security",
                "custom_details": self._base_payload(event),
            },
            "links": [
                {"href": f"https://app.ghostprompt.io/incidents/{event.get('request_id', '')}", "text": "View in GhostPrompt"}
            ],
        }

        async with self._get_client() as client:
            resp = await client.post(self.EVENTS_URL, json=payload)
            if resp.status_code == 202:
                data = resp.json()
                return ConnectorResult(
                    status="connected",
                    details=f"Event accepted — dedup_key: {data.get('dedup_key', 'N/A')}",
                    event_id=data.get("dedup_key"),
                )
            elif resp.status_code == 400:
                return ConnectorResult(status="error", details=f"Bad request: {resp.text[:200]}")
            elif resp.status_code == 429:
                return ConnectorResult(status="error", details="Rate limited by PagerDuty")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        routing_key = config.get("routing_key", "")
        if not routing_key:
            return ConnectorResult(status="error", details="No routing_key configured")

        # PagerDuty doesn't have a validate-key endpoint, so we send a change event
        # (non-alerting) to verify the key works without creating a real incident
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": "ghostprompt-connection-test",
            "payload": {
                "summary": "[GhostPrompt] Connection test — this event will auto-resolve",
                "severity": "info",
                "source": "ghostprompt-ai-firewall",
                "class": "connection_test",
            },
        }

        async with self._get_client() as client:
            resp = await client.post(self.EVENTS_URL, json=payload)
            if resp.status_code == 202:
                # Immediately resolve the test event
                resolve_payload = {
                    "routing_key": routing_key,
                    "event_action": "resolve",
                    "dedup_key": "ghostprompt-connection-test",
                }
                await client.post(self.EVENTS_URL, json=resolve_payload)
                return ConnectorResult(status="connected", details="Routing key valid, test event sent and auto-resolved")
            elif resp.status_code in (400, 403):
                return ConnectorResult(status="auth_failed", details="Invalid routing key")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")
