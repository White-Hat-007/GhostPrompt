"""
Datadog Connector — Events API v2

Sends events to Datadog via the Events API.
https://docs.datadoghq.com/api/latest/events/
"""

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class DatadogConnector(ConnectorInterface):
    name = "datadog"
    display_name = "Datadog"
    supports_bidirectional = False
    credential_fields = [
        {"field": "api_key", "label": "API Key", "type": "secret", "placeholder": "ddxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
        {"field": "site", "label": "Datadog Site", "type": "text", "placeholder": "datadoghq.com"},
    ]

    SEVERITY_MAP = {
        "safe": "info", "low": "low", "medium": "normal", "high": "warning", "critical": "error",
    }

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        api_key = config.get("api_key", "")
        site = config.get("site", "datadoghq.com")

        if not api_key:
            return ConnectorResult(status="error", details="Missing Datadog API key")

        base = self._base_payload(event)
        threat_level = base["threat_level"]
        categories = ", ".join(event.get("threat_categories", [])[:5]) or "none"

        dd_event = {
            "title": f"[GhostPrompt] {threat_level.upper()} — score {base['threat_score']:.2f}",
            "text": (
                f"**Action:** {base['action']}\\n"
                f"**Model:** {base['model_provider']}/{base['model_name']}\\n"
                f"**Blocked:** {base['is_blocked']}\\n"
                f"**Categories:** {categories}\\n"
                f"**Source IP:** {base['source_ip']}\\n"
                f"**Request ID:** {base['request_id']}"
            ),
            "alert_type": self.SEVERITY_MAP.get(threat_level, "info"),
            "source_type_name": "ghostprompt",
            "tags": [
                f"threat_level:{threat_level}",
                f"action:{base['action']}",
                f"provider:{base['model_provider']}",
                f"blocked:{base['is_blocked']}",
            ],
        }

        async with self._get_client() as client:
            resp = await client.post(
                f"https://api.{site}/api/v1/events",
                headers={
                    "DD-API-KEY": api_key,
                    "Content-Type": "application/json",
                },
                json=dd_event,
            )
            if resp.status_code in (200, 202):
                data = resp.json()
                return ConnectorResult(status="connected", details="Event created", event_id=str(data.get("event", {}).get("id", "")))
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="Invalid Datadog API key")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        api_key = config.get("api_key", "")
        site = config.get("site", "datadoghq.com")

        if not api_key:
            return ConnectorResult(status="error", details="Missing Datadog API key")

        # Validate API key
        async with self._get_client() as client:
            resp = await client.get(
                f"https://api.{site}/api/v1/validate",
                headers={"DD-API-KEY": api_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    return ConnectorResult(status="connected", details="API key valid")
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="Invalid API key")
            return ConnectorResult(status="error", details=f"Validation returned HTTP {resp.status_code}")
