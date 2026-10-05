"""
Opsgenie Connector — Alert API

Creates alerts via Opsgenie Alert API v2. GenieKey auth.
https://docs.opsgenie.com/docs/alert-api
"""

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class OpsgenieConnector(ConnectorInterface):
    name = "opsgenie"
    display_name = "Opsgenie"
    supports_bidirectional = True
    credential_fields = [
        {"field": "api_key", "label": "GenieKey (API Key)", "type": "secret", "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
        {"field": "api_url", "label": "API URL (optional, for EU)", "type": "url", "placeholder": "https://api.opsgenie.com (or https://api.eu.opsgenie.com)"},
        {"field": "responders_team", "label": "Responder Team (optional)", "type": "text", "placeholder": "security-team"},
    ]

    PRIORITY_MAP = {"safe": "P5", "low": "P4", "medium": "P3", "high": "P2", "critical": "P1"}

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        api_key = config.get("api_key", "")
        if not api_key:
            return ConnectorResult(status="error", details="No api_key (GenieKey) configured")

        base_url = (config.get("api_url", "") or "https://api.opsgenie.com").rstrip("/")
        threat_level = event.get("threat_level", "safe")
        score = event.get("threat_score", 0)
        categories = ", ".join(event.get("threat_categories", [])[:5]) or "none"

        alert = {
            "message": f"[GhostPrompt] {threat_level.upper()} — AI Security Alert (Score: {score:.2f})",
            "alias": f"ghostprompt-{event.get('request_id', 'unknown')}",
            "description": (
                f"Action: {event.get('action', 'scan')}\n"
                f"Model: {event.get('model_provider', '')}/{event.get('model_name', '')}\n"
                f"Source IP: {event.get('source_ip', 'N/A')}\n"
                f"Blocked: {event.get('is_blocked', False)}\n"
                f"Categories: {categories}"
            ),
            "priority": self.PRIORITY_MAP.get(threat_level, "P3"),
            "source": "GhostPrompt AI Firewall",
            "tags": ["ghostprompt", "ai-security", f"severity-{threat_level}"],
            "details": {
                "request_id": event.get("request_id", ""),
                "threat_score": str(score),
                "model": event.get("model_name", ""),
                "provider": event.get("model_provider", ""),
                "scan_duration_ms": str(event.get("scan_duration_ms", 0)),
            },
            "entity": event.get("model_name", "unknown"),
        }

        responders_team = config.get("responders_team")
        if responders_team:
            alert["responders"] = [{"name": responders_team, "type": "team"}]

        async with self._get_client() as client:
            resp = await client.post(
                f"{base_url}/v2/alerts",
                headers={"Authorization": f"GenieKey {api_key}", "Content-Type": "application/json"},
                json=alert,
            )
            if resp.status_code == 202:
                data = resp.json()
                return ConnectorResult(
                    status="connected",
                    details=f"Alert created — request: {data.get('requestId', 'N/A')}",
                    event_id=data.get("requestId"),
                )
            elif resp.status_code == 401:
                return ConnectorResult(status="auth_failed", details="Invalid GenieKey")
            elif resp.status_code == 422:
                return ConnectorResult(status="error", details=f"Validation error: {resp.text[:200]}")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        api_key = config.get("api_key", "")
        if not api_key:
            return ConnectorResult(status="error", details="No api_key (GenieKey) configured")

        base_url = (config.get("api_url", "") or "https://api.opsgenie.com").rstrip("/")

        async with self._get_client() as client:
            # Use the Account API to validate the key
            resp = await client.get(
                f"{base_url}/v2/account",
                headers={"Authorization": f"GenieKey {api_key}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                account = data.get("data", {})
                return ConnectorResult(status="connected", details=f"Account: {account.get('name', 'N/A')} ({account.get('plan', {}).get('name', 'N/A')} plan)")
            elif resp.status_code == 401:
                return ConnectorResult(status="auth_failed", details="Invalid GenieKey")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")
