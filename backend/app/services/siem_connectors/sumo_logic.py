"""
Sumo Logic Connector — HTTP Source

Sends events via Sumo Logic HTTP Source collector URL.
https://help.sumologic.com/docs/send-data/hosted-collectors/http-source/
"""

import json
from datetime import datetime, timezone

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class SumoLogicConnector(ConnectorInterface):
    name = "sumo_logic"
    display_name = "Sumo Logic"
    supports_bidirectional = False
    credential_fields = [
        {"field": "collector_url", "label": "HTTP Source Collector URL", "type": "secret", "placeholder": "https://endpoint1.collection.us2.sumologic.com/receiver/v1/http/..."},
        {"field": "source_category", "label": "Source Category (optional)", "type": "text", "placeholder": "ghostprompt/security"},
    ]

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        collector_url = config.get("collector_url", "")
        if not collector_url:
            return ConnectorResult(status="error", details="No collector_url configured")

        source_category = config.get("source_category", "ghostprompt/security")

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "ghostprompt-ai-firewall",
            **self._base_payload(event),
        }

        headers = {
            "Content-Type": "application/json",
            "X-Sumo-Category": source_category,
            "X-Sumo-Name": "ghostprompt",
            "X-Sumo-Host": "ghostprompt-firewall",
        }

        async with self._get_client() as client:
            resp = await client.post(collector_url, headers=headers, content=json.dumps(log_entry))
            if resp.status_code == 200:
                return ConnectorResult(status="connected", details="Log accepted by Sumo Logic collector")
            elif resp.status_code == 401:
                return ConnectorResult(status="auth_failed", details="Invalid collector URL")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        collector_url = config.get("collector_url", "")
        if not collector_url:
            return ConnectorResult(status="error", details="No collector_url configured")

        test_log = json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "ghostprompt",
            "event_type": "connection_test",
            "message": "GhostPrompt Sumo Logic integration test",
        })

        headers = {
            "Content-Type": "application/json",
            "X-Sumo-Category": config.get("source_category", "ghostprompt/test"),
            "X-Sumo-Name": "ghostprompt-test",
        }

        async with self._get_client() as client:
            resp = await client.post(collector_url, headers=headers, content=test_log)
            if resp.status_code == 200:
                return ConnectorResult(status="connected", details="Collector URL valid, test log accepted")
            elif resp.status_code in (401, 403, 404):
                return ConnectorResult(status="auth_failed", details="Invalid or expired collector URL")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")
