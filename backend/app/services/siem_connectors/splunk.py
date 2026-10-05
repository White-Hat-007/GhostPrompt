"""
Splunk Connector — HTTP Event Collector (HEC)

Sends events to Splunk via HTTP Event Collector.
https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
"""

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class SplunkConnector(ConnectorInterface):
    name = "splunk"
    display_name = "Splunk"
    supports_bidirectional = False
    credential_fields = [
        {"field": "endpoint", "label": "HEC Endpoint URL", "type": "url", "placeholder": "https://splunk.company.com:8088"},
        {"field": "token", "label": "HEC Token", "type": "secret", "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
        {"field": "index", "label": "Index (optional)", "type": "text", "placeholder": "ghostprompt_security"},
        {"field": "source", "label": "Source (optional)", "type": "text", "placeholder": "ghostprompt"},
    ]

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        endpoint = config.get("endpoint", "").rstrip("/")
        token = config.get("token", "")
        index = config.get("index", "main")
        source = config.get("source", "ghostprompt")

        if not endpoint or not token:
            return ConnectorResult(status="error", details="Missing HEC endpoint or token")

        base = self._base_payload(event)
        hec_payload = {
            "event": {
                **base,
                "summary": f"[GhostPrompt] {base['threat_level'].upper()} — score {base['threat_score']:.2f}",
            },
            "sourcetype": "_json",
            "source": source,
            "index": index,
        }

        async with self._get_client() as client:
            resp = await client.post(
                f"{endpoint}/services/collector/event",
                headers={
                    "Authorization": f"Splunk {token}",
                    "Content-Type": "application/json",
                },
                json=hec_payload,
            )
            data = resp.json()
            if resp.status_code == 200 and data.get("text") == "Success":
                return ConnectorResult(status="connected", details="Event ingested via HEC", event_id=str(data.get("ackId", "")))
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details=f"HEC auth failed: {data.get('text', 'invalid token')}")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {data.get('text', resp.text[:200])}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        endpoint = config.get("endpoint", "").rstrip("/")
        token = config.get("token", "")

        if not endpoint or not token:
            return ConnectorResult(status="error", details="Missing HEC endpoint or token")

        # Splunk HEC health check
        async with self._get_client() as client:
            resp = await client.get(
                f"{endpoint}/services/collector/health/1.0",
                headers={"Authorization": f"Splunk {token}"},
            )
            if resp.status_code == 200:
                return ConnectorResult(status="connected", details="HEC endpoint healthy and token valid")
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="HEC token invalid or disabled")
            else:
                return ConnectorResult(status="error", details=f"HEC health check returned HTTP {resp.status_code}")
