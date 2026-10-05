"""
Google Chronicle Connector — Ingestion API (Unstructured Logs / UDM)

Sends events to Google Chronicle SIEM via the Ingestion API.
https://cloud.google.com/chronicle/docs/reference/ingestion-api
"""

import json
from datetime import datetime, timezone
from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class GoogleChronicleConnector(ConnectorInterface):
    name = "google_chronicle"
    display_name = "Google Chronicle"
    supports_bidirectional = False
    credential_fields = [
        {"field": "endpoint", "label": "Chronicle API Endpoint", "type": "url", "placeholder": "https://malachiteingestion-pa.googleapis.com"},
        {"field": "api_key", "label": "API Key", "type": "secret", "placeholder": "Chronicle API key"},
        {"field": "customer_id", "label": "Customer ID", "type": "text", "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
        {"field": "log_type", "label": "Log Type", "type": "text", "placeholder": "GHOSTPROMPT"},
    ]

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        endpoint = config.get("endpoint", "https://malachiteingestion-pa.googleapis.com").rstrip("/")
        api_key = config.get("api_key", "")
        customer_id = config.get("customer_id", "")
        log_type = config.get("log_type", "GHOSTPROMPT")

        if not api_key or not customer_id:
            return ConnectorResult(status="error", details="Missing API key or Customer ID")

        base = self._base_payload(event)
        categories = ", ".join(event.get("threat_categories", [])[:5]) or "none"

        # Chronicle unstructured log entry
        log_entry = json.dumps({
            **base,
            "categories": categories,
            "summary": f"[GhostPrompt] {base['threat_level'].upper()} — {base['action']}",
        })

        payload = {
            "customer_id": customer_id,
            "log_type": log_type,
            "entries": [
                {
                    "log_text": log_entry,
                    "ts_epoch_microseconds": int(datetime.now(timezone.utc).timestamp() * 1_000_000),
                }
            ],
        }

        async with self._get_client() as client:
            resp = await client.post(
                f"{endpoint}/v2/unstructuredlogentries:batchCreate",
                headers={
                    "X-goog-api-key": api_key,
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if resp.status_code in (200, 202):
                return ConnectorResult(status="connected", details=f"Log ingested as {log_type}")
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="Invalid API key or Customer ID")
            elif resp.status_code == 429:
                return ConnectorResult(status="error", details="Chronicle rate limit exceeded — try again later")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        """Test by sending a lightweight heartbeat log entry."""
        endpoint = config.get("endpoint", "https://malachiteingestion-pa.googleapis.com").rstrip("/")
        api_key = config.get("api_key", "")
        customer_id = config.get("customer_id", "")

        if not api_key or not customer_id:
            return ConnectorResult(status="error", details="Missing API key or Customer ID")

        test_payload = {
            "customer_id": customer_id,
            "log_type": "GHOSTPROMPT_TEST",
            "entries": [
                {
                    "log_text": json.dumps({"source": "ghostprompt", "test": True, "message": "Connection test"}),
                    "ts_epoch_microseconds": int(datetime.now(timezone.utc).timestamp() * 1_000_000),
                }
            ],
        }

        async with self._get_client() as client:
            resp = await client.post(
                f"{endpoint}/v2/unstructuredlogentries:batchCreate",
                headers={
                    "X-goog-api-key": api_key,
                    "Content-Type": "application/json",
                },
                json=test_payload,
            )
            if resp.status_code in (200, 202):
                return ConnectorResult(status="connected", details=f"Chronicle ingestion API reachable — customer {customer_id[:8]}...")
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="Invalid API key or Customer ID")
            else:
                return ConnectorResult(status="error", details=f"Ingestion test returned HTTP {resp.status_code}")
