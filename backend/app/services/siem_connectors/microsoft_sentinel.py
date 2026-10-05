"""
Microsoft Sentinel Connector — Log Analytics Data Collector API

Sends events to Microsoft Sentinel via the HTTP Data Collector API.
https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
"""

import base64
import hashlib
import hmac
from datetime import datetime, timezone

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class MicrosoftSentinelConnector(ConnectorInterface):
    name = "microsoft_sentinel"
    display_name = "Microsoft Sentinel"
    supports_bidirectional = False
    credential_fields = [
        {"field": "workspace_id", "label": "Log Analytics Workspace ID", "type": "text", "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
        {"field": "shared_key", "label": "Primary/Secondary Key", "type": "secret", "placeholder": "Base64-encoded shared key"},
        {"field": "log_type", "label": "Custom Log Type", "type": "text", "placeholder": "GhostPrompt_CL"},
    ]

    def _build_signature(self, workspace_id: str, shared_key: str, date: str, content_length: int) -> str:
        """Build the authorization signature for the Data Collector API."""
        method = "POST"
        content_type = "application/json"
        resource = "/api/logs"
        x_headers = f"x-ms-date:{date}"
        string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {workspace_id}:{encoded_hash}"

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        workspace_id = config.get("workspace_id", "")
        shared_key = config.get("shared_key", "")
        log_type = config.get("log_type", "GhostPrompt")

        if not workspace_id or not shared_key:
            return ConnectorResult(status="error", details="Missing workspace ID or shared key")

        base = self._base_payload(event)
        categories = ", ".join(event.get("threat_categories", [])[:5]) or "none"
        body = [{
            **base,
            "categories": categories,
            "summary": f"{base['threat_level'].upper()} — score {base['threat_score']:.2f}",
        }]

        import json
        body_str = json.dumps(body)
        rfc1123date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

        try:
            signature = self._build_signature(workspace_id, shared_key, rfc1123date, len(body_str))
        except Exception as e:
            return ConnectorResult(status="auth_failed", details=f"Signature build failed: {str(e)[:100]}")

        async with self._get_client() as client:
            resp = await client.post(
                f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
                headers={
                    "Authorization": signature,
                    "Content-Type": "application/json",
                    "Log-Type": log_type,
                    "x-ms-date": rfc1123date,
                    "time-generated-field": "timestamp",
                },
                content=body_str,
            )
            if resp.status_code in (200, 202):
                return ConnectorResult(status="connected", details=f"Event ingested into {log_type}_CL")
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="Invalid workspace ID or shared key")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        """Test by sending a lightweight heartbeat event."""
        workspace_id = config.get("workspace_id", "")
        shared_key = config.get("shared_key", "")
        log_type = config.get("log_type", "GhostPrompt")

        if not workspace_id or not shared_key:
            return ConnectorResult(status="error", details="Missing workspace ID or shared key")

        import json
        test_body = [{"source": "ghostprompt", "test": True, "message": "Connection test"}]
        body_str = json.dumps(test_body)
        rfc1123date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

        try:
            signature = self._build_signature(workspace_id, shared_key, rfc1123date, len(body_str))
        except Exception as e:
            return ConnectorResult(status="auth_failed", details=f"Shared key invalid: {str(e)[:100]}")

        async with self._get_client() as client:
            resp = await client.post(
                f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
                headers={
                    "Authorization": signature,
                    "Content-Type": "application/json",
                    "Log-Type": f"{log_type}_Test",
                    "x-ms-date": rfc1123date,
                },
                content=body_str,
            )
            if resp.status_code in (200, 202):
                return ConnectorResult(status="connected", details=f"Authenticated — workspace {workspace_id[:8]}...")
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="Invalid workspace ID or shared key")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")
