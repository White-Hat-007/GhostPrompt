"""
IBM QRadar Connector — Syslog/REST API

Sends events to IBM QRadar via the Log Sources REST API.
https://www.ibm.com/docs/en/qsip/7.5?topic=api-siem
"""

import json
from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class QRadarConnector(ConnectorInterface):
    name = "ibm_qradar"
    display_name = "IBM QRadar"
    supports_bidirectional = False
    credential_fields = [
        {"field": "endpoint", "label": "QRadar Console URL", "type": "url", "placeholder": "https://qradar.company.com"},
        {"field": "token", "label": "SEC Token", "type": "secret", "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
        {"field": "log_source_id", "label": "Log Source ID (optional)", "type": "text", "placeholder": "Auto-detect"},
    ]

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        endpoint = config.get("endpoint", "").rstrip("/")
        token = config.get("token", "")

        if not endpoint or not token:
            return ConnectorResult(status="error", details="Missing QRadar endpoint or SEC token")

        base = self._base_payload(event)
        categories = ", ".join(event.get("threat_categories", [])[:5]) or "none"

        # QRadar reference map data via REST
        siem_event = {
            "source": "ghostprompt",
            "log_source_type_id": 4001,  # Universal REST API
            "event_data": json.dumps({
                **base,
                "categories": categories,
                "summary": f"[GhostPrompt] {base['threat_level'].upper()} — {base['action']}",
            }),
        }

        async with self._get_client() as client:
            # Push via siem/offenses or custom reference data
            resp = await client.post(
                f"{endpoint}/api/data_ingestion/events",
                headers={
                    "SEC": token,
                    "Content-Type": "application/json",
                    "Version": "19.0",
                },
                json=[siem_event],
            )
            if resp.status_code in (200, 201, 202):
                return ConnectorResult(status="connected", details="Event ingested via QRadar Data Ingestion API")
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="Invalid SEC token")
            elif resp.status_code == 422:
                return ConnectorResult(status="error", details=f"QRadar rejected event format: {resp.text[:200]}")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        endpoint = config.get("endpoint", "").rstrip("/")
        token = config.get("token", "")

        if not endpoint or not token:
            return ConnectorResult(status="error", details="Missing QRadar endpoint or SEC token")

        # QRadar system info endpoint — tests auth + reachability
        async with self._get_client() as client:
            resp = await client.get(
                f"{endpoint}/api/system/about",
                headers={"SEC": token, "Version": "19.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                version = data.get("build_version", "unknown")
                return ConnectorResult(status="connected", details=f"QRadar {version} — authenticated")
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="SEC token invalid or insufficient permissions")
            else:
                return ConnectorResult(status="error", details=f"System check returned HTTP {resp.status_code}")
