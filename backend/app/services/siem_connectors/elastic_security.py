"""
Elastic Security Connector — Elasticsearch Documents API

Sends events to Elastic Security / Elasticsearch via the Bulk/Index API.
https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
"""

from datetime import datetime, timezone

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class ElasticSecurityConnector(ConnectorInterface):
    name = "elastic_security"
    display_name = "Elastic Security"
    supports_bidirectional = False
    credential_fields = [
        {"field": "endpoint", "label": "Elasticsearch URL", "type": "url", "placeholder": "https://elasticsearch.company.com:9200"},
        {"field": "api_key", "label": "API Key (Base64 id:api_key)", "type": "secret", "placeholder": "Base64-encoded API key"},
        {"field": "index", "label": "Index Name", "type": "text", "placeholder": "ghostprompt-security"},
        {"field": "cloud_id", "label": "Cloud ID (Elastic Cloud only)", "type": "text", "placeholder": "deployment:region:hash"},
    ]

    SEVERITY_MAP = {
        "safe": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
    }

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        endpoint = config.get("endpoint", "").rstrip("/")
        api_key = config.get("api_key", "")
        index = config.get("index", "ghostprompt-security")

        if not endpoint or not api_key:
            return ConnectorResult(status="error", details="Missing Elasticsearch endpoint or API key")

        base = self._base_payload(event)
        categories = event.get("threat_categories", [])

        # ECS-compatible document
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event.kind": "alert",
            "event.category": ["intrusion_detection"],
            "event.severity": self.SEVERITY_MAP.get(base["threat_level"], 1),
            "event.action": base["action"],
            "event.module": "ghostprompt",
            "source.ip": base["source_ip"],
            "ghostprompt": {
                "request_id": base["request_id"],
                "threat_level": base["threat_level"],
                "threat_score": base["threat_score"],
                "model_provider": base["model_provider"],
                "model_name": base["model_name"],
                "is_blocked": base["is_blocked"],
                "categories": categories,
                "scan_duration_ms": base["scan_duration_ms"],
                "detections": base["detections"],
            },
            "message": f"[GhostPrompt] {base['threat_level'].upper()} — {base['action']} via {base['model_provider']}/{base['model_name']}",
        }

        async with self._get_client() as client:
            resp = await client.post(
                f"{endpoint}/{index}/_doc",
                headers={
                    "Authorization": f"ApiKey {api_key}",
                    "Content-Type": "application/json",
                },
                json=doc,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return ConnectorResult(status="connected", details=f"Indexed to {index}", event_id=data.get("_id", ""))
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="Invalid API key or insufficient permissions")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        endpoint = config.get("endpoint", "").rstrip("/")
        api_key = config.get("api_key", "")

        if not endpoint or not api_key:
            return ConnectorResult(status="error", details="Missing Elasticsearch endpoint or API key")

        # Cluster health check
        async with self._get_client() as client:
            resp = await client.get(
                f"{endpoint}/_cluster/health",
                headers={"Authorization": f"ApiKey {api_key}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                cluster = data.get("cluster_name", "unknown")
                status = data.get("status", "unknown")
                nodes = data.get("number_of_nodes", 0)
                return ConnectorResult(status="connected", details=f"Cluster '{cluster}' — {status} ({nodes} nodes)")
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="Invalid API key")
            else:
                return ConnectorResult(status="error", details=f"Health check returned HTTP {resp.status_code}")
