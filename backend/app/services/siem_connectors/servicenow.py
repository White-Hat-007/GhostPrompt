"""
ServiceNow Connector — Table API

Creates incident records via the ServiceNow Table API.
Supports bi-directional sync via Business Rule webhooks.
https://developer.servicenow.com/dev.do#!/reference/api/tokyo/rest/c_TableAPI
"""

import base64
from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class ServiceNowConnector(ConnectorInterface):
    name = "servicenow"
    display_name = "ServiceNow"
    supports_bidirectional = True
    credential_fields = [
        {"field": "instance_url", "label": "Instance URL", "type": "url", "placeholder": "https://your-instance.service-now.com"},
        {"field": "username", "label": "Username", "type": "text", "placeholder": "admin"},
        {"field": "password", "label": "Password", "type": "secret", "placeholder": "ServiceNow password"},
        {"field": "assignment_group", "label": "Assignment Group (optional)", "type": "text", "placeholder": "IT Security"},
    ]

    URGENCY_MAP = {"safe": 3, "low": 3, "medium": 2, "high": 1, "critical": 1}
    IMPACT_MAP = {"safe": 3, "low": 3, "medium": 2, "high": 1, "critical": 1}

    def _auth_header(self, config: dict) -> dict:
        username = config.get("username", "")
        password = config.get("password", "")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {token}", "Content-Type": "application/json", "Accept": "application/json"}

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        instance_url = config.get("instance_url", "").rstrip("/")
        if not instance_url:
            return ConnectorResult(status="error", details="No instance_url configured")

        threat_level = event.get("threat_level", "safe")
        score = event.get("threat_score", 0)
        categories = ", ".join(event.get("threat_categories", [])[:5]) or "none"

        incident = {
            "short_description": f"[GhostPrompt] {threat_level.upper()} AI Security Alert — Score: {score:.2f}",
            "description": (
                f"GhostPrompt AI Firewall Detection\n\n"
                f"Action: {event.get('action', 'scan')}\n"
                f"Threat Level: {threat_level}\n"
                f"Threat Score: {score:.2f}\n"
                f"Model: {event.get('model_provider', '')}/{event.get('model_name', '')}\n"
                f"Source IP: {event.get('source_ip', 'N/A')}\n"
                f"Blocked: {event.get('is_blocked', False)}\n"
                f"Categories: {categories}\n"
                f"Request ID: {event.get('request_id', 'N/A')}\n"
                f"Scan Duration: {event.get('scan_duration_ms', 0)}ms"
            ),
            "urgency": str(self.URGENCY_MAP.get(threat_level, 3)),
            "impact": str(self.IMPACT_MAP.get(threat_level, 3)),
            "category": "AI Security",
            "subcategory": "Prompt Injection" if "prompt_injection" in categories else "Security Alert",
            "caller_id": config.get("username", "admin"),
            "correlation_id": f"ghostprompt-{event.get('request_id', '')}",
        }

        assignment_group = config.get("assignment_group")
        if assignment_group:
            incident["assignment_group"] = assignment_group

        async with self._get_client() as client:
            resp = await client.post(
                f"{instance_url}/api/now/table/incident",
                headers=self._auth_header(config),
                json=incident,
            )
            if resp.status_code == 201:
                data = resp.json()
                result = data.get("result", {})
                return ConnectorResult(
                    status="connected",
                    details=f"Incident {result.get('number', 'N/A')} created",
                    event_id=result.get("sys_id"),
                )
            elif resp.status_code == 401:
                return ConnectorResult(status="auth_failed", details="Invalid credentials")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        instance_url = config.get("instance_url", "").rstrip("/")
        if not instance_url:
            return ConnectorResult(status="error", details="No instance_url configured")

        async with self._get_client() as client:
            # Query the sys_user table to verify credentials
            resp = await client.get(
                f"{instance_url}/api/now/table/sys_user?sysparm_limit=1",
                headers=self._auth_header(config),
            )
            if resp.status_code == 200:
                return ConnectorResult(status="connected", details=f"Authenticated to {instance_url.split('.')[0].split('//')[-1]}")
            elif resp.status_code == 401:
                return ConnectorResult(status="auth_failed", details="Invalid username or password")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")
