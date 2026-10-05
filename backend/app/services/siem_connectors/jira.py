"""
Jira Connector — REST API v3

Creates issues via Jira Cloud REST API v3. API-token + email Basic Auth.
Supports bi-directional sync via Jira webhooks.
https://developer.atlassian.com/cloud/jira/platform/rest/v3/
"""

import base64

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class JiraConnector(ConnectorInterface):
    name = "jira"
    display_name = "Jira"
    supports_bidirectional = True
    credential_fields = [
        {"field": "instance_url", "label": "Jira Cloud URL", "type": "url", "placeholder": "https://your-org.atlassian.net"},
        {"field": "email", "label": "Email", "type": "text", "placeholder": "you@company.com"},
        {"field": "api_token", "label": "API Token", "type": "secret", "placeholder": "Jira API Token"},
        {"field": "project_key", "label": "Project Key", "type": "text", "placeholder": "SEC"},
        {"field": "issue_type", "label": "Issue Type", "type": "text", "placeholder": "Bug"},
    ]

    PRIORITY_MAP = {"safe": "Lowest", "low": "Low", "medium": "Medium", "high": "High", "critical": "Highest"}

    def _auth_header(self, config: dict) -> dict:
        email = config.get("email", "")
        api_token = config.get("api_token", "")
        token = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        return {"Authorization": f"Basic {token}", "Content-Type": "application/json", "Accept": "application/json"}

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        instance_url = config.get("instance_url", "").rstrip("/")
        project_key = config.get("project_key", "SEC")
        issue_type = config.get("issue_type", "Bug")
        if not instance_url:
            return ConnectorResult(status="error", details="No instance_url configured")

        threat_level = event.get("threat_level", "safe")
        score = event.get("threat_score", 0)
        categories = ", ".join(event.get("threat_categories", [])[:5]) or "none"

        issue = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[GhostPrompt] {threat_level.upper()} — AI Security Alert (Score: {score:.2f})",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "heading",
                            "attrs": {"level": 3},
                            "content": [{"type": "text", "text": "GhostPrompt AI Firewall Detection"}]
                        },
                        {
                            "type": "table",
                            "content": [
                                {"type": "tableRow", "content": [
                                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Field"}]}]},
                                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Value"}]}]},
                                ]},
                                *[{"type": "tableRow", "content": [
                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": k}]}]},
                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": str(v)}]}]},
                                ]} for k, v in [
                                    ("Threat Level", threat_level.upper()),
                                    ("Score", f"{score:.2f}"),
                                    ("Action", event.get("action", "scan")),
                                    ("Model", f"{event.get('model_provider', '')}/{event.get('model_name', '')}"),
                                    ("Source IP", event.get("source_ip", "N/A")),
                                    ("Blocked", str(event.get("is_blocked", False))),
                                    ("Categories", categories),
                                    ("Request ID", event.get("request_id", "N/A")),
                                ]],
                            ]
                        },
                    ]
                },
                "issuetype": {"name": issue_type},
                "priority": {"name": self.PRIORITY_MAP.get(threat_level, "Medium")},
                "labels": ["ghostprompt", "ai-security", f"severity-{threat_level}"],
            }
        }

        async with self._get_client() as client:
            resp = await client.post(
                f"{instance_url}/rest/api/3/issue",
                headers=self._auth_header(config),
                json=issue,
            )
            if resp.status_code == 201:
                data = resp.json()
                return ConnectorResult(
                    status="connected",
                    details=f"Issue {data.get('key', 'N/A')} created",
                    event_id=data.get("id"),
                )
            elif resp.status_code == 401:
                return ConnectorResult(status="auth_failed", details="Invalid email or API token")
            elif resp.status_code == 404:
                return ConnectorResult(status="error", details=f"Project '{project_key}' not found")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:300]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        instance_url = config.get("instance_url", "").rstrip("/")
        if not instance_url:
            return ConnectorResult(status="error", details="No instance_url configured")

        async with self._get_client() as client:
            resp = await client.get(
                f"{instance_url}/rest/api/3/myself",
                headers=self._auth_header(config),
            )
            if resp.status_code == 200:
                data = resp.json()
                return ConnectorResult(
                    status="connected",
                    details=f"Authenticated as {data.get('displayName', data.get('emailAddress', 'unknown'))}"
                )
            elif resp.status_code == 401:
                return ConnectorResult(status="auth_failed", details="Invalid email or API token")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")
