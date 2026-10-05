"""
Microsoft Teams Connector — Power Automate Workflows Adaptive Card

Sends alerts via Power Automate Workflows webhook (Teams deprecated
the legacy Office 365 Connector path — this uses the current
Workflows-based incoming webhook with Adaptive Card payloads).
https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/
"""

from datetime import datetime, timezone

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class TeamsConnector(ConnectorInterface):
    name = "teams"
    display_name = "Microsoft Teams"
    supports_bidirectional = False
    credential_fields = [
        {"field": "webhook_url", "label": "Power Automate Workflow Webhook URL", "type": "secret", "placeholder": "https://prod-XX.westus.logic.azure.com:443/workflows/..."},
    ]

    SEVERITY_COLOR = {
        "safe": "Good", "low": "Accent", "medium": "Warning", "high": "Attention", "critical": "Attention",
    }

    def _build_adaptive_card(self, event: dict) -> dict:
        threat_level = event.get("threat_level", "safe")
        score = event.get("threat_score", 0)
        categories = ", ".join(event.get("threat_categories", [])[:5]) or "none"
        blocked = "🚫 BLOCKED" if event.get("is_blocked") else "✅ Allowed"
        color = self.SEVERITY_COLOR.get(threat_level, "Default")

        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.5",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": f"🛡️ GhostPrompt — {threat_level.upper()} Alert",
                                "weight": "Bolder",
                                "size": "Large",
                                "color": color,
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Threat Level", "value": threat_level.upper()},
                                    {"title": "Score", "value": f"{score:.2f}"},
                                    {"title": "Action", "value": event.get("action", "scan")},
                                    {"title": "Model", "value": f"{event.get('model_provider', '')}/{event.get('model_name', '')}"},
                                    {"title": "Source IP", "value": event.get("source_ip", "N/A")},
                                    {"title": "Status", "value": blocked},
                                    {"title": "Categories", "value": categories},
                                    {"title": "Duration", "value": f"{event.get('scan_duration_ms', 0)}ms"},
                                ],
                            },
                            {
                                "type": "TextBlock",
                                "text": f"Request ID: `{event.get('request_id', 'N/A')}`",
                                "isSubtle": True,
                                "size": "Small",
                            },
                        ],
                        "actions": [
                            {
                                "type": "Action.OpenUrl",
                                "title": "View in GhostPrompt",
                                "url": f"https://app.ghostprompt.io/incidents/{event.get('request_id', '')}",
                            },
                        ],
                    },
                }
            ],
        }

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            return ConnectorResult(status="error", details="No webhook_url configured")

        card = self._build_adaptive_card(event)

        async with self._get_client() as client:
            resp = await client.post(
                webhook_url,
                headers={"Content-Type": "application/json"},
                json=card,
            )
            if resp.status_code in (200, 202):
                return ConnectorResult(status="connected", details="Adaptive Card delivered to Teams channel")
            elif resp.status_code == 400:
                return ConnectorResult(status="error", details=f"Bad request — check webhook URL format: {resp.text[:200]}")
            elif resp.status_code in (401, 403):
                return ConnectorResult(status="auth_failed", details="Webhook URL expired or invalid")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            return ConnectorResult(status="error", details="No webhook_url configured")

        test_card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.5",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": "🔗 GhostPrompt Connection Test",
                                "weight": "Bolder",
                                "size": "Medium",
                            },
                            {
                                "type": "TextBlock",
                                "text": "If you see this card, your Microsoft Teams webhook is working correctly!",
                                "wrap": True,
                            },
                            {
                                "type": "TextBlock",
                                "text": f"Tested at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                "isSubtle": True,
                                "size": "Small",
                            },
                        ],
                    },
                }
            ],
        }

        async with self._get_client() as client:
            resp = await client.post(
                webhook_url,
                headers={"Content-Type": "application/json"},
                json=test_card,
            )
            if resp.status_code in (200, 202):
                return ConnectorResult(status="connected", details="Webhook valid — test card sent to Teams channel")
            elif resp.status_code in (401, 403, 404):
                return ConnectorResult(status="auth_failed", details="Webhook URL invalid, expired, or revoked")
            else:
                return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")
