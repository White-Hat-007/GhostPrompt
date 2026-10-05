"""
Slack Connector — Incoming Webhook + Block Kit

One-way alerts via Incoming Webhook (Block Kit JSON).
Full Slack App with Bot OAuth token for two-way (acknowledge/dismiss buttons).
https://api.slack.com/messaging/webhooks
"""

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class SlackConnector(ConnectorInterface):
    name = "slack"
    display_name = "Slack"
    supports_bidirectional = True
    credential_fields = [
        {"field": "webhook_url", "label": "Incoming Webhook URL", "type": "secret", "placeholder": "https://hooks.slack.com/services/T.../B.../..."},
        {"field": "bot_token", "label": "Bot OAuth Token (optional, for 2-way)", "type": "secret", "placeholder": "xoxb-..."},
        {"field": "channel", "label": "Channel (for Bot mode)", "type": "text", "placeholder": "#security-alerts"},
    ]

    SEVERITY_EMOJI = {
        "safe": "✅", "low": "🟡", "medium": "🟠", "high": "🔴", "critical": "🚨",
    }
    SEVERITY_COLOR = {
        "safe": "#22c55e", "low": "#eab308", "medium": "#f97316", "high": "#ef4444", "critical": "#dc2626",
    }

    def _build_blocks(self, event: dict) -> list:
        threat_level = event.get("threat_level", "safe")
        emoji = self.SEVERITY_EMOJI.get(threat_level, "❓")
        score = event.get("threat_score", 0)
        action = event.get("action", "scan")
        model = event.get("model_name", "unknown")
        provider = event.get("model_provider", "unknown")
        categories = ", ".join(event.get("threat_categories", [])[:5]) or "none"
        blocked = "🚫 BLOCKED" if event.get("is_blocked") else "✅ Allowed"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} GhostPrompt Alert — {threat_level.upper()}", "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Action:*\n`{action}`"},
                    {"type": "mrkdwn", "text": f"*Threat Score:*\n`{score:.2f}`"},
                    {"type": "mrkdwn", "text": f"*Model:*\n`{provider}/{model}`"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{blocked}"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Categories:* {categories}"}
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Request ID: `{event.get('request_id', 'N/A')}` | Source IP: `{event.get('source_ip', 'N/A')}`"}
                ]
            },
        ]

        # Add interactive buttons if using bot token (2-way mode)
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "🔍 View in GhostPrompt"},
                    "url": f"https://app.ghostprompt.io/incidents/{event.get('request_id', '')}",
                    "action_id": "view_incident",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ Acknowledge"},
                    "style": "primary",
                    "action_id": "acknowledge_incident",
                    "value": event.get("request_id", ""),
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "❌ Dismiss"},
                    "style": "danger",
                    "action_id": "dismiss_incident",
                    "value": event.get("request_id", ""),
                },
            ]
        })

        return blocks

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        webhook_url = config.get("webhook_url", "")
        bot_token = config.get("bot_token", "")
        channel = config.get("channel", "")

        blocks = self._build_blocks(event)
        threat_level = event.get("threat_level", "safe")
        fallback_text = f"[GhostPrompt] {threat_level.upper()} alert — score {event.get('threat_score', 0):.2f}"

        # Prefer Bot token + channel for full interactivity; fall back to webhook
        if bot_token and channel:
            async with self._get_client() as client:
                resp = await client.post(
                    "https://slack.com/api/chat.postMessage",
                    headers={"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"},
                    json={"channel": channel, "text": fallback_text, "blocks": blocks},
                )
                data = resp.json()
                if data.get("ok"):
                    return ConnectorResult(status="connected", details=f"Posted to {channel}", event_id=data.get("ts"))
                else:
                    return ConnectorResult(status="error", details=f"Slack API error: {data.get('error', 'unknown')}")

        elif webhook_url:
            payload = {
                "text": fallback_text,
                "blocks": blocks,
            }
            async with self._get_client() as client:
                resp = await client.post(webhook_url, json=payload)
                if resp.status_code == 200 and resp.text == "ok":
                    return ConnectorResult(status="connected", details="Message delivered via webhook")
                else:
                    return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")
        else:
            return ConnectorResult(status="error", details="No webhook_url or bot_token configured")

    async def test_connection(self, config: dict) -> ConnectorResult:
        webhook_url = config.get("webhook_url", "")
        bot_token = config.get("bot_token", "")

        if bot_token:
            async with self._get_client() as client:
                resp = await client.post(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {bot_token}"},
                )
                data = resp.json()
                if data.get("ok"):
                    return ConnectorResult(status="connected", details=f"Bot authenticated as @{data.get('user', 'unknown')} in team {data.get('team', 'unknown')}")
                else:
                    return ConnectorResult(status="auth_failed", details=f"Slack auth error: {data.get('error', 'invalid_auth')}")

        elif webhook_url:
            test_payload = {
                "text": "🔗 GhostPrompt connection test — if you see this, your Slack webhook is working!",
            }
            async with self._get_client() as client:
                resp = await client.post(webhook_url, json=test_payload)
                if resp.status_code == 200:
                    return ConnectorResult(status="connected", details="Webhook URL valid, test message sent")
                elif resp.status_code in (403, 404):
                    return ConnectorResult(status="auth_failed", details="Webhook URL invalid or revoked")
                else:
                    return ConnectorResult(status="error", details=f"HTTP {resp.status_code}: {resp.text[:200]}")
        else:
            return ConnectorResult(status="error", details="No webhook_url or bot_token configured")
