"""
ConnectorInterface — Documented Plugin Base Class

Enterprise tenants can subclass ConnectorInterface to build custom
SIEM/SOAR/ticketing connectors without waiting on a GhostPrompt release.

Usage:
    from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult

    class MyCustomConnector(ConnectorInterface):
        name = "my_platform"
        display_name = "My Platform"
        credential_fields = [
            {"field": "endpoint", "label": "API Endpoint", "type": "url"},
            {"field": "api_key", "label": "API Key", "type": "secret"},
        ]

        async def push_event(self, event: dict, config: dict) -> ConnectorResult:
            # Your push logic here
            ...

        async def test_connection(self, config: dict) -> ConnectorResult:
            # Your test logic here
            ...
"""

import time
from typing import Optional
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import httpx

from app.core.logging import get_logger

logger = get_logger("siem.connector")


@dataclass
class ConnectorResult:
    """Standard result from any connector operation."""
    provider: str = ""
    status: str = "unknown"       # connected, error, auth_failed, unreachable, timeout
    latency_ms: float = 0.0
    details: str = ""
    event_id: Optional[str] = None  # External event/ticket ID if created
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ConnectorInterface(ABC):
    """
    Base class for all SIEM/SOAR/Alerting connectors.

    Subclass this to add a new connector. Register it in the connector registry.

    Attributes:
        name:             Machine identifier (e.g. 'pagerduty')
        display_name:     Human-readable name (e.g. 'PagerDuty')
        credential_fields: List of dicts describing config fields for the Settings UI.
                          Each dict: {"field": str, "label": str, "type": "url"|"text"|"secret",
                                      "placeholder": str (optional)}
        supports_bidirectional: Whether this connector supports two-way sync (Workstream 5)
    """

    name: str = ""
    display_name: str = ""
    credential_fields: list[dict] = []
    supports_bidirectional: bool = False

    def _get_client(self, timeout: float = 10.0) -> httpx.AsyncClient:
        """Get a shared HTTP client. Callers must use `async with`."""
        return httpx.AsyncClient(timeout=timeout, verify=False)

    def _map_severity(self, threat_level: str) -> str:
        """Map GhostPrompt threat levels to standard severity strings."""
        return {
            "safe": "info",
            "low": "warning",
            "medium": "error",
            "high": "critical",
            "critical": "critical",
        }.get(threat_level, "info")

    def _base_payload(self, event: dict) -> dict:
        """Extract common fields from a GhostPrompt security event."""
        return {
            "source": "ghostprompt",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": event.get("request_id", ""),
            "action": event.get("action", "scan"),
            "threat_level": event.get("threat_level", "safe"),
            "threat_score": event.get("threat_score", 0),
            "model_provider": event.get("model_provider", ""),
            "model_name": event.get("model_name", ""),
            "is_blocked": event.get("is_blocked", False),
            "detections": event.get("detections", []),
            "threat_categories": event.get("threat_categories", []),
            "source_ip": event.get("source_ip", ""),
            "scan_duration_ms": event.get("scan_duration_ms", 0),
        }

    @abstractmethod
    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        """
        Push a security event to the external platform.

        Args:
            event: GhostPrompt security event dict
            config: Connector configuration (credentials, endpoint, etc.)

        Returns:
            ConnectorResult with status and details
        """
        ...

    @abstractmethod
    async def test_connection(self, config: dict) -> ConnectorResult:
        """
        Test the connection to the external platform.

        Args:
            config: Connector configuration (credentials, endpoint, etc.)

        Returns:
            ConnectorResult with connection status
        """
        ...

    async def safe_push(self, event: dict, config: dict) -> ConnectorResult:
        """Push with error handling and timing."""
        t0 = time.perf_counter()
        try:
            result = await self.push_event(event, config)
            result.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            result.provider = self.name
            return result
        except httpx.ConnectError:
            return ConnectorResult(
                provider=self.name, status="unreachable",
                latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                details="Connection refused — check endpoint URL"
            )
        except httpx.TimeoutException:
            return ConnectorResult(
                provider=self.name, status="timeout",
                latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                details="Connection timed out"
            )
        except Exception as e:
            logger.error("connector_push_failed", connector=self.name, error=str(e))
            return ConnectorResult(
                provider=self.name, status="error",
                latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                details=str(e)[:200]
            )

    async def safe_test(self, config: dict) -> ConnectorResult:
        """Test with error handling and timing."""
        t0 = time.perf_counter()
        try:
            result = await self.test_connection(config)
            result.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            result.provider = self.name
            return result
        except httpx.ConnectError:
            return ConnectorResult(
                provider=self.name, status="unreachable",
                latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                details="Connection refused — check endpoint URL"
            )
        except httpx.TimeoutException:
            return ConnectorResult(
                provider=self.name, status="timeout",
                latency_ms=10000,
                details="Connection timed out after 10s"
            )
        except Exception as e:
            logger.error("connector_test_failed", connector=self.name, error=str(e))
            return ConnectorResult(
                provider=self.name, status="error",
                latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                details=str(e)[:200]
            )
