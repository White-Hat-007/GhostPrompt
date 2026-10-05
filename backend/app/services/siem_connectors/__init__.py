"""
GhostPrompt SIEM/SOAR/Alerting Connector Framework

Each connector implements ConnectorInterface:
  - push_event()       → Send a security event to the external platform
  - test_connection()   → Validate credentials with a live probe
  - get_credential_fields() → Declare what config fields the UI should render

Enterprise tenants can extend ConnectorInterface to build custom connectors
without waiting on a GhostPrompt release.
"""

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult
from app.services.siem_connectors.registry import CONNECTOR_REGISTRY, get_connector

__all__ = [
    "CONNECTOR_REGISTRY",
    "ConnectorInterface",
    "ConnectorResult",
    "get_connector",
]
