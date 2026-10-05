"""
Connector Registry — Auto-discovery of all SIEM/SOAR connectors.

Maps provider names to their ConnectorInterface implementations.
"""


from app.services.siem_connectors.base import ConnectorInterface
from app.services.siem_connectors.datadog import DatadogConnector
from app.services.siem_connectors.elastic_security import ElasticSecurityConnector
from app.services.siem_connectors.google_chronicle import GoogleChronicleConnector
from app.services.siem_connectors.jira import JiraConnector
from app.services.siem_connectors.microsoft_sentinel import MicrosoftSentinelConnector
from app.services.siem_connectors.opsgenie import OpsgenieConnector

# Import all connectors
from app.services.siem_connectors.pagerduty import PagerDutyConnector
from app.services.siem_connectors.qradar import QRadarConnector
from app.services.siem_connectors.security_lake import SecurityLakeConnector
from app.services.siem_connectors.servicenow import ServiceNowConnector
from app.services.siem_connectors.slack import SlackConnector
from app.services.siem_connectors.splunk import SplunkConnector
from app.services.siem_connectors.sumo_logic import SumoLogicConnector
from app.services.siem_connectors.teams import TeamsConnector

# Registry — keyed by provider name
CONNECTOR_REGISTRY: dict[str, ConnectorInterface] = {
    "pagerduty": PagerDutyConnector(),
    "slack": SlackConnector(),
    "servicenow": ServiceNowConnector(),
    "jira": JiraConnector(),
    "security_lake": SecurityLakeConnector(),
    "sumo_logic": SumoLogicConnector(),
    "opsgenie": OpsgenieConnector(),
    "teams": TeamsConnector(),
    "splunk": SplunkConnector(),
    "datadog": DatadogConnector(),
    "microsoft_sentinel": MicrosoftSentinelConnector(),
    "ibm_qradar": QRadarConnector(),
    "elastic_security": ElasticSecurityConnector(),
    "google_chronicle": GoogleChronicleConnector(),
}


def get_connector(provider: str) -> ConnectorInterface | None:
    """Get a connector instance by provider name."""
    return CONNECTOR_REGISTRY.get(provider)


def list_connectors() -> list[dict]:
    """List all registered connectors with their metadata."""
    return [
        {
            "name": c.name,
            "display_name": c.display_name,
            "supports_bidirectional": c.supports_bidirectional,
            "credential_fields": c.credential_fields,
        }
        for c in CONNECTOR_REGISTRY.values()
    ]
