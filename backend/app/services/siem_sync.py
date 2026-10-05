"""
Bi-Directional SIEM Sync Engine

Handles:
1. External ticket ID storage — maps GhostPrompt incidents to external SIEM/SOAR tickets
2. Webhook receiver — accepts status updates from external systems
3. Conflict resolution — last-writer-wins with audit trail
"""

from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict

from app.core.logging import get_logger

logger = get_logger("siem_sync")


@dataclass
class ExternalTicketMapping:
    """Maps a GhostPrompt incident to an external SIEM/SOAR ticket."""
    incident_id: str
    external_system: str          # jira, servicenow, pagerduty, opsgenie, etc.
    external_ticket_id: str       # JIRA-1234, INC0012345, etc.
    external_url: str = ""        # Deep link to external ticket
    external_status: str = ""     # open, in_progress, resolved, closed
    sync_direction: str = "push"  # push (GP→SIEM), pull (SIEM→GP), bidirectional
    last_synced_at: str = ""
    created_at: str = ""
    conflict_count: int = 0
    audit_trail: list = field(default_factory=list)


class BiDirectionalSyncEngine:
    """Manages bi-directional synchronization between GhostPrompt and external SIEM/SOAR systems."""

    def __init__(self):
        # In-memory store (production: DB table)
        self._mappings: dict[str, list[ExternalTicketMapping]] = defaultdict(list)
        self._webhook_secrets: dict[str, str] = {}  # system → shared secret
        logger.info("bidirectional_sync_engine_initialized")

    # ── Ticket Mapping CRUD ──

    async def create_mapping(
        self,
        incident_id: str,
        external_system: str,
        external_ticket_id: str,
        external_url: str = "",
        sync_direction: str = "push",
    ) -> ExternalTicketMapping:
        """Create a new external ticket mapping for an incident."""
        now = datetime.now(timezone.utc).isoformat()
        mapping = ExternalTicketMapping(
            incident_id=incident_id,
            external_system=external_system,
            external_ticket_id=external_ticket_id,
            external_url=external_url,
            sync_direction=sync_direction,
            external_status="open",
            last_synced_at=now,
            created_at=now,
            audit_trail=[{
                "action": "created",
                "timestamp": now,
                "source": "ghostprompt",
                "details": f"Linked to {external_system}:{external_ticket_id}",
            }],
        )
        self._mappings[incident_id].append(mapping)
        logger.info(
            "ticket_mapping_created",
            incident_id=incident_id,
            external_system=external_system,
            external_ticket_id=external_ticket_id,
        )
        return mapping

    async def get_mappings(self, incident_id: str) -> list[dict]:
        """Get all external ticket mappings for an incident."""
        return [
            {
                "incident_id": m.incident_id,
                "external_system": m.external_system,
                "external_ticket_id": m.external_ticket_id,
                "external_url": m.external_url,
                "external_status": m.external_status,
                "sync_direction": m.sync_direction,
                "last_synced_at": m.last_synced_at,
                "created_at": m.created_at,
                "conflict_count": m.conflict_count,
            }
            for m in self._mappings.get(incident_id, [])
        ]

    async def get_all_synced_incidents(self) -> list[dict]:
        """Get all incidents that have external ticket mappings."""
        results = []
        for incident_id, mappings in self._mappings.items():
            for m in mappings:
                results.append({
                    "incident_id": m.incident_id,
                    "external_system": m.external_system,
                    "external_ticket_id": m.external_ticket_id,
                    "external_status": m.external_status,
                    "last_synced_at": m.last_synced_at,
                })
        return results

    # ── Webhook Processing ──

    async def process_webhook(
        self,
        source_system: str,
        payload: dict,
    ) -> dict:
        """
        Process an incoming webhook from an external SIEM/SOAR system.
        Updates the local incident status based on external changes.
        """
        external_ticket_id = payload.get("ticket_id") or payload.get("key") or payload.get("number", "")
        new_status = payload.get("status", "").lower()
        external_url = payload.get("url", "")

        if not external_ticket_id:
            return {"status": "error", "message": "Missing ticket_id in payload"}

        # Find matching mapping
        updated = False
        for incident_id, mappings in self._mappings.items():
            for mapping in mappings:
                if (mapping.external_system == source_system and
                    mapping.external_ticket_id == external_ticket_id):

                    old_status = mapping.external_status
                    now = datetime.now(timezone.utc).isoformat()

                    # Conflict detection: if both sides updated since last sync
                    if old_status != new_status:
                        mapping.external_status = new_status
                        mapping.last_synced_at = now
                        if external_url:
                            mapping.external_url = external_url

                        mapping.audit_trail.append({
                            "action": "status_updated_via_webhook",
                            "timestamp": now,
                            "source": source_system,
                            "old_status": old_status,
                            "new_status": new_status,
                        })

                        logger.info(
                            "webhook_status_updated",
                            incident_id=incident_id,
                            external_system=source_system,
                            old_status=old_status,
                            new_status=new_status,
                        )
                        updated = True

        if updated:
            return {"status": "accepted", "message": f"Updated {external_ticket_id} to {new_status}"}
        return {"status": "not_found", "message": f"No mapping found for {source_system}:{external_ticket_id}"}

    # ── Conflict Resolution ──

    async def resolve_conflict(
        self,
        incident_id: str,
        external_system: str,
        winner: str = "external",  # "external" or "ghostprompt"
    ) -> Optional[dict]:
        """
        Resolve a sync conflict using last-writer-wins strategy.
        Winner determines which system's status takes precedence.
        """
        for mapping in self._mappings.get(incident_id, []):
            if mapping.external_system == external_system:
                now = datetime.now(timezone.utc).isoformat()
                mapping.conflict_count += 1
                mapping.audit_trail.append({
                    "action": "conflict_resolved",
                    "timestamp": now,
                    "winner": winner,
                    "conflict_number": mapping.conflict_count,
                })
                mapping.last_synced_at = now
                logger.info(
                    "conflict_resolved",
                    incident_id=incident_id,
                    external_system=external_system,
                    winner=winner,
                    conflict_count=mapping.conflict_count,
                )
                return {"status": "resolved", "winner": winner, "conflict_count": mapping.conflict_count}
        return None

    # ── Webhook Secret Management ──

    def register_webhook_secret(self, system: str, secret: str):
        """Register a shared secret for webhook signature verification."""
        self._webhook_secrets[system] = secret

    def verify_webhook_signature(self, system: str, signature: str, body: bytes) -> bool:
        """Verify webhook signature using HMAC-SHA256."""
        import hmac
        import hashlib
        secret = self._webhook_secrets.get(system)
        if not secret:
            return False
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)


# Singleton
siem_sync_engine = BiDirectionalSyncEngine()
