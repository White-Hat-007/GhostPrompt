"""
Audit Log API — Immutable Event Trail

Every sensitive action is logged to an append-only audit trail:
- Login/logout events
- Setting changes
- RBAC role modifications
- Key operations (create/revoke)
- Training job starts
- Policy changes
- Threshold overrides

Supports filtering, search, and export.
"""

from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.core.logging import get_logger
from app.core.permissions import require_permission
from app.core.security import get_current_user

logger = get_logger("audit_log")
router = APIRouter(prefix="/audit", tags=["Audit Log"], dependencies=[Depends(require_permission("audit.view"))])


# ── Schemas ──

class AuditEntry(BaseModel):
    id: str
    timestamp: str
    actor_email: str
    actor_id: str
    action: str
    resource_type: str
    resource_id: str | None = None
    details: dict | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    org_id: str


# ── In-memory audit store (production: append-only Postgres table) ──
_audit_log: list[dict] = []
_log_counter = 0


def record_audit_event(
    actor_email: str,
    actor_id: str,
    org_id: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
):
    """Record an immutable audit event."""
    global _log_counter
    _log_counter += 1

    entry = {
        "id": f"AUD-{_log_counter:06d}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor_email": actor_email,
        "actor_id": actor_id,
        "org_id": org_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details,
        "ip_address": ip_address,
        "user_agent": user_agent,
    }
    _audit_log.append(entry)

    logger.info(
        "audit_event",
        actor=actor_email,
        action=action,
        resource=resource_type,
        resource_id=resource_id,
    )


# ── Endpoints ──

@router.get("", response_model=list[AuditEntry])
async def get_audit_log(
    action: str | None = Query(None),
    resource_type: str | None = Query(None),
    actor: str | None = Query(None),
    since: str | None = Query(None, description="ISO 8601 timestamp"),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    current_user: dict = Depends(get_current_user),
):
    """Get audit log entries for the current organization."""
    org_id = str(current_user.get("org_id"))

    entries = [e for e in _audit_log if e.get("org_id") == org_id]

    if action:
        entries = [e for e in entries if e.get("action") == action]
    if resource_type:
        entries = [e for e in entries if e.get("resource_type") == resource_type]
    if actor:
        entries = [e for e in entries if actor.lower() in e.get("actor_email", "").lower()]
    if since:
        since_dt = datetime.fromisoformat(since)
        entries = [e for e in entries if datetime.fromisoformat(e["timestamp"]) >= since_dt]

    entries = sorted(entries, key=lambda e: e["timestamp"], reverse=True)
    total = len(entries)
    entries = entries[offset:offset + limit]

    return entries


@router.get("/actions")
async def get_action_types(
    current_user: dict = Depends(get_current_user),
):
    """Get distinct action types in the audit log."""
    org_id = str(current_user.get("org_id"))
    actions = set(e.get("action") for e in _audit_log if e.get("org_id") == org_id)
    return sorted(actions)


@router.get("/stats")
async def get_audit_stats(
    current_user: dict = Depends(get_current_user),
):
    """Get audit log statistics for the current org."""
    org_id = str(current_user.get("org_id"))
    entries = [e for e in _audit_log if e.get("org_id") == org_id]

    action_counts: dict[str, int] = defaultdict(int)
    actor_counts: dict[str, int] = defaultdict(int)
    for e in entries:
        action_counts[e.get("action", "unknown")] += 1
        actor_counts[e.get("actor_email", "unknown")] += 1

    return {
        "total_events": len(entries),
        "actions": dict(sorted(action_counts.items(), key=lambda x: -x[1])),
        "top_actors": dict(sorted(actor_counts.items(), key=lambda x: -x[1])[:10]),
    }
