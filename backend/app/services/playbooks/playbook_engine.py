"""
Playbook Engine — Multi-Step Response Automation

Orchestrates response chains: trigger → enrich → ban → ticket → notify.
Playbooks are defined as JSON configurations and executed asynchronously.

Inspired by Cortex XSOAR's playbook automation model.
"""

import uuid
import time
import asyncio
from datetime import datetime, timezone
from typing import Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from app.core.logging import get_logger

logger = get_logger("playbook_engine")


class NodeType(str, Enum):
    TRIGGER = "trigger"
    CONDITION = "condition"
    OSINT_ENRICH = "osint_enrich"
    FIREWALL_BAN = "firewall_ban"
    CREATE_TICKET = "create_ticket"
    SEND_NOTIFICATION = "send_notification"
    WAIT = "wait"
    WEBHOOK = "webhook"
    AI_SUMMARIZE = "ai_summarize"
    UPDATE_POLICY = "update_policy"


class PlaybookStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PlaybookNode:
    """A single step in a playbook."""
    id: str = field(default_factory=lambda: f"node-{uuid.uuid4().hex[:8]}")
    type: str = NodeType.TRIGGER
    label: str = ""
    config: dict = field(default_factory=dict)
    position: dict = field(default_factory=lambda: {"x": 0, "y": 0})  # React Flow position
    next_nodes: list[str] = field(default_factory=list)       # IDs of downstream nodes
    condition_true_node: Optional[str] = None    # For condition nodes
    condition_false_node: Optional[str] = None   # For condition nodes


@dataclass
class PlaybookDefinition:
    """A complete playbook definition."""
    id: str = field(default_factory=lambda: f"pb-{uuid.uuid4().hex[:12]}")
    name: str = ""
    description: str = ""
    org_id: str = ""
    created_by: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = ""
    status: str = PlaybookStatus.DRAFT
    
    # Trigger configuration
    trigger_type: str = "severity"  # severity, category, source_ip, manual
    trigger_conditions: dict = field(default_factory=dict)
    
    # Node graph
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    
    # Execution stats
    total_runs: int = 0
    last_run_at: Optional[str] = None
    avg_duration_ms: float = 0


@dataclass
class PlaybookExecution:
    """A single execution of a playbook."""
    id: str = field(default_factory=lambda: f"exec-{uuid.uuid4().hex[:12]}")
    playbook_id: str = ""
    triggered_by: str = ""  # incident ID or manual
    status: str = ExecutionStatus.PENDING
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    duration_ms: float = 0
    node_results: list[dict] = field(default_factory=list)
    error: Optional[str] = None
    context: dict = field(default_factory=dict)  # Shared context passed between nodes


# ── In-memory stores (production: PostgreSQL) ──
_playbooks: dict[str, PlaybookDefinition] = {}
_executions: dict[str, PlaybookExecution] = {}


class PlaybookEngine:
    """Orchestrates multi-step response playbooks."""

    async def create_playbook(self, data: dict, org_id: str, user_id: str) -> PlaybookDefinition:
        """Create a new playbook definition."""
        pb = PlaybookDefinition(
            name=data.get("name", "Untitled Playbook"),
            description=data.get("description", ""),
            org_id=org_id,
            created_by=user_id,
            trigger_type=data.get("trigger_type", "severity"),
            trigger_conditions=data.get("trigger_conditions", {}),
            nodes=data.get("nodes", []),
            edges=data.get("edges", []),
            status=PlaybookStatus.DRAFT,
        )
        _playbooks[pb.id] = pb
        logger.info("playbook_created", id=pb.id, name=pb.name, org=org_id)
        return pb

    async def update_playbook(self, playbook_id: str, data: dict) -> Optional[PlaybookDefinition]:
        """Update an existing playbook."""
        pb = _playbooks.get(playbook_id)
        if not pb:
            return None
        
        for field_name in ["name", "description", "trigger_type", "trigger_conditions", "nodes", "edges", "status"]:
            if field_name in data:
                setattr(pb, field_name, data[field_name])
        pb.updated_at = datetime.now(timezone.utc).isoformat()
        
        logger.info("playbook_updated", id=playbook_id)
        return pb

    async def delete_playbook(self, playbook_id: str) -> bool:
        if playbook_id in _playbooks:
            del _playbooks[playbook_id]
            return True
        return False

    async def get_playbook(self, playbook_id: str) -> Optional[dict]:
        pb = _playbooks.get(playbook_id)
        if not pb:
            return None
        return self._serialize_playbook(pb)

    async def list_playbooks(self, org_id: str) -> list[dict]:
        return [
            self._serialize_playbook(pb)
            for pb in _playbooks.values()
            if pb.org_id == org_id
        ]

    async def execute_playbook(
        self,
        playbook_id: str,
        trigger_event: dict,
    ) -> PlaybookExecution:
        """Execute a playbook triggered by a security event."""
        pb = _playbooks.get(playbook_id)
        if not pb:
            raise ValueError(f"Playbook {playbook_id} not found")
        if pb.status != PlaybookStatus.ACTIVE:
            raise ValueError(f"Playbook {playbook_id} is not active (status: {pb.status})")

        execution = PlaybookExecution(
            playbook_id=playbook_id,
            triggered_by=trigger_event.get("request_id", "manual"),
            status=ExecutionStatus.RUNNING,
            context={
                "trigger_event": trigger_event,
                "results": {},
            },
        )
        _executions[execution.id] = execution

        t0 = time.perf_counter()

        try:
            # Build node lookup
            node_map = {n.get("id", ""): n for n in pb.nodes}
            edge_map = {}
            for edge in pb.edges:
                src = edge.get("source", "")
                if src not in edge_map:
                    edge_map[src] = []
                edge_map[src].append(edge.get("target", ""))

            # Find trigger nodes (entry points)
            trigger_nodes = [n for n in pb.nodes if n.get("type") == NodeType.TRIGGER]
            if not trigger_nodes:
                raise ValueError("Playbook has no trigger nodes")

            # Execute from trigger node through the graph
            for trigger_node in trigger_nodes:
                await self._execute_node(trigger_node, execution, node_map, edge_map)

            execution.status = ExecutionStatus.COMPLETED
        except Exception as e:
            execution.status = ExecutionStatus.FAILED
            execution.error = str(e)[:500]
            logger.error("playbook_execution_failed", playbook_id=playbook_id, error=str(e))

        execution.completed_at = datetime.now(timezone.utc).isoformat()
        execution.duration_ms = round((time.perf_counter() - t0) * 1000, 2)

        # Update playbook stats
        pb.total_runs += 1
        pb.last_run_at = execution.started_at
        pb.avg_duration_ms = (pb.avg_duration_ms * (pb.total_runs - 1) + execution.duration_ms) / pb.total_runs

        return execution

    async def _execute_node(
        self,
        node: dict,
        execution: PlaybookExecution,
        node_map: dict,
        edge_map: dict,
    ):
        """Execute a single node and follow edges to next nodes."""
        node_id = node.get("id", "")
        node_type = node.get("type", "")
        node_config = node.get("data", {}).get("config", {})
        node_result = {"node_id": node_id, "type": node_type, "status": "running", "started_at": datetime.now(timezone.utc).isoformat()}

        try:
            if node_type == NodeType.TRIGGER:
                node_result["output"] = {"triggered": True, "event": execution.context.get("trigger_event", {}).get("request_id", "")}

            elif node_type == NodeType.OSINT_ENRICH:
                from app.services.firewall.detectors.osint_enrichment import osint_engine
                source_ip = execution.context.get("trigger_event", {}).get("source_ip", "")
                if source_ip:
                    dossier = await osint_engine.enrich_incident(source_ip)
                    execution.context["results"]["osint"] = dossier
                    node_result["output"] = {"enriched": True, "lookups": dossier.get("total_lookups", 0)}
                else:
                    node_result["output"] = {"enriched": False, "reason": "No source IP"}

            elif node_type == NodeType.FIREWALL_BAN:
                from app.security.firewall_ban_bridge import firewall_ban_bridge
                source_ip = execution.context.get("trigger_event", {}).get("source_ip", "")
                severity = execution.context.get("trigger_event", {}).get("threat_level", "high")
                if source_ip:
                    ban = await firewall_ban_bridge.ban_ip(ip=source_ip, severity=severity, reason="Playbook auto-ban")
                    execution.context["results"]["ban"] = {"ban_id": ban.ban_id, "duration": ban.ban_duration_seconds}
                    node_result["output"] = {"banned": True, "ban_id": ban.ban_id}
                else:
                    node_result["output"] = {"banned": False, "reason": "No source IP"}

            elif node_type == NodeType.CREATE_TICKET:
                provider = node_config.get("provider", "jira")
                from app.services.siem_connectors.registry import get_connector
                connector = get_connector(provider)
                if connector:
                    result = await connector.safe_push(execution.context.get("trigger_event", {}), node_config)
                    execution.context["results"]["ticket"] = {"provider": provider, "event_id": result.event_id}
                    node_result["output"] = {"created": True, "provider": provider, "event_id": result.event_id}
                else:
                    node_result["output"] = {"created": False, "reason": f"Connector '{provider}' not found"}

            elif node_type == NodeType.SEND_NOTIFICATION:
                provider = node_config.get("provider", "slack")
                from app.services.siem_connectors.registry import get_connector
                connector = get_connector(provider)
                if connector:
                    result = await connector.safe_push(execution.context.get("trigger_event", {}), node_config)
                    node_result["output"] = {"sent": True, "provider": provider}
                else:
                    node_result["output"] = {"sent": False, "reason": f"Connector '{provider}' not found"}

            elif node_type == NodeType.CONDITION:
                # Evaluate condition
                condition_field = node_config.get("field", "threat_score")
                condition_op = node_config.get("operator", ">=")
                condition_value = node_config.get("value", 0.8)
                actual_value = execution.context.get("trigger_event", {}).get(condition_field, 0)
                
                met = False
                if condition_op == ">=": met = actual_value >= condition_value
                elif condition_op == "<=": met = actual_value <= condition_value
                elif condition_op == "==": met = actual_value == condition_value
                elif condition_op == "!=": met = actual_value != condition_value
                elif condition_op == "contains": met = str(condition_value) in str(actual_value)
                
                node_result["output"] = {"condition_met": met, "field": condition_field, "actual": actual_value}
                
                # Follow condition-specific edges
                if met and node.get("data", {}).get("condition_true_node"):
                    true_node = node_map.get(node["data"]["condition_true_node"])
                    if true_node:
                        await self._execute_node(true_node, execution, node_map, edge_map)
                elif not met and node.get("data", {}).get("condition_false_node"):
                    false_node = node_map.get(node["data"]["condition_false_node"])
                    if false_node:
                        await self._execute_node(false_node, execution, node_map, edge_map)
                
                node_result["status"] = "completed"
                execution.node_results.append(node_result)
                return  # Conditions handle their own routing

            elif node_type == NodeType.WAIT:
                wait_seconds = min(node_config.get("seconds", 5), 60)  # Max 60s wait
                await asyncio.sleep(wait_seconds)
                node_result["output"] = {"waited_seconds": wait_seconds}

            elif node_type == NodeType.WEBHOOK:
                import httpx
                url = node_config.get("url", "")
                if url:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.post(url, json=execution.context.get("trigger_event", {}))
                        node_result["output"] = {"status_code": resp.status_code, "url": url}
                else:
                    node_result["output"] = {"error": "No webhook URL configured"}

            elif node_type == NodeType.UPDATE_POLICY:
                from app.services.firewall.bioc_engine import bioc_engine
                categories = execution.context.get("trigger_event", {}).get("threat_categories", [])
                if categories:
                    rule = await bioc_engine.on_campaign_detected(
                        campaign_id=f"playbook-{execution.id}",
                        attack_categories=categories,
                        pattern_signatures=[],
                        severity="high",
                    )
                    node_result["output"] = {"rule_id": rule.id, "rule_name": rule.name}
                else:
                    node_result["output"] = {"error": "No threat categories to create rule for"}

            node_result["status"] = "completed"

        except Exception as e:
            node_result["status"] = "failed"
            node_result["error"] = str(e)[:300]
            logger.error("playbook_node_failed", node_id=node_id, type=node_type, error=str(e))

        node_result["completed_at"] = datetime.now(timezone.utc).isoformat()
        execution.node_results.append(node_result)

        # Follow edges to next nodes
        next_node_ids = edge_map.get(node_id, [])
        for next_id in next_node_ids:
            next_node = node_map.get(next_id)
            if next_node:
                await self._execute_node(next_node, execution, node_map, edge_map)

    async def check_triggers(self, event: dict, org_id: str) -> list[str]:
        """Check if any active playbooks should trigger for this event."""
        triggered = []
        for pb in _playbooks.values():
            if pb.org_id != org_id or pb.status != PlaybookStatus.ACTIVE:
                continue
            if self._matches_trigger(pb, event):
                triggered.append(pb.id)
        return triggered

    def _matches_trigger(self, pb: PlaybookDefinition, event: dict) -> bool:
        conditions = pb.trigger_conditions
        if pb.trigger_type == "severity":
            min_severity = conditions.get("min_severity", "high")
            severity_order = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            return severity_order.get(event.get("threat_level", "safe"), 0) >= severity_order.get(min_severity, 3)
        elif pb.trigger_type == "category":
            target_cats = conditions.get("categories", [])
            event_cats = event.get("threat_categories", [])
            return bool(set(target_cats) & set(event_cats))
        elif pb.trigger_type == "blocked":
            return event.get("is_blocked", False)
        return False

    def _serialize_playbook(self, pb: PlaybookDefinition) -> dict:
        return {
            "id": pb.id,
            "name": pb.name,
            "description": pb.description,
            "org_id": pb.org_id,
            "created_by": pb.created_by,
            "created_at": pb.created_at,
            "updated_at": pb.updated_at,
            "status": pb.status,
            "trigger_type": pb.trigger_type,
            "trigger_conditions": pb.trigger_conditions,
            "nodes": pb.nodes,
            "edges": pb.edges,
            "total_runs": pb.total_runs,
            "last_run_at": pb.last_run_at,
            "avg_duration_ms": pb.avg_duration_ms,
        }

    async def get_execution(self, execution_id: str) -> Optional[dict]:
        ex = _executions.get(execution_id)
        if not ex:
            return None
        return {
            "id": ex.id, "playbook_id": ex.playbook_id,
            "triggered_by": ex.triggered_by, "status": ex.status,
            "started_at": ex.started_at, "completed_at": ex.completed_at,
            "duration_ms": ex.duration_ms, "node_results": ex.node_results,
            "error": ex.error,
        }

    async def list_executions(self, playbook_id: str, limit: int = 20) -> list[dict]:
        execs = [e for e in _executions.values() if e.playbook_id == playbook_id]
        execs.sort(key=lambda x: x.started_at, reverse=True)
        return [
            {"id": e.id, "status": e.status, "started_at": e.started_at,
             "duration_ms": e.duration_ms, "triggered_by": e.triggered_by}
            for e in execs[:limit]
        ]


# Singleton
playbook_engine = PlaybookEngine()
