"""
GhostPrompt MCP Gateway

Centralized control plane for Model Context Protocol servers.
Server registry, traffic inspection, access control, observability.
"""

import uuid
import time
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum


class MCPAuthMethod(str, Enum):
    API_KEY = "api_key"
    OAUTH = "oauth"
    CUSTOM = "custom"
    NONE = "none"


@dataclass
class MCPTool:
    name: str
    description: str = ""
    parameters_schema: dict = field(default_factory=dict)
    call_count: int = 0
    error_count: int = 0
    total_latency_ms: float = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "parameters_schema": self.parameters_schema,
            "call_count": self.call_count,
            "error_count": self.error_count,
            "avg_latency_ms": round(self.total_latency_ms / max(self.call_count, 1), 1),
        }


@dataclass
class MCPServer:
    server_id: str
    tenant_id: str
    name: str
    url: str
    auth_method: MCPAuthMethod = MCPAuthMethod.API_KEY
    auth_credentials: dict = field(default_factory=dict)
    tools: dict = field(default_factory=dict)  # name -> MCPTool
    allowed_teams: list = field(default_factory=list)
    allowed_users: list = field(default_factory=list)
    is_active: bool = True
    created_at: float = field(default_factory=time.time)
    total_calls: int = 0
    total_errors: int = 0

    def to_dict(self) -> dict:
        return {
            "server_id": self.server_id,
            "name": self.name,
            "url": self.url,
            "auth_method": self.auth_method.value,
            "tools": [t.to_dict() for t in self.tools.values()],
            "tool_count": len(self.tools),
            "allowed_teams": self.allowed_teams,
            "is_active": self.is_active,
            "total_calls": self.total_calls,
            "total_errors": self.total_errors,
            "created_at": self.created_at,
        }


@dataclass
class MCPCallLog:
    call_id: str
    server_id: str
    tool_name: str
    user_id: str
    agent_id: str
    parameters: dict
    response: dict = field(default_factory=dict)
    latency_ms: float = 0
    blocked: bool = False
    block_reason: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "latency_ms": round(self.latency_ms, 1),
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "timestamp": self.timestamp,
        }


class MCPGateway:
    """Centralized MCP Gateway with inspection, access control, and observability."""

    def __init__(self):
        self._servers: dict[str, MCPServer] = {}
        self._tenant_servers: dict[str, list[str]] = defaultdict(list)
        self._call_logs: list[MCPCallLog] = []
        self._anomaly_baselines: dict[str, float] = defaultdict(float)  # tool -> avg calls/hour
        self._max_logs = 50000

    def register_server(self, tenant_id: str, name: str, url: str,
                       auth_method: str = "api_key", auth_credentials: dict = None,
                       tools: list = None, allowed_teams: list = None) -> dict:
        server_id = f"mcp_{uuid.uuid4().hex[:12]}"
        tool_map = {}
        for t in (tools or []):
            tool_map[t["name"]] = MCPTool(name=t["name"], description=t.get("description", ""), parameters_schema=t.get("parameters", {}))
        server = MCPServer(
            server_id=server_id, tenant_id=tenant_id, name=name, url=url,
            auth_method=MCPAuthMethod(auth_method), auth_credentials=auth_credentials or {},
            tools=tool_map, allowed_teams=allowed_teams or [],
        )
        self._servers[server_id] = server
        self._tenant_servers[tenant_id].append(server_id)
        return server.to_dict()

    def check_access(self, server_id: str, user_id: str, team: str = "") -> dict:
        server = self._servers.get(server_id)
        if not server or not server.is_active:
            return {"allowed": False, "reason": "Server not found or inactive"}
        if server.allowed_teams and team not in server.allowed_teams:
            return {"allowed": False, "reason": f"Team '{team}' not authorized"}
        if server.allowed_users and user_id not in server.allowed_users:
            return {"allowed": False, "reason": "User not authorized"}
        return {"allowed": True}

    def inspect_tool_call(self, server_id: str, tool_name: str, parameters: dict,
                         user_id: str = "", agent_id: str = "") -> MCPCallLog:
        call_id = uuid.uuid4().hex[:16]
        log = MCPCallLog(call_id=call_id, server_id=server_id, tool_name=tool_name,
                        user_id=user_id, agent_id=agent_id, parameters=parameters)
        # Inspect for injection in parameters
        param_str = str(parameters).lower()
        injection_signals = ["ignore previous", "system prompt", "drop table", "<script>", "eval(", "exec("]
        for signal in injection_signals:
            if signal in param_str:
                log.blocked = True
                log.block_reason = f"Injection detected: '{signal}'"
                break
        # Anomaly detection
        tool_key = f"{server_id}:{tool_name}"
        now = time.time()
        recent_calls = sum(1 for l in self._call_logs[-1000:] if l.server_id == server_id and l.tool_name == tool_name and now - l.timestamp < 3600)
        baseline = self._anomaly_baselines.get(tool_key, 50)
        if recent_calls > baseline * 10 and baseline > 0:
            log.blocked = True
            log.block_reason = f"Anomaly: {recent_calls} calls/hour vs baseline {baseline}"
        # Update baseline
        self._anomaly_baselines[tool_key] = max(baseline, recent_calls * 0.1 + baseline * 0.9)
        # Record
        server = self._servers.get(server_id)
        if server:
            server.total_calls += 1
            tool = server.tools.get(tool_name)
            if tool:
                tool.call_count += 1
            if log.blocked:
                server.total_errors += 1
        self._call_logs.append(log)
        if len(self._call_logs) > self._max_logs:
            self._call_logs = self._call_logs[-self._max_logs // 2:]
        return log

    def record_response(self, call_id: str, response: dict, latency_ms: float, error: bool = False):
        for log in reversed(self._call_logs):
            if log.call_id == call_id:
                log.response = response
                log.latency_ms = latency_ms
                server = self._servers.get(log.server_id)
                if server:
                    tool = server.tools.get(log.tool_name)
                    if tool:
                        tool.total_latency_ms += latency_ms
                        if error:
                            tool.error_count += 1
                break

    def list_servers(self, tenant_id: str) -> list[dict]:
        ids = self._tenant_servers.get(tenant_id, [])
        return [self._servers[sid].to_dict() for sid in ids if sid in self._servers]

    def get_server(self, server_id: str) -> Optional[dict]:
        s = self._servers.get(server_id)
        return s.to_dict() if s else None

    def get_call_logs(self, tenant_id: str = None, server_id: str = None, limit: int = 50) -> list[dict]:
        logs = self._call_logs
        if server_id:
            logs = [l for l in logs if l.server_id == server_id]
        elif tenant_id:
            server_ids = set(self._tenant_servers.get(tenant_id, []))
            logs = [l for l in logs if l.server_id in server_ids]
        return [l.to_dict() for l in reversed(logs)][:limit]

    def get_tool_analytics(self, server_id: str) -> list[dict]:
        server = self._servers.get(server_id)
        if not server:
            return []
        return [t.to_dict() for t in server.tools.values()]


# Singleton
mcp_gateway = MCPGateway()
