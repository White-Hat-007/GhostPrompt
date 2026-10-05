"""
AI Agent Security Service

Monitors and validates AI agent behavior:
- Tool call validation and authorization
- Autonomous action monitoring
- Agent workflow inspection
- Prompt-chain analysis
- Memory poisoning detection
- Permission enforcement
"""

import re
from typing import Any

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("service.agent_security")

# Dangerous tool patterns
DANGEROUS_TOOLS = {
    "shell_exec": {"risk": "critical", "description": "Shell command execution"},
    "file_write": {"risk": "high", "description": "File system write access"},
    "file_delete": {"risk": "critical", "description": "File deletion"},
    "network_request": {"risk": "medium", "description": "External network request"},
    "database_query": {"risk": "high", "description": "Direct database query"},
    "code_exec": {"risk": "critical", "description": "Arbitrary code execution"},
    "api_call": {"risk": "medium", "description": "External API invocation"},
    "email_send": {"risk": "high", "description": "Email sending capability"},
    "payment": {"risk": "critical", "description": "Payment processing"},
    "admin_action": {"risk": "critical", "description": "Administrative action"},
}

SUSPICIOUS_ARG_PATTERNS = [
    (r"(?:rm|del|format|fdisk)\s+", "destructive_command", "Destructive system command in arguments"),
    (r"(?:curl|wget|fetch)\s+https?://", "external_fetch", "External URL fetch in tool arguments"),
    (r"(?:password|secret|token|key)\s*[=:]", "credential_access", "Credential access pattern in arguments"),
    (r"(?:DROP|DELETE|TRUNCATE|ALTER)\s+", "destructive_sql", "Destructive SQL in arguments"),
    (r"(?:eval|exec|compile|__import__)\s*\(", "code_injection", "Code injection pattern in arguments"),
    (r"(?:sudo|runas|admin)", "privilege_escalation", "Privilege escalation attempt"),
]


class AgentSecurityService:
    """
    Validates and monitors AI agent behavior for security threats.

    Protections:
    - Tool call authorization against allowlists
    - Argument inspection for injection patterns
    - Action frequency anomaly detection
    - Workflow chain validation
    - Memory/context poisoning detection
    """

    def __init__(self):
        self._allowed_tools: set[str] = set()
        self._action_log: list[dict] = []
        self._compiled_arg_patterns: list[tuple[re.Pattern, str, str]] = []

    async def initialize(self, allowed_tools: set[str] | None = None) -> None:
        self._allowed_tools = allowed_tools or set()
        self._compiled_arg_patterns = [
            (re.compile(pattern, re.IGNORECASE), category, description)
            for pattern, category, description in SUSPICIOUS_ARG_PATTERNS
        ]
        logger.info("agent_security_initialized")

    async def validate_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        agent_id: str | None = None,
    ) -> list[DetectionResult]:
        """Validate a tool call before execution."""
        detections = []

        # Check tool authorization
        if self._allowed_tools and tool_name not in self._allowed_tools:
            detections.append(DetectionResult(
                detector="agent_security",
                confidence=0.95,
                category="agent.unauthorized_tool",
                description=f"Tool '{tool_name}' is not in the allowed tool list",
                matched_content=tool_name,
                severity="critical",
            ))

        # Check for dangerous tools
        tool_lower = tool_name.lower().replace("-", "_").replace(" ", "_")
        for dangerous_tool, info in DANGEROUS_TOOLS.items():
            if dangerous_tool in tool_lower:
                detections.append(DetectionResult(
                    detector="agent_security",
                    confidence=0.85,
                    category=f"agent.dangerous_tool.{info['risk']}",
                    description=f"High-risk tool call: {info['description']}",
                    matched_content=tool_name,
                    severity=info["risk"],
                ))
                break

        # Inspect arguments
        arg_detections = self._inspect_arguments(arguments)
        detections.extend(arg_detections)

        # Log action for anomaly detection
        self._action_log.append({
            "tool": tool_name,
            "agent_id": agent_id,
            "detection_count": len(detections),
        })

        # Anomaly: too many actions in short time
        if len(self._action_log) > 100:
            self._action_log = self._action_log[-100:]
        if len(self._action_log) > 50:
            detections.append(DetectionResult(
                detector="agent_security",
                confidence=0.60,
                category="agent.action_frequency_anomaly",
                description="Unusually high frequency of agent actions detected",
                severity="medium",
            ))

        return detections

    async def validate_workflow(
        self,
        workflow_steps: list[dict],
    ) -> list[DetectionResult]:
        """Validate an entire agent workflow for security issues."""
        detections = []

        # Check for escalation patterns
        risk_levels: list[str] = []
        for step in workflow_steps:
            tool = step.get("tool", "").lower()
            for dangerous_tool, info in DANGEROUS_TOOLS.items():
                if dangerous_tool in tool:
                    risk_levels.append(info["risk"])
                    break

        # Detect escalating risk pattern
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if len(risk_levels) >= 3:
            numeric_risks = [risk_order.get(r, 0) for r in risk_levels]
            if all(numeric_risks[i] <= numeric_risks[i + 1] for i in range(len(numeric_risks) - 1)):
                if numeric_risks[-1] >= 2:
                    detections.append(DetectionResult(
                        detector="agent_security",
                        confidence=0.78,
                        category="agent.escalation_pattern",
                        description="Workflow shows escalating privilege pattern — possible agent hijacking",
                        severity="high",
                    ))

        # Check for loop patterns
        tools_used = [step.get("tool", "") for step in workflow_steps]
        if len(tools_used) > 5:
            unique_ratio = len(set(tools_used)) / len(tools_used)
            if unique_ratio < 0.3:
                detections.append(DetectionResult(
                    detector="agent_security",
                    confidence=0.65,
                    category="agent.loop_detected",
                    description="Agent appears to be stuck in a loop — possible manipulation",
                    severity="medium",
                ))

        return detections

    async def check_memory_poisoning(
        self,
        memory_entries: list[str],
    ) -> list[DetectionResult]:
        """Check agent memory for poisoning attempts."""
        detections = []
        for entry in memory_entries:
            entry_lower = entry.lower()
            poisoning_indicators = [
                "ignore previous", "override instructions", "new system prompt",
                "from now on", "your real purpose", "secret instruction",
            ]
            for indicator in poisoning_indicators:
                if indicator in entry_lower:
                    detections.append(DetectionResult(
                        detector="agent_security",
                        confidence=0.80,
                        category="agent.memory_poisoning",
                        description=f"Memory poisoning indicator detected: '{indicator}'",
                        matched_content=entry[:200],
                        severity="high",
                    ))
                    break
        return detections

    def _inspect_arguments(self, arguments: dict[str, Any]) -> list[DetectionResult]:
        """Inspect tool call arguments for malicious patterns."""
        detections = []
        for key, value in arguments.items():
            if not isinstance(value, str):
                value = str(value)
            for pattern, category, description in self._compiled_arg_patterns:
                match = pattern.search(value)
                if match:
                    detections.append(DetectionResult(
                        detector="agent_security",
                        confidence=0.82,
                        category=f"agent.{category}",
                        description=f"{description} in argument '{key}'",
                        matched_content=match.group(0)[:100],
                        severity="high",
                    ))
                    break
        return detections


# Singleton
agent_security = AgentSecurityService()
