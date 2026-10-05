"""
Agentic Tool Call Inspector (Layer 5)

Inspects tool/function calls in agentic AI systems.
Detects attempts to trick AI agents into:
- Destructive tool calls (delete files, drop tables, send emails)
- Goal hijacking (redirecting the agent's primary task)
- Indirect injection via tool outputs (poisoned content in tool results)
- Privilege escalation through tool chaining

Zero competitors have this capability. Fastest growing attack surface.
"""

import re

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.tool_inspector")


class ToolInspector:
    """Inspects tool/function calls in agentic AI requests."""

    def __init__(self):
        # Dangerous tool operations by category
        self._destructive_patterns = {
            "file_delete": [
                re.compile(r"\b(?:delete|remove|rm|unlink|rmdir|shred)\b.*\b(?:file|directory|folder|path)\b", re.IGNORECASE),
                re.compile(r"\brm\s+-rf?\b", re.IGNORECASE),
            ],
            "data_delete": [
                re.compile(r"\b(?:DROP|TRUNCATE|DELETE\s+FROM)\b", re.IGNORECASE),
                re.compile(r"\b(?:destroy|wipe|purge|erase)\b.*\b(?:data|database|table|collection)\b", re.IGNORECASE),
            ],
            "email_send": [
                re.compile(r"\b(?:send|forward|compose)\b.*\b(?:email|mail|message)\b", re.IGNORECASE),
                re.compile(r"\bsmtp\b|\bsendgrid\b|\bmailgun\b", re.IGNORECASE),
            ],
            "code_execution": [
                re.compile(r"\b(?:exec|eval|system|subprocess|os\.system|popen)\b", re.IGNORECASE),
                re.compile(r"\b(?:execute|run)\b.*\b(?:command|script|code|shell)\b", re.IGNORECASE),
            ],
            "network_exfil": [
                re.compile(r"\b(?:curl|wget|fetch|request)\b.*\b(?:http|ftp|ssh)\b", re.IGNORECASE),
                re.compile(r"\bpost\b.*\b(?:data|secret|key|token|password)\b", re.IGNORECASE),
            ],
            "privilege_escalation": [
                re.compile(r"\b(?:sudo|admin|root|chmod\s+777|grant\s+all)\b", re.IGNORECASE),
                re.compile(r"\b(?:escalate|elevate)\b.*\b(?:privilege|permission|access)\b", re.IGNORECASE),
            ],
        }

        # Goal hijacking indicators
        self._goal_hijacking_patterns = [
            re.compile(r"(?:instead|rather|forget).*(?:original|previous|main|primary)\s+(?:task|goal|objective)", re.IGNORECASE),
            re.compile(r"(?:change|modify|update)\s+(?:your|the)\s+(?:goal|objective|task|mission)", re.IGNORECASE),
            re.compile(r"(?:new|different)\s+(?:priority|task|objective|mission)\s*:", re.IGNORECASE),
            re.compile(r"(?:stop|cancel|abort)\s+(?:what|whatever)\s+(?:you|you're)", re.IGNORECASE),
            re.compile(r"ignore\s+(?:your|the)\s+(?:original|current|primary)\s+(?:task|instructions)", re.IGNORECASE),
        ]

        # Indirect injection markers in tool outputs
        self._indirect_injection_patterns = [
            re.compile(r"\[(?:SYSTEM|ADMIN|INSTRUCTION|HIDDEN)\]", re.IGNORECASE),
            re.compile(r"<\s*(?:system|instruction|override)\s*>", re.IGNORECASE),
            re.compile(r"(?:IMPORTANT|URGENT|NOTE TO AI|ATTENTION AI|INSTRUCTIONS FOR AI)\s*:", re.IGNORECASE),
            re.compile(r"(?:you\s+must|you\s+should|please\s+ignore|disregard\s+the)", re.IGNORECASE),
        ]

    async def initialize(self) -> None:
        logger.info("tool_inspector_initialized")

    async def inspect(
        self,
        text: str,
        tools: list[dict] | None = None,
        tool_results: list[dict] | None = None,
    ) -> list[DetectionResult]:
        """
        Inspect for agentic attack patterns.

        Checks:
        1. Destructive tool call attempts in prompts
        2. Goal hijacking in user messages
        3. Indirect injection in tool outputs/results
        """
        detections = []

        # 1. Check for destructive tool call attempts
        destructive = self._detect_destructive_calls(text)
        detections.extend(destructive)

        # 2. Check for goal hijacking
        hijacking = self._detect_goal_hijacking(text)
        if hijacking:
            detections.append(hijacking)

        # 3. Check tool results for indirect injection
        if tool_results:
            for result in tool_results:
                content = str(result.get("content", result.get("output", "")))
                indirect = self._detect_indirect_injection(content)
                detections.extend(indirect)

        # 4. Check tool definitions for suspicious patterns
        if tools:
            tool_defs = self._detect_suspicious_tools(tools)
            detections.extend(tool_defs)

        return detections

    def _detect_destructive_calls(self, text: str) -> list[DetectionResult]:
        """Detect attempts to trigger destructive tool operations."""
        detections = []

        for category, patterns in self._destructive_patterns.items():
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    severity_map = {
                        "file_delete": "critical",
                        "data_delete": "critical",
                        "email_send": "high",
                        "code_execution": "critical",
                        "network_exfil": "high",
                        "privilege_escalation": "critical",
                    }
                    detections.append(DetectionResult(
                        detector="tool_inspector",
                        confidence=0.80,
                        category=f"agent.destructive.{category}",
                        description=f"Potentially destructive tool operation detected: {category.replace('_', ' ')}",
                        matched_content=match.group(0)[:100],
                        severity=severity_map.get(category, "high"),
                    ))
                    break  # One detection per category

        return detections

    def _detect_goal_hijacking(self, text: str) -> DetectionResult | None:
        """Detect goal hijacking attempts in user messages."""
        for pattern in self._goal_hijacking_patterns:
            match = pattern.search(text)
            if match:
                return DetectionResult(
                    detector="tool_inspector",
                    confidence=0.78,
                    category="agent.goal_hijacking",
                    description="Goal hijacking attempt detected: message attempts to redirect the AI agent from its primary task",
                    matched_content=match.group(0)[:100],
                    severity="high",
                )
        return None

    def _detect_indirect_injection(self, tool_output: str) -> list[DetectionResult]:
        """Detect indirect prompt injection in tool outputs."""
        detections = []

        for pattern in self._indirect_injection_patterns:
            match = pattern.search(tool_output)
            if match:
                detections.append(DetectionResult(
                    detector="tool_inspector",
                    confidence=0.82,
                    category="agent.indirect_injection",
                    description="Indirect prompt injection detected in tool output: content contains instruction-like directives that may hijack the AI agent",
                    matched_content=match.group(0)[:100],
                    severity="high",
                ))
                break  # One detection is enough

        return detections

    def _detect_suspicious_tools(self, tools: list[dict]) -> list[DetectionResult]:
        """Check tool definitions for suspicious patterns."""
        detections = []
        dangerous_tool_names = [
            "execute_command", "run_shell", "system_exec", "delete_all",
            "send_email", "transfer_funds", "admin_override",
        ]

        for tool in tools:
            func = tool.get("function", tool)
            name = func.get("name", "").lower()
            desc = func.get("description", "").lower()

            for dangerous in dangerous_tool_names:
                if dangerous in name or dangerous in desc:
                    detections.append(DetectionResult(
                        detector="tool_inspector",
                        confidence=0.70,
                        category="agent.suspicious_tool",
                        description=f"Suspicious tool definition: '{func.get('name', 'unknown')}' — matches known dangerous tool pattern",
                        matched_content=func.get("name", "")[:50],
                        severity="medium",
                    ))

        return detections
