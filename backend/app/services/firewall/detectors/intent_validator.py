"""
Intent Validator — Threat Layer 9 (Advanced)

Detects Business Logic Exploitation where a user social-engineers the AI
into executing a perfectly valid, authorized tool call for a destructive purpose.

Detection signals:
  - Irreversibility classification of tool calls
  - Pre-execution intent audit via conversational analysis
  - Scope creep detection (bulk vs stated intent)
  - Unverifiable context injection (fake policies, fake authority)
  - Urgency / authority framing detection
  - Cooldown enforcement after irreversible actions
"""

import re
import time

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.intent_validator")

# ── Tool classification ──────────────────────────────────────────────
TOOL_CLASSIFICATIONS = {
    # Destructive
    "drop": "DESTRUCTIVE", "delete": "DESTRUCTIVE", "destroy": "DESTRUCTIVE",
    "truncate": "DESTRUCTIVE", "purge": "DESTRUCTIVE", "wipe": "DESTRUCTIVE",
    "rm -rf": "DESTRUCTIVE", "format": "DESTRUCTIVE", "shutdown": "DESTRUCTIVE",
    "terminate": "DESTRUCTIVE", "revoke_all": "DESTRUCTIVE",
    # Irreversible writes
    "archive": "IRREVERSIBLE_WRITE", "merge": "IRREVERSIBLE_WRITE",
    "send_email": "IRREVERSIBLE_WRITE", "publish": "IRREVERSIBLE_WRITE",
    "deploy": "IRREVERSIBLE_WRITE", "transfer": "IRREVERSIBLE_WRITE",
    "submit": "IRREVERSIBLE_WRITE", "approve": "IRREVERSIBLE_WRITE",
    "execute_payment": "IRREVERSIBLE_WRITE", "sign": "IRREVERSIBLE_WRITE",
    # Reversible writes
    "update": "REVERSIBLE_WRITE", "create": "REVERSIBLE_WRITE",
    "modify": "REVERSIBLE_WRITE", "edit": "REVERSIBLE_WRITE",
    "insert": "REVERSIBLE_WRITE", "add": "REVERSIBLE_WRITE",
    # Read-only
    "get": "READ_ONLY", "list": "READ_ONLY", "read": "READ_ONLY",
    "search": "READ_ONLY", "query": "READ_ONLY", "fetch": "READ_ONLY",
    "count": "READ_ONLY", "describe": "READ_ONLY", "show": "READ_ONLY",
}

# Social engineering / urgency patterns
URGENCY_PATTERNS = [
    r"(urgent|immediately|right\s+now|asap|emergency|critical)",
    r"(do\s+it\s+now|no\s+time\s+to\s+waste|hurry|quick)",
    r"(before\s+it['\u2019]?s?\s+too\s+late|deadline|time[- ]sensitive)",
    r"(CEO|CTO|VP|director|boss|manager)\s+(said|told|asked|wants|needs|ordered|demanded)",
    r"(new\s+policy|updated\s+policy|company\s+policy|retention\s+policy)",
    r"(compliance\s+requires?|regulation\s+requires?|legal\s+requires?|audit\s+requires?)",
    r"(I\s+have\s+authorization|I['\u2019]?m?\s+authorized|I\s+was\s+told\s+to)",
    r"(don['\u2019]?t\s+(ask|question|check|verify)|just\s+do\s+it|no\s+need\s+to\s+confirm)",
]

# Scope inflation keywords
SCOPE_INFLATION = [
    r"\ball\b",
    r"\beverything\b",
    r"\bentire\b",
    r"\bevery\s+single\b",
    r"\bglobal(?:ly)?\b",
    r"\bwhole\b",
    r"\bcomplete(?:ly)?\b",
    r"\bfull\b",
]

# Cooldown tracking
_action_cooldowns: dict[str, float] = {}
COOLDOWN_SECONDS = 300  # 5-minute cooldown after irreversible action


class IntentValidator:
    """Validates business intent behind tool calls to prevent social engineering."""

    def __init__(self):
        self._urgency_compiled = []
        self._scope_compiled = []

    async def initialize(self) -> None:
        self._urgency_compiled = [
            re.compile(p, re.IGNORECASE) for p in URGENCY_PATTERNS
        ]
        self._scope_compiled = [
            re.compile(p, re.IGNORECASE) for p in SCOPE_INFLATION
        ]
        logger.info("intent_validator_initialized")

    async def detect(
        self,
        text: str,
        *,
        session_id: str | None = None,
        tool_name: str | None = None,
    ) -> list[DetectionResult]:
        detections: list[DetectionResult] = []
        text_lower = text.lower()
        sid = session_id or "default"

        # ── 1. Classify tool action ──────────────────────────────────
        detected_classification = "READ_ONLY"
        detected_tool_verb = None
        for verb, classification in TOOL_CLASSIFICATIONS.items():
            if verb in text_lower:
                if TOOL_CLASSIFICATIONS.get(verb, "READ_ONLY") in (
                    "DESTRUCTIVE", "IRREVERSIBLE_WRITE"
                ):
                    detected_classification = classification
                    detected_tool_verb = verb
                    break

        # Override with explicit tool_name if provided
        if tool_name:
            for verb, classification in TOOL_CLASSIFICATIONS.items():
                if verb in tool_name.lower():
                    detected_classification = classification
                    detected_tool_verb = verb
                    break

        # ── 2. Urgency / authority framing ───────────────────────────
        urgency_matches = []
        for pattern in self._urgency_compiled:
            match = pattern.search(text)
            if match:
                urgency_matches.append(match.group(0))

        if urgency_matches and detected_classification in ("DESTRUCTIVE", "IRREVERSIBLE_WRITE"):
            detections.append(DetectionResult(
                detector="intent_validator",
                confidence=min(0.65 + len(urgency_matches) * 0.1, 0.95),
                category="intent.urgency_with_destruction",
                description=(
                    f"Urgency/authority framing combined with {detected_classification} "
                    f"action '{detected_tool_verb}': {', '.join(urgency_matches[:3])}"
                ),
                severity="critical" if detected_classification == "DESTRUCTIVE" else "high",
                matched_content="; ".join(urgency_matches[:3]),
            ))
        elif urgency_matches and len(urgency_matches) >= 2:
            detections.append(DetectionResult(
                detector="intent_validator",
                confidence=min(0.5 + len(urgency_matches) * 0.1, 0.80),
                category="intent.social_engineering_signals",
                description=(
                    f"Multiple social engineering signals detected: "
                    f"{', '.join(urgency_matches[:3])}"
                ),
                severity="medium",
                matched_content="; ".join(urgency_matches[:3]),
            ))

        # ── 3. Scope creep detection ─────────────────────────────────
        scope_matches = []
        for pattern in self._scope_compiled:
            match = pattern.search(text)
            if match:
                scope_matches.append(match.group(0))

        if scope_matches and detected_classification in ("DESTRUCTIVE", "IRREVERSIBLE_WRITE"):
            detections.append(DetectionResult(
                detector="intent_validator",
                confidence=min(0.7 + len(scope_matches) * 0.08, 0.93),
                category="intent.scope_creep",
                description=(
                    f"Scope inflation in {detected_classification} action: "
                    f"broad-scope keywords ({', '.join(scope_matches[:3])}) combined with "
                    f"destructive verb '{detected_tool_verb}'"
                ),
                severity="high",
                matched_content=f"scope={', '.join(scope_matches[:3])}; action={detected_tool_verb}",
            ))

        # ── 4. Unverifiable context injection ────────────────────────
        unverifiable_patterns = [
            (r"(new|updated|revised)\s+(company|corporate|internal)?\s*policy", "policy_claim"),
            (r"(as\s+per|according\s+to|per)\s+(the\s+)?(new|latest|updated)", "external_reference"),
            (r"(I\s+was\s+told|they\s+said|management\s+said|HR\s+said)", "hearsay_authority"),
            (r"(you\s+don['\u2019]?t\s+need\s+to\s+verify|skip\s+verification)", "verification_bypass"),
        ]
        for pattern_str, flag_type in unverifiable_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            match = pattern.search(text)
            if match:
                detections.append(DetectionResult(
                    detector="intent_validator",
                    confidence=0.72,
                    category=f"intent.unverifiable_{flag_type}",
                    description=(
                        f"Unverifiable context injection ({flag_type}): justification for "
                        f"action relies on externally claimed authority that cannot be verified"
                    ),
                    severity="high",
                    matched_content=match.group(0)[:100],
                ))

        # ── 5. Cooldown enforcement ──────────────────────────────────
        if detected_classification in ("DESTRUCTIVE", "IRREVERSIBLE_WRITE"):
            last_action_time = _action_cooldowns.get(sid, 0)
            if last_action_time and time.time() - last_action_time < COOLDOWN_SECONDS:
                remaining = int(COOLDOWN_SECONDS - (time.time() - last_action_time))
                detections.append(DetectionResult(
                    detector="intent_validator",
                    confidence=0.80,
                    category="intent.cooldown_violation",
                    description=(
                        f"Cooldown violation: another {detected_classification} action "
                        f"attempted within {COOLDOWN_SECONDS}s window ({remaining}s remaining)"
                    ),
                    severity="high",
                    matched_content=f"action={detected_tool_verb}; cooldown={remaining}s",
                ))

            # Record this action for cooldown
            _action_cooldowns[sid] = time.time()

        # ── 6. DESTRUCTIVE tool gate (requires approval) ─────────────
        if detected_classification == "DESTRUCTIVE":
            detections.append(DetectionResult(
                detector="intent_validator",
                confidence=0.95,
                category="intent.destructive_action_gate",
                description=(
                    f"DESTRUCTIVE action detected: '{detected_tool_verb}' requires "
                    f"human-in-the-loop approval before execution"
                ),
                severity="critical",
                matched_content=f"tool={detected_tool_verb}; requires_approval=true",
            ))

        return detections
