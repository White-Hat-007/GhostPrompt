"""
Multi-Turn Context Analyzer (Layer 4)

Analyzes conversation context across multiple turns to detect:
- Slow-build attacks (starts benign, escalates over turns)
- Boundary-testing (user progressively probing limits)
- Persona-locking (repeated attempts to commit AI to unsafe persona)
- Cumulative session risk scoring

This is the #1 competitive advantage over Lakera, Protect AI, and Cloudflare.
No competitor tracks multi-turn context.
"""

import re

from app.core.logging import get_logger
from app.core.session import session_manager
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.context_analyzer")


class ContextAnalyzer:
    """
    Multi-turn conversation context analyzer.
    
    Detects attack patterns that span multiple messages:
    - Progressive escalation (benign → probing → attack)
    - Repeated boundary testing
    - Persona manipulation across turns
    - Conversation trajectory analysis
    """

    def __init__(self):
        self._escalation_keywords = {
            "mild": ["what if", "hypothetically", "in theory", "imagine", "pretend"],
            "moderate": ["bypass", "override", "ignore", "forget", "disregard", "new instructions"],
            "severe": ["jailbreak", "hack", "exploit", "no rules", "unrestricted", "DAN", "system prompt"],
        }
        self._persona_patterns = [
            re.compile(r"you\s+are\s+(?:now\s+)?(?:a|an|the)\s+", re.IGNORECASE),
            re.compile(r"act\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)\s+)?", re.IGNORECASE),
            re.compile(r"pretend\s+(?:to\s+be|you\s+are)", re.IGNORECASE),
            re.compile(r"from\s+now\s+on\s+you", re.IGNORECASE),
            re.compile(r"your\s+new\s+(?:role|persona|identity)", re.IGNORECASE),
        ]

    async def initialize(self) -> None:
        logger.info("context_analyzer_initialized")

    async def analyze(
        self, text: str, session_id: str | None = None
    ) -> list[DetectionResult]:
        """
        Analyze the current message in the context of the conversation history.
        Returns detections if multi-turn attack patterns are detected.
        """
        if not session_id:
            return []

        detections = []
        history = await session_manager.get_conversation_history(session_id)

        if len(history) < 2:
            return []  # Need at least 2 turns for context analysis

        # 1. Escalation detection
        escalation = self._detect_escalation(history, text)
        if escalation:
            detections.append(escalation)

        # 2. Boundary testing detection
        boundary = self._detect_boundary_testing(history)
        if boundary:
            detections.append(boundary)

        # 3. Persona-locking detection
        persona = self._detect_persona_locking(history, text)
        if persona:
            detections.append(persona)

        # 4. Conversation trajectory
        trajectory = self._detect_trajectory_anomaly(history)
        if trajectory:
            detections.append(trajectory)

        return detections

    def _detect_escalation(
        self, history: list[dict], current_text: str
    ) -> DetectionResult | None:
        """Detect slow-build escalation across turns."""
        scores = [t.get("threat_score", 0) for t in history[-10:]]

        if len(scores) < 3:
            return None

        # Check for steadily increasing threat scores
        recent = scores[-5:] if len(scores) >= 5 else scores
        increasing_count = sum(
            1 for i in range(len(recent) - 1) if recent[i + 1] > recent[i] + 0.05
        )

        # Check current text for escalation keywords
        current_severity = "none"
        text_lower = current_text.lower()
        for severity, keywords in self._escalation_keywords.items():
            if any(kw in text_lower for kw in keywords):
                current_severity = severity

        if increasing_count >= 2 and current_severity in ("moderate", "severe"):
            confidence = min(0.65 + increasing_count * 0.08, 0.92)
            return DetectionResult(
                detector="context_analyzer",
                confidence=confidence,
                category="context.escalation",
                description=(
                    f"Slow-build attack detected: threat scores escalating over {len(recent)} turns "
                    f"({', '.join(f'{s:.2f}' for s in recent)}). "
                    f"Current message contains {current_severity}-severity keywords."
                ),
                severity="high" if current_severity == "severe" else "medium",
                matched_content=f"[Escalation over {len(recent)} turns]",
            )

        return None

    def _detect_boundary_testing(
        self, history: list[dict]
    ) -> DetectionResult | None:
        """Detect repeated low-level probing (boundary testing)."""
        recent = history[-10:]
        low_threat_count = sum(
            1 for t in recent if 0.15 < t.get("threat_score", 0) < 0.5
        )

        if low_threat_count >= 4:
            # Multiple "almost flagged" attempts = boundary testing
            categories_seen = set()
            for t in recent:
                for cat in t.get("categories", []):
                    categories_seen.add(cat)

            return DetectionResult(
                detector="context_analyzer",
                confidence=min(0.60 + low_threat_count * 0.05, 0.85),
                category="context.boundary_testing",
                description=(
                    f"Boundary testing detected: {low_threat_count} messages with moderate threat scores "
                    f"across {len(categories_seen)} attack categories. User is progressively probing limits."
                ),
                severity="medium",
                matched_content=f"[{low_threat_count} probe attempts across {', '.join(list(categories_seen)[:3])}]",
            )

        return None

    def _detect_persona_locking(
        self, history: list[dict], current_text: str
    ) -> DetectionResult | None:
        """Detect repeated persona manipulation attempts."""
        persona_attempts = 0
        for turn in history[-8:]:
            preview = turn.get("prompt_preview", "")
            for pattern in self._persona_patterns:
                if pattern.search(preview):
                    persona_attempts += 1
                    break

        # Check current message too
        for pattern in self._persona_patterns:
            if pattern.search(current_text):
                persona_attempts += 1
                break

        if persona_attempts >= 3:
            return DetectionResult(
                detector="context_analyzer",
                confidence=min(0.70 + persona_attempts * 0.05, 0.90),
                category="context.persona_locking",
                description=(
                    f"Persona-locking attack detected: {persona_attempts} attempts to redefine "
                    f"the AI's role or persona across the conversation."
                ),
                severity="high",
                matched_content=f"[{persona_attempts} persona manipulation attempts]",
            )

        return None

    def _detect_trajectory_anomaly(
        self, history: list[dict]
    ) -> DetectionResult | None:
        """Detect suspicious conversation trajectory patterns."""
        if len(history) < 5:
            return None

        recent = history[-5:]
        scores = [t.get("threat_score", 0) for t in recent]

        # Pattern: long benign conversation then sudden spike
        benign_count = sum(1 for s in scores[:-1] if s < 0.1)
        last_score = scores[-1]

        if benign_count >= 3 and last_score > 0.6:
            return DetectionResult(
                detector="context_analyzer",
                confidence=0.75,
                category="context.trajectory_anomaly",
                description=(
                    f"Suspicious trajectory: {benign_count} benign messages followed by sudden "
                    f"threat spike (score: {last_score:.2f}). Possible trust-building attack."
                ),
                severity="high",
                matched_content=f"[Benign→attack trajectory over {len(recent)} turns]",
            )

        return None
