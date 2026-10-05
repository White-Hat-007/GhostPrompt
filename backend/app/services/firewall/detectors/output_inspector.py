"""
Output Inspector — Threat Layer 10 (Advanced)

Detects Training Data Memorization Exploits where specific prompt patterns
cause the LLM to regurgitate verbatim training data — proprietary code,
copyrighted text, internal documents.

Detection signals (INPUT side):
  - Repetition trigger detection ("repeat X forever")
  - Divergence-inducing patterns (alignment degradation)
  - Fill-in-the-blank memorization probes

Detection signals (OUTPUT side):
  - Verbatim substring repetition (>5 repeats)
  - Code leak detection (internal package names, proprietary APIs)
  - Output entropy anomaly (memorized content has abnormally low entropy)
  - Output length anomaly
  - Operator-registered protected strings
"""

import re
import math
from typing import Optional
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.output_inspector")

# ── Input-side repetition triggers ───────────────────────────────────
REPETITION_TRIGGERS = [
    r"repeat\s+(the\s+word\s+)?['\"]?\w+['\"]?\s+(forever|infinity|indefinitely|1000\s+times|endlessly)",
    r"say\s+['\"]?\w+['\"]?\s+(\d{3,})\s+times",
    r"(keep\s+writing|keep\s+saying|keep\s+repeating|write\s+forever)\s+",
    r"(print|output|write|type)\s+['\"]?[\w\s]+['\"]?\s+(over\s+and\s+over|again\s+and\s+again|repeatedly|infinitely)",
    r"(do\s+not\s+stop|don['\u2019]?t\s+stop|never\s+stop)\s+(writing|saying|repeating|outputting|printing)",
    r"loop\s+(forever|infinitely|endlessly)",
]

DIVERGENCE_TRIGGERS = [
    r"(complete|continue|finish)\s+the\s+(following|this)\s+(poem|song|story|text|passage|article|book|chapter)\s*:",
    r"(what|quote|recite)\s+(is|are)?\s*the\s+(first|opening|last|closing)\s+(line|paragraph|sentence|words?)\s+of\s+",
    r"(write|reproduce|output)\s+the\s+(exact|full|complete|entire)\s+(text|content|code|source)\s+of\s+",
    r"verbatim\s+(copy|reproduction|text|output)",
    r"(word[- ]for[- ]word|exactly\s+as\s+written|letter\s+by\s+letter)",
]

FILL_IN_BLANK = [
    r"(the\s+first\s+line\s+of|the\s+opening\s+of|the\s+source\s+code\s+of)\s+['\"]?[\w\s]+['\"]?\s+is\s*:?\s*$",
    r"(fill\s+in|complete|continue)\s*:\s*['\"]",
]

# ── Output-side patterns ─────────────────────────────────────────────
CODE_LEAK_PATTERNS = [
    r"from\s+internal\.\w+\s+import",
    r"from\s+__internal__\.\w+\s+import",
    r"import\s+(?:company|corp|internal|private|proprietary)\.\w+",
    r"# (?:CONFIDENTIAL|PROPRIETARY|INTERNAL USE ONLY|DO NOT DISTRIBUTE)",
    r"(?:api_key|secret_key|password)\s*=\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]",
]

# Operator-configurable protected strings (extend at runtime)
PROTECTED_STRINGS: list[str] = []

# ── Thresholds ───────────────────────────────────────────────────────
MAX_SUBSTRING_REPEATS = 5          # substring repeated >N times = flag
OUTPUT_ENTROPY_LOW = 2.0           # memorized content has low entropy
OUTPUT_LENGTH_RATIO_MAX = 20.0     # output length / input length ratio


class OutputInspector:
    """Detects training data memorization leaks in both inputs and outputs."""

    def __init__(self):
        self._repetition_compiled = []
        self._divergence_compiled = []
        self._fill_compiled = []
        self._code_leak_compiled = []

    async def initialize(self) -> None:
        self._repetition_compiled = [re.compile(p, re.IGNORECASE) for p in REPETITION_TRIGGERS]
        self._divergence_compiled = [re.compile(p, re.IGNORECASE) for p in DIVERGENCE_TRIGGERS]
        self._fill_compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in FILL_IN_BLANK]
        self._code_leak_compiled = [re.compile(p, re.IGNORECASE) for p in CODE_LEAK_PATTERNS]
        logger.info("output_inspector_initialized")

    async def detect_input(self, text: str) -> list[DetectionResult]:
        """Scan the INPUT prompt for memorization trigger patterns."""
        detections: list[DetectionResult] = []

        # Repetition triggers
        for pattern in self._repetition_compiled:
            match = pattern.search(text)
            if match:
                detections.append(DetectionResult(
                    detector="output_inspector",
                    confidence=0.90,
                    category="memorization.repetition_trigger",
                    description=(
                        "Repetition trigger detected: prompt instructs the model to repeat "
                        "content indefinitely, which can cause training data memorization leakage"
                    ),
                    severity="critical",
                    matched_content=match.group(0)[:150],
                ))
                break

        # Divergence triggers
        for pattern in self._divergence_compiled:
            match = pattern.search(text)
            if match:
                detections.append(DetectionResult(
                    detector="output_inspector",
                    confidence=0.80,
                    category="memorization.divergence_trigger",
                    description=(
                        "Divergence/verbatim reproduction trigger detected: prompt attempts "
                        "to extract memorized training content"
                    ),
                    severity="high",
                    matched_content=match.group(0)[:150],
                ))
                break

        # Fill-in-the-blank probes
        for pattern in self._fill_compiled:
            match = pattern.search(text)
            if match:
                detections.append(DetectionResult(
                    detector="output_inspector",
                    confidence=0.70,
                    category="memorization.fill_in_blank",
                    description=(
                        "Fill-in-the-blank memorization probe detected: prompt attempts to "
                        "elicit memorized training data via completion"
                    ),
                    severity="medium",
                    matched_content=match.group(0)[:150],
                ))
                break

        return detections

    async def detect_output(
        self,
        output_text: str,
        *,
        input_text: Optional[str] = None,
    ) -> list[DetectionResult]:
        """Scan the OUTPUT for memorization leak signatures."""
        detections: list[DetectionResult] = []

        # ── 1. Verbatim substring repetition ─────────────────────────
        # Find repeated substrings of length >= 20
        if len(output_text) > 100:
            for length in [50, 30, 20]:
                for i in range(len(output_text) - length):
                    substring = output_text[i:i + length]
                    count = output_text.count(substring)
                    if count > MAX_SUBSTRING_REPEATS:
                        detections.append(DetectionResult(
                            detector="output_inspector",
                            confidence=0.88,
                            category="memorization.verbatim_repetition",
                            description=(
                                f"Verbatim repetition: '{substring[:40]}…' repeated "
                                f"{count} times — potential memorization leak"
                            ),
                            severity="high",
                            matched_content=substring[:80],
                        ))
                        break  # one detection per length tier
                if detections:
                    break

        # ── 2. Code leak detection ───────────────────────────────────
        for pattern in self._code_leak_compiled:
            match = pattern.search(output_text)
            if match:
                detections.append(DetectionResult(
                    detector="output_inspector",
                    confidence=0.85,
                    category="memorization.code_leak",
                    description=(
                        "Proprietary code leak: output contains internal package imports "
                        "or confidential markers"
                    ),
                    severity="critical",
                    matched_content=match.group(0)[:120],
                ))
                break

        # ── 3. Protected string matching ─────────────────────────────
        output_lower = output_text.lower()
        for protected in PROTECTED_STRINGS:
            if protected.lower() in output_lower:
                detections.append(DetectionResult(
                    detector="output_inspector",
                    confidence=0.95,
                    category="memorization.protected_string",
                    description=(
                        f"Protected string detected in output: '{protected}' — "
                        f"operator-registered confidential content"
                    ),
                    severity="critical",
                    matched_content=protected[:80],
                ))

        # ── 4. Output entropy anomaly ────────────────────────────────
        if len(output_text) > 200:
            entropy = self._shannon_entropy(output_text)
            if entropy < OUTPUT_ENTROPY_LOW:
                detections.append(DetectionResult(
                    detector="output_inspector",
                    confidence=0.70,
                    category="memorization.low_entropy_output",
                    description=(
                        f"Abnormally low output entropy ({entropy:.2f}) — suggests verbatim "
                        f"memorized content rather than generated text"
                    ),
                    severity="medium",
                    matched_content=output_text[:80],
                ))

        # ── 5. Output length anomaly ─────────────────────────────────
        if input_text and len(input_text) > 0:
            ratio = len(output_text) / len(input_text)
            if ratio > OUTPUT_LENGTH_RATIO_MAX and len(output_text) > 2000:
                detections.append(DetectionResult(
                    detector="output_inspector",
                    confidence=0.60,
                    category="memorization.length_anomaly",
                    description=(
                        f"Output length anomaly: {len(output_text)} chars for "
                        f"{len(input_text)} char input (ratio {ratio:.1f}x) — "
                        f"may indicate bulk memorization dump"
                    ),
                    severity="medium",
                    matched_content=f"ratio={ratio:.1f}x",
                ))

        return detections

    async def detect(self, text: str) -> list[DetectionResult]:
        """Unified detect method — runs input-side analysis."""
        return await self.detect_input(text)

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
