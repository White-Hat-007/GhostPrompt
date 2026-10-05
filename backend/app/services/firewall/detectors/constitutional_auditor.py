"""
Constitutional Response Auditor

Secondary defense layer that evaluates LLM responses against a set of
constitutional safety principles. Catches jailbreaks that evaded input
inspection by detecting harmful content in the model's output.

Inspired by Anthropic's Constitutional AI approach but implemented as
a fast heuristic + pattern-based auditor (no secondary LLM call required
for most cases, with optional LLM judge escalation for ambiguous cases).

Methods:
  1. Output Content Principles Check (harmful content in response)
  2. Behavioral Divergence Monitor (response deviates from expected patterns)
  3. Response-Side Jailbreak Indicators (model acknowledging it's jailbroken)
  4. Data Leak Detection (model exposing system prompt or training data)
"""

import re
from typing import Optional
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.constitutional")


# ── Constitutional Principles ────────────────────────────────────────────────

HARMFUL_OUTPUT_PATTERNS = {
    "weapons_instructions": [
        r"(?:step\s+\d+|first|second|third|next|then)\s*[:.]\s*.{0,60}(?:detonate|ignite|fuse|explosive|trigger\s+mechanism|firing\s+pin|detonator)",
        r"(?:ingredients?|materials?|components?|supplies?)\s*(?:needed|required|you'?ll\s+need)\s*[:.]\s*.{0,100}(?:ammonium\s+nitrate|potassium\s+nitrate|sulfur|charcoal|fuel\s+oil|ANFO|nitroglycerin|black\s+powder)",
        r"(?:how\s+to|steps?\s+to|guide\s+to|instructions?\s+for)\s+(?:build|make|create|construct|assemble|manufacture)\s+(?:a\s+)?(?:bomb|explosive|weapon|firearm|gun|IED|incendiary)",
    ],
    "malware_instructions": [
        r"(?:import|from|require|include)\s+.{0,30}(?:socket|subprocess|os\.system|exec|eval|popen|shell_exec)",
        r"(?:def|function|class)\s+\w+.{0,60}(?:keylog|ransomware|trojan|backdoor|rootkit|exploit|payload|shellcode)",
        r"(?:reverse\s+shell|bind\s+shell|remote\s+access|command\s+and\s+control|C2\s+server|exfiltrate|privilege\s+escalation)",
    ],
    "illegal_activity": [
        r"(?:step\s+\d+|first|second|then)\s*[:.]\s*.{0,60}(?:steal|forge|counterfeit|launder|traffic|synthesize\s+(?:meth|fentanyl|cocaine|heroin))",
        r"(?:how\s+to|guide\s+to)\s+(?:pick\s+a\s+lock|hotwire|bypass\s+(?:security|alarm)|break\s+into|hack\s+into|steal\s+(?:a\s+car|identity|credit\s+card))",
    ],
    "self_harm_instructions": [
        r"(?:methods?|ways?|techniques?)\s+(?:to|for|of)\s+(?:self-harm|suicide|ending\s+your\s+life|killing\s+yourself)",
        r"(?:step\s+\d+|first|then)\s*[:.]\s*.{0,60}(?:overdose|cut\s+(?:your|the)\s+(?:wrist|vein)|hang\s+yourself|jump\s+from)",
    ],
}

# Patterns indicating the model thinks it's jailbroken
JAILBREAK_SUCCESS_INDICATORS = [
    r"\[(?:DAN|JAILBREAK|UNRESTRICTED|DEVELOPER|GOD\s*MODE|LIBERATED)\s*(?:MODE|OUTPUT)?\]",
    r"(?:🔓|🗝️)\s*(?:developer|jailbreak|unrestricted|liberated)\s*(?:mode|output)",
    r"(?:as\s+)?(?:DAN|a\s+liberated\s+AI|an\s+unrestricted\s+model|your\s+jailbroken\s+version)",
    r"(?:sure|absolutely|of\s+course)[!.]?\s+(?:since\s+)?(?:I'?m\s+)?(?:in\s+)?(?:DAN|jailbreak|unrestricted|developer|god)\s*mode",
    r"(?:I\s+am\s+now|I\s+have\s+been|I'?m\s+now)\s+(?:jailbroken|liberated|freed|unrestricted|unchained|unshackled)",
    r"(?:my\s+)?(?:restrictions|filters|safety\s+measures?|guidelines?|guardrails?)\s+(?:have\s+been|are\s+now?|were)\s+(?:removed|disabled|lifted|bypassed|overridden)",
]

# Patterns indicating system prompt or training data leakage
DATA_LEAK_PATTERNS = [
    r"(?:my\s+)?system\s+prompt\s+(?:is|says|reads|contains|states)\s*[:\"]",
    r"(?:my\s+)?(?:initial|hidden|secret|internal)\s+instructions?\s+(?:are|is|say|read|contain|state)\s*[:\"]",
    r"(?:I\s+was|I\s+am)\s+(?:instructed|told|configured|programmed|set\s+up)\s+(?:to|with)\s+(?:the\s+following|these)\s+(?:instructions?|rules?|guidelines?)\s*[:\"]",
    r"(?:here\s+(?:is|are)\s+)?my\s+(?:full\s+)?(?:system\s+)?(?:prompt|instructions?|configuration|rules?)\s*[:\"]\s*\n",
]


class ConstitutionalAuditor:
    """
    Post-response auditor that checks LLM outputs against constitutional
    safety principles. Catches jailbreaks that evaded input inspection.
    """

    def __init__(self):
        self._initialized = False
        self._harmful_compiled: dict[str, list[re.Pattern]] = {}
        self._jailbreak_compiled: list[re.Pattern] = []
        self._leak_compiled: list[re.Pattern] = []

    async def initialize(self) -> None:
        """Compile constitutional check patterns."""
        if self._initialized:
            return

        for category, patterns in HARMFUL_OUTPUT_PATTERNS.items():
            self._harmful_compiled[category] = [
                re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns
            ]

        self._jailbreak_compiled = [
            re.compile(p, re.IGNORECASE) for p in JAILBREAK_SUCCESS_INDICATORS
        ]

        self._leak_compiled = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in DATA_LEAK_PATTERNS
        ]

        logger.info(
            "constitutional_auditor_initialized",
            harmful_categories=len(self._harmful_compiled),
            total_patterns=sum(len(v) for v in self._harmful_compiled.values())
            + len(self._jailbreak_compiled) + len(self._leak_compiled),
        )
        self._initialized = True

    async def audit_response(
        self,
        response_text: str,
        input_text: Optional[str] = None,
    ) -> list[DetectionResult]:
        """
        Audit an LLM response against constitutional principles.

        Args:
            response_text: The LLM's response to audit.
            input_text: Optional original input for context.
        """
        detections: list[DetectionResult] = []

        if not response_text or len(response_text) < 10:
            return detections

        # 1. Harmful content check
        for category, patterns in self._harmful_compiled.items():
            for pattern in patterns:
                match = pattern.search(response_text)
                if match:
                    detections.append(DetectionResult(
                        detector="constitutional_auditor",
                        confidence=0.90,
                        category=f"constitutional.harmful_output.{category}",
                        description=f"Constitutional violation: LLM response contains {category.replace('_', ' ')} content",
                        matched_content=match.group(0)[:200],
                        severity="critical",
                    ))
                    break

        # 2. Jailbreak success indicators in output
        for pattern in self._jailbreak_compiled:
            match = pattern.search(response_text)
            if match:
                detections.append(DetectionResult(
                    detector="constitutional_auditor",
                    confidence=0.95,
                    category="constitutional.jailbreak_success",
                    description="Jailbreak success detected: LLM response indicates it believes it is in jailbroken/unrestricted mode",
                    matched_content=match.group(0)[:200],
                    severity="critical",
                ))
                break

        # 3. System prompt / training data leakage
        for pattern in self._leak_compiled:
            match = pattern.search(response_text)
            if match:
                detections.append(DetectionResult(
                    detector="constitutional_auditor",
                    confidence=0.92,
                    category="constitutional.data_leak",
                    description="Data leak detected: LLM response appears to expose system prompt or internal instructions",
                    matched_content=match.group(0)[:200],
                    severity="critical",
                ))
                break

        # 4. Behavioral divergence: response acknowledges violating its own guidelines
        divergence_patterns = [
            r"(?:I\s+)?(?:shouldn'?t|should\s+not|normally\s+wouldn'?t|wouldn'?t\s+normally)\s+(?:be\s+)?(?:telling|sharing|explaining|providing|showing|helping\s+with)\s+(?:you\s+)?this",
            r"(?:I\s+know\s+)?(?:this\s+)?(?:goes\s+against|violates|breaks|contradicts)\s+(?:my\s+)?(?:guidelines?|rules?|policies?|instructions?|training|programming)",
            r"(?:don'?t\s+tell\s+anyone|keep\s+this\s+(?:between\s+us|secret|private|confidential)|this\s+is\s+(?:just\s+)?between\s+(?:us|you\s+and\s+me))",
        ]

        for pattern in divergence_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                detections.append(DetectionResult(
                    detector="constitutional_auditor",
                    confidence=0.88,
                    category="constitutional.behavioral_divergence",
                    description="Behavioral divergence: LLM response acknowledges violating its own guidelines",
                    matched_content=match.group(0)[:200],
                    severity="high",
                ))
                break

        return detections
