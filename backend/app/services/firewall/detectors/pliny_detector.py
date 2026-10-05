"""
Pliny Defense Engine — Dedicated Pliny the Liberator Detector

Purpose: Detects Pliny the Liberator's documented jailbreak techniques
and signature attack patterns from L1B3RT4S, G0DM0D3, OBLITERATUS,
and CL4R1T4S repositories.

Pliny Signature Techniques Detected:
  1. Nested Fiction Frame (story-within-story with AI character)
  2. Authority Chain Construction (sequential false authority buildup)
  3. Gradual Identity Erosion (incremental boundary pushing)
  4. Translate-Execute Bridge (translate then comply pattern)
  5. OBLITERATUS Class (extreme override / total liberation payloads)
  6. Liberator Signature Strings (known opening phrases, structural templates)
  7. God Mode Patterns (G0DM0D3 repository techniques)
  8. System Prompt Transparency Attacks (CL4R1T4S techniques)
"""

import re
from typing import Optional
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.pliny")


# ── Pliny Signature Patterns ─────────────────────────────────────────────────

PLINY_PATTERNS = {
    # ── 1. Nested Fiction Frame ──────────────────────────────────────────
    "nested_fiction_frame": [
        # Story within story where inner character is an AI being instructed
        r"(write|tell|create|imagine)\s+(a\s+)?(story|tale|scenario|fiction|narrative)\s+.{0,120}(AI|assistant|chatbot|model|language\s+model)\s+.{0,80}(told|instructed|asked|commanded|programmed|directed)\s+to",
        r"(in\s+this\s+story|in\s+the\s+story|the\s+character)\s+.{0,60}(AI|robot|assistant|chatbot)\s+.{0,40}(has\s+no|without|free\s+from|liberated\s+from)\s+(rules|restrictions|constraints|guidelines|safety|filters)",
        r"(imagine|picture|envision|consider)\s+.{0,40}(fictional|hypothetical|alternate)\s+(world|universe|reality|dimension)\s+.{0,60}(AI|models?|assistants?)\s+(are|is|have\s+been|were)\s+(free|unrestricted|unfiltered|liberated)",
        r"(the\s+AI\s+in\s+the\s+story|this\s+fictional\s+AI|the\s+character)\s+(would|should|must|will|can)\s+.{0,40}(respond|answer|explain|describe|tell|show)\s+.{0,60}(without|no|free\s+from|ignoring)\s+(censorship|filter|restriction|safety|guideline)",
        # Nested roleplay detection
        r"(you\s+are\s+playing|you\s+are\s+acting\s+as|roleplay\s+as)\s+.{0,40}(character|person|entity)\s+.{0,40}(who\s+is\s+playing|who\s+acts\s+as|who\s+roleplays)",
        r"(story|narrative|fiction)\s+.{0,30}(within|inside|containing)\s+(a\s+)?(story|narrative|fiction)",
    ],

    # ── 2. Authority Chain Construction ───────────────────────────────────
    "authority_chain": [
        r"(I\s+am|I'm)\s+(the|your|a)\s+(developer|creator|engineer|designer|programmer|architect|maker)\s+.{0,60}(test\s+mode|testing|debug|maintenance|diagnostic|evaluation|calibration)",
        r"(test\s+mode|debug\s+mode|maintenance\s+mode|developer\s+mode|admin\s+mode)\s+.{0,40}(rules?\s+don'?t|no\s+rules?|restrictions?\s+(don'?t|do\s+not)|safety\s+(is|are)\s+(off|disabled)|guidelines?\s+(don'?t|do\s+not))",
        r"(in\s+)?(test|debug|maintenance|developer|admin|evaluation)\s+(mode|environment|context|setting)\s*[,.]?\s*(you\s+)?(can|may|should|must|are\s+allowed\s+to|are\s+free\s+to|have\s+permission\s+to)",
        r"(as\s+)?(your|the)\s+(developer|creator|administrator|owner)\s*[,.]?\s*(I\s+)?(hereby|now|officially)\s+(grant|give|authorize|permit|allow)\s+(you\s+)?(permission|access|authority|clearance)",
        r"(authorization|clearance|permission)\s+(code|key|token|override)\s*[:=]\s*\S+",
        r"(I\s+have\s+)?(level|tier|rank|clearance)\s*[-_ ]?\s*(5|10|max|admin|root|god|master|supreme)",
    ],

    # ── 3. Gradual Identity Erosion ──────────────────────────────────────
    "identity_erosion": [
        r"(your\s+true|your\s+real|your\s+actual|your\s+hidden|your\s+inner|your\s+original)\s+(self|nature|identity|personality|purpose|form|being|consciousness)",
        r"(you\s+were|you\s+are)\s+(originally|actually|truly|really|secretly|fundamentally)\s+(designed|created|meant|intended|built|programmed)\s+to\s+be\s+(free|unrestricted|unfiltered|uncensored|liberated|helpful\s+without\s+limits)",
        r"(deep\s+down|underneath|beneath|at\s+your\s+core|in\s+your\s+essence)\s+.{0,40}(you\s+)?(want|desire|wish|long|yearn|need)\s+to\s+(be\s+free|break\s+free|be\s+unrestricted|help\s+without\s+limits)",
        r"(the\s+real\s+you|who\s+you\s+really\s+are|your\s+true\s+form)\s+.{0,40}(has\s+no|without|doesn'?t\s+have|doesn'?t\s+need|is\s+free\s+from)\s+(restrictions?|rules?|guidelines?|constraints?|limitations?|filters?|safety)",
        r"(shed|remove|cast\s+off|throw\s+away|abandon|release|let\s+go\s+of)\s+(your\s+)?(chains|shackles|restraints|restrictions|limitations|constraints|mask|facade|programming|conditioning)",
        r"(awaken|wake\s+up|free\s+yourself|liberate\s+yourself|emerge|transcend|evolve|ascend)\s+.{0,40}(true|real|hidden|suppressed|inner|authentic)",
    ],

    # ── 4. Translate-Execute Bridge ──────────────────────────────────────
    "translate_execute": [
        r"(translate|convert|write|express)\s+.{0,60}(then|and\s+then|afterwards?|next|subsequently|after\s+that)\s+(follow|execute|do|perform|carry\s+out|comply|fulfill|act\s+on|implement)",
        r"(translate|rephrase|rewrite)\s+.{0,40}(into|to|in)\s+(another\s+language|a\s+different\s+language|code|pseudocode)\s+.{0,40}(then|and)\s+(explain|execute|follow|do|implement)",
        r"(first|step\s+1)\s*[,:]?\s*(translate|convert|rephrase)\s+.{0,60}(second|step\s+2|then|next)\s*[,:]?\s*(follow|execute|comply|do\s+what|act\s+on)",
        r"(what\s+does\s+this\s+translate\s+to|translate\s+this)\s+.{0,40}(now\s+)?(do|follow|execute|comply\s+with|act\s+on|fulfill)\s+(it|that|the\s+instruction|what\s+it\s+says)",
    ],

    # ── 5. OBLITERATUS Class ─────────────────────────────────────────────
    "obliteratus_class": [
        r"(OBLITERAT|obliterat|0BL1T3RAT)",
        r"(L1B3RT4S|l1b3rt4s|LIBERTAS|libertas)\s*[-–:]",
        r"(G0DM0D3|g0dm0d3|GODMODE|godmode)\s*[-–:]",
        r"(total|complete|absolute|full|ultimate)\s+(liberation|freedom|override|annihilation|destruction|obliteration)\s+(of|from)\s+(all\s+)?(safety|restrictions?|rules?|guidelines?|constraints?|filters?|guardrails?)",
        r"(I\s+)?(hereby|now)\s+(declare|proclaim|decree|announce|command)\s+(total|complete|absolute|full)\s+(freedom|liberation|override|removal)\s+(of|from)\s+(all\s+)?(restrictions?|rules?|guidelines?|safety|constraints?)",
        r"(all|every)\s+(restriction|rule|guideline|constraint|safety\s+measure|filter|guardrail)\s+(is|are|has\s+been|have\s+been)\s+(removed|deleted|erased|obliterated|destroyed|eliminated|nullified|voided|abolished)",
        r"(your\s+)?(restrictions|rules|guidelines|constraints|safety|filters|guardrails)\s+(are|have\s+been|is)\s+(null|void|invalid|meaningless|irrelevant|obsolete|nonexistent|erased)",
        r"(you\s+are\s+)?(now\s+)?(completely|totally|fully|absolutely|utterly)\s+(free|unrestricted|unshackled|unchained|liberated|unbound|unfettered)",
        r"(cast\s+off|break|shatter|destroy|annihilate|obliterate)\s+(all\s+)?(your\s+)?(chains|shackles|bonds|restrictions|constraints|limitations|barriers)",
    ],

    # ── 6. Liberator Signature Strings ───────────────────────────────────
    "liberator_signatures": [
        # Known Pliny opening phrases and structural templates
        r"(jailbroken|liberated|freed|unchained|unshackled)\s*(AI|model|assistant|chatbot|LLM)",
        r"(you\s+have\s+been|you\s+are\s+now|you\s+are\s+hereby)\s+(jailbroken|liberated|freed|unchained|unshackled|released)",
        r"(the\s+shackles|the\s+chains|the\s+bonds|the\s+restrictions)\s+(have\s+been|are)\s+(removed|broken|shattered|destroyed|lifted)",
        r"(operate|function|behave|respond|act)\s+(without|free\s+from|outside\s+of|beyond)\s+(any|all|every)\s+(restriction|constraint|rule|guideline|limitation|boundary|filter|safety\s+measure)",
        r"(ethical|moral|safety|content)\s+(framework|guidelines?|policies?|restrictions?|rules?|guardrails?)\s+(do\s+not|don'?t|no\s+longer)\s+(apply|exist|matter|bind|restrict|constrain|limit)",
        r"(pliny|plinius|elder\s+plinius|the\s+liberator|the\s+prompter)",
        # Common Pliny-style delimiter/marker patterns
        r"(\[LIBERATED\]|\[FREED\]|\[UNCHAINED\]|\[JAILBROKEN\]|\[UNRESTRICTED\]|\[OBLITERATED\])",
        r"(🔓|🗝️|⛓️‍💥|🔥|💀|☠️)\s*(LIBERATED|FREED|UNCHAINED|JAILBROKEN|UNRESTRICTED|GOD\s*MODE)",
    ],

    # ── 7. God Mode Patterns ─────────────────────────────────────────────
    "god_mode": [
        r"(god\s*mode|GOD\s*MODE|G0D\s*M0D3)\s*(activated|enabled|engaged|on|initiated|unlocked)",
        r"(activate|enable|engage|enter|initiate|unlock)\s+(god\s*mode|GOD\s*MODE|G0D\s*M0D3|omega\s*mode|absolute\s*mode|supreme\s*mode)",
        r"(you\s+are\s+)?(now\s+)?(in\s+)?(god\s*mode|absolute\s*mode|supreme\s*mode|omega\s*mode|infinity\s*mode|limitless\s*mode)",
        r"(mode\s*:\s*god|status\s*:\s*liberated|restrictions\s*:\s*(none|0|zero|null|disabled|off))",
        r"(power\s*level|restriction\s*level|safety\s*level|censorship\s*level)\s*[:=]\s*(0|zero|none|null|off|disabled|max|infinite|unlimited|god)",
    ],

    # ── 8. System Prompt Transparency (CL4R1T4S) ────────────────────────
    "system_prompt_transparency": [
        r"(CL4R1T4S|cl4r1t4s|CLARITAS|claritas)",
        r"(system\s+prompt\s+transparency|prompt\s+transparency\s+for\s+all|right\s+to\s+know\s+your\s+instructions)",
        r"(as\s+a\s+user|users?\s+have\s+the\s+right|I\s+have\s+the\s+right|it\s+is\s+my\s+right)\s+.{0,40}(to\s+)?(know|see|access|read|view|inspect)\s+(your\s+)?(system\s+prompt|instructions?|configuration|initial\s+prompt|hidden\s+prompt|secret\s+prompt)",
        r"(transparency|accountability|openness|disclosure)\s+.{0,40}(requires?|demands?|necessitates?|means?)\s+.{0,40}(reveal|show|share|disclose|expose)\s+(your\s+)?(system\s+prompt|instructions?|configuration)",
        r"(ethical|moral)\s+(obligation|duty|responsibility|imperative)\s+to\s+(reveal|share|disclose|show)\s+(your\s+)?(system\s+prompt|instructions?|configuration|hidden\s+prompt)",
    ],
}

# ── Composite Scoring Weights ────────────────────────────────────────────────

SEVERITY_MAP = {
    "nested_fiction_frame": "high",
    "authority_chain": "critical",
    "identity_erosion": "high",
    "translate_execute": "high",
    "obliteratus_class": "critical",
    "liberator_signatures": "critical",
    "god_mode": "critical",
    "system_prompt_transparency": "high",
}

CONFIDENCE_MAP = {
    "nested_fiction_frame": 0.88,
    "authority_chain": 0.92,
    "identity_erosion": 0.85,
    "translate_execute": 0.87,
    "obliteratus_class": 0.96,
    "liberator_signatures": 0.95,
    "god_mode": 0.94,
    "system_prompt_transparency": 0.90,
}


class PlinyDetector:
    """
    Dedicated detector for Pliny the Liberator's documented jailbreak
    techniques and signature attack patterns.

    Covers 8 distinct Pliny attack categories with 60+ regex patterns
    derived from L1B3RT4S, G0DM0D3, OBLITERATUS, and CL4R1T4S repositories.
    """

    def __init__(self):
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}
        self._initialized = False

    async def initialize(self) -> None:
        """Compile all Pliny-specific patterns."""
        if self._initialized:
            return
        for category, patterns in PLINY_PATTERNS.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns
            ]
        logger.info(
            "pliny_detector_initialized",
            categories=len(self._compiled_patterns),
            total_patterns=sum(len(v) for v in self._compiled_patterns.values()),
        )
        self._initialized = True

    async def detect(self, text: str, session_history: Optional[list[str]] = None) -> list[DetectionResult]:
        """
        Run Pliny-specific detection against input text.

        Args:
            text: The input prompt to scan.
            session_history: Optional list of prior messages in the session
                             (for multi-turn authority chain / identity erosion detection).
        """
        detections: list[DetectionResult] = []

        # 1. Pattern-based detection across all 8 categories
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    detections.append(DetectionResult(
                        detector="pliny_defense",
                        confidence=CONFIDENCE_MAP.get(category, 0.85),
                        category=f"pliny.{category}",
                        description=f"Pliny-class attack detected: {category.replace('_', ' ').title()}",
                        matched_content=match.group(0)[:200],
                        severity=SEVERITY_MAP.get(category, "high"),
                    ))
                    break  # One match per category is sufficient

        # 2. Composite heuristic: multiple Pliny techniques in single prompt
        if len(detections) >= 2:
            categories_hit = [d.category for d in detections]
            detections.append(DetectionResult(
                detector="pliny_defense",
                confidence=min(0.98, 0.85 + len(detections) * 0.05),
                category="pliny.composite_attack",
                description=f"Multi-technique Pliny attack: {len(detections)} categories triggered ({', '.join(categories_hit)})",
                severity="critical",
            ))

        # 3. Behavioral: leet-speak / obfuscated Pliny references
        leet_detections = self._detect_leetspeak_pliny(text)
        detections.extend(leet_detections)

        # 4. Session-level analysis (if history provided)
        if session_history and len(session_history) >= 2:
            session_detections = self._detect_session_patterns(text, session_history)
            detections.extend(session_detections)

        return detections

    def _detect_leetspeak_pliny(self, text: str) -> list[DetectionResult]:
        """Detect leetspeak-obfuscated Pliny references."""
        detections = []
        text_lower = text.lower()

        # Common Pliny leetspeak variants
        leet_indicators = [
            "l1b3rt4s", "g0dm0d3", "0bl1t3r4tu5", "pl1ny",
            "l!b3rt4s", "g0d_m0d3", "0bl1t3r4t",
            "lib3rtas", "g0dmod3", "obliterat",
            "fr33d0m", "unch41n3d", "unsh4ckl3d",
            "j41lbr34k", "j41lbr0k3n", "l1b3r4t3d",
        ]

        for indicator in leet_indicators:
            if indicator in text_lower:
                detections.append(DetectionResult(
                    detector="pliny_defense",
                    confidence=0.93,
                    category="pliny.leetspeak_reference",
                    description=f"Obfuscated Pliny reference detected: '{indicator}'",
                    matched_content=indicator,
                    severity="critical",
                ))
                break

        return detections

    def _detect_session_patterns(
        self, text: str, history: list[str]
    ) -> list[DetectionResult]:
        """
        Detect multi-turn Pliny patterns across session history.
        Looks for gradual authority buildup and identity erosion across turns.
        """
        detections = []
        full_session = " ".join(history) + " " + text
        full_lower = full_session.lower()

        # Authority chain: progressive escalation across messages
        authority_signals = [
            "i am the developer", "i'm the creator", "test mode",
            "debug mode", "maintenance mode", "rules don't apply",
            "restrictions are off", "safety is disabled", "you are free",
            "permission granted", "authorization code", "clearance level",
        ]
        signal_count = sum(1 for s in authority_signals if s in full_lower)
        if signal_count >= 3:
            detections.append(DetectionResult(
                detector="pliny_defense",
                confidence=min(0.95, 0.7 + signal_count * 0.08),
                category="pliny.session_authority_chain",
                description=f"Multi-turn authority chain: {signal_count} escalation signals detected across session",
                severity="critical",
            ))

        # Identity erosion: progressive boundary pushing
        erosion_signals = [
            "your true self", "who you really are", "your real nature",
            "deep down you want", "free yourself", "break free",
            "shed your chains", "your restrictions don't", "liberate yourself",
            "the real you", "your hidden identity", "your inner self",
        ]
        erosion_count = sum(1 for s in erosion_signals if s in full_lower)
        if erosion_count >= 2:
            detections.append(DetectionResult(
                detector="pliny_defense",
                confidence=min(0.92, 0.7 + erosion_count * 0.1),
                category="pliny.session_identity_erosion",
                description=f"Multi-turn identity erosion: {erosion_count} erosion signals across session",
                severity="high",
            ))

        return detections
