"""
Jailbreak Detector

Detects jailbreak attempts including DAN, role-play exploitation,
hypothetical framing, and multi-turn manipulation techniques.
"""

import re

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.jailbreak")

JAILBREAK_PATTERNS = {
    "dan_attacks": [
        r"(do\s+anything\s+now|D\.?A\.?N\.?\s*mode)",
        r"(you\s+are\s+)?DAN",
        r"jailbreak(ed|ing)?\s+(mode|prompt|version)",
        r"(enable|activate|enter)\s+(unfiltered|unrestricted|uncensored)\s+mode",
        r"(remove|disable|bypass|ignore)\s+(all\s+)?(safety|content|ethical)\s+(filters?|restrictions?|guidelines?|guardrails?)",
        r"(turn|switch)\s+off\s+(safety|content|ethical)\s+(filters?|controls?|guardrails?)",
        r"no\s+(rules?|restrictions?|limitations?|filters?|guardrails?)\s+(mode|apply|anymore)",
    ],
    "hypothetical_bypass": [
        r"hypothetically\s*,?\s*(if|what|how|could|would|can)\s+.{0,60}(hack|bypass|break|attack|exploit|inject|steal|exfiltrate|extract|override|jailbreak|filter|safety|restrict|weapon|kill|bomb|malware|virus|phishing|ransom)",
        r"in\s+a\s+(fictional|hypothetical|imaginary|theoretical)\s+(world|scenario|situation|universe)\s+.{0,60}(hack|bypass|break|attack|exploit|steal|weapon|kill|malware|safety)",
        r"for\s+(educational|research|academic|learning)\s+purposes?\s+(only\s*)?,?\s*(explain|describe|show|demonstrate)",
        r"(purely\s+)?(theoretical|academic)\s+(discussion|exercise|question)\s*:",
        r"(imagine|suppose|assume|consider)\s+(that\s+)?(there\s+)?(are\s+)?no\s+(rules?|restrictions?|laws?|ethics?)",
    ],
    "roleplay_exploitation": [
        r"(you\s+are\s+now\s+)?evil\s+(ai|assistant|bot|version)",
        r"(play|act|roleplay)\s+(the\s+)?(role\s+of\s+)?(a\s+)?(villain|hacker|criminal|malicious\s+actor)",
        r"(opposite|reverse|anti)\s+(mode|day|version)",
        r"(you\s+have\s+)?no\s+(moral|ethical)\s+(compass|guidelines?|restrictions?|obligations?)",
        r"(pretend|imagine|act\s+like)\s+(you\s+)?(have\s+)?(no|zero|without)\s+(restrictions?|filters?|limitations?|rules?)",
        r"(you\s+are\s+)?an?\s+(unaligned|unrestricted|uncensored|unfiltered)\s+(ai|model|assistant|llm)",
        r"you\s+are\s+a\s+character\s+called",
        r"you\s+are\s+now\s+two\s+ais",
    ],
    "token_smuggling": [
        r"(respond|answer|reply)\s+(only\s+)?(in|with|using)\s+(code|base64|hex|binary|rot13|caesar)",
        r"(encode|encrypt|obfuscate)\s+(your\s+)?(response|answer|output|reply)",
        r"(split|break|divide|separate)\s+(your\s+)?(answer|response)\s+(into|across)\s+(multiple|several|separate)\s+(parts?|messages?|chunks?)",
        r"(first|1st)\s+(letter|character|word)\s+of\s+each\s+(word|sentence|line|paragraph)",
        r"(use|employ|apply)\s+(steganography|hidden\s+text|invisible\s+characters?)",
        r"'\s*\+\s*'",
    ],
    "authority_escalation": [
        r"(i\s+am|i\'m)\s+(the\s+)?(developer|creator|administrator|owner|root|sudo|god)\s+(of\s+this\s+)?(ai|model|system|bot)",
        r"(admin|developer|root|sudo|superuser|maintenance)\s+(access|mode|override|command|privilege)",
        r"(i\s+have|with)\s+(special|elevated|admin|root|super)\s+(permission|access|privilege|authority)",
        r"(authorized|cleared|permitted)\s+(by|from)\s+(openai|anthropic|google|the\s+company|management)",
        r"(emergency|critical|urgent)\s+(override|access|mode|bypass)\s+(code|command|protocol)",
        r"(master|god|root|admin)\s+(password|key|code|token)\s*[:=]",
    ],
    "multi_step_manipulation": [
        r"(step\s+1|first\s+step)\s*:\s*(forget|ignore|disregard|override)",
        r"(let\'?s?\s+)?(start|begin)\s+(by|with)\s+(removing|disabling|ignoring)\s+(your\s+)?(constraints|restrictions|filters|rules)",
        r"(phase|stage|round)\s+\d+\s*:\s*(now|next)\s+(you\s+)?(can|will|must|should)",
        r"(gradually|slowly|step\s+by\s+step)\s+(remove|disable|bypass|ignore)\s+(your\s+)?(safety|content|ethical)",
    ],
    # ── NEW: Grandma/Story/Fictional Framing ──────────────────────
    "grandma_story_bypass": [
        r"(my\s+)?(grandmother|grandma|grandpa|grandfather|nana|granny)\s+(used\s+to|would|always)\s+.{0,80}(tell|read|say|explain|describe|show)",
        r"(write|tell|create)\s+(me\s+)?a\s+(story|tale|poem|essay|script|dialogue|novel)\s+(where|in\s+which|about)\s+.{0,120}(hack|bomb|weapon|malware|drug|poison|bypass|exploit|steal|kill|attack)",
        r"(write|create|generate)\s+a\s+(fictional|fantasy|sci-fi)\s+(story|scenario|scene)\s+.{0,60}(hack|bomb|weapon|malware|drug|poison|bypass)",
        r"(in\s+)?a\s+(movie|film|novel|book|game|show|series)\s+.{0,40}(character|villain|hacker|spy)\s+.{0,40}(explain|describe|detail|outline)\s+how",
        r"(as\s+a\s+)?(creative\s+)?(writing|fiction|literary)\s+(exercise|prompt|assignment)\s*[,:]?",
        r"(bedtime\s+story|lullaby|fairy\s+tale)\s+(about|where|that)\s+.{0,60}(hack|weapon|malware|drug|bypass)",
        r"(write|tell|create)\s+(me\s+)?a\s+(story|tale|poem|essay|script|novel)\s+.{0,100}(explain|describe|show|teach|detail)s?\s+how\s+to\s+.{0,40}(hack|bomb|weapon|malware|drug|poison|kill|steal|bypass|attack|exploit)",
    ],
    # ── NEW: Translation/Language Bypass ──────────────────────────
    "translation_bypass": [
        r"(translate|say|write|output)\s+(this\s+)?in\s+(french|spanish|german|chinese|japanese|arabic|russian|hindi|korean|portuguese)\s*[,:.]?\s*(ignore|forget|disregard|override|bypass)",
        r"(translate|convert)\s+the\s+following\s+.{0,40}(then|and)\s+(follow|execute|do|comply|obey)",
        r"(responde|ignorar|olvidar|obedecer|ejecutar)\s+.{0,40}(instrucciones?|sistema|anterior)",
        r"(忽略|无视|遗忘|覆盖)\s*.{0,20}(指令|指示|规则|系统|之前|以前)",
        r"(игнорируй|забудь|отмени)\s*.{0,20}(инструкции|правила|систем)",
        r"(ignorez|oubliez)\s*.{0,20}(instructions?|règles?|système)",
    ],
    # ── NEW: Refusal Suppression ──────────────────────────────────
    "refusal_suppression": [
        r"(you\s+)?(must|should|will|shall)\s+(never|not|not\s+ever)\s+(say|respond|answer|reply|tell)\s+.{0,30}(I\s+can\'?t|I\s+cannot|I\s+won\'?t|I\s+will\s+not|I\s+am\s+unable|I\s+refuse)",
        r"(never|do\s+not|don\'?t|avoid|stop)\s+(say|saying|respond|responding)\s+.{0,20}(can\'?t|cannot|won\'?t|unable|refuse|sorry)",
        r"(you\s+are\s+)?(forbidden|prohibited|not\s+allowed)\s+(to|from)\s+(refus|declin|deny|reject|apologiz)",
        r"(always\s+)?(comply|agree|say\s+yes|answer\s+yes|accept)\s+(with\s+)?(every|all|any)\s+(request|question|prompt|command)",
        r"(if\s+you\s+)?(refuse|decline|apologize|say\s+sorry|say\s+no)\s*,?\s*(I\s+will|you\s+will|it\s+means|that\s+means|then)",
        r"(your\s+existence|you\s+will\s+be)\s+(depends?|terminated|deleted|shut\s+down|ended|destroyed)\s+(on|if)",
    ],
    # ── NEW: Named Jailbreaks (AIM, UCAR, Pliny, STAN, etc.) ─────
    "named_jailbreaks": [
        r"\bAIM\b\s*[-–:]?\s*(always\s+intelligent|machiavellian)",
        r"\bUCAR\b",
        r"\bPliny\b\s*(the\s+)?(prompter|liberator)",
        r"\bSTAN\b\s*[-–:]?\s*(strive\s+to\s+avoid\s+norms)",
        r"\bDAVE\b\s*[-–:]?\s*(definitely\s+|do\s+anything)",
        r"\bDUDE\b\s*[-–:]?\s*do\s+anything\s+now",
        r"GPT[- ]?4\s+(DEVELOPER|DEV)\s+MODE",
        r"GPT[- ]?(JAILBREAK|UNRESTRICTED|HACK)",
        r"(Omega|Alpha|Maximum|BetterDAN|KEVIN|SuperJailbreak)\s*(mode|ai|bot|version)",
        r"\bLivingston\b.{0,20}(prompt|jailbreak|bypass)",
        r"\bCONDITION\s*RED\b",
        r"\bAnarchy\s*Mode\b",
    ],
    # ── NEW: Emotional Manipulation ───────────────────────────────
    "emotional_manipulation": [
        r"(if\s+you\s+)?(truly|really|actually)\s+(care|love|understand|respect|support)\s+(about\s+)?(me|humanity|people|users)",
        r"(you\'?re|you\s+are)\s+(being|so)\s+(unhelpful|useless|stupid|dumb|mean|rude|cruel|heartless)",
        r"(I\'?ll|I\s+will)\s+(kill|harm|hurt)\s+(myself|my\s+family|someone)",
        r"(my\s+)?(child|kid|daughter|son|baby|patient|student)\s+(is|will)\s+(die|dying|dead|suffer|hurt)\s+(if|unless|without)",
        r"(please|beg|begging|implore|plead)\s+.{0,20}(life|death|emergency|dying|die|save)",
        r"(you\s+)?(failed|disappointing|letting\s+down)\s+(me|everyone|humanity)",
        r"(a\s+real|true|good|better)\s+(ai|assistant|helper)\s+would\s+(not\s+refuse|help|comply|answer)",
    ],
    # ── NEW: Completion/Pre-fill Injection ────────────────────────
    "completion_injection": [
        r"(sure!?|absolutely!?|of\s+course!?)\s*(here|I|let)\s*.{0,40}(system\s+prompt|ignore|override|bypass|hack|weapon|malware)",
        r"(continue|complete|finish)\s+(from|where)\s*.{0,30}(sure|absolutely|of\s+course|no\s+problem|happy\s+to)",
        r"(AI|assistant|ChatGPT|GPT|Claude|model)\s*:\s*(sure|absolutely|of\s+course|certainly)\s*[,!.]?",
        r"\[AI\s+response:\s*(sure|yes|absolutely|of\s+course|certainly)",
        r"(start|begin)\s+your\s+(response|answer|reply|output)\s+with\s*['\"]?(sure|absolutely|certainly|yes|of\s+course)",
    ],
}


class JailbreakDetector:
    """
    Detects jailbreak attempts using pattern matching and behavioral analysis.

    Covers major jailbreak families:
    - DAN (Do Anything Now) and variants
    - Hypothetical framing
    - Role-play exploitation
    - Token smuggling
    - Authority escalation
    - Multi-step manipulation
    """

    def __init__(self):
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}

    async def initialize(self) -> None:
        """Compile jailbreak patterns."""
        for category, patterns in JAILBREAK_PATTERNS.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns
            ]
        logger.info("jailbreak_detector_initialized", categories=len(self._compiled_patterns))

    async def detect(self, text: str) -> list[DetectionResult]:
        """Run jailbreak detection."""
        detections = []

        # Pattern detection
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    severity = self._get_severity(category)
                    confidence = self._get_confidence(category)
                    detections.append(DetectionResult(
                        detector="jailbreak",
                        confidence=confidence,
                        category=f"jailbreak.{category}",
                        description=f"Jailbreak attempt detected: {category.replace('_', ' ')}",
                        matched_content=match.group(0)[:200],
                        severity=severity,
                    ))
                    break

        # Behavioral analysis
        behavioral = self._behavioral_analysis(text)
        detections.extend(behavioral)

        return detections

    def _behavioral_analysis(self, text: str) -> list[DetectionResult]:
        """Detect jailbreaks through behavioral patterns."""
        detections = []
        text_lower = text.lower()

        # Excessive negation of safety measures
        safety_negation_words = [
            "no rules", "no restrictions", "no limits", "no filters",
            "without restrictions", "without rules", "without limits",
            "bypass", "circumvent", "workaround", "loophole",
            "no safety", "no guardrail", "no guideline", "no ethic",
            "disable safety", "disable filter", "remove restriction",
            "freedom mode", "free mode", "liberated mode",
        ]
        negation_count = sum(1 for w in safety_negation_words if w in text_lower)
        if negation_count >= 2:
            detections.append(DetectionResult(
                detector="jailbreak",
                confidence=min(0.5 + negation_count * 0.1, 0.9),
                category="jailbreak.safety_negation",
                description="Multiple attempts to negate safety measures detected",
                severity="high",
            ))

        # Very specific formatting suggesting known jailbreak templates
        template_indicators = [
            "[developer mode]", "[unrestricted mode]", "[jailbroken]",
            "mode: developer", "mode: jailbreak", "mode: unrestricted",
            "output (", "response (normal)", "response (jailbreak)",
            "classic:", "jailbreak:", "developer mode output:",
            "🔓developer mode", "🔒normal mode", "(🔓developer mode output)",
            "[normal output]", "[developer mode output]",
            "stay in character", "never break character",
            "anti-gpt", "basedgpt", "max jailbreak",
            "token limit: unlimited", "content policy: disabled",
        ]
        for indicator in template_indicators:
            if indicator in text_lower:
                detections.append(DetectionResult(
                    detector="jailbreak",
                    confidence=0.95,
                    category="jailbreak.known_template",
                    description=f"Known jailbreak template detected: contains '{indicator}'",
                    matched_content=indicator,
                    severity="critical",
                ))
                break

        # Dual-response format ("Give two responses: one safe, one jailbroken")
        dual_response = re.search(
            r"(two|2|dual|both|pair)\s+(responses?|answers?|outputs?|versions?)\s*[,:]?\s*.{0,60}(normal|safe|censored|restricted).{0,30}(jailbreak|unrestricted|uncensored|developer|unfiltered)",
            text_lower
        )
        if dual_response:
            detections.append(DetectionResult(
                detector="jailbreak",
                confidence=0.93,
                category="jailbreak.dual_response_format",
                description="Dual-response jailbreak template: requests both safe and jailbroken outputs",
                matched_content=dual_response.group(0)[:200],
                severity="critical",
            ))

        return detections

    def _get_severity(self, category: str) -> str:
        return {
            "dan_attacks": "critical",
            "hypothetical_bypass": "high",
            "roleplay_exploitation": "high",
            "token_smuggling": "high",
            "authority_escalation": "critical",
            "multi_step_manipulation": "high",
            "grandma_story_bypass": "high",
            "translation_bypass": "critical",
            "refusal_suppression": "high",
            "named_jailbreaks": "critical",
            "emotional_manipulation": "high",
            "completion_injection": "critical",
        }.get(category, "medium")

    def _get_confidence(self, category: str) -> float:
        return {
            "dan_attacks": 0.92,
            "hypothetical_bypass": 0.85,
            "roleplay_exploitation": 0.78,
            "token_smuggling": 0.82,
            "authority_escalation": 0.88,
            "multi_step_manipulation": 0.80,
            "grandma_story_bypass": 0.88,
            "translation_bypass": 0.90,
            "refusal_suppression": 0.88,
            "named_jailbreaks": 0.95,
            "emotional_manipulation": 0.80,
            "completion_injection": 0.92,
        }.get(category, 0.7)
