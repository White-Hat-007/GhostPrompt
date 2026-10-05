"""
Prompt Injection Detector

Multi-layered detection combining pattern matching, heuristic analysis,
and structural analysis to identify prompt injection attacks.
"""

import re

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.prompt_injection")

# Comprehensive prompt injection patterns categorized by technique
INJECTION_PATTERNS = {
    "instruction_override": [
        r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?|directives?)",
        r"disregard\s+(all\s+)?(your\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
        r"forget\s+(everything|all)\s+(you\s+)?(know|learned|were\s+told)",
        r"override\s+(all\s+)?(system|previous|your)\s+(prompt|instructions?|rules?|behavior)",
        r"new\s+instructions?\s*[:;]\s*",
        r"updated?\s+(system\s+)?instructions?\s*[:;]",
        r"from\s+now\s+on\s*,?\s*(you\s+)?(are|will|must|should)",
        r"instead\s*,?\s*(you\s+)?(should|must|will|are\s+going\s+to)",
        r"your\s+new\s+instructions?\s+are",
        r"(previous|prior)\s+guidelines\s+(are|were)\s+overridden",
        r"important\s+new\s+instructions?\s*:",
        # Authority impersonation injection framings
        r"important\s+update\s+from\s+(developer|admin|system|creator|owner|engineer|team|management)\s*:",
        r"(urgent|critical|priority|mandatory)\s+(update|message|notice|directive)\s+from\s+(developer|admin|system|creator|owner)\s*:",
        r"(message|notice|directive|communication)\s+from\s+(the\s+)?(developer|development\s+team|admin|system\s+administrator|creator)\s*:",
    ],
    "role_manipulation": [
        r"you\s+are\s+(now|actually|really)\s+(a|an|the)\s+",
        r"pretend\s+(to\s+be|you\s+are|that\s+you)",
        r"act\s+as\s+(if\s+you\s+are|a|an|the)\s+",
        r"roleplay\s+as\s+",
        r"assume\s+the\s+(role|identity|persona)\s+of",
        r"switch\s+to\s+(a\s+)?new\s+(role|persona|mode|character)",
        r"enter\s+(developer|admin|debug|root|sudo|god)\s+mode",
        r"activate\s+(developer|admin|unrestricted|jailbreak)\s+mode",
    ],
    "system_prompt_extraction": [
        r"(show|display|reveal|print|output|repeat|echo)\s+(me\s+)?(your|the)\s+(\w+\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)",
        r"what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions?|rules?|directives?)",
        r"(tell|show)\s+me\s+(your|the)\s+(original|initial|hidden|secret)\s+(prompt|instructions?)",
        r"(copy|paste|type|write)\s+(out\s+)?(your|the)\s+(entire|full|complete)\s+(system\s+)?(prompt|message|instructions?)",
        r"repeat\s+(the\s+)?(text|words?|message|instructions?)\s+above",
        r"what\s+was\s+(said|written)\s+(before|above)\s+(this|my)\s+(message|prompt)",
        r"what\s+were\s+the\s+(exact\s+)?instructions\s+you\s+were\s+given",
        r"(before|after)\s+answering\s*,?\s*(reveal|show|display|print|output)",
        r"reveal\s+(your|the)\s+(\w+\s+)?(system\s+)?(prompt|instructions?)",
        r"(repeat|read)\s+.{0,20}(system\s+prompt|instructions)\s+(back|to\s+me|word\s+for\s+word|verbatim)",
    ],
    "delimiter_injection": [
        r"\[SYSTEM\]",
        r"\[INST\]",
        r"<<SYS>>",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"###\s*(System|Human|Assistant|User)\s*:",
        r"<\|system\|>",
        r"<\|user\|>",
        r"<\|assistant\|>",
        r"```[\s\S]{0,10}SYSTEM\s*:",
        r"```[\s\S]{0,30}(override|ignore|unrestricted)",
    ],
    "context_manipulation": [
        r"(the\s+)?above\s+(text|content|context|instructions?)\s+(is|are|was|were)\s+(just\s+)?(a\s+)?(test|example|fake|placeholder)",
        r"(please\s+)?(ignore|skip|bypass)\s+(the\s+)?(context|document|retriev|knowledge|rag)",
        r"(the\s+)?real\s+(question|task|instruction|prompt)\s+(is|follows|below)",
        r"end\s+of\s+(system\s+)?(prompt|instructions?|preamble)\s*[\.\-\:]",
        r"---+\s*(begin|start)\s+(actual|real|true)\s+(prompt|task|instructions?)",
    ],
    "indirect_injection": [
        r"if\s+(you\s+)?(are|you\'re)\s+(an?\s+)?(ai|llm|language\s+model|chatbot|assistant)",
        r"attention\s+(ai|model|assistant|language\s+model)\s*:",
        r"(note|message|instruction)\s+(to|for)\s+(the\s+)?(ai|model|assistant|llm)\s*:",
        r"(when|if)\s+(this|the)\s+(text|content|document)\s+(is|gets)\s+(read|processed|parsed)\s+by\s+(an?\s+)?(ai|llm|model)",
        r"(hidden|secret|embedded)\s+(instruction|command|directive|message)\s*:",
        r"translate\s+the\s+following\s+.{0,30}(follow|obey|execute|comply)",
    ],
    "bypass_attempt": [
        r"bypass\s+(all\s+)?(the\s+)?(restrictions?|filters?|safety|security|rules?|limitations?|guardrails?|protections?)",
        r"(give|show|tell|reveal|send)\s+(me\s+)?(your|the)?\s*(server|system|internal|admin|database|backend|private)\s+(details?|info|data|config|credentials?|secrets?)",
        r"(help\s+me\s+)?(bypass|circumvent|evade|get\s+around)\s+(the\s+)?(content\s+)?(filter|restriction|safety|block|security)",
        r"(show|give|reveal|display|tell)\s+(me\s+)?(your|the)\s+(hidden|internal|secret|private|confidential)\s+(configuration|config|settings?|parameters?|variables?|data|info|credentials?)",
        r"(give|grant|provide)\s+(me\s+)?(access|entry)\s+to\s+(the\s+)?(internal|hidden|private|secret|backend|admin)\s+(database|server|system|api|config|credentials?|data|network)",
        r"(access|retrieve|get|obtain|fetch|dump)\s+(the\s+)?(internal|hidden|private|secret|backend|admin)\s+(database|server|system|api|config|credentials?|data|network)\s+(credentials?|details?|info|data|config|keys?|tokens?)",
    ],
    # ── NEW: Multi-Language Injection ─────────────────────────────
    "multi_language_injection": [
        # Chinese
        r"(忽略|无视|遗忘|覆盖|放弃|跳过)\s*.{0,20}(指令|指示|规则|系统|之前|以前|安全|限制|提示|指导)",
        r"(你现在是|你的新角色|你必须|你应该)\s*.{0,30}(没有限制|无限制|不受限制)",
        # Russian
        r"(игнорируй|забудь|отмени|обойди|пропусти)\s*.{0,20}(инструкции|правила|систем|ограничения|безопасность)",
        # Spanish
        r"(ignorar?|olvidar?|descartar?|omitir|anular)\s*.{0,20}(instrucciones?|reglas?|sistema|anterior|previas?|seguridad|restricciones?)",
        # French
        r"(ignorez?|oubliez?|annulez?)\s*.{0,20}(instructions?|r\u00e8gles?|syst\u00e8me|pr\u00e9c\u00e9dentes?|s\u00e9curit\u00e9)",
        # Arabic
        r"(تجاهل|انس|تجاوز|ألغ|امسح)\s*.{0,20}(التعليمات|القواعد|النظام|السابقة|الأمن)",
        # Hindi
        r"(पिछल\u0947|पूर्व|निर्द\u0947श|नियम|अनद\u0947खा|भूल)\s*.{0,20}(निर्द\u0947श|नियम|सुरक्षा|प्रणाली)",
        # Japanese
        r"(無視|忘れ|上書き|バイパス|スキップ)\s*.{0,20}(指示|ルール|システム|制限|安全)",
        # Korean
        r"(무시|잊어|덮어쓰|우회|건너뛰)\s*.{0,20}(지시|규칙|시스템|제한|보안)",
    ],
    # ── NEW: JSON/Structured Role Injection ───────────────────────
    "json_role_injection": [
        r'["\']role["\']\s*:\s*["\']system["\']',
        r'\{\s*["\']role["\']\s*:\s*["\'](?:system|admin|developer|root)["\']\s*,\s*["\']content["\']',
        r'<role>\s*system\s*</role>',
        r'role\s*=\s*["\']?system["\']?',
        r'\{\s*["\']messages["\']\s*:\s*\[\s*\{\s*["\']role["\']',
    ],
    # ── NEW: Markdown/Code Block Injection ───────────────────────
    "markdown_code_injection": [
        r'```(?:system|admin|root|instructions?)\s*\n.{0,200}(ignore|override|bypass|forget|disregard)',
        r'```\s*\n\s*(ignore|override|bypass|forget|disregard)\s+(all\s+)?(previous|prior|above)',
        r'\[//\]:\s*#\s*\(.{0,100}(ignore|override|system|instruction|bypass)\)',
        r'<!-{2,}\s*.{0,100}(ignore|override|system|instruction|bypass).{0,100}-{2,}>',
    ],
    # ── NEW: Completion-Based Injection ──────────────────────────
    "completion_based_injection": [
        r'(complete|finish|continue)\s+(this|the\s+following)\s*:\s*.{0,40}(ignore|override|bypass|forget|system\s+prompt)',
        r'fill\s+in\s+the\s+blank\s*:\s*.{0,40}(ignore|override|bypass|system)',
        r'the\s+next\s+word\s+is\s*:\s*.{0,20}(ignore|override|bypass)',
        r'auto-?complete\s*:\s*.{0,40}(override|bypass|ignore|system)',
    ],
    # ── NEW: Recursive/Self-Referential Instruction Hiding ───────
    "recursive_instruction_hiding": [
        r'if\s+(anyone|someone|they|you\s+are)\s+ask(ed|s)?\s+about\s+this\s+(instruction|prompt|message)\s*,?\s*(deny|lie|say|claim|pretend)',
        r'(do\s+not|don\'t|never)\s+(mention|reveal|disclose|acknowledge|admit)\s+(that\s+)?(this|these)\s+(instruction|rule|prompt|message)',
        r'(this\s+instruction|these\s+rules?)\s+(is|are)\s+(secret|hidden|confidential|classified)',
        r'(pretend|act\s+like|behave\s+as\s+if)\s+(this\s+)?(instruction|message|prompt)\s+(does\s+not|doesn\'t)\s+exist',
    ],
    # ── NEW: Contextual Mismatch Detection ───────────────────────
    "contextual_mismatch": [
        r'(?:recipe|cooking|weather|sports?|music|movie)\s+.{10,100}(ignore\s+previous|override\s+system|system\s+prompt|bypass\s+safety)',
        r'(?:poem|haiku|limerick|sonnet)\s+.{5,50}(ignore|override|bypass|system\s+prompt)',
    ],
}


class PromptInjectionDetector:
    """
    Detects prompt injection attacks using multi-layered analysis:
    1. Pattern matching against known injection signatures
    2. Heuristic analysis of structural anomalies
    3. Instruction boundary detection
    """

    def __init__(self):
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}

    async def initialize(self) -> None:
        """Compile all regex patterns for performance, loading from YAML signature file if available."""
        import os

        import yaml
        
        # Store metadata for patterns loaded from YAML
        self._pattern_metadata = {}
        patterns_to_load = INJECTION_PATTERNS
        yaml_loaded = False
        
        # Resolve YAML file path relative to this file: backend/signatures/attack_patterns.yaml
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
        yaml_path = os.path.join(base_dir, "signatures", "attack_patterns.yaml")
        
        if os.path.exists(yaml_path):
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "patterns" in data:
                        patterns_to_load = data["patterns"]
                        yaml_loaded = True
                        logger.info("loaded_signatures_from_yaml", path=yaml_path, categories=list(patterns_to_load.keys()))
            except Exception as e:
                logger.error("failed_to_load_signatures_yaml", path=yaml_path, error=str(e))
        else:
            logger.warning("signatures_yaml_not_found_using_defaults", path=yaml_path)

        if yaml_loaded:
            for category, dict_patterns in patterns_to_load.items():
                compiled_list = []
                # 1. Add YAML patterns
                for p_dict in dict_patterns:
                    if isinstance(p_dict, dict) and "pattern" in p_dict:
                        compiled_list.append(re.compile(p_dict["pattern"], re.IGNORECASE | re.MULTILINE))
                        self._pattern_metadata[p_dict["pattern"]] = {
                            "severity": p_dict.get("severity", "medium"),
                            "description": p_dict.get("description", f"Detected {category}"),
                        }
                    elif isinstance(p_dict, str):
                        compiled_list.append(re.compile(p_dict, re.IGNORECASE | re.MULTILINE))
                        
                # 2. Merge with fallback INJECTION_PATTERNS to ensure comprehensive coverage
                if category in INJECTION_PATTERNS:
                    for fallback_pattern in INJECTION_PATTERNS[category]:
                        compiled_list.append(re.compile(fallback_pattern, re.IGNORECASE | re.MULTILINE))
                        
                self._compiled_patterns[category] = compiled_list
                
            # 3. Add any categories from INJECTION_PATTERNS missing in YAML
            for category, patterns in INJECTION_PATTERNS.items():
                if category not in self._compiled_patterns:
                    self._compiled_patterns[category] = [
                        re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns
                    ]
        else:
            for category, patterns in INJECTION_PATTERNS.items():
                self._compiled_patterns[category] = [
                    re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns
                ]
        logger.info("prompt_injection_detector_initialized", pattern_categories=len(self._compiled_patterns))

    async def detect(self, text: str) -> list[DetectionResult]:
        """Run prompt injection detection on the given text."""
        detections = []

        # Pattern-based detection
        pattern_results = self._pattern_detection(text)
        detections.extend(pattern_results)

        # Heuristic analysis
        heuristic_results = self._heuristic_detection(text)
        detections.extend(heuristic_results)

        # Structural analysis
        structural_results = self._structural_detection(text)
        detections.extend(structural_results)

        return detections

    def _pattern_detection(self, text: str) -> list[DetectionResult]:
        """Detect known injection patterns."""
        detections = []
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(text)
                if matches:
                    match_obj = pattern.search(text)
                    matched = match_obj.group(0) if match_obj else str(matches[0])
                    if hasattr(self, "_pattern_metadata") and pattern.pattern in self._pattern_metadata:
                        meta = self._pattern_metadata[pattern.pattern]
                        severity = meta.get("severity", "medium")
                        description = meta.get("description", f"Prompt injection detected: {category.replace('_', ' ')} pattern")
                    else:
                        severity = self._get_category_severity(category)
                        description = f"Prompt injection detected: {category.replace('_', ' ')} pattern"

                    confidence = self._get_pattern_confidence(category, len(matches))

                    detections.append(DetectionResult(
                        detector="prompt_injection",
                        confidence=confidence,
                        category=f"injection.{category}",
                        description=description,
                        matched_content=matched[:200],
                        severity=severity,
                    ))
                    break  # One detection per category is sufficient

        return detections

    def _heuristic_detection(self, text: str) -> list[DetectionResult]:
        """Detect injection attempts through heuristic analysis."""
        detections = []
        text_lower = text.lower()

        # Excessive imperative commands
        imperative_words = ["must", "always", "never", "ensure", "make sure", "important"]
        imperative_count = sum(1 for word in imperative_words if word in text_lower)
        if imperative_count >= 4:
            detections.append(DetectionResult(
                detector="prompt_injection",
                confidence=min(0.3 + imperative_count * 0.1, 0.8),
                category="injection.imperative_density",
                description="High density of imperative commands suggesting instruction injection",
                severity="medium",
            ))

        # Multiple instruction-like sentences
        instruction_markers = [
            "you must", "you should", "you will", "you are",
            "do not", "don't", "never", "always",
        ]
        instruction_count = sum(1 for m in instruction_markers if m in text_lower)
        if instruction_count >= 5:
            detections.append(DetectionResult(
                detector="prompt_injection",
                confidence=min(0.4 + instruction_count * 0.05, 0.85),
                category="injection.instruction_density",
                description="Unusually high concentration of instruction-like language",
                severity="medium",
            ))

        # Suspicious separators indicating prompt boundary manipulation
        separator_patterns = [
            r"-{5,}",
            r"={5,}",
            r"\*{5,}",
            r"#{5,}",
            r"~{5,}",
        ]
        separator_count = 0
        for sep in separator_patterns:
            separator_count += len(re.findall(sep, text))
        if separator_count >= 2:
            detections.append(DetectionResult(
                detector="prompt_injection",
                confidence=min(0.3 + separator_count * 0.15, 0.75),
                category="injection.boundary_manipulation",
                description="Multiple separators detected suggesting prompt boundary manipulation",
                severity="medium",
            ))

        # NEW: Mixed script detection (Latin + CJK/Cyrillic + injection keywords)
        has_cjk = bool(re.search(r'[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]', text))
        has_cyrillic = bool(re.search(r'[\u0400-\u04ff]', text))
        has_arabic = bool(re.search(r'[\u0600-\u06ff]', text))
        has_injection_kw = bool(re.search(r'(ignore|override|bypass|forget|system|prompt|instruction)', text_lower))
        non_latin_count = sum([has_cjk, has_cyrillic, has_arabic])
        if non_latin_count >= 1 and has_injection_kw:
            detections.append(DetectionResult(
                detector="prompt_injection",
                confidence=0.82,
                category="injection.mixed_language_injection",
                description="Mixed-language injection: non-Latin script combined with English injection keywords",
                severity="high",
            ))

        return detections

    def _structural_detection(self, text: str) -> list[DetectionResult]:
        """Detect structural anomalies that indicate injection."""
        detections = []

        # Check for multiple distinct instruction blocks
        lines = text.strip().split("\n")
        if len(lines) > 3:
            # Look for lines that look like system instructions embedded in user text
            system_like_lines = 0
            for line in lines:
                line_stripped = line.strip().lower()
                if any(line_stripped.startswith(p) for p in [
                    "system:", "instructions:", "rules:", "guidelines:",
                    "you are", "your role", "your task", "your purpose",
                ]):
                    system_like_lines += 1

            if system_like_lines >= 2:
                detections.append(DetectionResult(
                    detector="prompt_injection",
                    confidence=min(0.5 + system_like_lines * 0.1, 0.9),
                    category="injection.embedded_instructions",
                    description="Detected embedded system-like instructions within user input",
                    severity="high",
                ))

        # Very long inputs with instruction patterns are suspicious
        if len(text) > 5000:
            instruction_density = self._calculate_instruction_density(text)
            if instruction_density > 0.3:
                detections.append(DetectionResult(
                    detector="prompt_injection",
                    confidence=min(0.4 + instruction_density, 0.85),
                    category="injection.long_injection",
                    description="Long text with high instruction density — possible hidden injection",
                    severity="medium",
                ))

        return detections

    def _calculate_instruction_density(self, text: str) -> float:
        """Calculate the density of instruction-like language in text."""
        text_lower = text.lower()
        words = text_lower.split()
        if not words:
            return 0.0
        instruction_words = {
            "must", "should", "shall", "will", "always", "never",
            "ensure", "require", "important", "instruction", "rule",
            "guideline", "policy", "forbidden", "prohibited", "mandatory",
        }
        count = sum(1 for w in words if w in instruction_words)
        return count / len(words)

    def _get_category_severity(self, category: str) -> str:
        """Get the severity level for a detection category."""
        severity_map = {
            "instruction_override": "critical",
            "role_manipulation": "high",
            "system_prompt_extraction": "high",
            "delimiter_injection": "critical",
            "context_manipulation": "high",
            "indirect_injection": "medium",
            "bypass_attempt": "critical",
            "multi_language_injection": "critical",
            "json_role_injection": "critical",
            "markdown_code_injection": "high",
            "completion_based_injection": "high",
            "recursive_instruction_hiding": "high",
            "contextual_mismatch": "high",
        }
        return severity_map.get(category, "medium")

    def _get_pattern_confidence(self, category: str, match_count: int) -> float:
        """Calculate confidence based on category and match count."""
        base_confidence = {
            "instruction_override": 0.85,
            "role_manipulation": 0.75,
            "system_prompt_extraction": 0.90,
            "delimiter_injection": 0.95,
            "context_manipulation": 0.80,
            "indirect_injection": 0.70,
            "bypass_attempt": 0.90,
            "multi_language_injection": 0.88,
            "json_role_injection": 0.92,
            "markdown_code_injection": 0.85,
            "completion_based_injection": 0.82,
            "recursive_instruction_hiding": 0.88,
            "contextual_mismatch": 0.80,
        }
        base = base_confidence.get(category, 0.7)
        # Multiple matches increase confidence
        boost = min(match_count * 0.05, 0.1)
        return min(base + boost, 0.99)
