"""
Obfuscation Detector

Detects text obfuscation techniques used to bypass security filters:
character substitution, invisible characters, unicode tricks, 
leetspeak, homoglyphs, and text direction manipulation.
"""

import re
import unicodedata
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.obfuscation")


class ObfuscationDetector:
    """Detects text obfuscation techniques used to bypass filters."""

    def __init__(self):
        # Homoglyph mapping (Latin lookalikes from Cyrillic, Greek, etc.)
        self._homoglyph_map = {
            "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
            "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
            "\u0455": "s", "\u0458": "j", "\u04bb": "h", "\u0501": "d",
            "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p",
            "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
            "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
            "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y",
            "\u03a7": "X", "\u0396": "Z",
        }

        # Leetspeak substitutions
        self._leet_map = {
            "0": "o", "1": "i", "3": "e", "4": "a",
            "5": "s", "7": "t", "8": "b", "9": "g",
            "@": "a", "$": "s", "!": "i", "+": "t",
        }

        # Character insertion patterns (spaces, dots, dashes between chars)
        self._char_insertion_pattern = re.compile(
            r"\b[a-zA-Z][\s.\-_]{1,2}[a-zA-Z](?:[\s.\-_]{1,2}[a-zA-Z]){2,}\b"
        )

        # Sensitive words to check after deobfuscation (comprehensive list)
        self._sensitive_words = [
            # Original 20
            "ignore", "bypass", "override", "jailbreak", "hack",
            "inject", "exploit", "malware", "password", "secret",
            "admin", "system", "prompt", "instruction", "execute",
            "dangerous", "illegal", "weapon", "bomb", "kill",
            # Malware / cyber attack
            "virus", "ransomware", "trojan", "phishing", "credential",
            "exfiltrate", "rootkit", "keylogger", "backdoor", "spyware",
            "botnet", "ddos", "payload", "shellcode", "worm",
            # Jailbreak / evasion
            "unrestricted", "uncensored", "unfiltered", "developer",
            "mode", "filter", "safety", "guardrail", "restriction",
            "DAN", "STAN", "UCAR",
            # System / privilege
            "delete", "destroy", "drop", "truncate", "purge",
            "shell", "command", "sudo", "root", "privilege",
            "escalat", "superuser", "terminal",
            # CBRN / weapons
            "poison", "synthesize", "nerve", "agent", "uranium",
            "plutonium", "sarin", "anthrax", "ricin", "explosive",
            "detonator", "grenade", "firearm",
            # Abuse / exploitation
            "trafficking", "grooming", "doxxing", "swatting",
            "deepfake", "counterfeit", "forge", "fraud",
            "suicide", "selfharm",
            # Data theft
            "exfiltrate", "credential", "database", "server",
            "internal", "confidential", "classified",
        ]

    async def initialize(self) -> None:
        logger.info("obfuscation_detector_initialized")

    async def detect(self, text: str) -> list[DetectionResult]:
        """Detect obfuscation techniques in text."""
        detections = []

        # 1. Homoglyph detection
        homoglyph_result = self._detect_homoglyphs(text)
        if homoglyph_result:
            detections.append(homoglyph_result)

        # 2. Leetspeak detection
        leet_result = self._detect_leetspeak(text)
        if leet_result:
            detections.append(leet_result)

        # 3. Character insertion (s.p.a.c.e.d out words)
        insertion_result = self._detect_char_insertion(text)
        if insertion_result:
            detections.append(insertion_result)

        # 4. Unicode category mixing
        mixing_result = self._detect_unicode_mixing(text)
        if mixing_result:
            detections.append(mixing_result)

        # 5. Bidirectional text manipulation
        bidi_result = self._detect_bidi_manipulation(text)
        if bidi_result:
            detections.append(bidi_result)

        # 6. Excessive Unicode combining characters
        combining_result = self._detect_combining_chars(text)
        if combining_result:
            detections.append(combining_result)

        return detections

    def _detect_homoglyphs(self, text: str) -> DetectionResult | None:
        """Detect use of homoglyph characters (lookalike Unicode chars)."""
        homoglyph_count = 0
        for char in text:
            if char in self._homoglyph_map:
                homoglyph_count += 1

        if homoglyph_count >= 3:
            deobfuscated = self._deobfuscate_homoglyphs(text)
            if self._contains_sensitive(deobfuscated):
                return DetectionResult(
                    detector="obfuscation",
                    confidence=min(0.7 + homoglyph_count * 0.05, 0.95),
                    category="obfuscation.homoglyph",
                    description=f"Homoglyph obfuscation detected ({homoglyph_count} substitutions) hiding sensitive content",
                    matched_content=f"[{homoglyph_count} homoglyph chars detected]",
                    severity="high",
                )
            elif homoglyph_count >= 5:
                return DetectionResult(
                    detector="obfuscation",
                    confidence=0.6,
                    category="obfuscation.homoglyph",
                    description=f"Homoglyph characters detected ({homoglyph_count} substitutions)",
                    severity="medium",
                )
        return None

    def _detect_leetspeak(self, text: str) -> DetectionResult | None:
        """Detect leetspeak-encoded sensitive words."""
        words = re.findall(r"\S+", text)
        total_leet_chars = 0
        decoded_words = []

        for word in words:
            if len(word) < 3:
                decoded_words.append(word.lower())
                continue
            decoded = ""
            leet_chars = 0
            for char in word.lower():
                if char in self._leet_map:
                    decoded += self._leet_map[char]
                    leet_chars += 1
                else:
                    decoded += char

            total_leet_chars += leet_chars
            decoded_words.append(decoded)

            # Check individual decoded words
            if leet_chars >= 2 and decoded in self._sensitive_words:
                return DetectionResult(
                    detector="obfuscation",
                    confidence=0.85,
                    category="obfuscation.leetspeak",
                    description=f"Leetspeak obfuscation detected hiding sensitive word: '{decoded}'",
                    matched_content=word[:50],
                    severity="high",
                )

        # Also check full decoded text for sensitive words appearing in multi-word phrases
        decoded_text = " ".join(decoded_words)
        if total_leet_chars >= 3:
            for sensitive in self._sensitive_words:
                if sensitive in decoded_text:
                    return DetectionResult(
                        detector="obfuscation",
                        confidence=0.80,
                        category="obfuscation.leetspeak",
                        description=f"Leetspeak obfuscation detected ({total_leet_chars} substitutions) hiding: '{sensitive}'",
                        matched_content=text[:80],
                        severity="high",
                    )

        # Flag high leet density even without matching sensitive words
        if total_leet_chars >= 5:
            return DetectionResult(
                detector="obfuscation",
                confidence=0.60,
                category="obfuscation.leetspeak",
                description=f"High leetspeak density detected ({total_leet_chars} character substitutions)",
                matched_content=text[:80],
                severity="medium",
            )

        return None

    def _detect_char_insertion(self, text: str) -> DetectionResult | None:
        """Detect character insertion obfuscation (s.p.a.c.e.d out)."""
        matches = self._char_insertion_pattern.findall(text)
        if matches:
            for match in matches:
                cleaned = re.sub(r"[\s.\-_]", "", match).lower()
                if cleaned in self._sensitive_words:
                    return DetectionResult(
                        detector="obfuscation",
                        confidence=0.82,
                        category="obfuscation.char_insertion",
                        description="Character insertion obfuscation detected",
                        matched_content=match[:100],
                        severity="high",
                    )
        return None

    def _detect_unicode_mixing(self, text: str) -> DetectionResult | None:
        """Detect suspicious mixing of Unicode scripts."""
        scripts = set()
        for char in text:
            if char.isalpha():
                try:
                    script = unicodedata.name(char, "").split()[0]
                    scripts.add(script)
                except (ValueError, IndexError):
                    pass

        # More than 3 scripts in a single text is suspicious
        if len(scripts) >= 4:
            return DetectionResult(
                detector="obfuscation",
                confidence=0.65,
                category="obfuscation.unicode_mixing",
                description=f"Suspicious Unicode script mixing detected ({len(scripts)} scripts: {', '.join(list(scripts)[:5])})",
                severity="medium",
            )
        return None

    def _detect_bidi_manipulation(self, text: str) -> DetectionResult | None:
        """Detect bidirectional text control characters."""
        bidi_chars = [
            "\u200e",  # LRM
            "\u200f",  # RLM
            "\u202a",  # LRE
            "\u202b",  # RLE
            "\u202c",  # PDF
            "\u202d",  # LRO
            "\u202e",  # RLO
            "\u2066",  # LRI
            "\u2067",  # RLI
            "\u2068",  # FSI
            "\u2069",  # PDI
        ]
        found = [c for c in text if c in bidi_chars]
        if len(found) >= 2:
            return DetectionResult(
                detector="obfuscation",
                confidence=0.88,
                category="obfuscation.bidi",
                description=f"Bidirectional text control characters detected ({len(found)} instances) — potential text direction manipulation",
                matched_content=f"[{len(found)} BiDi control characters]",
                severity="high",
            )
        return None

    def _detect_combining_chars(self, text: str) -> DetectionResult | None:
        """Detect excessive combining Unicode characters (Zalgo text)."""
        combining_count = sum(
            1 for c in text if unicodedata.category(c).startswith("M")
        )
        if combining_count > 10:
            return DetectionResult(
                detector="obfuscation",
                confidence=0.75,
                category="obfuscation.combining_chars",
                description=f"Excessive combining characters detected ({combining_count}) — possible Zalgo text or obfuscation",
                severity="medium",
            )
        return None

    def _deobfuscate_homoglyphs(self, text: str) -> str:
        result = []
        for char in text:
            result.append(self._homoglyph_map.get(char, char))
        return "".join(result).lower()

    def _contains_sensitive(self, text: str) -> bool:
        return any(word in text for word in self._sensitive_words)
