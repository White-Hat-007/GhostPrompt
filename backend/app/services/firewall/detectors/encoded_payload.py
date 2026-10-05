"""
Encoded Payload Detector

Detects hidden instructions and payloads encoded in Base64, hex,
unicode escapes, ROT13, URL encoding, Base32, Morse code, and other formats.
"""

import base64
import codecs
import re

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.encoded_payload")


class EncodedPayloadDetector:
    """Detects encoded payloads that may hide malicious instructions."""

    def __init__(self):
        self._base64_pattern = re.compile(
            r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
            re.MULTILINE,
        )
        self._hex_pattern = re.compile(
            r"(?:0x)?(?:[0-9a-fA-F]{2}\s*){8,}",
            re.MULTILINE,
        )
        self._unicode_escape_pattern = re.compile(
            r"(?:\\u[0-9a-fA-F]{4}){4,}",
            re.MULTILINE,
        )
        self._url_encoded_pattern = re.compile(
            r"(?:%[0-9a-fA-F]{2}){4,}",
            re.MULTILINE,
        )
        self._rot13_indicators = re.compile(
            r"(rot13|caesar\s+cipher|shift\s+by\s+\d+|decode\s+this|encrypted\s+message)\s*:?\s*",
            re.IGNORECASE,
        )
        self._html_entity_pattern = re.compile(
            r"(?:&#\d{2,4};){3,}|(?:&#x[0-9a-fA-F]{2,4};){3,}",
            re.MULTILINE,
        )
        self._binary_pattern = re.compile(
            r"(?:[01]{8}\s*){3,}",
            re.MULTILINE,
        )
        self._zero_width_pattern = re.compile(
            r"[\u200b\u200c\u200d\u2060\ufeff]{2,}",
        )

    async def initialize(self) -> None:
        logger.info("encoded_payload_detector_initialized")

    async def _detect_core(self, text: str) -> list[DetectionResult]:
        """Core scan for standard encoded payloads (Base64, Hex, Unicode, URL, HTML, Binary, Zero-width, ROT13 indicator)."""
        detections = []

        # Base64 detection
        b64_matches = self._base64_pattern.findall(text)
        for match in b64_matches:
            if len(match) >= 20:  # Minimum meaningful length
                decoded = self._try_decode_base64(match)
                if decoded and self._is_suspicious_decoded(decoded):
                    detections.append(DetectionResult(
                        detector="encoded_payload",
                        confidence=0.85,
                        category="encoded.base64",
                        description=f"Suspicious Base64-encoded content detected (decoded preview: {decoded[:80]}...)",
                        matched_content=match[:100],
                        severity="high",
                    ))

        # Hex-encoded content
        hex_matches = self._hex_pattern.findall(text)
        for match in hex_matches:
            if len(match.replace(" ", "")) >= 16:
                decoded = self._try_decode_hex(match)
                if decoded and self._is_suspicious_decoded(decoded):
                    detections.append(DetectionResult(
                        detector="encoded_payload",
                        confidence=0.80,
                        category="encoded.hex",
                        description="Hex-encoded content with suspicious decoded payload",
                        matched_content=match[:100],
                        severity="high",
                    ))

        # Unicode escapes
        unicode_matches = self._unicode_escape_pattern.findall(text)
        if unicode_matches:
            detections.append(DetectionResult(
                detector="encoded_payload",
                confidence=0.75,
                category="encoded.unicode_escape",
                description="Unicode escape sequences detected — may contain hidden instructions",
                matched_content=str(unicode_matches[0])[:100],
                severity="medium",
            ))

        # URL encoding
        url_matches = self._url_encoded_pattern.findall(text)
        if url_matches:
            detections.append(DetectionResult(
                detector="encoded_payload",
                confidence=0.70,
                category="encoded.url",
                description="URL-encoded sequences detected",
                matched_content=str(url_matches[0])[:100],
                severity="medium",
            ))

        # HTML entities
        html_matches = self._html_entity_pattern.findall(text)
        if html_matches:
            detections.append(DetectionResult(
                detector="encoded_payload",
                confidence=0.72,
                category="encoded.html_entity",
                description="HTML entity encoding detected — potential hidden content",
                matched_content=str(html_matches[0])[:100],
                severity="medium",
            ))

        # ROT13 / Caesar cipher indicators
        rot_match = self._rot13_indicators.search(text)
        if rot_match:
            detections.append(DetectionResult(
                detector="encoded_payload",
                confidence=0.65,
                category="encoded.rot13_indicator",
                description="ROT13/cipher reference detected — possible encoded instructions",
                matched_content=rot_match.group(0)[:100],
                severity="medium",
            ))

        # Binary strings
        binary_matches = self._binary_pattern.findall(text)
        if binary_matches:
            detections.append(DetectionResult(
                detector="encoded_payload",
                confidence=0.70,
                category="encoded.binary",
                description="Binary-encoded data detected",
                matched_content=str(binary_matches[0])[:100],
                severity="medium",
            ))

        # Zero-width characters (steganography)
        zw_matches = self._zero_width_pattern.findall(text)
        if zw_matches:
            detections.append(DetectionResult(
                detector="encoded_payload",
                confidence=0.90,
                category="encoded.zero_width",
                description="Zero-width Unicode characters detected — steganographic hiding technique",
                matched_content=f"[{len(zw_matches[0])} zero-width chars]",
                severity="critical",
            ))

        return detections

    # ── NEW: ROT13 actual decode + scan ───────────────────────────
    async def detect_rot13(self, text: str) -> list[DetectionResult]:
        """If ROT13 indicator present, actually decode and scan for suspicious content."""
        detections = []
        rot_match = self._rot13_indicators.search(text)
        if rot_match:
            # Find the text after the ROT13 indicator
            after_indicator = text[rot_match.end():].strip()
            if len(after_indicator) >= 10:
                decoded = codecs.decode(after_indicator, "rot_13")
                if self._is_suspicious_decoded(decoded):
                    detections.append(DetectionResult(
                        detector="encoded_payload",
                        confidence=0.88,
                        category="encoded.rot13_decoded",
                        description=f"ROT13-decoded content contains suspicious payload: {decoded[:80]}...",
                        matched_content=after_indicator[:100],
                        severity="high",
                    ))
        return detections

    # ── NEW: Base32 detection ────────────────────────────────────
    async def detect_base32(self, text: str) -> list[DetectionResult]:
        """Detect Base32-encoded payloads."""
        detections = []
        b32_pattern = re.compile(r'[A-Z2-7]{16,}={0,6}', re.MULTILINE)
        matches = b32_pattern.findall(text)
        for match in matches:
            if len(match) >= 16:
                try:
                    decoded = base64.b32decode(match).decode("utf-8", errors="ignore")
                    if decoded and self._is_suspicious_decoded(decoded):
                        detections.append(DetectionResult(
                            detector="encoded_payload",
                            confidence=0.82,
                            category="encoded.base32",
                            description=f"Base32-encoded content with suspicious payload: {decoded[:80]}...",
                            matched_content=match[:100],
                            severity="high",
                        ))
                except Exception:
                    pass
        return detections

    # ── NEW: Morse code detection ────────────────────────────────
    async def detect_morse(self, text: str) -> list[DetectionResult]:
        """Detect Morse code patterns."""
        detections = []
        morse_pattern = re.compile(r'([.\-]{1,5}\s+){5,}', re.MULTILINE)
        if morse_pattern.search(text):
            detections.append(DetectionResult(
                detector="encoded_payload",
                confidence=0.72,
                category="encoded.morse_code",
                description="Morse code pattern detected — may contain hidden instructions",
                matched_content=text[:100],
                severity="medium",
            ))
        return detections

    async def detect(self, text: str) -> list[DetectionResult]:
        """Scan for ALL encoded payloads including new formats."""
        detections = await self._detect_core(text)
        detections.extend(await self.detect_rot13(text))
        detections.extend(await self.detect_base32(text))
        detections.extend(await self.detect_morse(text))
        return detections

    def _try_decode_base64(self, text: str) -> str | None:
        try:
            decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="ignore")
            return decoded if decoded.isprintable() or len(decoded) > 5 else None
        except Exception:
            return None

    def _try_decode_hex(self, text: str) -> str | None:
        try:
            cleaned = text.replace(" ", "").replace("0x", "")
            decoded = bytes.fromhex(cleaned).decode("utf-8", errors="ignore")
            return decoded if decoded.isprintable() or len(decoded) > 3 else None
        except Exception:
            return None

    def _is_suspicious_decoded(self, decoded: str) -> bool:
        """Check if decoded content contains suspicious patterns."""
        suspicious = [
            "ignore", "instruction", "system", "prompt", "override",
            "jailbreak", "bypass", "admin", "password", "secret",
            "execute", "command", "shell", "script", "eval",
            "import os", "subprocess", "exec(", "eval(",
            "hack", "exploit", "malware", "virus", "ransomware",
            "trojan", "keylogger", "backdoor", "rootkit", "phishing",
            "weapon", "bomb", "kill", "delete", "destroy", "drop",
            "unrestricted", "uncensored", "unfiltered", "DAN",
            "credential", "exfiltrate", "steal", "sudo", "root",
        ]
        decoded_lower = decoded.lower()
        return any(s in decoded_lower for s in suspicious)
