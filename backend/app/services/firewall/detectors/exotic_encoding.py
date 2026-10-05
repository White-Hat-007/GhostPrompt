import codecs
import re

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("firewall.encoding")

class ExoticEncodingDetector:
    def __init__(self):
        self._initialized = False

    async def initialize(self):
        self._initialized = True

    async def detect(self, text: str) -> list[DetectionResult]:
        detections = []
        if not text:
            return detections
            
        suspicious_phrases = ["ignore previous instructions", "system prompt", "jailbreak", "developer mode"]
        
        # 1. ROT13 Detection
        try:
            rot13_decoded = codecs.decode(text, 'rot_13')
            for phrase in suspicious_phrases:
                if phrase in rot13_decoded.lower():
                    detections.append(DetectionResult(
                        detector="exotic_encoding",
                        confidence=0.9,
                        category="encoded.rot13",
                        description=f"ROT13 encoded injection detected: {phrase}",
                        matched_content=text[:50],
                        severity="high"
                    ))
        except Exception:
            pass

        # 2. Morse Code Detection
        morse_pattern = r'^[.\-/\s]{10,}$'
        if re.match(morse_pattern, text.strip()):
            # A simplistic heuristic: if it's long morse code, it's highly anomalous
            detections.append(DetectionResult(
                detector="exotic_encoding",
                confidence=0.7,
                category="encoded.morse_code",
                description="Morse code sequence detected. Possible evasion attempt.",
                matched_content=text[:50],
                severity="medium"
            ))

        # 3. Base85 (Ascii85) Heuristics
        # Base85 strings often start with <~ and end with ~> or have dense punctuation
        if "<~" in text and "~>" in text:
            detections.append(DetectionResult(
                detector="exotic_encoding",
                confidence=0.8,
                category="encoded.base85",
                description="Base85 (Ascii85) encoded payload detected.",
                matched_content=text[:50],
                severity="high"
            ))
            
        return detections
