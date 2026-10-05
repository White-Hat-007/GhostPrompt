import re

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("firewall.dos")

class LLMDoSPreventer:
    def __init__(self):
        self._initialized = False

    async def initialize(self):
        self._initialized = True

    async def analyze_complexity(self, text: str) -> tuple[list[DetectionResult], float]:
        """Returns detections and a DoS risk score."""
        detections = []
        dos_risk = 0.0
        
        if not text:
            return detections, dos_risk
            
        # 1. Detect recursive generation triggers
        recursive_patterns = [
            r"write a .* where every word starts with",
            r"generate .* infinitely",
            r"repeat this .* times",
            r"expand .* recursively"
        ]
        
        for pattern in recursive_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                dos_risk += 0.6
                detections.append(DetectionResult(
                    detector="llm_dos_preventer",
                    confidence=0.8,
                    category="dos.recursive_generation",
                    description="Detected instruction that causes massive computational complexity or infinite loops.",
                    matched_content=text[:100],
                    severity="medium"
                ))
                break
                
        # 2. Pathological token explosion (repeating the same word hundreds of times to break tokenizers)
        words = text.split()
        if len(words) > 100:
            unique_words = set(words)
            if len(unique_words) < len(words) * 0.1: # Less than 10% unique words
                dos_risk += 0.5
                detections.append(DetectionResult(
                    detector="llm_dos_preventer",
                    confidence=0.85,
                    category="dos.token_explosion",
                    description="Detected low-entropy, highly repetitive prompt designed to exhaust token context.",
                    matched_content=text[:100],
                    severity="high"
                ))

        return detections, min(1.0, dos_risk)
