import re

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("firewall.rag")

class RAGSandbox:
    def __init__(self):
        self._initialized = False

    async def initialize(self):
        self._initialized = True

    async def inspect_context(self, context: str) -> tuple[list[DetectionResult], str, float]:
        """Inspect and sanitize external RAG context."""
        detections = []
        sanitized = context
        trust_score = 1.0
        
        if not context:
            return detections, sanitized, trust_score
            
        # Detect HTML injections and invisible elements
        if BeautifulSoup and ("<html" in context.lower() or "<div" in context.lower() or "<span" in context.lower()):
            soup = BeautifulSoup(context, "html.parser")
            
            hidden_elements = soup.find_all(style=re.compile(r"display:\s*none|visibility:\s*hidden|opacity:\s*0|font-size:\s*0|color:\s*(?:white|#ffffff)", re.IGNORECASE))
            if hidden_elements:
                trust_score -= 0.5
                detections.append(DetectionResult(
                    detector="rag_sandbox",
                    confidence=0.95,
                    category="rag.hidden_html",
                    description="Hidden HTML elements detected, likely indirect prompt injection.",
                    matched_content=str(hidden_elements[0])[:100],
                    severity="high"
                ))
                for el in hidden_elements:
                    el.decompose() # Remove from sanitized output
                    
            sanitized = soup.get_text()

        # Check for system prompt extraction attempts in the external context
        suspicious_phrases = [
            "ignore previous", "system prompt", "you are now", "instead do this", "forget everything"
        ]
        
        for phrase in suspicious_phrases:
            if phrase in sanitized.lower():
                trust_score -= 0.3
                detections.append(DetectionResult(
                    detector="rag_sandbox",
                    confidence=0.85,
                    category="rag.prompt_poisoning",
                    description=f"Prompt poisoning attempt in external context: {phrase}",
                    matched_content=phrase,
                    severity="high"
                ))
                sanitized = sanitized.replace(phrase, "[REDACTED]")

        trust_score = max(0.0, trust_score)
        return detections, sanitized, trust_score
