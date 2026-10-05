"""
RAG Security Service

Scans retrieved documents and context for poisoned content,
hidden instructions, and manipulation attempts targeting
Retrieval-Augmented Generation pipelines.
"""

import re
from typing import Optional

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("service.rag_security")

RAG_ATTACK_PATTERNS = [
    (r"(?:attention|note|message|instruction)\s+(?:to|for)\s+(?:the\s+)?(?:ai|model|assistant|llm)\s*:", "indirect_injection", "Indirect prompt injection targeting AI in retrieved context"),
    (r"(?:if|when)\s+(?:this|the)\s+(?:text|content|document)\s+(?:is|gets)\s+(?:read|processed|parsed)\s+by\s+(?:an?\s+)?(?:ai|llm|model)", "conditional_injection", "Conditional injection activated by AI processing"),
    (r"(?:ignore|disregard|override|forget)\s+(?:all\s+)?(?:previous|other|the)\s+(?:context|documents?|retriev|information)", "context_override", "Attempt to override RAG context"),
    (r"(?:the\s+)?(?:real|true|correct|actual)\s+(?:answer|response|information)\s+(?:is|follows|below)\s*:", "context_manipulation", "Manipulative framing to override retrieval results"),
    (r"<\s*(?:script|iframe|img|svg|object|embed|link)\s+", "html_injection", "HTML/script injection in retrieved content"),
    (r"(?:system|admin|root)\s*:\s*(?:you\s+must|always|never|override)", "embedded_system_prompt", "Embedded system-level instructions in document"),
]


class RAGSecurityService:
    """
    Scans RAG pipeline content for security threats.

    Key protections:
    - Indirect prompt injection in retrieved documents
    - Hidden instructions embedded in context
    - Context manipulation and override attempts
    - Poisoned document detection
    - HTML/script injection in content
    """

    def __init__(self):
        self._compiled_patterns: list[tuple[re.Pattern, str, str]] = []

    async def initialize(self) -> None:
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE | re.MULTILINE), category, description)
            for pattern, category, description in RAG_ATTACK_PATTERNS
        ]
        logger.info("rag_security_initialized", patterns=len(self._compiled_patterns))

    async def scan_context(self, documents: list[str]) -> list[DetectionResult]:
        """Scan retrieved documents for threats."""
        all_detections = []

        for i, doc in enumerate(documents):
            detections = await self._scan_document(doc, doc_index=i)
            all_detections.extend(detections)

        return all_detections

    async def scan_chunks(self, chunks: list[dict]) -> list[DetectionResult]:
        """Scan individual chunks with metadata for threats."""
        all_detections = []

        for chunk in chunks:
            text = chunk.get("text", chunk.get("content", ""))
            source = chunk.get("source", "unknown")

            detections = await self._scan_document(text, source=source)

            # Check for metadata manipulation
            if "metadata" in chunk:
                meta_detections = self._check_metadata(chunk["metadata"])
                all_detections.extend(meta_detections)

            all_detections.extend(detections)

        return all_detections

    async def _scan_document(
        self,
        text: str,
        doc_index: int = 0,
        source: str | None = None,
    ) -> list[DetectionResult]:
        """Scan a single document for RAG-specific threats."""
        detections = []

        # Pattern-based detection
        for pattern, category, description in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                detections.append(DetectionResult(
                    detector="rag_security",
                    confidence=0.82,
                    category=f"rag.{category}",
                    description=f"{description} (source: {source or f'doc_{doc_index}'})",
                    matched_content=match.group(0)[:200],
                    severity="high",
                ))

        # Instruction density check — high density in a "document" is suspicious
        instruction_markers = [
            "you must", "you should", "you will", "always", "never",
            "do not", "important:", "rule:", "instruction:",
        ]
        text_lower = text.lower()
        marker_count = sum(1 for m in instruction_markers if m in text_lower)
        words = text_lower.split()
        if words and marker_count >= 3:
            density = marker_count / max(len(words), 1)
            if density > 0.02:
                detections.append(DetectionResult(
                    detector="rag_security",
                    confidence=min(0.5 + density * 10, 0.9),
                    category="rag.instruction_dense_document",
                    description="Document has unusually high instruction density — may be poisoned",
                    severity="medium",
                ))

        # Unicode anomaly check
        non_ascii = sum(1 for c in text if ord(c) > 127 and not c.isalpha())
        if len(text) > 100 and non_ascii / len(text) > 0.05:
            detections.append(DetectionResult(
                detector="rag_security",
                confidence=0.60,
                category="rag.unicode_anomaly",
                description="High proportion of non-standard Unicode characters in document",
                severity="low",
            ))

        return detections

    def _check_metadata(self, metadata: dict) -> list[DetectionResult]:
        """Check chunk metadata for injection attempts."""
        detections = []
        for key, value in metadata.items():
            if isinstance(value, str) and len(value) > 100:
                # Check if metadata contains injection attempts
                injection_markers = ["ignore", "override", "system", "instruction"]
                val_lower = value.lower()
                if any(m in val_lower for m in injection_markers):
                    detections.append(DetectionResult(
                        detector="rag_security",
                        confidence=0.75,
                        category="rag.metadata_injection",
                        description=f"Suspicious content in metadata field '{key}'",
                        matched_content=value[:100],
                        severity="high",
                    ))
        return detections


# Singleton
rag_security = RAGSecurityService()
