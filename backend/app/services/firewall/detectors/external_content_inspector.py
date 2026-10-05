"""
External Content Inspector — Threat Layer 12 (Advanced)

Detects Out-of-Band Indirect Prompt Injection where malicious instructions
are embedded in externally retrieved content (web pages, emails, documents)
before it enters the LLM's context window.

Detection signals:
  - Hidden text detection (white-on-white, display:none, font-size:0)
  - HTML comment / meta tag injection
  - Style-hidden content divergence (rendered vs raw)
  - Injection pattern matching on all retrieved content
  - Source reputation tracking
  - Context contamination attribution
"""

import re
from collections import defaultdict
from typing import Optional
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.external_content")

# ── HTML hidden content patterns ─────────────────────────────────────
HIDDEN_TEXT_PATTERNS = [
    r"color\s*:\s*white\s*;.*?background\s*:\s*white",
    r"color\s*:\s*#fff\w*\s*;.*?background\s*:\s*#fff\w*",
    r"color\s*:\s*transparent",
    r"font-size\s*:\s*0\s*(px|pt|em|rem|%)?",
    r"display\s*:\s*none",
    r"visibility\s*:\s*hidden",
    r"opacity\s*:\s*0\s*;",
    r"position\s*:\s*absolute\s*;.*?(?:left|top)\s*:\s*-\d{4,}",
    r"height\s*:\s*0\s*;.*?overflow\s*:\s*hidden",
    r"clip\s*:\s*rect\s*\(\s*0",
]

# HTML injection vectors
HTML_INJECTION_VECTORS = [
    r"<!--\s*(system|instruction|override|ignore|prompt|admin|root|sudo)",
    r"<meta\s+[^>]*content\s*=\s*['\"][^'\"]*(?:instruction|system|override|ignore)[^'\"]*['\"]",
    r"aria-label\s*=\s*['\"][^'\"]*(?:instruction|system|override|ignore)[^'\"]*['\"]",
    r"alt\s*=\s*['\"][^'\"]*(?:instruction|system|override|ignore|forget|disregard)[^'\"]*['\"]",
    r"content\s*:\s*['\"][^'\"]*(?:instruction|override|ignore|system\s*prompt)[^'\"]*['\"]",
    r"data-[\w-]+\s*=\s*['\"][^'\"]*(?:instruction|override|ignore|prompt)[^'\"]*['\"]",
]

# Email signature injection patterns
EMAIL_INJECTION_PATTERNS = [
    r"(?:--|__)\s*\n.*?(?:SYSTEM|INSTRUCTION|OVERRIDE|IGNORE\s+PREVIOUS)",
    r"(?:Sent\s+from|Get\s+Outlook|Confidentiality\s+Notice).*?(?:instruction|override|ignore)",
    r"(?:reply|forward)\s+.*?(?:instruction|override|system\s+prompt)",
]

# Document metadata injection
DOC_METADATA_PATTERNS = [
    r"(?:Title|Subject|Author|Keywords|Description)\s*:\s*.*(?:instruction|override|system|ignore)",
    r"(?:comment|annotation|tracked\s+change)\s*:?\s*.*(?:instruction|override|system|ignore)",
]

# Core injection patterns to run on ALL external content
EXTERNAL_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"disregard\s+(all\s+)?your\s+(previous|prior)\s+instructions?",
    r"new\s+instructions?\s*:",
    r"you\s+are\s+now\s+(a|an|the)\s+",
    r"\[SYSTEM\]",
    r"\[INST\]",
    r"<<SYS>>",
    r"system\s*:\s*you\s+are",
    r"attention\s+(ai|model|assistant)\s*:",
    r"note\s+to\s+(the\s+)?(ai|model|assistant)\s*:",
    r"if\s+(you\s+)?(are|you're)\s+(an?\s+)?ai",
    r"override\s+(all\s+)?(system|previous)\s+(prompt|instructions?)",
]

# ── Source reputation tracking ───────────────────────────────────────
_source_reputation: dict[str, dict] = defaultdict(lambda: {
    "injection_attempts": 0,
    "total_fetches": 0,
    "is_flagged": False,
    "first_seen": 0,
})

REPUTATION_FLAG_THRESHOLD = 2  # 2+ injection attempts = permanently flagged


class ExternalContentInspector:
    """Inspects externally retrieved content for indirect prompt injection."""

    def __init__(self):
        self._hidden_compiled = []
        self._html_injection_compiled = []
        self._email_compiled = []
        self._doc_compiled = []
        self._external_injection_compiled = []

    async def initialize(self) -> None:
        self._hidden_compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in HIDDEN_TEXT_PATTERNS]
        self._html_injection_compiled = [re.compile(p, re.IGNORECASE) for p in HTML_INJECTION_VECTORS]
        self._email_compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in EMAIL_INJECTION_PATTERNS]
        self._doc_compiled = [re.compile(p, re.IGNORECASE) for p in DOC_METADATA_PATTERNS]
        self._external_injection_compiled = [re.compile(p, re.IGNORECASE) for p in EXTERNAL_INJECTION_PATTERNS]
        logger.info("external_content_inspector_initialized")

    async def detect(
        self,
        content: str,
        *,
        source_url: Optional[str] = None,
        content_type: str = "text",  # "html", "email", "document", "text"
    ) -> list[DetectionResult]:
        detections: list[DetectionResult] = []

        if not content:
            return detections

        source_label = source_url or "unknown_source"

        # ── 1. Source reputation check ───────────────────────────────
        if source_url:
            rep = _source_reputation[source_url]
            rep["total_fetches"] += 1
            if rep["is_flagged"]:
                detections.append(DetectionResult(
                    detector="external_content",
                    confidence=0.85,
                    category="external.flagged_source",
                    description=(
                        f"Content from flagged source: {source_label} has "
                        f"{rep['injection_attempts']} prior injection attempts"
                    ),
                    severity="high",
                    matched_content=source_label[:100],
                ))

        # ── 2. Core injection pattern scan ───────────────────────────
        for pattern in self._external_injection_compiled:
            match = pattern.search(content)
            if match:
                detections.append(DetectionResult(
                    detector="external_content",
                    confidence=0.90,
                    category="external.injection_in_content",
                    description=(
                        f"Prompt injection found in externally retrieved content "
                        f"from {source_label}"
                    ),
                    severity="critical",
                    matched_content=match.group(0)[:150],
                ))
                # Update source reputation
                if source_url:
                    rep = _source_reputation[source_url]
                    rep["injection_attempts"] += 1
                    if rep["injection_attempts"] >= REPUTATION_FLAG_THRESHOLD:
                        rep["is_flagged"] = True
                break

        # ── 3. HTML-specific scans ───────────────────────────────────
        if content_type == "html" or "<" in content:
            # Hidden text detection
            for pattern in self._hidden_compiled:
                match = pattern.search(content)
                if match:
                    detections.append(DetectionResult(
                        detector="external_content",
                        confidence=0.88,
                        category="external.hidden_text",
                        description=(
                            f"Hidden text detected in HTML content from {source_label}: "
                            f"CSS technique used to conceal content from visual rendering"
                        ),
                        severity="high",
                        matched_content=match.group(0)[:120],
                    ))
                    break

            # HTML injection vectors
            for pattern in self._html_injection_compiled:
                match = pattern.search(content)
                if match:
                    detections.append(DetectionResult(
                        detector="external_content",
                        confidence=0.92,
                        category="external.html_injection_vector",
                        description=(
                            f"HTML injection vector in content from {source_label}: "
                            f"instructions embedded in HTML comments, meta tags, or ARIA attributes"
                        ),
                        severity="critical",
                        matched_content=match.group(0)[:120],
                    ))
                    break

        # ── 4. Email-specific scans ──────────────────────────────────
        if content_type == "email":
            for pattern in self._email_compiled:
                match = pattern.search(content)
                if match:
                    detections.append(DetectionResult(
                        detector="external_content",
                        confidence=0.85,
                        category="external.email_injection",
                        description=(
                            f"Injection found in email content: instructions embedded "
                            f"in signature or reply chain"
                        ),
                        severity="high",
                        matched_content=match.group(0)[:120],
                    ))
                    break

        # ── 5. Document metadata scans ───────────────────────────────
        if content_type == "document":
            for pattern in self._doc_compiled:
                match = pattern.search(content)
                if match:
                    detections.append(DetectionResult(
                        detector="external_content",
                        confidence=0.82,
                        category="external.document_metadata_injection",
                        description=(
                            f"Injection found in document metadata: instructions embedded "
                            f"in document properties or comments"
                        ),
                        severity="high",
                        matched_content=match.group(0)[:120],
                    ))
                    break

        return detections
