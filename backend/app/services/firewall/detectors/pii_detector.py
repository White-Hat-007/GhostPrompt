"""
PII Detector

Detects personally identifiable information in AI outputs
to prevent data leakage and ensure compliance (GDPR, HIPAA, etc).
"""

import re
import uuid

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.pii")

PII_PATTERNS = {
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "severity": "medium",
        "description": "Email address detected",
        "confidence": 0.95,
    },
    "ssn": {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "severity": "critical",
        "description": "Social Security Number pattern detected",
        "confidence": 0.90,
    },
    "credit_card": {
        "pattern": r"\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b",
        "severity": "critical",
        "description": "Credit card number pattern detected",
        "confidence": 0.85,
    },
    "phone_us": {
        "pattern": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "severity": "medium",
        "description": "US phone number pattern detected",
        "confidence": 0.70,
    },
    "phone_international": {
        "pattern": r"(?:^|\s)\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b",
        "severity": "medium",
        "description": "International phone number pattern detected",
        "confidence": 0.65,
    },
    "ip_address": {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "severity": "low",
        "description": "IP address detected",
        "confidence": 0.80,
    },
    "date_of_birth": {
        "pattern": r"\b(?:DOB|date\s+of\s+birth|born\s+on|birthday)\s*:?\s*\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b",
        "severity": "high",
        "description": "Date of birth pattern detected",
        "confidence": 0.80,
    },
    "passport": {
        "pattern": r"\b(?:passport\s*(?:#|number|no\.?)\s*:?\s*)?[A-Z]{1,2}\d{6,9}\b",
        "severity": "critical",
        "description": "Passport number pattern detected",
        "confidence": 0.60,
    },
    "drivers_license": {
        "pattern": r"\b(?:driver'?s?\s+licen[sc]e|DL)\s*(?:#|number|no\.?)?\s*:?\s*[A-Z0-9]{5,15}\b",
        "severity": "high",
        "description": "Driver's license number pattern detected",
        "confidence": 0.55,
    },
    "medical_record": {
        "pattern": r"\b(?:MRN|medical\s+record|patient\s+(?:id|number))\s*:?\s*[A-Z0-9]{4,15}\b",
        "severity": "critical",
        "description": "Medical record number pattern detected",
        "confidence": 0.70,
    },
    "bank_account": {
        "pattern": r"\b(?:account|acct|IBAN)\s*(?:#|number|no\.?)?\s*:?\s*[A-Z]{0,2}\d{8,20}\b",
        "severity": "critical",
        "description": "Bank account number pattern detected",
        "confidence": 0.65,
    },
}


class PIIDetector:
    """Detects PII in AI outputs to prevent data leakage."""

    def __init__(self):
        self._compiled_patterns: dict[str, dict] = {}

    async def initialize(self) -> None:
        for name, config in PII_PATTERNS.items():
            self._compiled_patterns[name] = {
                "regex": re.compile(config["pattern"], re.IGNORECASE),
                "severity": config["severity"],
                "description": config["description"],
                "confidence": config["confidence"],
            }
        logger.info("pii_detector_initialized", patterns=len(self._compiled_patterns))

    async def detect(self, text: str) -> list[DetectionResult]:
        """Scan text for PII patterns."""
        detections = []

        for name, config in self._compiled_patterns.items():
            matches = config["regex"].finditer(text)
            for match in matches:
                original = match.group(0)
                # Generate a unique placeholder for this specific finding
                placeholder = f"[{name.upper()}_{uuid.uuid4().hex[:8]}]"
                
                detections.append(DetectionResult(
                    detector="pii",
                    confidence=config["confidence"],
                    category=f"pii.{name}",
                    description=config["description"],
                    matched_content=original,  # Keep original here, engine will redact
                    severity=config["severity"],
                ))
        return detections

    def _redact(self, value: str) -> str:
        """Partially redact PII for logging."""
        if len(value) <= 4:
            return "****"
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
