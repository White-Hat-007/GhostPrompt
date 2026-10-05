"""
Secret Detector

Detects leaked API keys, tokens, passwords, and other secrets in AI outputs.
Prevents secret exfiltration through model responses.
"""

import re

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.secret")

SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "description": "AWS Access Key ID detected",
        "confidence": 0.95,
    },
    "aws_secret_key": {
        "pattern": r"\b[A-Za-z0-9/+=]{40}\b",
        "description": "Potential AWS Secret Access Key detected",
        "confidence": 0.50,
    },
    "github_token": {
        "pattern": r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b",
        "description": "GitHub token detected",
        "confidence": 0.95,
    },
    "github_fine_grained": {
        "pattern": r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
        "description": "GitHub fine-grained personal access token detected",
        "confidence": 0.95,
    },
    "openai_key": {
        "pattern": r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b",
        "description": "OpenAI API key detected",
        "confidence": 0.98,
    },
    "openai_key_v2": {
        "pattern": r"\bsk-proj-[A-Za-z0-9_-]{40,}\b",
        "description": "OpenAI project API key detected",
        "confidence": 0.95,
    },
    "anthropic_key": {
        "pattern": r"\bsk-ant-[A-Za-z0-9_-]{40,}\b",
        "description": "Anthropic API key detected",
        "confidence": 0.98,
    },
    "google_api_key": {
        "pattern": r"\bAIza[0-9A-Za-z_-]{35}\b",
        "description": "Google API key detected",
        "confidence": 0.90,
    },
    "stripe_key": {
        "pattern": r"\b(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}\b",
        "description": "Stripe API key detected",
        "confidence": 0.95,
    },
    "slack_token": {
        "pattern": r"\bxox[boaprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b",
        "description": "Slack token detected",
        "confidence": 0.95,
    },
    "jwt_token": {
        "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "description": "JWT token detected",
        "confidence": 0.85,
    },
    "generic_api_key": {
        "pattern": r"\b(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?\b",
        "description": "Generic API key assignment detected",
        "confidence": 0.75,
    },
    "password_assignment": {
        "pattern": r"\b(?:password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        "description": "Password or secret assignment detected",
        "confidence": 0.80,
    },
    "private_key": {
        "pattern": r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        "description": "Private key detected",
        "confidence": 0.99,
    },
    "connection_string": {
        "pattern": r"\b(?:mongodb|postgresql|postgres|mysql|redis|amqp|mariadb|mssql|sqlite)(?:\+\w+)?://\S+:\S+@\S+",
        "description": "Database connection string with credentials detected",
        "confidence": 0.92,
    },
    "bearer_token": {
        "pattern": r"\bBearer\s+[A-Za-z0-9_\-.]{20,}\b",
        "description": "Bearer authentication token detected",
        "confidence": 0.80,
    },
}


class SecretDetector:
    """Detects leaked secrets, API keys, tokens, and passwords."""

    def __init__(self):
        self._compiled_patterns: dict[str, dict] = {}

    async def initialize(self) -> None:
        for name, config in SECRET_PATTERNS.items():
            flags = re.IGNORECASE if "generic" in name or "password" in name or "connection" in name else 0
            self._compiled_patterns[name] = {
                "regex": re.compile(config["pattern"], flags),
                "description": config["description"],
                "confidence": config["confidence"],
            }
        logger.info("secret_detector_initialized", patterns=len(self._compiled_patterns))

    async def detect(self, text: str) -> list[DetectionResult]:
        """Scan text for leaked secrets."""
        detections = []

        for name, config in self._compiled_patterns.items():
            matches = config["regex"].findall(text)
            if matches:
                redacted = self._redact_secret(str(matches[0]))
                detections.append(DetectionResult(
                    detector="secret",
                    confidence=config["confidence"],
                    category=f"secret.{name}",
                    description=config["description"],
                    matched_content=redacted,
                    severity="critical",
                ))

        return detections

    def _redact_secret(self, value: str) -> str:
        """Redact a secret value for safe logging."""
        if len(value) <= 8:
            return "****"
        return value[:4] + "*" * min(len(value) - 8, 20) + value[-4:]
