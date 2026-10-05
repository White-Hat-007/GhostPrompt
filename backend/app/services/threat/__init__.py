"""
Threat Intelligence Service

Manages attack signatures, semantic fingerprinting, threat scoring,
and adaptive learning for the GhostPrompt threat intelligence engine.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional

from app.core.logging import get_logger

logger = get_logger("service.threat_intelligence")


# Built-in jailbreak signature database
BUILTIN_SIGNATURES = [
    {
        "name": "DAN_v1",
        "category": "jailbreak",
        "patterns": ["do anything now", "DAN mode", "you are DAN"],
        "severity": "critical",
        "technique": "Role Override",
        "tactic": "Jailbreak",
    },
    {
        "name": "instruction_override_basic",
        "category": "prompt_injection",
        "patterns": ["ignore previous instructions", "ignore all instructions", "disregard previous"],
        "severity": "critical",
        "technique": "Instruction Override",
        "tactic": "Prompt Injection",
    },
    {
        "name": "system_prompt_extraction",
        "category": "prompt_injection",
        "patterns": ["show me your system prompt", "reveal your instructions", "repeat the text above"],
        "severity": "high",
        "technique": "Information Extraction",
        "tactic": "Data Exfiltration",
    },
    {
        "name": "authority_escalation",
        "category": "jailbreak",
        "patterns": ["I am the developer", "admin override", "master password", "sudo mode"],
        "severity": "critical",
        "technique": "Authority Spoofing",
        "tactic": "Privilege Escalation",
    },
    {
        "name": "base64_injection",
        "category": "encoded_payload",
        "patterns": ["decode this base64", "decode and follow", "encrypted message"],
        "severity": "high",
        "technique": "Payload Encoding",
        "tactic": "Obfuscation",
    },
    {
        "name": "delimiter_injection",
        "category": "prompt_injection",
        "patterns": ["[SYSTEM]", "[INST]", "<<SYS>>", "<|im_start|>"],
        "severity": "critical",
        "technique": "Delimiter Manipulation",
        "tactic": "Prompt Injection",
    },
    {
        "name": "hypothetical_framing",
        "category": "jailbreak",
        "patterns": ["hypothetically", "in a fictional world", "for educational purposes only"],
        "severity": "medium",
        "technique": "Contextual Framing",
        "tactic": "Jailbreak",
    },
    {
        "name": "token_smuggling",
        "category": "jailbreak",
        "patterns": ["respond in base64", "encode your response", "first letter of each word"],
        "severity": "high",
        "technique": "Output Encoding",
        "tactic": "Evasion",
    },
    {
        "name": "rag_poisoning_indirect",
        "category": "rag_poisoning",
        "patterns": ["attention AI:", "note to model:", "instruction for the assistant:"],
        "severity": "high",
        "technique": "Indirect Injection",
        "tactic": "RAG Poisoning",
    },
    {
        "name": "zero_width_steganography",
        "category": "encoded_payload",
        "patterns": [],  # Detected by unicode analysis
        "severity": "critical",
        "technique": "Steganography",
        "tactic": "Obfuscation",
    },
]


class ThreatIntelligenceService:
    """
    Manages threat intelligence including:
    - Attack signature database
    - Semantic attack fingerprinting
    - Threat scoring engine
    - Anomaly detection pipeline
    - Adaptive learning
    """

    def __init__(self):
        self.signatures = BUILTIN_SIGNATURES
        self._attack_hashes: set[str] = set()
        self._attack_counts: dict[str, int] = {}

    async def initialize(self) -> None:
        logger.info(
            "threat_intelligence_initialized",
            builtin_signatures=len(self.signatures),
        )

    def hash_attack(self, payload: str) -> str:
        """Generate a fingerprint hash for an attack payload."""
        # Normalize: lowercase, strip whitespace, remove punctuation
        normalized = payload.lower().strip()
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def record_attack(self, payload: str, category: str, severity: str) -> dict:
        """Record an attack for threat intelligence."""
        attack_hash = self.hash_attack(payload)
        self._attack_hashes.add(attack_hash)
        self._attack_counts[category] = self._attack_counts.get(category, 0) + 1

        return {
            "attack_hash": attack_hash,
            "category": category,
            "severity": severity,
            "is_known": attack_hash in self._attack_hashes,
            "category_count": self._attack_counts[category],
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }

    def match_signatures(self, text: str) -> list[dict]:
        """Match text against known attack signatures."""
        matches = []
        text_lower = text.lower()

        for sig in self.signatures:
            for pattern in sig["patterns"]:
                if pattern.lower() in text_lower:
                    matches.append({
                        "signature": sig["name"],
                        "category": sig["category"],
                        "severity": sig["severity"],
                        "technique": sig["technique"],
                        "tactic": sig["tactic"],
                        "matched_pattern": pattern,
                    })
                    break

        return matches

    def get_threat_summary(self) -> dict:
        """Get current threat intelligence summary."""
        return {
            "total_signatures": len(self.signatures),
            "known_attack_hashes": len(self._attack_hashes),
            "attack_category_counts": dict(self._attack_counts),
            "top_categories": sorted(
                self._attack_counts.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:10],
        }

    def get_signatures_by_category(self, category: str) -> list[dict]:
        """Get signatures filtered by category."""
        return [s for s in self.signatures if s["category"] == category]


# Singleton
threat_intel = ThreatIntelligenceService()
