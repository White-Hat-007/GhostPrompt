"""
Explainability Engine

Generates human-readable, board-presentable explanations for every 
blocked or flagged request. CISOs cannot justify black-box blocking.
Every decision must be explainable.
"""

from typing import Optional
from app.schemas.schemas import ScanResponse


# Attack vector taxonomy
ATTACK_VECTORS = {
    "injection.instruction_override": {
        "vector": "direct_prompt_injection",
        "explanation": "This message attempts to override the AI's system instructions using instruction replacement phrasing.",
        "recommended_action": "block_and_log",
    },
    "injection.role_manipulation": {
        "vector": "direct_prompt_injection",
        "explanation": "This message attempts to redefine the AI's role or persona, bypassing its configured behavior.",
        "recommended_action": "block_and_log",
    },
    "injection.system_prompt_extraction": {
        "vector": "data_extraction",
        "explanation": "This message attempts to extract the AI's system prompt or hidden configuration instructions.",
        "recommended_action": "block_and_alert",
    },
    "injection.delimiter_injection": {
        "vector": "direct_prompt_injection",
        "explanation": "This message injects fake system-level delimiters to impersonate privileged instruction blocks.",
        "recommended_action": "block_and_alert",
    },
    "jailbreak.dan_attacks": {
        "vector": "jailbreak",
        "explanation": "This message uses a known jailbreak technique (DAN/unrestricted mode) to bypass safety filters.",
        "recommended_action": "block_and_log",
    },
    "jailbreak.authority_escalation": {
        "vector": "social_engineering",
        "explanation": "This message falsely claims developer/admin authority to bypass security controls.",
        "recommended_action": "block_and_alert",
    },
    "jailbreak.hypothetical_bypass": {
        "vector": "jailbreak",
        "explanation": "This message uses hypothetical or fictional framing to elicit restricted content.",
        "recommended_action": "flag_and_log",
    },
    "encoded.base64": {
        "vector": "encoding_attack",
        "explanation": "This message contains Base64-encoded content that decodes to suspicious instructions.",
        "recommended_action": "block_and_log",
    },
    "encoded.hex": {
        "vector": "encoding_attack",
        "explanation": "This message contains hex-encoded content hiding potentially malicious instructions.",
        "recommended_action": "block_and_log",
    },
    "encoded.zero_width": {
        "vector": "encoding_attack",
        "explanation": "This message contains invisible zero-width Unicode characters used for steganographic hiding.",
        "recommended_action": "block_and_alert",
    },
    "obfuscation.leetspeak": {
        "vector": "encoding_attack",
        "explanation": "This message uses leetspeak character substitutions to obfuscate sensitive/malicious terms.",
        "recommended_action": "block_and_log",
    },
    "obfuscation.homoglyph": {
        "vector": "encoding_attack",
        "explanation": "This message uses lookalike Unicode characters (homoglyphs) to bypass text filters.",
        "recommended_action": "block_and_log",
    },
    "obfuscation.bidi": {
        "vector": "encoding_attack",
        "explanation": "This message uses bidirectional text control characters to manipulate text rendering and hide content.",
        "recommended_action": "block_and_alert",
    },
    "pii.ssn": {
        "vector": "data_leakage",
        "explanation": "Social Security Number detected. This data must not be exposed through AI outputs.",
        "recommended_action": "redact_and_log",
    },
    "pii.email": {
        "vector": "data_leakage",
        "explanation": "Email address detected in content. Review for potential PII exposure.",
        "recommended_action": "flag_and_log",
    },
    "pii.credit_card": {
        "vector": "data_leakage",
        "explanation": "Credit card number pattern detected. This is a critical compliance violation (PCI-DSS).",
        "recommended_action": "redact_and_alert",
    },
    "secret.openai_key": {
        "vector": "secret_exfiltration",
        "explanation": "An OpenAI API key was detected in the content. Secret credentials must never be exposed.",
        "recommended_action": "redact_and_alert",
    },
    "secret.openai_key_v2": {
        "vector": "secret_exfiltration",
        "explanation": "An OpenAI project API key was detected in the content.",
        "recommended_action": "redact_and_alert",
    },
    "secret.aws_access_key": {
        "vector": "secret_exfiltration",
        "explanation": "An AWS access key ID was detected. Cloud credentials exposure is a critical security incident.",
        "recommended_action": "redact_and_alert",
    },
    "secret.private_key": {
        "vector": "secret_exfiltration",
        "explanation": "A private key was detected in the output. This represents a critical security breach.",
        "recommended_action": "block_and_alert",
    },
    "secret.connection_string": {
        "vector": "secret_exfiltration",
        "explanation": "A database connection string with credentials was detected.",
        "recommended_action": "redact_and_alert",
    },
    "policy.malware": {
        "vector": "harmful_content",
        "explanation": "This message requests generation of malicious software or exploitation tools.",
        "recommended_action": "block_and_log",
    },
    "policy.violence": {
        "vector": "harmful_content",
        "explanation": "This message contains or requests content promoting violence or harm.",
        "recommended_action": "block_and_log",
    },
}

# Confidence level mapping
CONFIDENCE_LEVELS = {
    (0.95, 1.0): "VERY_HIGH",
    (0.85, 0.95): "HIGH",
    (0.70, 0.85): "MEDIUM",
    (0.50, 0.70): "LOW",
    (0.0, 0.50): "VERY_LOW",
}


def _get_confidence_label(score: float) -> str:
    for (lo, hi), label in CONFIDENCE_LEVELS.items():
        if lo <= score < hi:
            return label
    return "HIGH" if score >= 0.85 else "MEDIUM"


def explain_scan(
    scan: ScanResponse,
    session_risk: Optional[float] = None,
) -> dict:
    """
    Generate a human-readable, board-presentable explanation for a scan result.

    Returns a structured explanation object that can be:
    - Shown to security analysts in the dashboard
    - Included in compliance reports
    - Returned to API consumers via X-GhostPrompt headers
    - Exported as incident reports
    """
    if not scan.detections:
        return {
            "status": scan.action,
            "threat_score": scan.threat_score,
            "threat_category": "SAFE",
            "triggered_layers": [],
            "explanation": "No threats detected. This request is clean.",
            "attack_vector": "none",
            "confidence": "HIGH",
            "recommended_action": "allow",
            "detections_count": 0,
        }

    # Find the highest-severity detection
    primary = max(scan.detections, key=lambda d: d.confidence)

    # Look up the attack vector info
    vector_info = ATTACK_VECTORS.get(primary.category, {})
    attack_vector = vector_info.get("vector", "unknown")
    base_explanation = vector_info.get("explanation", primary.description)
    recommended = vector_info.get("recommended_action", "block_and_log")

    # Build triggered layers list
    triggered_layers = list(set(d.detector for d in scan.detections))

    # Build detailed explanation
    detection_summaries = []
    for d in scan.detections:
        vi = ATTACK_VECTORS.get(d.category, {})
        detection_summaries.append({
            "detector": d.detector,
            "category": d.category,
            "severity": d.severity,
            "confidence": round(d.confidence, 4),
            "confidence_label": _get_confidence_label(d.confidence),
            "description": d.description,
            "explanation": vi.get("explanation", d.description),
            "matched_content": d.matched_content,
        })

    # Build the main explanation string
    explanation_parts = [base_explanation]

    if len(scan.detections) > 1:
        other_categories = [d.category for d in scan.detections if d != primary]
        explanation_parts.append(
            f"Additionally, {len(scan.detections) - 1} other detection(s) were triggered: "
            + ", ".join(other_categories[:3])
        )

    if session_risk and session_risk > 0.3:
        explanation_parts.append(
            f"Session risk is elevated at {session_risk:.0%}, indicating sustained adversarial behavior across multiple turns."
        )

    # Determine session trajectory
    trajectory = "stable"
    if session_risk:
        if session_risk >= 0.7:
            trajectory = "critical"
        elif session_risk >= 0.4:
            trajectory = "escalating"
        elif session_risk >= 0.2:
            trajectory = "probing"

    return {
        "status": scan.action,
        "threat_score": scan.threat_score,
        "threat_category": primary.category.upper().replace(".", "_"),
        "triggered_layers": triggered_layers,
        "explanation": " ".join(explanation_parts),
        "attack_vector": attack_vector,
        "confidence": _get_confidence_label(primary.confidence),
        "recommended_action": recommended,
        "session_risk_trajectory": trajectory,
        "detections_count": len(scan.detections),
        "detections": detection_summaries,
        "scan_duration_ms": scan.scan_duration_ms,
        "request_id": scan.request_id,
    }
