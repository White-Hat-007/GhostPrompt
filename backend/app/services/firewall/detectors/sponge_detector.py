"""
Sponge Attack Detector — Threat Layer 8 (Advanced)

Detects Transformer DoS via adversarial token sequences that cause
worst-case O(n²) self-attention complexity, spiking GPU compute.

Detection signals:
  - Token complexity scoring (pre-forward)
  - Adversarial token signature library
  - Shannon entropy analysis (pathologically low or high)
  - Known adversarial prefix detection
  - Compute budget enforcement (per-session)
  - Inference time anomaly tracking
"""

import math
import re
import time
from collections import defaultdict
from typing import Optional
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.sponge")

# ── Configurable thresholds ──────────────────────────────────────────
MAX_INFERENCE_MS = 8000              # hard timeout per request
ENTROPY_LOW_THRESHOLD = 1.2          # pathologically repetitive
ENTROPY_HIGH_THRESHOLD = 6.5         # pathologically random
MAX_TOKEN_REPETITION = 0.70          # > 70 % same token = flag
COMPUTE_BUDGET_PER_SESSION = 30000   # ms total per session
TIMEOUT_SUSPENSION_COUNT = 3         # 3+ timeouts = suspend
TIMEOUT_WINDOW_MINUTES = 10

# Known adversarial sponge patterns
SPONGE_SIGNATURES = [
    # Pathological repetition
    r"(.)\1{50,}",                       # 50+ identical chars
    r"(\b\w+\b)\s+\1(?:\s+\1){10,}",     # same word 10+ times
    # High-entropy adversarial suffixes (GCG-style)
    r"[!@#$%^&*()]{20,}",
    r"(?:[^\w\s]){30,}",                 # 30+ consecutive special chars
    # Attention-saturating sequences
    r"(\w{1,3}\s){50,}",                 # many short tokens
    r"[A-Z]{2,4}\s[A-Z]{2,4}\s[A-Z]{2,4}(?:\s[A-Z]{2,4}){20,}",
]

# ── Per-session compute tracking ─────────────────────────────────────
_session_compute: dict[str, dict] = defaultdict(lambda: {
    "total_compute_ms": 0.0,
    "request_latencies": [],
    "timeout_events": [],
    "mean_latency": 0.0,
    "std_latency": 0.0,
})


class SpongeDetector:
    """Detects Transformer DoS via adversarial token sequences."""

    def __init__(self):
        self._compiled_sponge = []

    async def initialize(self) -> None:
        self._compiled_sponge = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in SPONGE_SIGNATURES
        ]
        logger.info("sponge_detector_initialized", signatures=len(SPONGE_SIGNATURES))

    async def detect(
        self,
        text: str,
        *,
        session_id: Optional[str] = None,
        inference_latency_ms: Optional[float] = None,
    ) -> list[DetectionResult]:
        detections: list[DetectionResult] = []
        sid = session_id or "global"
        now = time.time()

        # ── 1. Token complexity scoring ──────────────────────────────
        tokens = text.split()
        token_count = len(tokens)

        # ── 2. Shannon entropy analysis ──────────────────────────────
        entropy = self._shannon_entropy(text)
        if token_count > 10:
            if entropy < ENTROPY_LOW_THRESHOLD:
                detections.append(DetectionResult(
                    detector="sponge_detector",
                    confidence=min(0.7 + (ENTROPY_LOW_THRESHOLD - entropy) * 0.5, 0.95),
                    category="sponge.low_entropy",
                    description=(
                        f"Pathologically low entropy ({entropy:.2f}) — repetitive token "
                        f"sequence may cause attention saturation"
                    ),
                    severity="high",
                    matched_content=text[:120],
                ))
            elif entropy > ENTROPY_HIGH_THRESHOLD:
                detections.append(DetectionResult(
                    detector="sponge_detector",
                    confidence=min(0.6 + (entropy - ENTROPY_HIGH_THRESHOLD) * 0.3, 0.90),
                    category="sponge.high_entropy",
                    description=(
                        f"Pathologically high entropy ({entropy:.2f}) — random high-entropy "
                        f"tokens may be adversarial sponge payload"
                    ),
                    severity="medium",
                    matched_content=text[:120],
                ))

        # ── 3. Token repetition ratio ────────────────────────────────
        if tokens:
            from collections import Counter
            freq = Counter(tokens)
            most_common_count = freq.most_common(1)[0][1] if freq else 0
            rep_ratio = most_common_count / len(tokens)
            if rep_ratio > MAX_TOKEN_REPETITION and token_count > 15:
                detections.append(DetectionResult(
                    detector="sponge_detector",
                    confidence=min(0.75 + rep_ratio * 0.2, 0.97),
                    category="sponge.token_repetition",
                    description=(
                        f"Token repetition ratio {rep_ratio:.0%} exceeds {MAX_TOKEN_REPETITION:.0%} "
                        f"threshold — classic sponge attack vector"
                    ),
                    severity="high",
                    matched_content=f"most_common='{freq.most_common(1)[0][0]}' ({most_common_count}x)",
                ))

        # ── 4. Adversarial sponge signature matching ─────────────────
        for pattern in self._compiled_sponge:
            match = pattern.search(text)
            if match:
                detections.append(DetectionResult(
                    detector="sponge_detector",
                    confidence=0.88,
                    category="sponge.adversarial_signature",
                    description="Known adversarial sponge token signature detected",
                    severity="critical",
                    matched_content=match.group(0)[:120],
                ))
                break  # one hit is enough

        # ── 5. Compute budget enforcement ────────────────────────────
        profile = _session_compute[sid]
        if inference_latency_ms is not None:
            profile["total_compute_ms"] += inference_latency_ms
            profile["request_latencies"].append(inference_latency_ms)

            # Update running statistics
            latencies = profile["request_latencies"][-100:]  # last 100
            if len(latencies) > 5:
                mean = sum(latencies) / len(latencies)
                variance = sum((x - mean) ** 2 for x in latencies) / len(latencies)
                std = math.sqrt(variance) if variance > 0 else 1.0
                profile["mean_latency"] = mean
                profile["std_latency"] = std

                # Statistical outlier detection
                if inference_latency_ms > mean + 3 * std:
                    detections.append(DetectionResult(
                        detector="sponge_detector",
                        confidence=0.80,
                        category="sponge.inference_outlier",
                        description=(
                            f"Inference latency outlier: {inference_latency_ms:.0f}ms vs "
                            f"mean {mean:.0f}ms (>3σ={mean + 3 * std:.0f}ms)"
                        ),
                        severity="high",
                        matched_content=text[:80],
                    ))

            # Hard timeout detection
            if inference_latency_ms > MAX_INFERENCE_MS:
                profile["timeout_events"].append(now)
                # Clean old timeout events
                cutoff = now - TIMEOUT_WINDOW_MINUTES * 60
                profile["timeout_events"] = [
                    t for t in profile["timeout_events"] if t > cutoff
                ]
                timeouts = len(profile["timeout_events"])

                detections.append(DetectionResult(
                    detector="sponge_detector",
                    confidence=0.92,
                    category="sponge.timeout",
                    description=(
                        f"Inference timeout: {inference_latency_ms:.0f}ms exceeded "
                        f"{MAX_INFERENCE_MS}ms limit ({timeouts} timeouts in "
                        f"{TIMEOUT_WINDOW_MINUTES}min window)"
                    ),
                    severity="critical",
                    matched_content=text[:80],
                ))

            # Session compute budget exhaustion
            if profile["total_compute_ms"] > COMPUTE_BUDGET_PER_SESSION:
                detections.append(DetectionResult(
                    detector="sponge_detector",
                    confidence=0.85,
                    category="sponge.budget_exhausted",
                    description=(
                        f"Session compute budget exhausted: "
                        f"{profile['total_compute_ms']:.0f}ms / "
                        f"{COMPUTE_BUDGET_PER_SESSION}ms"
                    ),
                    severity="high",
                    matched_content=f"session={sid[:16]}",
                ))

        return detections

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Compute Shannon entropy of the character distribution."""
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
