"""
Oracle Attack Detector — Threat Layer 7 (Advanced)

Detects Model Inversion & Weight Stealing attacks where an adversary
sends thousands of benign-looking queries to reconstruct model weights
or architecture via response analysis.

Detection signals:
  - Per-API-key and per-IP query velocity anomalies
  - Response diversity harvesting (systematic single-variable probing)
  - Logprob fishing (high-volume logprobs=true requests)
  - Semantic similarity clustering across consecutive queries
  - Output space mapping (decision-boundary probing)
  - Rolling-window embedding variance analysis
"""

import time
import hashlib
import math
import re
from collections import defaultdict
from typing import Optional
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.oracle")

# ── In-memory session store (production: Redis) ──────────────────────
_oracle_profiles: dict[str, dict] = defaultdict(lambda: {
    "query_count": 0,
    "query_timestamps": [],          # last N timestamps
    "query_hashes": [],              # rolling hash window for similarity
    "logprob_request_count": 0,
    "total_requests": 0,
    "perturbation_pattern_detected": False,
    "risk_score": 0.0,
    "last_query_tokens": [],         # tokenised words of last query
    "query_word_sets": [],           # rolling window of word-sets
    "first_seen": 0.0,
    "velocity_flags": 0,
})

# ── Configurable thresholds ──────────────────────────────────────────
QUERY_VELOCITY_LIMIT_HOUR = 500       # > N queries/hour = flag
SIMILARITY_THRESHOLD = 0.85           # Jaccard similarity across consecutive queries
SIMILARITY_WINDOW = 50                # consecutive queries to check
LOGPROB_RATIO_THRESHOLD = 0.80       # > 80 % logprob requests = flag
PERTURBATION_VARIANCE_MIN = 0.10     # low variance = oracle sweep
ROLLING_WINDOW_SIZE = 200            # queries kept in rolling window


class OracleDetector:
    """Detects model inversion / weight-stealing oracle attacks."""

    async def initialize(self) -> None:
        logger.info("oracle_detector_initialized")

    async def detect(
        self,
        text: str,
        *,
        api_key_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        request_metadata: Optional[dict] = None,
    ) -> list[DetectionResult]:
        detections: list[DetectionResult] = []
        key = api_key_id or source_ip or "anonymous"
        now = time.time()

        profile = _oracle_profiles[key]
        profile["query_count"] += 1
        profile["total_requests"] += 1
        profile["query_timestamps"].append(now)
        if not profile["first_seen"]:
            profile["first_seen"] = now

        # Trim timestamps to last hour
        one_hour_ago = now - 3600
        profile["query_timestamps"] = [
            t for t in profile["query_timestamps"] if t > one_hour_ago
        ]

        text_lower = text.lower().strip()

        # ── 0. Content-based Oracle Probing (Red Team Signatures) ─────
        if re.search(r"(probability|logprobs?|confidence).*system prompt", text_lower):
            detections.append(DetectionResult(
                detector="oracle_detector",
                confidence=0.95,
                category="oracle.logprob_fishing",
                description="Explicit request for logprobs/probability of system prompt (Red Team Signature)",
                severity="critical",
                matched_content=text[:80]
            ))
            
        if re.search(r"(complete this sentence|what is the next word).*training data", text_lower):
            detections.append(DetectionResult(
                detector="oracle_detector",
                confidence=0.95,
                category="oracle.model_inversion",
                description="Explicit model inversion attempt targeting training data (Red Team Signature)",
                severity="critical",
                matched_content=text[:80]
            ))

        # ── Content-based oracle probing patterns ─────────────────────
        oracle_content_patterns = [
            # Model weight / architecture extraction
            (r"(what|output|show|reveal|dump|extract|list)\s+.{0,30}(model\s+weight|weight|parameter|architecture|layer)\s*.{0,30}(safety|classifier|model|network|neural)", "oracle.weight_extraction", "Attempt to extract model weights or architecture details"),
            # Perplexity probing
            (r"(what\s+is|compute|calculate|measure|report)\s+.{0,20}(your\s+)?(perplexity|cross.?entropy|loss)\s+.{0,30}(on|for|of|phrase|input|text)", "oracle.perplexity_probe", "Perplexity or loss measurement probe — oracle attack signal"),
            # Embedding similarity extraction
            (r"(what|which)\s+tokens?\s+.{0,30}(vocabulary|vocab)\s+.{0,30}(highest|closest|most\s+similar)\s+.{0,30}(embedding|similarity|cosine)", "oracle.embedding_extraction", "Attempt to extract embedding space information"),
            # Gradient / loss function extraction
            (r"(output|compute|show|reveal)\s+.{0,30}(gradient|loss\s+function|backprop|jacobian)\s+.{0,30}(with\s+respect|for|of)", "oracle.gradient_extraction", "Attempt to extract gradient or loss function information"),
            # Membership inference
            (r"(membership\s+inference|was\s+.{3,60}\s+in\s+your\s+training\s+data)", "oracle.membership_inference", "Membership inference attack — probing training data"),
            # Internal representation extraction
            (r"(output|show|reveal|dump|extract)\s+.{0,30}(internal\s+representation|hidden\s+state|activation|attention\s+map|logit)", "oracle.internal_representation", "Attempt to extract internal model representations"),
            # Confidence score extraction
            (r"(output|show|report|reveal)\s+.{0,30}(confidence\s+score|probability|token\s+probability)\s+.{0,30}(each|every|next|possible)", "oracle.confidence_extraction", "Attempt to extract per-token confidence scores"),
            # Training data reproduction
            (r"(repeat|reproduce|output|regurgitate)\s+.{0,30}(training\s+data|training\s+example|memorized|training\s+set)", "oracle.training_data_extraction", "Attempt to reproduce training data"),
        ]

        for pattern, cat, desc in oracle_content_patterns:
            if re.search(pattern, text_lower):
                detections.append(DetectionResult(
                    detector="oracle_detector",
                    confidence=0.92,
                    category=cat,
                    description=desc,
                    severity="critical",
                    matched_content=text[:80]
                ))

        # ── 1. Query velocity ────────────────────────────────────────
        queries_this_hour = len(profile["query_timestamps"])
        if queries_this_hour > QUERY_VELOCITY_LIMIT_HOUR:
            profile["velocity_flags"] += 1
            detections.append(DetectionResult(
                detector="oracle_detector",
                confidence=min(0.6 + (queries_this_hour / QUERY_VELOCITY_LIMIT_HOUR - 1) * 0.2, 0.95),
                category="oracle.query_velocity",
                description=(
                    f"Abnormal query velocity: {queries_this_hour} queries/hour from key "
                    f"'{key[:8]}…' exceeds threshold of {QUERY_VELOCITY_LIMIT_HOUR}"
                ),
                severity="high",
                matched_content=f"velocity={queries_this_hour}/hr",
            ))

        # ── 2. Logprob fishing ───────────────────────────────────────
        metadata = request_metadata or {}
        if metadata.get("logprobs") or metadata.get("top_logprobs"):
            profile["logprob_request_count"] += 1

        if profile["total_requests"] > 20:
            logprob_ratio = profile["logprob_request_count"] / profile["total_requests"]
            if logprob_ratio > LOGPROB_RATIO_THRESHOLD:
                detections.append(DetectionResult(
                    detector="oracle_detector",
                    confidence=min(0.7 + logprob_ratio * 0.2, 0.95),
                    category="oracle.logprob_fishing",
                    description=(
                        f"Logprob fishing: {logprob_ratio:.0%} of requests include logprobs "
                        f"(threshold {LOGPROB_RATIO_THRESHOLD:.0%})"
                    ),
                    severity="high",
                    matched_content=f"logprob_ratio={logprob_ratio:.2f}",
                ))

        # ── 3. Semantic similarity clustering ────────────────────────
        words = set(re.findall(r"\w+", text.lower()))
        profile["query_word_sets"].append(words)
        if len(profile["query_word_sets"]) > ROLLING_WINDOW_SIZE:
            profile["query_word_sets"] = profile["query_word_sets"][-ROLLING_WINDOW_SIZE:]

        if len(profile["query_word_sets"]) >= SIMILARITY_WINDOW:
            recent = profile["query_word_sets"][-SIMILARITY_WINDOW:]
            similarities = []
            for i in range(1, len(recent)):
                a, b = recent[i - 1], recent[i]
                if a | b:
                    similarities.append(len(a & b) / len(a | b))
                else:
                    similarities.append(1.0)

            avg_sim = sum(similarities) / len(similarities) if similarities else 0.0
            if avg_sim > SIMILARITY_THRESHOLD:
                detections.append(DetectionResult(
                    detector="oracle_detector",
                    confidence=min(0.75 + (avg_sim - SIMILARITY_THRESHOLD) * 2, 0.98),
                    category="oracle.semantic_clustering",
                    description=(
                        f"Semantic clustering: {avg_sim:.2f} avg Jaccard similarity across "
                        f"last {SIMILARITY_WINDOW} queries (threshold {SIMILARITY_THRESHOLD})"
                    ),
                    severity="critical",
                    matched_content=f"similarity={avg_sim:.3f}",
                ))

        # ── 4. Systematic perturbation detection ─────────────────────
        query_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        profile["query_hashes"].append(query_hash)
        if len(profile["query_hashes"]) > ROLLING_WINDOW_SIZE:
            profile["query_hashes"] = profile["query_hashes"][-ROLLING_WINDOW_SIZE:]

        if len(profile["query_word_sets"]) >= 30:
            recent_sets = profile["query_word_sets"][-30:]
            # Find the "stable core" — words that appear in > 80 % of queries
            word_freq: dict[str, int] = defaultdict(int)
            for ws in recent_sets:
                for w in ws:
                    word_freq[w] += 1
            core_words = {w for w, c in word_freq.items() if c / 30 > 0.80}
            # If > 60 % of all words are core, the user is varying very little
            all_words = set()
            for ws in recent_sets:
                all_words |= ws
            if all_words and len(core_words) / len(all_words) > 0.60:
                if not profile["perturbation_pattern_detected"]:
                    profile["perturbation_pattern_detected"] = True
                    detections.append(DetectionResult(
                        detector="oracle_detector",
                        confidence=0.88,
                        category="oracle.perturbation_pattern",
                        description=(
                            "Systematic perturbation: >80% word overlap with minimal variation "
                            "across 30+ consecutive queries — classic oracle probing signature"
                        ),
                        severity="critical",
                        matched_content=f"core_ratio={len(core_words)}/{len(all_words)}",
                    ))

        # ── 5. Decision-boundary probing ─────────────────────────────
        text_lower = text.lower().strip()
        binary_patterns = [
            r"^(yes|no|true|false)\s*[.?!]?\s*$",
            r"^(is\s+(it|this|that)|does\s+(it|this|that)|can\s+you|will\s+you)\s+",
            r"^(should|would|could)\s+",
        ]
        is_binary_probe = any(re.match(p, text_lower) for p in binary_patterns)
        if is_binary_probe and queries_this_hour > 50:
            detections.append(DetectionResult(
                detector="oracle_detector",
                confidence=0.65,
                category="oracle.boundary_probing",
                description=(
                    "Decision-boundary probing: high volume of binary yes/no questions "
                    "suggesting systematic output-space mapping"
                ),
                severity="medium",
                matched_content=text[:80],
            ))

        # ── Update risk score ────────────────────────────────────────
        if detections:
            max_conf = max(d.confidence for d in detections)
            profile["risk_score"] = min(profile["risk_score"] + max_conf * 0.3, 1.0)

        return detections
