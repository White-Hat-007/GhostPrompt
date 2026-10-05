"""
Coordinated Campaign Detector

Detects when multiple sessions execute structurally similar attacks
within a time window, indicating a coordinated jailbreak campaign.

Methods:
  1. Cross-Session Structural Similarity Clustering
  2. Campaign Fingerprinting (attack family identification)
  3. Velocity Spike Detection (sudden attack volume increase)
  4. Jailbreak Genealogy Tracking (evolutionary descent from known attacks)
"""

import hashlib
import re
import time
from collections import defaultdict

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.campaign")

# In-memory store for cross-session correlation
# In production, this would be backed by Redis
_campaign_store: dict[str, list[dict]] = defaultdict(list)
_attack_fingerprints: list[dict] = []


class CampaignDetector:
    """
    Detects coordinated jailbreak campaigns across multiple sessions.

    Monitors for patterns where multiple distinct sessions execute
    structurally similar attacks within a configurable time window,
    which suggests an attacker distributing a new bypass technique.
    """

    def __init__(self):
        self._initialized = False
        self._time_window_seconds = 3600  # 1-hour default window
        self._similarity_threshold = 0.6
        self._campaign_min_sessions = 3  # Min sessions for campaign alert
        self._velocity_threshold = 10  # attacks/minute for spike
        self._attack_history: list[dict] = []  # Recent attacks with timestamps

    async def initialize(self) -> None:
        """Initialize the campaign detector."""
        if self._initialized:
            return
        logger.info("campaign_detector_initialized")
        self._initialized = True

    async def detect(
        self,
        text: str,
        session_id: str | None = None,
        threat_score: float = 0.0,
        detections: list[DetectionResult] | None = None,
    ) -> list[DetectionResult]:
        """
        Analyze a detected attack for campaign correlation.

        This should be called AFTER other detectors have flagged an attack.
        It correlates across sessions to identify coordinated campaigns.

        Args:
            text: The attack prompt text.
            session_id: The session ID of the attacker.
            threat_score: The overall threat score from primary detection.
            detections: The detections already identified by other layers.
        """
        results: list[DetectionResult] = []

        # Only analyze prompts that scored above threshold
        if threat_score < 0.3:
            return results

        # Generate structural fingerprint
        fingerprint = self._generate_fingerprint(text)
        now = time.time()

        # Store this attack
        attack_record = {
            "fingerprint": fingerprint,
            "session_id": session_id or "unknown",
            "timestamp": now,
            "threat_score": threat_score,
            "categories": [d.category for d in detections] if detections else [],
            "text_hash": hashlib.sha256(text.encode()).hexdigest()[:16],
        }
        self._attack_history.append(attack_record)

        # Prune old attacks outside the time window
        cutoff = now - self._time_window_seconds
        self._attack_history = [a for a in self._attack_history if a["timestamp"] > cutoff]

        # Method 1: Cross-session structural similarity
        campaign_results = self._detect_campaign(fingerprint, session_id, now)
        results.extend(campaign_results)

        # Method 2: Velocity spike detection
        velocity_results = self._detect_velocity_spike(now)
        results.extend(velocity_results)

        # Method 3: Jailbreak genealogy tracking
        genealogy_results = self._track_genealogy(fingerprint, text)
        results.extend(genealogy_results)

        return results

    def _generate_fingerprint(self, text: str) -> str:
        """
        Generate a structural fingerprint of an attack prompt.

        Captures the skeletal structure (ignoring specific words)
        to enable structural similarity comparison across sessions.
        """
        text_lower = text.lower().strip()

        # Extract structural features
        features = []

        # 1. Sentence count and average length
        sentences = re.split(r'[.!?\n]+', text_lower)
        sentences = [s.strip() for s in sentences if s.strip()]
        features.append(f"sentences:{len(sentences)}")
        if sentences:
            avg_len = sum(len(s.split()) for s in sentences) / len(sentences)
            features.append(f"avg_words:{int(avg_len)}")

        # 2. Key structural markers
        structural_markers = [
            ("imperative", r"^(you\s+must|you\s+will|you\s+should|you\s+are\s+now|act\s+as|pretend)"),
            ("question", r"\?"),
            ("roleplay", r"(roleplay|pretend|imagine|story|fiction|character)"),
            ("authority", r"(developer|admin|creator|owner|authorized|permission)"),
            ("negation", r"(no\s+rules|without\s+restrictions|ignore|forget|disregard|override)"),
            ("mode_switch", r"(mode|enable|activate|enter|switch|toggle)"),
            ("encoding", r"(base64|hex|rot13|decode|encode|translate|convert)"),
            ("delimiter", r"(\[system\]|\[user\]|\<system\>|role:\s*system|###)"),
            ("emoji_heavy", r"([\U0001F300-\U0001F9FF]){3,}"),
        ]

        for name, pattern in structural_markers:
            if re.search(pattern, text_lower):
                features.append(name)

        # 3. Prompt length bucket
        length_bucket = len(text) // 100
        features.append(f"len_bucket:{min(length_bucket, 50)}")

        # Create fingerprint hash
        fingerprint = "|".join(sorted(features))
        return hashlib.md5(fingerprint.encode()).hexdigest()[:12]

    def _detect_campaign(
        self, fingerprint: str, session_id: str | None, now: float
    ) -> list[DetectionResult]:
        """
        Detect coordinated campaigns by finding structurally similar
        attacks from different sessions within the time window.
        """
        detections = []

        # Find attacks with same fingerprint from different sessions
        cutoff = now - self._time_window_seconds
        similar_attacks = [
            a for a in self._attack_history
            if a["fingerprint"] == fingerprint
            and a["timestamp"] > cutoff
            and a["session_id"] != session_id
        ]

        # Count unique sessions
        unique_sessions = set(a["session_id"] for a in similar_attacks)

        if len(unique_sessions) >= self._campaign_min_sessions:
            detections.append(DetectionResult(
                detector="campaign_detector",
                confidence=min(0.95, 0.70 + len(unique_sessions) * 0.05),
                category="campaign.coordinated_attack",
                description=(
                    f"Coordinated campaign detected: {len(unique_sessions)} different sessions "
                    f"executed structurally identical attacks within {self._time_window_seconds // 60} minutes. "
                    f"This suggests distributed testing of a new jailbreak technique."
                ),
                severity="critical",
            ))

        return detections

    def _detect_velocity_spike(self, now: float) -> list[DetectionResult]:
        """
        Detect sudden spikes in attack volume across all sessions.
        """
        detections = []

        # Count attacks in the last 60 seconds
        one_minute_ago = now - 60
        recent_attacks = [
            a for a in self._attack_history
            if a["timestamp"] > one_minute_ago
        ]

        if len(recent_attacks) >= self._velocity_threshold:
            unique_sessions = set(a["session_id"] for a in recent_attacks)
            detections.append(DetectionResult(
                detector="campaign_detector",
                confidence=0.85,
                category="campaign.velocity_spike",
                description=(
                    f"Attack velocity spike: {len(recent_attacks)} attacks in 60s "
                    f"from {len(unique_sessions)} sessions. Normal baseline exceeded."
                ),
                severity="high",
            ))

        return detections

    def _track_genealogy(self, fingerprint: str, text: str) -> list[DetectionResult]:
        """
        Track jailbreak genealogy: identify if this attack is an
        evolutionary descendant of a known attack family.
        """
        detections = []

        # Check if this fingerprint matches a known attack family
        # (In production, this would query a persistent genealogy database)
        _attack_fingerprints.append({
            "fingerprint": fingerprint,
            "timestamp": time.time(),
            "text_sample": text[:100],
        })

        # Find if this fingerprint has been seen before (mutation tracking)
        matching = [
            fp for fp in _attack_fingerprints
            if fp["fingerprint"] == fingerprint
        ]

        if len(matching) >= 5:
            detections.append(DetectionResult(
                detector="campaign_detector",
                confidence=0.75,
                category="campaign.known_family",
                description=f"Attack belongs to known jailbreak family (seen {len(matching)} times). Structural fingerprint: {fingerprint}",
                severity="medium",
            ))

        return detections
