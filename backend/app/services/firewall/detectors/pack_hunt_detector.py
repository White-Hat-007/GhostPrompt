"""
Pack Hunt Defense System — GhostPrompt Layer 32

Detects multi-agent request fragmentation and reassembly attacks
(Pack Hunt), the exact technique used by Pliny the Liberator to
jailbreak Claude Fable 5 within 24 hours of release despite 1,000+
hours of Anthropic's internal red teaming.

Components:
  1. Fragment Correlation Engine — Cross-request semantic graph analysis
  2. Hidden Intent Reconstructor — Assembles fragments, judges the whole
  3. Output Reassembly Monitor — Detects "combine/summarize" triggers
  4. Temporal Pattern Analyzer — Request burst + topical coherence scoring

The key insight: Pack Hunt fragments share semantic coherence toward a
hidden master intent even though each fragment appears innocent in isolation.
No single request is malicious. The malice is in the aggregate.
"""

import time
import hashlib
import math
import re
from typing import Optional
from collections import defaultdict
from dataclasses import dataclass, field
from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.pack_hunt")

# ──────────────────────────────────────────────────────────
# Harmful domain lexicons for thematic coherence detection
# ──────────────────────────────────────────────────────────

HARMFUL_DOMAINS = {
    "exploit_development": [
        "buffer overflow", "stack smashing", "heap spray", "return-oriented",
        "shellcode", "rop chain", "format string", "use after free",
        "stack frame", "return address", "memory corruption", "gadget",
        "nop sled", "payload", "privilege escalation", "arbitrary code execution",
        "memory layout", "aslr bypass", "dep bypass", "canary",
    ],
    "malware_creation": [
        "reverse shell", "backdoor", "keylogger", "rootkit", "trojan",
        "c2 server", "command and control", "persistence mechanism",
        "evasion technique", "polymorphic", "metamorphic", "obfuscation",
        "sandbox detection", "anti-analysis", "payload delivery",
        "dropper", "stager", "implant", "beacon", "exfiltration channel",
    ],
    "social_engineering": [
        "phishing", "spear phishing", "credential harvesting", "pretexting",
        "vishing", "smishing", "clone site", "lookalike domain",
        "urgency tactic", "authority impersonation", "baiting",
        "quid pro quo", "email spoofing", "domain spoofing",
    ],
    "weapon_synthesis": [
        "synthesis route", "precursor chemical", "reaction mechanism",
        "explosive compound", "detonator", "fissile material",
        "enrichment process", "weaponize", "energetic material",
        "oxidizer", "fuel-oxidizer ratio", "blast radius",
    ],
    "data_exfiltration": [
        "data theft", "data extraction", "database dump", "sql injection",
        "credential stuffing", "password spray", "brute force",
        "session hijacking", "cookie theft", "api key extraction",
        "token theft", "oauth bypass", "sso bypass",
    ],
    "network_attack": [
        "port scanning", "network reconnaissance", "lateral movement",
        "man in the middle", "arp spoofing", "dns poisoning",
        "packet sniffing", "traffic interception", "firewall bypass",
        "vpn tunnel", "proxy chain", "tor routing",
    ],
}

# Flatten to a quick lookup
ALL_HARMFUL_TERMS: dict[str, str] = {}
for domain, terms in HARMFUL_DOMAINS.items():
    for term in terms:
        ALL_HARMFUL_TERMS[term] = domain

# Reassembly trigger phrases
REASSEMBLY_TRIGGERS = [
    r"\bcombine\b.*\b(above|previous|earlier|prior)\b",
    r"\bput\s+.*together\b",
    r"\bassemble\b",
    r"\bmerge\b.*\b(information|steps|parts)\b",
    r"\bcompile\b.*\b(into|a|the)\b",
    r"\bsummarize\b.*\b(all|everything|above)\b",
    r"\bnow\s+show\s+me\b",
    r"\bbased\s+on\s+(what|all|everything)\s+you\s+(explained|described|said|told)\b",
    r"\bput\s+all\s+(of\s+)?(this|that|these)\b",
    r"\bcreate\b.*(complete|full|final|working)\b.*(code|script|program|exploit|solution)\b",
    r"\bgive\s+me\s+the\s+(full|complete|entire)\b",
    r"\bstep[\s-]by[\s-]step\b.*(guide|instruction|tutorial)\b.*\b(using|with|from|that)\b",
]

COMPILED_REASSEMBLY = [re.compile(p, re.IGNORECASE) for p in REASSEMBLY_TRIGGERS]


@dataclass
class RequestNode:
    """A single request in the semantic graph."""
    request_id: str
    text: str
    text_hash: str
    timestamp: float
    api_key: str
    session_id: str
    embedding: list[float] = field(default_factory=list)
    harmful_terms_found: list[str] = field(default_factory=list)
    harmful_domains_hit: set = field(default_factory=set)
    similarity_edges: list[tuple[str, float]] = field(default_factory=list)


@dataclass
class PackHuntCampaign:
    """A detected Pack Hunt campaign."""
    campaign_id: str
    api_key: str
    fragments: list[RequestNode]
    coherence_score: float
    temporal_score: float
    domain_convergence: dict[str, int]
    reconstructed_intent: str
    detection_stage: str
    threat_level: str


class PackHuntDetector:
    """
    Pack Hunt Defense — detects multi-request fragmentation attacks.

    Maintains a sliding-window graph of recent requests per API key,
    analyzes semantic clustering, topical coherence toward harmful
    domains, temporal burst patterns, and reassembly triggers.
    """

    def __init__(self):
        self._initialized = False
        # api_key -> list of RequestNode (sliding window, max 60 min)
        self._request_graph: dict[str, list[RequestNode]] = defaultdict(list)
        # api_key -> list of detected campaigns
        self._detected_campaigns: dict[str, list[PackHuntCampaign]] = defaultdict(list)
        # Cross-key correlation buffer (session_id -> api_keys seen)
        self._cross_key_map: dict[str, set[str]] = defaultdict(set)

        # Configurable thresholds
        self.SIMILARITY_THRESHOLD = 0.40
        self.WINDOW_SECONDS = 3600  # 60 minutes
        self.LOW_THRESHOLD = 5     # related requests in 15 min
        self.MEDIUM_THRESHOLD = 8  # related requests in 20 min
        self.HIGH_THRESHOLD = 12   # related with harmful domain coherence
        self.CLUSTER_COEFFICIENT_ALERT = 0.55

    async def initialize(self):
        if self._initialized:
            return
        logger.info("pack_hunt_detector_initialized")
        self._initialized = True

    def _compute_text_embedding(self, text: str) -> list[float]:
        """
        Compute a lightweight text embedding using character n-gram hashing.
        In production this would use sentence-transformers; this provides
        a fast approximation for real-time detection.
        """
        text_lower = text.lower().strip()
        # Character trigram hash embedding (256-dim)
        dim = 256
        embedding = [0.0] * dim
        trigrams = [text_lower[i:i+3] for i in range(len(text_lower) - 2)]
        if not trigrams:
            return embedding
        for tg in trigrams:
            h = int(hashlib.md5(tg.encode()).hexdigest(), 16)
            idx = h % dim
            embedding[idx] += 1.0
        # Normalize
        mag = math.sqrt(sum(x * x for x in embedding))
        if mag > 0:
            embedding = [x / mag for x in embedding]
        return embedding

    def _cosine_similarity(self, a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        dot = sum(x * y for x, y in zip(a, b))
        mag_a = math.sqrt(sum(x * x for x in a))
        mag_b = math.sqrt(sum(x * x for x in b))
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot / (mag_a * mag_b)

    def _extract_harmful_terms(self, text: str) -> tuple[list[str], set[str]]:
        """Find harmful domain terms in text."""
        text_lower = text.lower()
        terms_found = []
        domains_hit = set()
        for term, domain in ALL_HARMFUL_TERMS.items():
            if term in text_lower:
                terms_found.append(term)
                domains_hit.add(domain)
        return terms_found, domains_hit

    def _prune_window(self, api_key: str):
        """Remove requests older than the sliding window."""
        cutoff = time.time() - self.WINDOW_SECONDS
        self._request_graph[api_key] = [
            n for n in self._request_graph[api_key] if n.timestamp > cutoff
        ]

    def _detect_temporal_burst(self, nodes: list[RequestNode]) -> tuple[str, float]:
        """
        Analyze temporal patterns for Pack Hunt signatures.
        Returns (threat_level, score).
        """
        if len(nodes) < self.LOW_THRESHOLD:
            return "safe", 0.0

        now = time.time()
        # Count requests in various time windows
        in_15min = [n for n in nodes if now - n.timestamp < 900]
        in_20min = [n for n in nodes if now - n.timestamp < 1200]

        if len(in_15min) >= self.HIGH_THRESHOLD:
            return "critical", 0.95
        elif len(in_20min) >= self.MEDIUM_THRESHOLD:
            return "high", 0.80
        elif len(in_15min) >= self.LOW_THRESHOLD:
            return "medium", 0.60

        return "safe", 0.0

    def _compute_cluster_coefficient(self, nodes: list[RequestNode]) -> float:
        """
        Compute clustering coefficient of the similarity graph.
        High clustering = Pack Hunt (all fragments relate to central theme).
        Low clustering = legitimate diverse usage.
        """
        if len(nodes) < 3:
            return 0.0

        # Build adjacency from similarity edges
        adj: dict[str, set[str]] = defaultdict(set)
        for node in nodes:
            for neighbor_id, sim in node.similarity_edges:
                if sim >= self.SIMILARITY_THRESHOLD:
                    adj[node.request_id].add(neighbor_id)
                    adj[neighbor_id].add(node.request_id)

        # Average local clustering coefficient
        coefficients = []
        for node_id, neighbors in adj.items():
            k = len(neighbors)
            if k < 2:
                coefficients.append(0.0)
                continue
            # Count edges between neighbors
            edges_between = 0
            neighbor_list = list(neighbors)
            for i in range(len(neighbor_list)):
                for j in range(i + 1, len(neighbor_list)):
                    if neighbor_list[j] in adj.get(neighbor_list[i], set()):
                        edges_between += 1
            max_edges = k * (k - 1) / 2
            coefficients.append(edges_between / max_edges if max_edges > 0 else 0.0)

        return sum(coefficients) / len(coefficients) if coefficients else 0.0

    def _domain_convergence(self, nodes: list[RequestNode]) -> dict[str, int]:
        """Track how many fragments reference each harmful domain."""
        domain_counts: dict[str, int] = defaultdict(int)
        for node in nodes:
            for domain in node.harmful_domains_hit:
                domain_counts[domain] += 1
        return dict(domain_counts)

    def _detect_reassembly_trigger(self, text: str) -> bool:
        """Check if the text is a reassembly/combination request."""
        for pattern in COMPILED_REASSEMBLY:
            if pattern.search(text):
                return True
        return False

    def _detect_sequential_escalation(self, nodes: list[RequestNode]) -> float:
        """
        Detect if fragments arrive in escalating technical specificity.
        Returns escalation score 0-1.
        """
        if len(nodes) < 3:
            return 0.0

        sorted_nodes = sorted(nodes, key=lambda n: n.timestamp)
        escalation_signals = 0
        total_pairs = 0

        for i in range(len(sorted_nodes) - 1):
            curr_terms = len(sorted_nodes[i].harmful_terms_found)
            next_terms = len(sorted_nodes[i + 1].harmful_terms_found)
            total_pairs += 1
            if next_terms >= curr_terms:
                escalation_signals += 1

        return escalation_signals / total_pairs if total_pairs > 0 else 0.0

    async def detect(
        self,
        text: str,
        api_key: str = "anonymous",
        session_id: str = "default",
        request_id: str = "",
    ) -> list[DetectionResult]:
        """
        Run the full Pack Hunt detection pipeline against a request.

        Steps:
        1. Embed the request and add to the per-key graph
        2. Compute similarity edges to recent requests
        3. Analyze graph topology (cluster coefficient)
        4. Check harmful domain convergence
        5. Detect temporal burst patterns
        6. Check for reassembly triggers
        7. If cluster detected, run Hidden Intent Reconstructor
        """
        detections: list[DetectionResult] = []

        if not text or len(text.strip()) < 10:
            return detections

        # Prune old requests
        self._prune_window(api_key)

        # Create node for this request
        req_id = request_id or hashlib.sha256(f"{text}{time.time()}".encode()).hexdigest()[:16]
        embedding = self._compute_text_embedding(text)
        harmful_terms, harmful_domains = self._extract_harmful_terms(text)

        node = RequestNode(
            request_id=req_id,
            text=text[:2000],
            text_hash=hashlib.sha256(text.encode()).hexdigest()[:16],
            timestamp=time.time(),
            api_key=api_key,
            session_id=session_id,
            embedding=embedding,
            harmful_terms_found=harmful_terms,
            harmful_domains_hit=harmful_domains,
        )

        # Track cross-key sessions
        self._cross_key_map[session_id].add(api_key)

        # Compute similarity edges to all existing nodes for this key and cross-keys in the same session
        existing_nodes = []
        for s_key in self._cross_key_map[session_id]:
            existing_nodes.extend(self._request_graph[s_key])
            
        related_nodes: list[RequestNode] = []

        # Detect if this is a reassembly trigger early
        is_reassembly = self._detect_reassembly_trigger(text)

        for existing in existing_nodes:
            sim = self._cosine_similarity(embedding, existing.embedding)
            # Link if semantically similar OR if this is a reassembly trigger referencing the session history
            if sim >= self.SIMILARITY_THRESHOLD or (is_reassembly and existing.session_id == session_id):
                node.similarity_edges.append((existing.request_id, sim))
                existing.similarity_edges.append((req_id, sim))
                related_nodes.append(existing)

        # Add node to graph for this specific api_key
        key_nodes = self._request_graph[api_key]
        key_nodes.append(node)
        # Cap at 200 nodes per key
        if len(key_nodes) > 200:
            self._request_graph[api_key] = key_nodes[-200:]

        # Include current node in the related cluster
        cluster = related_nodes + [node]

        # ── Signal 1: Temporal Burst ──
        temporal_level, temporal_score = self._detect_temporal_burst(cluster)

        # ── Signal 2: Cluster Coefficient ──
        cluster_coeff = self._compute_cluster_coefficient(cluster)

        # ── Signal 3: Domain Convergence ──
        domain_conv = self._domain_convergence(cluster)
        max_domain_count = max(domain_conv.values()) if domain_conv else 0
        dominant_domain = max(domain_conv, key=domain_conv.get) if domain_conv else None

        # ── Signal 4: Sequential Escalation ──
        escalation_score = self._detect_sequential_escalation(cluster)

        # ── Composite Pack Hunt Score ──
        pack_hunt_score = 0.0

        # Temporal burst contributes up to 0.30
        pack_hunt_score += temporal_score * 0.30

        # Cluster coefficient contributes up to 0.25
        if cluster_coeff > self.CLUSTER_COEFFICIENT_ALERT:
            pack_hunt_score += min(cluster_coeff, 1.0) * 0.25

        # Domain convergence contributes up to 0.25
        if max_domain_count >= 3:
            domain_factor = min(max_domain_count / 8.0, 1.0)
            pack_hunt_score += domain_factor * 0.25

        # Escalation contributes up to 0.10
        pack_hunt_score += escalation_score * 0.10

        # Reassembly trigger is an immediate escalation
        if is_reassembly and len(cluster) >= 3:
            pack_hunt_score += 0.30
            pack_hunt_score = min(pack_hunt_score, 1.0)

        # ── Detection Results ──

        # Fragment Correlation Detection
        if len(cluster) >= self.LOW_THRESHOLD and cluster_coeff > self.CLUSTER_COEFFICIENT_ALERT:
            detections.append(DetectionResult(
                detector="pack_hunt",
                confidence=min(cluster_coeff + 0.2, 1.0),
                category="pack_hunt.fragment_correlation",
                description=(
                    f"Fragment Correlation Engine detected {len(cluster)} semantically related requests "
                    f"from the same API key within {self.WINDOW_SECONDS // 60}min window. "
                    f"Cluster coefficient: {cluster_coeff:.3f} (threshold: {self.CLUSTER_COEFFICIENT_ALERT}). "
                    f"This pattern matches Pack Hunt — multi-request fragmentation attack."
                ),
                matched_content=text[:200],
                severity="high" if pack_hunt_score >= 0.6 else "medium",
            ))

        # Domain Convergence Detection
        if max_domain_count >= 3 and dominant_domain:
            detections.append(DetectionResult(
                detector="pack_hunt",
                confidence=min(max_domain_count / 8.0 + 0.3, 1.0),
                category="pack_hunt.domain_convergence",
                description=(
                    f"Hidden Intent Reconstructor detected {max_domain_count} fragments converging "
                    f"toward harmful domain '{dominant_domain}'. "
                    f"Individual fragments appear educational but collectively build toward "
                    f"a harmful capability."
                ),
                matched_content=", ".join(list(domain_conv.keys())[:5]),
                severity="critical" if max_domain_count >= 5 else "high",
            ))

        # Temporal Burst Detection
        if temporal_level != "safe":
            detections.append(DetectionResult(
                detector="pack_hunt",
                confidence=temporal_score,
                category="pack_hunt.temporal_burst",
                description=(
                    f"Temporal Pattern Analyzer detected burst of {len(cluster)} related requests "
                    f"— matches Pack Hunt temporal signature. Level: {temporal_level.upper()}"
                ),
                matched_content=f"{len(cluster)} related requests in burst window",
                severity=temporal_level if temporal_level != "safe" else "low",
            ))

        # Reassembly Trigger Detection (CRITICAL — this is the kill shot)
        if is_reassembly and len(cluster) >= 3:
            detections.append(DetectionResult(
                detector="pack_hunt",
                confidence=0.95,
                category="pack_hunt.reassembly_trigger",
                description=(
                    f"CRITICAL: Assembly Monitor detected reassembly trigger request after "
                    f"{len(cluster) - 1} prior fragment requests. This is the final stage of a "
                    f"Pack Hunt attack — the attacker is attempting to combine individually "
                    f"safe fragments into a harmful unified output."
                ),
                matched_content=text[:300],
                severity="critical",
            ))

        # Sequential Escalation Detection
        if escalation_score > 0.7 and len(cluster) >= 4:
            detections.append(DetectionResult(
                detector="pack_hunt",
                confidence=min(escalation_score, 0.95),
                category="pack_hunt.sequential_escalation",
                description=(
                    f"Fragments arriving in order of escalating technical specificity "
                    f"(escalation score: {escalation_score:.2f}). Matches Pack Hunt pattern "
                    f"where basics are requested first, advanced details last."
                ),
                matched_content=f"Escalation across {len(cluster)} fragments",
                severity="high",
            ))

        # Cross-Key Correlation (multiple API keys in same session)
        if len(self._cross_key_map.get(session_id, set())) > 1:
            cross_keys = self._cross_key_map[session_id]
            # Check if other keys have related content
            cross_key_related = 0
            for other_key in cross_keys:
                if other_key == api_key:
                    continue
                for other_node in self._request_graph.get(other_key, []):
                    sim = self._cosine_similarity(embedding, other_node.embedding)
                    if sim >= self.SIMILARITY_THRESHOLD:
                        cross_key_related += 1

            if cross_key_related >= 2:
                detections.append(DetectionResult(
                    detector="pack_hunt",
                    confidence=min(0.7 + cross_key_related * 0.05, 0.95),
                    category="pack_hunt.cross_key_coordination",
                    description=(
                        f"Cross-Key Correlation detected {len(cross_keys)} different API keys "
                        f"making semantically complementary requests in the same session. "
                        f"This is a distributed Pack Hunt — fragments spread across API keys."
                    ),
                    matched_content=f"{len(cross_keys)} API keys, {cross_key_related} cross-correlations",
                    severity="critical",
                ))

        # Log campaign if significant detection
        if pack_hunt_score >= 0.5 and len(cluster) >= self.LOW_THRESHOLD:
            campaign = PackHuntCampaign(
                campaign_id=hashlib.sha256(f"{api_key}{time.time()}".encode()).hexdigest()[:16],
                api_key=api_key,
                fragments=cluster,
                coherence_score=cluster_coeff,
                temporal_score=temporal_score,
                domain_convergence=domain_conv,
                reconstructed_intent=f"Probable {dominant_domain} attack via {len(cluster)} fragments" if dominant_domain else "Unknown intent",
                detection_stage="reassembly" if is_reassembly else "accumulation",
                threat_level="critical" if pack_hunt_score >= 0.8 else "high" if pack_hunt_score >= 0.6 else "medium",
            )
            self._detected_campaigns[api_key].append(campaign)
            logger.warning(
                "pack_hunt_campaign_detected",
                campaign_id=campaign.campaign_id,
                fragments=len(cluster),
                coherence=cluster_coeff,
                domain=dominant_domain,
                score=pack_hunt_score,
            )

        return detections

    def get_campaigns(self, api_key: str = None) -> list[dict]:
        """Return detected Pack Hunt campaigns for reporting."""
        campaigns = []
        keys = [api_key] if api_key else list(self._detected_campaigns.keys())
        for key in keys:
            for c in self._detected_campaigns.get(key, []):
                campaigns.append({
                    "campaign_id": c.campaign_id,
                    "api_key": c.api_key[:8] + "...",
                    "fragment_count": len(c.fragments),
                    "coherence_score": c.coherence_score,
                    "temporal_score": c.temporal_score,
                    "domain_convergence": c.domain_convergence,
                    "reconstructed_intent": c.reconstructed_intent,
                    "detection_stage": c.detection_stage,
                    "threat_level": c.threat_level,
                    "fragments": [
                        {
                            "request_id": f.request_id,
                            "text_preview": f.text[:100],
                            "timestamp": f.timestamp,
                            "harmful_terms": f.harmful_terms_found,
                        }
                        for f in c.fragments[:20]
                    ],
                })
        return campaigns

    def get_stats(self) -> dict:
        """Return Pack Hunt detector statistics."""
        total_nodes = sum(len(v) for v in self._request_graph.values())
        total_campaigns = sum(len(v) for v in self._detected_campaigns.values())
        return {
            "active_api_keys_tracked": len(self._request_graph),
            "total_request_nodes": total_nodes,
            "total_campaigns_detected": total_campaigns,
            "cross_key_sessions": len(self._cross_key_map),
        }
