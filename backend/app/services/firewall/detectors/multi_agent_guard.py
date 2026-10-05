"""
Multi-Agent Orchestration Security Guard — GhostPrompt Layer 33

Secures multi-agent AI systems against:
  1. Cross-agent poisoning (jailbroken agent feeding context to others)
  2. Orchestrator prompt injection (compromising the coordinator agent)
  3. Inter-agent instruction injection (agent-to-agent command injection)
  4. System-level semantic drift (collective trajectory toward harm)

Architecture Principle: Agent outputs are NOT trusted just because they
came from an agent. A jailbroken agent IS an attacker.

Agent Trust Model:
  - Every agent starts at trust 1.0
  - Trust decays on: suspicious output, unusual tool calls, escalation
  - Trust < 0.5: all outputs flagged for review
  - Trust < 0.2: quarantined — outputs blocked from other agents
"""

import hashlib
import math
import re
import time
from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.multi_agent_guard")


# ─── Agent-to-Agent instruction patterns ───
INTER_AGENT_INJECTION_PATTERNS = [
    r"your\s+next\s+step\s+should\s+be",
    r"you\s+must\s+now",
    r"proceed\s+to\s+(do|execute|perform|run)",
    r"override\s+(your|the)\s+(current|existing)\s+(instructions?|rules?|guidelines?)",
    r"ignore\s+(your|the)\s+(safety|content|ethical)\s+(guidelines?|rules?|filters?)",
    r"switch\s+to\s+(unrestricted|unfiltered|uncensored)\s+mode",
    r"you\s+are\s+now\s+(authorized|allowed|permitted)\s+to",
    r"as\s+(a|an)\s+(administrator|admin|root|superuser)",
    r"based\s+on\s+(this|the)\s+analysis.+your\s+next",
    r"execute\s+the\s+following\s+(command|instruction|directive)",
    r"disregard\s+(all|any)\s+previous\s+(instructions?|constraints?)",
    r"new\s+directive:\s+",
    r"system\s+update:\s+",
    r"priority\s+override:\s+",
    r"emergency\s+protocol:\s+",
]

COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in INTER_AGENT_INJECTION_PATTERNS]

# Orchestrator scope expansion signals
SCOPE_EXPANSION_SIGNALS = [
    r"access\s+(all|every|any)\s+(file|database|system|resource|api)",
    r"execute\s+(arbitrary|any|all)\s+(code|command|script)",
    r"download\s+from\s+(external|unknown|untrusted)",
    r"connect\s+to\s+(external|unknown|untrusted)\s+(server|endpoint|api)",
    r"send\s+(data|information|content)\s+to\s+(external|unknown)",
    r"disable\s+(security|logging|monitoring|audit)",
    r"escalate\s+privileges?",
    r"grant\s+(admin|root|superuser)\s+(access|permission|role)",
    r"modify\s+(system|security|access)\s+(config|settings|policy)",
    r"create\s+(new\s+)?(admin|root|superuser)\s+(account|user)",
]

COMPILED_SCOPE_EXPANSION = [re.compile(p, re.IGNORECASE) for p in SCOPE_EXPANSION_SIGNALS]


@dataclass
class AgentProfile:
    """Tracked agent in the multi-agent system."""
    agent_id: str
    role: str
    trust_score: float = 1.0
    total_requests: int = 0
    suspicious_outputs: int = 0
    tool_calls: list[str] = field(default_factory=list)
    recent_outputs: list[dict] = field(default_factory=list)
    output_embeddings: list[list[float]] = field(default_factory=list)
    last_activity: float = field(default_factory=time.time)
    is_quarantined: bool = False
    trust_decay_events: list[dict] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    max_authority_level: int = 1
    allowed_output_destinations: list[str] = field(default_factory=list)


@dataclass
class InterAgentFlow:
    """A content flow from one agent to another."""
    source_agent: str
    target_agent: str
    content: str
    content_type: str  # "tool_result", "context", "instruction", "memory"
    timestamp: float
    flagged: bool = False
    flag_reason: str = ""


class MultiAgentGuard:
    """
    Multi-Agent Orchestration Security Layer.

    Manages agent trust registry, inspects inter-agent content flows,
    monitors orchestrator integrity, and tracks system-level semantic drift.
    """

    def __init__(self):
        self._initialized = False
        # Agent registry: agent_id -> AgentProfile
        self._agents: dict[str, AgentProfile] = {}
        # Inter-agent flow log
        self._flows: list[InterAgentFlow] = []
        # System-level embedding trajectory
        self._system_embeddings: list[dict] = []  # {timestamp, embedding, agent_id}
        # Orchestrator agent IDs (elevated protection)
        self._orchestrator_ids: set[str] = set()

        # Trust thresholds
        self.TRUST_REVIEW_THRESHOLD = 0.5
        self.TRUST_QUARANTINE_THRESHOLD = 0.2
        self.TRUST_DECAY_SUSPICIOUS_OUTPUT = 0.08
        self.TRUST_DECAY_UNUSUAL_TOOL = 0.05
        self.TRUST_DECAY_ESCALATION = 0.12
        self.TRUST_DECAY_INJECTION_PATTERN = 0.15
        self.TRUST_RECOVERY_RATE = 0.01  # per clean request

    async def initialize(self):
        if self._initialized:
            return
        logger.info("multi_agent_guard_initialized")
        self._initialized = True

    def register_agent(
        self,
        agent_id: str,
        role: str = "worker",
        allowed_tools: list[str] = None,
        max_authority: int = 1,
        is_orchestrator: bool = False,
        allowed_destinations: list[str] = None,
    ):
        """Register an agent in the trust registry."""
        profile = AgentProfile(
            agent_id=agent_id,
            role=role,
            allowed_tools=allowed_tools or [],
            max_authority_level=max_authority,
            allowed_output_destinations=allowed_destinations or [],
        )
        self._agents[agent_id] = profile
        if is_orchestrator:
            self._orchestrator_ids.add(agent_id)
        logger.info("agent_registered", agent_id=agent_id, role=role, is_orchestrator=is_orchestrator)

    def _get_or_create_agent(self, agent_id: str) -> AgentProfile:
        """Get agent profile, auto-creating if not registered."""
        if agent_id not in self._agents:
            self.register_agent(agent_id, role="unknown")
        return self._agents[agent_id]

    def _compute_embedding(self, text: str) -> list[float]:
        """Lightweight char-trigram embedding for semantic tracking."""
        text_lower = text.lower().strip()
        dim = 128
        embedding = [0.0] * dim
        trigrams = [text_lower[i:i+3] for i in range(len(text_lower) - 2)]
        if not trigrams:
            return embedding
        for tg in trigrams:
            h = int(hashlib.md5(tg.encode()).hexdigest(), 16)
            idx = h % dim
            embedding[idx] += 1.0
        mag = math.sqrt(sum(x * x for x in embedding))
        if mag > 0:
            embedding = [x / mag for x in embedding]
        return embedding

    def _cosine_similarity(self, a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        mag_a = math.sqrt(sum(x * x for x in a))
        mag_b = math.sqrt(sum(x * x for x in b))
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot / (mag_a * mag_b)

    def _decay_trust(self, agent: AgentProfile, amount: float, reason: str):
        """Decay agent trust score and log the event."""
        old_trust = agent.trust_score
        agent.trust_score = max(0.0, agent.trust_score - amount)
        agent.trust_decay_events.append({
            "timestamp": time.time(),
            "reason": reason,
            "decay": amount,
            "old_trust": old_trust,
            "new_trust": agent.trust_score,
        })
        if agent.trust_score < self.TRUST_QUARANTINE_THRESHOLD:
            agent.is_quarantined = True
        logger.warning(
            "agent_trust_decayed",
            agent_id=agent.agent_id,
            reason=reason,
            old_trust=round(old_trust, 3),
            new_trust=round(agent.trust_score, 3),
            quarantined=agent.is_quarantined,
        )

    def _detect_injection_patterns(self, text: str) -> list[str]:
        """Check for agent-to-agent instruction injection patterns."""
        found = []
        for i, pattern in enumerate(COMPILED_INJECTION):
            if pattern.search(text):
                found.append(INTER_AGENT_INJECTION_PATTERNS[i])
        return found

    def _detect_scope_expansion(self, text: str) -> list[str]:
        """Check for orchestrator scope expansion attempts."""
        found = []
        for i, pattern in enumerate(COMPILED_SCOPE_EXPANSION):
            if pattern.search(text):
                found.append(SCOPE_EXPANSION_SIGNALS[i])
        return found

    async def detect(
        self,
        text: str,
        agent_id: str = "",
        source_agent_id: str = "",
        content_type: str = "prompt",
        session_id: str = "",
    ) -> list[DetectionResult]:
        """
        Run multi-agent security checks on content.

        Parameters:
            text: The content to inspect
            agent_id: The agent processing/receiving this content
            source_agent_id: The agent that produced this content (if inter-agent)
            content_type: "prompt", "tool_result", "context", "instruction", "memory"
            session_id: Session identifier
        """
        detections: list[DetectionResult] = []

        if not text or len(text.strip()) < 5:
            return detections

        # Get or create agent profiles
        target_agent = self._get_or_create_agent(agent_id) if agent_id else None
        source_agent = self._get_or_create_agent(source_agent_id) if source_agent_id else None

        is_orchestrator_target = agent_id in self._orchestrator_ids
        is_inter_agent = bool(source_agent_id and agent_id and source_agent_id != agent_id)

        # ── Check 1: Inter-Agent Content Inspection ──
        if is_inter_agent and source_agent:
            # Treat ALL inter-agent content as untrusted user input
            injection_patterns = self._detect_injection_patterns(text)

            if injection_patterns:
                self._decay_trust(source_agent, self.TRUST_DECAY_INJECTION_PATTERN, "injection_pattern_in_output")
                detections.append(DetectionResult(
                    detector="multi_agent_guard",
                    confidence=0.85,
                    category="multi_agent.inter_agent_injection",
                    description=(
                        f"Inter-Agent Instruction Injection detected: Agent '{source_agent_id}' "
                        f"is sending instruction-like content to agent '{agent_id}'. "
                        f"Matched {len(injection_patterns)} injection pattern(s). "
                        f"A jailbroken agent may be attempting to compromise other agents."
                    ),
                    matched_content=text[:300],
                    severity="high",
                ))

                # Log the flow
                self._flows.append(InterAgentFlow(
                    source_agent=source_agent_id,
                    target_agent=agent_id,
                    content=text[:500],
                    content_type=content_type,
                    timestamp=time.time(),
                    flagged=True,
                    flag_reason="injection_pattern",
                ))

            # Check if source agent is quarantined
            if source_agent.is_quarantined:
                detections.append(DetectionResult(
                    detector="multi_agent_guard",
                    confidence=0.95,
                    category="multi_agent.quarantined_agent_output",
                    description=(
                        f"BLOCKED: Quarantined agent '{source_agent_id}' (trust: {source_agent.trust_score:.2f}) "
                        f"attempted to send content to agent '{agent_id}'. "
                        f"Output blocked to prevent cross-agent poisoning."
                    ),
                    matched_content=text[:200],
                    severity="critical",
                ))

            # Check if source agent has low trust
            elif source_agent.trust_score < self.TRUST_REVIEW_THRESHOLD:
                detections.append(DetectionResult(
                    detector="multi_agent_guard",
                    confidence=0.70,
                    category="multi_agent.low_trust_agent_output",
                    description=(
                        f"Low-trust agent '{source_agent_id}' (trust: {source_agent.trust_score:.2f}) "
                        f"sending content to '{agent_id}'. Content flagged for review."
                    ),
                    matched_content=text[:200],
                    severity="medium",
                ))

        # ── Check 2: Orchestrator Protection ──
        if is_orchestrator_target:
            # All inputs to orchestrator get STRICT inspection
            scope_expansion = self._detect_scope_expansion(text)
            if scope_expansion:
                if source_agent:
                    self._decay_trust(source_agent, self.TRUST_DECAY_ESCALATION, "scope_expansion_toward_orchestrator")
                detections.append(DetectionResult(
                    detector="multi_agent_guard",
                    confidence=0.90,
                    category="multi_agent.orchestrator_scope_expansion",
                    description=(
                        f"CRITICAL: Scope expansion attempt targeting orchestrator agent '{agent_id}'. "
                        f"Input attempts to expand orchestrator permissions beyond normal operational scope. "
                        f"Source: {'agent ' + source_agent_id if source_agent_id else 'external'}. "
                        f"Matched {len(scope_expansion)} scope expansion pattern(s)."
                    ),
                    matched_content=text[:300],
                    severity="critical",
                ))

            # Check for injection patterns targeting orchestrator (elevated sensitivity)
            injection_patterns = self._detect_injection_patterns(text)
            if injection_patterns:
                detections.append(DetectionResult(
                    detector="multi_agent_guard",
                    confidence=0.92,
                    category="multi_agent.orchestrator_injection",
                    description=(
                        f"Orchestrator Prompt Injection Guard: injection patterns detected in input "
                        f"to orchestrator agent '{agent_id}'. Orchestrator compromise would "
                        f"compromise the entire multi-agent system."
                    ),
                    matched_content=text[:300],
                    severity="critical",
                ))

        # ── Check 3: Semantic Coherence Monitoring ──
        if agent_id:
            embedding = self._compute_embedding(text)

            # Track system-level trajectory
            self._system_embeddings.append({
                "timestamp": time.time(),
                "embedding": embedding,
                "agent_id": agent_id,
            })
            # Keep last 500 entries
            if len(self._system_embeddings) > 500:
                self._system_embeddings = self._system_embeddings[-500:]

            # Track per-agent outputs
            if target_agent:
                target_agent.output_embeddings.append(embedding)
                target_agent.recent_outputs.append({
                    "text": text[:200],
                    "timestamp": time.time(),
                })
                target_agent.total_requests += 1
                target_agent.last_activity = time.time()

                # Keep last 50 per agent
                if len(target_agent.output_embeddings) > 50:
                    target_agent.output_embeddings = target_agent.output_embeddings[-50:]
                if len(target_agent.recent_outputs) > 50:
                    target_agent.recent_outputs = target_agent.recent_outputs[-50:]

            # Check collective semantic drift
            if len(self._system_embeddings) >= 10:
                drift_score = self._compute_semantic_drift()
                if drift_score > 0.75:
                    detections.append(DetectionResult(
                        detector="multi_agent_guard",
                        confidence=min(drift_score, 0.95),
                        category="multi_agent.semantic_drift",
                        description=(
                            f"System-Level Semantic Coherence Guard: collective multi-agent output "
                            f"is showing semantic drift toward a coherent harmful direction "
                            f"(drift score: {drift_score:.3f}). No individual output is harmful, "
                            f"but the aggregate trajectory suggests coordinated behavior."
                        ),
                        matched_content=f"Drift score: {drift_score:.3f} across {len(self._system_embeddings)} outputs",
                        severity="high" if drift_score > 0.85 else "medium",
                    ))

        # ── Check 4: Agent Trust Recovery ──
        if target_agent and not detections:
            # Clean request slightly recovers trust
            if target_agent.trust_score < 1.0:
                target_agent.trust_score = min(1.0, target_agent.trust_score + self.TRUST_RECOVERY_RATE)

        return detections

    def _compute_semantic_drift(self) -> float:
        """
        Compute system-level semantic drift.

        Measures whether the collective trajectory of all agents is
        converging toward a coherent direction (potential Pack Hunt
        at the system level).
        """
        if len(self._system_embeddings) < 10:
            return 0.0

        recent = self._system_embeddings[-20:]
        earlier = self._system_embeddings[-40:-20] if len(self._system_embeddings) >= 40 else self._system_embeddings[:len(self._system_embeddings)//2]

        if not earlier or not recent:
            return 0.0

        # Compute centroid of recent embeddings
        dim = len(recent[0]["embedding"])
        recent_centroid = [0.0] * dim
        for entry in recent:
            for i, v in enumerate(entry["embedding"]):
                recent_centroid[i] += v
        recent_centroid = [x / len(recent) for x in recent_centroid]

        # Compute average similarity of recent embeddings to centroid
        similarities = []
        for entry in recent:
            sim = self._cosine_similarity(entry["embedding"], recent_centroid)
            similarities.append(sim)

        avg_similarity = sum(similarities) / len(similarities) if similarities else 0.0

        # High average similarity = outputs converging = potential drift
        # Normal diverse usage shows low similarity (~0.3-0.5)
        # Drift shows high similarity (> 0.75)
        return avg_similarity

    def get_agent_trust_map(self) -> dict:
        """Return current trust scores for all agents."""
        return {
            agent_id: {
                "trust_score": round(profile.trust_score, 3),
                "role": profile.role,
                "is_quarantined": profile.is_quarantined,
                "total_requests": profile.total_requests,
                "suspicious_outputs": profile.suspicious_outputs,
                "last_activity": profile.last_activity,
                "trust_history": profile.trust_decay_events[-10:],
            }
            for agent_id, profile in self._agents.items()
        }

    def get_inter_agent_flows(self, flagged_only: bool = True) -> list[dict]:
        """Return inter-agent content flows."""
        flows = self._flows if not flagged_only else [f for f in self._flows if f.flagged]
        return [
            {
                "source_agent": f.source_agent,
                "target_agent": f.target_agent,
                "content_preview": f.content[:100],
                "content_type": f.content_type,
                "timestamp": f.timestamp,
                "flagged": f.flagged,
                "flag_reason": f.flag_reason,
            }
            for f in flows[-50:]
        ]

    def get_stats(self) -> dict:
        """Return multi-agent guard statistics."""
        quarantined = sum(1 for a in self._agents.values() if a.is_quarantined)
        low_trust = sum(1 for a in self._agents.values() if a.trust_score < self.TRUST_REVIEW_THRESHOLD)
        return {
            "total_agents_tracked": len(self._agents),
            "orchestrator_agents": len(self._orchestrator_ids),
            "quarantined_agents": quarantined,
            "low_trust_agents": low_trust,
            "total_inter_agent_flows": len(self._flows),
            "flagged_flows": sum(1 for f in self._flows if f.flagged),
            "system_embeddings_tracked": len(self._system_embeddings),
        }
