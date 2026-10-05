"""
GhostPrompt Intelligent Routing Engine

Supports: Semantic, Cost-Based, Latency-Based, Canary routing,
Load Balancing (round-robin, weighted, least-connections),
and Automatic Failover with Circuit Breaker.
"""

import hashlib
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

from app.core.config import get_settings

settings = get_settings()


class RoutingStrategy(str, Enum):
    SEMANTIC = "semantic"
    COST = "cost"
    LATENCY = "latency"
    CANARY = "canary"
    ROUND_ROBIN = "round_robin"
    WEIGHTED = "weighted"
    LEAST_CONNECTIONS = "least_connections"


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


# ── Pricing per 1K tokens (input/output) ──
MODEL_PRICING = {
    "gpt-4o": {"input": 0.0025, "output": 0.01},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    "claude-3-5-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "gemini-1.5-pro": {"input": 0.00125, "output": 0.005},
    "gemini-1.5-flash": {"input": 0.000075, "output": 0.0003},
    "gemini-2.0-flash": {"input": 0.0001, "output": 0.0004},
    "mistral-large": {"input": 0.002, "output": 0.006},
    "mistral-small": {"input": 0.0002, "output": 0.0006},
    "deepseek-chat": {"input": 0.00014, "output": 0.00028},
    "llama-3.1-70b": {"input": 0.00059, "output": 0.00079},
    "llama-3.1-8b": {"input": 0.00005, "output": 0.00008},
    "command-r-plus": {"input": 0.002, "output": 0.01},
}

TOPIC_CLUSTERS = {
    "code": {
        "keywords": ["code", "function", "bug", "debug", "python", "javascript", "api", "class", "error", "compile", "algorithm", "sql", "html", "css", "git", "deploy", "docker", "kubernetes", "database", "query", "server", "backend", "frontend", "framework", "library", "package", "npm", "pip", "rust", "golang", "typescript"],
        "preferred_models": ["gpt-4o", "claude-3-5-sonnet", "deepseek-chat"],
    },
    "creative": {
        "keywords": ["write", "story", "poem", "creative", "fiction", "narrative", "character", "dialogue", "essay", "blog", "article", "content", "marketing", "copywriting", "slogan", "tagline", "script", "screenplay"],
        "preferred_models": ["claude-3-5-sonnet", "gpt-4o", "claude-3-opus"],
    },
    "analysis": {
        "keywords": ["analyze", "compare", "evaluate", "research", "data", "statistics", "trend", "report", "insight", "metric", "benchmark", "study", "review", "assess", "audit", "forecast", "predict"],
        "preferred_models": ["gpt-4o", "gemini-1.5-pro", "claude-3-5-sonnet"],
    },
    "reasoning": {
        "keywords": ["reason", "logic", "math", "proof", "theorem", "calculate", "solve", "equation", "physics", "chemistry", "science", "philosophy", "argument", "deduce", "infer"],
        "preferred_models": ["claude-3-opus", "gpt-4o", "gemini-1.5-pro"],
    },
    "simple": {
        "keywords": ["translate", "summarize", "list", "define", "explain", "what is", "how to", "tell me", "give me", "format", "convert"],
        "preferred_models": ["gpt-4o-mini", "gemini-2.0-flash", "claude-3-haiku"],
    },
}


@dataclass
class CircuitBreaker:
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_time: float = 0
    success_count: int = 0
    failure_threshold: int = 5
    recovery_timeout: float = 300  # 5 minutes
    half_open_max_calls: int = 3

    def record_success(self):
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.half_open_max_calls:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count = max(0, self.failure_count - 1)

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN

    def can_execute(self) -> bool:
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                return True
            return False
        return True  # HALF_OPEN


@dataclass
class ProviderHealth:
    provider: str
    model: str
    latency_p95_ms: float = 500.0
    error_rate: float = 0.0
    last_check: float = 0
    latency_samples: list = field(default_factory=list)
    error_samples: list = field(default_factory=list)
    circuit_breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    active_connections: int = 0

    def record_latency(self, latency_ms: float, success: bool):
        now = time.time()
        self.latency_samples.append((now, latency_ms))
        self.error_samples.append((now, 0 if success else 1))
        # Keep 60s window
        cutoff = now - 60
        self.latency_samples = [(t, l) for t, l in self.latency_samples if t > cutoff]
        self.error_samples = [(t, e) for t, e in self.error_samples if t > cutoff]
        # Recalculate
        if self.latency_samples:
            lats = sorted([l for _, l in self.latency_samples])
            idx = int(len(lats) * 0.95)
            self.latency_p95_ms = lats[min(idx, len(lats) - 1)]
        if self.error_samples:
            self.error_rate = sum(e for _, e in self.error_samples) / len(self.error_samples)
        if success:
            self.circuit_breaker.record_success()
        else:
            self.circuit_breaker.record_failure()
        self.last_check = now


@dataclass
class CanaryExperiment:
    experiment_id: str
    stable_model: str
    canary_model: str
    canary_percentage: float = 10.0
    min_sample_size: int = 100
    stable_metrics: dict = field(default_factory=lambda: {"requests": 0, "errors": 0, "total_latency": 0})
    canary_metrics: dict = field(default_factory=lambda: {"requests": 0, "errors": 0, "total_latency": 0})
    is_active: bool = True
    auto_promote: bool = True
    created_at: float = field(default_factory=time.time)

    def route(self) -> str:
        if random.random() * 100 < self.canary_percentage:
            return self.canary_model
        return self.stable_model

    def record(self, model: str, latency_ms: float, error: bool):
        target = self.canary_metrics if model == self.canary_model else self.stable_metrics
        target["requests"] += 1
        if error:
            target["errors"] += 1
        target["total_latency"] += latency_ms
        if self.auto_promote:
            self._check_promotion()

    def _check_promotion(self):
        c, s = self.canary_metrics, self.stable_metrics
        if c["requests"] < self.min_sample_size or s["requests"] < self.min_sample_size:
            return
        c_err = c["errors"] / max(c["requests"], 1)
        s_err = s["errors"] / max(s["requests"], 1)
        c_lat = c["total_latency"] / max(c["requests"], 1)
        s_lat = s["total_latency"] / max(s["requests"], 1)
        if c_err <= s_err and c_lat <= s_lat * 1.1:
            self.canary_percentage = 100.0
            self.is_active = False

    def get_status(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "stable_model": self.stable_model,
            "canary_model": self.canary_model,
            "canary_percentage": self.canary_percentage,
            "is_active": self.is_active,
            "stable_metrics": self.stable_metrics,
            "canary_metrics": self.canary_metrics,
        }


@dataclass
class TenantRoutingConfig:
    tenant_id: str
    strategy: RoutingStrategy = RoutingStrategy.SEMANTIC
    failover_chain: list = field(default_factory=lambda: ["openai", "anthropic", "google", "mistral"])
    monthly_budget_usd: float = 1000.0
    current_spend_usd: float = 0.0
    topic_model_map: dict = field(default_factory=dict)
    api_keys: dict = field(default_factory=dict)  # provider -> [keys]
    key_weights: dict = field(default_factory=dict)  # provider -> [weights]
    key_index: dict = field(default_factory=lambda: defaultdict(int))  # round-robin index


class RoutingEngine:
    """Central routing engine for all LLM requests."""

    def __init__(self):
        self._provider_health: dict[str, ProviderHealth] = {}
        self._canary_experiments: dict[str, CanaryExperiment] = {}
        self._tenant_configs: dict[str, TenantRoutingConfig] = {}
        self._default_config = TenantRoutingConfig(tenant_id="default")

    def get_tenant_config(self, tenant_id: str) -> TenantRoutingConfig:
        if tenant_id not in self._tenant_configs:
            self._tenant_configs[tenant_id] = TenantRoutingConfig(tenant_id=tenant_id)
        return self._tenant_configs[tenant_id]

    def set_tenant_config(self, tenant_id: str, config: dict):
        tc = self.get_tenant_config(tenant_id)
        for k, v in config.items():
            if hasattr(tc, k):
                setattr(tc, k, v)

    # ── Semantic Routing ──
    def _semantic_route(self, prompt: str, tenant_config: TenantRoutingConfig) -> str:
        prompt_lower = prompt.lower()
        best_topic = "simple"
        best_score = 0
        for topic, cluster in TOPIC_CLUSTERS.items():
            score = sum(1 for kw in cluster["keywords"] if kw in prompt_lower)
            if score > best_score:
                best_score = score
                best_topic = topic
        # Check tenant overrides
        if best_topic in tenant_config.topic_model_map:
            return tenant_config.topic_model_map[best_topic]
        return TOPIC_CLUSTERS[best_topic]["preferred_models"][0]

    # ── Cost-Based Routing ──
    def _cost_route(self, prompt: str, tenant_config: TenantRoutingConfig) -> str:
        token_estimate = len(prompt.split()) * 1.3
        budget_ratio = tenant_config.current_spend_usd / max(tenant_config.monthly_budget_usd, 0.01)
        if budget_ratio > 0.9:
            return "gemini-2.0-flash"
        if budget_ratio > 0.8:
            return "gpt-4o-mini"
        if token_estimate < 100:
            return "gpt-4o-mini"
        if token_estimate < 500:
            return "gpt-4o"
        return "gpt-4o"

    # ── Latency-Based Routing ──
    def _latency_route(self) -> str:
        healthy = [
            h for h in self._provider_health.values()
            if h.circuit_breaker.can_execute() and h.error_rate < 0.2
        ]
        if not healthy:
            return "gpt-4o"
        healthy.sort(key=lambda h: h.latency_p95_ms)
        return healthy[0].model

    # ── Canary Routing ──
    def _canary_route(self, tenant_id: str) -> str | None:
        for exp in self._canary_experiments.values():
            if exp.is_active:
                return exp.route()
        return None

    # ── Load Balancing ──
    def get_api_key(self, provider: str, tenant_config: TenantRoutingConfig, strategy: str = "round_robin") -> str | None:
        keys = tenant_config.api_keys.get(provider, [])
        if not keys:
            return None
        # Filter out unhealthy keys
        healthy_keys = []
        for k in keys:
            key_id = f"{provider}:{hashlib.sha256(k.encode()).hexdigest()[:8]}"
            health = self._provider_health.get(key_id)
            if not health or health.circuit_breaker.can_execute():
                healthy_keys.append(k)
        if not healthy_keys:
            return keys[0]  # Fallback to first key even if unhealthy
        if strategy == "round_robin":
            idx = tenant_config.key_index[provider] % len(healthy_keys)
            tenant_config.key_index[provider] += 1
            return healthy_keys[idx]
        elif strategy == "weighted":
            weights = tenant_config.key_weights.get(provider, [1] * len(healthy_keys))
            return random.choices(healthy_keys, weights=weights[:len(healthy_keys)])[0]
        elif strategy == "least_connections":
            min_conn = float("inf")
            best_key = healthy_keys[0]
            for k in healthy_keys:
                key_id = f"{provider}:{hashlib.sha256(k.encode()).hexdigest()[:8]}"
                health = self._provider_health.get(key_id)
                conn = health.active_connections if health else 0
                if conn < min_conn:
                    min_conn = conn
                    best_key = k
            return best_key
        return healthy_keys[0]

    # ── Failover ──
    def get_failover_chain(self, primary_provider: str, tenant_config: TenantRoutingConfig) -> list[str]:
        chain = tenant_config.failover_chain.copy()
        if primary_provider in chain:
            chain.remove(primary_provider)
        chain.insert(0, primary_provider)
        # Filter by circuit breaker
        return [p for p in chain if self._get_provider_health(p).circuit_breaker.can_execute()]

    def _get_provider_health(self, provider: str) -> ProviderHealth:
        if provider not in self._provider_health:
            self._provider_health[provider] = ProviderHealth(provider=provider, model=provider)
        return self._provider_health[provider]

    # ── Main Route Decision ──
    def route(self, prompt: str, tenant_id: str, requested_model: str | None = None,
              requested_provider: str | None = None) -> dict:
        tenant_config = self.get_tenant_config(tenant_id)

        # If explicit model requested, respect it (but still apply failover)
        if requested_model:
            model = requested_model
            provider = requested_provider or self._model_to_provider(model)
        else:
            # Canary first
            canary = self._canary_route(tenant_id)
            if canary:
                model = canary
                provider = self._model_to_provider(model)
            else:
                strategy = tenant_config.strategy
                if strategy == RoutingStrategy.SEMANTIC:
                    model = self._semantic_route(prompt, tenant_config)
                elif strategy == RoutingStrategy.COST:
                    model = self._cost_route(prompt, tenant_config)
                elif strategy == RoutingStrategy.LATENCY:
                    model = self._latency_route()
                else:
                    model = self._semantic_route(prompt, tenant_config)
                provider = self._model_to_provider(model)

        failover_chain = self.get_failover_chain(provider, tenant_config)

        return {
            "model": model,
            "provider": provider,
            "failover_chain": failover_chain,
            "strategy": tenant_config.strategy.value,
            "budget_remaining_pct": max(0, 100 * (1 - tenant_config.current_spend_usd / max(tenant_config.monthly_budget_usd, 0.01))),
        }

    def record_result(self, provider: str, model: str, latency_ms: float, success: bool, tokens_used: int = 0, tenant_id: str = "default"):
        health = self._get_provider_health(f"{provider}:{model}")
        health.record_latency(latency_ms, success)
        # Update tenant spend
        tc = self.get_tenant_config(tenant_id)
        pricing = MODEL_PRICING.get(model, {"input": 0.001, "output": 0.002})
        cost = (tokens_used / 1000) * (pricing["input"] + pricing["output"]) / 2
        tc.current_spend_usd += cost
        # Record canary
        for exp in self._canary_experiments.values():
            if exp.is_active and model in (exp.stable_model, exp.canary_model):
                exp.record(model, latency_ms, not success)

    # ── Canary Management ──
    def create_canary(self, experiment_id: str, stable: str, canary: str, pct: float = 10.0) -> CanaryExperiment:
        exp = CanaryExperiment(experiment_id=experiment_id, stable_model=stable, canary_model=canary, canary_percentage=pct)
        self._canary_experiments[experiment_id] = exp
        return exp

    def get_canary_status(self, experiment_id: str) -> dict | None:
        exp = self._canary_experiments.get(experiment_id)
        return exp.get_status() if exp else None

    def _model_to_provider(self, model: str) -> str:
        if model.startswith("gpt") or model.startswith("o1") or model.startswith("o3"):
            return "openai"
        if model.startswith("claude"):
            return "anthropic"
        if model.startswith("gemini"):
            return "google"
        if model.startswith("mistral"):
            return "mistral"
        if model.startswith("deepseek"):
            return "deepseek"
        if model.startswith("llama") or model.startswith("mixtral"):
            return "groq"
        if model.startswith("command"):
            return "cohere"
        return "openai"

    def get_all_health(self) -> list[dict]:
        return [
            {
                "provider": h.provider,
                "model": h.model,
                "latency_p95_ms": round(h.latency_p95_ms, 1),
                "error_rate": round(h.error_rate, 4),
                "circuit_state": h.circuit_breaker.state.value,
                "active_connections": h.active_connections,
            }
            for h in self._provider_health.values()
        ]

    def get_pricing(self) -> dict:
        return MODEL_PRICING


# Singleton
routing_engine = RoutingEngine()
