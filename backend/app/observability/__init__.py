"""
GhostPrompt Observability Platform

Complete request tracing, token/cost tracking, log export,
metrics aggregation, and analytics engine.
"""

import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SpanKind(str, Enum):
    REQUEST = "request"
    PREPROCESSING = "preprocessing"
    DETECTION = "detection"
    LLM_CALL = "llm_call"
    POSTPROCESSING = "postprocessing"
    TOOL_CALL = "tool_call"
    CACHE_LOOKUP = "cache_lookup"


@dataclass
class Span:
    span_id: str
    trace_id: str
    parent_span_id: str | None
    name: str
    kind: SpanKind
    start_time: float
    end_time: float = 0
    duration_ms: float = 0
    attributes: dict = field(default_factory=dict)
    status: str = "ok"
    events: list = field(default_factory=list)

    def finish(self, status: str = "ok"):
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000
        self.status = status

    def to_dict(self) -> dict:
        return {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "kind": self.kind.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": round(self.duration_ms, 2),
            "attributes": self.attributes,
            "status": self.status,
            "events": self.events,
        }


@dataclass
class Trace:
    trace_id: str
    tenant_id: str
    spans: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def add_span(self, name: str, kind: SpanKind, parent_span_id: str = None, attributes: dict = None) -> Span:
        span = Span(
            span_id=uuid.uuid4().hex[:16], trace_id=self.trace_id,
            parent_span_id=parent_span_id, name=name, kind=kind,
            start_time=time.time(), attributes=attributes or {},
        )
        self.spans.append(span)
        return span

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "tenant_id": self.tenant_id,
            "spans": [s.to_dict() for s in self.spans],
            "total_duration_ms": round(sum(s.duration_ms for s in self.spans if s.kind == SpanKind.REQUEST), 2),
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


# ── Model Pricing Table ──
MODEL_PRICES = {
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    "claude-3-5-sonnet": {"input": 3.00, "output": 15.00},
    "claude-3-haiku": {"input": 0.25, "output": 1.25},
    "claude-3-opus": {"input": 15.00, "output": 75.00},
    "gemini-1.5-pro": {"input": 1.25, "output": 5.00},
    "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
    "gemini-2.0-flash": {"input": 0.10, "output": 0.40},
    "mistral-large": {"input": 2.00, "output": 6.00},
    "deepseek-chat": {"input": 0.14, "output": 0.28},
}


@dataclass
class TokenRecord:
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    tenant_id: str
    user_id: str = ""
    api_key_id: str = ""
    feature_tag: str = ""
    timestamp: float = field(default_factory=time.time)


class Tracer:
    """Request tracing engine with OpenTelemetry-compatible output."""

    def __init__(self):
        self._traces: list[Trace] = []
        self._max_traces = 50000

    def start_trace(self, tenant_id: str, metadata: dict = None) -> Trace:
        trace = Trace(trace_id=uuid.uuid4().hex[:32], tenant_id=tenant_id, metadata=metadata or {})
        self._traces.append(trace)
        if len(self._traces) > self._max_traces:
            self._traces = self._traces[-self._max_traces // 2:]
        return trace

    def get_trace(self, trace_id: str) -> dict | None:
        for t in reversed(self._traces):
            if t.trace_id == trace_id:
                return t.to_dict()
        return None

    def list_traces(self, tenant_id: str, limit: int = 50, offset: int = 0) -> list[dict]:
        filtered = [t for t in reversed(self._traces) if t.tenant_id == tenant_id]
        return [t.to_dict() for t in filtered[offset:offset + limit]]


class TokenTracker:
    """Token and cost tracking per request."""

    def __init__(self):
        self._records: list[TokenRecord] = []
        self._max_records = 100000

    def record(self, model: str, input_tokens: int, output_tokens: int, tenant_id: str,
               user_id: str = "", api_key_id: str = "", feature_tag: str = "") -> TokenRecord:
        prices = MODEL_PRICES.get(model, {"input": 1.0, "output": 2.0})
        cost = (input_tokens / 1_000_000) * prices["input"] + (output_tokens / 1_000_000) * prices["output"]
        rec = TokenRecord(model=model, input_tokens=input_tokens, output_tokens=output_tokens,
                          cost_usd=cost, tenant_id=tenant_id, user_id=user_id,
                          api_key_id=api_key_id, feature_tag=feature_tag)
        self._records.append(rec)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records // 2:]
        return rec

    def get_cost_summary(self, tenant_id: str, period: str = "day") -> dict:
        now = time.time()
        cutoffs = {"hour": 3600, "day": 86400, "week": 604800, "month": 2592000}
        cutoff = now - cutoffs.get(period, 86400)
        filtered = [r for r in self._records if r.tenant_id == tenant_id and r.timestamp > cutoff]
        by_model = defaultdict(lambda: {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "requests": 0})
        total_cost = 0.0
        total_input = 0
        total_output = 0
        for r in filtered:
            m = by_model[r.model]
            m["input_tokens"] += r.input_tokens
            m["output_tokens"] += r.output_tokens
            m["cost_usd"] += r.cost_usd
            m["requests"] += 1
            total_cost += r.cost_usd
            total_input += r.input_tokens
            total_output += r.output_tokens
        return {
            "period": period,
            "total_cost_usd": round(total_cost, 6),
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_requests": len(filtered),
            "by_model": {k: {**v, "cost_usd": round(v["cost_usd"], 6)} for k, v in by_model.items()},
        }

    def get_top_users(self, tenant_id: str, limit: int = 10) -> list[dict]:
        by_user = defaultdict(lambda: {"tokens": 0, "cost": 0.0, "requests": 0})
        for r in self._records:
            if r.tenant_id == tenant_id and r.user_id:
                u = by_user[r.user_id]
                u["tokens"] += r.input_tokens + r.output_tokens
                u["cost"] += r.cost_usd
                u["requests"] += 1
        sorted_users = sorted(by_user.items(), key=lambda x: -x[1]["tokens"])[:limit]
        return [{"user_id": uid, **data} for uid, data in sorted_users]


class MetricsAggregator:
    """Aggregate metrics per tenant/model/key."""

    def __init__(self):
        self._latencies: dict[str, list] = defaultdict(list)  # model -> [(timestamp, latency_ms)]
        self._errors: dict[str, list] = defaultdict(list)

    def record(self, model: str, latency_ms: float, error: bool, tenant_id: str):
        now = time.time()
        self._latencies[f"{tenant_id}:{model}"].append((now, latency_ms))
        if error:
            self._errors[f"{tenant_id}:{model}"].append(now)
        # Prune old data (keep 1 hour)
        cutoff = now - 3600
        key = f"{tenant_id}:{model}"
        self._latencies[key] = [(t, l) for t, l in self._latencies[key] if t > cutoff]
        self._errors[key] = [t for t in self._errors[key] if t > cutoff]

    def get_percentiles(self, tenant_id: str, model: str) -> dict:
        key = f"{tenant_id}:{model}"
        lats = sorted([l for _, l in self._latencies.get(key, [])])
        if not lats:
            return {"p50": 0, "p95": 0, "p99": 0, "count": 0}
        return {
            "p50": round(lats[int(len(lats) * 0.5)], 1),
            "p95": round(lats[int(len(lats) * 0.95)], 1),
            "p99": round(lats[min(int(len(lats) * 0.99), len(lats) - 1)], 1),
            "count": len(lats),
            "error_count": len(self._errors.get(key, [])),
        }

    def get_all_models(self, tenant_id: str) -> dict:
        result = {}
        for key in self._latencies:
            if key.startswith(f"{tenant_id}:"):
                model = key.split(":", 1)[1]
                result[model] = self.get_percentiles(tenant_id, model)
        return result


class AnalyticsEngine:
    """Usage analytics and reporting."""

    def __init__(self, token_tracker: 'TokenTracker', metrics: 'MetricsAggregator'):
        self.token_tracker = token_tracker
        self.metrics = metrics

    def get_dashboard_data(self, tenant_id: str) -> dict:
        return {
            "cost_today": self.token_tracker.get_cost_summary(tenant_id, "day"),
            "cost_week": self.token_tracker.get_cost_summary(tenant_id, "week"),
            "cost_month": self.token_tracker.get_cost_summary(tenant_id, "month"),
            "top_users": self.token_tracker.get_top_users(tenant_id),
            "model_performance": self.metrics.get_all_models(tenant_id),
        }


# ── Singletons ──
tracer = Tracer()
token_tracker = TokenTracker()
metrics_aggregator = MetricsAggregator()
analytics_engine = AnalyticsEngine(token_tracker, metrics_aggregator)
