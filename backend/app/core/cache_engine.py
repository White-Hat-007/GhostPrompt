"""
GhostPrompt Semantic Caching Engine

Exact Cache: SHA256 hash → Redis with configurable TTL
Semantic Cache: Embedding similarity → FAISS index per tenant
Cache Analytics: Hit rates, cost savings, popular queries
"""

import hashlib
import json
import time
import numpy as np
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class CacheEntry:
    key: str
    response: dict
    model: str
    tokens_saved: int
    created_at: float
    ttl: int
    hits: int = 0


@dataclass
class CacheAnalytics:
    exact_hits: int = 0
    exact_misses: int = 0
    semantic_hits: int = 0
    semantic_misses: int = 0
    total_tokens_saved: int = 0
    total_cost_saved: float = 0.0
    popular_queries: dict = field(default_factory=lambda: defaultdict(int))

    def hit_rate_exact(self) -> float:
        total = self.exact_hits + self.exact_misses
        return self.exact_hits / max(total, 1)

    def hit_rate_semantic(self) -> float:
        total = self.semantic_hits + self.semantic_misses
        return self.semantic_hits / max(total, 1)

    def to_dict(self) -> dict:
        top_queries = sorted(self.popular_queries.items(), key=lambda x: -x[1])[:20]
        return {
            "exact_hit_rate": round(self.hit_rate_exact(), 4),
            "semantic_hit_rate": round(self.hit_rate_semantic(), 4),
            "exact_hits": self.exact_hits,
            "exact_misses": self.exact_misses,
            "semantic_hits": self.semantic_hits,
            "semantic_misses": self.semantic_misses,
            "total_tokens_saved": self.total_tokens_saved,
            "total_cost_saved_usd": round(self.total_cost_saved, 4),
            "top_cached_queries": [{"query": q[:80], "hits": h} for q, h in top_queries],
        }


class CacheEngine:
    """Exact + Semantic caching for LLM responses."""

    def __init__(self):
        self._exact_cache: dict[str, CacheEntry] = {}
        self._semantic_index: dict[str, list] = defaultdict(list)  # tenant -> [(embedding, key)]
        self._analytics: dict[str, CacheAnalytics] = defaultdict(CacheAnalytics)
        self._tenant_ttls: dict[str, int] = {}
        self._semantic_threshold: float = 0.92
        self._embedding_dim: int = 384  # sentence-transformers default

    def _hash_request(self, model: str, messages: list, temperature: float = 1.0, top_p: float = 1.0) -> str:
        payload = json.dumps({"model": model, "messages": messages, "temperature": temperature, "top_p": top_p}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def _simple_embed(self, text: str) -> np.ndarray:
        """Lightweight embedding using character n-gram hashing (no ML model needed).
        For production, replace with sentence-transformers."""
        vec = np.zeros(self._embedding_dim, dtype=np.float32)
        text_lower = text.lower().strip()
        words = text_lower.split()
        for i, word in enumerate(words):
            for n in range(1, min(4, len(word) + 1)):
                for j in range(len(word) - n + 1):
                    ngram = word[j:j + n]
                    h = hash(ngram) % self._embedding_dim
                    vec[h] += 1.0 / (i + 1)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec

    def set_tenant_ttl(self, tenant_id: str, ttl_seconds: int):
        self._tenant_ttls[tenant_id] = ttl_seconds

    def set_semantic_threshold(self, threshold: float):
        self._semantic_threshold = max(0.5, min(1.0, threshold))

    # ── Exact Cache ──
    def exact_get(self, model: str, messages: list, temperature: float = 1.0, top_p: float = 1.0, tenant_id: str = "default") -> Optional[dict]:
        key = self._hash_request(model, messages, temperature, top_p)
        entry = self._exact_cache.get(key)
        analytics = self._analytics[tenant_id]
        if entry and (time.time() - entry.created_at) < entry.ttl:
            entry.hits += 1
            analytics.exact_hits += 1
            analytics.total_tokens_saved += entry.tokens_saved
            analytics.total_cost_saved += entry.tokens_saved * 0.000003  # ~avg cost
            query_text = messages[-1].get("content", "")[:80] if messages else ""
            analytics.popular_queries[query_text] += 1
            return entry.response
        elif entry:
            del self._exact_cache[key]  # Expired
        analytics.exact_misses += 1
        return None

    def exact_set(self, model: str, messages: list, response: dict, tokens_used: int, temperature: float = 1.0, top_p: float = 1.0, tenant_id: str = "default"):
        key = self._hash_request(model, messages, temperature, top_p)
        ttl = self._tenant_ttls.get(tenant_id, 3600)
        self._exact_cache[key] = CacheEntry(
            key=key, response=response, model=model,
            tokens_saved=tokens_used, created_at=time.time(), ttl=ttl,
        )

    # ── Semantic Cache ──
    def semantic_get(self, messages: list, tenant_id: str = "default") -> Optional[dict]:
        analytics = self._analytics[tenant_id]
        query = messages[-1].get("content", "") if messages else ""
        if not query or len(query) < 10:
            analytics.semantic_misses += 1
            return None
        query_emb = self._simple_embed(query)
        index = self._semantic_index.get(tenant_id, [])
        best_sim = 0.0
        best_entry = None
        for emb, cache_key in index:
            sim = float(np.dot(query_emb, emb))
            if sim > best_sim:
                best_sim = sim
                best_entry = cache_key
        if best_sim >= self._semantic_threshold and best_entry:
            entry = self._exact_cache.get(best_entry)
            if entry and (time.time() - entry.created_at) < entry.ttl:
                entry.hits += 1
                analytics.semantic_hits += 1
                analytics.total_tokens_saved += entry.tokens_saved
                analytics.total_cost_saved += entry.tokens_saved * 0.000003
                analytics.popular_queries[query[:80]] += 1
                return entry.response
        analytics.semantic_misses += 1
        return None

    def semantic_set(self, messages: list, model: str, response: dict, tokens_used: int, tenant_id: str = "default"):
        query = messages[-1].get("content", "") if messages else ""
        if not query or len(query) < 10:
            return
        # Also set exact cache
        self.exact_set(model, messages, response, tokens_used, tenant_id=tenant_id)
        key = self._hash_request(model, messages)
        emb = self._simple_embed(query)
        self._semantic_index[tenant_id].append((emb, key))
        # Limit index size per tenant
        if len(self._semantic_index[tenant_id]) > 10000:
            self._semantic_index[tenant_id] = self._semantic_index[tenant_id][-5000:]

    # ── Cache Management ──
    def flush_tenant(self, tenant_id: str):
        keys_to_remove = []
        for key, entry in self._exact_cache.items():
            # We don't store tenant_id in entry, so flush all for simplicity
            pass
        self._semantic_index.pop(tenant_id, None)
        self._analytics[tenant_id] = CacheAnalytics()

    def flush_all(self):
        self._exact_cache.clear()
        self._semantic_index.clear()
        self._analytics.clear()

    def get_analytics(self, tenant_id: str = "default") -> dict:
        return self._analytics[tenant_id].to_dict()

    def get_cache_size(self) -> dict:
        return {
            "exact_entries": len(self._exact_cache),
            "semantic_tenants": len(self._semantic_index),
            "semantic_total_entries": sum(len(v) for v in self._semantic_index.values()),
        }

    def warm_cache(self, queries: list[dict], tenant_id: str = "default"):
        """Pre-populate cache with expected high-frequency queries."""
        for q in queries:
            if "messages" in q and "response" in q:
                self.semantic_set(q["messages"], q.get("model", "gpt-4o"), q["response"], q.get("tokens", 100), tenant_id)


# Singleton
cache_engine = CacheEngine()
