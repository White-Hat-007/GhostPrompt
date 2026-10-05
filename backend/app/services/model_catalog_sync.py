"""
Live Model Catalog Sync — Background job to sync provider model lists.

Calls each provider's /models endpoint every 12h and caches to an
in-memory catalog (production: provider_models DB table).
Routing engine reads from this catalog, never calls providers live.
"""

import time
from datetime import datetime, timezone

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

settings = get_settings()
logger = get_logger("model_catalog")


# ── In-memory model catalog (production: PostgreSQL table) ──
_model_catalog: dict[str, list[dict]] = {}
_last_sync: str | None = None


PROVIDER_ENDPOINTS = {
    "openai": {
        "url": "https://api.openai.com/v1/models",
        "key_attr": "OPENAI_API_KEY",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "models_path": "data",
    },
    "anthropic": {
        "url": "https://api.anthropic.com/v1/models",
        "key_attr": "ANTHROPIC_API_KEY",
        "auth_header": "x-api-key",
        "auth_prefix": "",
        "models_path": "data",
        "extra_headers": {"anthropic-version": "2023-06-01"},
    },
    "google": {
        "url": "https://generativelanguage.googleapis.com/v1/models",
        "key_attr": "GOOGLE_AI_API_KEY",
        "auth_header": None,  # Uses query param
        "auth_prefix": "",
        "models_path": "models",
        "auth_query_param": "key",
    },
    "groq": {
        "url": "https://api.groq.com/openai/v1/models",
        "key_attr": "GROQ_API_KEY",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "models_path": "data",
    },
    "together": {
        "url": "https://api.together.xyz/v1/models",
        "key_attr": "TOGETHER_API_KEY",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "models_path": None,  # Root is the array
    },
    "mistral": {
        "url": "https://api.mistral.ai/v1/models",
        "key_attr": "MISTRAL_API_KEY",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "models_path": "data",
    },
    "deepseek": {
        "url": "https://api.deepseek.com/v1/models",
        "key_attr": "DEEPSEEK_API_KEY",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "models_path": "data",
    },
    "xai": {
        "url": "https://api.x.ai/v1/models",
        "key_attr": "XAI_API_KEY",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "models_path": "data",
    },
    "perplexity": {
        "url": "https://api.perplexity.ai/models",
        "key_attr": "PERPLEXITY_API_KEY",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "models_path": "data",
    },
}


# ── Static fallbacks for when API calls fail ──
STATIC_FALLBACK = {
    "openai": [
        {"id": "gpt-4o", "name": "GPT-4o", "context_window": 128000, "type": "chat"},
        {"id": "gpt-4o-mini", "name": "GPT-4o Mini", "context_window": 128000, "type": "chat"},
        {"id": "gpt-4-turbo", "name": "GPT-4 Turbo", "context_window": 128000, "type": "chat"},
        {"id": "gpt-3.5-turbo", "name": "GPT-3.5 Turbo", "context_window": 16385, "type": "chat"},
        {"id": "o1-preview", "name": "O1 Preview", "context_window": 128000, "type": "reasoning"},
        {"id": "o1-mini", "name": "O1 Mini", "context_window": 128000, "type": "reasoning"},
    ],
    "anthropic": [
        {"id": "claude-sonnet-4-20250514", "name": "Claude Sonnet 4", "context_window": 200000, "type": "chat"},
        {"id": "claude-3-5-sonnet-20241022", "name": "Claude 3.5 Sonnet", "context_window": 200000, "type": "chat"},
        {"id": "claude-3-5-haiku-20241022", "name": "Claude 3.5 Haiku", "context_window": 200000, "type": "chat"},
        {"id": "claude-3-opus-20240229", "name": "Claude 3 Opus", "context_window": 200000, "type": "chat"},
    ],
    "google": [
        {"id": "gemini-2.5-pro", "name": "Gemini 2.5 Pro", "context_window": 1048576, "type": "chat"},
        {"id": "gemini-2.5-flash", "name": "Gemini 2.5 Flash", "context_window": 1048576, "type": "chat"},
        {"id": "gemini-2.0-flash", "name": "Gemini 2.0 Flash", "context_window": 1048576, "type": "chat"},
    ],
    "groq": [
        {"id": "llama-3.3-70b-versatile", "name": "LLaMA 3.3 70B", "context_window": 131072, "type": "chat"},
        {"id": "llama-3.1-8b-instant", "name": "LLaMA 3.1 8B", "context_window": 131072, "type": "chat"},
        {"id": "mixtral-8x7b-32768", "name": "Mixtral 8x7B", "context_window": 32768, "type": "chat"},
    ],
}


async def sync_model_catalog():
    """Sync model lists from all configured providers."""
    global _last_sync
    logger.info("model_catalog_sync_started")
    t0 = time.perf_counter()

    for provider, config in PROVIDER_ENDPOINTS.items():
        api_key = getattr(settings, config["key_attr"], None)
        if not api_key:
            continue

        try:
            headers = {"Accept": "application/json"}
            if config.get("extra_headers"):
                headers.update(config["extra_headers"])

            params = {}
            if config.get("auth_header"):
                headers[config["auth_header"]] = f"{config['auth_prefix']}{api_key}"
            elif config.get("auth_query_param"):
                params[config["auth_query_param"]] = api_key

            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(config["url"], headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    models_path = config.get("models_path")
                    if models_path:
                        raw_models = data.get(models_path, [])
                    else:
                        raw_models = data if isinstance(data, list) else []

                    models = []
                    for m in raw_models:
                        model_id = m.get("id", "")
                        if not model_id:
                            continue
                        models.append({
                            "id": model_id,
                            "name": m.get("name", model_id),
                            "context_window": m.get("context_window", m.get("input_token_limit", 0)),
                            "type": _classify_model_type(model_id, m),
                            "created": m.get("created", m.get("created_at", "")),
                            "owned_by": m.get("owned_by", m.get("owner", provider)),
                            "source": "live",
                            "last_synced": datetime.now(timezone.utc).isoformat(),
                        })

                    _model_catalog[provider] = models
                    logger.info("provider_synced", provider=provider, models=len(models))
                else:
                    logger.warning("provider_sync_failed", provider=provider, status=resp.status_code)
                    # Use fallback
                    if provider in STATIC_FALLBACK and provider not in _model_catalog:
                        _model_catalog[provider] = [
                            {**m, "source": "fallback", "last_synced": datetime.now(timezone.utc).isoformat()}
                            for m in STATIC_FALLBACK[provider]
                        ]
        except Exception as e:
            logger.warning("provider_sync_error", provider=provider, error=str(e)[:200])
            if provider in STATIC_FALLBACK and provider not in _model_catalog:
                _model_catalog[provider] = [
                    {**m, "source": "fallback", "last_synced": datetime.now(timezone.utc).isoformat()}
                    for m in STATIC_FALLBACK[provider]
                ]

    _last_sync = datetime.now(timezone.utc).isoformat()
    duration = round((time.perf_counter() - t0) * 1000, 1)
    total = sum(len(v) for v in _model_catalog.values())
    logger.info("model_catalog_sync_complete", total_models=total, duration_ms=duration)


def get_all_models() -> dict:
    """Get the full model catalog grouped by provider."""
    return {
        "providers": {
            provider: {
                "models": models,
                "count": len(models),
                "has_key": bool(getattr(settings, PROVIDER_ENDPOINTS.get(provider, {}).get("key_attr", ""), None)),
            }
            for provider, models in _model_catalog.items()
        },
        "total_models": sum(len(v) for v in _model_catalog.values()),
        "last_sync": _last_sync,
    }


def get_provider_models(provider: str) -> list[dict]:
    """Get models for a specific provider."""
    return _model_catalog.get(provider, STATIC_FALLBACK.get(provider, []))


def _classify_model_type(model_id: str, raw: dict) -> str:
    """Classify a model's capability type from its ID."""
    mid = model_id.lower()
    if "embedding" in mid or "embed" in mid:
        return "embedding"
    if "whisper" in mid or "tts" in mid or "audio" in mid:
        return "audio"
    if "dall-e" in mid or "image" in mid:
        return "image"
    if "o1" in mid or "o3" in mid or "reasoning" in mid:
        return "reasoning"
    if "vision" in mid or "multimodal" in mid:
        return "multimodal"
    return "chat"
