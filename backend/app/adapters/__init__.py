"""
GhostPrompt LLM Adapter Registry

Supports 11 providers with automatic model-to-provider detection.
Every provider is scanned through the same AI Firewall pipeline.
"""

from fastapi import HTTPException

from app.adapters.anthropic import AnthropicAdapter
from app.adapters.base import LLMAdapter, LLMResponse
from app.adapters.cohere import CohereAdapter
from app.adapters.deepseek import DeepSeekAdapter
from app.adapters.gemini import GeminiAdapter
from app.adapters.groq import GroqAdapter
from app.adapters.huggingface import HuggingFaceAdapter
from app.adapters.mistral import MistralAdapter
from app.adapters.ollama import OllamaAdapter
from app.adapters.openai import OpenAIAdapter
from app.adapters.perplexity import PerplexityAdapter
from app.adapters.together import TogetherAdapter
from app.adapters.xai import XAIAdapter

# ── Provider Registry ─────────────────────────────────────────
PROVIDER_REGISTRY = {
    "openai": OpenAIAdapter,
    "anthropic": AnthropicAdapter,
    "google": GeminiAdapter,
    "gemini": GeminiAdapter,
    "mistral": MistralAdapter,
    "ollama": OllamaAdapter,
    "cohere": CohereAdapter,
    "groq": GroqAdapter,
    "together": TogetherAdapter,
    "deepseek": DeepSeekAdapter,
    "perplexity": PerplexityAdapter,
    "huggingface": HuggingFaceAdapter,
    "hf": HuggingFaceAdapter,
    "xai": XAIAdapter,
    "grok": XAIAdapter,
}

# ── Model → Provider Auto-detection ──────────────────────────
MODEL_PREFIXES = {
    "gpt": "openai",
    "o1": "openai",
    "o3": "openai",
    "o4": "openai",
    "chatgpt": "openai",
    "claude": "anthropic",
    "gemini": "google",
    "gemma": "google",
    "mistral": "mistral",
    "mixtral": "mistral",
    "codestral": "mistral",
    "pixtral": "mistral",
    "command": "cohere",
    "command-r": "cohere",
    "llama": "groq",          # Default for llama models (fast inference)
    "deepseek": "deepseek",
    "sonar": "perplexity",
    "pplx": "perplexity",
    "qwen": "together",
    "yi": "together",
    "dbrx": "together",
    "grok": "xai",
}

# ── Supported Models Catalog ──────────────────────────────────
PROVIDER_MODELS = {
    "openai": {
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo", "o1", "o1-mini", "o3-mini", "o4-mini"],
        "display_name": "OpenAI",
        "docs": "https://platform.openai.com/docs",
    },
    "anthropic": {
        "models": ["claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022", "claude-3-haiku-20240307", "claude-3-opus-20240229"],
        "display_name": "Anthropic",
        "docs": "https://docs.anthropic.com",
    },
    "google": {
        "models": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        "display_name": "Google Gemini",
        "docs": "https://ai.google.dev/docs",
    },
    "mistral": {
        "models": ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest", "codestral-latest", "pixtral-large-latest"],
        "display_name": "Mistral AI",
        "docs": "https://docs.mistral.ai",
    },
    "cohere": {
        "models": ["command-r-plus", "command-r", "command-light"],
        "display_name": "Cohere",
        "docs": "https://docs.cohere.com",
    },
    "groq": {
        "models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768", "gemma2-9b-it"],
        "display_name": "Groq",
        "docs": "https://console.groq.com/docs",
    },
    "together": {
        "models": ["meta-llama/Llama-3.3-70B-Instruct-Turbo", "Qwen/Qwen2.5-72B-Instruct-Turbo", "deepseek-ai/DeepSeek-R1-Distill-Llama-70B"],
        "display_name": "Together AI",
        "docs": "https://docs.together.ai",
    },
    "deepseek": {
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "display_name": "DeepSeek",
        "docs": "https://platform.deepseek.com/docs",
    },
    "perplexity": {
        "models": ["sonar-pro", "sonar", "sonar-reasoning-pro", "sonar-reasoning"],
        "display_name": "Perplexity AI",
        "docs": "https://docs.perplexity.ai",
    },
    "huggingface": {
        "models": ["meta-llama/Llama-3.1-8B-Instruct", "mistralai/Mistral-7B-Instruct-v0.3", "microsoft/Phi-3-mini-4k-instruct"],
        "display_name": "Hugging Face",
        "docs": "https://huggingface.co/docs/api-inference",
    },
    "ollama": {
        "models": ["llama3.2", "llama3.1", "mistral", "codellama", "phi3", "gemma2", "qwen2.5"],
        "display_name": "Ollama (Local)",
        "docs": "https://ollama.com",
    },
    "xai": {
        "models": ["grok-2", "grok-2-mini", "grok-3", "grok-3-mini"],
        "display_name": "xAI (Grok)",
        "docs": "https://docs.x.ai",
    },
}


def get_adapter(provider: str) -> LLMAdapter:
    """Factory to get the correct LLM adapter for a given provider."""
    adapter_class = PROVIDER_REGISTRY.get(provider.lower())
    if not adapter_class:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}. Supported: {list(PROVIDER_REGISTRY.keys())}")
    return adapter_class()


def detect_provider(model: str) -> str:
    """Auto-detect provider from model name."""
    m = model.lower()
    for prefix, provider in MODEL_PREFIXES.items():
        if m.startswith(prefix):
            return provider
    # Default to ollama for unknown models (local inference)
    return "ollama"
