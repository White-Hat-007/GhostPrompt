"""
Perplexity AI Adapter — pplx-7b-online, sonar, etc.
Perplexity uses OpenAI-compatible API with citations.
"""

import httpx
import json
from typing import AsyncGenerator, Optional
from fastapi import HTTPException
from app.adapters.base import LLMAdapter, LLMResponse
from app.core.config import get_settings

settings = get_settings()


class PerplexityAdapter(LLMAdapter):
    ENDPOINT = "https://api.perplexity.ai/chat/completions"

    async def complete(
        self,
        model: str,
        messages: list[dict],
        api_key: Optional[str] = None,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        key = api_key or getattr(settings, "PERPLEXITY_API_KEY", None)
        if not key:
            raise HTTPException(400, "Perplexity API key not configured")

        body = {"model": model, "messages": messages, "stream": False}
        if kwargs.get("temperature"):
            body["temperature"] = kwargs["temperature"]
        if kwargs.get("max_tokens"):
            body["max_tokens"] = kwargs["max_tokens"]

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                self.ENDPOINT,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return LLMResponse(content=content, raw_response=data)

    async def stream_complete(
        self,
        model: str,
        messages: list[dict],
        api_key: Optional[str] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        key = api_key or getattr(settings, "PERPLEXITY_API_KEY", None)
        if not key:
            raise HTTPException(400, "Perplexity API key not configured")

        body = {"model": model, "messages": messages, "stream": True}

        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                self.ENDPOINT,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json=body,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.strip():
                        yield line
