import httpx
import uuid
from typing import AsyncGenerator, Optional
from fastapi import HTTPException
from app.adapters.base import LLMAdapter, LLMResponse
from app.core.config import get_settings

settings = get_settings()

class MistralAdapter(LLMAdapter):
    ENDPOINT = "https://api.mistral.ai/v1/chat/completions"

    async def complete(
        self, 
        model: str,
        messages: list[dict], 
        api_key: Optional[str] = None,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        # Assuming MISTRAL_API_KEY might exist in real environment
        key = api_key or getattr(settings, "MISTRAL_API_KEY", None)
        if not key:
            raise HTTPException(400, "Mistral API key not configured")

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                self.ENDPOINT,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": model, "messages": messages, "stream": stream, **kwargs},
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
        key = api_key or getattr(settings, "MISTRAL_API_KEY", None)
        if not key:
            raise HTTPException(400, "Mistral API key not configured")

        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                self.ENDPOINT,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": model, "messages": messages, "stream": True, **kwargs},
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.strip():
                        yield line
