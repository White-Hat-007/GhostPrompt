import httpx
import uuid
from typing import AsyncGenerator, Optional
from fastapi import HTTPException
from app.adapters.base import LLMAdapter, LLMResponse
from app.core.config import get_settings

settings = get_settings()

class OpenAIAdapter(LLMAdapter):
    ENDPOINT = "https://api.openai.com/v1/chat/completions"

    async def complete(
        self, 
        model: str,
        messages: list[dict], 
        api_key: Optional[str] = None,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        key = api_key or settings.OPENAI_API_KEY
        if not key:
            raise HTTPException(400, "OpenAI API key not configured")

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
        key = api_key or settings.OPENAI_API_KEY
        if not key:
            raise HTTPException(400, "OpenAI API key not configured")

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
