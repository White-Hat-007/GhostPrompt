"""
Cohere Adapter — Command R+ / Command R family
Drop-in proxy support for Cohere's chat API.
"""

import httpx
import uuid
import time
import json
from typing import AsyncGenerator, Optional
from fastapi import HTTPException
from app.adapters.base import LLMAdapter, LLMResponse
from app.core.config import get_settings

settings = get_settings()


class CohereAdapter(LLMAdapter):
    ENDPOINT = "https://api.cohere.com/v2/chat"

    async def complete(
        self,
        model: str,
        messages: list[dict],
        api_key: Optional[str] = None,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        key = api_key or getattr(settings, "COHERE_API_KEY", None)
        if not key:
            raise HTTPException(400, "Cohere API key not configured")

        body = {
            "model": model,
            "messages": messages,
        }
        if kwargs.get("temperature"):
            body["temperature"] = kwargs["temperature"]
        if kwargs.get("max_tokens"):
            body["max_tokens"] = kwargs["max_tokens"]

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                self.ENDPOINT,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

            content = ""
            msg = data.get("message", {})
            for block in msg.get("content", []):
                if block.get("type") == "text":
                    content += block.get("text", "")

            # Normalize to OpenAI format
            normalized = {
                "id": data.get("id", str(uuid.uuid4())),
                "object": "chat.completion",
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": data.get("finish_reason", "stop"),
                }],
                "usage": {
                    "prompt_tokens": data.get("usage", {}).get("billed_units", {}).get("input_tokens", 0),
                    "completion_tokens": data.get("usage", {}).get("billed_units", {}).get("output_tokens", 0),
                    "total_tokens": 0,
                },
            }
            normalized["usage"]["total_tokens"] = normalized["usage"]["prompt_tokens"] + normalized["usage"]["completion_tokens"]
            return LLMResponse(content=content, raw_response=normalized)

    async def stream_complete(
        self,
        model: str,
        messages: list[dict],
        api_key: Optional[str] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        key = api_key or getattr(settings, "COHERE_API_KEY", None)
        if not key:
            raise HTTPException(400, "Cohere API key not configured")

        body = {
            "model": model,
            "messages": messages,
            "stream": True,
        }

        stream_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created_time = int(time.time())

        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                self.ENDPOINT,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json=body,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("data:"):
                        data_str = line[5:].strip()
                        try:
                            data = json.loads(data_str)
                            if data.get("type") == "content-delta":
                                text = data.get("delta", {}).get("message", {}).get("content", {}).get("text", "")
                                openai_chunk = {
                                    "id": stream_id,
                                    "object": "chat.completion.chunk",
                                    "created": created_time,
                                    "model": model,
                                    "choices": [{
                                        "index": 0,
                                        "delta": {"content": text} if text else {},
                                        "finish_reason": None,
                                    }],
                                }
                                yield f"data: {json.dumps(openai_chunk)}"
                        except Exception:
                            pass
        yield "data: [DONE]"
