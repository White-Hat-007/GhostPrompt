"""
Hugging Face Inference Adapter
Supports HuggingFace's Inference API (free) and Inference Endpoints (dedicated).
Uses the Messages API format (OpenAI-compatible via HF).
"""

import httpx
import json
import uuid
import time
from typing import AsyncGenerator, Optional
from fastapi import HTTPException
from app.adapters.base import LLMAdapter, LLMResponse
from app.core.config import get_settings

settings = get_settings()


class HuggingFaceAdapter(LLMAdapter):
    # Default to HF Inference API, can be overridden for endpoints
    BASE_URL = "https://api-inference.huggingface.co/models"

    async def complete(
        self,
        model: str,
        messages: list[dict],
        api_key: Optional[str] = None,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        key = api_key or getattr(settings, "HUGGINGFACE_API_KEY", None)
        if not key:
            raise HTTPException(400, "HuggingFace API key not configured")

        # HF Inference API supports chat via /v1/chat/completions for compatible models
        endpoint = f"https://api-inference.huggingface.co/models/{model}/v1/chat/completions"

        body = {"model": model, "messages": messages, "stream": False}
        if kwargs.get("temperature"):
            body["temperature"] = kwargs["temperature"]
        if kwargs.get("max_tokens"):
            body["max_tokens"] = kwargs["max_tokens"]

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                endpoint,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

            # If the response is in OpenAI format (from compatible models)
            if "choices" in data:
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return LLMResponse(content=content, raw_response=data)

            # Fallback: text-generation format
            if isinstance(data, list) and data:
                content = data[0].get("generated_text", "")
            else:
                content = data.get("generated_text", str(data))

            normalized = {
                "id": str(uuid.uuid4()),
                "object": "chat.completion",
                "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            }
            return LLMResponse(content=content, raw_response=normalized)

    async def stream_complete(
        self,
        model: str,
        messages: list[dict],
        api_key: Optional[str] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        key = api_key or getattr(settings, "HUGGINGFACE_API_KEY", None)
        if not key:
            raise HTTPException(400, "HuggingFace API key not configured")

        endpoint = f"https://api-inference.huggingface.co/models/{model}/v1/chat/completions"
        body = {"model": model, "messages": messages, "stream": True}

        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                endpoint,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json=body,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.strip():
                        yield line
