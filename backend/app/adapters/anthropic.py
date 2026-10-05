import uuid
from collections.abc import AsyncGenerator

import httpx
from fastapi import HTTPException

from app.adapters.base import LLMAdapter, LLMResponse
from app.core.config import get_settings

settings = get_settings()

class AnthropicAdapter(LLMAdapter):
    ENDPOINT = "https://api.anthropic.com/v1/messages"

    async def complete(
        self, 
        model: str,
        messages: list[dict], 
        api_key: str | None = None,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        key = api_key or settings.ANTHROPIC_API_KEY
        if not key:
            raise HTTPException(400, "Anthropic API key not configured")

        system_msg = ""
        user_messages = []
        for msg in messages:
            if msg.get("role") == "system":
                system_msg = msg.get("content", "")
            else:
                user_messages.append(msg)

        body = {
            "model": model,
            "messages": user_messages,
            "max_tokens": kwargs.get("max_tokens", 4096),
        }
        if system_msg:
            body["system"] = system_msg

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                self.ENDPOINT,
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()
            
            content = ""
            for block in data.get("content", []):
                if block.get("type") == "text":
                    content += block.get("text", "")
            
            # Normalize to OpenAI format for internal consistency
            normalized = {
                "id": data.get("id", str(uuid.uuid4())),
                "object": "chat.completion",
                "model": data.get("model"),
                "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": data.get("stop_reason", "stop")}],
                "usage": {
                    "prompt_tokens": data.get("usage", {}).get("input_tokens", 0),
                    "completion_tokens": data.get("usage", {}).get("output_tokens", 0),
                    "total_tokens": data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0),
                },
            }
            return LLMResponse(content=content, raw_response=normalized)

    async def stream_complete(
        self,
        model: str,
        messages: list[dict],
        api_key: str | None = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        import json
        import time
        key = api_key or settings.ANTHROPIC_API_KEY
        if not key:
            raise HTTPException(400, "Anthropic API key not configured")

        system_msg = ""
        user_messages = []
        for msg in messages:
            if msg.get("role") == "system":
                system_msg = msg.get("content", "")
            else:
                user_messages.append(msg)

        body = {
            "model": model,
            "messages": user_messages,
            "max_tokens": kwargs.get("max_tokens", 4096),
            "stream": True,
        }
        if system_msg:
            body["system"] = system_msg

        stream_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created_time = int(time.time())

        async with httpx.AsyncClient(timeout=120.0) as client, client.stream(
            "POST",
            self.ENDPOINT,
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json=body,
        ) as response:
            response.raise_for_status()
            current_event = None
            async for line in response.aiter_lines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("event:"):
                    current_event = line[6:].strip()
                elif line.startswith("data:"):
                    data_str = line[5:].strip()
                    if current_event == "content_block_delta":
                        try:
                            data = json.loads(data_str)
                            text = data.get("delta", {}).get("text", "")
                            
                            openai_chunk = {
                                "id": stream_id,
                                "object": "chat.completion.chunk",
                                "created": created_time,
                                "model": model,
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {"content": text} if text else {},
                                        "finish_reason": None
                                    }
                                ]
                            }
                            yield f"data: {json.dumps(openai_chunk)}"
                        except Exception:
                            pass
            yield "data: [DONE]"
