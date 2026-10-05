import uuid
from collections.abc import AsyncGenerator

import httpx

from app.adapters.base import LLMAdapter, LLMResponse
from app.core.config import get_settings

settings = get_settings()

class OllamaAdapter(LLMAdapter):
    async def complete(
        self, 
        model: str,
        messages: list[dict], 
        api_key: str | None = None,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        endpoint = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/chat"
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                endpoint,
                json={
                    "model": model,
                    "messages": messages,
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            
            content = data.get("message", {}).get("content", "")
            normalized = {
                "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
                "object": "chat.completion",
                "model": model,
                "choices": [{"index": 0, "message": data.get("message", {}), "finish_reason": "stop"}],
                "usage": {"prompt_tokens": data.get("prompt_eval_count", 0), "completion_tokens": data.get("eval_count", 0)},
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
        endpoint = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/chat"
        stream_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created_time = int(time.time())
        
        async with httpx.AsyncClient(timeout=120.0) as client, client.stream(
            "POST",
            endpoint,
            json={
                "model": model,
                "messages": messages,
                "stream": True,
            },
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.strip():
                    continue
                try:
                    chunk = json.loads(line)
                    content = chunk.get("message", {}).get("content", "")
                    done = chunk.get("done", False)
                    
                    openai_chunk = {
                        "id": stream_id,
                        "object": "chat.completion.chunk",
                        "created": created_time,
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": content} if content else {},
                                "finish_reason": "stop" if done else None
                            }
                        ]
                    }
                    yield f"data: {json.dumps(openai_chunk)}"
                except Exception:
                    pass
            yield "data: [DONE]"
