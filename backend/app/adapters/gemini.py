import httpx
import uuid
from typing import AsyncGenerator, Optional
from fastapi import HTTPException
from app.adapters.base import LLMAdapter, LLMResponse
from app.core.config import get_settings

settings = get_settings()

class GeminiAdapter(LLMAdapter):
    ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    async def complete(
        self, 
        model: str,
        messages: list[dict], 
        api_key: Optional[str] = None,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        key = api_key or settings.GOOGLE_AI_API_KEY
        if not key:
            raise HTTPException(400, "Google AI API key not configured")

        # Convert OpenAI messages to Gemini contents
        contents = []
        for msg in messages:
            role = msg.get("role")
            if role == "system":
                # Basic mapping for now
                contents.append({"role": "user", "parts": [{"text": "System instructions: " + msg.get("content", "")}]})
            else:
                gemini_role = "model" if role == "assistant" else "user"
                contents.append({"role": gemini_role, "parts": [{"text": msg.get("content", "")}]})

        endpoint = f"{self.ENDPOINT.format(model=model)}?key={key}"
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                endpoint,
                headers={"Content-Type": "application/json"},
                json={"contents": contents},
            )
            resp.raise_for_status()
            data = resp.json()
            
            content = ""
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    content = parts[0].get("text", "")
            
            normalized = {
                "id": str(uuid.uuid4()),
                "object": "chat.completion",
                "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            }
            return LLMResponse(content=content, raw_response=normalized)

    async def stream_complete(
        self,
        model: str,
        messages: list[dict],
        api_key: Optional[str] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        import json
        import time
        key = api_key or settings.GOOGLE_AI_API_KEY
        if not key:
            raise HTTPException(400, "Google AI API key not configured")

        contents = []
        for msg in messages:
            role = msg.get("role")
            if role == "system":
                contents.append({"role": "user", "parts": [{"text": "System instructions: " + msg.get("content", "")}]})
            else:
                gemini_role = "model" if role == "assistant" else "user"
                contents.append({"role": gemini_role, "parts": [{"text": msg.get("content", "")}]})

        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent?key={key}"
        stream_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created_time = int(time.time())

        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                endpoint,
                headers={"Content-Type": "application/json"},
                json={"contents": contents},
            ) as response:
                response.raise_for_status()
                buffer = ""
                async for text_chunk in response.aiter_text():
                    buffer += text_chunk
                    while True:
                        buffer = buffer.strip()
                        if buffer.startswith("["):
                            buffer = buffer[1:].strip()
                        if buffer.startswith(","):
                            buffer = buffer[1:].strip()
                            
                        if not buffer.startswith("{"):
                            break
                            
                        bracket_count = 0
                        in_string = False
                        escape = False
                        end_idx = -1
                        
                        for i, char in enumerate(buffer):
                            if escape:
                                escape = False
                                continue
                            if char == "\\":
                                escape = True
                                continue
                            if char == '"':
                                in_string = not in_string
                                continue
                            if not in_string:
                                if char == "{":
                                    bracket_count += 1
                                elif char == "}":
                                    bracket_count -= 1
                                    if bracket_count == 0:
                                        end_idx = i
                                        break
                                        
                        if end_idx == -1:
                            break
                            
                        obj_str = buffer[:end_idx+1]
                        buffer = buffer[end_idx+1:].strip()
                        
                        try:
                            data = json.loads(obj_str)
                            candidates = data.get("candidates", [])
                            content = ""
                            if candidates:
                                parts = candidates[0].get("content", {}).get("parts", [])
                                if parts:
                                    content = parts[0].get("text", "")
                                    
                            openai_chunk = {
                                "id": stream_id,
                                "object": "chat.completion.chunk",
                                "created": created_time,
                                "model": model,
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {"content": content} if content else {},
                                        "finish_reason": None
                                    }
                                ]
                            }
                            yield f"data: {json.dumps(openai_chunk)}"
                        except Exception:
                            pass
                yield "data: [DONE]"
