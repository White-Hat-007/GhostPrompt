import os
import json
import httpx
from typing import Optional, Dict, Any, Generator

class GhostPromptError(Exception):
    pass

class GhostPrompt:
    """
    GhostPrompt Python SDK
    Drop-in replacement for OpenAI SDK with built-in prompt firewalling.
    """
    
    def __init__(
        self, 
        api_key: Optional[str] = None, 
        base_url: Optional[str] = None,
        sensitivity: str = "BALANCED",
        provider: str = "openai"
    ):
        self.api_key = api_key or os.environ.get("GHOSTPROMPT_API_KEY")
        self.base_url = base_url or os.environ.get("GHOSTPROMPT_BASE_URL", "https://api.ghostprompt.com/v1")
        self.sensitivity = sensitivity
        self.provider = provider
        
        self.chat = self.Chat(self)

    class Chat:
        def __init__(self, client):
            self.client = client
            self.completions = self.Completions(client)

        class Completions:
            def __init__(self, client):
                self.client = client

            def create(
                self, 
                model: str, 
                messages: list[dict], 
                stream: bool = False, 
                session_id: Optional[str] = None,
                **kwargs
            ) -> Any:
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.client.api_key}",
                    "X-GhostPrompt-Sensitivity": self.client.sensitivity,
                    "X-GhostPrompt-Provider": self.client.provider
                }
                
                if session_id:
                    headers["X-GhostPrompt-Session-Id"] = session_id
                    
                payload = {
                    "model": model,
                    "messages": messages,
                    "stream": stream,
                    **kwargs
                }

                try:
                    response = httpx.post(
                        f"{self.client.base_url}/chat/completions",
                        headers=headers,
                        json=payload,
                        timeout=120.0
                    )
                    
                    response.raise_for_status()
                    
                    if stream:
                        return self._handle_stream(response)
                        
                    return response.json()
                    
                except httpx.HTTPStatusError as e:
                    error_msg = e.response.text
                    try:
                        error_json = e.response.json()
                        error_msg = error_json.get("error", {}).get("message", error_msg)
                    except Exception:
                        pass
                    raise GhostPromptError(f"API Error {e.response.status_code}: {error_msg}")
                except Exception as e:
                    raise GhostPromptError(f"Request failed: {str(e)}")

            def _handle_stream(self, response: httpx.Response) -> Generator[Dict[str, Any], None, None]:
                for line in response.iter_lines():
                    if line.startswith("data: "):
                        data = line[6:]
                        if data == "[DONE]":
                            break
                        try:
                            yield json.loads(data)
                        except json.JSONDecodeError:
                            pass
