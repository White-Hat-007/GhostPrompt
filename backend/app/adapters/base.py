from abc import ABC, abstractmethod
from typing import AsyncGenerator, Optional, Dict, Any

class LLMResponse:
    def __init__(self, content: str, raw_response: Dict[str, Any]):
        self.content = content
        self.raw_response = raw_response

class LLMAdapter(ABC):
    """Abstract base class for all LLM providers."""
    
    @abstractmethod
    async def complete(
        self, 
        model: str,
        messages: list[dict], 
        api_key: Optional[str] = None,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        """Execute a completion request."""
        pass

    @abstractmethod
    async def stream_complete(
        self,
        model: str,
        messages: list[dict],
        api_key: Optional[str] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """Stream a completion response."""
        pass
