from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from typing import Any


class LLMResponse:
    def __init__(self, content: str, raw_response: dict[str, Any]):
        self.content = content
        self.raw_response = raw_response

class LLMAdapter(ABC):
    """Abstract base class for all LLM providers."""
    
    @abstractmethod
    async def complete(
        self, 
        model: str,
        messages: list[dict], 
        api_key: str | None = None,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        """Execute a completion request."""

    @abstractmethod
    async def stream_complete(
        self,
        model: str,
        messages: list[dict],
        api_key: str | None = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """Stream a completion response."""
