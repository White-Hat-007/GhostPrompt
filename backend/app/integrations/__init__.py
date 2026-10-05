"""
GhostPrompt Agent Framework Integrations

Drop-in LLM clients for LangChain, LlamaIndex, CrewAI, AutoGen, Haystack, OpenAI Agents SDK.
Each integration routes through GhostPrompt's security, routing, caching, and observability.
"""


class GhostPromptBaseLLM:
    """Base class for all framework integrations."""

    def __init__(self, api_key: str, base_url: str = "http://localhost:8000",
                 model: str = "gpt-4o", **kwargs):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.extra_params = kwargs

    def _get_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-GhostPrompt-Client": "sdk",
        }

    def _get_endpoint(self) -> str:
        return f"{self.base_url}/v1/chat/completions"


# ── LangChain Integration ──
class GhostPromptLangChainLLM(GhostPromptBaseLLM):
    """Drop-in replacement for LangChain's ChatOpenAI.

    Usage:
        from ghostprompt.integrations import GhostPromptLangChainLLM
        llm = GhostPromptLangChainLLM(api_key="gp_vk_...", model="gpt-4o")
        # Use exactly like ChatOpenAI
    """

    @property
    def _llm_type(self) -> str:
        return "ghostprompt"

    def _generate(self, messages: list, **kwargs) -> dict:
        import requests
        payload = {"model": self.model, "messages": messages, **kwargs}
        resp = requests.post(self._get_endpoint(), json=payload, headers=self._get_headers())
        return resp.json()

    async def _agenerate(self, messages: list, **kwargs) -> dict:
        import aiohttp
        payload = {"model": self.model, "messages": messages, **kwargs}
        async with aiohttp.ClientSession() as session:
            async with session.post(self._get_endpoint(), json=payload, headers=self._get_headers()) as resp:
                return await resp.json()


# ── LlamaIndex Integration ──
class GhostPromptLlamaIndexLLM(GhostPromptBaseLLM):
    """Drop-in replacement for LlamaIndex's OpenAI LLM.

    Usage:
        from ghostprompt.integrations import GhostPromptLlamaIndexLLM
        llm = GhostPromptLlamaIndexLLM(api_key="gp_vk_...", model="gpt-4o")
    """

    def complete(self, prompt: str, **kwargs) -> dict:
        import requests
        payload = {"model": self.model, "messages": [{"role": "user", "content": prompt}], **kwargs}
        resp = requests.post(self._get_endpoint(), json=payload, headers=self._get_headers())
        return resp.json()

    def chat(self, messages: list, **kwargs) -> dict:
        import requests
        payload = {"model": self.model, "messages": messages, **kwargs}
        resp = requests.post(self._get_endpoint(), json=payload, headers=self._get_headers())
        return resp.json()


# ── CrewAI Integration ──
class GhostPromptCrewAILLM(GhostPromptBaseLLM):
    """Drop-in for CrewAI's LLM configuration.

    Usage:
        from ghostprompt.integrations import GhostPromptCrewAILLM
        llm = GhostPromptCrewAILLM(api_key="gp_vk_...", model="gpt-4o")
    """

    def call(self, prompt: str, **kwargs) -> str:
        import requests
        payload = {"model": self.model, "messages": [{"role": "user", "content": prompt}]}
        resp = requests.post(self._get_endpoint(), json=payload, headers=self._get_headers())
        data = resp.json()
        choices = data.get("choices", [])
        return choices[0]["message"]["content"] if choices else ""


# ── AutoGen Integration ──
class GhostPromptAutoGenConfig:
    """AutoGen model configuration pointing to GhostPrompt.

    Usage:
        from ghostprompt.integrations import GhostPromptAutoGenConfig
        config = GhostPromptAutoGenConfig(api_key="gp_vk_...").to_config_list()
    """

    def __init__(self, api_key: str, base_url: str = "http://localhost:8000",
                 models: list = None):
        self.api_key = api_key
        self.base_url = base_url
        self.models = models or ["gpt-4o"]

    def to_config_list(self) -> list[dict]:
        return [
            {"model": m, "api_key": self.api_key, "base_url": f"{self.base_url}/v1"}
            for m in self.models
        ]


# ── Haystack Integration ──
class GhostPromptHaystackComponent(GhostPromptBaseLLM):
    """Haystack pipeline component.

    Usage:
        from ghostprompt.integrations import GhostPromptHaystackComponent
        llm = GhostPromptHaystackComponent(api_key="gp_vk_...", model="gpt-4o")
    """

    def run(self, prompt: str, **kwargs) -> dict:
        import requests
        payload = {"model": self.model, "messages": [{"role": "user", "content": prompt}]}
        resp = requests.post(self._get_endpoint(), json=payload, headers=self._get_headers())
        data = resp.json()
        choices = data.get("choices", [])
        content = choices[0]["message"]["content"] if choices else ""
        return {"replies": [content], "metadata": data.get("usage", {})}


# ── OpenAI Agents SDK Integration ──
class GhostPromptOpenAIAgentsClient(GhostPromptBaseLLM):
    """OpenAI Agents SDK integration.

    Usage:
        from ghostprompt.integrations import GhostPromptOpenAIAgentsClient
        client = GhostPromptOpenAIAgentsClient(api_key="gp_vk_...")
        # Use client.chat.completions.create() as normal
    """

    class _Chat:
        class _Completions:
            def __init__(self, parent):
                self._parent = parent

            def create(self, model: str = None, messages: list = None, **kwargs) -> dict:
                import requests
                payload = {"model": model or self._parent.model, "messages": messages or [], **kwargs}
                resp = requests.post(self._parent._get_endpoint(), json=payload, headers=self._parent._get_headers())
                return resp.json()

        def __init__(self, parent):
            self.completions = self._Completions(parent)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chat = self._Chat(self)


INTEGRATION_INFO = {
    "langchain": {"class": "GhostPromptLangChainLLM", "description": "Drop-in for ChatOpenAI"},
    "llamaindex": {"class": "GhostPromptLlamaIndexLLM", "description": "Drop-in for LlamaIndex LLM"},
    "crewai": {"class": "GhostPromptCrewAILLM", "description": "Drop-in for CrewAI LLM"},
    "autogen": {"class": "GhostPromptAutoGenConfig", "description": "AutoGen config list generator"},
    "haystack": {"class": "GhostPromptHaystackComponent", "description": "Haystack pipeline component"},
    "openai_agents": {"class": "GhostPromptOpenAIAgentsClient", "description": "OpenAI Agents SDK client"},
}
