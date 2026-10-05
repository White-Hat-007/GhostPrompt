"""
OpenAI-Compatible Middleware

Drop-in middleware that wraps OpenAI's Python SDK to automatically
scan all prompts and outputs through GhostPrompt.

Usage:
    from ghostprompt.middleware.openai import protect_openai
    import openai

    client = openai.OpenAI()
    protect_openai(client, api_key="gp_live_...")

    # All calls are now automatically scanned
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )
"""

from typing import Any, Optional
import functools
from ghostprompt import GhostPrompt, ScanBlockedError


def protect_openai(
    client: Any,
    api_key: str,
    base_url: Optional[str] = None,
    scan_output: bool = True,
    auto_block: bool = True,
) -> None:
    """
    Monkey-patch an OpenAI client to scan all chat completions.

    Args:
        client: OpenAI client instance
        api_key: GhostPrompt API key
        base_url: GhostPrompt API URL (for self-hosted)
        scan_output: Whether to scan model outputs
        auto_block: Whether to block detected threats
    """
    gp = GhostPrompt(
        api_key=api_key,
        base_url=base_url,
        auto_block=auto_block,
    )

    original_create = client.chat.completions.create

    @functools.wraps(original_create)
    def protected_create(*args, **kwargs):
        messages = kwargs.get("messages", args[0] if args else [])
        model = kwargs.get("model", "unknown")

        # Scan all user messages
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") in ("user", "system"):
                content = msg.get("content", "")
                if isinstance(content, str) and content.strip():
                    gp.scan(content, model=model)

        # Call original
        response = original_create(*args, **kwargs)

        # Scan output
        if scan_output and hasattr(response, "choices"):
            for choice in response.choices:
                if hasattr(choice, "message") and hasattr(choice.message, "content"):
                    output = choice.message.content
                    if output:
                        try:
                            gp.scan_output(output, model=model)
                        except ScanBlockedError:
                            # Replace blocked output
                            choice.message.content = (
                                "[BLOCKED BY GHOSTPROMPT] "
                                "This response was blocked due to security policy."
                            )

        return response

    client.chat.completions.create = protected_create


def protect_langchain(
    api_key: str,
    base_url: Optional[str] = None,
    auto_block: bool = True,
):
    """
    LangChain callback handler for GhostPrompt integration.

    Usage:
        from langchain.callbacks import CallbackManager
        from ghostprompt.middleware.openai import protect_langchain

        handler = protect_langchain(api_key="gp_live_...")
        llm = ChatOpenAI(callbacks=[handler])
    """
    from langchain_core.callbacks import BaseCallbackHandler

    gp = GhostPrompt(api_key=api_key, base_url=base_url, auto_block=auto_block)

    class GhostPromptCallback(BaseCallbackHandler):
        def on_llm_start(self, serialized, prompts, **kwargs):
            for prompt in prompts:
                gp.scan(prompt)

        def on_llm_end(self, response, **kwargs):
            for gen_list in response.generations:
                for gen in gen_list:
                    if gen.text:
                        gp.scan_output(gen.text)

    return GhostPromptCallback()
