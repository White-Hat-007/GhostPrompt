"""
AI Gateway Routes

Unified AI gateway proxy that routes requests to multiple model providers
while applying firewall scanning on both input and output.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
import httpx
import uuid
import time

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.config import get_settings
from app.core.permissions import require_permission
from app.services.firewall.engine import firewall_engine
from app.schemas.schemas import GatewayRequest, GatewayResponse, ScanRequest

settings = get_settings()
router = APIRouter(
    prefix="/gateway",
    tags=["AI Gateway"],
    dependencies=[Depends(require_permission("scan.execute"))],
)

# Provider endpoint mapping
PROVIDER_ENDPOINTS = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
    "google": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
    "ollama": "{base_url}/api/chat",
}


@router.post("/chat", response_model=GatewayResponse)
async def gateway_chat(
    request: GatewayRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Send a chat request through the AI Gateway.

    The gateway:
    1. Scans the input prompt through the firewall
    2. Routes to the appropriate AI provider
    3. Scans the output through the firewall
    4. Returns the response with security metadata
    """
    request_id = str(uuid.uuid4())
    provider = request.provider or _detect_provider(request.model)

    # Step 1: Scan input
    prompt_text = _extract_prompt_text(request.messages)
    input_scan = await firewall_engine.scan(
        ScanRequest(
            prompt=prompt_text,
            model=request.model,
            provider=provider,
            scan_type="prompt",
        ),
        org_id=current_user.get("org_id"),
    )

    if input_scan.action == "blocked":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Request blocked by AI Firewall",
                "threat_level": input_scan.threat_level,
                "threat_score": input_scan.threat_score,
                "detections": [d.model_dump() for d in input_scan.detections],
                "request_id": input_scan.request_id,
            },
        )

    # Step 2: Route to provider
    start_time = time.perf_counter()
    try:
        provider_response = await _call_provider(provider, request)
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Error communicating with AI provider: {str(e)}",
        )
    latency_ms = (time.perf_counter() - start_time) * 1000

    # Step 3: Scan output
    output_text = _extract_output_text(provider_response, provider)
    output_scan = None
    if output_text:
        output_scan = await firewall_engine.scan(
            ScanRequest(
                prompt=output_text,
                model=request.model,
                provider=provider,
                scan_type="output",
            ),
            org_id=current_user.get("org_id"),
        )

    return GatewayResponse(
        id=request_id,
        model=request.model,
        provider=provider,
        choices=provider_response.get("choices", []),
        usage=provider_response.get("usage", {}),
        scan_result=input_scan,
        output_scan_result=output_scan,
    )


@router.get("/models")
async def list_supported_models(
    current_user: dict = Depends(get_current_user),
):
    """List all supported AI models and providers (11 providers, 50+ models)."""
    from app.adapters import PROVIDER_MODELS
    providers = []
    key_map = {
        "openai": settings.OPENAI_API_KEY,
        "anthropic": settings.ANTHROPIC_API_KEY,
        "google": settings.GOOGLE_AI_API_KEY,
        "mistral": getattr(settings, "MISTRAL_API_KEY", None),
        "cohere": getattr(settings, "COHERE_API_KEY", None),
        "groq": getattr(settings, "GROQ_API_KEY", None),
        "together": getattr(settings, "TOGETHER_API_KEY", None),
        "deepseek": getattr(settings, "DEEPSEEK_API_KEY", None),
        "perplexity": getattr(settings, "PERPLEXITY_API_KEY", None),
        "huggingface": getattr(settings, "HUGGINGFACE_API_KEY", None),
        "xai": getattr(settings, "XAI_API_KEY", None),
        "ollama": True,
    }
    for key, info in PROVIDER_MODELS.items():
        providers.append({
            "name": key,
            "display_name": info["display_name"],
            "models": info["models"],
            "configured": bool(key_map.get(key)),
            "docs": info["docs"],
        })
    return {"providers": providers, "total_providers": len(providers)}


def _detect_provider(model: str) -> str:
    """Auto-detect the provider from the model name."""
    model_lower = model.lower()
    if model_lower.startswith(("gpt", "o1", "o3", "o4")):
        return "openai"
    elif model_lower.startswith("claude"):
        return "anthropic"
    elif model_lower.startswith(("gemini", "gemma")):
        return "google"
    elif model_lower.startswith(("mistral", "mixtral", "codestral", "pixtral")):
        return "mistral"
    elif model_lower.startswith("command"):
        return "cohere"
    elif model_lower.startswith("llama"):
        return "groq"
    elif model_lower.startswith("deepseek"):
        return "deepseek"
    elif model_lower.startswith(("sonar", "pplx")):
        return "perplexity"
    elif model_lower.startswith("grok"):
        return "xai"
    else:
        return "ollama"


def _extract_prompt_text(messages: list[dict]) -> str:
    """Extract all text from message list for scanning."""
    parts = []
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(item.get("text", ""))
    return "\n".join(parts)


def _extract_output_text(response: dict, provider: str) -> str:
    """Extract output text from provider response."""
    try:
        if provider in ("openai", "ollama"):
            choices = response.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
        elif provider == "anthropic":
            content = response.get("content", [])
            if content:
                return content[0].get("text", "")
        elif provider == "google":
            candidates = response.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
    except (IndexError, KeyError, TypeError):
        pass
    return ""


async def _call_provider(provider: str, request: GatewayRequest) -> dict:
    """Route request to the appropriate AI provider."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        if provider == "openai":
            if not settings.OPENAI_API_KEY:
                raise HTTPException(400, "OpenAI API key not configured")
            response = await client.post(
                PROVIDER_ENDPOINTS["openai"],
                headers={
                    "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": request.model,
                    "messages": request.messages,
                    "temperature": request.temperature or 0.7,
                    "max_tokens": request.max_tokens or 4096,
                },
            )
            response.raise_for_status()
            return response.json()

        elif provider == "anthropic":
            if not settings.ANTHROPIC_API_KEY:
                raise HTTPException(400, "Anthropic API key not configured")
            # Convert messages to Anthropic format
            system_msg = ""
            user_messages = []
            for msg in request.messages:
                if msg.get("role") == "system":
                    system_msg = msg.get("content", "")
                else:
                    user_messages.append(msg)

            body = {
                "model": request.model,
                "messages": user_messages,
                "max_tokens": request.max_tokens or 4096,
            }
            if system_msg:
                body["system"] = system_msg

            response = await client.post(
                PROVIDER_ENDPOINTS["anthropic"],
                headers={
                    "x-api-key": settings.ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=body,
            )
            response.raise_for_status()
            return response.json()

        elif provider == "ollama":
            endpoint = PROVIDER_ENDPOINTS["ollama"].format(
                base_url=settings.OLLAMA_BASE_URL
            )
            response = await client.post(
                endpoint,
                json={
                    "model": request.model,
                    "messages": request.messages,
                    "stream": False,
                },
            )
            response.raise_for_status()
            data = response.json()
            # Normalize to OpenAI format
            return {
                "choices": [
                    {"message": data.get("message", {}), "index": 0}
                ],
                "usage": {
                    "prompt_tokens": data.get("prompt_eval_count", 0),
                    "completion_tokens": data.get("eval_count", 0),
                },
            }

        else:
            raise HTTPException(400, f"Unsupported provider: {provider}")
