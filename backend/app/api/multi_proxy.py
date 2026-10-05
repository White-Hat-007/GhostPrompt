"""
Multi-Provider Native Proxy Endpoints

Drop-in replacement endpoints for EVERY major AI provider.
Companies just change their base_url to GhostPrompt and get 
instant AI Firewall protection with zero code changes.

Supported native endpoints:
- POST /v1/chat/completions          → OpenAI (already in proxy.py)
- POST /v1/messages                  → Anthropic Claude
- POST /v1/models/{model}:generateContent → Google Gemini
- POST /api/chat                     → Ollama
- POST /hf/v1/chat/completions       → HuggingFace Inference
- POST /cohere/v2/chat               → Cohere
- POST /groq/v1/chat/completions     → Groq
- POST /together/v1/chat/completions  → Together AI
- POST /deepseek/chat/completions    → DeepSeek
- POST /perplexity/chat/completions  → Perplexity AI
"""

import json
import time
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, Header, Depends
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.events import event_broadcaster
from app.core.session import session_manager
from app.services.firewall.engine import firewall_engine
from app.services.firewall.dlp_vault import dlp_vault
from app.services.firewall.detectors.attacker_profiler import attacker_profiler
from app.services.explainer import explain_scan
from app.schemas.schemas import ScanRequest
from app.adapters import get_adapter, detect_provider, PROVIDER_MODELS
from app.core.database import get_db
from app.models.scan_event import ScanEvent
from app.models.organization import Organization
from app.models.api_key import APIKey

settings = get_settings()
logger = get_logger("multi_proxy")
router = APIRouter(tags=["Multi-Provider Proxy"])


def _extract_text(messages: list[dict]) -> str:
    parts = []
    for msg in messages:
        c = msg.get("content", "")
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, list):
            for item in c:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(item.get("text", ""))
    return "\n".join(parts)


async def _resolve_org(db: AsyncSession, authorization: Optional[str], request: Request):
    """Resolve organization from API key or default."""
    key_obj = None
    api_key = None
    
    if authorization:
        val = authorization.replace("Bearer ", "").strip()
        if val.startswith("gp-sk-"):
            hashed_token = hashlib.sha256(val.encode()).hexdigest()
            result = await db.execute(select(APIKey).where(APIKey.key_hash == hashed_token))
            key_obj = result.scalar_one_or_none()
            if not key_obj or not key_obj.is_active:
                raise HTTPException(401, "Invalid or inactive GhostPrompt API key")
            key_obj.total_requests += 1
            key_obj.last_used_at = datetime.now(timezone.utc)
            key_obj.last_used_ip = request.client.host if request.client else None
            db.add(key_obj)
        elif val.lower() not in ["dummy", "sk-dummy", "your_api_key", "bearer"]:
            api_key = val

    org_result = await db.execute(select(Organization).limit(1))
    default_org = org_result.scalars().first()
    org_id = str(key_obj.organization_id) if key_obj else (str(default_org.id) if default_org else None)
    
    return key_obj, api_key, org_id


async def _scan_and_proxy(
    request: Request,
    db: AsyncSession,
    provider: str,
    model: str,
    messages: list[dict],
    stream: bool,
    body: dict,
    authorization: Optional[str],
    session_id: Optional[str] = None,
):
    """Universal scan-and-proxy pipeline used by ALL provider endpoints."""
    key_obj, api_key, org_id = await _resolve_org(db, authorization, request)

    # ── SCAN INPUT ──
    prompt_text = _extract_text(messages)
    scan_type = "agent" if body.get("tools") or body.get("functions") else "prompt"

    input_scan = await firewall_engine.scan(
        ScanRequest(prompt=prompt_text, model=model, provider=provider, scan_type=scan_type),
        org_id=org_id,
    )

    # ── SESSION RISK ──
    session_risk = 0.0
    if session_id:
        await session_manager.record_turn(session_id, prompt_text, input_scan.threat_score, [d.category for d in input_scan.detections])
        session_risk = await session_manager.get_session_risk(session_id)

    effective_score = max(input_scan.threat_score, session_risk * 0.8)
    is_blocked = input_scan.action == "blocked" or session_risk >= 0.9

    # ── PROFILER ──
    profile = None
    if input_scan.action in ("blocked", "flagged") or is_blocked:
        await attacker_profiler.initialize()
        final_action = "blocked" if is_blocked else input_scan.action
        final_threat_level = "critical" if is_blocked else input_scan.threat_level
        profile = await attacker_profiler.profile_request(request, session_id=session_id, action=final_action, threat_level=final_threat_level, detections=input_scan.detections)

    # ── PERSIST ──
    if org_id:
        scan_event = ScanEvent(
            organization_id=org_id,
            request_id=input_scan.request_id,
            source_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:512],
            model_provider=provider,
            model_name=model,
            scan_type=scan_type,
            prompt_text=prompt_text[:10000],
            prompt_length=len(prompt_text),
            threat_level="critical" if is_blocked else input_scan.threat_level,
            threat_score=effective_score,
            threat_categories=[d.category for d in input_scan.detections],
            detections=[d.model_dump() for d in input_scan.detections],
            scan_duration_ms=input_scan.scan_duration_ms,
            total_latency_ms=input_scan.scan_duration_ms,
            is_blocked=is_blocked,
            event_metadata={"attacker_profile": profile.model_dump()} if profile else {},
        )
        db.add(scan_event)
        await db.commit()

    # ── BLOCK ──
    if is_blocked or input_scan.action == "blocked":
        explanation = explain_scan(input_scan, session_risk=session_risk)
        broadcast_org = str(key_obj.organization_id) if key_obj else org_id
        if broadcast_org:
            await event_broadcaster.broadcast_scan({
                "organization_id": broadcast_org,
                **input_scan.model_dump(),
                "model": model, "provider": provider,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "attacker_profile": profile.model_dump() if profile else None,
            })
        return JSONResponse(
            status_code=403,
            content={"error": {"message": f"Blocked by GhostPrompt AI Firewall: {input_scan.threat_level} threat", "type": "ghostprompt_blocked", "code": "threat_detected", "ghostprompt": explanation}},
            headers={"X-GhostPrompt-Action": "blocked", "X-GhostPrompt-Threat-Level": input_scan.threat_level},
        )

    # ── DLP REDACTION ──
    if input_scan.action == "sanitized" and input_scan.dlp_mappings:
        await dlp_vault.store_mappings(input_scan.request_id, input_scan.dlp_mappings)
        for msg in messages:
            if isinstance(msg.get("content"), str):
                for placeholder, original in input_scan.dlp_mappings.items():
                    msg["content"] = msg["content"].replace(original, placeholder)

    # ── BROADCAST INPUT ──
    broadcast_org = str(key_obj.organization_id) if key_obj else org_id
    if broadcast_org:
        await event_broadcaster.broadcast_scan({
            "organization_id": broadcast_org,
            **input_scan.model_dump(),
            "model": model, "provider": provider,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "attacker_profile": profile.model_dump() if profile else None,
        })

    # ── FORWARD TO LLM ──
    adapter = get_adapter(provider)

    if stream:
        async def stream_gen():
            chunks = []
            try:
                async for line in adapter.stream_complete(model=model, messages=messages, api_key=api_key, **{k: v for k, v in body.items() if k not in ["model", "messages", "stream"]}):
                    if not line.strip():
                        continue
                    yield line + "\n"
                    if line.startswith("data: ") and not line.startswith("data: [DONE]"):
                        try:
                            d = json.loads(line[6:])
                            delta = d.get("choices", [{}])[0].get("delta", {}).get("content", "")
                            if delta:
                                chunks.append(delta)
                        except Exception:
                            pass
            except Exception as e:
                logger.error("stream_error", error=str(e), provider=provider)
                yield f'data: {{"error": {{"message": "Stream error: {str(e)}"}}}}\n\n'
                return

            # Post-stream output scan
            text = "".join(chunks)
            if text:
                try:
                    output_scan = await firewall_engine.scan(ScanRequest(prompt=text, model=model, provider=provider, scan_type="output"), org_id=org_id)
                    if org_id:
                        oe = ScanEvent(organization_id=org_id, request_id=output_scan.request_id, model_provider=provider, model_name=model, scan_type="output", output_text=text[:10000], output_length=len(text), threat_level=output_scan.threat_level, threat_score=output_scan.threat_score, threat_categories=[d.category for d in output_scan.detections], detections=[d.model_dump() for d in output_scan.detections], action=output_scan.action, is_blocked=output_scan.action == "blocked", scan_duration_ms=output_scan.scan_duration_ms)
                        db.add(oe)
                        await db.commit()
                except Exception as e:
                    logger.error("post_stream_scan_error", error=str(e))

        return StreamingResponse(
            stream_gen(), media_type="text/event-stream",
            headers={"X-GhostPrompt-Action": input_scan.action, "X-GhostPrompt-Threat-Level": input_scan.threat_level, "X-GhostPrompt-Request-ID": input_scan.request_id},
        )

    # Non-streaming
    try:
        resp = await adapter.complete(model=model, messages=messages, api_key=api_key, stream=False, **{k: v for k, v in body.items() if k not in ["model", "messages", "stream"]})
        provider_response = resp.raw_response
    except Exception as e:
        logger.warning("provider_failed", provider=provider, error=str(e))
        return JSONResponse(status_code=502, content={"error": {"message": f"Provider error: {str(e)}", "type": "provider_error"}})

    # ── OUTPUT SCAN ──
    output_text = ""
    try:
        choices = provider_response.get("choices", [])
        if choices:
            output_text = choices[0].get("message", {}).get("content", "")
    except Exception:
        pass

    output_headers = {}
    if output_text:
        output_scan = await firewall_engine.scan(ScanRequest(prompt=output_text, model=model, provider=provider, scan_type="output"), org_id=org_id)
        output_headers["X-GhostPrompt-Output-Threat"] = output_scan.threat_level
        output_headers["X-GhostPrompt-Output-Score"] = str(output_scan.threat_score)

        if org_id:
            oe = ScanEvent(organization_id=org_id, request_id=output_scan.request_id, model_provider=provider, model_name=model, scan_type="output", output_text=output_text[:10000], output_length=len(output_text), threat_level=output_scan.threat_level, threat_score=output_scan.threat_score, threat_categories=[d.category for d in output_scan.detections], detections=[d.model_dump() for d in output_scan.detections], action=output_scan.action, is_blocked=output_scan.action == "blocked", scan_duration_ms=output_scan.scan_duration_ms)
            db.add(oe)
            await db.commit()

        if output_scan.action == "blocked":
            for det in output_scan.detections:
                if det.matched_content and det.matched_content in output_text:
                    output_text = output_text.replace(det.matched_content, "[REDACTED]")
            provider_response["choices"][0]["message"]["content"] = output_text

    # DLP Unredaction
    if input_scan.action == "sanitized" and input_scan.dlp_mappings:
        mappings = await dlp_vault.retrieve_mappings(input_scan.request_id)
        if mappings and "choices" in provider_response and provider_response["choices"]:
            final = provider_response["choices"][0].get("message", {}).get("content", "")
            for placeholder, original in mappings.items():
                final = final.replace(placeholder, original)
            provider_response["choices"][0]["message"]["content"] = final

    return JSONResponse(
        content=provider_response,
        headers={"X-GhostPrompt-Action": input_scan.action, "X-GhostPrompt-Threat-Level": input_scan.threat_level, "X-GhostPrompt-Request-ID": input_scan.request_id, **output_headers},
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ANTHROPIC-NATIVE: POST /v1/messages
# Usage: client = anthropic.Anthropic(base_url="http://ghostprompt/")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/v1/messages")
async def anthropic_native_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """Anthropic-native proxy — drop-in for Anthropic SDK."""
    body = await request.json()
    model = body.get("model", "claude-sonnet-4-20250514")
    
    # Convert Anthropic messages to OpenAI format for scanning
    messages = []
    if body.get("system"):
        messages.append({"role": "system", "content": body["system"]})
    for msg in body.get("messages", []):
        messages.append(msg)

    # Use x-api-key header (Anthropic convention) if no Bearer auth
    auth = authorization or (f"Bearer {x_api_key}" if x_api_key else None)
    
    return await _scan_and_proxy(request, db, "anthropic", model, messages, body.get("stream", False), body, auth, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GOOGLE GEMINI: POST /v1/models/{model}:generateContent
# Usage: genai.configure(api_key="...", transport="rest", client_options={"api_endpoint": "http://ghostprompt"})
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/v1/models/{model}:generateContent")
async def gemini_native_proxy(
    model: str,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """Gemini-native proxy — drop-in for Google AI SDK."""
    body = await request.json()
    
    # Convert Gemini format to OpenAI messages
    messages = []
    contents = body.get("contents", [])
    for content in contents:
        role = content.get("role", "user")
        if role == "model":
            role = "assistant"
        parts = content.get("parts", [])
        text = " ".join(p.get("text", "") for p in parts if "text" in p)
        if text:
            messages.append({"role": role, "content": text})
    
    if body.get("systemInstruction"):
        parts = body["systemInstruction"].get("parts", [])
        sys_text = " ".join(p.get("text", "") for p in parts if "text" in p)
        if sys_text:
            messages.insert(0, {"role": "system", "content": sys_text})

    return await _scan_and_proxy(request, db, "google", model, messages, False, body, authorization, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OLLAMA: POST /api/chat
# Usage: ollama.Client(host="http://ghostprompt")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/api/chat")
async def ollama_native_proxy(
    request: Request,
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """Ollama-native proxy — drop-in for Ollama SDK."""
    body = await request.json()
    model = body.get("model", "llama3.2")
    messages = body.get("messages", [])
    stream = body.get("stream", False)

    return await _scan_and_proxy(request, db, "ollama", model, messages, stream, body, None, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HUGGING FACE: POST /hf/v1/chat/completions
# Usage: openai.OpenAI(base_url="http://ghostprompt/hf")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/hf/v1/chat/completions")
async def huggingface_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """HuggingFace Inference proxy — drop-in for HF Inference API."""
    body = await request.json()
    model = body.get("model", "meta-llama/Llama-3.1-8B-Instruct")
    messages = body.get("messages", [])

    return await _scan_and_proxy(request, db, "huggingface", model, messages, body.get("stream", False), body, authorization, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# COHERE: POST /cohere/v2/chat
# Usage: cohere.ClientV2(base_url="http://ghostprompt/cohere")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/cohere/v2/chat")
async def cohere_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """Cohere-native proxy — drop-in for Cohere SDK."""
    body = await request.json()
    model = body.get("model", "command-r-plus")
    messages = body.get("messages", [])

    return await _scan_and_proxy(request, db, "cohere", model, messages, body.get("stream", False), body, authorization, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GROQ: POST /groq/v1/chat/completions
# Usage: openai.OpenAI(base_url="http://ghostprompt/groq")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/groq/v1/chat/completions")
async def groq_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """Groq proxy — ultra-fast inference with firewall scanning."""
    body = await request.json()
    model = body.get("model", "llama-3.3-70b-versatile")
    messages = body.get("messages", [])

    return await _scan_and_proxy(request, db, "groq", model, messages, body.get("stream", False), body, authorization, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TOGETHER AI: POST /together/v1/chat/completions
# Usage: openai.OpenAI(base_url="http://ghostprompt/together")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/together/v1/chat/completions")
async def together_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """Together AI proxy — open-source models with firewall scanning."""
    body = await request.json()
    model = body.get("model", "meta-llama/Llama-3.3-70B-Instruct-Turbo")
    messages = body.get("messages", [])

    return await _scan_and_proxy(request, db, "together", model, messages, body.get("stream", False), body, authorization, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DEEPSEEK: POST /deepseek/chat/completions
# Usage: openai.OpenAI(base_url="http://ghostprompt/deepseek")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/deepseek/chat/completions")
async def deepseek_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """DeepSeek proxy — reasoning models with firewall scanning."""
    body = await request.json()
    model = body.get("model", "deepseek-chat")
    messages = body.get("messages", [])

    return await _scan_and_proxy(request, db, "deepseek", model, messages, body.get("stream", False), body, authorization, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PERPLEXITY: POST /perplexity/chat/completions
# Usage: openai.OpenAI(base_url="http://ghostprompt/perplexity")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/perplexity/chat/completions")
async def perplexity_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """Perplexity AI proxy — search-grounded inference with firewall."""
    body = await request.json()
    model = body.get("model", "sonar-pro")
    messages = body.get("messages", [])

    return await _scan_and_proxy(request, db, "perplexity", model, messages, body.get("stream", False), body, authorization, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# UNIVERSAL ENDPOINT: POST /v1/universal/chat
# Auto-detects provider from model name
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/v1/universal/chat")
async def universal_chat(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """
    Universal AI Gateway — auto-detects provider from model name.
    
    Send ANY model to this single endpoint and GhostPrompt routes it
    to the correct provider while scanning through the AI Firewall.
    """
    body = await request.json()
    model = body.get("model", "gpt-4o")
    messages = body.get("messages", [])
    provider = body.get("provider") or detect_provider(model)

    return await _scan_and_proxy(request, db, provider, model, messages, body.get("stream", False), body, authorization, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# XAI (GROK): POST /xai/v1/chat/completions
# Usage: openai.OpenAI(base_url="http://ghostprompt/xai")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/xai/v1/chat/completions")
async def xai_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """xAI (Grok) proxy — Grok models with firewall scanning."""
    body = await request.json()
    model = body.get("model", "grok-2")
    messages = body.get("messages", [])

    return await _scan_and_proxy(request, db, "xai", model, messages, body.get("stream", False), body, authorization, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MISTRAL: POST /mistral/v1/chat/completions
# Usage: openai.OpenAI(base_url="http://ghostprompt/mistral")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.post("/mistral/v1/chat/completions")
async def mistral_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """Mistral AI proxy — Mistral models with firewall scanning."""
    body = await request.json()
    model = body.get("model", "mistral-large-latest")
    messages = body.get("messages", [])

    return await _scan_and_proxy(request, db, "mistral", model, messages, body.get("stream", False), body, authorization, x_ghostprompt_session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROVIDER CATALOG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@router.get("/v1/providers")
async def list_all_providers():
    """List all supported providers with their models and configuration status."""
    catalog = []
    for key, info in PROVIDER_MODELS.items():
        # Check if the provider has a key configured
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
            "ollama": True,  # Always available (local)
        }
        catalog.append({
            "id": key,
            "display_name": info["display_name"],
            "models": info["models"],
            "docs": info["docs"],
            "configured": bool(key_map.get(key)),
        })
    return {"providers": catalog, "total": len(catalog)}

