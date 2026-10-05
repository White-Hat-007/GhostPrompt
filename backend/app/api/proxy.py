"""
OpenAI-Compatible Proxy Endpoint

The core product feature: a drop-in replacement for the OpenAI API.
Companies just change base_url from api.openai.com to their GhostPrompt instance.
Zero code changes needed. GhostPrompt transparently scans input, forwards to the 
real LLM, scans output, and returns the response.

Usage:
    # Before (direct OpenAI):
    client = OpenAI(api_key="sk-...")
    
    # After (through GhostPrompt):
    client = OpenAI(
        api_key="sk-...",
        base_url="http://ghostprompt.company.com/v1"
    )
    # That's it. Zero other changes.
"""

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, Header, Depends
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.events import event_broadcaster
from app.core.session import session_manager
from app.services.firewall.engine import firewall_engine
from app.services.firewall.dlp_vault import dlp_vault
from app.services.firewall.detectors.attacker_profiler import attacker_profiler
from app.services.explainer import explain_scan
from app.schemas.schemas import ScanRequest
from app.adapters import get_adapter
from app.core.database import get_db
from app.models.scan_event import ScanEvent
from app.models.organization import Organization
from app.models.api_key import APIKey
import hashlib

settings = get_settings()
logger = get_logger("proxy")
router = APIRouter(tags=["OpenAI-Compatible Proxy"])


# Provider routing
PROVIDER_ENDPOINTS = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
    "ollama": "{base_url}/api/chat",
}

PROVIDER_KEYS = {
    "openai": lambda: settings.OPENAI_API_KEY,
    "anthropic": lambda: settings.ANTHROPIC_API_KEY,
    "google": lambda: settings.GOOGLE_AI_API_KEY,
}


def _detect_provider(model: str) -> str:
    m = model.lower()
    if m.startswith(("gpt", "o1", "o3", "o4")):
        return "openai"
    if m.startswith("claude"):
        return "anthropic"
    if m.startswith("gemini"):
        return "google"
    return "ollama"


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


from app.core.rate_limit import limiter

@router.post("/v1/chat/completions")
@limiter.limit("500/minute")
async def openai_compatible_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_ghostprompt_session: Optional[str] = Header(None, alias="X-GhostPrompt-Session"),
    db: AsyncSession = Depends(get_db),
):
    """
    OpenAI-compatible chat completions endpoint.
    
    Drop-in replacement: just change base_url to your GhostPrompt instance.
    GhostPrompt transparently:
    1. Scans the input through the AI Firewall (7 detectors)
    2. Checks multi-turn session context for slow-build attacks
    3. Forwards clean requests to the real LLM
    4. Scans the output for PII, secrets, policy violations
    5. Returns the response with security headers
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON request body")
    
    model = body.get("model", "gpt-4o")
    messages = body.get("messages", [])
    stream = body.get("stream", False)
    tools = body.get("tools") or body.get("functions")
    provider = _detect_provider(model)
    session_id = x_ghostprompt_session or request.headers.get("X-Session-ID")
    
    # Extract API key from Authorization header (pass-through to provider)
    api_key = None
    key_obj = None
    if authorization:
        val = authorization.replace("Bearer ", "").strip()
        if val.startswith("gp-sk-"):
            hashed_token = hashlib.sha256(val.encode()).hexdigest()
            result = await db.execute(
                select(APIKey).where(APIKey.key_hash == hashed_token)
            )
            key_obj = result.scalar_one_or_none()
            if not key_obj or not key_obj.is_active:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or inactive GhostPrompt API key",
                )
            
            # Increment request counter and update metadata
            key_obj.total_requests += 1
            key_obj.last_used_at = datetime.now(timezone.utc)
            key_obj.last_used_ip = request.client.host if request.client else None
            db.add(key_obj)
            
            # Use default backend keys configured in the environment,
            # so the adapter will use settings.OPENAI_API_KEY / settings.ANTHROPIC_API_KEY
            api_key = None
        elif val.lower() not in ["dummy", "sk-dummy", "your_openai_key", "your_api_key", "bearer"]:
            api_key = val
    
    # ── STEP 1: Scan Input ──────────────────────────────────────
    prompt_text = _extract_text(messages)
    scan_type = "agent" if tools else "prompt"
    
    input_scan = await firewall_engine.scan(
        ScanRequest(
            prompt=prompt_text,
            model=model,
            provider=provider,
            scan_type=scan_type,
        )
    )



    
    # ── STEP 2: Multi-turn session context ──────────────────────
    session_risk = 0.0
    if session_id:
        await session_manager.record_turn(
            session_id, prompt_text, input_scan.threat_score,
            [d.category for d in input_scan.detections]
        )
        session_risk = await session_manager.get_session_risk(session_id)
        
    # Combine single-turn threat with session risk
    effective_score = max(input_scan.threat_score, session_risk * 0.8)
    is_blocked = input_scan.action == "blocked" or session_risk >= 0.9

    # ── STEP 2.5: Profiler ──────────────────────────────────────
    profile = None
    if input_scan.action in ("blocked", "flagged") or is_blocked:
        await attacker_profiler.initialize()
        # Override action/threat_level if blocked by session risk
        final_action = "blocked" if is_blocked else input_scan.action
        final_threat_level = "critical" if is_blocked else input_scan.threat_level
        profile = await attacker_profiler.profile_request(
            request, 
            session_id=session_id, 
            action=final_action, 
            threat_level=final_threat_level, 
            detections=input_scan.detections
        )
        if profile.threat_narrative:
            logger.info("threat_narrative", narrative=profile.threat_narrative)

    # Fetch default organization for persistence
    org_result = await db.execute(select(Organization))
    default_org = org_result.scalars().first()
    org_id = default_org.id if default_org else None
    
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
            policy_id=None,
            policy_rules_triggered=[],
            scan_duration_ms=input_scan.scan_duration_ms,
            total_latency_ms=input_scan.scan_duration_ms,  # Start with scan latency
            is_blocked=is_blocked,
            event_metadata={"attacker_profile": profile.model_dump()} if profile else {}
        )
        db.add(scan_event)
        await db.commit()

    if session_id:
        # Check if session should be terminated
        if session_risk >= 0.9:
            explanation = explain_scan(input_scan, session_risk=session_risk)
            # Determine org_id for broadcast
            _broadcast_org_id = str(key_obj.organization_id) if key_obj else str(org_id) if org_id else "unknown"
            # Broadcast event so dashboard updates
            await event_broadcaster.broadcast_scan({
                "organization_id": _broadcast_org_id,
                **input_scan.model_dump(),
                "model": model,
                "provider": provider,
                "session_id": session_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "action": "blocked",
                "threat_score": 1.0,
                "threat_level": "critical",
                "attacker_profile": profile.model_dump() if profile else None,
                "explanation": explanation,
            })

            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": "Session terminated by GhostPrompt AI Firewall — cumulative threat threshold exceeded",
                        "type": "ghostprompt_session_terminated",
                        "code": "session_risk_exceeded",
                        "ghostprompt": explanation,
                    }
                },
                headers={
                    "X-GhostPrompt-Action": "session_terminated",
                    "X-GhostPrompt-Session-Risk": str(round(session_risk, 4)),
                },
            )
    
    # ── STEP 3: Block if threat detected ────────────────────────
    # Combine single-turn threat with session risk
    effective_score = max(input_scan.threat_score, session_risk * 0.8)
    
    if input_scan.action == "blocked":
        explanation = explain_scan(input_scan, session_risk=session_risk)
        
        # Broadcast event
        _broadcast_org_id = str(key_obj.organization_id) if key_obj else str(org_id) if org_id else "unknown"
        await event_broadcaster.broadcast_scan({
            "organization_id": _broadcast_org_id,
            **input_scan.model_dump(),
            "model": model,
            "provider": provider,
            "session_id": session_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "attacker_profile": profile.model_dump() if profile else None
        })
        
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": f"Request blocked by GhostPrompt AI Firewall: {input_scan.threat_level} threat detected",
                    "type": "ghostprompt_blocked",
                    "code": "threat_detected",
                    "ghostprompt": explanation,
                }
            },
            headers={
                "X-GhostPrompt-Action": input_scan.action,
                "X-GhostPrompt-Threat-Level": input_scan.threat_level,
                "X-GhostPrompt-Threat-Score": str(input_scan.threat_score),
                "X-GhostPrompt-Request-ID": input_scan.request_id,
                "X-GhostPrompt-Scan-Duration": f"{input_scan.scan_duration_ms}ms",
            },
        )
        
    # ── Context-Aware DLP (Redaction) ──
    if input_scan.action == "sanitized" and input_scan.dlp_mappings:
        # Store mappings in Redis for this request
        await dlp_vault.store_mappings(input_scan.request_id, input_scan.dlp_mappings)
        
        # Apply redaction to the actual messages payload sent to the LLM
        for msg in messages:
            if isinstance(msg.get("content"), str):
                for placeholder, original in input_scan.dlp_mappings.items():
                    msg["content"] = msg["content"].replace(original, placeholder)
    
    # Broadcast scan input event
    _broadcast_org_id = str(key_obj.organization_id) if key_obj else str(org_id) if org_id else "unknown"
    await event_broadcaster.broadcast_scan({
        "organization_id": _broadcast_org_id,
        **input_scan.model_dump(),
        "model": model,
        "provider": provider,
        "session_id": session_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "attacker_profile": profile.model_dump() if profile else None
    })

    # ── STEP 4: Forward to real LLM provider ────────────────────
    if stream:
        async def stream_generator():
            accumulated_chunks = []
            try:
                adapter = get_adapter(provider)
                async for line in adapter.stream_complete(
                    model=model,
                    messages=messages,
                    api_key=api_key,
                    **{k: v for k, v in body.items() if k not in ["model", "messages", "stream"]}
                ):
                    if not line.strip():
                        continue
                    
                    yield line + "\n"
                    
                    # Accumulate for output scan
                    if line.startswith("data: ") and not line.startswith("data: [DONE]"):
                        try:
                            data_str = line[6:]
                            data = json.loads(data_str)
                            choices = data.get("choices", [])
                            if choices:
                                delta_content = choices[0].get("delta", {}).get("content", "")
                                if delta_content:
                                    accumulated_chunks.append(delta_content)
                        except Exception:
                            pass
            except Exception as e:
                logger.error("stream_error", error=str(e))
                yield f'data: {{"error": {{"message": "An error occurred during streaming. Please try again.", "type": "stream_error"}}}}\n\n'
                return

            # ── Post-stream Output Scan ──
            accumulated_text = "".join(accumulated_chunks)
            if accumulated_text:
                try:
                    output_scan = await firewall_engine.scan(
                        ScanRequest(prompt=accumulated_text, model=model, provider=provider, scan_type="output")
                    )
                    
                    if org_id:
                        output_event = ScanEvent(
                            organization_id=org_id,
                            request_id=output_scan.request_id,
                            source_ip=request.client.host if request.client else None,
                            user_agent=request.headers.get("user-agent", "")[:512],
                            model_provider=provider,
                            model_name=model,
                            scan_type="output",
                            output_text=accumulated_text[:10000],
                            output_length=len(accumulated_text),
                            threat_level=output_scan.threat_level,
                            threat_score=output_scan.threat_score,
                            threat_categories=[d.category for d in output_scan.detections],
                            detections=[d.model_dump() for d in output_scan.detections],
                            action=output_scan.action,
                            is_blocked=output_scan.action == "blocked",
                            scan_duration_ms=output_scan.scan_duration_ms,
                        )
                        db.add(output_event)
                        await db.commit()

                    
                    # Broadcast the updated scan event with final response and output scan results
                    _stream_org_id = str(key_obj.organization_id) if key_obj else str(org_id) if org_id else "unknown"
                    await event_broadcaster.broadcast_scan({
                        "organization_id": _stream_org_id,
                        **input_scan.model_dump(),
                        "model": model,
                        "provider": provider,
                        "session_id": session_id,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "output_scan": output_scan.model_dump(),
                        "response_text": accumulated_text
                    })
                    
                    # If session exists, record turn and threat levels
                    if session_id and output_scan.threat_score > 0.0:
                        await session_manager.record_turn(
                            session_id, "[STREAMED OUTPUT]", output_scan.threat_score,
                            [d.category for d in output_scan.detections]
                        )
                except Exception as e:
                    logger.error("stream_post_scan_error", error=str(e))

        return StreamingResponse(
            stream_generator(),
            media_type="text/event-stream",
            headers={
                "X-GhostPrompt-Action": input_scan.action,
                "X-GhostPrompt-Threat-Level": input_scan.threat_level,
                "X-GhostPrompt-Threat-Score": str(input_scan.threat_score),
                "X-GhostPrompt-Request-ID": input_scan.request_id,
                "X-GhostPrompt-Scan-Duration": f"{input_scan.scan_duration_ms}ms",
            }
        )

    try:
        adapter = get_adapter(provider)
        response_obj = await adapter.complete(
            model=model,
            messages=messages,
            api_key=api_key,
            stream=stream,
            **{k: v for k, v in body.items() if k not in ["model", "messages", "stream"]}
        )
        provider_response = response_obj.raw_response
    except Exception as e:
        # Universal AI Gateway Fallback Routing (Phase 1)
        # If the primary provider fails, automatically route to Anthropic Claude-3-Haiku
        logger.warning("primary_llm_failed", provider=provider, error=str(e), action="fallback_routing_anthropic")
        try:
            fallback_provider = "anthropic"
            fallback_model = "claude-3-haiku-20240307"
            fallback_adapter = get_adapter(fallback_provider)
            # Reformat messages slightly if needed (basic conversion)
            response_obj = await fallback_adapter.complete(
                model=fallback_model,
                messages=messages,
                api_key=None, # Use system configured fallback key
                stream=stream,
                **{k: v for k, v in body.items() if k not in ["model", "messages", "stream"]}
            )
            provider_response = response_obj.raw_response
            provider = fallback_provider
            model = fallback_model
        except Exception as fallback_e:
            return JSONResponse(
                status_code=502,
                content={"error": {"message": f"Failed to reach primary LLM and fallback LLM. Primary: {str(e)}. Fallback: {str(fallback_e)}", "type": "gateway_unreachable"}},
            )
    
    # ── STEP 5: Scan output ─────────────────────────────────────
    output_text = ""
    try:
        choices = provider_response.get("choices", [])
        if choices:
            output_text = choices[0].get("message", {}).get("content", "")
    except (IndexError, KeyError, TypeError):
        pass
    
    output_scan = None
    output_headers = {}
    if output_text:
        output_scan = await firewall_engine.scan(
            ScanRequest(prompt=output_text, model=model, provider=provider, scan_type="output")
        )
        output_headers["X-GhostPrompt-Output-Threat"] = output_scan.threat_level
        output_headers["X-GhostPrompt-Output-Score"] = str(output_scan.threat_score)
        
        if org_id:
            output_event = ScanEvent(
                organization_id=org_id,
                request_id=output_scan.request_id,
                source_ip=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent", "")[:512],
                model_provider=provider,
                model_name=model,
                scan_type="output",
                output_text=output_text[:10000],
                output_length=len(output_text),
                threat_level=output_scan.threat_level,
                threat_score=output_scan.threat_score,
                threat_categories=[d.category for d in output_scan.detections],
                detections=[d.model_dump() for d in output_scan.detections],
                action=output_scan.action,
                is_blocked=output_scan.action == "blocked",
                scan_duration_ms=output_scan.scan_duration_ms,
            )
            db.add(output_event)
            await db.commit()

        
        # Redact output if PII/secrets detected
        if output_scan.action == "blocked":
            for detection in output_scan.detections:
                if detection.matched_content and detection.matched_content in output_text:
                    output_text = output_text.replace(detection.matched_content, "[REDACTED]")
            provider_response["choices"][0]["message"]["content"] = output_text
            
    # ── Context-Aware DLP (Unredaction) ──
    if input_scan.action == "sanitized" and input_scan.dlp_mappings:
        mappings = await dlp_vault.retrieve_mappings(input_scan.request_id)
        if mappings:
            final_output = output_text
            for placeholder, original in mappings.items():
                if placeholder in final_output:
                    final_output = final_output.replace(placeholder, original)
            
            if "choices" in provider_response and len(provider_response["choices"]) > 0:
                provider_response["choices"][0]["message"]["content"] = final_output
    
    # ── STEP 6: Return response with security headers ───────────
    return JSONResponse(
        content=provider_response,
        headers={
            "X-GhostPrompt-Action": input_scan.action,
            "X-GhostPrompt-Threat-Level": input_scan.threat_level,
            "X-GhostPrompt-Threat-Score": str(input_scan.threat_score),
            "X-GhostPrompt-Request-ID": input_scan.request_id,
            "X-GhostPrompt-Scan-Duration": f"{input_scan.scan_duration_ms}ms",
            **output_headers,
        },
    )



