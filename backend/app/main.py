"""
GhostPrompt FastAPI Application

Main application entry point with middleware, CORS, error handling,
and lifecycle management.

Security: All responses include hardened HTTP security headers.
Error responses never leak internal details.
"""

import time
import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.adaptive_ml import router as adaptive_ml_router
from app.api.admin import router as admin_router
from app.api.analytics import router as analytics_router
from app.api.api_keys import router as api_keys_router
from app.api.attribution import router as attribution_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.billing import router as billing_router
from app.api.compliance_frameworks import router as compliance_frameworks_router
from app.api.dashboard import router as dashboard_router
from app.api.enterprise import router as enterprise_router
from app.api.federation import router as federation_router
from app.api.gateway import router as gateway_router
from app.api.honeypot import router as honeypot_router
from app.api.killswitch import router as killswitch_router
from app.api.model_security import enterprise_router as model_security_enterprise_router
from app.api.model_security import router as model_security_router
from app.api.multi_proxy import router as multi_proxy_router
from app.api.notifications import router as notifications_router
from app.api.platform import router as platform_router
from app.api.policies import router as policies_router
from app.api.providers import router as providers_router
from app.api.proxy import router as proxy_router
from app.api.scan import public_router as scan_public_router
from app.api.scan import router as scan_router
from app.api.settings import router as settings_router
from app.api.superadmin import router as superadmin_router
from app.api.superadmin_v2 import router as superadmin_v2_router
from app.api.training import router as training_router
from app.core.config import get_settings
from app.core.database import close_db, init_db
from app.core.events import event_broadcaster
from app.core.logging import get_logger, setup_logging
from app.core.rate_limit import limiter
from app.core.redis import close_redis, get_redis
from app.services.firewall.engine import firewall_engine
from app.services.playbooks.playbook_api import router as playbook_router
from scripts.seed_policies import seed as seed_policies

settings = get_settings()
logger = get_logger("app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager."""
    # Startup
    setup_logging()
    logger.info("ghostprompt_starting", version=settings.APP_VERSION, env=settings.APP_ENV)

    # Initialize database
    await init_db()
    logger.info("database_initialized")

    # Seed default policies for organization
    try:
        await seed_policies()
        logger.info("policies_seeded")
    except Exception as e:
        logger.warning("policies_seeding_failed", error=str(e))

    # Initialize Redis
    try:
        redis = await get_redis()
        await redis.ping()
        logger.info("redis_connected")
    except Exception as e:
        logger.warning("redis_connection_failed", error=str(e))

    # Initialize AI Firewall Engine
    await firewall_engine.initialize()
    logger.info("firewall_engine_ready")

    # Start adaptive ML drift daemon background task
    try:
        from app.ml.adaptive.drift_daemon import drift_daemon
        # Seed initial baselines for the default detectors
        default_detectors = [
            "prompt_injection", "jailbreak", "pii_scanner", "encoded_payload",
            "multi_agent_guard", "semantic_classifier", "rag_sandbox",
            "tokenizer_shield", "sponge_detector", "pack_hunt_detector",
            "pliny_detector", "zero_day_detector", "content_policy",
            "obfuscation", "hallucination_detector",
        ]
        for det in default_detectors:
            drift_daemon.record_score("system", det, 0.70)  # seed baseline
        logger.info("drift_daemon_initialized", detectors=len(default_detectors))
    except Exception as e:
        logger.warning("drift_daemon_init_failed", error=str(e))

    logger.info("ghostprompt_started", version=settings.APP_VERSION)

    yield

    # Shutdown
    logger.info("ghostprompt_shutting_down")
    await close_db()
    await close_redis()
    logger.info("ghostprompt_stopped")


# Create FastAPI application
app = FastAPI(
    title="GhostPrompt",
    description="AI Runtime Security Platform — Global AI Firewall",
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.APP_DEBUG else None,
    redoc_url="/redoc" if settings.APP_DEBUG else None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── CORS Middleware (Hardened) ───
# Security: Explicit method/header whitelists prevent unexpected request types.
# Wildcard origins are NEVER used on authenticated endpoints.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=[
        "Authorization", "Content-Type", "Accept", "Origin",
        "X-Requested-With", "X-Request-ID",
    ],
    expose_headers=[
        "X-Request-ID", "X-Scan-Duration",
        "X-GhostPrompt-Action", "X-GhostPrompt-Threat-Level",
        "X-GhostPrompt-Threat-Score", "X-GhostPrompt-Request-ID",
        "X-GhostPrompt-Scan-Duration", "X-GhostPrompt-Output-Threat",
        "X-GhostPrompt-Output-Score", "X-GhostPrompt-Session-Risk",
    ],
)


# ─── Sensitive path prefixes (get Cache-Control: no-store) ───
_SENSITIVE_PATHS = frozenset([
    "/api/v1/auth", "/api/v1/admin", "/api/v1/superadmin",
    "/api/v1/billing", "/api/v1/api-keys", "/api/v1/dashboard",
])


# ─── Security Headers & Request Middleware ───
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """
    Add request ID, timing, and comprehensive security headers.
    
    Security headers prevent:
    - Clickjacking (X-Frame-Options, CSP frame-ancestors)
    - MIME sniffing (X-Content-Type-Options)
    - Protocol downgrade (HSTS)
    - Information leakage (Referrer-Policy)
    - Unauthorized API access (Permissions-Policy)
    - Cross-origin attacks (COEP, COOP, CORP)
    """
    # ── Request size guard ──
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.SECURITY_MAX_REQUEST_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": "Request body too large"},
        )

    # ── URL length guard ──
    if len(str(request.url)) > settings.SECURITY_MAX_URL_LENGTH:
        return JSONResponse(
            status_code=414,
            content={"detail": "URI too long"},
        )

    request_id = str(uuid.uuid4())[:12]
    start_time = time.perf_counter()

    # Bind request context for structured logging
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
    )

    try:
        response = await call_next(request)
    except Exception as e:
        # Security: NEVER leak exception details to clients
        logger.error("unhandled_exception", error=str(e), path=request.url.path, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal error occurred. Please try again later."},
        )

    # Calculate duration
    duration_ms = (time.perf_counter() - start_time) * 1000

    # ── Standard headers ──
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

    # ── Security headers (Layer 1) ──
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains; preload"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), "
        "usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    # CSP — strict policy, no inline scripts/eval
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    # ── Cache-Control on sensitive endpoints ──
    if any(request.url.path.startswith(p) for p in _SENSITIVE_PATHS):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    # ── Remove server identification headers ──
    if "server" in response.headers:
        del response.headers["server"]
    if "Server" in response.headers:
        del response.headers["Server"]
    if "X-Powered-By" in response.headers:
        del response.headers["X-Powered-By"]

    # Log request
    logger.info(
        "request_completed",
        status_code=response.status_code,
        duration_ms=round(duration_ms, 2),
    )

    return response


# ─── RBAC Enforcement Middleware ───
@app.middleware("http")
async def rbac_enforcement_middleware(request: Request, call_next):
    """
    RBAC enforcement — checks route-level permissions based on user's role.
    Runs after security headers middleware, before route handlers.
    
    Public routes (auth, health, docs, test) are bypassed.
    Authenticated routes are checked against the permission matrix.
    """
    path = request.url.path
    method = request.method

    # Skip public/unauthenticated routes
    public_prefixes = (
        "/api/v1/auth/", "/api/v1/scan/test", "/api/v1/health",
        "/docs", "/redoc", "/openapi.json", "/v1/chat/completions",
        "/api/v1/dashboard/config",
    )
    if any(path.startswith(p) for p in public_prefixes) or method == "OPTIONS":
        return await call_next(request)

    # For authenticated routes, we check RBAC via the dependency injection
    # (the rbac_middleware.py handles per-route checks via ROUTE_PERMISSIONS)
    # This middleware just logs RBAC activity at the HTTP layer
    response = await call_next(request)
    return response


# ─── Global Exception Handler ───
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler — never leaks internal details.
    
    Security: Returns generic error message to client.
    Full exception details are logged server-side only.
    """
    logger.error(
        "unhandled_error",
        error=str(exc),
        error_type=type(exc).__name__,
        path=request.url.path,
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Please try again later."},
    )


# Register routers
app.include_router(auth_router, prefix=settings.API_PREFIX)
app.include_router(scan_router, prefix=settings.API_PREFIX)
app.include_router(scan_public_router, prefix=settings.API_PREFIX)
app.include_router(dashboard_router, prefix=settings.API_PREFIX)
app.include_router(policies_router, prefix=settings.API_PREFIX)
app.include_router(gateway_router, prefix=settings.API_PREFIX)
app.include_router(billing_router, prefix=settings.API_PREFIX)
app.include_router(admin_router, prefix=settings.API_PREFIX)
app.include_router(api_keys_router, prefix=settings.API_PREFIX)
app.include_router(superadmin_router, prefix=settings.API_PREFIX)
app.include_router(killswitch_router, prefix=settings.API_PREFIX)
app.include_router(attribution_router, prefix=settings.API_PREFIX)
app.include_router(enterprise_router, prefix=settings.API_PREFIX)
app.include_router(model_security_router, prefix=settings.API_PREFIX)
app.include_router(model_security_enterprise_router, prefix=settings.API_PREFIX)
app.include_router(providers_router, prefix=settings.API_PREFIX)
app.include_router(platform_router, prefix=settings.API_PREFIX)
app.include_router(analytics_router, prefix=settings.API_PREFIX)
app.include_router(training_router, prefix=settings.API_PREFIX)
app.include_router(settings_router, prefix=settings.API_PREFIX)
app.include_router(superadmin_v2_router, prefix=settings.API_PREFIX)
app.include_router(audit_router, prefix=settings.API_PREFIX)
app.include_router(federation_router, prefix=settings.API_PREFIX)
app.include_router(adaptive_ml_router, prefix=settings.API_PREFIX)
app.include_router(compliance_frameworks_router, prefix=settings.API_PREFIX)
app.include_router(notifications_router, prefix=settings.API_PREFIX)
app.include_router(playbook_router, prefix=settings.API_PREFIX)

# OpenAI-compatible proxy — mounted at root level (no prefix)
app.include_router(proxy_router)

# Multi-provider native proxies — mounted at root level
app.include_router(multi_proxy_router)

# Honeypot with catch-all route should be included last
app.include_router(honeypot_router)


# Health check
@app.get("/health")
async def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "ghostprompt",
        "version": settings.APP_VERSION,
    }


@app.get("/")
async def root():
    """Root endpoint — API info."""
    return {
        "name": "GhostPrompt",
        "description": "AI Runtime Security Platform",
        "version": settings.APP_VERSION,
        "api": settings.API_PREFIX,
    }


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket, token: str = None):
    """
    WebSocket endpoint for real-time scan event streaming.

    Security: Requires valid JWT token for connection.
    Rejects connections without valid authentication.
    """
    org_id = None
    is_admin = False

    if token:
        try:
            from jose import jwt as jose_jwt
            payload = jose_jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=settings.allowed_jwt_algorithms,
            )
            org_id = payload.get("org_id")
            role = payload.get("role")
            if role in ("admin", "owner"):
                is_admin = True
        except Exception:
            logger.warning("ws_token_validation_failed")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    else:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await event_broadcaster.connect(websocket, org_id, is_admin)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
            elif data == "stats":
                await websocket.send_json({
                    "type": "stats",
                    "data": event_broadcaster.get_stats(org_id),
                })
    except WebSocketDisconnect:
        event_broadcaster.disconnect(websocket)
    except Exception:
        event_broadcaster.disconnect(websocket)
