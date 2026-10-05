
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from app.core.logging import get_logger
from app.security.audit_log import AuditAction, audit_log

logger = get_logger("honeypot")
router = APIRouter(tags=["Honeypot"])

# Specific attacker probe paths — NO catch-all
HONEYPOT_ROUTES = [
    "/wp-login.php",
    "/wp-admin",
    "/.env",
    "/config.php",
    "/phpmyadmin",
    "/.git/config",
    "/admin.php",
    "/xmlrpc.php",
    "/.aws/credentials",
    "/server-status",
    "/shell",
    "/eval",
    "/debug/vars",
]


async def _handle_honeypot(request: Request):
    """Shared handler for all honeypot trap routes."""
    client_ip = request.client.host if request.client else "unknown"
    full_path = request.url.path

    logger.warning(
        "honeypot_triggered",
        ip=client_ip,
        path=full_path,
        user_agent=request.headers.get("user-agent", "unknown")
    )

    audit_log(
        action=AuditAction.SECURITY_EVENT,
        actor_email="anonymous",
        ip_address=client_ip,
        resource_type="honeypot",
        resource_id=full_path,
        outcome="ip_flagged",
        details={"user_agent": request.headers.get("user-agent", "unknown")}
    )

    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"error": "Access Denied"}
    )


# Register each honeypot route individually
for _route in HONEYPOT_ROUTES:
    router.add_api_route(
        _route,
        _handle_honeypot,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )
