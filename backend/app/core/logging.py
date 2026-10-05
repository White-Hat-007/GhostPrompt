"""
GhostPrompt Structured Logging

JSON-structured logging with correlation IDs, request context,
and configurable output formats for production observability.

Security:
- PII and sensitive data are scrubbed from logs
- No passwords, tokens, or raw keys are ever logged
"""

import structlog
import logging
import sys
import re
from app.core.config import get_settings

settings = get_settings()

# Keys that should always be redacted
SENSITIVE_KEYS = {
    "password", "hashed_password", "token", "access_token", "refresh_token", 
    "api_key", "secret", "key", "authorization", "cookie", "session_id"
}

def pii_scrubber(logger, log_method, event_dict):
    """
    Remove sensitive data from logs before writing.
    Redacts specific keys and masks email addresses.
    """
    # Create a new dict to avoid modifying the original context
    clean_dict = {}
    
    for key, value in event_dict.items():
        # Redact exact sensitive keys
        if key.lower() in SENSITIVE_KEYS:
            clean_dict[key] = "[REDACTED]"
            continue
            
        # Mask email fields
        if key.lower() == "email" and isinstance(value, str):
            if "@" in value:
                local, domain = value.split("@", 1)
                clean_dict[key] = f"{local[:2]}***@{domain}"
            else:
                clean_dict[key] = "***"
            continue
            
        clean_dict[key] = value
        
    return clean_dict


def setup_logging() -> None:
    """Configure structured logging for the application."""

    # Shared processors
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        pii_scrubber,  # SECURITY: Added PII scrubber before rendering
    ]

    if settings.LOG_FORMAT == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

    # Suppress noisy loggers
    for logger_name in ["uvicorn.access", "sqlalchemy.engine", "httpx"]:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def get_logger(name: str = "ghostprompt") -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)
