"""
Input Validation & Sanitization Module

Centralized utilities for input sanitization across the application.

Attack vectors prevented:
- CRLF/Header injection
- Path traversal
- Open redirect
- SQL/NoSQL operator injection
- Prototype pollution keys
"""

import re
from urllib.parse import urlparse

# ─── CRLF Injection Prevention ───

def sanitize_header_value(value: str) -> str:
    """
    Strip CR/LF characters from header values.
    Prevents HTTP response splitting attacks.
    """
    return value.replace("\r", "").replace("\n", "").replace("\x00", "")


# ─── Path Traversal Prevention ───

def is_safe_path(path: str) -> bool:
    """
    Reject paths containing traversal sequences.
    Prevents directory traversal attacks.
    """
    dangerous_patterns = ["..", "~", "%2e", "%2E", "%00"]
    for pattern in dangerous_patterns:
        if pattern in path:
            return False
    return True


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing dangerous characters.
    Only allows alphanumeric, hyphens, underscores, and dots.
    """
    # Remove path separators and traversal chars
    clean = re.sub(r'[^\w\-.]', '_', filename)
    # Remove leading dots (hidden files)
    clean = clean.lstrip('.')
    # Limit length
    return clean[:255] if clean else "unnamed"


# ─── Open Redirect Prevention ───

_ALLOWED_REDIRECT_HOSTS: set[str] = set()


def is_safe_redirect(url: str, allowed_hosts: set[str] | None = None) -> bool:
    """
    Validate redirect URLs to prevent open redirect attacks.
    Only relative paths or whitelisted hosts are allowed.
    """
    if not url:
        return False

    # Relative paths are always safe
    if url.startswith("/") and not url.startswith("//"):
        return True

    # Absolute URLs must match allowed hosts
    try:
        parsed = urlparse(url)
        hosts = allowed_hosts or _ALLOWED_REDIRECT_HOSTS
        return parsed.hostname in hosts if parsed.hostname else False
    except Exception:
        return False


# ─── NoSQL Operator Sanitization ───

_DANGEROUS_MONGO_OPERATORS = {"$where", "$gt", "$gte", "$lt", "$lte", "$ne", "$in", "$nin", "$or", "$and", "$not", "$regex"}


def sanitize_nosql_input(value: str) -> str:
    """
    Strip MongoDB operators from string input.
    Prevents NoSQL injection attacks.
    """
    if isinstance(value, str):
        for op in _DANGEROUS_MONGO_OPERATORS:
            value = value.replace(op, "")
    return value


def reject_object_input(value) -> str:
    """
    Ensure input is a string, not a dict/object.
    Prevents NoSQL injection via operator objects.
    """
    if not isinstance(value, str):
        raise ValueError("Expected string input, received object")
    return value


# ─── Prototype Pollution Prevention ───

_DANGEROUS_KEYS = {"__proto__", "constructor", "prototype"}


def is_safe_key(key: str) -> bool:
    """
    Reject keys that could trigger prototype pollution.
    """
    return key.lower() not in _DANGEROUS_KEYS


def sanitize_dict_keys(data: dict) -> dict:
    """
    Remove dangerous keys from user-supplied dictionaries.
    """
    return {k: v for k, v in data.items() if is_safe_key(k)}


# ─── General Sanitization ───

def strip_null_bytes(value: str) -> str:
    """Remove null bytes that could bypass security checks."""
    return value.replace("\x00", "")


def validate_string_length(value: str, field_name: str, max_length: int) -> str:
    """
    Validate string length with clear error messaging.
    """
    if len(value) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length}")
    return value
