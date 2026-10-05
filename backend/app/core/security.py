"""
GhostPrompt Security Module

JWT token management, password hashing, and authentication utilities.
Hardened against: timing attacks, JWT algorithm confusion, brute force,
credential stuffing, token replay.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
import hmac
import hashlib
import secrets

from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.config import get_settings

settings = get_settings()

import bcrypt

# Bearer token scheme
security_scheme = HTTPBearer()


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt with explicit cost factor.
    
    Security: bcrypt cost factor 12 = ~250ms per hash on modern hardware.
    This makes brute force attacks computationally expensive while remaining
    acceptable for user-facing login latency.
    """
    return bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt(rounds=settings.SECURITY_BCRYPT_ROUNDS)
    ).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash using timing-safe comparison.
    
    Security: bcrypt.checkpw internally uses constant-time comparison,
    preventing timing attacks that could reveal password length or prefix.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except (ValueError, TypeError):
        return False


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a JWT access token with explicit algorithm and short expiry.
    
    Security: 15-minute expiry limits the blast radius of a stolen token.
    Algorithm is explicitly set to prevent algorithm confusion attacks.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    if "type" not in to_encode:
        to_encode["type"] = "access"
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


def create_refresh_token(data: dict) -> str:
    """
    Create a JWT refresh token.
    
    Security: Refresh tokens have longer expiry but are only used to
    obtain new access tokens. They should be rotated on every use.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_hex(16),  # Unique ID for token revocation
    })
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token with strict algorithm enforcement.
    
    Security: 
    - Explicitly specifies allowed algorithms to prevent 'none' algorithm attacks.
    - Validates expiry, preventing use of expired tokens.
    - Never returns raw JWTError details to prevent information leakage.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=settings.allowed_jwt_algorithms,
            options={
                "verify_exp": True,
                "verify_iat": True,
                "require": ["exp", "sub"],
            }
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def generate_api_key() -> str:
    """Generate a cryptographically secure API key."""
    return f"gp_{secrets.token_urlsafe(48)}"


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key for secure storage using SHA-256.
    
    Security: API keys are hashed before storage so that even if the
    database is compromised, the raw keys cannot be recovered.
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    """
    Verify an API key against its hash using timing-safe comparison.
    
    Security: hmac.compare_digest prevents timing attacks that could
    reveal the hash value byte-by-byte.
    """
    computed_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    return hmac.compare_digest(computed_hash, stored_hash)


from app.core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db)
) -> dict:
    """
    Extract and validate the current user from JWT token.
    
    Security:
    - Demo token is ONLY accepted when SECURITY_DEMO_MODE=True (disabled by default).
    - Token type is validated to prevent refresh tokens being used as access tokens.
    - No internal details are leaked in error messages.
    """
    # Demo mode: only enabled explicitly via environment variable
    if settings.SECURITY_DEMO_MODE and credentials.credentials == "demo_token":
        from sqlalchemy import select
        from app.models.organization import Organization
        result = await db.execute(
            select(Organization).where(Organization.slug == "demo-org")
        )
        org = result.scalar_one_or_none()
        if org:
            return {
                "user_id": "demo_user",
                "org_id": str(org.id),
                "role": "owner",
                "email": "admin@ghostprompt.ai",
            }
        # Fallback: use first org
        result = await db.execute(select(Organization))
        org = result.scalars().first()
        if org:
            return {
                "user_id": "demo_user",
                "org_id": str(org.id),
                "role": "owner",
                "email": "admin@ghostprompt.ai",
            }

    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    return {
        "user_id": user_id,
        "org_id": payload.get("org_id"),
        "role": payload.get("role", "viewer"),
        "email": payload.get("email"),
    }


def require_role(required_role: str):
    """
    Dependency factory for role-based access control.
    
    Security: Server-side role hierarchy enforcement.
    Client-side role claims are NEVER trusted — the role in the JWT
    is set by the server at login and re-validated here.
    """
    ROLE_HIERARCHY = {
        "owner": 4,
        "admin": 3,
        "analyst": 2,
        "viewer": 1,
    }

    async def role_checker(
        current_user: dict = Depends(get_current_user),
    ) -> dict:
        user_level = ROLE_HIERARCHY.get(current_user.get("role", "viewer"), 0)
        required_level = ROLE_HIERARCHY.get(required_role, 0)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return role_checker


def require_plan(required_plan: str):
    """
    Dependency factory for plan-based feature gating.
    
    Security: Enforces pricing tiers (starter, pro, enterprise) server-side.
    Checks the organization's current plan on every request to a premium endpoint.
    """
    PLAN_HIERARCHY = {
        "enterprise": 3,
        "pro": 2,
        "starter": 1,
    }

    async def plan_checker(
        current_user: dict = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
    ) -> dict:
        from sqlalchemy import select
        from app.models.organization import Organization
        result = await db.execute(
            select(Organization).where(Organization.id == current_user["org_id"])
        )
        org = result.scalar_one_or_none()
        if not org:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Organization not found",
            )
            
        user_level = PLAN_HIERARCHY.get(org.plan, 1) # Default to starter if unknown
        required_level = PLAN_HIERARCHY.get(required_plan, 1)
        
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Feature requires {required_plan.capitalize()} plan or higher",
            )
        return current_user

    return plan_checker
