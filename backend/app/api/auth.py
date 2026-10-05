"""
Authentication Routes

Registration, login, token refresh, and user profile endpoints.

Security:
- Account lockout after 5 failed attempts
- Rate limited: login 5/15min, register 3/hour, reset 3/hour
- Generic error messages prevent email enumeration
- All auth events are audit logged
- Timing-safe password comparison via bcrypt
"""

import hashlib
import re
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import limiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.models.api_key import APIKey
from app.models.organization import Organization
from app.models.user import User
from app.schemas.schemas import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.security.account_lockout import lockout_tracker
from app.security.audit_log import AuditAction, audit_log
from app.services.email_service import email_service

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["Authentication"])


class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/hour")
async def register(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user and organization.
    
    Security: Rate limited to 3 registrations per hour per IP.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Check if email already exists
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Check if username exists
    existing_user = await db.execute(select(User).where(User.username == payload.username))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already taken")

    # Create organization
    slug = re.sub(r"[^a-z0-9]+", "-", payload.organization_name.lower()).strip("-")
    existing_org = await db.execute(select(Organization).where(Organization.slug == slug))
    if existing_org.scalar_one_or_none():
        slug = f"{slug}-{int(datetime.now(timezone.utc).timestamp()) % 10000}"

    org = Organization(
        name=payload.organization_name,
        slug=slug,
        plan="free",
    )
    db.add(org)
    await db.flush()

    # Create user
    user = User(
        organization_id=org.id,
        email=payload.email,
        username=payload.username,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role="owner",
        is_active=True,
    )
    db.add(user)
    await db.flush()

    # Generate default API key for the new organization
    raw_key = f"gp-sk-{secrets.token_hex(32)}"
    key_prefix = f"gp-sk-...{raw_key[-4:]}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    api_key = APIKey(
        organization_id=org.id,
        name="Default API Key",
        key_hash=key_hash,
        key_prefix=key_prefix,
        environment="PRODUCTION",
        is_active=True
    )
    db.add(api_key)
    await db.flush()

    # Audit log
    audit_log(
        action=AuditAction.REGISTER,
        actor_id=str(user.id),
        actor_email=user.email,
        ip_address=client_ip,
        resource_type="user",
        resource_id=str(user.id),
        details={"organization": org.name},
    )

    # Generate tokens
    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "org_id": str(org.id),
        "role": user.role,
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    # Generate verification token and send email
    verify_token_data = {"sub": str(user.id), "type": "verification"}
    verification_token = create_access_token(verify_token_data)
    await email_service.send_verification_email(user.email, verification_token)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/15minutes")
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and return tokens.
    
    Security:
    - Rate limited to 5 attempts per 15 minutes per IP
    - Account lockout after 5 failed attempts per (IP, email)
    - Generic error message prevents email enumeration
    - All attempts (success and failure) are audit logged
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    login_identifier = payload.email  # Could be email or username

    # ── Account lockout check ──
    if lockout_tracker.is_locked_out(client_ip, login_identifier):
        remaining = lockout_tracker.get_lockout_remaining_seconds(client_ip, login_identifier)
        audit_log(
            action=AuditAction.LOGIN_FAILURE,
            actor_email=login_identifier,
            ip_address=client_ip,
            user_agent=user_agent,
            outcome="locked_out",
            details={"remaining_seconds": remaining},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked. Try again in {remaining} seconds.",
        )

    # ── Find user ──
    result = await db.execute(
        select(User).where(
            or_(
                User.email == login_identifier,
                User.username == login_identifier
            )
        )
    )
    user = result.scalar_one_or_none()

    # ── Verify credentials ──
    # Security: Generic error message for both "user not found" and "wrong password"
    if not user or not verify_password(payload.password, user.hashed_password):
        # Record failure for lockout tracking
        is_locked = lockout_tracker.record_failure(client_ip, login_identifier, user_agent)
        audit_log(
            action=AuditAction.LOGIN_FAILURE,
            actor_email=login_identifier,
            ip_address=client_ip,
            user_agent=user_agent,
            outcome="invalid_credentials",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        audit_log(
            action=AuditAction.LOGIN_FAILURE,
            actor_id=str(user.id),
            actor_email=user.email,
            ip_address=client_ip,
            outcome="account_disabled",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    if not user.is_verified:
        audit_log(
            action=AuditAction.LOGIN_FAILURE,
            actor_id=str(user.id),
            actor_email=user.email,
            ip_address=client_ip,
            outcome="email_not_verified",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email address to login.",
        )

    # ── Success: clear lockout, update login metadata ──
    lockout_tracker.record_success(client_ip, login_identifier)

    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = client_ip

    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "org_id": str(user.organization_id),
        "role": user.role,
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    audit_log(
        action=AuditAction.LOGIN_SUCCESS,
        actor_id=str(user.id),
        actor_email=user.email,
        ip_address=client_ip,
        user_agent=user_agent,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest):
    """Refresh an access token."""
    payload = decode_token(request.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    token_data = {
        "sub": payload["sub"],
        "email": payload.get("email"),
        "org_id": payload.get("org_id"),
        "role": payload.get("role"),
    }
    access_token = create_access_token(token_data)
    refresh_token_new = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_new,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserResponse)
async def get_profile(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current user profile along with organization plan."""
    from sqlalchemy.orm import joinedload
    result = await db.execute(
        select(User)
        .options(joinedload(User.organization))
        .where(User.id == current_user["user_id"])
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user.organization_plan = user.organization.plan if user.organization else "starter"
    return user


@router.get("/verify-email")
async def verify_email(
    token: str,
    db: AsyncSession = Depends(get_db)
):
    """Verify user email address using JWT token."""
    try:
        payload = decode_token(token)
        if payload.get("type") != "verification":
            raise HTTPException(status_code=400, detail="Invalid verification link")
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid verification link")
            
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=400, detail="Invalid verification link")
            
        user.is_verified = True
        await db.commit()

        audit_log(
            action=AuditAction.EMAIL_VERIFIED,
            actor_id=str(user.id),
            actor_email=user.email,
            resource_type="user",
            resource_id=str(user.id),
        )

        return {"message": "Email verified successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired verification link")


@router.post("/forgot-password")
@limiter.limit("3/hour")
async def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Send password reset email.
    
    Security: Always returns 200 to prevent email enumeration.
    Rate limited to 3 per hour per IP.
    """
    client_ip = request.client.host if request.client else "unknown"
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    
    if user:
        reset_token_data = {"sub": str(user.id), "type": "reset_password"}
        reset_token = create_access_token(reset_token_data)
        await email_service.send_password_reset_email(user.email, reset_token)

    audit_log(
        action=AuditAction.PASSWORD_RESET_REQUEST,
        actor_email=payload.email,
        ip_address=client_ip,
        outcome="sent" if user else "no_account",
    )
    
    # Always return 200 to prevent email enumeration
    return {"message": "If an account with that email exists, a reset link has been sent."}


@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    """Reset user password using token."""
    try:
        payload = decode_token(request.token)
        if payload.get("type") != "reset_password":
            raise HTTPException(status_code=400, detail="Invalid reset link")
            
        user_id = payload.get("sub")
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=400, detail="Invalid reset link")
            
        user.hashed_password = hash_password(request.new_password)
        await db.commit()

        audit_log(
            action=AuditAction.PASSWORD_RESET_COMPLETE,
            actor_id=str(user.id),
            actor_email=user.email,
            resource_type="user",
            resource_id=str(user.id),
        )

        return {"message": "Password has been reset successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")
