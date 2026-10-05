"""
Settings API — Enterprise Settings Hub (Persistent, Multi-Tenant)

CRUD endpoints for all settings sections, persisted to Organization.settings JSON column.
No in-memory dicts — everything survives restarts.

Sections:
- Profile & Account
- Organization
- Security & Detection
- Notifications
- Integrations / SIEM (real connection testing)
- SSO / Identity (SAML, OIDC, SCIM, BYOK, MFA)
- Appearance (applied to UI)
- Compliance (GDPR, HIPAA, DPDPA, SOC2, ISO, CCPA, PCI, NIST, EU AI Act)
- Danger Zone
"""

import httpx
import asyncio
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel

from app.core.database import get_db
from app.core.security import get_current_user, hash_password, verify_password
from app.core.permissions import require_permission
from app.core.logging import get_logger
from app.models.user import User
from app.models.organization import Organization

logger = get_logger("api.settings")
router = APIRouter(
    prefix="/settings",
    tags=["Settings"],
    dependencies=[Depends(require_permission("settings.view"))],
)


# ── Schemas ──

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class OrgSettingsUpdate(BaseModel):
    name: Optional[str] = None
    logo_url: Optional[str] = None
    domain: Optional[str] = None
    data_residency: Optional[str] = None  # us, eu, ap, in

class SecuritySettings(BaseModel):
    threat_score_threshold: float = 0.7
    auto_block_critical: bool = True
    pii_auto_redact: bool = True
    max_prompt_length: int = 32000
    rate_limit_per_minute: int = 60
    mfa_required: bool = False

class NotificationSettings(BaseModel):
    email_alerts: bool = True
    slack_webhook_url: Optional[str] = None
    pagerduty_key: Optional[str] = None
    webhook_url: Optional[str] = None
    alert_threshold: str = "high"  # low, medium, high, critical

class AppearanceSettings(BaseModel):
    theme: str = "dark"  # dark, darker
    accent_color: str = "#8b5cf6"  # ghost purple default
    density: str = "comfortable"  # comfortable, compact
    font_size: str = "base"  # sm, base, lg
    code_font: str = "JetBrains Mono"
    animation_speed: str = "normal"  # none, slow, normal, fast
    reduced_motion: bool = False
    sidebar_collapsed: bool = False
    threat_color_scheme: str = "default"  # default, deuteranopia, protanopia

class IntegrationConfig(BaseModel):
    provider: str  # splunk, datadog, microsoft_sentinel, ibm_qradar, elastic_security, crowdstrike, google_chronicle, webhook
    enabled: bool = False
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    hec_token: Optional[str] = None  # Splunk HEC
    workspace_id: Optional[str] = None  # Sentinel
    index_name: Optional[str] = None
    format: str = "json"  # json, ocsf, cef
    verified: bool = False
    last_test_at: Optional[str] = None
    last_test_status: Optional[str] = None

class SSOConfig(BaseModel):
    protocol: str = "none"  # none, saml, oidc
    idp_url: Optional[str] = None
    entity_id: Optional[str] = None
    certificate: Optional[str] = None
    acs_url: Optional[str] = None  # Assertion Consumer Service
    attribute_mapping: Optional[dict] = None  # e.g. {"email": "nameID", "role": "groups"}
    enforce_sso: bool = False
    allow_admin_bypass: bool = True
    jit_provisioning: bool = False  # Just-in-time user creation

class SCIMConfig(BaseModel):
    enabled: bool = False
    endpoint: Optional[str] = None
    bearer_token: Optional[str] = None
    sync_interval_minutes: int = 15
    auto_deprovision: bool = False
    group_mapping: Optional[dict] = None

class BYOKEncryptionConfig(BaseModel):
    enabled: bool = False
    kms_provider: str = "none"  # none, aws_kms, gcp_kms, azure_keyvault, custom
    key_id: Optional[str] = None
    key_arn: Optional[str] = None  # AWS KMS ARN
    region: Optional[str] = None
    rotation_days: int = 90
    envelope_encryption: bool = True

class MFAConfig(BaseModel):
    enabled: bool = False
    method: str = "totp"  # totp, webauthn, sms
    grace_period_hours: int = 24
    exempt_admins: bool = False
    remember_device_days: int = 30

class IPAllowlistConfig(BaseModel):
    enabled: bool = False
    cidrs: List[str] = []
    enforce: bool = False

class ComplianceSettings(BaseModel):
    # AI-Specific Frameworks
    nist_ai_rmf_enabled: bool = False
    iso_42001_enabled: bool = False
    # Global Standards
    soc2_enabled: bool = False
    iso27001_enabled: bool = False
    nist_csf_enabled: bool = False
    pci_dss_enabled: bool = False
    # Europe
    gdpr_enabled: bool = False
    eu_ai_act_enabled: bool = False
    # Americas
    hipaa_enabled: bool = False
    ccpa_enabled: bool = False
    # Asia-Pacific
    dpdpa_enabled: bool = False
    # Data Controls
    audit_retention_days: int = 90
    data_export_enabled: bool = True
    data_residency: str = "us"  # us, eu, ap, in
    consent_logging: bool = False
    right_to_erasure: bool = False
    breach_notification_hours: int = 72
    automated_dpia: bool = False  # Data Protection Impact Assessment


# ── Helpers ──

DEFAULT_SETTINGS = {
    "security": SecuritySettings().model_dump(),
    "notifications": NotificationSettings().model_dump(),
    "appearance": AppearanceSettings().model_dump(),
    "integrations": [],
    "compliance": ComplianceSettings().model_dump(),
    "sso": SSOConfig().model_dump(),
    "scim": SCIMConfig().model_dump(),
    "byok_encryption": BYOKEncryptionConfig().model_dump(),
    "mfa": MFAConfig().model_dump(),
    "ip_allowlist": IPAllowlistConfig().model_dump(),
}


async def _get_org_settings(org_id: str, db: AsyncSession) -> dict:
    """Get settings from the Organization.settings JSON column, with defaults."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        return dict(DEFAULT_SETTINGS)

    stored = org.settings or {}
    # Merge with defaults so new keys are always present
    merged = dict(DEFAULT_SETTINGS)
    for key in DEFAULT_SETTINGS:
        if key in stored:
            if isinstance(merged[key], dict):
                merged[key] = {**merged[key], **stored[key]}
            else:
                merged[key] = stored[key]
    return merged


async def _save_org_settings(org_id: str, section: str, value, db: AsyncSession):
    """Persist a settings section to the Organization.settings JSON column."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")

    current = dict(org.settings or {})
    current[section] = value if not isinstance(value, BaseModel) else value.model_dump()

    await db.execute(
        update(Organization).where(Organization.id == org_id).values(settings=current)
    )
    await db.commit()
    logger.info("settings_persisted", org=str(org_id), section=section)


# ── Profile & Account ──

@router.get("/profile")
async def get_profile(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current user profile."""
    user_id = current_user.get("user_id")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")

    org_result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
    org = org_result.scalar_one_or_none()

    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "organization_name": org.name if org else "Unknown",
        "organization_plan": org.plan if org else "free",
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


@router.patch("/profile")
async def update_profile(
    updates: ProfileUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update current user profile."""
    user_id = current_user.get("user_id")
    update_data = {k: v for k, v in updates.model_dump().items() if v is not None}
    if update_data:
        await db.execute(
            update(User).where(User.id == user_id).values(**update_data)
        )
        await db.commit()
    return {"status": "updated", "fields": list(update_data.keys())}


@router.post("/password")
async def change_password(
    payload: PasswordChange,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change current user password."""
    user_id = current_user.get("user_id")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")

    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")

    if len(payload.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")

    await db.execute(
        update(User).where(User.id == user_id).values(
            password_hash=hash_password(payload.new_password)
        )
    )
    await db.commit()
    logger.info("password_changed", user_id=str(user_id))
    return {"status": "password_changed"}


# ── Organization ──

@router.get("/organization")
async def get_org_settings_endpoint(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get organization settings."""
    org_id = current_user.get("org_id")
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")

    settings = await _get_org_settings(str(org_id), db)
    return {
        "id": str(org.id),
        "name": org.name,
        "slug": org.slug,
        "plan": org.plan,
        "data_residency": settings.get("data_residency", "us"),
        "created_at": org.created_at.isoformat() if org.created_at else None,
        "settings": settings,
    }


@router.patch("/organization")
async def update_org_settings_endpoint(
    updates: OrgSettingsUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update organization settings."""
    org_id = current_user.get("org_id")
    update_data = {k: v for k, v in updates.model_dump().items() if v is not None}
    if update_data:
        await db.execute(
            update(Organization).where(Organization.id == org_id).values(**update_data)
        )
        await db.commit()
    return {"status": "updated", "fields": list(update_data.keys())}


# ── Security & Detection ──

@router.get("/security")
async def get_security_settings(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get security/detection settings."""
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    return settings.get("security", SecuritySettings().model_dump())


@router.put("/security")
async def update_security_settings(
    settings: SecuritySettings,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update security/detection settings — persisted to DB."""
    org_id = str(current_user.get("org_id"))
    await _save_org_settings(org_id, "security", settings.model_dump(), db)
    return {"status": "updated", "settings": settings.model_dump()}


# ── Notifications ──

@router.get("/notifications")
async def get_notification_settings(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    return settings.get("notifications", NotificationSettings().model_dump())


@router.put("/notifications")
async def update_notification_settings(
    settings: NotificationSettings,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    await _save_org_settings(org_id, "notifications", settings.model_dump(), db)
    return {"status": "updated"}


# ── Appearance ──

@router.get("/appearance")
async def get_appearance_settings(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    return settings.get("appearance", AppearanceSettings().model_dump())


@router.put("/appearance")
async def update_appearance_settings(
    settings: AppearanceSettings,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    await _save_org_settings(org_id, "appearance", settings.model_dump(), db)
    return {"status": "updated"}


# ══════════════════════════════════════════════════════════════════════════
# INTEGRATIONS / SIEM — Real Connection Testing
# ══════════════════════════════════════════════════════════════════════════

@router.get("/integrations")
async def get_integrations(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    return settings.get("integrations", [])


@router.post("/integrations")
async def add_integration(
    config: IntegrationConfig,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add or update a SIEM integration — persisted to DB."""
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    integrations = settings.get("integrations", [])

    # Replace if same provider exists
    integrations = [i for i in integrations if i.get("provider") != config.provider]
    integrations.append(config.model_dump())
    await _save_org_settings(org_id, "integrations", integrations, db)
    logger.info("integration_added", provider=config.provider, org=org_id)
    return {"status": "added", "provider": config.provider}


@router.delete("/integrations/{provider}")
async def remove_integration(
    provider: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    integrations = [i for i in settings.get("integrations", []) if i.get("provider") != provider]
    await _save_org_settings(org_id, "integrations", integrations, db)
    logger.info("integration_removed", provider=provider, org=org_id)
    return {"status": "removed", "provider": provider}


@router.post("/integrations/{provider}/test")
async def test_integration(
    provider: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Test a SIEM integration by sending a real probe to the configured endpoint.
    Each provider uses its own validation logic.
    """
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    integrations = settings.get("integrations", [])

    config = next((i for i in integrations if i.get("provider") == provider), None)
    if not config:
        raise HTTPException(404, f"Integration '{provider}' not configured")

    endpoint = config.get("endpoint", "")
    api_key = config.get("api_key", "")
    hec_token = config.get("hec_token", "")

    if not endpoint:
        raise HTTPException(400, "No endpoint configured for this integration")

    test_event = {
        "source": "ghostprompt",
        "event_type": "connection_test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "GhostPrompt SIEM integration test event",
        "severity": "info",
    }

    result = {"provider": provider, "status": "unknown", "latency_ms": 0, "details": ""}

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            start = asyncio.get_event_loop().time()

            if provider == "splunk":
                # Splunk HTTP Event Collector (HEC)
                token = hec_token or api_key
                resp = await client.post(
                    f"{endpoint.rstrip('/')}/services/collector/event",
                    headers={"Authorization": f"Splunk {token}"},
                    json={"event": test_event, "sourcetype": "ghostprompt", "index": config.get("index_name", "main")},
                )
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                if resp.status_code == 200:
                    result = {"provider": provider, "status": "connected", "latency_ms": round(elapsed, 1), "details": "HEC token valid, event accepted"}
                elif resp.status_code == 403:
                    result = {"provider": provider, "status": "auth_failed", "latency_ms": round(elapsed, 1), "details": "Invalid HEC token"}
                else:
                    result = {"provider": provider, "status": "error", "latency_ms": round(elapsed, 1), "details": f"HTTP {resp.status_code}: {resp.text[:200]}"}

            elif provider == "datadog":
                # Datadog API key validation
                resp = await client.get(
                    "https://api.datadoghq.com/api/v1/validate",
                    headers={"DD-API-KEY": api_key},
                )
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                if resp.status_code == 200:
                    result = {"provider": provider, "status": "connected", "latency_ms": round(elapsed, 1), "details": "API key valid"}
                else:
                    result = {"provider": provider, "status": "auth_failed", "latency_ms": round(elapsed, 1), "details": "Invalid Datadog API key"}

            elif provider == "microsoft_sentinel":
                # Azure Sentinel — Data Collector API
                workspace_id = config.get("workspace_id", "")
                resp = await client.post(
                    f"{endpoint.rstrip('/')}/api/logs?api-version=2016-04-01",
                    headers={
                        "Authorization": f"SharedKey {workspace_id}:{api_key}",
                        "Content-Type": "application/json",
                        "Log-Type": "GhostPrompt_Test",
                    },
                    json=[test_event],
                )
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                if resp.status_code in (200, 202):
                    result = {"provider": provider, "status": "connected", "latency_ms": round(elapsed, 1), "details": f"Workspace {workspace_id[:8]}... accepting events"}
                else:
                    result = {"provider": provider, "status": "error", "latency_ms": round(elapsed, 1), "details": f"HTTP {resp.status_code}"}

            elif provider == "ibm_qradar":
                # QRadar SIEM REST API
                resp = await client.get(
                    f"{endpoint.rstrip('/')}/api/system/about",
                    headers={"SEC": api_key, "Accept": "application/json"},
                )
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                if resp.status_code == 200:
                    data = resp.json()
                    result = {"provider": provider, "status": "connected", "latency_ms": round(elapsed, 1),
                              "details": f"QRadar v{data.get('release_name', 'unknown')} reachable"}
                else:
                    result = {"provider": provider, "status": "error", "latency_ms": round(elapsed, 1), "details": f"HTTP {resp.status_code}"}

            elif provider == "elastic_security":
                # Elasticsearch cluster health
                resp = await client.get(
                    f"{endpoint.rstrip('/')}/_cluster/health",
                    auth=(api_key.split(":")[0], api_key.split(":")[-1]) if ":" in api_key else None,
                    headers={"Authorization": f"ApiKey {api_key}"} if ":" not in api_key else {},
                )
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                if resp.status_code == 200:
                    data = resp.json()
                    result = {"provider": provider, "status": "connected", "latency_ms": round(elapsed, 1),
                              "details": f"Cluster '{data.get('cluster_name')}' status: {data.get('status')}"}
                else:
                    result = {"provider": provider, "status": "error", "latency_ms": round(elapsed, 1), "details": f"HTTP {resp.status_code}"}

            elif provider == "crowdstrike":
                # CrowdStrike Falcon OAuth2 token exchange
                resp = await client.post(
                    f"{endpoint.rstrip('/')}/oauth2/token",
                    data={"client_id": api_key, "client_secret": config.get("api_secret", "")},
                )
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                if resp.status_code == 201:
                    result = {"provider": provider, "status": "connected", "latency_ms": round(elapsed, 1), "details": "OAuth2 credentials valid"}
                else:
                    result = {"provider": provider, "status": "auth_failed", "latency_ms": round(elapsed, 1), "details": "Invalid credentials"}

            elif provider == "google_chronicle":
                # Google Chronicle feed test
                resp = await client.post(
                    f"{endpoint.rstrip('/')}/v1/feedSourceTypeSchemas",
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                )
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                if resp.status_code in (200, 403):
                    # 403 means auth worked but feed not configured — still a valid connection
                    result = {"provider": provider, "status": "connected", "latency_ms": round(elapsed, 1), "details": "Chronicle API reachable"}
                else:
                    result = {"provider": provider, "status": "error", "latency_ms": round(elapsed, 1), "details": f"HTTP {resp.status_code}"}

            elif provider == "webhook":
                # Generic webhook — just POST the test event
                resp = await client.post(
                    endpoint,
                    headers={"X-GhostPrompt-Event": "connection_test", "Authorization": f"Bearer {api_key}" if api_key else ""},
                    json=test_event,
                )
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                if resp.status_code < 400:
                    result = {"provider": provider, "status": "connected", "latency_ms": round(elapsed, 1), "details": f"Webhook responded with {resp.status_code}"}
                else:
                    result = {"provider": provider, "status": "error", "latency_ms": round(elapsed, 1), "details": f"HTTP {resp.status_code}"}

            else:
                # Delegate to the new connector registry for all other providers
                from app.services.siem_connectors.registry import get_connector as _get_connector
                connector = _get_connector(provider)
                if connector:
                    conn_result = await connector.safe_test(config)
                    result = {
                        "provider": provider,
                        "status": conn_result.status,
                        "latency_ms": conn_result.latency_ms,
                        "details": conn_result.details,
                    }
                else:
                    result = {"provider": provider, "status": "unsupported", "latency_ms": 0, "details": f"Provider '{provider}' not supported for testing"}

    except httpx.ConnectError:
        result = {"provider": provider, "status": "unreachable", "latency_ms": 0, "details": "Connection refused — check endpoint URL"}
    except httpx.TimeoutException:
        result = {"provider": provider, "status": "timeout", "latency_ms": 10000, "details": "Connection timed out after 10s"}
    except Exception as e:
        result = {"provider": provider, "status": "error", "latency_ms": 0, "details": str(e)[:300]}

    # Persist test result back to integration config
    for i in integrations:
        if i.get("provider") == provider:
            i["last_test_at"] = datetime.now(timezone.utc).isoformat()
            i["last_test_status"] = result["status"]
            i["verified"] = result["status"] == "connected"
            break
    await _save_org_settings(org_id, "integrations", integrations, db)

    logger.info("integration_test", provider=provider, status=result["status"], org=org_id)
    return result


@router.get("/integrations/{provider}/status")
async def integration_status(
    provider: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the stored health status of a SIEM integration."""
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    integrations = settings.get("integrations", [])
    config = next((i for i in integrations if i.get("provider") == provider), None)
    if not config:
        raise HTTPException(404, f"Integration '{provider}' not configured")
    return {
        "provider": provider,
        "enabled": config.get("enabled", False),
        "verified": config.get("verified", False),
        "last_test_at": config.get("last_test_at"),
        "last_test_status": config.get("last_test_status"),
    }


# ══════════════════════════════════════════════════════════════════════════
# SSO / IDENTITY — SAML, OIDC, SCIM, BYOK, MFA, IP Allowlist
# ══════════════════════════════════════════════════════════════════════════

@router.get("/sso")
async def get_sso_config(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    return settings.get("sso", SSOConfig().model_dump())


@router.put("/sso")
async def update_sso_config(
    config: SSOConfig,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    await _save_org_settings(org_id, "sso", config.model_dump(), db)
    logger.info("sso_config_updated", org=org_id, protocol=config.protocol)
    return {"status": "updated", "protocol": config.protocol}


@router.post("/sso/test")
async def test_sso_connection(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Validate SSO IdP metadata URL reachability."""
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    sso = settings.get("sso", {})
    idp_url = sso.get("idp_url", "")

    if not idp_url:
        return {"status": "error", "details": "No IdP URL configured"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            start = asyncio.get_event_loop().time()
            resp = await client.get(idp_url)
            elapsed = (asyncio.get_event_loop().time() - start) * 1000

            if resp.status_code < 400:
                # Check if response looks like SAML metadata
                content = resp.text[:500].lower()
                is_saml = "entitydescriptor" in content or "saml" in content
                is_oidc = "openid-configuration" in content or "jwks_uri" in content

                return {
                    "status": "connected",
                    "latency_ms": round(elapsed, 1),
                    "protocol_detected": "saml" if is_saml else ("oidc" if is_oidc else "unknown"),
                    "details": f"IdP reachable at {idp_url[:50]}...",
                }
            else:
                return {"status": "error", "latency_ms": round(elapsed, 1), "details": f"IdP returned HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "unreachable", "details": str(e)[:200]}


@router.get("/scim")
async def get_scim_config(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    return settings.get("scim", SCIMConfig().model_dump())


@router.put("/scim")
async def update_scim_config(
    config: SCIMConfig,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    await _save_org_settings(org_id, "scim", config.model_dump(), db)
    return {"status": "updated"}


@router.get("/byok-encryption")
async def get_byok_config(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    return settings.get("byok_encryption", BYOKEncryptionConfig().model_dump())


@router.put("/byok-encryption")
async def update_byok_config(
    config: BYOKEncryptionConfig,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    await _save_org_settings(org_id, "byok_encryption", config.model_dump(), db)
    logger.info("byok_updated", org=org_id, provider=config.kms_provider)
    return {"status": "updated"}


@router.get("/mfa")
async def get_mfa_config(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    return settings.get("mfa", MFAConfig().model_dump())


@router.put("/mfa")
async def update_mfa_config(
    config: MFAConfig,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    await _save_org_settings(org_id, "mfa", config.model_dump(), db)
    return {"status": "updated"}


@router.get("/ip-allowlist")
async def get_ip_allowlist(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    return settings.get("ip_allowlist", IPAllowlistConfig().model_dump())


@router.put("/ip-allowlist")
async def update_ip_allowlist(
    config: IPAllowlistConfig,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    await _save_org_settings(org_id, "ip_allowlist", config.model_dump(), db)
    return {"status": "updated"}


# ══════════════════════════════════════════════════════════════════════════
# COMPLIANCE — Full Framework Coverage
# ══════════════════════════════════════════════════════════════════════════

@router.get("/compliance")
async def get_compliance_settings(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    settings = await _get_org_settings(org_id, db)
    return settings.get("compliance", ComplianceSettings().model_dump())


@router.put("/compliance")
async def update_compliance_settings(
    compliance: ComplianceSettings,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.get("org_id"))
    await _save_org_settings(org_id, "compliance", compliance.model_dump(), db)
    logger.info("compliance_updated", org=org_id,
                frameworks=[k for k, v in compliance.model_dump().items() if k.endswith("_enabled") and v])
    return {"status": "updated"}


# ── All settings (single fetch) ──

@router.get("")
async def get_all_settings(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all settings in one call — from DB, not memory."""
    org_id = str(current_user.get("org_id"))
    user_id = current_user.get("user_id")

    # User profile
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    # Org
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()

    settings = await _get_org_settings(org_id, db)

    return {
        "profile": {
            "email": user.email if user else "",
            "full_name": user.full_name if user else "",
            "role": user.role if user else "",
            "created_at": user.created_at.isoformat() if user and user.created_at else None,
        },
        "organization": {
            "id": str(org.id) if org else "",
            "name": org.name if org else "",
            "slug": org.slug if org else "",
            "plan": org.plan if org else "free",
        },
        **settings,
    }
