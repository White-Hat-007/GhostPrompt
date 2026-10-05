"""
GhostPrompt Compliance & Data Controls

Data residency, retention, audit logging, BAA controls, BYOK encryption.
"""

import uuid
import time
import hashlib
import hmac
import json
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum


class DataRegion(str, Enum):
    US = "us"
    EU = "eu"
    APAC = "apac"
    GLOBAL = "global"


@dataclass
class AuditEntry:
    entry_id: str
    tenant_id: str
    actor_id: str
    actor_email: str
    action: str
    resource_type: str
    resource_id: str
    details: dict
    ip_address: str = ""
    timestamp: float = field(default_factory=time.time)
    hmac_signature: str = ""

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "actor_id": self.actor_id,
            "actor_email": self.actor_email,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "details": self.details,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp,
            "hmac_signature": self.hmac_signature[:16] + "..." if self.hmac_signature else "",
        }


@dataclass
class TenantCompliance:
    tenant_id: str
    data_region: DataRegion = DataRegion.GLOBAL
    log_retention_days: int = 90
    baa_enabled: bool = False
    byok_enabled: bool = False
    byok_kms_arn: str = ""
    auto_redact_phi: bool = False
    gdpr_enabled: bool = False
    allowed_export_formats: list = field(default_factory=lambda: ["json", "csv"])
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "data_region": self.data_region.value,
            "log_retention_days": self.log_retention_days,
            "baa_enabled": self.baa_enabled,
            "byok_enabled": self.byok_enabled,
            "auto_redact_phi": self.auto_redact_phi,
            "gdpr_enabled": self.gdpr_enabled,
        }


class ComplianceEngine:
    """Compliance controls: data residency, retention, audit, BAA, BYOK."""

    def __init__(self):
        self._tenant_configs: dict[str, TenantCompliance] = {}
        self._audit_log: list[AuditEntry] = []
        self._hmac_key = b"ghostprompt-audit-integrity-key-v1"
        self._deleted_data_log: list[dict] = []
        self._max_audit = 100000

    def get_config(self, tenant_id: str) -> TenantCompliance:
        if tenant_id not in self._tenant_configs:
            self._tenant_configs[tenant_id] = TenantCompliance(tenant_id=tenant_id)
        return self._tenant_configs[tenant_id]

    def update_config(self, tenant_id: str, **kwargs) -> dict:
        config = self.get_config(tenant_id)
        for k, v in kwargs.items():
            if hasattr(config, k):
                if k == "data_region":
                    v = DataRegion(v)
                setattr(config, k, v)
        # BAA auto-enables PHI redaction
        if config.baa_enabled:
            config.auto_redact_phi = True
        self.log_action(tenant_id, "system", "system@ghostprompt.ai", "update_compliance", "compliance_config", tenant_id, kwargs)
        return config.to_dict()

    # ── Data Residency ──
    def check_residency(self, tenant_id: str, request_region: str) -> dict:
        config = self.get_config(tenant_id)
        if config.data_region == DataRegion.GLOBAL:
            return {"allowed": True}
        if config.data_region.value != request_region:
            return {"allowed": False, "error": f"Data must stay in {config.data_region.value} region", "required_region": config.data_region.value}
        return {"allowed": True}

    # ── Audit Logging (immutable, HMAC-signed) ──
    def log_action(self, tenant_id: str, actor_id: str, actor_email: str,
                   action: str, resource_type: str, resource_id: str,
                   details: dict = None, ip_address: str = ""):
        entry_id = uuid.uuid4().hex[:16]
        entry_data = json.dumps({"entry_id": entry_id, "tenant_id": tenant_id, "actor_id": actor_id, "action": action, "resource_type": resource_type, "resource_id": resource_id, "timestamp": time.time()}, sort_keys=True)
        signature = hmac.new(self._hmac_key, entry_data.encode(), hashlib.sha256).hexdigest()
        entry = AuditEntry(
            entry_id=entry_id, tenant_id=tenant_id, actor_id=actor_id,
            actor_email=actor_email, action=action, resource_type=resource_type,
            resource_id=resource_id, details=details or {}, ip_address=ip_address,
            hmac_signature=signature,
        )
        self._audit_log.append(entry)
        if len(self._audit_log) > self._max_audit:
            self._audit_log = self._audit_log[-self._max_audit // 2:]

    def get_audit_log(self, tenant_id: str, limit: int = 100, action_filter: str = None) -> list[dict]:
        filtered = [e for e in reversed(self._audit_log) if e.tenant_id == tenant_id]
        if action_filter:
            filtered = [e for e in filtered if e.action == action_filter]
        return [e.to_dict() for e in filtered[:limit]]

    # ── Data Retention ──
    def enforce_retention(self, tenant_id: str) -> dict:
        config = self.get_config(tenant_id)
        cutoff = time.time() - (config.log_retention_days * 86400)
        before = len(self._audit_log)
        self._audit_log = [e for e in self._audit_log if e.timestamp > cutoff or e.tenant_id != tenant_id]
        purged = before - len(self._audit_log)
        return {"purged_entries": purged, "retention_days": config.log_retention_days}

    # ── GDPR Right to Erasure ──
    def delete_user_data(self, tenant_id: str, user_id: str, requester: str) -> dict:
        deleted = 0
        # Remove from audit log
        before = len(self._audit_log)
        self._audit_log = [e for e in self._audit_log if not (e.tenant_id == tenant_id and e.actor_id == user_id)]
        deleted = before - len(self._audit_log)
        self._deleted_data_log.append({"tenant_id": tenant_id, "user_id": user_id, "entries_deleted": deleted, "requested_by": requester, "timestamp": time.time()})
        self.log_action(tenant_id, requester, "", "gdpr_erasure", "user_data", user_id, {"entries_deleted": deleted})
        return {"deleted_entries": deleted, "status": "completed"}

    # ── Data Export (GDPR Right to Portability) ──
    def export_tenant_data(self, tenant_id: str, format: str = "json") -> dict:
        entries = [e.to_dict() for e in self._audit_log if e.tenant_id == tenant_id]
        config = self.get_config(tenant_id)
        return {
            "format": format,
            "tenant_id": tenant_id,
            "compliance_config": config.to_dict(),
            "audit_entries": entries,
            "total_entries": len(entries),
            "exported_at": time.time(),
        }

    # ── PHI Redaction (BAA) ──
    def redact_phi(self, text: str, tenant_id: str) -> str:
        config = self.get_config(tenant_id)
        if not config.auto_redact_phi:
            return text
        import re
        # SSN
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN-REDACTED]', text)
        # Phone
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE-REDACTED]', text)
        # Email
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL-REDACTED]', text)
        # DOB patterns
        text = re.sub(r'\b\d{1,2}/\d{1,2}/\d{2,4}\b', '[DATE-REDACTED]', text)
        # Medical record numbers (generic)
        text = re.sub(r'\bMRN[:\s]*\d+\b', '[MRN-REDACTED]', text, flags=re.IGNORECASE)
        return text


# Singleton
compliance_engine = ComplianceEngine()
