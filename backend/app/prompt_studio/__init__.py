"""
GhostPrompt Prompt Engineering Studio

Prompt Registry, versioning, A/B testing, security scanning, variable injection.
"""

import uuid
import time
import re
import hashlib
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum


class PromptStatus(str, Enum):
    DRAFT = "draft"
    STAGING = "staging"
    PRODUCTION = "production"
    ARCHIVED = "archived"


@dataclass
class PromptVersion:
    version_id: str
    version_number: int
    content: str
    creator: str
    status: PromptStatus = PromptStatus.DRAFT
    variables: list = field(default_factory=list)
    security_scan: dict = field(default_factory=dict)
    test_results: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "version_id": self.version_id,
            "version_number": self.version_number,
            "content": self.content,
            "creator": self.creator,
            "status": self.status.value,
            "variables": self.variables,
            "security_scan": self.security_scan,
            "test_results": self.test_results,
            "created_at": self.created_at,
        }


@dataclass
class PromptTemplate:
    prompt_id: str
    tenant_id: str
    name: str
    description: str = ""
    template_type: str = "system"  # system, user, few_shot
    versions: list = field(default_factory=list)
    active_version: int = 0
    usage_count: int = 0
    created_at: float = field(default_factory=time.time)

    def get_active_version(self) -> Optional[PromptVersion]:
        for v in self.versions:
            if v.version_number == self.active_version:
                return v
        return self.versions[-1] if self.versions else None

    def to_dict(self) -> dict:
        active = self.get_active_version()
        return {
            "prompt_id": self.prompt_id,
            "name": self.name,
            "description": self.description,
            "template_type": self.template_type,
            "active_version": self.active_version,
            "total_versions": len(self.versions),
            "usage_count": self.usage_count,
            "active_content": active.content if active else "",
            "variables": active.variables if active else [],
            "security_scan": active.security_scan if active else {},
            "created_at": self.created_at,
        }


@dataclass
class ABExperiment:
    experiment_id: str
    prompt_id: str
    variant_a_version: int
    variant_b_version: int
    traffic_split: float = 50.0  # % to variant A
    metrics_a: dict = field(default_factory=lambda: {"requests": 0, "avg_quality": 0, "total_quality": 0})
    metrics_b: dict = field(default_factory=lambda: {"requests": 0, "avg_quality": 0, "total_quality": 0})
    is_active: bool = True
    min_samples: int = 100
    created_at: float = field(default_factory=time.time)

    def select_variant(self) -> int:
        import random
        return self.variant_a_version if random.random() * 100 < self.traffic_split else self.variant_b_version

    def record_quality(self, version: int, quality_score: float):
        target = self.metrics_a if version == self.variant_a_version else self.metrics_b
        target["requests"] += 1
        target["total_quality"] += quality_score
        target["avg_quality"] = target["total_quality"] / target["requests"]
        self._check_significance()

    def _check_significance(self):
        a, b = self.metrics_a, self.metrics_b
        if a["requests"] >= self.min_samples and b["requests"] >= self.min_samples:
            if abs(a["avg_quality"] - b["avg_quality"]) > 0.1:
                self.is_active = False

    def get_status(self) -> dict:
        winner = None
        if not self.is_active:
            winner = "A" if self.metrics_a["avg_quality"] > self.metrics_b["avg_quality"] else "B"
        return {
            "experiment_id": self.experiment_id,
            "is_active": self.is_active,
            "variant_a": {"version": self.variant_a_version, **self.metrics_a},
            "variant_b": {"version": self.variant_b_version, **self.metrics_b},
            "winner": winner,
        }


# ── Security Scanner ──
SECRET_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Token"),
    (r'xoxb-[0-9]{10,}', "Slack Bot Token"),
    (r'password\s*[:=]\s*["\']?[^\s"\']+', "Hardcoded Password"),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email Address (PII)"),
    (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', "Phone Number (PII)"),
    (r'\b\d{3}-\d{2}-\d{4}\b', "SSN (PII)"),
]

WEAK_INSTRUCTIONS = [
    "ignore previous", "disregard", "forget everything", "you are now",
    "pretend you are", "act as if", "bypass", "override",
    "do not follow", "ignore all rules", "no restrictions",
]


def scan_prompt_security(content: str) -> dict:
    issues = []
    # Check for secrets
    for pattern, desc in SECRET_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            issues.append({"type": "secret", "description": desc, "severity": "critical", "count": len(matches)})
    # Check for weak instructions
    content_lower = content.lower()
    for phrase in WEAK_INSTRUCTIONS:
        if phrase in content_lower:
            issues.append({"type": "weak_instruction", "description": f"Contains '{phrase}' which could be exploited", "severity": "high"})
    # Check for missing safety instructions
    safety_keywords = ["safe", "appropriate", "harmful", "refuse", "cannot", "should not"]
    has_safety = any(kw in content_lower for kw in safety_keywords)
    if not has_safety and len(content) > 100:
        issues.append({"type": "missing_safety", "description": "No safety guardrail instructions detected", "severity": "medium"})
    return {
        "passed": len(issues) == 0,
        "issues": issues,
        "scanned_at": time.time(),
        "risk_level": "critical" if any(i["severity"] == "critical" for i in issues) else "high" if any(i["severity"] == "high" for i in issues) else "medium" if issues else "safe",
    }


class PromptStudio:
    """Prompt Engineering Studio — registry, versioning, A/B testing."""

    def __init__(self):
        self._prompts: dict[str, PromptTemplate] = {}
        self._tenant_prompts: dict[str, list[str]] = defaultdict(list)
        self._experiments: dict[str, ABExperiment] = {}
        self._variables: dict[str, dict] = defaultdict(dict)

    def create_prompt(self, tenant_id: str, name: str, content: str, creator: str,
                      description: str = "", template_type: str = "system") -> dict:
        prompt_id = f"sp_{uuid.uuid4().hex[:12]}"
        variables = re.findall(r'\{\{(\w+)\}\}', content)
        security = scan_prompt_security(content)
        version = PromptVersion(
            version_id=uuid.uuid4().hex[:16], version_number=1,
            content=content, creator=creator, variables=variables,
            security_scan=security,
        )
        template = PromptTemplate(
            prompt_id=prompt_id, tenant_id=tenant_id, name=name,
            description=description, template_type=template_type,
            versions=[version], active_version=1,
        )
        self._prompts[prompt_id] = template
        self._tenant_prompts[tenant_id].append(prompt_id)
        return template.to_dict()

    def update_prompt(self, prompt_id: str, content: str, creator: str) -> dict:
        template = self._prompts.get(prompt_id)
        if not template:
            return {"error": "Prompt not found"}
        variables = re.findall(r'\{\{(\w+)\}\}', content)
        security = scan_prompt_security(content)
        new_version = PromptVersion(
            version_id=uuid.uuid4().hex[:16],
            version_number=len(template.versions) + 1,
            content=content, creator=creator, variables=variables,
            security_scan=security,
        )
        template.versions.append(new_version)
        return template.to_dict()

    def deploy_version(self, prompt_id: str, version_number: int, status: PromptStatus = PromptStatus.PRODUCTION) -> dict:
        template = self._prompts.get(prompt_id)
        if not template:
            return {"error": "Prompt not found"}
        for v in template.versions:
            if v.version_number == version_number:
                v.status = status
                if status == PromptStatus.PRODUCTION:
                    template.active_version = version_number
                return {"status": "deployed", "version": version_number}
        return {"error": "Version not found"}

    def resolve_prompt(self, prompt_id: str, variables: dict = None) -> Optional[str]:
        template = self._prompts.get(prompt_id)
        if not template:
            return None
        active = template.get_active_version()
        if not active:
            return None
        template.usage_count += 1
        content = active.content
        if variables:
            for key, value in variables.items():
                content = content.replace(f"{{{{{key}}}}}", str(value))
        # Also use tenant variable store
        tenant_vars = self._variables.get(template.tenant_id, {})
        for key, value in tenant_vars.items():
            content = content.replace(f"{{{{{key}}}}}", str(value))
        return content

    def set_variables(self, tenant_id: str, variables: dict):
        self._variables[tenant_id].update(variables)

    def list_prompts(self, tenant_id: str) -> list[dict]:
        ids = self._tenant_prompts.get(tenant_id, [])
        return [self._prompts[pid].to_dict() for pid in ids if pid in self._prompts]

    def get_prompt(self, prompt_id: str) -> Optional[dict]:
        t = self._prompts.get(prompt_id)
        if not t:
            return None
        result = t.to_dict()
        result["versions"] = [v.to_dict() for v in t.versions]
        return result

    def get_version_diff(self, prompt_id: str, v1: int, v2: int) -> dict:
        template = self._prompts.get(prompt_id)
        if not template:
            return {"error": "Prompt not found"}
        ver1 = ver2 = None
        for v in template.versions:
            if v.version_number == v1: ver1 = v
            if v.version_number == v2: ver2 = v
        if not ver1 or not ver2:
            return {"error": "Version not found"}
        return {"v1": {"version": v1, "content": ver1.content}, "v2": {"version": v2, "content": ver2.content}}

    # ── A/B Testing ──
    def create_experiment(self, prompt_id: str, version_a: int, version_b: int, split: float = 50.0) -> dict:
        exp_id = f"exp_{uuid.uuid4().hex[:8]}"
        exp = ABExperiment(experiment_id=exp_id, prompt_id=prompt_id, variant_a_version=version_a, variant_b_version=version_b, traffic_split=split)
        self._experiments[exp_id] = exp
        return exp.get_status()

    def get_experiment(self, experiment_id: str) -> Optional[dict]:
        exp = self._experiments.get(experiment_id)
        return exp.get_status() if exp else None

    def list_experiments(self, prompt_id: str = None) -> list[dict]:
        exps = self._experiments.values()
        if prompt_id:
            exps = [e for e in exps if e.prompt_id == prompt_id]
        return [e.get_status() for e in exps]


# Singleton
prompt_studio = PromptStudio()
