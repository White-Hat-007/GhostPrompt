"""
GhostPrompt — Compliance Framework Base Architecture

Shared abstractions for all 9 compliance frameworks. Every framework module
inherits from ComplianceFramework and produces ComplianceSnapshot objects
that guarantee PDF/CSV/JSON exports always derive from identical data.

CRITICAL LEGAL FRAMING:
- NIST AI RMF, ISO 42001, EU AI Act: self-assessable — alignment score is meaningful
- SOC 2 Type II, PCI DSS: NOT self-certifiable — GhostPrompt generates technical
  control evidence for auditors, never claims compliance
- GDPR, CCPA, DPDPA: legal frameworks — GhostPrompt maps technical controls to
  legal articles as evidence, never claims legal compliance
- HIPAA: "Technical Safeguards Alignment", never "HIPAA Certified"
"""

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONTROL STATUS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ControlStatus(str, Enum):
    SATISFIED = "SATISFIED"
    PARTIAL = "PARTIAL"
    GAP = "GAP"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONTROL REQUIREMENT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class ControlRequirement:
    """A single compliance control/requirement mapped to GhostPrompt evidence."""
    control_id: str
    title: str
    requirement_text: str
    ghostprompt_evidence_sources: list[str]
    status: ControlStatus
    evidence_type: str = "automated"
    gap_note: str | None = None
    remediation: str | None = None
    requires_external_audit: bool = False  # True for SOC2, PCI DSS controls
    last_verified: str = ""

    def __post_init__(self):
        if not self.last_verified:
            self.last_verified = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "requirement": self.requirement_text,
            "status": self.status.value,
            "evidence_sources": self.ghostprompt_evidence_sources,
            "evidence_type": self.evidence_type,
            "gap_note": self.gap_note,
            "remediation": self.remediation,
            "requires_external_audit": self.requires_external_audit,
            "last_verified": self.last_verified,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# COMPLIANCE SNAPSHOT — Immutable Point-in-Time Data
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class ComplianceSnapshot:
    """
    Single immutable snapshot at a point in time.
    PDF, CSV, and JSON exports for the same request MUST all derive from
    this same snapshot object — never re-query live data per export format.
    """
    tenant_id: str
    framework_id: str
    framework_name: str
    framework_version: str
    generated_at: str
    snapshot_id: str
    overall_score: float
    total_controls: int
    satisfied: int
    partial: int
    gap: int
    not_applicable: int
    sections: dict  # {section_name: {title, controls: [ControlRequirement], score}}
    gaps: list[dict]
    disclaimer: str
    hmac_signature: str = ""

    def to_dict(self) -> dict:
        sections_out = {}
        for sec_name, sec_data in self.sections.items():
            controls_out = {}
            for ctrl in sec_data.get("controls", []):
                if isinstance(ctrl, ControlRequirement):
                    controls_out[ctrl.control_id] = ctrl.to_dict()
                elif isinstance(ctrl, dict):
                    controls_out[ctrl.get("control_id", "")] = ctrl
            sections_out[sec_name] = {
                "title": sec_data.get("title", sec_name),
                "controls": controls_out,
                "score": sec_data.get("score", 0),
            }

        return {
            "report_id": self.snapshot_id,
            "tenant_id": self.tenant_id,
            "framework": self.framework_name,
            "framework_id": self.framework_id,
            "framework_version": self.framework_version,
            "generated_at": self.generated_at,
            "overall_score": self.overall_score,
            "total_controls": self.total_controls,
            "satisfied": self.satisfied,
            "partial": self.partial,
            "gap": self.gap,
            "not_applicable": self.not_applicable,
            "sections": sections_out,
            "gaps": self.gaps,
            "disclaimer": self.disclaimer,
            "hmac_signature": self.hmac_signature,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FRAMEWORK-SPECIFIC DISCLAIMERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DISCLAIMERS = {
    "nist_ai_rmf": (
        "This report documents GhostPrompt's technical control mapping to NIST AI RMF 1.0. "
        "It is evidence to support your organization's own risk management program, "
        "not a certification. GhostPrompt is not NIST certified."
    ),
    "iso_42001": (
        "This report documents GhostPrompt's technical control mapping to ISO/IEC 42001:2023. "
        "It is evidence to support your organization's ISO 42001 certification efforts. "
        "GhostPrompt is not itself ISO 42001 certified."
    ),
    "soc2_type2": (
        "IMPORTANT: This report provides technical control evidence for your organization's "
        "SOC 2 Type II audit. It is NOT a SOC 2 report and does NOT substitute for an audit "
        "opinion issued by a licensed CPA firm. SOC 2 Type II certification requires an "
        "independent audit over a real observation period (typically 3–12 months). "
        "This evidence package is designed to accelerate your audit by documenting "
        "GhostPrompt's continuous control operation."
    ),
    "pci_dss": (
        "IMPORTANT: This report maps GhostPrompt's technical controls to PCI DSS v4.0 requirements. "
        "It is NOT a PCI DSS certification. PCI DSS compliance above certain transaction volumes "
        "requires assessment by a Qualified Security Assessor (QSA). Controls not relevant to "
        "GhostPrompt's scope are honestly marked NOT_APPLICABLE. This evidence package supports "
        "your organization's PCI DSS compliance program for AI system security specifically."
    ),
    "gdpr": (
        "This report maps GhostPrompt's technical controls to GDPR articles as evidence for "
        "your organization's data protection compliance program. It does NOT constitute legal "
        "compliance advice. GDPR compliance requires legal review of your entire organization's "
        "data processing activities, not just technical controls."
    ),
    "eu_ai_act": (
        "This report maps GhostPrompt's technical controls to EU AI Act requirements. "
        "The EU AI Act is a self-assessable framework for most risk tiers — this alignment "
        "score is meaningful evidence. However, high-risk AI systems may require conformity "
        "assessment by notified bodies."
    ),
    "hipaa": (
        "This report documents GhostPrompt's alignment with HIPAA Technical Safeguards "
        "(45 CFR 164.312). There is no federal 'HIPAA Certification' — this report provides "
        "technical evidence for your organization's HIPAA compliance program. Full HIPAA "
        "compliance requires administrative, physical, and organizational safeguards beyond "
        "technical controls."
    ),
    "ccpa": (
        "This report maps GhostPrompt's technical controls to CCPA/CPRA requirements as "
        "evidence for your organization's privacy compliance program. It does NOT constitute "
        "legal compliance. CCPA/CPRA compliance requires legal review of your organization's "
        "entire data handling practices."
    ),
    "dpdpa": (
        "This report maps GhostPrompt's technical controls to India's Digital Personal Data "
        "Protection Act 2023 (DPDPA) requirements. It does NOT constitute legal compliance. "
        "DPDPA compliance requires organizational-level implementation of consent management, "
        "Data Principal rights processes, and Data Protection Board registration."
    ),
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# COMPLIANCE FRAMEWORK — Abstract Base Class
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ComplianceFramework(ABC):
    """
    Base class for all compliance framework implementations.
    Every framework module inherits from this and implements the control taxonomy.
    """

    framework_id: str = ""
    framework_name: str = ""
    framework_version: str = ""

    @property
    def disclaimer(self) -> str:
        return DISCLAIMERS.get(self.framework_id, DISCLAIMERS["nist_ai_rmf"])

    @abstractmethod
    def get_control_taxonomy(self) -> dict[str, dict]:
        """
        Returns the full official taxonomy for this framework.
        Format: {section_id: {title: str, controls: [ControlRequirement]}}
        """
        ...

    def generate_snapshot(self, tenant_id: str) -> ComplianceSnapshot:
        """
        Generates ONE immutable snapshot object at a single point in time.
        PDF, CSV, and JSON exports for the same request MUST all derive from
        this same snapshot — never re-query live data per export format.
        """
        taxonomy = self.get_control_taxonomy()
        now = datetime.now(timezone.utc).isoformat()
        snapshot_id = str(uuid.uuid4())

        total = 0
        satisfied = 0
        partial = 0
        gap = 0
        not_applicable = 0
        gaps = []
        sections = {}

        for section_id, section_data in taxonomy.items():
            controls = section_data.get("controls", [])
            sec_total = 0
            sec_satisfied = 0
            sec_partial = 0

            for ctrl in controls:
                total += 1
                sec_total += 1
                if ctrl.status == ControlStatus.SATISFIED:
                    satisfied += 1
                    sec_satisfied += 1
                elif ctrl.status == ControlStatus.PARTIAL:
                    partial += 1
                    sec_partial += 1
                elif ctrl.status == ControlStatus.NOT_APPLICABLE:
                    not_applicable += 1
                else:
                    gap += 1
                    gaps.append({
                        "id": ctrl.control_id,
                        "section": section_id,
                        "title": ctrl.title,
                        "requirement": ctrl.requirement_text,
                        "status": ctrl.status.value,
                        "remediation": ctrl.remediation or "No remediation guidance available.",
                    })

            # Score: SATISFIED counts full, PARTIAL counts half, NOT_APPLICABLE excluded
            scoreable = sec_total - sum(1 for c in controls if c.status == ControlStatus.NOT_APPLICABLE)
            sec_score = round(
                ((sec_satisfied + sec_partial * 0.5) / scoreable) * 100, 1
            ) if scoreable > 0 else 100.0

            sections[section_id] = {
                "title": section_data.get("title", section_id),
                "controls": controls,
                "score": sec_score,
            }

        # Overall score excludes NOT_APPLICABLE
        scoreable_total = total - not_applicable
        overall_score = round(
            ((satisfied + partial * 0.5) / scoreable_total) * 100, 1
        ) if scoreable_total > 0 else 100.0

        return ComplianceSnapshot(
            tenant_id=tenant_id,
            framework_id=self.framework_id,
            framework_name=self.framework_name,
            framework_version=self.framework_version,
            generated_at=now,
            snapshot_id=snapshot_id,
            overall_score=overall_score,
            total_controls=total,
            satisfied=satisfied,
            partial=partial,
            gap=gap,
            not_applicable=not_applicable,
            sections=sections,
            gaps=gaps,
            disclaimer=self.disclaimer,
        )
