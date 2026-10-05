"""
GhostPrompt — Unified Compliance Engine

Central engine that produces framework-specific reports and cross-framework
governance maturity assessments across all 9 supported frameworks.

Supported frameworks:
  - NIST AI RMF 1.0
  - ISO/IEC 42001:2023
  - SOC 2 Type II
  - PCI DSS v4.0
  - GDPR
  - EU AI Act
  - HIPAA
  - CCPA/CPRA
  - DPDPA (India 2023)

Architecture:
  - All frameworks inherit from ComplianceFramework base class
  - generate_snapshot() produces a ComplianceSnapshot for any framework
  - PDF/CSV/JSON exports all derive from ONE snapshot (consistency guarantee)
  - HMAC-SHA256 signing via shared ComplianceSigningEngine

DISCLAIMER: GhostPrompt generates compliance evidence. It is NOT itself
certified under any of these frameworks.
"""

import csv
import io
import json
from datetime import datetime, timezone

from app.compliance.ccpa import ccpa_framework
from app.compliance.dpdpa import dpdpa_framework
from app.compliance.eu_ai_act import eu_ai_act_framework
from app.compliance.framework_base import (
    DISCLAIMERS,
    ComplianceFramework,
    ComplianceSnapshot,
    ControlRequirement,
)
from app.compliance.gdpr import gdpr_framework
from app.compliance.hipaa import hipaa_framework
from app.compliance.iso_42001 import ISO_42001_MAPPING, get_iso_summary

# ── Import all 9 framework singletons ──
from app.compliance.nist_ai_rmf import NIST_AI_RMF_MAPPING, get_nist_summary
from app.compliance.pci_dss import pci_dss_framework
from app.compliance.signing_engine import signing_engine
from app.compliance.soc2_type2 import soc2_type2_framework

# ── Framework registry (new framework modules that use ComplianceFramework base) ──
FRAMEWORK_REGISTRY: dict[str, ComplianceFramework] = {
    "soc2_type2": soc2_type2_framework,
    "pci_dss": pci_dss_framework,
    "gdpr": gdpr_framework,
    "eu_ai_act": eu_ai_act_framework,
    "hipaa": hipaa_framework,
    "ccpa": ccpa_framework,
    "dpdpa": dpdpa_framework,
}

# ── All 9 framework IDs ──
ALL_FRAMEWORK_IDS = [
    "nist_ai_rmf", "iso_42001",
    "soc2_type2", "pci_dss",
    "gdpr", "eu_ai_act",
    "hipaa", "ccpa", "dpdpa",
]


class UnifiedComplianceEngine:
    """
    Central compliance engine that produces framework-specific reports
    and cross-framework governance maturity assessments for all 9 frameworks.
    """

    SUPPORTED_FRAMEWORKS = ALL_FRAMEWORK_IDS

    def __init__(self):
        self._hmac_key = b"ghostprompt-compliance-report-integrity-v1"

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SNAPSHOT-BASED GENERATION (new architecture)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def generate_framework_snapshot(self, framework_id: str, tenant_id: str) -> ComplianceSnapshot:
        """
        Generate a ComplianceSnapshot for any of the 7 new frameworks.
        NIST and ISO use their own legacy report generators (below) which
        produce equivalent data shapes.
        """
        if framework_id not in FRAMEWORK_REGISTRY:
            raise ValueError(f"Unknown framework: {framework_id}. Use one of: {list(FRAMEWORK_REGISTRY.keys())}")

        framework = FRAMEWORK_REGISTRY[framework_id]
        snapshot = framework.generate_snapshot(tenant_id)

        # Sign the snapshot
        snapshot.hmac_signature = signing_engine.sign_snapshot(snapshot)
        return snapshot

    def generate_any_report(self, framework_id: str, tenant_id: str) -> dict:
        """
        Generate a report dict for ANY of the 9 frameworks.
        Returns a consistent shape regardless of framework.
        """
        if framework_id == "nist_ai_rmf":
            return self.generate_nist_report(tenant_id)
        elif framework_id == "iso_42001":
            return self.generate_iso_report(tenant_id)
        else:
            snapshot = self.generate_framework_snapshot(framework_id, tenant_id)
            return signing_engine.sign_json_payload(snapshot)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CSV EXPORT
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def generate_csv(self, framework_id: str, tenant_id: str) -> str:
        """Generate a signed CSV export for any framework."""
        if framework_id in ("nist_ai_rmf", "iso_42001"):
            # Legacy frameworks — build CSV from their report dicts
            report = self.generate_any_report(framework_id, tenant_id)
            return self._legacy_csv(report, framework_id)

        snapshot = self.generate_framework_snapshot(framework_id, tenant_id)
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "Section", "Control ID", "Title", "Requirement",
            "Status", "Evidence Sources", "Evidence Type",
            "Requires External Audit", "Last Verified"
        ])

        for section_id, section_data in snapshot.sections.items():
            for ctrl in section_data.get("controls", []):
                if isinstance(ctrl, ControlRequirement):
                    writer.writerow([
                        section_id,
                        ctrl.control_id,
                        ctrl.title,
                        ctrl.requirement_text,
                        ctrl.status.value,
                        " | ".join(ctrl.ghostprompt_evidence_sources),
                        ctrl.evidence_type,
                        str(ctrl.requires_external_audit),
                        ctrl.last_verified,
                    ])

        csv_body = output.getvalue()
        return signing_engine.sign_csv_export(csv_body, snapshot)

    def _legacy_csv(self, report: dict, framework_id: str) -> str:
        """Build CSV from legacy NIST/ISO report dicts."""
        output = io.StringIO()
        writer = csv.writer(output)

        if framework_id == "nist_ai_rmf":
            writer.writerow([
                "Function", "Subcategory", "Requirement", "Status",
                "Evidence Sources", "Evidence Type", "Last Verified"
            ])
            for func_name, func_data in report.get("functions", {}).items():
                for sub_id, sub in func_data.get("subcategories", {}).items():
                    writer.writerow([
                        func_name, sub_id,
                        sub.get("requirement", ""),
                        sub.get("status", ""),
                        " | ".join(sub.get("evidence_sources", [])),
                        sub.get("evidence_type", ""),
                        sub.get("last_verified", ""),
                    ])
        elif framework_id == "iso_42001":
            writer.writerow([
                "Clause", "Requirement ID", "Requirement", "Status",
                "Evidence Sources", "Last Verified"
            ])
            for clause_id, clause_data in report.get("clauses", {}).items():
                for req_id, req in clause_data.get("requirements", {}).items():
                    writer.writerow([
                        clause_id, req_id,
                        req.get("requirement", ""),
                        req.get("status", ""),
                        " | ".join(req.get("evidence_sources", [])),
                        req.get("last_verified", ""),
                    ])

        csv_body = output.getvalue()

        # Create a minimal snapshot for signing
        import uuid

        from app.compliance.framework_base import ComplianceSnapshot
        snap = ComplianceSnapshot(
            tenant_id="legacy",
            framework_id=framework_id,
            framework_name=report.get("framework", ""),
            framework_version="",
            generated_at=report.get("generated_at", ""),
            snapshot_id=report.get("report_id", str(uuid.uuid4())),
            overall_score=report.get("overall_alignment_score", report.get("overall_readiness_score", 0)),
            total_controls=0, satisfied=0, partial=0, gap=0, not_applicable=0,
            sections={}, gaps=[], disclaimer="",
        )
        return signing_engine.sign_csv_export(csv_body, snap)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # NIST AI RMF Report (legacy, kept for backward compatibility)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def generate_nist_report(self, tenant_id: str) -> dict:
        """Generate full NIST AI RMF 1.0 compliance evidence report."""
        import uuid
        summary = get_nist_summary()
        functions = {}
        gaps = []

        for func_name, func_data in NIST_AI_RMF_MAPPING.items():
            subcats = {}
            for subcat_id, subcat in func_data["subcategories"].items():
                subcats[subcat_id] = {
                    "requirement": subcat["requirement"],
                    "status": subcat["status"],
                    "evidence_sources": subcat["ghostprompt_evidence"],
                    "evidence_type": subcat.get("evidence_type", "manual"),
                    "last_verified": datetime.now(timezone.utc).isoformat(),
                }
                if subcat["status"] != "SATISFIED":
                    gaps.append({
                        "id": subcat_id,
                        "function": func_name,
                        "requirement": subcat["requirement"],
                        "status": subcat["status"],
                        "remediation": subcat.get("remediation", "No remediation guidance available."),
                    })

            functions[func_name] = {
                "description": func_data["description"],
                "subcategories": subcats,
                "score": summary["by_function"][func_name]["score"],
            }

        report = {
            "report_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "framework": "NIST AI RMF 1.0",
            "framework_id": "nist_ai_rmf",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_alignment_score": summary["overall_score"],
            "total_subcategories": summary["total_subcategories"],
            "satisfied": summary["satisfied"],
            "partial": summary["partial"],
            "gap": summary["gap"],
            "functions": functions,
            "gaps": gaps,
            "disclaimer": DISCLAIMERS["nist_ai_rmf"],
        }

        report["hmac_signature"] = self._sign_report(report)
        return report

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # ISO 42001 Report (legacy, kept for backward compatibility)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def generate_iso_report(self, tenant_id: str) -> dict:
        """Generate full ISO/IEC 42001:2023 compliance readiness report."""
        import uuid
        summary = get_iso_summary()
        clauses = {}
        gaps = []

        for clause_id, clause_data in ISO_42001_MAPPING.items():
            reqs = {}
            for req_id, req in clause_data["requirements"].items():
                reqs[req_id] = {
                    "requirement": req["requirement"],
                    "status": req["status"],
                    "evidence_sources": req["ghostprompt_evidence"],
                    "last_verified": datetime.now(timezone.utc).isoformat(),
                }
                if req["status"] != "SATISFIED":
                    gaps.append({
                        "id": req_id,
                        "clause": clause_id,
                        "requirement": req["requirement"],
                        "status": req["status"],
                        "remediation": req.get("remediation", "No remediation guidance available."),
                    })

            clauses[clause_id] = {
                "title": clause_data["title"],
                "requirements": reqs,
                "score": summary["by_clause"][clause_id]["score"],
            }

        report = {
            "report_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "framework": "ISO/IEC 42001:2023",
            "framework_id": "iso_42001",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_readiness_score": summary["overall_score"],
            "total_requirements": summary["total_requirements"],
            "satisfied": summary["satisfied"],
            "partial": summary["partial"],
            "gap": summary["gap"],
            "clauses": clauses,
            "gaps": gaps,
            "disclaimer": DISCLAIMERS["iso_42001"],
        }

        report["hmac_signature"] = self._sign_report(report)
        return report

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CROSS-FRAMEWORK GOVERNANCE SUMMARY (all 9)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def get_cross_framework_summary(self, tenant_id: str) -> dict:
        """Summary scores across all 9 supported frameworks."""
        nist = get_nist_summary()
        iso = get_iso_summary()

        frameworks = {
            "nist_ai_rmf": {
                "name": "NIST AI RMF 1.0",
                "score": nist["overall_score"],
                "satisfied": nist["satisfied"],
                "partial": nist["partial"],
                "gap": nist["gap"],
                "total": nist["total_subcategories"],
            },
            "iso_42001": {
                "name": "ISO/IEC 42001:2023",
                "score": iso["overall_score"],
                "satisfied": iso["satisfied"],
                "partial": iso["partial"],
                "gap": iso["gap"],
                "total": iso["total_requirements"],
            },
        }

        # Add all 7 new frameworks from registry
        for fw_id, fw in FRAMEWORK_REGISTRY.items():
            snapshot = fw.generate_snapshot(tenant_id)
            frameworks[fw_id] = {
                "name": fw.framework_name,
                "score": snapshot.overall_score,
                "satisfied": snapshot.satisfied,
                "partial": snapshot.partial,
                "gap": snapshot.gap,
                "not_applicable": snapshot.not_applicable,
                "total": snapshot.total_controls,
                "disclaimer": snapshot.disclaimer,
            }

        scores = [fw.get("score", 0) for fw in frameworks.values()]
        maturity = round(sum(scores) / len(scores), 1) if scores else 0

        return {
            "tenant_id": tenant_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "frameworks": frameworks,
            "overall_governance_maturity": maturity,
            "total_frameworks": len(frameworks),
            "disclaimer": (
                "GhostPrompt generates compliance evidence across 9 frameworks. "
                "It is NOT certified under any of these frameworks. These scores "
                "document technical control alignment to support your organization's "
                "own compliance efforts."
            ),
        }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # ALL GAPS (across all 9)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def get_all_gaps(self, tenant_id: str) -> dict:
        """Get all compliance gaps across all 9 frameworks."""
        all_gaps = {}
        total = 0

        # NIST and ISO (legacy format)
        nist_report = self.generate_nist_report(tenant_id)
        iso_report = self.generate_iso_report(tenant_id)
        all_gaps["nist_ai_rmf"] = nist_report.get("gaps", [])
        all_gaps["iso_42001"] = iso_report.get("gaps", [])
        total += len(all_gaps["nist_ai_rmf"]) + len(all_gaps["iso_42001"])

        # New frameworks
        for fw_id, fw in FRAMEWORK_REGISTRY.items():
            snapshot = fw.generate_snapshot(tenant_id)
            all_gaps[fw_id] = snapshot.gaps
            total += len(snapshot.gaps)

        return {
            "tenant_id": tenant_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gaps_by_framework": all_gaps,
            "total_gaps": total,
        }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # HMAC Signing (legacy, kept for backward compatibility)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _sign_report(self, report: dict) -> str:
        """HMAC-SHA256 sign a report for tamper evidence."""
        import hashlib
        import hmac
        serializable = {k: v for k, v in report.items() if k != "hmac_signature"}
        payload = json.dumps(serializable, sort_keys=True, default=str)
        return hmac.new(self._hmac_key, payload.encode(), hashlib.sha256).hexdigest()


# Singleton
unified_compliance_engine = UnifiedComplianceEngine()
