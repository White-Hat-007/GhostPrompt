"""
GhostPrompt — ISO/IEC 42001:2023 Compliance Mapping

Maps GhostPrompt's existing capabilities to the full ISO/IEC 42001 AI
Management System standard (Clauses 4–10 + Annex A Controls).

IMPORTANT: GhostPrompt generates compliance evidence to support your
organization's ISO 42001 certification efforts. GhostPrompt is NOT
itself ISO 42001 certified. This module maps technical controls to
the standard's requirements to accelerate your audit readiness.
"""



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ISO/IEC 42001:2023 — COMPLETE CLAUSE + ANNEX A MAPPING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ISO_42001_MAPPING = {
    "Clause 4": {
        "title": "Context of the Organization",
        "requirements": {
            "4.1": {
                "requirement": "Understanding the organization and its context regarding AI",
                "ghostprompt_evidence": [
                    "Per-tenant deployment configuration and workspace hierarchy",
                    "Multi-tenant isolation architecture",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "4.2": {
                "requirement": "Understanding the needs and expectations of interested parties",
                "ghostprompt_evidence": [
                    "RBAC roles: org_owner, org_admin, security_analyst, developer — each with defined expectations",
                    "Billing module: stakeholder cost visibility",
                    "SIEM integration: SOC team requirements addressed",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "4.3": {
                "requirement": "Determining the scope of the AI management system",
                "ghostprompt_evidence": [
                    "Policy scoping per workspace/tenant",
                    "Configurable detection engine enable/disable per tenant",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "4.4": {
                "requirement": "AI management system establishment, implementation, maintenance, and continual improvement",
                "ghostprompt_evidence": [
                    "Continuous learning pipeline from analyst feedback",
                    "Adaptive ML drift daemon for ongoing improvement",
                    "Red Team certification re-evaluation cycles",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
        },
    },
    "Clause 5": {
        "title": "Leadership",
        "requirements": {
            "5.1": {
                "requirement": "Leadership and commitment to the AI management system",
                "ghostprompt_evidence": [
                    "Org Owner role: exclusive access to billing, settings, and danger zone",
                    "Super Admin platform-wide oversight dashboard",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "5.2": {
                "requirement": "AI policy is established, communicated, and maintained",
                "ghostprompt_evidence": [
                    "Policy engine: per-category configurable actions (BLOCK/FLAG/REDACT/SANITIZE)",
                    "Content policy configuration per tenant",
                    "Prompt Studio security scanning policy",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "5.3": {
                "requirement": "Organizational roles, responsibilities, and authorities are assigned and communicated",
                "ghostprompt_evidence": [
                    "RBAC 7-role hierarchy with granular resource.action permissions",
                    "Custom roles with per-permission configuration",
                    "core/permissions.py — permission enforcement on every endpoint",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
        },
    },
    "Clause 6": {
        "title": "Planning",
        "requirements": {
            "6.1.1": {
                "requirement": "General considerations for actions to address risks and opportunities",
                "ghostprompt_evidence": [
                    "33 detection engines addressing 18 attack categories",
                    "THREAT_SCORE_THRESHOLD configurable risk appetite",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "6.1.2": {
                "requirement": "AI risk assessment process is defined and applied",
                "ghostprompt_evidence": [
                    "Threat severity scoring (LOW/MEDIUM/HIGH/CRITICAL)",
                    "Quantitative threat score 0.0–1.0 per detection",
                    "Red Team simulator: systematic risk assessment",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "6.1.3": {
                "requirement": "AI risk treatment process is defined",
                "ghostprompt_evidence": [
                    "Policy-based BLOCK/FLAG/REDACT/SANITIZE actions per risk category",
                    "Human-in-the-loop approval gates for high-risk actions",
                    "Kill switch for emergency deactivation",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "6.1.4": {
                "requirement": "AI risk treatment plan is established",
                "ghostprompt_evidence": [
                    "Per-tenant policy configuration with risk tolerance levels",
                    "STRICT/BALANCED/PERMISSIVE modes define treatment strategy",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "6.2": {
                "requirement": "AI objectives and planning to achieve them",
                "ghostprompt_evidence": [
                    "Red Team certification tier progression tracking",
                    "Detection accuracy improvement as measurable objective",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "6.3": {
                "requirement": "Planning of changes to the AI management system",
                "ghostprompt_evidence": [
                    "Model canary deployment pipeline (shadow → canary → promote)",
                    "Audit logging of all policy and configuration changes",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
        },
    },
    "Clause 7": {
        "title": "Support",
        "requirements": {
            "7.1": {
                "requirement": "Resources for the AI management system are determined and provided",
                "ghostprompt_evidence": [
                    "Billing module: compute resource tracking per tenant",
                    "Budget controls: spend caps, TPM/RPM limits",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "7.2": {
                "requirement": "Competence of persons managing AI systems is ensured",
                "ghostprompt_evidence": [
                    "RBAC role assignment requires admin/owner authorization with documented competency scope",
                    "Role descriptions document required competencies per permission level",
                    "Red Team certification tiers (Bronze/Silver/Gold/Platinum) serve as competency benchmarks",
                    "Permission-gated actions prevent unauthorized personnel from managing critical AI security functions",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "7.3": {
                "requirement": "Awareness of AI policies and management system requirements",
                "ghostprompt_evidence": [
                    "Super Admin broadcast system for platform-wide announcements",
                    "Policy documentation accessible to all authorized users",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "7.4": {
                "requirement": "Internal and external communication about AI risks and the AIMS",
                "ghostprompt_evidence": [
                    "Alerting system: email/Slack/PagerDuty on threshold breaches",
                    "SIEM forwarding for SOC team visibility",
                    "WebSocket real-time event streaming to dashboards",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "7.5.1": {
                "requirement": "Documented information required by the AIMS is controlled",
                "ghostprompt_evidence": [
                    "HMAC-signed immutable audit logs (compliance/__init__.py)",
                    "Prompt Studio version control for prompt templates",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "7.5.2": {
                "requirement": "Creating and updating documented information",
                "ghostprompt_evidence": [
                    "All audit log entries include timestamp, actor, action, and HMAC signature",
                    "Policy change history tracked in audit log",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "7.5.3": {
                "requirement": "Control of documented information (storage, retention, disposition)",
                "ghostprompt_evidence": [
                    "Configurable log retention policy per tenant (30/60/90/365 days)",
                    "Data residency controls (US/EU/APAC/GLOBAL)",
                    "GDPR right-to-erasure implementation",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
        },
    },
    "Clause 8": {
        "title": "Operation",
        "requirements": {
            "8.1": {
                "requirement": "Operational planning and control of the AI system lifecycle",
                "ghostprompt_evidence": [
                    "Shadow → canary → promote deployment pipeline for custom models",
                    "Feature flags for gradual rollout",
                    "Circuit breaker pattern for provider health management",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "8.2": {
                "requirement": "AI risk assessment is performed at planned intervals",
                "ghostprompt_evidence": [
                    "Weekly automated Red Team cycles",
                    "Adaptive ML drift monitoring (continuous)",
                    "One-click compliance report generation (on-demand)",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "8.3": {
                "requirement": "AI risk treatment is implemented according to the risk treatment plan",
                "ghostprompt_evidence": [
                    "33 active detection engines with configurable actions",
                    "Automatic BLOCK/FLAG/REDACT/SANITIZE based on policy",
                    "Real-time threat response latency < 15ms",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "8.4": {
                "requirement": "AI system impact assessment is conducted",
                "ghostprompt_evidence": [
                    "Severity × confidence impact scoring per detection event",
                    "Campaign-level impact assessment for coordinated attacks",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
        },
    },
    "Clause 9": {
        "title": "Performance Evaluation",
        "requirements": {
            "9.1": {
                "requirement": "Monitoring, measurement, analysis, and evaluation of the AIMS",
                "ghostprompt_evidence": [
                    "Datewise Analytics Dashboard with trend tracking",
                    "Detection accuracy metrics per engine",
                    "Drift daemon continuous performance monitoring",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "9.2": {
                "requirement": "Internal audit of the AI management system at planned intervals",
                "ghostprompt_evidence": [
                    "Automated Red Team simulator functions as continuous internal audit",
                    "One-click compliance report generation",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "9.3": {
                "requirement": "Management review of the AI management system at planned intervals",
                "ghostprompt_evidence": [
                    "Super Admin platform analytics dashboard",
                    "Weekly red team digest reports",
                    "Cross-framework compliance summary view",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
        },
    },
    "Clause 10": {
        "title": "Improvement",
        "requirements": {
            "10.1": {
                "requirement": "Continual improvement of the AI management system",
                "ghostprompt_evidence": [
                    "Continuous learning pipeline: false negatives feed retraining",
                    "Adaptive ML auto-tunes detection thresholds",
                    "Federated Threat Intel: cross-tenant zero-day sharing",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "10.2": {
                "requirement": "Nonconformity and corrective action",
                "ghostprompt_evidence": [
                    "Certification tier downgrade on regression triggers corrective action",
                    "Model rollback on quality decrease",
                    "Failed Red Team tests documented as nonconformities",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
        },
    },
    "Annex A": {
        "title": "AI System-Specific Controls",
        "requirements": {
            "A.5.2": {
                "requirement": "AI policy statement and objectives",
                "ghostprompt_evidence": [
                    "Per-tenant configurable AI security policy",
                    "STRICT/BALANCED/PERMISSIVE risk posture modes",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.5.3": {
                "requirement": "Roles and responsibilities for AI",
                "ghostprompt_evidence": [
                    "RBAC with 7 built-in roles + unlimited custom roles",
                    "Granular resource.action permission matrix",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.5.4": {
                "requirement": "AI system inventory",
                "ghostprompt_evidence": [
                    "1600+ model registry with provider → endpoint mapping",
                    "MCP Gateway tool registry with trust scoring",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.6.1.2": {
                "requirement": "Risk identification for AI systems",
                "ghostprompt_evidence": [
                    "18 attack category taxonomy with automated detection",
                    "Zero-Day detector for emerging risk identification",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.6.2.2": {
                "requirement": "AI system impact assessment is documented",
                "ghostprompt_evidence": [
                    "Severity + confidence scoring per detection event",
                    "Campaign-level coordinated attack assessment",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.6.2.3": {
                "requirement": "AI system risk treatment",
                "ghostprompt_evidence": [
                    "BLOCK/FLAG/REDACT/SANITIZE per category",
                    "Kill switch emergency deactivation",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.6.2.4": {
                "requirement": "Responsible AI considerations",
                "ghostprompt_evidence": [
                    "Content policy engine: hate speech, bias detection",
                    "Constitutional AI auditor for brand safety",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.6.2.5": {
                "requirement": "Documentation of AI system risk assessment and treatment",
                "ghostprompt_evidence": [
                    "HMAC-signed audit trail of all detection events",
                    "One-click compliance report generation",
                    "NIST AI RMF alignment report",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.7.2": {
                "requirement": "Data quality for AI systems",
                "ghostprompt_evidence": [
                    "RAG Sandbox content verification for document integrity",
                    "Training dataset deduplication and quality filtering",
                    "PII detection and redaction in training data",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.7.3": {
                "requirement": "Data provenance for AI systems",
                "ghostprompt_evidence": [
                    "Supply chain detector for model/data provenance verification",
                    "Audit trail of all data processing operations",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.7.4": {
                "requirement": "Data acquisition and preparation",
                "ghostprompt_evidence": [
                    "Training data ingestion pipeline with quality checks",
                    "BYOK encryption for sensitive training data",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.8.2": {
                "requirement": "AI system design documentation",
                "ghostprompt_evidence": [
                    "33 detection engines with documented architecture and purpose",
                    "API documentation (Swagger/ReDoc in development mode)",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.8.5": {
                "requirement": "AI system testing and validation",
                "ghostprompt_evidence": [
                    "Automated Red Team simulator with 30+ test scenarios",
                    "TruthfulQA/HaluEval benchmark validation",
                    "4-tier certification system",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.9.2": {
                "requirement": "AI system transparency and explainability",
                "ghostprompt_evidence": [
                    "Human-readable explainability output on every block decision",
                    "Per-engine confidence score breakdown",
                    "Detection rationale documentation in incident drawer",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.9.3": {
                "requirement": "AI system interpretability",
                "ghostprompt_evidence": [
                    "Threat breakdown: engine name, confidence score, severity",
                    "Attack-Flow STIX 2.1 incident documentation",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.9.4": {
                "requirement": "User awareness of AI system interaction",
                "ghostprompt_evidence": [
                    "Every scanned request receives clear action header (X-GhostPrompt-Action)",
                    "Dashboard displays real-time AI scanning status",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.10.2": {
                "requirement": "Processes for third-party AI components",
                "ghostprompt_evidence": [
                    "Supply chain detector for third-party evaluation",
                    "MCP Gateway trust scoring per tool provider",
                    "Provider health monitoring with circuit breakers",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
            "A.10.3": {
                "requirement": "Third-party monitoring and review",
                "ghostprompt_evidence": [
                    "Real-time provider latency/error rate monitoring",
                    "Automatic failover on third-party degradation",
                ],
                "status": "SATISFIED",
                "remediation": None,
            },
        },
    },
}


def get_iso_summary() -> dict:
    """Calculate summary statistics across all ISO 42001 requirements."""
    total = 0
    satisfied = 0
    partial = 0
    gap = 0
    by_clause = {}

    for clause_id, clause_data in ISO_42001_MAPPING.items():
        clause_total = len(clause_data["requirements"])
        clause_satisfied = sum(1 for r in clause_data["requirements"].values() if r["status"] == "SATISFIED")
        clause_partial = sum(1 for r in clause_data["requirements"].values() if r["status"] == "PARTIAL")
        clause_gap = clause_total - clause_satisfied - clause_partial

        by_clause[clause_id] = {
            "title": clause_data["title"],
            "total": clause_total,
            "satisfied": clause_satisfied,
            "partial": clause_partial,
            "gap": clause_gap,
            "score": round(((clause_satisfied + clause_partial * 0.5) / clause_total) * 100, 1) if clause_total else 0,
        }

        total += clause_total
        satisfied += clause_satisfied
        partial += clause_partial
        gap += clause_gap

    return {
        "framework": "ISO/IEC 42001:2023",
        "total_requirements": total,
        "satisfied": satisfied,
        "partial": partial,
        "gap": gap,
        "overall_score": round(((satisfied + partial * 0.5) / total) * 100, 1) if total else 0,
        "by_clause": by_clause,
    }
