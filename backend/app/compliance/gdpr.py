"""
GhostPrompt — GDPR Compliance Mapping

Maps GhostPrompt's technical controls to GDPR articles as evidence for
data protection compliance programs.

Covers: Art 5 (principles), Art 6 (lawful basis), Art 9 (special category data),
Art 17 (Right to Erasure), Art 20 (Right to Portability), Art 25 (privacy by design),
Art 30 (records of processing), Art 32 (security of processing), Art 33/34 (breach
notification), Art 35 (DPIA).

NOTE: This does NOT constitute legal compliance advice. GDPR compliance requires
legal review of your entire organization's data processing activities.

DIFFERENTIATOR: Includes DPIA auto-generator — since GhostPrompt processes personal
data via PII detection, it generates a starter DPIA based on observed PII categories.
"""

from app.compliance.framework_base import (
    ComplianceFramework,
    ControlRequirement,
    ControlStatus,
)


class GDPRFramework(ComplianceFramework):
    framework_id = "gdpr"
    framework_name = "GDPR"
    framework_version = "Regulation (EU) 2016/679"

    def get_control_taxonomy(self) -> dict[str, dict]:
        return {
            "Art 5 — Data Processing Principles": {
                "title": "Principles Relating to Processing of Personal Data",
                "controls": [
                    ControlRequirement(
                        control_id="Art-5.1(a)",
                        title="Lawfulness, Fairness, and Transparency",
                        requirement_text="Personal data shall be processed lawfully, fairly and in a transparent manner in relation to the data subject",
                        ghostprompt_evidence_sources=[
                            "Every blocked/flagged request includes human-readable explanation",
                            "Scan explainability provides transparency on automated decisions",
                            "Content policy engine blocks unfair/biased AI outputs",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="transparency",
                    ),
                    ControlRequirement(
                        control_id="Art-5.1(b)",
                        title="Purpose Limitation",
                        requirement_text="Personal data shall be collected for specified, explicit and legitimate purposes",
                        ghostprompt_evidence_sources=[
                            "PII detection processes personal data only for security scanning purposes",
                            "DLP vault stores tokenized references only — original data not retained",
                            "Per-tenant scoping ensures data processed only for that tenant's security",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_governance",
                    ),
                    ControlRequirement(
                        control_id="Art-5.1(c)",
                        title="Data Minimization",
                        requirement_text="Personal data shall be adequate, relevant and limited to what is necessary",
                        ghostprompt_evidence_sources=[
                            "PII redaction strips personal data before forwarding to LLM providers",
                            "Only threat scores and detection metadata retained — not full prompt content in default mode",
                            "Configurable log retention limits data storage duration",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_minimization",
                    ),
                    ControlRequirement(
                        control_id="Art-5.1(d)",
                        title="Accuracy",
                        requirement_text="Personal data shall be accurate and, where necessary, kept up to date",
                        ghostprompt_evidence_sources=[
                            "Hallucination forensics engine validates AI output accuracy",
                            "Data subjects can request correction via API",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="accuracy",
                    ),
                    ControlRequirement(
                        control_id="Art-5.1(e)",
                        title="Storage Limitation",
                        requirement_text="Personal data shall be kept for no longer than is necessary for the purposes for which it is processed",
                        ghostprompt_evidence_sources=[
                            "Configurable log retention periods per tenant (default 90 days)",
                            "Automatic data retention enforcement with purging",
                            "enforce_retention() API purges data beyond retention window",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="retention",
                    ),
                    ControlRequirement(
                        control_id="Art-5.1(f)",
                        title="Integrity and Confidentiality",
                        requirement_text="Personal data shall be processed in a manner that ensures appropriate security",
                        ghostprompt_evidence_sources=[
                            "HMAC-SHA256 signed audit entries ensure data integrity",
                            "RBAC prevents unauthorized access to personal data",
                            "DLP prevents personal data leakage to LLM providers",
                            "Data residency controls restrict processing to configured regions",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="security",
                    ),
                ],
            },

            "Art 6 — Lawful Basis": {
                "title": "Lawfulness of Processing",
                "controls": [
                    ControlRequirement(
                        control_id="Art-6.1",
                        title="Lawful Basis for Processing",
                        requirement_text="Processing shall be lawful only if and to the extent that at least one lawful basis applies",
                        ghostprompt_evidence_sources=[
                            "GhostPrompt processes data under legitimate interest (Art 6.1(f)) — security scanning of AI interactions to protect organizations from threats",
                            "Per-tenant compliance configuration documents lawful basis",
                            "Consent management infrastructure for tenants requiring consent-based processing",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="legal_basis",
                    ),
                ],
            },

            "Art 9 — Special Category Data": {
                "title": "Processing of Special Categories of Personal Data",
                "controls": [
                    ControlRequirement(
                        control_id="Art-9.1",
                        title="Special Category Data Detection",
                        requirement_text="Processing of special categories of personal data (racial/ethnic origin, political opinions, religious beliefs, health data, biometric data, sexual orientation) is prohibited unless exceptions apply",
                        ghostprompt_evidence_sources=[
                            "PII detector identifies sensitive-category patterns: SSN, medical record numbers (MRN), health-related data (BAA/HIPAA mode)",
                            "Content policy engine can detect and flag discussions involving sensitive categories",
                            "Auto-redact PHI mode specifically targets health-related personal data",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="sensitive_data_detection",
                    ),
                ],
            },

            "Art 17 — Right to Erasure": {
                "title": "Right to Erasure ('Right to Be Forgotten')",
                "controls": [
                    ControlRequirement(
                        control_id="Art-17.1",
                        title="Data Subject Erasure Requests",
                        requirement_text="The data subject shall have the right to obtain from the controller the erasure of personal data concerning him or her without undue delay",
                        ghostprompt_evidence_sources=[
                            "delete_user_data() API — removes all audit entries for a specific user",
                            "Deletion logged in separate deleted_data_log for compliance records",
                            "Erasure action itself logged with requester ID and timestamp",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_subject_rights",
                    ),
                ],
            },

            "Art 20 — Right to Portability": {
                "title": "Right to Data Portability",
                "controls": [
                    ControlRequirement(
                        control_id="Art-20.1",
                        title="Data Portability",
                        requirement_text="The data subject shall have the right to receive the personal data concerning him or her in a structured, commonly used and machine-readable format",
                        ghostprompt_evidence_sources=[
                            "export_tenant_data() API — exports all tenant data in JSON format",
                            "Structured machine-readable format with compliance configuration and audit entries",
                            "CSV export capability for spreadsheet-compatible portability",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_subject_rights",
                    ),
                ],
            },

            "Art 25 — Privacy by Design": {
                "title": "Data Protection by Design and by Default",
                "controls": [
                    ControlRequirement(
                        control_id="Art-25.1",
                        title="Data Protection by Design",
                        requirement_text="The controller shall implement appropriate technical and organisational measures designed to implement data-protection principles effectively",
                        ghostprompt_evidence_sources=[
                            "PII detection is active by default on all scans — privacy-by-design architecture",
                            "Context-Aware DLP automatically redacts personal data before LLM processing",
                            "Multi-tenant isolation ensures data segregation by design",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="architecture",
                    ),
                    ControlRequirement(
                        control_id="Art-25.2",
                        title="Data Protection by Default",
                        requirement_text="The controller shall implement appropriate measures for ensuring that, by default, only personal data which are necessary for each specific purpose of the processing are processed",
                        ghostprompt_evidence_sources=[
                            "Default STRICT enforcement mode blocks suspicious content",
                            "PII redaction active by default — personal data stripped before LLM forwarding",
                            "Minimal data retention defaults",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="default_protection",
                    ),
                ],
            },

            "Art 30 — Records of Processing": {
                "title": "Records of Processing Activities",
                "controls": [
                    ControlRequirement(
                        control_id="Art-30.1",
                        title="Processing Activity Records",
                        requirement_text="Each controller shall maintain a record of processing activities under its responsibility",
                        ghostprompt_evidence_sources=[
                            "Immutable HMAC-signed audit trail records every processing activity",
                            "Each entry: actor_id, action, resource_type, resource_id, timestamp, IP address",
                            "Exportable audit logs in JSON format for regulatory submission",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="record_keeping",
                    ),
                ],
            },

            "Art 32 — Security of Processing": {
                "title": "Security of Processing",
                "controls": [
                    ControlRequirement(
                        control_id="Art-32.1",
                        title="Appropriate Security Measures",
                        requirement_text="The controller and processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk",
                        ghostprompt_evidence_sources=[
                            "33 detection engines providing comprehensive AI security",
                            "RBAC with 7 roles for access control",
                            "HMAC-signed audit trail for integrity",
                            "Data residency controls for regional compliance",
                            "BYOK encryption support for key management",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="security",
                    ),
                    ControlRequirement(
                        control_id="Art-32.1(a)",
                        title="Pseudonymization and Encryption",
                        requirement_text="The pseudonymisation and encryption of personal data",
                        ghostprompt_evidence_sources=[
                            "DLP uses tokenized pseudonymization — PII replaced with vault tokens",
                            "BYOK encryption support for customer-managed encryption keys",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="encryption",
                    ),
                    ControlRequirement(
                        control_id="Art-32.1(d)",
                        title="Regular Testing and Assessment",
                        requirement_text="A process for regularly testing, assessing and evaluating the effectiveness of technical and organisational measures",
                        ghostprompt_evidence_sources=[
                            "Automated Red Team simulator for regular security testing",
                            "Red Team certification scoring validates control effectiveness",
                            "Cross-framework compliance assessment identifies gaps",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="testing",
                    ),
                ],
            },

            "Art 33/34 — Breach Notification": {
                "title": "Notification of Personal Data Breach",
                "controls": [
                    ControlRequirement(
                        control_id="Art-33.1",
                        title="Supervisory Authority Notification (72 hours)",
                        requirement_text="In the case of a personal data breach, the controller shall without undue delay and, where feasible, not later than 72 hours after having become aware of it, notify the personal data breach to the supervisory authority",
                        ghostprompt_evidence_sources=[
                            "Real-time WebSocket alerting for PII-related security events",
                            "SIEM integration enables automated breach notification workflows",
                            "All PII detection events logged with timestamps for 72-hour compliance tracking",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="breach_notification",
                    ),
                    ControlRequirement(
                        control_id="Art-34.1",
                        title="Data Subject Notification",
                        requirement_text="When the personal data breach is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall communicate the data breach to the data subject without undue delay",
                        ghostprompt_evidence_sources=[
                            "Incident forensics provide full breach impact assessment",
                            "Attack chain reconstruction identifies affected data subjects",
                            "Exportable incident reports for data subject communication",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="breach_notification",
                    ),
                ],
            },

            "Art 35 — Data Protection Impact Assessment": {
                "title": "Data Protection Impact Assessment (DPIA)",
                "controls": [
                    ControlRequirement(
                        control_id="Art-35.1",
                        title="DPIA Requirement",
                        requirement_text="Where processing is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall carry out an assessment of the impact of the envisaged processing operations on the protection of personal data",
                        ghostprompt_evidence_sources=[
                            "DPIA auto-generator: GhostPrompt generates a starter DPIA based on observed PII categories flowing through the AI system",
                            "PII detection statistics provide data for risk assessment (types, volumes, frequency)",
                            "Cross-framework compliance scoring quantifies data protection posture",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="impact_assessment",
                    ),
                    ControlRequirement(
                        control_id="Art-35.7",
                        title="DPIA Content",
                        requirement_text="The assessment shall contain a systematic description of processing, necessity assessment, risk assessment, and measures to address risks",
                        ghostprompt_evidence_sources=[
                            "Systematic description: GhostPrompt scans AI prompts/responses for threats and PII",
                            "Necessity: security scanning is necessary to prevent data breaches via AI systems",
                            "Risk assessment: threat scoring across 33 detection engines quantifies risk",
                            "Measures: DLP, PII redaction, RBAC, audit logging, and encryption address identified risks",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="impact_assessment",
                    ),
                ],
            },
        }


# Singleton
gdpr_framework = GDPRFramework()
