"""
GhostPrompt — HIPAA Compliance Mapping

Maps GhostPrompt's technical controls to HIPAA requirements across all three rules:
- Privacy Rule (minimum necessary, PHI use/disclosure)
- Security Rule (Administrative, Physical, Technical Safeguards — 45 CFR 164.312)
- Breach Notification Rule (60-day notification, risk assessment)

NOTE: There is no federal "HIPAA Certification" — this report provides technical
evidence for your organization's HIPAA compliance program. Full HIPAA compliance
requires administrative, physical, and organizational safeguards beyond technical
controls.
"""

from app.compliance.framework_base import (
    ComplianceFramework, ControlRequirement, ControlStatus
)


class HIPAAFramework(ComplianceFramework):
    framework_id = "hipaa"
    framework_name = "HIPAA"
    framework_version = "45 CFR Parts 160, 162, 164 (2024)"

    def get_control_taxonomy(self) -> dict[str, dict]:
        return {
            # ═══════════════════════════════════════════════════
            # PRIVACY RULE (45 CFR 164.502-164.514)
            # ═══════════════════════════════════════════════════
            "Privacy Rule — Minimum Necessary": {
                "title": "Privacy Rule: Minimum Necessary Standard",
                "controls": [
                    ControlRequirement(
                        control_id="164.502(b)",
                        title="Minimum Necessary Standard",
                        requirement_text="A covered entity must make reasonable efforts to use, disclose, and request only the minimum necessary PHI to accomplish the intended purpose",
                        ghostprompt_evidence_sources=[
                            "Context-Aware DLP redacts PHI before forwarding to LLM providers — only de-identified data reaches third parties",
                            "PII vault stores tokenized references — minimum necessary data retained",
                            "Auto-redact PHI mode specifically targets health-related personal data",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_minimization",
                    ),
                    ControlRequirement(
                        control_id="164.502(e)",
                        title="Business Associate Agreements",
                        requirement_text="A covered entity may disclose PHI to a business associate and may allow a business associate to create, receive, maintain, or transmit PHI only if the covered entity obtains satisfactory assurance that the business associate will appropriately safeguard the information",
                        ghostprompt_evidence_sources=[
                            "BAA mode enabled per tenant — activates enhanced PHI protections",
                            "Auto-redact PHI mode is automatically enabled when BAA is active",
                            "DLP prevents PHI exposure to LLM providers that may not have BAAs",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="contractual",
                    ),
                    ControlRequirement(
                        control_id="164.514(a)",
                        title="De-identification Standard",
                        requirement_text="Health information that does not identify an individual is not PHI and is not subject to the Privacy Rule",
                        ghostprompt_evidence_sources=[
                            "PII detector identifies 18 HIPAA identifiers: SSN, MRN, DOB, phone, email, etc.",
                            "DLP redaction produces de-identified text before LLM processing",
                            "PHI patterns automatically replaced with [*-REDACTED] tokens",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="de_identification",
                    ),
                ],
            },

            "Privacy Rule — Use and Disclosure": {
                "title": "Privacy Rule: Use and Disclosure of PHI",
                "controls": [
                    ControlRequirement(
                        control_id="164.506",
                        title="Uses and Disclosures for Treatment, Payment, Health Care Operations",
                        requirement_text="A covered entity may use or disclose PHI for treatment, payment, or health care operations",
                        ghostprompt_evidence_sources=[
                            "Per-tenant policy configuration controls PHI handling rules",
                            "Audit trail logs every PHI access/processing event with purpose codes",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="access_control",
                    ),
                    ControlRequirement(
                        control_id="164.508",
                        title="Authorization for Non-TPO Disclosures",
                        requirement_text="A covered entity must obtain the individual's written authorization for uses and disclosures not covered by the Privacy Rule",
                        ghostprompt_evidence_sources=[
                            "DLP prevents unauthorized PHI disclosure to LLM providers",
                            "Data residency controls prevent cross-border PHI transfer without authorization",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="authorization",
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # SECURITY RULE — Administrative Safeguards (164.308)
            # ═══════════════════════════════════════════════════
            "Security Rule — Administrative Safeguards": {
                "title": "Security Rule: Administrative Safeguards (45 CFR 164.308)",
                "controls": [
                    ControlRequirement(
                        control_id="164.308(a)(1)",
                        title="Security Management Process",
                        requirement_text="Implement policies and procedures to prevent, detect, contain, and correct security violations",
                        ghostprompt_evidence_sources=[
                            "33 detection engines prevent and detect security violations in AI interactions",
                            "Automatic blocking/flagging/sanitization contains threats",
                            "Compliance gap analysis identifies areas for correction",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="security_management",
                    ),
                    ControlRequirement(
                        control_id="164.308(a)(1)(ii)(A)",
                        title="Risk Analysis",
                        requirement_text="Conduct an accurate and thorough assessment of the potential risks and vulnerabilities to the confidentiality, integrity, and availability of ePHI",
                        ghostprompt_evidence_sources=[
                            "Cross-framework compliance risk assessment",
                            "Red Team simulator tests AI system vulnerabilities",
                            "Threat analytics dashboard quantifies risk levels",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="risk_analysis",
                    ),
                    ControlRequirement(
                        control_id="164.308(a)(1)(ii)(B)",
                        title="Risk Management",
                        requirement_text="Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level",
                        ghostprompt_evidence_sources=[
                            "Configurable enforcement modes (STRICT/BALANCED/PERMISSIVE)",
                            "Per-category action rules (BLOCK/FLAG/REDACT/SANITIZE)",
                            "Continuous monitoring via ML drift daemon",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="risk_management",
                    ),
                    ControlRequirement(
                        control_id="164.308(a)(3)",
                        title="Workforce Security",
                        requirement_text="Implement policies and procedures to ensure that all members of its workforce have appropriate access to ePHI",
                        ghostprompt_evidence_sources=[
                            "7-role RBAC with least-privilege access",
                            "Role assignment changes logged in immutable audit trail",
                            "read_only role prevents unauthorized PHI access",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="access_control",
                    ),
                    ControlRequirement(
                        control_id="164.308(a)(5)",
                        title="Security Awareness and Training",
                        requirement_text="Implement a security awareness and training program for all members of its workforce",
                        ghostprompt_evidence_sources=[
                            "Real-time security dashboard provides continuous threat awareness and education",
                            "Scan explainability engine educates operators on each attack type, risk level, and remediation",
                            "Incident response playbooks guide staff through proper security procedures",
                            "Contextual compliance guidance displayed alongside every security event",
                            "Knowledge Graph provides continuous learning context for AI security operations",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="security_awareness",
                    ),
                    ControlRequirement(
                        control_id="164.308(a)(6)",
                        title="Security Incident Procedures",
                        requirement_text="Implement policies and procedures to address security incidents",
                        ghostprompt_evidence_sources=[
                            "Automatic incident response based on policy rules",
                            "Real-time WebSocket alerting for security events",
                            "SIEM integration for enterprise incident response",
                            "Incident forensics with attack chain reconstruction",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="incident_response",
                    ),
                    ControlRequirement(
                        control_id="164.308(a)(7)",
                        title="Contingency Plan",
                        requirement_text="Establish policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI",
                        ghostprompt_evidence_sources=[
                            "Kill switch for emergency model deactivation",
                            "Multi-provider routing with automatic failover",
                            "Canary rollback for system recovery",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="contingency",
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # SECURITY RULE — Physical Safeguards (164.310)
            # ═══════════════════════════════════════════════════
            "Security Rule — Physical Safeguards": {
                "title": "Security Rule: Physical Safeguards (45 CFR 164.310)",
                "controls": [
                    ControlRequirement(
                        control_id="164.310(a)",
                        title="Facility Access Controls",
                        requirement_text="Implement policies and procedures to limit physical access to electronic information systems and the facility in which they are housed",
                        ghostprompt_evidence_sources=[
                            "NOT APPLICABLE: GhostPrompt is a cloud-native software platform. Physical facility access controls are the responsibility of the cloud infrastructure provider and deploying organization.",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="physical",
                        gap_note="Physical facility controls outside GhostPrompt's scope as a cloud-native application",
                    ),
                    ControlRequirement(
                        control_id="164.310(b)",
                        title="Workstation Use and Security",
                        requirement_text="Implement policies and procedures that specify the proper functions to be performed and the physical attributes of the surroundings of a specific workstation",
                        ghostprompt_evidence_sources=[
                            "NOT APPLICABLE: Workstation policies are organizational responsibilities.",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="physical",
                        gap_note="Workstation controls outside GhostPrompt's scope",
                    ),
                    ControlRequirement(
                        control_id="164.310(d)",
                        title="Device and Media Controls",
                        requirement_text="Implement policies and procedures that govern the receipt and removal of hardware and electronic media that contain ePHI",
                        ghostprompt_evidence_sources=[
                            "NOT APPLICABLE: Hardware/media controls are organizational responsibilities.",
                            "GhostPrompt's data retention and erasure capabilities support media disposal compliance for digital data",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="physical",
                        gap_note="Hardware media controls outside GhostPrompt's scope",
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # SECURITY RULE — Technical Safeguards (164.312)
            # ═══════════════════════════════════════════════════
            "Security Rule — Technical Safeguards": {
                "title": "Security Rule: Technical Safeguards (45 CFR 164.312)",
                "controls": [
                    ControlRequirement(
                        control_id="164.312(a)(1)",
                        title="Access Control",
                        requirement_text="Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to those persons or software programs that have been granted access rights",
                        ghostprompt_evidence_sources=[
                            "7-role RBAC with granular resource.action permission matrix",
                            "JWT-based authentication with session management",
                            "API key authentication for programmatic access",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="access_control",
                    ),
                    ControlRequirement(
                        control_id="164.312(a)(2)(i)",
                        title="Unique User Identification",
                        requirement_text="Assign a unique name and/or number for identifying and tracking user identity",
                        ghostprompt_evidence_sources=[
                            "Every user has unique actor_id and actor_email tracked in audit logs",
                            "API keys are uniquely scoped per user/service account",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="identification",
                    ),
                    ControlRequirement(
                        control_id="164.312(a)(2)(iv)",
                        title="Encryption and Decryption",
                        requirement_text="Implement a mechanism to encrypt and decrypt ePHI",
                        ghostprompt_evidence_sources=[
                            "BYOK encryption support for customer-managed encryption keys",
                            "DLP vault uses tokenized pseudonymization for PHI",
                            "All API communications over HTTPS/TLS",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="encryption",
                    ),
                    ControlRequirement(
                        control_id="164.312(b)",
                        title="Audit Controls",
                        requirement_text="Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI",
                        ghostprompt_evidence_sources=[
                            "HMAC-SHA256 signed immutable audit trail",
                            "Every PHI access/processing event logged with full forensic detail",
                            "Exportable audit logs for compliance review",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="audit",
                    ),
                    ControlRequirement(
                        control_id="164.312(c)(1)",
                        title="Integrity Controls",
                        requirement_text="Implement policies and procedures to protect ePHI from improper alteration or destruction",
                        ghostprompt_evidence_sources=[
                            "HMAC signatures detect any tampering with audit records",
                            "DLP prevents improper PHI modification during LLM processing",
                            "Compliance report signatures ensure integrity of exported evidence",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="integrity",
                    ),
                    ControlRequirement(
                        control_id="164.312(d)",
                        title="Person or Entity Authentication",
                        requirement_text="Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed",
                        ghostprompt_evidence_sources=[
                            "JWT-based authentication verifies user identity",
                            "API key authentication for service accounts",
                            "Session management with token expiration",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="authentication",
                    ),
                    ControlRequirement(
                        control_id="164.312(e)(1)",
                        title="Transmission Security",
                        requirement_text="Implement technical security measures to guard against unauthorized access to ePHI that is being transmitted over an electronic communications network",
                        ghostprompt_evidence_sources=[
                            "All API communications over HTTPS/TLS",
                            "DLP redacts PHI BEFORE transmission to LLM providers",
                            "Secret detector catches credentials in transit",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="transmission",
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # BREACH NOTIFICATION RULE (164.400-164.414)
            # ═══════════════════════════════════════════════════
            "Breach Notification Rule": {
                "title": "Breach Notification Rule (45 CFR 164.400-414)",
                "controls": [
                    ControlRequirement(
                        control_id="164.404",
                        title="Notification to Individuals (60 days)",
                        requirement_text="A covered entity shall notify each individual whose unsecured PHI has been, or is reasonably believed to have been, accessed, acquired, used, or disclosed as a result of such breach, without unreasonable delay and in no case later than 60 calendar days from the discovery of the breach",
                        ghostprompt_evidence_sources=[
                            "Real-time WebSocket alerting for PHI-related security events enables immediate breach discovery",
                            "All PHI detection events logged with timestamps for 60-day compliance tracking",
                            "Incident forensics identify affected individuals for notification",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="breach_notification",
                    ),
                    ControlRequirement(
                        control_id="164.406",
                        title="Notification to Secretary of HHS",
                        requirement_text="A covered entity shall notify the Secretary of HHS of breaches of unsecured PHI",
                        ghostprompt_evidence_sources=[
                            "SIEM integration can trigger HHS notification workflows",
                            "Exportable breach incident reports for regulatory filing",
                            "Audit trail provides evidence for breach impact assessment",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="regulatory_notification",
                    ),
                    ControlRequirement(
                        control_id="164.402",
                        title="Breach Risk Assessment",
                        requirement_text="A covered entity shall conduct a risk assessment to determine whether use or disclosure of PHI constitutes a breach requiring notification, considering the nature and extent of PHI involved, the unauthorized person, whether PHI was actually acquired/viewed, and the extent to which risk has been mitigated",
                        ghostprompt_evidence_sources=[
                            "Threat scoring quantifies breach severity (safe/low/medium/high/critical)",
                            "PII detection identifies specific types of PHI exposed",
                            "Attack chain reconstruction shows extent of data access",
                            "DLP redaction log shows whether data was intercepted before exposure",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="risk_assessment",
                    ),
                ],
            },
        }


# Singleton
hipaa_framework = HIPAAFramework()
