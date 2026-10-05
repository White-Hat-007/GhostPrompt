"""
GhostPrompt — PCI DSS v4.0 Compliance Mapping

Maps GhostPrompt's technical controls to PCI DSS v4.0 requirements across
the 6 goals and 12 requirements.

CRITICAL: PCI DSS is NOT self-certifiable above certain transaction volumes.
It requires assessment by a Qualified Security Assessor (QSA). GhostPrompt
generates TECHNICAL CONTROL EVIDENCE — it NEVER claims "PCI DSS Certified."

HONEST SCOPING: GhostPrompt does NOT process payments. Its relevance to PCI
DSS is narrower — focused on preventing cardholder data exposure via AI
systems. Controls not relevant to GhostPrompt are honestly marked NOT_APPLICABLE.
"""

from app.compliance.framework_base import (
    ComplianceFramework,
    ControlRequirement,
    ControlStatus,
)


class PCIDSSFramework(ComplianceFramework):
    framework_id = "pci_dss"
    framework_name = "PCI DSS v4.0"
    framework_version = "4.0 (March 2022)"

    def get_control_taxonomy(self) -> dict[str, dict]:
        return {
            # ═══════════════════════════════════════════════════
            # GOAL 1: Build and Maintain a Secure Network
            # ═══════════════════════════════════════════════════
            "Req 1 — Network Security Controls": {
                "title": "Install and Maintain Network Security Controls",
                "controls": [
                    ControlRequirement(
                        control_id="1.1",
                        title="Network Security Controls Defined and Implemented",
                        requirement_text="Processes and mechanisms for installing and maintaining network security controls are defined and understood",
                        ghostprompt_evidence_sources=[
                            "NOT APPLICABLE: GhostPrompt operates as an application-layer AI firewall proxy, not a network-layer firewall. Network segmentation and firewall rules are the responsibility of the deploying organization's infrastructure team.",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="infrastructure",
                        gap_note="Network security controls are outside GhostPrompt's scope — it operates at the application/API layer",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="1.2",
                        title="Network Security Controls Configured and Maintained",
                        requirement_text="Network security controls are configured and maintained",
                        ghostprompt_evidence_sources=[
                            "NOT APPLICABLE: Network firewall configuration is the deploying organization's responsibility.",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="infrastructure",
                        gap_note="Network-layer controls outside GhostPrompt scope",
                        requires_external_audit=True,
                    ),
                ],
            },

            "Req 2 — Secure Configurations": {
                "title": "Apply Secure Configurations to All System Components",
                "controls": [
                    ControlRequirement(
                        control_id="2.1",
                        title="Secure Configuration Standards",
                        requirement_text="Processes and mechanisms for applying secure configurations are defined and understood",
                        ghostprompt_evidence_sources=[
                            "Three enforcement tiers: STRICT/BALANCED/PERMISSIVE with documented security postures",
                            "Per-tenant policy configuration with secure defaults",
                            "All configuration changes logged in immutable audit trail",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="configuration",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="2.2",
                        title="System Components Securely Configured",
                        requirement_text="System components are configured and managed securely",
                        ghostprompt_evidence_sources=[
                            "Default STRICT mode blocks all suspicious content",
                            "RBAC prevents unauthorized configuration changes",
                            "Configuration drift detection via audit trail analysis",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="configuration",
                        requires_external_audit=True,
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # GOAL 2: Protect Account Data
            # ═══════════════════════════════════════════════════
            "Req 3 — Protect Stored Account Data": {
                "title": "Protect Stored Account Data",
                "controls": [
                    ControlRequirement(
                        control_id="3.1",
                        title="Account Data Storage Minimized",
                        requirement_text="Processes and mechanisms for protecting stored account data are defined and understood",
                        ghostprompt_evidence_sources=[
                            "PII detector specifically catches PAN (Primary Account Number) patterns in LLM prompts/responses",
                            "Credit card number patterns (4111-xxxx, etc.) are automatically detected and redacted",
                            "CVV/CVC patterns are detected and blocked from LLM exposure",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="detection",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="3.3",
                        title="SAD Not Stored After Authorization",
                        requirement_text="Sensitive Authentication Data (SAD) is not stored after authorization",
                        ghostprompt_evidence_sources=[
                            "Context-Aware DLP redacts sensitive authentication data before forwarding to LLM providers",
                            "PII vault uses tokenized references — original values never persisted in logs",
                            "No cardholder data stored in GhostPrompt's own data stores",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_protection",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="3.4",
                        title="PAN Display Restricted",
                        requirement_text="Access to displays of full PAN and ability to copy cardholder data are restricted",
                        ghostprompt_evidence_sources=[
                            "PAN patterns automatically masked in all dashboard displays",
                            "Audit log entries truncate sensitive data (signature shown as first 16 chars + '...')",
                            "DLP redaction replaces full PAN with [CREDIT_CARD-REDACTED] tokens",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="display_masking",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="3.5",
                        title="PAN Secured Wherever Stored",
                        requirement_text="PAN is secured wherever it is stored",
                        ghostprompt_evidence_sources=[
                            "GhostPrompt does NOT store PAN — it detects and redacts PAN in transit through AI systems",
                            "If PAN is detected, it is replaced with tokenized references before any storage",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="encryption",
                        requires_external_audit=True,
                    ),
                ],
            },

            "Req 4 — Protect Data in Transit": {
                "title": "Protect Cardholder Data with Strong Cryptography During Transmission",
                "controls": [
                    ControlRequirement(
                        control_id="4.1",
                        title="Strong Cryptography for Transmission",
                        requirement_text="Processes and mechanisms for protecting cardholder data with strong cryptography during transmission over open, public networks are defined and understood",
                        ghostprompt_evidence_sources=[
                            "All API communications over HTTPS/TLS",
                            "DLP engine redacts cardholder data BEFORE transmission to LLM providers",
                            "Secret detector catches credit card data, API keys, and tokens in API payloads",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="transmission_security",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="4.2",
                        title="PAN Protected During Transmission",
                        requirement_text="PAN is protected with strong cryptography during transmission",
                        ghostprompt_evidence_sources=[
                            "DLP intercepts and redacts PAN before forwarding prompts to any LLM provider",
                            "Ensures cardholder data never reaches third-party AI providers in plaintext",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_protection",
                        requires_external_audit=True,
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # GOAL 3: Maintain a Vulnerability Management Program
            # ═══════════════════════════════════════════════════
            "Req 5 — Anti-Malware": {
                "title": "Protect All Systems and Networks from Malicious Software",
                "controls": [
                    ControlRequirement(
                        control_id="5.1",
                        title="Malicious Software Prevention",
                        requirement_text="Processes and mechanisms for protecting all systems and networks from malicious software are defined and understood",
                        ghostprompt_evidence_sources=[
                            "Supply chain attack detection engine",
                            "Package hallucination detector for malicious package recommendations",
                            "Encoded payload detection (Base64, hex, Unicode tricks) prevents obfuscated malware delivery via AI",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="anti_malware",
                        requires_external_audit=True,
                    ),
                ],
            },

            "Req 6 — Secure Systems and Software": {
                "title": "Develop and Maintain Secure Systems and Software",
                "controls": [
                    ControlRequirement(
                        control_id="6.1",
                        title="Security Vulnerability Identification",
                        requirement_text="Processes and mechanisms for developing and maintaining secure systems and software are defined and understood",
                        ghostprompt_evidence_sources=[
                            "Automated Red Team simulator with 20+ attack categories",
                            "Red Team certification tier scoring (BASIC → ADVANCED → ELITE → PLATINUM)",
                            "Zero-day attack detection via ML embedding similarity engine",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="vulnerability_management",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="6.3",
                        title="Security Vulnerabilities Identified and Addressed",
                        requirement_text="Security vulnerabilities are identified and addressed",
                        ghostprompt_evidence_sources=[
                            "Continuous detection engine updates for new attack patterns",
                            "ML adaptive drift daemon monitors for emerging threats",
                            "Gap analysis with specific remediation suggestions across all compliance frameworks",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="vulnerability_management",
                        requires_external_audit=True,
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # GOAL 4: Implement Strong Access Control Measures
            # ═══════════════════════════════════════════════════
            "Req 7 — Restrict Access": {
                "title": "Restrict Access to System Components and Cardholder Data by Business Need to Know",
                "controls": [
                    ControlRequirement(
                        control_id="7.1",
                        title="Need-to-Know Access Defined",
                        requirement_text="Processes and mechanisms for restricting access to system components and cardholder data by business need to know are defined and understood",
                        ghostprompt_evidence_sources=[
                            "7-role RBAC with least-privilege principle",
                            "Granular resource.action permission matrix",
                            "read_only role cannot access sensitive configuration or raw scan data",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="access_control",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="7.2",
                        title="Access Appropriately Assigned",
                        requirement_text="Access to system components and data is appropriately defined and assigned",
                        ghostprompt_evidence_sources=[
                            "Role assignment requires org_admin or higher",
                            "Each role has explicitly defined permission boundaries",
                            "billing_viewer role segregated from security operations",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="access_control",
                        requires_external_audit=True,
                    ),
                ],
            },

            "Req 8 — Identify Users and Authenticate Access": {
                "title": "Identify Users and Authenticate Access to System Components",
                "controls": [
                    ControlRequirement(
                        control_id="8.1",
                        title="User Identification and Authentication",
                        requirement_text="Processes and mechanisms for identifying users and authenticating access to system components are defined and understood",
                        ghostprompt_evidence_sources=[
                            "JWT-based authentication with session management",
                            "API key authentication for programmatic access",
                            "Every action logged with actor_id and actor_email for accountability",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="authentication",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="8.3",
                        title="Strong Authentication for Users and Administrators",
                        requirement_text="Strong authentication for users and administrators is established and managed",
                        ghostprompt_evidence_sources=[
                            "OAuth 2.0 / OIDC SSO integration with enterprise identity providers (Okta, Azure AD, Google Workspace) — MFA enforced at IdP level",
                            "JWT-based session tokens with configurable expiry, secure httpOnly cookies, and CSRF protection",
                            "API keys with per-key scoping, automatic rotation reminders, and instant revocation capability",
                            "Role-based access control (RBAC) with least-privilege enforcement across all endpoints",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="authentication",
                        requires_external_audit=True,
                    ),
                ],
            },

            "Req 9 — Physical Access": {
                "title": "Restrict Physical Access to Cardholder Data",
                "controls": [
                    ControlRequirement(
                        control_id="9.1",
                        title="Physical Access Controls",
                        requirement_text="Processes and mechanisms for restricting physical access to cardholder data are defined and understood",
                        ghostprompt_evidence_sources=[
                            "NOT APPLICABLE: GhostPrompt is a cloud-native software application. Physical access controls are the responsibility of the cloud infrastructure provider (AWS/GCP/Azure) and the deploying organization's data center management.",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="physical",
                        gap_note="Physical security is outside GhostPrompt's scope as a software-only platform",
                        requires_external_audit=True,
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # GOAL 5: Regularly Monitor and Test Networks
            # ═══════════════════════════════════════════════════
            "Req 10 — Log and Monitor": {
                "title": "Log and Monitor All Access to System Components and Cardholder Data",
                "controls": [
                    ControlRequirement(
                        control_id="10.1",
                        title="Audit Logging Defined",
                        requirement_text="Processes and mechanisms for logging and monitoring all access to system components and cardholder data are defined and understood",
                        ghostprompt_evidence_sources=[
                            "Every scan event immutably logged with full forensic detail",
                            "HMAC-SHA256 signed audit entries prevent log tampering",
                            "Includes IP address, user-agent, threat categories, scan duration, and detection results",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="audit_trail",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="10.2",
                        title="Audit Logs Record Events",
                        requirement_text="Audit logs are implemented to support the detection of anomalies and suspicious activity",
                        ghostprompt_evidence_sources=[
                            "All security events logged: blocks, flags, sanitizations, policy changes",
                            "Each audit entry includes timestamp, actor_id, action, resource, and HMAC signature",
                            "Audit log retention configurable per tenant (default 90 days)",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="audit_trail",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="10.4",
                        title="Audit Logs Reviewed",
                        requirement_text="Audit logs are reviewed to identify anomalies or suspicious activity",
                        ghostprompt_evidence_sources=[
                            "Real-time threat analytics dashboard for audit log review",
                            "Campaign velocity spike detection automatically surfaces anomalous patterns",
                            "SIEM integration exports audit data for enterprise review workflows",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="monitoring",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="10.7",
                        title="Audit Log Integrity",
                        requirement_text="Failures of critical security control systems are detected, reported, and responded to promptly",
                        ghostprompt_evidence_sources=[
                            "HMAC-SHA256 signatures on every audit entry detect any tampering",
                            "Compliance report signatures enable independent verification",
                            "Verification endpoint (/compliance-frameworks/verify) validates report integrity",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="integrity",
                        requires_external_audit=True,
                    ),
                ],
            },

            "Req 11 — Test Security": {
                "title": "Test Security of Systems and Networks Regularly",
                "controls": [
                    ControlRequirement(
                        control_id="11.3",
                        title="Vulnerability Scanning",
                        requirement_text="External and internal vulnerabilities are regularly identified, prioritized, and addressed",
                        ghostprompt_evidence_sources=[
                            "Automated Red Team simulator with 20+ attack category coverage",
                            "Red Team certification tiers validate detection effectiveness",
                            "Zero-day detection via ML embedding similarity for unknown attack patterns",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="testing",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="11.4",
                        title="Penetration Testing",
                        requirement_text="External and internal penetration testing is regularly performed",
                        ghostprompt_evidence_sources=[
                            "Automated penetration testing via Red Team simulator covering prompt injection, jailbreak, PII exfiltration, encoded payloads, oracle attacks, cross-lingual attacks, and more",
                            "Certification tiers: BASIC (70%+) → ADVANCED (80%+) → ELITE (90%+) → PLATINUM (95%+)",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="penetration_testing",
                        requires_external_audit=True,
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # GOAL 6: Maintain an Information Security Policy
            # ═══════════════════════════════════════════════════
            "Req 12 — Information Security Policy": {
                "title": "Support Information Security with Organizational Policies and Programs",
                "controls": [
                    ControlRequirement(
                        control_id="12.1",
                        title="Security Policy Established",
                        requirement_text="A comprehensive information security policy that governs and provides direction for protection of the entity's information assets is known and current",
                        ghostprompt_evidence_sources=[
                            "Per-tenant security policy configuration with documented enforcement modes",
                            "33 detection engine categories with configurable action rules",
                            "Policy changes tracked in immutable audit trail",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="policy",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="12.3",
                        title="Security Risk Assessment",
                        requirement_text="Risks to the cardholder data environment are formally identified, evaluated, and managed",
                        ghostprompt_evidence_sources=[
                            "Cross-framework compliance risk assessment across 9 frameworks",
                            "Gap analysis with specific remediation suggestions",
                            "Continuous risk scoring through real-time threat analytics",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="risk_assessment",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="12.10",
                        title="Incident Response Plan",
                        requirement_text="Security incidents are responded to immediately",
                        ghostprompt_evidence_sources=[
                            "Automatic incident response: blocking, flagging, sanitization based on policy",
                            "Real-time WebSocket alerting for critical security events",
                            "SIEM integration for enterprise incident response workflows",
                            "Kill switch for emergency model deactivation",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="incident_response",
                        requires_external_audit=True,
                    ),
                ],
            },
        }


# Singleton
pci_dss_framework = PCIDSSFramework()
