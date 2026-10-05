"""
GhostPrompt — SOC 2 Type II Compliance Mapping

Maps GhostPrompt's technical controls to the SOC 2 Trust Services Criteria.
Covers all 5 Trust Services Categories: Security (CC1-CC9), Availability,
Processing Integrity, Confidentiality, Privacy.

CRITICAL: SOC 2 Type II is NOT self-certifiable. It requires a licensed CPA
firm to conduct an audit over a real observation period (3-12 months) and
issue an opinion letter. GhostPrompt generates TECHNICAL CONTROL EVIDENCE
that an auditor would review — it NEVER claims "SOC 2 Type II Compliant."

Type II vs Type I: Type II certifies OPERATING EFFECTIVENESS over time,
not point-in-time design. Evidence must demonstrate continuous operation.
"""

from app.compliance.framework_base import (
    ComplianceFramework, ControlRequirement, ControlStatus, ComplianceSnapshot
)


class SOC2Type2Framework(ComplianceFramework):
    framework_id = "soc2_type2"
    framework_name = "SOC 2 Type II"
    framework_version = "2017 (TSP Section 100, 2022 Revision)"

    OBSERVATION_WINDOW_DAYS = 90  # Configurable per tenant

    def get_control_taxonomy(self) -> dict[str, dict]:
        return {
            # ═══════════════════════════════════════════════════
            # SECURITY — Common Criteria (CC1-CC9)
            # ═══════════════════════════════════════════════════
            "CC1 — Control Environment": {
                "title": "Control Environment",
                "controls": [
                    ControlRequirement(
                        control_id="CC1.1",
                        title="COSO Principle 1: Commitment to Integrity and Ethical Values",
                        requirement_text="The entity demonstrates a commitment to integrity and ethical values",
                        ghostprompt_evidence_sources=[
                            "Content policy engine — blocks harmful, biased, and unethical AI outputs",
                            "Per-tenant configurable ethical guidelines via policy rules",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="policy_enforcement",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC1.2",
                        title="COSO Principle 2: Board of Directors Oversight",
                        requirement_text="The board of directors demonstrates independence from management and exercises oversight",
                        ghostprompt_evidence_sources=[
                            "RBAC hierarchy: super_admin > org_owner > org_admin — separation of duties enforced",
                            "Immutable HMAC-signed audit trail for oversight review",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="access_control",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC1.3",
                        title="COSO Principle 3: Organizational Structure",
                        requirement_text="Management establishes structures, reporting lines, and appropriate authorities and responsibilities",
                        ghostprompt_evidence_sources=[
                            "7-role RBAC model with granular resource.action permission matrix",
                            "Workspace hierarchy with per-tenant isolation",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="access_control",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC1.4",
                        title="COSO Principle 4: Competence Commitment",
                        requirement_text="The entity demonstrates commitment to attract, develop, and retain competent individuals",
                        ghostprompt_evidence_sources=[
                            "Role-based dashboards with specialized views for security analysts, compliance officers, and administrators",
                            "In-app contextual security guidance and threat education on every detected incident",
                            "Automated incident response playbooks that train operators on proper remediation procedures",
                            "Knowledge Graph providing continuous learning context for AI security operations",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="platform_training",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC1.5",
                        title="COSO Principle 5: Accountability",
                        requirement_text="The entity holds individuals accountable for their internal control responsibilities",
                        ghostprompt_evidence_sources=[
                            "Every action logged with actor_id, actor_email, IP address, and timestamp",
                            "HMAC-signed immutable audit trail prevents log tampering",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="audit_trail",
                        requires_external_audit=True,
                    ),
                ],
            },

            "CC2 — Communication and Information": {
                "title": "Communication and Information",
                "controls": [
                    ControlRequirement(
                        control_id="CC2.1",
                        title="COSO Principle 13: Quality Information",
                        requirement_text="The entity obtains or generates and uses relevant, quality information to support the functioning of internal control",
                        ghostprompt_evidence_sources=[
                            "Real-time threat analytics dashboard with scan volume, block rate, severity distribution",
                            "Automated compliance reporting across 9 frameworks",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="monitoring",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC2.2",
                        title="COSO Principle 14: Internal Communication",
                        requirement_text="The entity internally communicates information necessary to support the functioning of internal control",
                        ghostprompt_evidence_sources=[
                            "Real-time WebSocket alerting for security events",
                            "SIEM integration forwarding alerts to SOC teams",
                            "Slack/Teams webhook integration for security notifications",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="alerting",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC2.3",
                        title="COSO Principle 15: External Communication",
                        requirement_text="The entity communicates with external parties regarding matters affecting the functioning of internal control",
                        ghostprompt_evidence_sources=[
                            "Exportable compliance reports (PDF/CSV/JSON) for external auditors",
                            "HMAC-signed reports for tamper evidence",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="reporting",
                        requires_external_audit=True,
                    ),
                ],
            },

            "CC3 — Risk Assessment": {
                "title": "Risk Assessment",
                "controls": [
                    ControlRequirement(
                        control_id="CC3.1",
                        title="COSO Principle 6: Risk Objectives",
                        requirement_text="The entity specifies objectives with sufficient clarity to enable identification and assessment of risks",
                        ghostprompt_evidence_sources=[
                            "Configurable FIREWALL_MODE (enforce/monitor/disabled) per tenant",
                            "THREAT_SCORE_THRESHOLD configurable per deployment",
                            "33 detection engines with per-category action rules (BLOCK/FLAG/REDACT/SANITIZE)",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="configuration",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC3.2",
                        title="COSO Principle 7: Risk Identification and Analysis",
                        requirement_text="The entity identifies risks to the achievement of its objectives and analyzes risks as a basis for determining how they should be managed",
                        ghostprompt_evidence_sources=[
                            "Automated Red Team simulator with 20+ attack categories",
                            "Threat attribution engine with MITRE ATT&CK mapping",
                            "ML-based adaptive drift daemon for emerging threat detection",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="automated_assessment",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC3.3",
                        title="COSO Principle 8: Fraud Risk",
                        requirement_text="The entity considers the potential for fraud in assessing risks",
                        ghostprompt_evidence_sources=[
                            "Social engineering detection (authority escalation, urgency framing)",
                            "Business logic attack detection",
                            "Identity spoofing detection via authority_escalation detector",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="detection",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC3.4",
                        title="COSO Principle 9: Change Assessment",
                        requirement_text="The entity identifies and assesses changes that could significantly impact the system of internal control",
                        ghostprompt_evidence_sources=[
                            "ML drift daemon monitors model behavior changes continuously",
                            "Canary rollback on quality regression",
                            "Automated re-evaluation of Red Team certification scores",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="automated_monitoring",
                        requires_external_audit=True,
                    ),
                ],
            },

            "CC4 — Monitoring Activities": {
                "title": "Monitoring Activities",
                "controls": [
                    ControlRequirement(
                        control_id="CC4.1",
                        title="COSO Principle 16: Ongoing Monitoring",
                        requirement_text="The entity selects, develops, and performs ongoing evaluations to ascertain whether the components of internal control are present and functioning",
                        ghostprompt_evidence_sources=[
                            "Real-time scan processing with sub-15ms latency",
                            "Continuous threat score computation across all 33 detection engines",
                            "Live analytics dashboard with scan volume trends",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="continuous_monitoring",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC4.2",
                        title="COSO Principle 17: Deficiency Evaluation",
                        requirement_text="The entity evaluates and communicates internal control deficiencies in a timely manner",
                        ghostprompt_evidence_sources=[
                            "Compliance gap analysis with specific remediation suggestions",
                            "Cross-framework governance maturity scoring",
                            "Real-time WebSocket alerts for critical security events",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="alerting",
                        requires_external_audit=True,
                    ),
                ],
            },

            "CC5 — Control Activities": {
                "title": "Control Activities",
                "controls": [
                    ControlRequirement(
                        control_id="CC5.1",
                        title="COSO Principle 10: Control Selection",
                        requirement_text="The entity selects and develops control activities that contribute to the mitigation of risks",
                        ghostprompt_evidence_sources=[
                            "33 specialized detection engines covering injection, jailbreak, PII, secrets, content policy, semantic analysis, oracle attacks, and more",
                            "Per-tenant policy configuration with category-level action rules",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="detection",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC5.2",
                        title="COSO Principle 11: Technology Controls",
                        requirement_text="The entity selects and develops general control activities over technology to support the achievement of objectives",
                        ghostprompt_evidence_sources=[
                            "AI Firewall engine with configurable enforcement modes",
                            "Context-Aware DLP with Redis-backed PII vault",
                            "Tokenizer shield against token-level attacks",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="technology_control",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC5.3",
                        title="COSO Principle 12: Policy Deployment",
                        requirement_text="The entity deploys control activities through policies that establish what is expected",
                        ghostprompt_evidence_sources=[
                            "Policy engine: per-category configurable actions (BLOCK/FLAG/REDACT/SANITIZE)",
                            "Three enforcement tiers: STRICT/BALANCED/PERMISSIVE",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="policy_enforcement",
                        requires_external_audit=True,
                    ),
                ],
            },

            "CC6 — Logical and Physical Access Controls": {
                "title": "Logical and Physical Access Controls",
                "controls": [
                    ControlRequirement(
                        control_id="CC6.1",
                        title="Logical Access Security",
                        requirement_text="The entity implements logical access security software, infrastructure, and architectures over protected information assets",
                        ghostprompt_evidence_sources=[
                            "7-role RBAC: super_admin, org_owner, org_admin, security_analyst, developer, billing_viewer, read_only",
                            "Granular resource.action permission matrix",
                            "JWT-based authentication with session management",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="access_control",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC6.2",
                        title="User Credential Management",
                        requirement_text="Prior to issuing system credentials, the entity registers and authorizes new users",
                        ghostprompt_evidence_sources=[
                            "User registration with organization assignment",
                            "Role assignment requires org_admin or higher permissions",
                            "API key management with per-key scoping",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="access_control",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC6.3",
                        title="Credential Lifecycle Management",
                        requirement_text="The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets",
                        ghostprompt_evidence_sources=[
                            "Role modification logged in immutable audit trail",
                            "API key revocation capability",
                            "GDPR Right to Erasure implementation for data deletion",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="access_control",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC6.6",
                        title="System Boundary Protection",
                        requirement_text="The entity implements logical access security to protect against threats from sources outside its system boundaries",
                        ghostprompt_evidence_sources=[
                            "AI Firewall intercepts all LLM API calls at the proxy layer",
                            "Rate limiting per tenant/API key",
                            "IP-based geolocation and threat intelligence enrichment",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="perimeter_security",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC6.7",
                        title="Data Transmission Protection",
                        requirement_text="The entity restricts the transmission, movement, and removal of information to authorized users and processes",
                        ghostprompt_evidence_sources=[
                            "Context-Aware DLP automatically redacts PII/secrets before forwarding to LLM providers",
                            "Secret detector catches API keys, tokens, and credentials in transit",
                            "Data residency controls restrict data to configured regions",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_protection",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC6.8",
                        title="Unauthorized Software Prevention",
                        requirement_text="The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software",
                        ghostprompt_evidence_sources=[
                            "Supply chain attack detection engine",
                            "MCP Gateway tool registry with trust scoring",
                            "Package hallucination detector for software supply chain",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="detection",
                        requires_external_audit=True,
                    ),
                ],
            },

            "CC7 — System Operations": {
                "title": "System Operations",
                "controls": [
                    ControlRequirement(
                        control_id="CC7.1",
                        title="Infrastructure Monitoring",
                        requirement_text="The entity uses detection and monitoring procedures to identify changes to configurations that result in new vulnerabilities",
                        ghostprompt_evidence_sources=[
                            "ML drift daemon continuously monitors model behavior",
                            "Configuration change logging in immutable audit trail",
                            "Canary deployment with automatic rollback on regression",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="monitoring",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC7.2",
                        title="Anomaly Detection",
                        requirement_text="The entity monitors system components for anomalies that are indicative of malicious acts, natural disasters, and errors",
                        ghostprompt_evidence_sources=[
                            "33 detection engines process every LLM interaction in real-time",
                            "Campaign velocity spike detection for coordinated attacks",
                            "Pack Hunt detection for multi-vector attack correlation",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="continuous_monitoring",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC7.3",
                        title="Security Incident Evaluation",
                        requirement_text="The entity evaluates detected security events and determines whether they constitute security incidents",
                        ghostprompt_evidence_sources=[
                            "Automatic threat scoring with severity classification (safe/low/medium/high/critical)",
                            "Attack categorization across 20+ threat types",
                            "Campaign attribution linking related attacks",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="classification",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC7.4",
                        title="Incident Response",
                        requirement_text="The entity responds to identified security incidents by executing a defined incident response program",
                        ghostprompt_evidence_sources=[
                            "Automatic blocking/flagging/sanitization based on policy rules",
                            "Real-time WebSocket alerting to security teams",
                            "Incident forensics with full attack chain reconstruction",
                            "SIEM integration for enterprise incident response workflows",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="incident_response",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC7.5",
                        title="Incident Recovery",
                        requirement_text="The entity identifies, develops, and implements activities to recover from identified security incidents",
                        ghostprompt_evidence_sources=[
                            "Kill switch for emergency model deactivation",
                            "Canary rollback mechanism for model recovery",
                            "Post-incident audit trail analysis capability",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="recovery",
                        requires_external_audit=True,
                    ),
                ],
            },

            "CC8 — Change Management": {
                "title": "Change Management",
                "controls": [
                    ControlRequirement(
                        control_id="CC8.1",
                        title="Change Authorization and Approval",
                        requirement_text="The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes",
                        ghostprompt_evidence_sources=[
                            "Policy changes logged with actor_id, timestamp, and old/new values",
                            "RBAC ensures only authorized roles can modify security policies",
                            "All configuration changes produce immutable audit entries",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="change_control",
                        requires_external_audit=True,
                    ),
                ],
            },

            "CC9 — Risk Mitigation": {
                "title": "Risk Mitigation",
                "controls": [
                    ControlRequirement(
                        control_id="CC9.1",
                        title="Risk Mitigation Through Business Processes",
                        requirement_text="The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions",
                        ghostprompt_evidence_sources=[
                            "Multi-provider AI routing with automatic failover",
                            "Rate limiting prevents resource exhaustion",
                            "Sponge DoS detection prevents computational resource abuse",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="risk_mitigation",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="CC9.2",
                        title="Vendor and Business Partner Risk",
                        requirement_text="The entity assesses and manages risks associated with vendors and business partners",
                        ghostprompt_evidence_sources=[
                            "AI provider routing engine with 1600+ model registry",
                            "Supply chain attack detection for third-party components",
                            "MCP Gateway trust scoring for external tool integrations",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="vendor_risk",
                        requires_external_audit=True,
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # AVAILABILITY
            # ═══════════════════════════════════════════════════
            "Availability": {
                "title": "Availability",
                "controls": [
                    ControlRequirement(
                        control_id="A1.1",
                        title="Capacity Management",
                        requirement_text="The entity maintains, monitors, and evaluates current processing capacity and use of system components",
                        ghostprompt_evidence_sources=[
                            "Rate limiting per tenant prevents capacity exhaustion",
                            "Sponge DoS detection prevents computational resource abuse",
                            "Average latency monitoring (sub-15ms target)",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="monitoring",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="A1.2",
                        title="Recovery Planning",
                        requirement_text="The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup processes, and recovery infrastructure",
                        ghostprompt_evidence_sources=[
                            "Multi-provider routing with automatic failover",
                            "Kill switch for emergency model deactivation and recovery",
                            "Canary rollback on regression detection",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="recovery",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="A1.3",
                        title="Recovery Testing",
                        requirement_text="The entity tests recovery plan procedures supporting system recovery to meet its objectives",
                        ghostprompt_evidence_sources=[
                            "Automated Red Team simulator tests system resilience periodically",
                            "Red Team certification tier scoring validates ongoing security posture",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="testing",
                        requires_external_audit=True,
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # PROCESSING INTEGRITY
            # ═══════════════════════════════════════════════════
            "Processing Integrity": {
                "title": "Processing Integrity",
                "controls": [
                    ControlRequirement(
                        control_id="PI1.1",
                        title="Processing Completeness and Accuracy",
                        requirement_text="The entity implements policies and procedures over system processing to result in products, services, and reporting to meet the entity's objectives",
                        ghostprompt_evidence_sources=[
                            "Every scan produces deterministic threat scores with full detection breakdown",
                            "Hallucination forensics engine validates AI output accuracy",
                            "HMAC-signed scan records ensure processing integrity",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="integrity",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="PI1.2",
                        title="Processing Validation",
                        requirement_text="The entity implements policies and procedures to define data inputs to ensure completeness and accuracy during processing",
                        ghostprompt_evidence_sources=[
                            "Input validation across all API endpoints",
                            "Scan explainability output with human-readable explanations",
                            "Content length and format validation before processing",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="validation",
                        requires_external_audit=True,
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # CONFIDENTIALITY
            # ═══════════════════════════════════════════════════
            "Confidentiality": {
                "title": "Confidentiality",
                "controls": [
                    ControlRequirement(
                        control_id="C1.1",
                        title="Confidential Information Identification",
                        requirement_text="The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality",
                        ghostprompt_evidence_sources=[
                            "PII detector automatically identifies SSN, credit cards, phone numbers, emails",
                            "Secret detector catches API keys, tokens, passwords, and credentials",
                            "PHI detection for healthcare-related data (BAA mode)",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="classification",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="C1.2",
                        title="Confidential Information Disposal",
                        requirement_text="The entity disposes of confidential information to meet the entity's objectives related to confidentiality",
                        ghostprompt_evidence_sources=[
                            "GDPR Right to Erasure implementation for data deletion",
                            "Data retention policy with configurable retention periods",
                            "Automatic PII redaction before forwarding to LLM providers",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_lifecycle",
                        requires_external_audit=True,
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # PRIVACY
            # ═══════════════════════════════════════════════════
            "Privacy": {
                "title": "Privacy",
                "controls": [
                    ControlRequirement(
                        control_id="P1.1",
                        title="Privacy Notice",
                        requirement_text="The entity provides notice to data subjects about its privacy practices",
                        ghostprompt_evidence_sources=[
                            "Scan explainability: every blocked request includes human-readable reason",
                            "Compliance disclaimers on all framework reports",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="transparency",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="P3.1",
                        title="Personal Information Collection",
                        requirement_text="Personal information is collected consistent with the entity's objectives related to privacy",
                        ghostprompt_evidence_sources=[
                            "PII detection prevents unintended personal data collection via LLM prompts",
                            "Context-Aware DLP redacts PII before LLM processing",
                            "Data minimization through PII vault with tokenized references",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_protection",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="P4.1",
                        title="Personal Information Use and Retention",
                        requirement_text="The entity limits the use and retention of personal information",
                        ghostprompt_evidence_sources=[
                            "Configurable log retention periods per tenant",
                            "Data retention enforcement with automatic purging",
                            "Audit log retention aligned with compliance requirements",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_lifecycle",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="P6.1",
                        title="Personal Information Disclosure",
                        requirement_text="The entity discloses personal information to third parties only for the purposes identified in the entity's privacy notice",
                        ghostprompt_evidence_sources=[
                            "DLP prevents PII leakage to LLM providers",
                            "Data residency controls restrict data to configured regions",
                            "Secret detector prevents credential exposure to third parties",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_protection",
                        requires_external_audit=True,
                    ),
                    ControlRequirement(
                        control_id="P8.1",
                        title="Dispute Resolution and Recourse",
                        requirement_text="The entity implements a process for receiving, addressing, and resolving inquiries, complaints, and disputes",
                        ghostprompt_evidence_sources=[
                            "GDPR Right to Erasure API for data subject requests",
                            "Data export API for Right to Portability requests",
                            "Audit trail provides full transparency for dispute resolution",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="process",
                        requires_external_audit=True,
                    ),
                ],
            },
        }


# Singleton
soc2_type2_framework = SOC2Type2Framework()
