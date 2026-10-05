"""
GhostPrompt — EU AI Act Compliance Mapping

Maps GhostPrompt's technical controls to EU AI Act (Regulation 2024/1689)
requirements for high-risk AI systems.

Covers: Art 9 (risk management), Art 10 (data governance), Art 11 (technical
documentation), Art 12 (record-keeping), Art 13 (transparency), Art 14 (human
oversight), Art 15 (accuracy/robustness/cybersecurity), Art 50 (transparency
obligations for AI systems).

DIFFERENTIATOR: Includes Annex III risk-tier classifier helper — walks tenants
through high-risk use case categories to self-classify their AI deployment.
"""

from app.compliance.framework_base import (
    ComplianceFramework, ControlRequirement, ControlStatus
)


class EUAIActFramework(ComplianceFramework):
    framework_id = "eu_ai_act"
    framework_name = "EU AI Act"
    framework_version = "Regulation (EU) 2024/1689"

    def get_control_taxonomy(self) -> dict[str, dict]:
        return {
            "Art 9 — Risk Management System": {
                "title": "Risk Management System",
                "controls": [
                    ControlRequirement(
                        control_id="Art-9.1",
                        title="Risk Management System Establishment",
                        requirement_text="A risk management system shall be established, implemented, documented and maintained in relation to high-risk AI systems",
                        ghostprompt_evidence_sources=[
                            "33 detection engines constitute a comprehensive AI risk management system",
                            "Configurable FIREWALL_MODE: enforce/monitor/disabled per tenant",
                            "THREAT_SCORE_THRESHOLD configurable per deployment",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="risk_management",
                    ),
                    ControlRequirement(
                        control_id="Art-9.2",
                        title="Risk Identification and Analysis",
                        requirement_text="The risk management system shall identify and analyse the known and reasonably foreseeable risks that the high-risk AI system can pose",
                        ghostprompt_evidence_sources=[
                            "Automated Red Team simulator tests 20+ attack categories",
                            "Threat attribution engine with MITRE ATLAS mapping",
                            "ML adaptive drift daemon for emerging threat detection",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="risk_analysis",
                    ),
                    ControlRequirement(
                        control_id="Art-9.4",
                        title="Risk Mitigation Measures",
                        requirement_text="Risk management measures shall be such that the relevant residual risk associated with each hazard is judged to be acceptable",
                        ghostprompt_evidence_sources=[
                            "Per-category configurable actions: BLOCK/FLAG/REDACT/SANITIZE",
                            "Three enforcement tiers: STRICT/BALANCED/PERMISSIVE",
                            "Gap remediation suggestions in compliance reports",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="risk_mitigation",
                    ),
                    ControlRequirement(
                        control_id="Art-9.5",
                        title="Testing for Risk Management",
                        requirement_text="High-risk AI systems shall be tested for the purposes of identifying the most appropriate and targeted risk management measures",
                        ghostprompt_evidence_sources=[
                            "Red Team certification tiers: BASIC → ADVANCED → ELITE → PLATINUM",
                            "Automated penetration testing across prompt injection, jailbreak, PII, encoded payloads, oracle attacks",
                            "Zero-day detection via ML embedding similarity",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="testing",
                    ),
                ],
            },

            "Art 10 — Data Governance": {
                "title": "Data and Data Governance",
                "controls": [
                    ControlRequirement(
                        control_id="Art-10.1",
                        title="Data Governance Practices",
                        requirement_text="High-risk AI systems which make use of techniques involving the training of AI models with data shall be developed on the basis of training, validation and testing data sets that meet quality criteria",
                        ghostprompt_evidence_sources=[
                            "PII detection ensures training data quality by identifying personal data leakage",
                            "Data residency controls restrict data to configured regions",
                            "Context-Aware DLP prevents sensitive data contamination",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_governance",
                    ),
                    ControlRequirement(
                        control_id="Art-10.2",
                        title="Data Quality Criteria",
                        requirement_text="Training, validation and testing data sets shall be subject to data governance and management practices",
                        ghostprompt_evidence_sources=[
                            "ML drift daemon monitors model behavior for quality degradation",
                            "Hallucination forensics engine validates output quality",
                            "Canary rollback on quality regression",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_quality",
                    ),
                    ControlRequirement(
                        control_id="Art-10.5",
                        title="Bias Examination",
                        requirement_text="To the extent that it is strictly necessary for the purposes of ensuring bias detection and correction, the providers of such systems may exceptionally process special categories of personal data",
                        ghostprompt_evidence_sources=[
                            "Content policy engine detects and flags biased AI outputs",
                            "Toxicity detection across multiple categories",
                            "Fairness monitoring as part of Red Team testing",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="bias_detection",
                    ),
                ],
            },

            "Art 11 — Technical Documentation": {
                "title": "Technical Documentation",
                "controls": [
                    ControlRequirement(
                        control_id="Art-11.1",
                        title="Technical Documentation",
                        requirement_text="The technical documentation of a high-risk AI system shall be drawn up before that system is placed on the market or put into service",
                        ghostprompt_evidence_sources=[
                            "Compliance reports generate comprehensive technical documentation",
                            "Cross-framework governance reports document system architecture",
                            "API documentation for all detection engines and policy configurations",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="documentation",
                    ),
                ],
            },

            "Art 12 — Record-Keeping": {
                "title": "Record-Keeping",
                "controls": [
                    ControlRequirement(
                        control_id="Art-12.1",
                        title="Automatic Logging",
                        requirement_text="High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system",
                        ghostprompt_evidence_sources=[
                            "Every scan event immutably logged with HMAC-SHA256 signatures",
                            "Audit trail includes: actor_id, action, resource, timestamp, IP, threat results",
                            "Configurable retention periods (default 90 days, up to unlimited)",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="logging",
                    ),
                    ControlRequirement(
                        control_id="Art-12.2",
                        title="Traceability",
                        requirement_text="The logging capabilities shall ensure a level of traceability of the functioning of the AI system that is appropriate to the intended purpose",
                        ghostprompt_evidence_sources=[
                            "Full attack chain reconstruction for every security event",
                            "Campaign attribution linking related attacks",
                            "Traceback evidence chain with attacker profiling",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="traceability",
                    ),
                ],
            },

            "Art 13 — Transparency": {
                "title": "Transparency and Provision of Information to Deployers",
                "controls": [
                    ControlRequirement(
                        control_id="Art-13.1",
                        title="Transparency for Deployers",
                        requirement_text="High-risk AI systems shall be designed and developed in such a way as to ensure that their operation is sufficiently transparent to enable deployers to interpret the system's output and use it appropriately",
                        ghostprompt_evidence_sources=[
                            "Every blocked request includes human-readable explanation of detection reasons",
                            "Detection breakdown shows which of 33 engines triggered and why",
                            "Threat score composition is fully transparent",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="explainability",
                    ),
                    ControlRequirement(
                        control_id="Art-13.3",
                        title="Interpretability of Output",
                        requirement_text="Information shall be provided in a clear, comprehensive and accessible format",
                        ghostprompt_evidence_sources=[
                            "Dashboard provides visual representation of all security metrics",
                            "Compliance reports available in PDF, CSV, and JSON formats",
                            "MITRE ATLAS attack taxonomy mapping for industry-standard classification",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="reporting",
                    ),
                ],
            },

            "Art 14 — Human Oversight": {
                "title": "Human Oversight",
                "controls": [
                    ControlRequirement(
                        control_id="Art-14.1",
                        title="Human Oversight Design",
                        requirement_text="High-risk AI systems shall be designed and developed in such a way that they can be effectively overseen by natural persons during the period in which they are in use",
                        ghostprompt_evidence_sources=[
                            "Dashboard with real-time attack feed for human monitoring",
                            "Manual policy override capability for security analysts",
                            "FLAG mode allows human review before blocking",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="human_oversight",
                    ),
                    ControlRequirement(
                        control_id="Art-14.3(a)",
                        title="Human Override Capability",
                        requirement_text="The individuals to whom human oversight is assigned are able to fully understand the capacities and limitations of the system",
                        ghostprompt_evidence_sources=[
                            "Scan explainability output with full detection reasoning",
                            "Compliance gap analysis highlights system limitations",
                            "Red Team certification tier shows system's detection boundaries",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="explainability",
                    ),
                    ControlRequirement(
                        control_id="Art-14.4",
                        title="Stop or Override Mechanism",
                        requirement_text="Where appropriate, the human oversight measures shall enable the individuals to override or reverse the output of the system",
                        ghostprompt_evidence_sources=[
                            "Kill switch (api/killswitch.py) for emergency model deactivation",
                            "Per-category action override: security analysts can change BLOCK→FLAG→ALLOW",
                            "Canary rollback for reversing automated decisions",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="override",
                    ),
                ],
            },

            "Art 15 — Accuracy, Robustness, Cybersecurity": {
                "title": "Accuracy, Robustness and Cybersecurity",
                "controls": [
                    ControlRequirement(
                        control_id="Art-15.1",
                        title="Accuracy",
                        requirement_text="High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy",
                        ghostprompt_evidence_sources=[
                            "Red Team certification tier scoring validates detection accuracy",
                            "Hallucination forensics engine validates AI output accuracy",
                            "ML drift daemon monitors for accuracy degradation",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="accuracy",
                    ),
                    ControlRequirement(
                        control_id="Art-15.3",
                        title="Robustness",
                        requirement_text="High-risk AI systems shall be resilient as regards attempts by unauthorised third parties to alter their use, outputs or performance by exploiting the system vulnerabilities",
                        ghostprompt_evidence_sources=[
                            "33 detection engines protect against adversarial attacks",
                            "Encoded payload detection prevents evasion via obfuscation",
                            "Cross-lingual attack detection prevents language-based bypass",
                            "Zero-day detection via ML embedding similarity",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="robustness",
                    ),
                    ControlRequirement(
                        control_id="Art-15.4",
                        title="Cybersecurity",
                        requirement_text="High-risk AI systems shall be resilient as regards attempts by unauthorised third parties to exploit system vulnerabilities",
                        ghostprompt_evidence_sources=[
                            "AI Firewall intercepts all LLM API calls at the proxy layer",
                            "Supply chain attack detection engine",
                            "Oracle attack prevention (model extraction, memorization probing)",
                            "Sponge DoS detection prevents resource exhaustion attacks",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="cybersecurity",
                    ),
                ],
            },

            "Art 50 — Transparency Obligations": {
                "title": "Transparency Obligations for Certain AI Systems",
                "controls": [
                    ControlRequirement(
                        control_id="Art-50.1",
                        title="AI Interaction Disclosure",
                        requirement_text="Providers shall ensure that AI systems intended to directly interact with natural persons are designed and developed in such a way that the natural person concerned is informed that they are interacting with an AI system",
                        ghostprompt_evidence_sources=[
                            "Scan explainability clearly identifies GhostPrompt as an AI security system in its output",
                            "Compliance reports carry explicit disclaimers about automated processing",
                            "Content transparency labels in scan results",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="transparency",
                    ),
                    ControlRequirement(
                        control_id="Art-50.4",
                        title="Synthetic Content Marking",
                        requirement_text="Providers of AI systems that generate synthetic content shall ensure that the outputs of the AI system are marked in a machine-readable format and detectable as artificially generated or manipulated",
                        ghostprompt_evidence_sources=[
                            "GhostPrompt does not generate synthetic content — it scans and filters existing AI system interactions",
                            "Hallucination detection helps identify AI-generated false content",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="content_marking",
                        gap_note="GhostPrompt is a scanning/filtering system, not a content generation system",
                    ),
                ],
            },

            "Annex III — Risk-Tier Classification": {
                "title": "High-Risk AI Systems (Risk-Tier Classifier)",
                "controls": [
                    ControlRequirement(
                        control_id="Annex-III.1",
                        title="Biometric Identification Systems",
                        requirement_text="AI systems intended to be used for real-time and post remote biometric identification of natural persons",
                        ghostprompt_evidence_sources=[
                            "Risk-Tier Classifier: GhostPrompt can help tenants self-classify whether their AI deployment falls into this high-risk category",
                            "If applicable: GhostPrompt's PII detection would protect biometric data from LLM exposure",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="risk_classification",
                        gap_note="GhostPrompt does not perform biometric identification — mark as applicable if your protected AI system does",
                    ),
                    ControlRequirement(
                        control_id="Annex-III.4",
                        title="Employment and Workers Management",
                        requirement_text="AI systems intended to be used for recruitment, selection, or worker management decisions",
                        ghostprompt_evidence_sources=[
                            "Risk-Tier Classifier: If your AI system makes employment decisions, it falls under high-risk tier",
                            "GhostPrompt's content policy engine detects bias in AI outputs — directly relevant evidence for employment AI fairness",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="risk_classification",
                        gap_note="Mark as applicable if the AI system protected by GhostPrompt makes employment decisions",
                    ),
                    ControlRequirement(
                        control_id="Annex-III.5",
                        title="Essential Services Access",
                        requirement_text="AI systems intended to evaluate creditworthiness, set insurance premiums, or determine access to essential services",
                        ghostprompt_evidence_sources=[
                            "Risk-Tier Classifier: AI systems determining access to essential services are high-risk",
                            "GhostPrompt's fairness monitoring and bias detection provide critical evidence for these use cases",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="risk_classification",
                        gap_note="Mark as applicable if the AI system determines access to credit, insurance, or essential services",
                    ),
                    ControlRequirement(
                        control_id="Annex-III.8",
                        title="Law Enforcement",
                        requirement_text="AI systems intended to be used by law enforcement authorities for risk assessments, polygraph, or detecting emotional state",
                        ghostprompt_evidence_sources=[
                            "Risk-Tier Classifier: Law enforcement AI applications are high-risk",
                            "GhostPrompt provides audit trail and transparency evidence critical for law enforcement AI oversight",
                        ],
                        status=ControlStatus.NOT_APPLICABLE,
                        evidence_type="risk_classification",
                        gap_note="Mark as applicable if the AI system is used in law enforcement contexts",
                    ),
                ],
            },
        }


# Singleton
eu_ai_act_framework = EUAIActFramework()
