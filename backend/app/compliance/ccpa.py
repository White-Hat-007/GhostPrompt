"""
GhostPrompt — CCPA/CPRA Compliance Mapping

Maps GhostPrompt's technical controls to the California Consumer Privacy Act
(CCPA) and California Privacy Rights Act (CPRA) requirements.

Consumer Rights: Right to Know, Right to Delete, Right to Opt-Out of Sale/Sharing,
Right to Correct, Right to Limit Use of Sensitive Personal Information,
Non-Discrimination.

DIFFERENTIATOR: Includes ADMT (Automated Decision-Making Technology) risk
assessment section — maps GhostPrompt's detection/blocking logic as evidence
of automated decision oversight, directly relevant to CPRA's newer regulations.

NOTE: This does NOT constitute legal compliance. CCPA/CPRA compliance requires
legal review of your organization's entire data handling practices.
"""

from app.compliance.framework_base import (
    ComplianceFramework, ControlRequirement, ControlStatus
)


class CCPAFramework(ComplianceFramework):
    framework_id = "ccpa"
    framework_name = "CCPA/CPRA"
    framework_version = "Cal. Civ. Code §1798.100-199.100 (as amended by CPRA 2023)"

    def get_control_taxonomy(self) -> dict[str, dict]:
        return {
            "§1798.100 — Right to Know": {
                "title": "Consumer's Right to Know About Personal Information Collected",
                "controls": [
                    ControlRequirement(
                        control_id="1798.100(a)",
                        title="Right to Know Categories of PI",
                        requirement_text="A consumer shall have the right to request that a business that collects personal information about the consumer disclose the categories and specific pieces of personal information the business has collected",
                        ghostprompt_evidence_sources=[
                            "PII detection categorizes all personal information types observed: SSN, credit cards, phone numbers, emails, medical records",
                            "Audit trail logs every piece of data processed with categorization",
                            "export_tenant_data() API provides full data inventory for disclosure",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="disclosure",
                    ),
                    ControlRequirement(
                        control_id="1798.100(b)",
                        title="Collection Disclosure at Point of Collection",
                        requirement_text="A business that collects personal information shall, at or before the point of collection, inform consumers of the categories of personal information to be collected and the purposes for which those categories shall be used",
                        ghostprompt_evidence_sources=[
                            "Scan explainability output transparently describes what data is being processed",
                            "API responses include detection category labels",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="notice",
                    ),
                ],
            },

            "§1798.105 — Right to Delete": {
                "title": "Consumer's Right to Request Deletion",
                "controls": [
                    ControlRequirement(
                        control_id="1798.105(a)",
                        title="Right to Delete Personal Information",
                        requirement_text="A consumer shall have the right to request that a business delete any personal information about the consumer which the business has collected from the consumer",
                        ghostprompt_evidence_sources=[
                            "delete_user_data() API — removes all audit entries for a specific user",
                            "Deletion logged in deleted_data_log with timestamp and requester",
                            "Data retention enforcement ensures no residual data beyond retention window",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_subject_rights",
                    ),
                    ControlRequirement(
                        control_id="1798.105(c)",
                        title="Service Provider Deletion Forwarding",
                        requirement_text="A business that receives a verifiable consumer request to delete shall delete the consumer's personal information from its records and direct any service providers to delete the consumer's personal information",
                        ghostprompt_evidence_sources=[
                            "DLP vault tokens can be invalidated to prevent future unredaction",
                            "Deletion cascades across audit log entries",
                            "SIEM integration can trigger downstream deletion workflows",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="deletion_cascade",
                    ),
                ],
            },

            "§1798.120 — Right to Opt-Out": {
                "title": "Consumer's Right to Opt-Out of Sale or Sharing",
                "controls": [
                    ControlRequirement(
                        control_id="1798.120(a)",
                        title="Right to Opt-Out of Sale/Sharing of PI",
                        requirement_text="A consumer shall have the right, at any time, to direct a business that sells or shares personal information about the consumer to third parties not to sell or share the consumer's personal information",
                        ghostprompt_evidence_sources=[
                            "GhostPrompt does NOT sell or share personal information to third parties",
                            "DLP prevents personal data from being sent to LLM providers (third parties) — effectively an automatic opt-out of sharing",
                            "Per-tenant data residency controls restrict data flow",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="opt_out",
                    ),
                ],
            },

            "§1798.106 — Right to Correct": {
                "title": "Consumer's Right to Correct Inaccurate Personal Information",
                "controls": [
                    ControlRequirement(
                        control_id="1798.106(a)",
                        title="Right to Correct Inaccurate Information",
                        requirement_text="A consumer shall have the right to request a business that maintains inaccurate personal information about the consumer to correct that inaccurate personal information",
                        ghostprompt_evidence_sources=[
                            "Correction-request workflow appends updated records while preserving originals for audit integrity",
                            "Correction events tracked as compliance actions in HMAC-signed immutable audit trail",
                            "Hallucination forensics validates data accuracy and flags potential inaccuracies proactively",
                            "Data subject request API supports programmatic correction requests with full traceability",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="data_subject_rights",
                    ),
                ],
            },

            "§1798.121 — Right to Limit Use of Sensitive PI": {
                "title": "Consumer's Right to Limit Use of Sensitive Personal Information",
                "controls": [
                    ControlRequirement(
                        control_id="1798.121(a)",
                        title="Limit Use and Disclosure of Sensitive PI",
                        requirement_text="A consumer shall have the right to direct a business that collects sensitive personal information to limit its use to that which is necessary for legitimate purposes",
                        ghostprompt_evidence_sources=[
                            "PII detector identifies sensitive PI categories: SSN, financial data, health information, precise geolocation",
                            "DLP automatically redacts sensitive PI before LLM processing — limits use to security scanning only",
                            "BAA mode provides enhanced protections for health-related sensitive PI",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="sensitive_data",
                    ),
                ],
            },

            "§1798.125 — Non-Discrimination": {
                "title": "Right of Non-Discrimination",
                "controls": [
                    ControlRequirement(
                        control_id="1798.125(a)",
                        title="Non-Discrimination for Exercising Rights",
                        requirement_text="A business shall not discriminate against a consumer because the consumer exercised any of the consumer's rights under this title",
                        ghostprompt_evidence_sources=[
                            "Security scanning applies uniformly regardless of privacy rights exercised",
                            "Service quality is not affected by data deletion or opt-out requests",
                            "Content policy engine monitors for discriminatory AI outputs",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="non_discrimination",
                    ),
                ],
            },

            # ═══════════════════════════════════════════════════
            # CPRA — AUTOMATED DECISION-MAKING TECHNOLOGY (ADMT)
            # ═══════════════════════════════════════════════════
            "CPRA — ADMT Risk Assessment": {
                "title": "Automated Decision-Making Technology (ADMT) Risk Assessment",
                "controls": [
                    ControlRequirement(
                        control_id="ADMT-1",
                        title="ADMT Profiling Transparency",
                        requirement_text="A business that uses automated decision-making technology shall provide consumers with meaningful information about the logic involved, the type of output produced, and the intended use",
                        ghostprompt_evidence_sources=[
                            "GhostPrompt IS automated decision-making technology — it automatically decides to block/flag/sanitize AI interactions",
                            "Every automated decision includes full scan explainability with detection reasoning",
                            "33 detection engines are documented and their logic is transparent to deployers",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="transparency",
                    ),
                    ControlRequirement(
                        control_id="ADMT-2",
                        title="ADMT Risk Assessment",
                        requirement_text="A business that uses automated decision-making technology shall conduct a risk assessment on a regular basis to evaluate the potential risks and benefits of the processing",
                        ghostprompt_evidence_sources=[
                            "Cross-framework compliance assessment evaluates ADMT risks across 9 frameworks",
                            "Red Team simulator regularly tests the accuracy and fairness of automated decisions",
                            "Content policy engine specifically monitors for biased automated outputs",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="risk_assessment",
                    ),
                    ControlRequirement(
                        control_id="ADMT-3",
                        title="Right to Opt-Out of ADMT",
                        requirement_text="A consumer shall have the right to opt out of a business's use of automated decision-making technology in connection with decisions that produce legal or similarly significant effects",
                        ghostprompt_evidence_sources=[
                            "FIREWALL_MODE can be set to 'monitor' (no blocking) or 'disabled' per tenant",
                            "FLAG mode allows human review before final automated action",
                            "Kill switch provides immediate opt-out of all automated decisions",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="opt_out",
                    ),
                    ControlRequirement(
                        control_id="ADMT-4",
                        title="Human Review of ADMT Decisions",
                        requirement_text="A consumer shall have the right to request human review of decisions made solely by automated decision-making technology",
                        ghostprompt_evidence_sources=[
                            "Dashboard provides full incident forensics for human review of every automated decision",
                            "Security analyst role specifically designed for human review of automated blocks",
                            "Manual policy override capability for overriding automated decisions",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="human_oversight",
                    ),
                    ControlRequirement(
                        control_id="ADMT-5",
                        title="ADMT Accuracy and Bias Monitoring",
                        requirement_text="Businesses using ADMT must monitor for accuracy and evaluate whether the technology has a disparate impact on consumers",
                        ghostprompt_evidence_sources=[
                            "Red Team certification scoring validates detection accuracy",
                            "Hallucination forensics engine monitors output accuracy",
                            "Content policy engine detects biased or discriminatory AI outputs",
                            "ML drift daemon monitors for accuracy degradation over time",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="monitoring",
                    ),
                ],
            },

            "Service Provider Obligations": {
                "title": "Service Provider and Contractor Obligations",
                "controls": [
                    ControlRequirement(
                        control_id="1798.140(ag)",
                        title="Service Provider Processing Limits",
                        requirement_text="A service provider shall not retain, use, or disclose personal information collected pursuant to its written contract with the business for any purpose other than those specified in the contract",
                        ghostprompt_evidence_sources=[
                            "GhostPrompt processes data only for security scanning as specified in service agreements",
                            "PII vault tokenization ensures personal data is not retained in usable form",
                            "Per-tenant isolation prevents cross-tenant data use",
                        ],
                        status=ControlStatus.SATISFIED,
                        evidence_type="contractual",
                    ),
                ],
            },
        }


# Singleton
ccpa_framework = CCPAFramework()
