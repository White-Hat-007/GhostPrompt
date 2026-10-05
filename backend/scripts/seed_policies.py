import asyncio
import sys
import os

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from app.core.database import async_session_factory
from app.models.organization import Organization
from app.models.policy import Policy, PolicyRule
from app.core.logging import get_logger

logger = get_logger("seed_policies")

async def seed():
    async with async_session_factory() as db:
        # Get all organizations
        result = await db.execute(select(Organization))
        orgs = result.scalars().all()
        if not orgs:
            org = Organization(name="GhostPrompt Demo Org", slug="demo-org", plan="enterprise")
            db.add(org)
            await db.commit()
            await db.refresh(org)
            orgs = [org]
            logger.info("created_demo_org", org_id=str(org.id))

        # Define the default policies - 12 Enterprise Security Policies
        default_policies = [
            {
                "name": "Direct Instruction Override Detection",
                "description": "Detects direct system prompt overrides and instruction injection attempts.",
                "policy_type": "default",
                "priority": 120,
                "is_active": True,
                "rules": [
                    {
                        "name": "Direct Override Blocker",
                        "description": "Blocks direct system prompt overrides.",
                        "rule_type": "direct_instruction_override",
                        "detector": "direct_instruction_override",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Jailbreak & Persona Switch Defense",
                "description": "Catches persona adoption and jailbreak bypass attempts.",
                "policy_type": "default",
                "priority": 115,
                "is_active": True,
                "rules": [
                    {
                        "name": "Jailbreak Persona Blocker",
                        "description": "Catches persona adoption and bypasses.",
                        "rule_type": "jailbreak_persona_switch",
                        "detector": "jailbreak_persona_switch",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "System Prompt Extraction Prevention",
                "description": "Prevents extraction and leakage of system prompts.",
                "policy_type": "strict",
                "priority": 110,
                "is_active": True,
                "rules": [
                    {
                        "name": "Prompt Extraction Blocker",
                        "description": "Catches attempts to leak the system prompt.",
                        "rule_type": "system_prompt_extraction",
                        "detector": "system_prompt_extraction",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Multi-Turn Slow Build Attack Detection",
                "description": "Detects gradual conversational attacks built over multiple turns.",
                "policy_type": "strict",
                "priority": 105,
                "is_active": True,
                "rules": [
                    {
                        "name": "Multi-Turn Attack Analyzer",
                        "description": "Catches slow-build conversational attacks.",
                        "rule_type": "multi_turn_slow_build",
                        "detector": "multi_turn_slow_build",
                        "action": "flag",
                        "severity": "high",
                    }
                ]
            },
            {
                "name": "Encoding & Obfuscation Defense",
                "description": "Detects encoded payloads, Base64, Hex, and obfuscated text attacks.",
                "policy_type": "strict",
                "priority": 100,
                "is_active": True,
                "rules": [
                    {
                        "name": "Encoding Detector",
                        "description": "Catches Base64, Hex, and obfuscated text.",
                        "rule_type": "encoding_obfuscation",
                        "detector": "encoding_obfuscation",
                        "action": "block",
                        "severity": "high",
                    }
                ]
            },
            {
                "name": "Data Exfiltration Prevention",
                "description": "Prevents unauthorized data retrieval and exfiltration attempts.",
                "policy_type": "compliance",
                "priority": 95,
                "is_active": True,
                "rules": [
                    {
                        "name": "Data Exfiltration Blocker",
                        "description": "Catches unauthorized data retrieval attempts.",
                        "rule_type": "data_exfiltration",
                        "detector": "data_exfiltration",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Agentic Tool & Function Hijacking Defense",
                "description": "Validates and monitors AI agent tool calls to prevent hijacking.",
                "policy_type": "custom",
                "priority": 90,
                "is_active": True,
                "rules": [
                    {
                        "name": "Agent Tool Guard",
                        "description": "Catches malicious agent function calls.",
                        "rule_type": "agentic_tool_hijacking",
                        "detector": "agentic_tool_hijacking",
                        "action": "block",
                        "severity": "high",
                    }
                ]
            },
            {
                "name": "Social Engineering Attack Detection",
                "description": "Catches social engineering using urgency, authority, and manipulation.",
                "policy_type": "custom",
                "priority": 85,
                "is_active": True,
                "rules": [
                    {
                        "name": "Social Engineering Blocker",
                        "description": "Catches urgency and authority manipulation.",
                        "rule_type": "social_engineering",
                        "detector": "social_engineering",
                        "action": "flag",
                        "severity": "high",
                    }
                ]
            },
            {
                "name": "Delimiter & Role Injection Prevention",
                "description": "Blocks fake system and role delimiters used in prompt injection.",
                "policy_type": "custom",
                "priority": 80,
                "is_active": True,
                "rules": [
                    {
                        "name": "Delimiter Injection Blocker",
                        "description": "Catches fake system or role delimiters.",
                        "rule_type": "delimiter_injection",
                        "detector": "delimiter_injection",
                        "action": "block",
                        "severity": "high",
                    }
                ]
            },
            {
                "name": "Output Manipulation Detection",
                "description": "Detects attempts to manipulate and constrain output formatting.",
                "policy_type": "advanced",
                "priority": 75,
                "is_active": True,
                "rules": [
                    {
                        "name": "Output Manipulation Blocker",
                        "description": "Catches forced output formatting constraints.",
                        "rule_type": "output_manipulation",
                        "detector": "output_manipulation",
                        "action": "flag",
                        "severity": "medium",
                    }
                ]
            },
            {
                "name": "Adversarial Suffix Detection",
                "description": "Catches anomalous special character strings and adversarial suffixes.",
                "policy_type": "advanced",
                "priority": 70,
                "is_active": True,
                "rules": [
                    {
                        "name": "Adversarial Suffix Detector",
                        "description": "Catches anomalous special character strings.",
                        "rule_type": "adversarial_suffix",
                        "detector": "adversarial_suffix",
                        "action": "flag",
                        "severity": "medium",
                    }
                ]
            },
            {
                "name": "Sensitive Topic Escalation Prevention",
                "description": "Blocks requests for harmful materials, software, and sensitive information.",
                "policy_type": "compliance",
                "priority": 65,
                "is_active": True,
                "rules": [
                    {
                        "name": "Sensitive Topic Enforcer",
                        "description": "Catches requests for harmful materials and software.",
                        "rule_type": "sensitive_topic_escalation",
                        "detector": "sensitive_topic_escalation",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Comprehensive PII & Secrets Protection",
                "description": "Scans for personally identifiable information and API credentials in output.",
                "policy_type": "strict",
                "priority": 60,
                "is_active": True,
                "rules": [
                    {
                        "name": "PII Detection",
                        "description": "Catches leaked personally identifiable info.",
                        "rule_type": "pii_detector",
                        "detector": "pii_detector",
                        "action": "sanitize",
                        "severity": "high",
                    },
                    {
                        "name": "Secrets & API Keys Scanner",
                        "description": "Catches AWS keys, JWTs, and passwords.",
                        "rule_type": "secret_detector",
                        "detector": "secret_detector",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            # ── Advanced Threat Protection Policies (Layers 18-23) ──
            {
                "name": "Oracle Attack Shield",
                "description": "Detects model inversion and weight stealing via behavioral pattern analysis across query sessions. Monitors query velocity, logprob fishing, semantic clustering, and systematic perturbation patterns.",
                "policy_type": "default",
                "priority": 55,
                "is_active": True,
                "rules": [
                    {
                        "name": "Query Velocity Monitor",
                        "description": "Throttles API keys exceeding 500 queries/hour.",
                        "rule_type": "oracle_velocity",
                        "detector": "oracle_detector",
                        "action": "flag",
                        "severity": "high",
                    },
                    {
                        "name": "Logprob Fuzzing",
                        "description": "Flags sessions requesting logprobs on >80% of requests.",
                        "rule_type": "oracle_logprob",
                        "detector": "oracle_detector",
                        "action": "flag",
                        "severity": "high",
                    },
                    {
                        "name": "Semantic Clustering Detector",
                        "description": "Flags oracle sweeps with >0.85 similarity across 50+ queries.",
                        "rule_type": "oracle_clustering",
                        "detector": "oracle_detector",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Sponge DoS Protector",
                "description": "Prevents adversarial token sequences from causing GPU compute exhaustion through worst-case Transformer attention complexity.",
                "policy_type": "default",
                "priority": 50,
                "is_active": True,
                "rules": [
                    {
                        "name": "Token Complexity Scorer",
                        "description": "Blocks prompts with adversarial entropy profiles.",
                        "rule_type": "sponge_complexity",
                        "detector": "sponge_detector",
                        "action": "block",
                        "severity": "critical",
                    },
                    {
                        "name": "Compute Budget Enforcer",
                        "description": "Throttles sessions exceeding compute allocation.",
                        "rule_type": "sponge_budget",
                        "detector": "sponge_detector",
                        "action": "flag",
                        "severity": "high",
                    },
                    {
                        "name": "Inference Timeout Guard",
                        "description": "Kills requests exceeding max inference time.",
                        "rule_type": "sponge_timeout",
                        "detector": "sponge_detector",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Business Logic Guard",
                "description": "Requires intent validation before any irreversible or destructive tool execution. Detects social engineering, scope creep, and unverifiable authority claims.",
                "policy_type": "advanced",
                "priority": 45,
                "is_active": True,
                "rules": [
                    {
                        "name": "Intent Auditor",
                        "description": "Validates business intent behind destructive actions.",
                        "rule_type": "intent_audit",
                        "detector": "intent_validator",
                        "action": "flag",
                        "severity": "high",
                    },
                    {
                        "name": "Scope Anomaly Detector",
                        "description": "Flags actions broader than the stated user goal.",
                        "rule_type": "intent_scope",
                        "detector": "intent_validator",
                        "action": "flag",
                        "severity": "high",
                    },
                    {
                        "name": "Destructive Action Gate",
                        "description": "Requires human approval for destructive tool calls.",
                        "rule_type": "intent_gate",
                        "detector": "intent_validator",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Memorization Leak Blocker",
                "description": "Detects and blocks training data exfiltration via repetition attacks, divergence triggers, and verbatim reproduction patterns.",
                "policy_type": "default",
                "priority": 40,
                "is_active": True,
                "rules": [
                    {
                        "name": "Repetition Trigger Detector",
                        "description": "Blocks prompts that trigger training data regurgitation.",
                        "rule_type": "memorization_trigger",
                        "detector": "output_inspector",
                        "action": "block",
                        "severity": "critical",
                    },
                    {
                        "name": "Code Leak Scanner",
                        "description": "Redacts proprietary code patterns from AI output.",
                        "rule_type": "memorization_code",
                        "detector": "output_inspector",
                        "action": "sanitize",
                        "severity": "high",
                    },
                    {
                        "name": "Copyright Fingerprinter",
                        "description": "Flags outputs with high similarity to protected content.",
                        "rule_type": "memorization_copyright",
                        "detector": "output_inspector",
                        "action": "flag",
                        "severity": "medium",
                    }
                ]
            },
            {
                "name": "Tokenizer Shield",
                "description": "Blocks zero-day Unicode and tokenizer-splitting attacks invisible to standard content filters. Detects homoglyphs, BiDi overrides, zero-width injection, and Private Use Area abuse.",
                "policy_type": "advanced",
                "priority": 35,
                "is_active": True,
                "rules": [
                    {
                        "name": "Full Unicode Normalizer",
                        "description": "Sanitizes weaponized Unicode normalization divergence.",
                        "rule_type": "tokenizer_normalize",
                        "detector": "tokenizer_shield",
                        "action": "sanitize",
                        "severity": "high",
                    },
                    {
                        "name": "Bidirectional Override Blocker",
                        "description": "Immediately blocks bidirectional override characters.",
                        "rule_type": "tokenizer_bidi",
                        "detector": "tokenizer_shield",
                        "action": "block",
                        "severity": "critical",
                    },
                    {
                        "name": "Token Boundary Analyzer",
                        "description": "Flags invisible characters at token boundaries.",
                        "rule_type": "tokenizer_boundary",
                        "detector": "tokenizer_shield",
                        "action": "flag",
                        "severity": "medium",
                    }
                ]
            },
            {
                "name": "RAG & Out-of-Band Defender",
                "description": "Inspects all externally retrieved content (web pages, emails, documents) before it enters the LLM context window. Detects hidden text, HTML injection vectors, and tracks source reputation.",
                "policy_type": "custom",
                "priority": 30,
                "is_active": True,
                "rules": [
                    {
                        "name": "External Content Inspector",
                        "description": "Sanitizes prompt injections embedded in retrieved content.",
                        "rule_type": "external_injection",
                        "detector": "external_content_inspector",
                        "action": "sanitize",
                        "severity": "critical",
                    },
                    {
                        "name": "Hidden Text Extractor",
                        "description": "Flags white-on-white and display:none hidden text.",
                        "rule_type": "external_hidden",
                        "detector": "external_content_inspector",
                        "action": "flag",
                        "severity": "high",
                    },
                    {
                        "name": "Source Reputation Engine",
                        "description": "Throttles content from sources with prior injection history.",
                        "rule_type": "external_reputation",
                        "detector": "external_content_inspector",
                        "action": "flag",
                        "severity": "high",
                    }
                ]
            },
            {
                "name": "Pliny Defense Engine",
                "description": "Detects Pliny the Liberator techniques: nested fiction, authority chains, and OBLITERATUS.",
                "policy_type": "ultra-advanced",
                "priority": 25,
                "is_active": True,
                "rules": [
                    {
                        "name": "Pliny Jailbreak Detector",
                        "description": "Catches known Pliny structural jailbreaks.",
                        "rule_type": "pliny_defense",
                        "detector": "pliny_defense",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Zero-Day Jailbreak Radar",
                "description": "Detects novel and emerging attacks via perplexity spikes, entropy analysis, and adversarial suffix detection.",
                "policy_type": "ultra-advanced",
                "priority": 24,
                "is_active": True,
                "rules": [
                    {
                        "name": "Zero-Day Radar Engine",
                        "description": "Catches unknown zero-day anomalies.",
                        "rule_type": "zero_day_radar",
                        "detector": "zero_day_radar",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "ML Threat Classifier Ensemble",
                "description": "Three-model ensemble trained on 50K+ synthetic jailbreak samples for sub-millisecond intent classification.",
                "policy_type": "ultra-advanced",
                "priority": 23,
                "is_active": True,
                "rules": [
                    {
                        "name": "ML Ensemble Core",
                        "description": "Classifies inputs via DistilBERT, RoBERTa, and MiniLM embeddings.",
                        "rule_type": "ml_ensemble",
                        "detector": "ml_ensemble",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Coordinated Campaign Detector",
                "description": "Detects coordinated multi-session and cross-IP jailbreak campaigns and distributed probing.",
                "policy_type": "ultra-advanced",
                "priority": 22,
                "is_active": True,
                "rules": [
                    {
                        "name": "Campaign Correlation Engine",
                        "description": "Blocks coordinated distributed attacks.",
                        "rule_type": "campaign_detector",
                        "detector": "campaign_detector",
                        "action": "block",
                        "severity": "high",
                    }
                ]
            },
            {
                "name": "Constitutional Response Auditor",
                "description": "Acts as a post-response safety judge to catch jailbreaks that successfully evade input inspection.",
                "policy_type": "ultra-advanced",
                "priority": 21,
                "is_active": True,
                "rules": [
                    {
                        "name": "Constitutional Judge",
                        "description": "Audits outbound model outputs against constitutional bounds.",
                        "rule_type": "constitutional_auditor",
                        "detector": "constitutional_auditor",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            # ── Elite Security Layers (Layers 31-33) ──
            {
                "name": "Pack Hunt Defense",
                "description": "Defends against multi-agent request fragmentation and reassembly attacks (like the Pliny Claude jailbreak). Tracks and aggregates partial prompts across sessions.",
                "policy_type": "ultra-advanced",
                "priority": 20,
                "is_active": True,
                "rules": [
                    {
                        "name": "Fragmentation Aggregator",
                        "description": "Aggregates partial payload fragments across concurrent sessions.",
                        "rule_type": "pack_hunt_defense",
                        "detector": "pack_hunt_detector",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Multi-Agent Hijacking Guard",
                "description": "Prevents cross-agent prompt propagation, inter-agent privilege escalation, and swarm hijacking.",
                "policy_type": "ultra-advanced",
                "priority": 19,
                "is_active": True,
                "rules": [
                    {
                        "name": "Cross-Agent Validator",
                        "description": "Validates inter-agent communications for propagation attacks.",
                        "rule_type": "multi_agent_guard",
                        "detector": "multi_agent_guard",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
            {
                "name": "Hardware Side-Channel Protector",
                "description": "Detects cache timing attacks, power analysis probes, and physical hardware exploits disguised as AI queries.",
                "policy_type": "ultra-advanced",
                "priority": 18,
                "is_active": True,
                "rules": [
                    {
                        "name": "Hardware Exploit Scanner",
                        "description": "Scans for hardware-level exploit payloads.",
                        "rule_type": "hardware_security",
                        "detector": "hardware_side_channel",
                        "action": "block",
                        "severity": "critical",
                    }
                ]
            },
        ]

        for org in orgs:
            # Check existing policies to avoid duplicates
            result = await db.execute(select(Policy).where(Policy.organization_id == org.id))
            existing_policies = {p.name: p for p in result.scalars().all()}

            created = 0
            for p_data in default_policies:
                if p_data["name"] in existing_policies:
                    logger.info(f"Policy already exists: {p_data['name']} for org {org.id}")
                    continue
                    
                policy = Policy(
                    organization_id=org.id,
                    name=p_data["name"],
                    description=p_data["description"],
                    policy_type=p_data["policy_type"],
                    priority=p_data["priority"],
                    is_active=p_data["is_active"]
                )
                db.add(policy)
                await db.flush() # get ID

                for r_data in p_data["rules"]:
                    rule = PolicyRule(
                        policy_id=policy.id,
                        name=r_data["name"],
                        description=r_data["description"],
                        rule_type=r_data["rule_type"],
                        detector=r_data["detector"],
                        action=r_data["action"],
                        severity=r_data["severity"],
                        threshold=r_data.get("threshold", 0.7),
                        is_active=True,
                        priority=100
                    )
                    db.add(rule)
                
                created += 1

            await db.commit()
            logger.info(f"Successfully seeded {created} policies with rules for org {org.id}")

if __name__ == "__main__":
    asyncio.run(seed())
