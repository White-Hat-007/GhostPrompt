import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select

from app.core.database import async_session_factory
from app.models.organization import Organization
from app.models.policy import Policy, PolicyRule

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
            }
        ]

async def fix():
    async with async_session_factory() as db:
        result = await db.execute(select(Organization))
        orgs = result.scalars().all()
        
        for org in orgs:
            result_pol = await db.execute(select(Policy).where(Policy.organization_id == org.id))
            existing_policies = {p.name: p for p in result_pol.scalars().all()}
            
            created = 0
            for p_data in default_policies:
                if p_data["name"] in existing_policies:
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
                
            print(f"Seeded {created} policies for org: {org.name} ({org.id})")
        await db.commit()

if __name__ == "__main__":
    asyncio.run(fix())
