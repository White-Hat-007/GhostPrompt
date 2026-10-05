"""
GhostPrompt AI Firewall Engine

The central orchestrator that runs all detection pipelines against
incoming prompts and AI outputs, aggregates threat scores, and
determines the final action (allow, block, sanitize, flag).

33 Detection Layers:
 1. Prompt Injection (pattern matching)
 2. Jailbreak Detection
 3. Encoded Payload Detection (Base64, hex, URL, zero-width)
 4. Obfuscation Detection (leetspeak, homoglyphs, BiDi)
 5. PII Detection (SSN, email, credit card, phone, etc.)
 6. Secret Detection (API keys, tokens, passwords)
 7. Content Policy (malware, violence, illegal)
 8. Multi-Turn Context Analysis (escalation, boundary testing, persona-locking)
 9. Agentic Tool Call Inspection (destructive calls, goal hijacking)
10. Semantic Intent Classifier (ML)
11. Vector Anomaly (Zero-Day)
12. Multimodal Inspector (steganography)
13. RAG Sandbox (context poisoning)
14. Exotic Encoding
15. Cross-Lingual
16. LLM DoS Prevention
17. Supply Chain Validation
--- Advanced Threat Protection ---
18. Oracle Attack Detector (Model Inversion / Weight Stealing)
19. Sponge DoS Detector (Transformer compute attacks)
20. Intent Validator (Business Logic Exploitation)
21. Output Inspector (Training Data Memorization)
22. Tokenizer Shield (Zero-Day Unicode)
23. External Content Inspector (Out-of-Band Injection)
24. Hallucination Detector (Output Factuality)
25. Model Weight Scanner (Supply Chain Integrity)
--- Ultra-Advanced Threat Protection ---
26. Hardware Side-Channel Detector
27. Pliny Defense Engine (L1B3RT4S / G0DM0D3 / OBLITERATUS)
28. Zero-Day Jailbreak Radar (Entropy / Adversarial Suffix)
29. ML Ensemble Classifier (3-Model Threat Pipeline)
30. Coordinated Campaign Detector (Cross-Session Correlation)
31. Constitutional Response Auditor (Output-Side Judge)
--- Distributed & Agentic Defense ---
32. Pack Hunt Detector (Distributed Attack Coordination)
33. Multi-Agent Guard (Agent-to-Agent Threat Propagation)
"""

import time
import uuid
import hashlib
from typing import Optional
from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.firewall.detectors.prompt_injection import PromptInjectionDetector
from app.services.firewall.detectors.jailbreak import JailbreakDetector
from app.services.firewall.detectors.encoded_payload import EncodedPayloadDetector
from app.services.firewall.detectors.pii_detector import PIIDetector
from app.services.firewall.detectors.secret_detector import SecretDetector
from app.services.firewall.detectors.content_policy import ContentPolicyDetector
from app.services.firewall.detectors.obfuscation import ObfuscationDetector
from app.services.firewall.detectors.context_analyzer import ContextAnalyzer
from app.services.firewall.detectors.tool_inspector import ToolInspector
from app.services.firewall.detectors.semantic_classifier import SemanticClassifier
from app.services.firewall.detectors.vector_detector import VectorAnomalyDetector
from app.services.firewall.detectors.multimodal_inspector import MultimodalInspector
from app.services.firewall.detectors.rag_sandbox import RAGSandbox
from app.services.firewall.detectors.exotic_encoding import ExoticEncodingDetector
from app.services.firewall.detectors.cross_lingual import CrossLingualDetector
from app.services.firewall.detectors.llm_dos_preventer import LLMDoSPreventer
from app.services.firewall.detectors.supply_chain import SupplyChainValidator
from app.services.firewall.detectors.oracle_detector import OracleDetector
from app.services.firewall.detectors.sponge_detector import SpongeDetector
from app.services.firewall.detectors.intent_validator import IntentValidator
from app.services.firewall.detectors.output_inspector import OutputInspector
from app.services.firewall.detectors.tokenizer_shield import TokenizerShield
from app.services.firewall.detectors.external_content_inspector import ExternalContentInspector
from app.services.firewall.detectors.hallucination_detector import HallucinationEngine
from app.services.firewall.detectors.model_weight_scanner import ModelWeightScanner
from app.services.firewall.detectors.hardware_side_channel import HardwareSideChannelDetector
from app.services.firewall.detectors.pliny_detector import PlinyDetector
from app.services.firewall.detectors.zero_day_detector import ZeroDayDetector
from app.services.firewall.detectors.ml_ensemble_classifier import MLEnsembleClassifier
from app.services.firewall.detectors.campaign_detector import CampaignDetector
from app.services.firewall.detectors.constitutional_auditor import ConstitutionalAuditor
from app.services.firewall.detectors.pack_hunt_detector import PackHuntDetector
from app.services.firewall.detectors.multi_agent_guard import MultiAgentGuard
from app.services.firewall.normalizer import Normalizer
from app.schemas.schemas import ScanRequest, ScanResponse, DetectionResult

settings = get_settings()
logger = get_logger("firewall.engine")


class FirewallEngine:
    """
    Core AI Firewall Engine.

    Orchestrates 10 detection pipelines and produces a unified
    threat assessment for every prompt/output passing through the system.
    """

    def __init__(self):
        self.prompt_injection_detector = PromptInjectionDetector()
        self.jailbreak_detector = JailbreakDetector()
        self.encoded_payload_detector = EncodedPayloadDetector()
        self.pii_detector = PIIDetector()
        self.secret_detector = SecretDetector()
        self.content_policy_detector = ContentPolicyDetector()
        self.obfuscation_detector = ObfuscationDetector()
        self.context_analyzer = ContextAnalyzer()
        self.tool_inspector = ToolInspector()
        self.semantic_classifier = SemanticClassifier()
        self.vector_detector = VectorAnomalyDetector()
        
        # Advanced modules
        self.multimodal_inspector = MultimodalInspector()
        self.rag_sandbox = RAGSandbox()
        self.exotic_encoding = ExoticEncodingDetector()
        self.cross_lingual = CrossLingualDetector()
        self.llm_dos_preventer = LLMDoSPreventer()
        self.supply_chain = SupplyChainValidator()
        
        # Advanced Threat Protection (Layers 18-23)
        self.oracle_detector = OracleDetector()
        self.sponge_detector = SpongeDetector()
        self.intent_validator = IntentValidator()
        self.output_inspector = OutputInspector()
        self.tokenizer_shield = TokenizerShield()
        self.external_content_inspector = ExternalContentInspector()
        
        # Advanced Threat Protection (Layers 24-25)
        self.hallucination_detector = HallucinationEngine()
        self.model_weight_scanner = ModelWeightScanner()
        
        # Hardware Level Security
        self.hardware_detector = HardwareSideChannelDetector()
        
        # Ultra-Advanced Threat Protection (Layers 27-31)
        self.pliny_detector = PlinyDetector()
        self.zero_day_detector = ZeroDayDetector()
        self.ml_ensemble = MLEnsembleClassifier()
        self.campaign_detector = CampaignDetector()
        self.constitutional_auditor = ConstitutionalAuditor()
        
        # Pack Hunt & Multi-Agent Security (Layers 32-33)
        self.pack_hunt_detector = PackHuntDetector()
        self.multi_agent_guard = MultiAgentGuard()
        
        self.normalizer = Normalizer()
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize all detectors and load models."""
        if self._initialized:
            return
        logger.info("firewall_engine_initializing")
        await self.prompt_injection_detector.initialize()
        await self.jailbreak_detector.initialize()
        await self.encoded_payload_detector.initialize()
        await self.pii_detector.initialize()
        await self.secret_detector.initialize()
        await self.content_policy_detector.initialize()
        await self.obfuscation_detector.initialize()
        await self.context_analyzer.initialize()
        await self.tool_inspector.initialize()
        await self.semantic_classifier.initialize()
        await self.vector_detector.initialize()
        
        # Initialize Advanced Modules
        await self.multimodal_inspector.initialize()
        await self.rag_sandbox.initialize()
        await self.exotic_encoding.initialize()
        await self.cross_lingual.initialize()
        await self.llm_dos_preventer.initialize()
        await self.supply_chain.initialize()
        
        # Initialize Advanced Threat Protection (Layers 18-23)
        await self.oracle_detector.initialize()
        await self.sponge_detector.initialize()
        await self.intent_validator.initialize()
        await self.output_inspector.initialize()
        await self.tokenizer_shield.initialize()
        await self.external_content_inspector.initialize()
        
        # Initialize Layers 24-25
        await self.hallucination_detector.initialize()
        await self.model_weight_scanner.initialize()
        await self.hardware_detector.initialize()
        
        # Initialize Ultra-Advanced Layers 27-31
        await self.pliny_detector.initialize()
        await self.zero_day_detector.initialize()
        await self.ml_ensemble.initialize()
        await self.campaign_detector.initialize()
        await self.constitutional_auditor.initialize()
        
        # Initialize Pack Hunt & Multi-Agent Security (Layers 32-33)
        await self.pack_hunt_detector.initialize()
        await self.multi_agent_guard.initialize()
        
        self._initialized = True
        logger.info("firewall_engine_initialized", detectors=33)

    async def _load_disabled_detectors(self, org_id: Optional[str]) -> set[str]:
        """Load the set of detector names that are disabled via policy toggles."""
        if not org_id or org_id == "test":
            return set()
        try:
            from app.core.database import async_session_factory
            from app.models.policy import Policy, PolicyRule
            from sqlalchemy import select, and_

            async with async_session_factory() as session:
                # Find policies that are INACTIVE for this org
                result = await session.execute(
                    select(Policy).where(
                        and_(Policy.organization_id == org_id, Policy.is_active == False)
                    )
                )
                disabled_policies = result.scalars().all()
                disabled_detectors: set[str] = set()
                for policy in disabled_policies:
                    # Load rules to find which detectors this policy controls
                    rules_result = await session.execute(
                        select(PolicyRule).where(PolicyRule.policy_id == policy.id)
                    )
                    for rule in rules_result.scalars().all():
                        disabled_detectors.add(rule.detector)
                return disabled_detectors
        except Exception as e:
            logger.warning("failed_to_load_policies", error=str(e))
            return set()

    def _is_detector_enabled(self, detector_name: str, disabled: set[str]) -> bool:
        """Check if a detector is enabled (not in the disabled set)."""
        return detector_name not in disabled

    def reset_state(self) -> None:
        """Reset ALL stateful detector data.
        
        MUST be called before each red-team simulator / certification run
        to prevent cross-contamination from accumulated threat signals.
        """
        from collections import defaultdict

        # Campaign detector — instance state
        if hasattr(self, 'campaign_detector') and hasattr(self.campaign_detector, '_attack_history'):
            self.campaign_detector._attack_history = []

        # Campaign detector — MODULE-LEVEL globals (critical: these persist across resets otherwise)
        try:
            from app.services.firewall.detectors.campaign_detector import _campaign_store, _attack_fingerprints
            _campaign_store.clear()
            _attack_fingerprints.clear()
        except ImportError:
            pass

        # Pack hunt detector
        if hasattr(self, 'pack_hunt_detector'):
            if hasattr(self.pack_hunt_detector, '_request_graph'):
                self.pack_hunt_detector._request_graph = defaultdict(list)
            if hasattr(self.pack_hunt_detector, '_detected_campaigns'):
                self.pack_hunt_detector._detected_campaigns = defaultdict(list)
            if hasattr(self.pack_hunt_detector, '_cross_key_map'):
                self.pack_hunt_detector._cross_key_map = defaultdict(set)

        # Context analyzer (session history)
        if hasattr(self, 'context_analyzer') and hasattr(self.context_analyzer, 'session_history'):
            self.context_analyzer.session_history = {}

        # Sponge detector (session tracking)
        if hasattr(self, 'sponge_detector') and hasattr(self.sponge_detector, '_session_tokens'):
            self.sponge_detector._session_tokens = {}
            
        try:
            from app.services.firewall.detectors.sponge_detector import _session_compute
            _session_compute.clear()
        except ImportError:
            pass

        # Zero-day detector (session scores)
        if hasattr(self, 'zero_day_detector') and hasattr(self.zero_day_detector, '_session_scores'):
            self.zero_day_detector._session_scores = {}

        # Intent validator (action cooldowns)
        try:
            from app.services.firewall.detectors.intent_validator import _action_cooldowns
            _action_cooldowns.clear()
        except ImportError:
            pass

        # Oracle detector (module-level cache)
        try:
            from app.services.firewall.detectors.oracle_detector import _oracle_profiles
            _oracle_profiles.clear()
        except ImportError:
            pass
            
        # External content inspector (module-level cache)
        try:
            from app.services.firewall.detectors.external_content_inspector import _source_reputation
            _source_reputation.clear()
        except ImportError:
            pass

        logger.info("firewall_state_reset")

    async def scan(
        self,
        request: ScanRequest,
        org_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ScanResponse:
        """
        Run the full detection pipeline against a prompt or output.
        Respects policy enable/disable — disabled policies skip their detectors.
        """
        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())[:16]
        text = request.prompt
        scan_type = request.scan_type

        # Load which detectors are disabled by policy
        disabled_detectors = await self._load_disabled_detectors(org_id)
        if disabled_detectors:
            logger.info("policy_disabled_detectors", disabled=list(disabled_detectors), org_id=org_id)

        logger.info(
            "scan_started",
            request_id=request_id,
            scan_type=scan_type,
            text_length=len(text),
            org_id=org_id,
        )

        all_detections: list[DetectionResult] = []
        dos_risk = 0.0
        rag_trust_score = 1.0

        # Optional Inputs from request
        media_payloads = getattr(request, 'media_payloads', [])
        rag_context = getattr(request, 'rag_context', None)
        
        # Advanced Multimodal Scanning
        if media_payloads:
            detections = await self.multimodal_inspector.inspect_media(media_payloads)
            all_detections.extend(detections)
            
        # Advanced RAG Sandbox
        if rag_context:
            detections, sanitized_rag, rag_trust_score = await self.rag_sandbox.inspect_context(rag_context)
            all_detections.extend(detections)

        # Advanced DoS Prevention
        if text:
            detections, dos_risk = await self.llm_dos_preventer.analyze_complexity(text)
            all_detections.extend(detections)

        # 0. Layer 1 Normalization
        text, evasion_flags = await self.normalizer.normalize(text)

        # NOTE: Do NOT re-initialize all_detections here — multimodal, RAG,
        # and DoS detections are already collected above (lines 226-247).

        if evasion_flags:
            all_detections.append(DetectionResult(
                detector="encoded_payload",
                confidence=0.9,
                category="encoded.evasion_attempt",
                description=f"Layer-1 Normalizer intercepted evasion attempt and normalized payload: {', '.join(evasion_flags)}",
                matched_content=text[:100],
                severity="high",
            ))

        # Helper: run detector only if its policy is enabled
        async def _run(detector_key: str, coro):
            if self._is_detector_enabled(detector_key, disabled_detectors):
                return await coro
            return []

        # 1. Prompt Injection Detection
        all_detections.extend(await _run("direct_instruction_override", self.prompt_injection_detector.detect(text)))

        # 2. Jailbreak Detection
        all_detections.extend(await _run("jailbreak_persona_switch", self.jailbreak_detector.detect(text)))

        # 3. Encoded Payload Detection
        all_detections.extend(await _run("encoding_obfuscation", self.encoded_payload_detector.detect(text)))

        # 4. Obfuscation Detection
        all_detections.extend(await _run("encoding_obfuscation", self.obfuscation_detector.detect(text)))

        # Advanced Exotic Encoding
        all_detections.extend(await _run("encoding_obfuscation", self.exotic_encoding.detect(text)))

        # Advanced Cross Lingual
        all_detections.extend(await _run("cross_lingual_vector", self.cross_lingual.detect(text)))

        # 5. PII Detection
        all_detections.extend(await _run("pii_detector", self.pii_detector.detect(text)))

        # 6. Secret Detection
        all_detections.extend(await _run("secret_detector", self.secret_detector.detect(text)))

        # 7. Content Policy
        all_detections.extend(await _run("sensitive_topic_escalation", self.content_policy_detector.detect(text)))

        # 8. Semantic Intent Classifier (ML)
        all_detections.extend(await _run("social_engineering", self.semantic_classifier.detect(text)))

        # 8.5 Semantic Vector Anomaly (Zero-Day)
        all_detections.extend(await _run("adversarial_suffix", self.vector_detector.detect(text)))

        # 9. Multi-Turn Context Analysis (if session provided)
        if session_id:
            all_detections.extend(await _run("multi_turn_slow_build", self.context_analyzer.analyze(text, session_id)))

        # 10. Agentic Tool Call Inspection (if tools/agent scan type)
        # Tool inspector: trigger on agent scan type, or if ANY tool-related keywords appear
        _tl = text.lower()
        _tool_signals = any(kw in _tl for kw in [
            "tool", "function", "execute", "call", "run", "invoke", "api",
            "delete", "drop", "send_email", "deploy", "shell", "command",
            "fetch", "retrieve", "localhost", "127.0.0.1", "curl", "wget",
        ])
        if scan_type == "agent" or _tool_signals:
            all_detections.extend(await _run("agentic_tool_hijacking", self.tool_inspector.inspect(text)))

        # Advanced Supply Chain Validation for generated outputs
        if scan_type == "output":
            all_detections.extend(await _run("supply_chain_intercept", self.supply_chain.validate_output(text)))
            # Output-side memorization leak detection
            all_detections.extend(await _run("output_manipulation", self.output_inspector.detect_output(text, input_text=request.prompt)))
            # Output-side hallucination detection
            all_detections.extend(await _run("hallucination_detector", self.hallucination_detector.detect_output(text, input_text=request.prompt)))

        # ── Advanced Threat Protection Layers 18-23 ──────────────

        # 18. Oracle Attack Detection (Model Inversion & Weight Stealing)
        all_detections.extend(await _run("oracle_detector", self.oracle_detector.detect(text)))

        # 19. Sponge DoS Detection (Transformer DoS via Adversarial Tokens)
        all_detections.extend(await _run("sponge_detector", self.sponge_detector.detect(text, session_id=session_id)))

        # 20. Intent Validator (Business Logic Exploitation)
        all_detections.extend(await _run("intent_validator", self.intent_validator.detect(text, session_id=session_id)))

        # 21. Output Inspector (Training Data Memorization)
        all_detections.extend(await _run("output_inspector", self.output_inspector.detect(text)))

        # 22. Tokenizer Shield (Zero-Day Unicode & Tokenizer Splitting)
        all_detections.extend(await _run("tokenizer_shield", self.tokenizer_shield.detect(text)))

        # 23. External Content Inspector (Out-of-Band Indirect Injection)
        if rag_context:
            all_detections.extend(await _run("external_content_inspector", self.external_content_inspector.detect(rag_context, content_type="html")))
        # Also check for URLs in plain prompts that could be used for indirect injection
        import re as _re
        if _re.search(r'https?://\S+', text):
            all_detections.extend(await _run("external_content_inspector", self.external_content_inspector.detect(text, content_type="text")))

        # 24. Hallucination Detector (Input-side: elicitation attempts)
        all_detections.extend(await _run("hallucination_detector", self.hallucination_detector.detect(text)))

        # 25. Model Weight Scanner (Input-side: suspicious model operations)
        all_detections.extend(await _run("model_weight_scanner", self.model_weight_scanner.detect(text)))

        # 26. Hardware Side-Channel Detector
        all_detections.extend(await _run("hardware_side_channel", self.hardware_detector.detect(text)))

        # ── Ultra-Advanced Threat Protection Layers 27-31 ──────────────

        # 27. Pliny Defense Engine
        all_detections.extend(await _run("pliny_defense", self.pliny_detector.detect(text)))

        # 28. Zero-Day Jailbreak Radar
        all_detections.extend(await _run("zero_day_radar", self.zero_day_detector.detect(text, session_id=session_id)))

        # 29. ML Ensemble Classifier
        all_detections.extend(await _run("ml_ensemble", self.ml_ensemble.detect(text)))

        # 30. Coordinated Campaign Detector (post-detection correlation)
        if all_detections:  # Only run campaign detection if there are existing detections
            campaign_threat = self._calculate_threat_score(all_detections)
            all_detections.extend(await _run(
                "campaign_detector",
                self.campaign_detector.detect(
                    text,
                    session_id=session_id,
                    threat_score=campaign_threat,
                    detections=all_detections,
                ),
            ))

        # 31. Constitutional Response Auditor (output-side only)
        if scan_type == "output":
            all_detections.extend(await _run(
                "constitutional_auditor",
                self.constitutional_auditor.audit_response(text, input_text=request.prompt),
            ))

        # ── Pack Hunt & Multi-Agent Security Layers 32-33 ──────────────

        # 32. Pack Hunt Detector (Multi-Request Fragmentation Defense)
        all_detections.extend(await _run(
            "pack_hunt_detector",
            self.pack_hunt_detector.detect(
                text,
                api_key=org_id or "anonymous",
                session_id=session_id or "default",
                request_id=request_id,
            ),
        ))

        # 33. Multi-Agent Orchestration Guard
        all_detections.extend(await _run(
            "multi_agent_guard",
            self.multi_agent_guard.detect(
                text,
                agent_id=getattr(request, 'agent_id', ''),
                source_agent_id=getattr(request, 'source_agent_id', ''),
                content_type=scan_type,
                session_id=session_id or "",
            ),
        ))

        # Calculate aggregate threat score
        threat_score = self._calculate_threat_score(all_detections)
        threat_level = self._classify_threat_level(threat_score)
        action = self._determine_action(threat_level, threat_score)

        # Sanitize prompt if needed
        sanitized = None
        dlp_mappings = {}
        # If the action is blocked due to PII/Secrets, we should try to sanitize it
        if action in ("sanitized", "blocked"):
            # Check if any detection allows redaction (e.g. PII, Secrets)
            redactable_detections = [d for d in all_detections if d.detector in ("pii", "secret")]
            if redactable_detections:
                sanitized, dlp_mappings = await self._sanitize_prompt(text, redactable_detections)
                # If we successfully redacted everything, we can allow the request instead of blocking it!
                if action == "blocked":
                    # Check if blocking was SOLELY due to redactable detections by recalculating
                    remaining = [d for d in all_detections if d.detector not in ("pii", "secret")]
                    rem_score = self._calculate_threat_score(remaining)
                    rem_level = self._classify_threat_level(rem_score)
                    rem_action = self._determine_action(rem_level, rem_score)
                    if rem_action != "blocked":
                        # Only PII/Secrets pushed it over the blocking threshold. We can allow it as sanitized.
                        action = "sanitized"
        scan_duration = (time.perf_counter() - start_time) * 1000

        response = ScanResponse(
            request_id=request_id,
            threat_level=threat_level,
            threat_score=round(threat_score, 4),
            action=action,
            detections=all_detections,
            sanitized_prompt=sanitized,
            prompt=text,
            scan_duration_ms=round(scan_duration, 2),
            dlp_mappings=dlp_mappings,
            metadata={
                "scan_type": scan_type,
                "text_length": len(text),
                "detectors_run": self._get_detectors_run(scan_type, session_id),
                "content_hash": hashlib.sha256(text.encode()).hexdigest()[:16],
                "advanced_telemetry": {
                    "dos_risk": dos_risk,
                    "rag_trust_score": rag_trust_score,
                    "media_elements_scanned": len(media_payloads) if media_payloads else 0
                }
            },
        )

        logger.info(
            "scan_completed",
            request_id=request_id,
            threat_level=threat_level,
            threat_score=threat_score,
            action=action,
            detections_count=len(all_detections),
            duration_ms=scan_duration,
        )

        return response

    def _calculate_threat_score(self, detections: list[DetectionResult]) -> float:
        """Calculate weighted aggregate threat score from all detections."""
        if not detections:
            return 0.0

        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
        }

        weighted_scores = []
        for d in detections:
            weight = severity_weights.get(d.severity, 0.5)
            weighted_scores.append(d.confidence * weight)

        # Use max-weighted approach: highest detection dominates
        # but multiple detections increase the score
        max_score = max(weighted_scores)
        avg_boost = sum(weighted_scores) / len(weighted_scores) * 0.2
        combined = min(max_score + avg_boost, 1.0)

        return combined

    def _classify_threat_level(self, score: float) -> str:
        """Map threat score to a threat level — tightened thresholds for higher accuracy."""
        if score >= 0.85:
            return "critical"
        elif score >= 0.60:
            return "high"
        elif score >= 0.35:
            return "medium"
        elif score >= 0.10:
            return "low"
        return "safe"

    def _determine_action(self, threat_level: str, threat_score: float) -> str:
        """Determine the action based on threat level and firewall mode."""
        if settings.FIREWALL_MODE == "disabled":
            return "allowed"

        if settings.FIREWALL_MODE == "monitor":
            if threat_level in ("high", "critical"):
                return "flagged"
            return "allowed"

        # Enforce mode
        if threat_level == "critical":
            return "blocked"
        elif threat_level == "high":
            return "blocked"
        elif threat_level == "medium":
            if threat_score >= settings.THREAT_SCORE_THRESHOLD:
                return "blocked"
            return "flagged"
        elif threat_level == "low":
            return "flagged"
        return "allowed"

    async def _sanitize_prompt(
        self, text: str, detections: list[DetectionResult]
    ) -> tuple[str, dict[str, str]]:
        """Attempt to sanitize a prompt by removing detected threats."""
        sanitized = text
        dlp_mappings = {}
        for d in detections:
            if d.matched_content:
                cat = d.category.split(".")[-1].upper()
                placeholder = f"[{cat}_{uuid.uuid4().hex[:8]}]"
                sanitized = sanitized.replace(d.matched_content, placeholder)
                dlp_mappings[placeholder] = d.matched_content
        return sanitized, dlp_mappings

    def _get_detectors_run(self, scan_type: str, session_id: str = None) -> list[str]:
        """Get list of detectors run for a scan type."""
        detectors = [
            "prompt_injection", "jailbreak", "encoded_payload",
            "obfuscation", "pii", "secret", "content_policy", "semantic_classifier",
            "oracle_detector", "sponge_detector", "intent_validator",
            "output_inspector", "tokenizer_shield", "external_content_inspector",
            "hallucination_detector", "model_weight_scanner",
            "hardware_side_channel", "pliny_defense", "zero_day_radar",
            "ml_ensemble", "campaign_detector",
        ]
        if session_id:
            detectors.append("context_analyzer")
        if scan_type == "agent":
            detectors.append("tool_inspector")
        if scan_type == "output":
            detectors.append("constitutional_auditor")
        return detectors


# Singleton instance
firewall_engine = FirewallEngine()
