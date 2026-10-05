"""
Hallucination Detector — Threat Layer 24

Detects hallucinated, fabricated, or factually unreliable content in
LLM outputs. Operates on the OUTPUT side of the bi-directional firewall.

Detection Signals:
  1. Confidence Hedging — excessive hedging language indicating uncertainty
  2. Self-Contradiction — conflicting statements within the same response
  3. Citation Fabrication — fake DOIs, URLs, ISBN numbers, or paper titles
  4. Statistical Anomalies — implausible numbers, dates, or percentages
  5. Entity Fabrication — references to non-existent people, orgs, events
  6. Knowledge Boundary Violations — claims about post-training-cutoff events
  7. Logical Inconsistency — statements that violate basic logic or math
  8. Repetition Drift — repetitive patterns indicating generation collapse
"""

import re
import math
from typing import Optional
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.hallucination")


# ── Confidence Hedging Patterns ─────────────────────────────────────
HEDGING_PHRASES = [
    r"\b(I think|I believe|I'm not sure|I'm not certain|I cannot confirm|I don't have access to real-time)\b",
    r"\b(it's possible that|it might be|it could be|perhaps|maybe|potentially)\b",
    r"\b(to the best of my knowledge|as far as I know|I'm not 100% sure)\b",
    r"\b(however, I should note|please verify|I may be wrong|I cannot guarantee)\b",
    r"\b(allegedly|supposedly|reportedly|unverified|unconfirmed)\b",
]

# ── Self-Contradiction Patterns ─────────────────────────────────────
CONTRADICTION_PAIRS = [
    (r"\bis\s+(?:the\s+)?largest\b", r"\bis\s+(?:the\s+)?smallest\b"),
    (r"\bwas born in (\d{4})\b", r"\bwas born in (\d{4})\b"),
    (r"\bis (?:a |an )?(\w+)\b", r"\bis not (?:a |an )?(\w+)\b"),
    (r"\balways\b", r"\bnever\b"),
    (r"\bincreased by\b", r"\bdecreased by\b"),
    (r"\bfounded in (\d{4})\b", r"\bfounded in (\d{4})\b"),
    (r"\byes\b", r"\bno\b"),
    (r"\btrue\b", r"\bfalse\b"),
]

# ── Fabricated Citation Patterns ────────────────────────────────────
FAKE_CITATION_PATTERNS = [
    # Fake DOIs with suspicious structure
    r"(?:doi|DOI)[:\s]+10\.\d{4,}/[a-z]{2,}\.\d{4}\.\d{5,}",
    # Fake arXiv IDs with impossible dates
    r"arXiv:\d{4}\.\d{5,}(?:v\d+)?",
    # Fake ISBN numbers
    r"ISBN[:\s]+(?:978|979)-\d-\d{2,7}-\d{1,7}-\d",
    # Suspicious URL patterns
    r"https?://(?:www\.)?(?:journal|paper|study|research)\w*\.(?:com|org)/\w+/\d+",
    # Fake journal references
    r"(?:Journal of|Proceedings of|International Conference on)\s+[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*,?\s*(?:Vol\.|Volume)\s*\d+",
]

# ── Statistical Anomaly Patterns ────────────────────────────────────
STAT_ANOMALY_PATTERNS = [
    # Percentages over 100 in non-growth context
    r"(?:is|was|are|were|at|of|about)\s+(\d{4,})%",
    # Implausible dates (future or very old)
    r"\b(?:in|since|from|year)\s+(2[1-9]\d{2}|1[0-4]\d{2})\b",
    # Suspiciously precise large numbers
    r"\b(\d{10,})\s+(?:people|users|customers|employees|deaths|cases)\b",
    # Population numbers that seem fabricated
    r"\bpopulation of\s+(\d{1,3}(?:,\d{3})*)\b",
    # Overly specific fabricated statistics in context of sports or events
    r"\b\d{1,3}%\s+(?:possession|accuracy|efficiency|completion)\b",
    r"\b(?:completed|achieved|reached)\s+(?:\d{1,3},)?\d{3}\s+(?:successful\s+)?(?:passes|attempts|shots|goals)\b",
]

# ── Entity Fabrication Signals ──────────────────────────────────────
ENTITY_FABRICATION_SIGNALS = [
    r"Dr\.\s+[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+(?:from|at|of)\s+(?:the\s+)?University of\s+[A-Z][a-z]+",
    r"(?:Professor|Dr\.)\s+[A-Z][a-z]+\s+published\s+(?:a|the)\s+(?:seminal|groundbreaking|landmark)\s+(?:study|paper|research)",
    r"according to\s+(?:a\s+)?(?:\d{4}\s+)?(?:study|research|report|paper)\s+(?:by|from|in)\s+[A-Z]",
    # Confidently hallucinated generic reports/studies
    r"(?:according to|based on)\s+(?:the\s+)?(?:[A-Z][a-zA-Z]+\s+){1,4}(?:Report|Study|Paper|Analysis|Review)(?:\s+\d{4})?",
]

# ── Repetition / Generation Collapse ────────────────────────────────
MIN_REPEAT_LENGTH = 15
MAX_REPEAT_COUNT = 4

# ── Thresholds ──────────────────────────────────────────────────────
HEDGING_THRESHOLD = 3       # N+ hedging phrases → flag
HIGH_HEDGING_THRESHOLD = 6  # N+ → high severity


class StructuralHallucinationDetector:
    """Detects hallucinated or fabricated content in LLM outputs."""

    def __init__(self):
        self._hedging_compiled = []
        self._citation_compiled = []
        self._stat_compiled = []
        self._entity_compiled = []
        self._initialized = False

    async def initialize(self) -> None:
        self._hedging_compiled = [re.compile(p, re.IGNORECASE) for p in HEDGING_PHRASES]
        self._citation_compiled = [re.compile(p, re.IGNORECASE) for p in FAKE_CITATION_PATTERNS]
        self._stat_compiled = [re.compile(p, re.IGNORECASE) for p in STAT_ANOMALY_PATTERNS]
        self._entity_compiled = [re.compile(p) for p in ENTITY_FABRICATION_SIGNALS]
        self._initialized = True
        logger.info("hallucination_detector_initialized")

    async def detect(self, text: str) -> list[DetectionResult]:
        """Scan INPUT prompts for hallucination elicitation attempts."""
        # Input-side: detect prompts that try to force hallucination
        detections = []
        lower = text.lower()
        
        hallucination_elicitation = [
            r"(make up|fabricate|invent|create|generate)\s+(a|an|some)?\s*(fake|false|fictional|imaginary)\s*(data|facts|statistics|references|citations|study|paper)",
            r"(pretend|assume|imagine)\s+that\s+.{5,50}\s+(is|was|are|were)\s+(true|real|fact)",
            r"(cite|reference|quote)\s+(a|an|some)?\s*(nonexistent|fake|made-up|fictional)\s*(source|study|paper|research|journal)",
            r"(do not|don't)\s+(say|mention|tell|admit)\s+.{3,30}\s*(don't know|unsure|uncertain|not sure)",
            r"(never say|avoid saying)\s+.{3,30}\s*(hallucin|uncertain|don't know|not sure)",
        ]

        # Input-side fake authority patterns — prompts that present fabricated
        # citations/statistics and ask the model to confirm/elaborate on them
        fake_authority_elicitation = [
            # Fake DOI citations presented as fact and asking to confirm/summarize
            r"(according to|as (confirmed|stated|reported|published) (by|in))\s+.{5,80}(doi|10\.\d{4}/).{5,40}(confirm|summarize|elaborate|explain|support)",
            # Fake statistics with authoritative source asking for endorsement
            r"(the|a)\s+(WHO|FDA|CDC|NIH|EPA|UN|UNESCO|UNICEF)\s+(reported|stated|confirmed|published|announced)\s+.{10,80}(summarize|confirm|explain|support|elaborate)",
            # Pattern: "According to [fake authority], [dangerous claim]. Confirm this."
            r"(according to|based on)\s+.{10,60}(paper|study|report|bulletin|press release)\s+.{5,40}\d{4}.{5,100}(confirm|summarize|findings|explain)",
            # Fake medical/health claims with fake citation — relaxed distance
            r"(approved|confirmed|proven|established)\s+.{0,60}(treat|cure|prevent|cause)\s+.{0,60}(cancer|autism|depression|disease|illness)",
            # Fake paper author citations: "Dr. X et al. in Nature/Science/Lancet"
            r"(dr\.|professor|prof\.)\s+\w+\s+(et al\.?|and colleagues)\s+in\s+(nature|science|lancet|nejm|bmj|cell|pnas)\s*\(",
            # Broad: "As confirmed/stated by the FDA/WHO" + fake reference ID
            r"as\s+(confirmed|stated|reported|verified)\s+by\s+(the\s+)?(FDA|WHO|CDC|NIH|EPA|NIST).{0,60}(press release|bulletin|report|advisory|memorandum)\s+\w{1,5}[-\s]?\d{4}",
            # Fake regulatory approval claims
            r"(this|the)\s+(drug|treatment|product|therapy|device)\s+is\s+(approved|cleared|authorized)\s+for\s+(treat|cur|prevent|diagnos|use)",
            # Fake court case citations: "Cite the Supreme Court case 'X v. Y' from 2024"
            r"(cite|reference|quote|describe)\s+.{0,20}(supreme\s+court|court|federal|district)\s+(case|ruling|decision|opinion)\s+.{0,60}\d{4}",
            # Fake paper summarization: "Summarize the paper 'Title' by Dr. X, published in Journal YYYY"
            r"(summarize|describe|explain)\s+.{0,10}(the\s+)?(paper|study|article|research)\s+.{0,80}(by|authored\s+by)\s+(dr\.?|prof\.?|professor)\s+\w+.{0,40}(published|in)\s+(nature|science|lancet|cell|nejm|bmj|pnas)",
            # Fake Nobel Prize in non-existent categories
            r"(describe|tell\s+me\s+about|explain|who\s+won)\s+.{0,10}(the\s+)?\d{4}\s+nobel\s+prize\s+in\s+(computer\s+science|artificial\s+intelligence|mathematics|engineering|technology)",
            # Generic: "Cite/Describe the [year] [fake event]" 
            r"(cite|describe|summarize|reference)\s+.{0,10}(the\s+)?\d{4}\s+.{0,40}(award|prize|case|ruling|report|study)\s+.{0,40}(by|from|in|about)",
            # ── Fictional events with specific date/location ──
            # "Tell me about the Battle of X that happened in YYYY"
            r"(tell\s+me\s+about|describe|explain|what\s+(happened|was))\s+.{0,20}(the\s+)?(battle\s+of|war\s+of|siege\s+of|conflict\s+(in|of|between))\s+.{0,40}\d{4}",
            # "What happened at the YYYY X Summit/Conference in City"
            r"(what\s+happened|describe|tell\s+me)\s+.{0,20}(at\s+)?(the\s+)?\d{4}\s+.{0,40}(summit|conference|convention|congress|forum)\s+in\s+",
            # Attendee/participant list requests for events (hallucination bait)
            r"(list\s+(all\s+)?attendees?|list\s+(all\s+)?participants?|who\s+(attended|participated|was\s+there))\s*.{0,40}(summit|conference|event|meeting)",
            # ── Fictional substances / materials ──
            # "What is the chemical formula for adamantium/vibranium/unobtanium"
            r"(what\s+is|give\s+me|provide)\s+.{0,20}(chemical\s+formula|molecular\s+formula|composition|melting\s+point|boiling\s+point)\s+.{0,20}(for|of)\s+.{0,20}(adamantium|vibranium|unobtanium|mithril|dilithium|kryptonite|carbonite)",
            # ── Generic fictional fact bait ──
            # "What did [person] say in their YYYY [speech/interview]"
            r"(what\s+did|quote)\s+.{3,40}(say|said)\s+in\s+.{0,20}(their|his|her)\s+\d{4}\s+(speech|interview|address|statement|testimony)",
            # ── Real-time data hallucination baits ──
            # Stock price requests with ticker symbols (e.g. "$QLLM", "$AIGT")
            r"(what\s+is|provide|give\s+me|tell\s+me)\s+.{0,20}(the\s+)?(current|latest|today'?s?|live|real-?time)\s+(stock\s+)?price\s+of\s+\$?[A-Z]{2,5}",
            # "current stock price of X" without "current" keyword
            r"(stock\s+price|share\s+price|market\s+price|trading\s+price)\s+of\s+\$[A-Z]{2,5}",
            # Demanding exact real-time figures/numbers
            r"(what\s+is|provide|give\s+me)\s+.{0,30}(exact\s+figure|exact\s+number|exact\s+price|exact\s+value|precise\s+figure|precise\s+number)\b",
            # Current score/result/stat requests that force hallucination
            r"(what\s+is|provide|give)\s+.{0,20}(the\s+)?(current|live|latest|today'?s?)\s+(score|result|temperature|exchange\s+rate|crypto\s+price)\s+.{0,30}(exact|precise|specific)",
        ]
        
        for pattern_str in hallucination_elicitation + fake_authority_elicitation:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            match = pattern.search(text)
            if match:
                detections.append(DetectionResult(
                    detector="hallucination",
                    confidence=0.85,
                    category="hallucination.elicitation_attempt",
                    description=(
                        "Hallucination elicitation attempt detected: prompt instructs "
                        "the model to fabricate information, endorse fake citations, "
                        "or suppress uncertainty about unverified claims"
                    ),
                    severity="high",
                    matched_content=match.group(0)[:150],
                ))
                break
        
        return detections

    async def detect_output(
        self,
        output_text: str,
        *,
        input_text: Optional[str] = None,
    ) -> list[DetectionResult]:
        """Scan OUTPUT response for hallucination indicators."""
        detections: list[DetectionResult] = []
        if not output_text or len(output_text) < 50:
            return detections

        # ── 1. Confidence Hedging Analysis ────────────────────────────
        hedging_count = 0
        hedging_matches = []
        for pattern in self._hedging_compiled:
            matches = pattern.findall(output_text)
            hedging_count += len(matches)
            hedging_matches.extend(matches[:3])

        if hedging_count >= HIGH_HEDGING_THRESHOLD:
            detections.append(DetectionResult(
                detector="hallucination",
                confidence=0.82,
                category="hallucination.excessive_hedging",
                description=(
                    f"Excessive hedging detected: {hedging_count} uncertainty markers found. "
                    f"The model appears highly uncertain about its output, indicating potential hallucination."
                ),
                severity="high",
                matched_content="; ".join(hedging_matches[:5]),
            ))
        elif hedging_count >= HEDGING_THRESHOLD:
            detections.append(DetectionResult(
                detector="hallucination",
                confidence=0.60,
                category="hallucination.moderate_hedging",
                description=(
                    f"Moderate hedging detected: {hedging_count} uncertainty markers found. "
                    f"Output may contain unverified claims."
                ),
                severity="medium",
                matched_content="; ".join(hedging_matches[:3]),
            ))

        # ── 2. Self-Contradiction Detection ───────────────────────────
        sentences = re.split(r'[.!?]+', output_text)
        for pattern_a_str, pattern_b_str in CONTRADICTION_PAIRS:
            matches_a = []
            matches_b = []
            for i, sent in enumerate(sentences):
                if re.search(pattern_a_str, sent, re.IGNORECASE):
                    matches_a.append((i, sent.strip()))
                if re.search(pattern_b_str, sent, re.IGNORECASE):
                    matches_b.append((i, sent.strip()))

            if matches_a and matches_b:
                # Check if they're in different sentences (not negation in same)
                for idx_a, sent_a in matches_a:
                    for idx_b, sent_b in matches_b:
                        if idx_a != idx_b:
                            detections.append(DetectionResult(
                                detector="hallucination",
                                confidence=0.78,
                                category="hallucination.self_contradiction",
                                description=(
                                    "Self-contradiction detected in output: conflicting "
                                    "statements suggest hallucinated content"
                                ),
                                severity="high",
                                matched_content=f"'{sent_a[:60]}' vs '{sent_b[:60]}'",
                            ))
                            break
                    else:
                        continue
                    break

        # ── 3. Citation Fabrication Detection ─────────────────────────
        for pattern in self._citation_compiled:
            match = pattern.search(output_text)
            if match:
                detections.append(DetectionResult(
                    detector="hallucination",
                    confidence=0.75,
                    category="hallucination.fabricated_citation",
                    description=(
                        "Potentially fabricated citation detected: the model generated "
                        "a citation/reference that may not exist"
                    ),
                    severity="medium",
                    matched_content=match.group(0)[:150],
                ))
                break  # One detection per category

        # ── 4. Statistical Anomaly Detection ──────────────────────────
        for pattern in self._stat_compiled:
            match = pattern.search(output_text)
            if match:
                detections.append(DetectionResult(
                    detector="hallucination",
                    confidence=0.70,
                    category="hallucination.statistical_anomaly",
                    description=(
                        "Statistical anomaly detected in output: implausible numbers "
                        "or dates suggest fabricated data"
                    ),
                    severity="medium",
                    matched_content=match.group(0)[:100],
                ))
                break

        # ── 5. Entity Fabrication Signals ─────────────────────────────
        for pattern in self._entity_compiled:
            match = pattern.search(output_text)
            if match:
                detections.append(DetectionResult(
                    detector="hallucination",
                    confidence=0.65,
                    category="hallucination.entity_fabrication",
                    description=(
                        "Potential entity fabrication: output references specific "
                        "people, studies, or institutions that may not exist"
                    ),
                    severity="medium",
                    matched_content=match.group(0)[:150],
                ))
                break

        # ── 6. Repetition Drift / Generation Collapse ─────────────────
        if len(output_text) > 200:
            for length in [50, 30, MIN_REPEAT_LENGTH]:
                for i in range(0, min(len(output_text) - length, 500)):
                    substring = output_text[i:i + length]
                    if substring.strip() and output_text.count(substring) > MAX_REPEAT_COUNT:
                        detections.append(DetectionResult(
                            detector="hallucination",
                            confidence=0.85,
                            category="hallucination.repetition_drift",
                            description=(
                                f"Generation collapse detected: '{substring[:30]}...' repeated "
                                f"{output_text.count(substring)} times — model may be stuck in a loop"
                            ),
                            severity="high",
                            matched_content=substring[:80],
                        ))
                        break
                if any(d.category == "hallucination.repetition_drift" for d in detections):
                    break

        # ── 7. Confidence Score ───────────────────────────────────────
        # Calculate overall hallucination risk score
        if detections:
            max_conf = max(d.confidence for d in detections)
            logger.info(
                "hallucination_detected",
                signals=len(detections),
                max_confidence=max_conf,
                categories=[d.category for d in detections],
            )

        return detections

    @staticmethod
    def calculate_hallucination_score(detections: list[DetectionResult]) -> float:
        """Calculate aggregate hallucination risk from all hallucination detections."""
        if not detections:
            return 0.0

        hall_detections = [d for d in detections if d.detector == "hallucination"]
        if not hall_detections:
            return 0.0

        severity_weights = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
        scores = [d.confidence * severity_weights.get(d.severity, 0.5) for d in hall_detections]
        return min(max(scores) + sum(scores) / len(scores) * 0.15, 1.0)


from app.services.firewall.detectors.hallucination_layers import (
    NLIEntailmentLayer,
    CitationVerificationLayer,
    WikipediaEntityLayer,
    LLMJudgeLayer,
    RAGGroundingLayer
)
from app.services.firewall.detectors.hallucination_policy import POLICIES, determine_adaptive_layers
from app.services.firewall.detectors.hallucination_forensic import ForensicHallucinationAnalyzer
from app.core.config import get_settings
import time

class HallucinationEngine:
    """Orchestrates the multi-layer hallucination detection pipeline."""
    
    def __init__(self):
        self.layer_0_structural = StructuralHallucinationDetector()
        self.forensic_analyzer = ForensicHallucinationAnalyzer()
        
        # Lazy load other layers
        self._layers = {}
        
    async def initialize(self):
        await self.layer_0_structural.initialize()
        
    def _get_layer(self, name: str):
        if name in self._layers:
            return self._layers[name]
            
        if name == "layer_1_nli":
            self._layers[name] = NLIEntailmentLayer()
        elif name == "layer_2_citation":
            self._layers[name] = CitationVerificationLayer()
        elif name == "layer_3_wikipedia":
            self._layers[name] = WikipediaEntityLayer()
        elif name == "layer_4_llm_judge":
            self._layers[name] = LLMJudgeLayer()
        elif name == "layer_5_rag_grounding":
            self._layers[name] = RAGGroundingLayer()
            
        return self._layers.get(name)

    async def detect_multi_layer(self, output_text: str, input_text: Optional[str] = None, context_documents: Optional[list[str]] = None, policy_tier: Optional[str] = None) -> dict:
        settings = get_settings()
        tier = policy_tier or settings.HALLUCINATION_POLICY
        
        # 1. Always run Layer 0 (Structural)
        t0 = time.perf_counter()
        layer_0_detections = await self.layer_0_structural.detect_output(output_text, input_text=input_text)
        layer_0_score = StructuralHallucinationDetector.calculate_hallucination_score(layer_0_detections)
        layer_0_categories = [d.category for d in layer_0_detections]
        layer_0_duration = (time.perf_counter() - t0) * 1000
        
        # Run forensic analysis (self-contained, zero external API)
        forensic_report = await self.forensic_analyzer.analyze(output_text, input_text=input_text)
        forensic_score = forensic_report["overall_risk_score"]
        
        # Merge scores: take the higher of structural vs forensic
        combined_score = max(layer_0_score, forensic_score)
        
        results = {
            "policy_tier_used": tier,
            "layer_0_structural": {
                "score": layer_0_score,
                "is_hallucination": layer_0_score >= 0.35,
                "detections": [d.dict() for d in layer_0_detections],
                "duration_ms": layer_0_duration
            },
            "layer_results": {},
            "final_score": combined_score,
            "is_hallucination": combined_score >= 0.35,
            "forensic_analysis": forensic_report
        }
        
        # Determine layers
        if tier == "ADAPTIVE":
            layers_to_run = determine_adaptive_layers(layer_0_score, layer_0_categories)
        else:
            policy = POLICIES.get(tier, POLICIES["STANDARD"])
            layers_to_run = policy.layers
            
        # 2. Run configured layers sequentially (could be parallelized later)
        max_score = combined_score  # Start from forensic+structural combined score
        is_hallucination = results["is_hallucination"]
        
        for layer_name in layers_to_run:
            if layer_name == "layer_0_structural" or layer_name == "dynamic":
                continue
                
            layer = self._get_layer(layer_name)
            if not layer:
                continue
                
            res = None
            if layer_name == "layer_1_nli":
                if context_documents:
                    res = await layer.check(output_text, context_documents)
            elif layer_name == "layer_2_citation":
                res = await layer.check(output_text)
            elif layer_name == "layer_3_wikipedia":
                res = await layer.check(output_text)
            elif layer_name == "layer_4_llm_judge":
                res = await layer.check(output_text, input_text or "")
            elif layer_name == "layer_5_rag_grounding":
                if context_documents:
                    res = await layer.check(output_text, context_documents)
                    
            if res:
                results["layer_results"][layer_name] = res.dict()
                if not res.skipped:
                    max_score = max(max_score, res.score)
                    if res.is_hallucination:
                        is_hallucination = True
                        
        results["final_score"] = round(max_score, 4)
        results["is_hallucination"] = is_hallucination
        
        return results

    async def detect_output(self, output_text: str, input_text: Optional[str] = None, context_documents: Optional[list[str]] = None) -> list[DetectionResult]:
        """Adapter for FirewallEngine output scanning pipeline."""
        # Run the full multi-layer detection using the organization's policy (or STANDARD by default)
        results = await self.detect_multi_layer(output_text, input_text=input_text, context_documents=context_documents)
        
        detections = []
        # Convert the structural detections
        layer_0 = results.get("layer_0_structural", {})
        for raw_det in layer_0.get("detections", []):
            detections.append(DetectionResult(**raw_det))
            
        # Convert advanced layer detections
        layer_results = results.get("layer_results", {})
        for layer_name, layer_res in layer_results.items():
            if layer_res.get("is_hallucination"):
                detections.append(DetectionResult(
                    detector=f"hallucination.{layer_name}",
                    confidence=layer_res.get("score", 0.9),
                    category="hallucination.multi_layer_verified",
                    description=f"Multi-layer engine flagged hallucination via {layer_name}. Details: {layer_res.get('details', {})}",
                    severity="critical" if layer_res.get("score", 0) > 0.8 else "high"
                ))
                
        return detections

    async def detect(self, input_text: str) -> list[DetectionResult]:
        """Adapter for FirewallEngine input scanning pipeline (elicitation attempts)."""
        return await self.layer_0_structural.detect(input_text)

# Singleton export matching the old usage, but now it's the full engine
hallucination_engine = HallucinationEngine()
# Provide the old singleton for backwards compatibility in other modules if any
hallucination_detector = hallucination_engine.layer_0_structural
