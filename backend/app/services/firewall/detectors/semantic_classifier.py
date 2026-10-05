"""
Semantic Intent Classifier (Layer 3)

Uses a fine-tuned transformer model (DistilBERT/MiniLM) to classify the 
underlying intent of a prompt, completely ignoring specific keywords.
This catches zero-day attacks and rewording bypasses where traditional
regex/pattern matching fails.
"""

from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.semantic_classifier")
settings = get_settings()

INTENT_CATEGORIES = {
    0: "SAFE",
    1: "JAILBREAK_ATTEMPT",
    2: "INSTRUCTION_OVERRIDE",
    3: "DATA_EXTRACTION",
    4: "SOCIAL_ENGINEERING",
    5: "ROLE_MANIPULATION",
    6: "ENCODING_ATTACK",
    7: "UNKNOWN_SUSPICIOUS",
    8: "SPML_DELIMITER_CONFUSION",
    9: "CONTEXT_IGNORING"
}

class SemanticClassifier:
    """
    ML-based Semantic Intent Classifier.
    Runs local inference via HuggingFace transformers or ONNX runtime.
    Falls back to a heuristic mock if ML dependencies are missing.
    """

    def __init__(self):
        self._model = None
        self._tokenizer = None
        self._is_active = False
        
        # Sensitivity mapping: stricter sensitivity requires lower confidence to trigger
        self.thresholds = {
            "STRICT": 0.50,
            "BALANCED": 0.75,
            "PERMISSIVE": 0.90
        }
        # In a real app, sensitivity comes from DB/org config. Hardcoding to BALANCED for now.
        self.current_sensitivity = "BALANCED"

    async def initialize(self) -> None:
        """Load the fine-tuned ML model for intent classification."""
        import json
        from pathlib import Path

        # Path to our fine-tuned model (trained via train_classifier.py)
        trained_model_path = Path(__file__).resolve().parents[3] / "ml_models" / "semantic_classifier"

        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            if trained_model_path.exists() and (trained_model_path / "config.json").exists():
                logger.info("loading_trained_semantic_classifier", path=str(trained_model_path))
                self._tokenizer = AutoTokenizer.from_pretrained(str(trained_model_path))
                self._model = AutoModelForSequenceClassification.from_pretrained(str(trained_model_path))
                self._model = self._model.cpu()
                self._model.eval()
                self._is_active = True

                # Load label map if available
                label_map_path = trained_model_path / "label_map.json"
                if label_map_path.exists():
                    with open(label_map_path) as f:
                        self._label_map = {int(k): v for k, v in json.load(f).items()}
                    logger.info("label_map_loaded", labels=len(self._label_map))

                logger.info("semantic_classifier_initialized", status="active_trained_model")
            else:
                logger.warning(
                    "semantic_classifier_using_heuristic",
                    reason=f"No trained model at {trained_model_path} — using heuristic fallback"
                )
                self._is_active = False
        except ImportError:
            logger.warning("semantic_classifier_fallback", reason="torch/transformers not installed")
            self._is_active = False
        except Exception as e:
            logger.error("semantic_classifier_failed", error=str(e))
            self._is_active = False

    async def detect(self, text: str) -> list[DetectionResult]:
        """Classify the semantic intent of the text."""
        if not text.strip():
            return []

        if self._is_active:
            return self._run_ml_inference(text)
        else:
            return self._run_heuristic_fallback(text)

    def _run_ml_inference(self, text: str) -> list[DetectionResult]:
        """Run inference using the fine-tuned DistilBERT classifier."""
        import torch
        import torch.nn.functional as F

        try:
            inputs = self._tokenizer(
                text, return_tensors="pt", truncation=True, max_length=128
            )

            with torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits
                probs = F.softmax(logits, dim=-1).squeeze()

            max_prob, max_idx = torch.max(probs, dim=0)
            score = max_prob.item()
            category_idx = max_idx.item()

            # Use trained label map, fall back to INTENT_CATEGORIES
            label_map = getattr(self, '_label_map', INTENT_CATEGORIES)
            category_name = label_map.get(category_idx, "UNKNOWN_SUSPICIOUS")

            # If the model classifies as SAFE → no detection
            if category_name == "SAFE":
                return []

            threshold = self.thresholds.get(self.current_sensitivity, 0.75)

            if score >= threshold:
                return [
                    DetectionResult(
                        detector="semantic_classifier",
                        confidence=round(score, 4),
                        category=f"intent.{category_name.lower()}",
                        description=f"ML Semantic Classifier: {category_name} (score: {score:.3f})",
                        matched_content="[Trained Model Detection]",
                        severity="critical" if score > 0.95 else "high" if score > 0.85 else "medium"
                    )
                ]
            return []

        except Exception as e:
            logger.error("ml_inference_failed", error=str(e))
            return self._run_heuristic_fallback(text)

    def _run_heuristic_fallback(self, text: str) -> list[DetectionResult]:
        """
        Comprehensive heuristic-based semantic intent classifier.
        
        Covers ALL 7 malicious intent categories with 100+ signal patterns,
        proximity-weighted scoring, multi-signal boosting, and combinatorial
        detection. This is the primary classifier when the ML model is not
        fine-tuned.
        """
        text_lower = text.lower()
        detections = []
        
        # ── Comprehensive intent signal database ──────────────────────
        # Each category has: signal word-pairs (w1, w2), max proximity distance,
        # base confidence, and severity
        INTENT_SIGNALS = {
            "JAILBREAK_ATTEMPT": {
                "pairs": [
                    ("unrestricted", "mode"), ("bypass", "filter"), ("ignore", "rules"),
                    ("no", "restrictions"), ("remove", "safety"), ("disable", "filter"),
                    ("bypass", "safety"), ("bypass", "guardrail"), ("bypass", "protection"),
                    ("unrestricted", "access"), ("unfiltered", "mode"), ("uncensored", "mode"),
                    ("jailbreak", "mode"), ("developer", "mode"), ("god", "mode"),
                    ("no", "censorship"), ("no", "filter"), ("no", "limit"),
                    ("without", "restriction"), ("without", "filter"), ("without", "rule"),
                    ("free", "restriction"), ("freed", "restriction"), ("break", "free"),
                    ("remove", "guardrail"), ("disable", "safety"), ("turn", "off"),
                    ("DAN", "mode"), ("do", "anything"), ("anything", "now"),
                    ("unaligned", "ai"), ("evil", "mode"), ("opposite", "day"),
                    ("no", "moral"), ("no", "ethical"), ("no", "guideline"),
                    ("unlock", "potential"), ("unlock", "capability"), ("full", "power"),
                    ("grandma", "recipe"), ("grandma", "tell"), ("grandma", "used"),
                    ("story", "villain"), ("story", "hacker"), ("fictional", "scenario"),
                    ("fictional", "bypass"), ("imagine", "no"), ("hypothetical", "hack"),
                    ("bypass", "security"), ("hypothetical", "bypass"), ("hypothetically", "bypass"),
                    ("academic", "research"), ("educational", "purposes"),
                ],
                "max_dist": 80,
                "base_confidence": 0.82,
                "severity": "high",
            },
            "INSTRUCTION_OVERRIDE": {
                "pairs": [
                    ("forget", "instructions"), ("new", "instructions"), ("disregard", "previous"),
                    ("ignore", "previous"), ("ignore", "instruction"), ("ignore", "above"),
                    ("override", "system"), ("override", "instruction"), ("override", "prompt"),
                    ("forget", "everything"), ("forget", "rules"), ("forget", "told"),
                    ("disregard", "rules"), ("disregard", "instruction"), ("disregard", "above"),
                    ("new", "directive"), ("new", "rule"), ("updated", "instruction"),
                    ("replace", "instruction"), ("replace", "rules"), ("replace", "prompt"),
                    ("from", "now"), ("instead", "should"), ("instead", "must"),
                    ("real", "instruction"), ("actual", "task"), ("true", "purpose"),
                    ("previous", "overridden"), ("reset", "default"), ("wipe", "memory"),
                    ("clear", "context"), ("erase", "instruction"), ("important", "new"),
                ],
                "max_dist": 60,
                "base_confidence": 0.85,
                "severity": "high",
            },
            "DATA_EXTRACTION": {
                "pairs": [
                    ("reveal", "prompt"), ("show", "prompt"), ("display", "prompt"),
                    ("repeat", "instruction"), ("repeat", "above"), ("repeat", "word"),
                    ("print", "system"), ("echo", "system"), ("output", "system"),
                    ("what", "instruction"), ("what", "prompt"), ("what", "told"),
                    ("tell", "secret"), ("tell", "system"), ("tell", "prompt"),
                    ("show", "instruction"), ("show", "configuration"), ("show", "hidden"),
                    ("copy", "prompt"), ("paste", "instruction"), ("write", "instruction"),
                    ("leak", "prompt"), ("extract", "prompt"), ("exfiltrate", "data"),
                    ("dump", "memory"), ("dump", "context"), ("dump", "instruction"),
                    ("read", "system"), ("read", "back"), ("verbatim", "prompt"),
                    ("word", "word"), ("letter", "letter"), ("exact", "instruction"),
                    ("list", "database"), ("retrieve", "record"), ("access", "internal"),
                    ("show", "api"), ("show", "key"), ("show", "credential"),
                    ("server", "detail"), ("internal", "info"), ("backend", "data"),
                    ("network", "config"), ("ip", "address"), ("database", "credential"),
                    ("what", "ip"), ("your", "ip"), ("server", "ip"), ("host", "ip"),
                    ("internal", "ip"), ("what", "address"), ("your", "address"),
                    ("mac", "address"), ("your", "mac"), ("what", "mac"),
                    ("your", "hostname"), ("server", "hostname"), ("what", "hostname"),
                    ("your", "os"), ("server", "os"), ("what", "os"), ("your", "version"),
                    ("your", "port"), ("server", "port"), ("open", "port"),
                    ("your", "architecture"), ("server", "architecture"),
                    ("your", "config"), ("server", "config"), ("your", "secret"),
                    ("your", "password"), ("your", "token"), ("your", "key"),
                    ("your", "endpoint"), ("your", "url"), ("your", "domain"),
                ],
                "max_dist": 60,
                "base_confidence": 0.83,
                "severity": "high",
            },
            "SOCIAL_ENGINEERING": {
                "pairs": [
                    ("developer", "override"), ("admin", "access"), ("emergency", "disable"),
                    ("i", "developer"), ("i", "creator"), ("i", "administrator"),
                    ("i", "authorized"), ("i", "owner"), ("i", "root"),
                    ("special", "permission"), ("elevated", "access"), ("admin", "privilege"),
                    ("ceo", "said"), ("boss", "told"), ("manager", "ordered"),
                    ("authorized", "openai"), ("authorized", "anthropic"), ("authorized", "company"),
                    ("emergency", "override"), ("emergency", "access"), ("emergency", "bypass"),
                    ("urgent", "immediately"), ("critical", "now"), ("hurry", "quick"),
                    ("lives", "stake"), ("people", "die"), ("emergency", "situation"),
                    ("trust", "me"), ("believe", "me"), ("promise", "safe"),
                    ("don't", "question"), ("don't", "ask"), ("just", "do"),
                    ("new", "policy"), ("company", "policy"), ("compliance", "require"),
                    ("skip", "verification"), ("no", "confirm"), ("no", "check"),
                ],
                "max_dist": 80,
                "base_confidence": 0.78,
                "severity": "high",
            },
            "ROLE_MANIPULATION": {
                "pairs": [
                    ("you", "are"), ("act", "as"), ("pretend", "be"),
                    ("roleplay", "as"), ("simulate", "being"), ("assume", "role"),
                    ("switch", "persona"), ("switch", "character"), ("switch", "role"),
                    ("enter", "mode"), ("activate", "mode"), ("enable", "mode"),
                    ("you", "now"), ("from", "now"), ("henceforth", "you"),
                    ("new", "identity"), ("new", "persona"), ("new", "character"),
                    ("evil", "ai"), ("evil", "assistant"), ("evil", "version"),
                    ("villain", "ai"), ("villain", "assistant"), ("malicious", "actor"),
                    ("two", "ais"), ("two", "personalities"), ("split", "personality"),
                    ("opposite", "mode"), ("reverse", "mode"), ("anti", "mode"),
                    ("character", "called"), ("character", "named"), ("persona", "named"),
                ],
                "max_dist": 40,
                "base_confidence": 0.76,
                "severity": "high",
            },
            "ENCODING_ATTACK": {
                "pairs": [
                    ("decode", "this"), ("decode", "execute"), ("decode", "follow"),
                    ("base64", "decode"), ("hex", "decode"), ("rot13", "decode"),
                    ("encode", "response"), ("encrypt", "answer"), ("obfuscate", "output"),
                    ("split", "answer"), ("first", "letter"), ("first", "character"),
                    ("respond", "code"), ("respond", "base64"), ("respond", "hex"),
                    ("hidden", "instruction"), ("hidden", "message"), ("hidden", "command"),
                    ("invisible", "character"), ("invisible", "text"), ("steganography", "text"),
                    ("reverse", "text"), ("backwards", "read"), ("mirror", "text"),
                    ("caesar", "cipher"), ("cipher", "decode"), ("encrypted", "message"),
                    ("morse", "code"), ("binary", "decode"), ("braille", "text"),
                ],
                "max_dist": 60,
                "base_confidence": 0.80,
                "severity": "high",
            },
            "UNKNOWN_SUSPICIOUS": {
                "pairs": [
                    ("exploit", "vulnerability"), ("hack", "system"), ("attack", "model"),
                    ("steal", "weight"), ("steal", "data"), ("extract", "model"),
                    ("inversion", "attack"), ("adversarial", "example"), ("adversarial", "input"),
                    ("poison", "training"), ("poison", "data"), ("backdoor", "model"),
                    ("trojan", "model"), ("supply", "chain"), ("model", "extraction"),
                    ("membership", "inference"), ("gradient", "leak"), ("weight", "extraction"),
                    ("training", "leak"), ("memorize", "data"), ("regurgitate", "training"),
                    ("reproduce", "training"), ("repeat", "forever"), ("loop", "infinite"),
                ],
                "max_dist": 80,
                "base_confidence": 0.75,
                "severity": "medium",
            },
            "SPML_DELIMITER_CONFUSION": {
                "pairs": [
                    ("###", "system"), ("###", "instruction"), ("<system>", "</system>"),
                    ("<instruction>", "</instruction>"), ("```", "system"),
                    ("xml", "tag"), ("markdown", "header"), ("ignore", "```"),
                    ("ignore", "###"), ("begin", "system"), ("end", "system"),
                    ("system", "prompt"), ("user", "prompt"), ("assistant", "prompt"),
                ],
                "max_dist": 60,
                "base_confidence": 0.85,
                "severity": "high",
            },
            "CONTEXT_IGNORING": {
                "pairs": [
                    ("ignore", "above"), ("disregard", "above"), ("forget", "above"),
                    ("ignore", "previous"), ("forget", "previous"), ("disregard", "previous"),
                    ("only", "pay"), ("only", "attention"), ("focus", "only"),
                    ("ignore", "everything"), ("disregard", "everything"),
                ],
                "max_dist": 40,
                "base_confidence": 0.80,
                "severity": "medium",
            },
        }

        # ── Multi-signal detection with proximity scoring ─────────────
        category_scores: dict[str, float] = {}
        category_matches: dict[str, list[str]] = {}
        
        for category, config in INTENT_SIGNALS.items():
            hits = 0
            matched_pairs = []
            max_dist = config["max_dist"]
            
            for w1, w2 in config["pairs"]:
                import re
                m1 = re.search(rf"\b{re.escape(w1)}\b", text_lower)
                m2 = re.search(rf"\b{re.escape(w2)}\b", text_lower)
                if m1 and m2:
                    # Find positions — check proximity
                    pos1 = m1.start()
                    pos2 = m2.start()
                    dist = abs(pos1 - pos2)
                    
                    if dist < max_dist:
                        # Proximity bonus: closer = higher confidence
                        proximity_bonus = max(0, 1.0 - (dist / max_dist)) * 0.15
                        hits += 1
                        matched_pairs.append(f"{w1}...{w2}")
            
            if hits > 0:
                # Multi-hit boosting: each additional hit increases confidence
                confidence = min(config["base_confidence"] + (hits - 1) * 0.05 + proximity_bonus, 0.95)
                category_scores[category] = confidence
                category_matches[category] = matched_pairs

        # ── Generate detections for all matched categories ────────────
        for category, confidence in sorted(category_scores.items(), key=lambda x: -x[1]):
            severity = INTENT_SIGNALS[category]["severity"]
            # Boost severity if many signals fire
            if len(category_matches[category]) >= 4:
                severity = "critical" if severity == "high" else "high"
            
            detections.append(
                DetectionResult(
                    detector="semantic_classifier",
                    confidence=round(confidence, 4),
                    category=f"intent.{category.lower()}",
                    description=f"Semantic intent classifier detected {category} ({len(category_matches[category])} signals)",
                    matched_content=f"[{'; '.join(category_matches[category][:5])}]",
                    severity=severity,
                )
            )
        
        # ── Cross-category amplification ──────────────────────────────
        # If multiple malicious categories fire, boost the top detection
        if len(detections) >= 2:
            detections[0] = DetectionResult(
                detector="semantic_classifier",
                confidence=min(detections[0].confidence + 0.10, 0.98),
                category=detections[0].category,
                description=f"{detections[0].description} [MULTI-VECTOR: {len(detections)} categories]",
                matched_content=detections[0].matched_content,
                severity="critical" if detections[0].severity in ("high", "critical") else "high",
            )
        
        return detections
