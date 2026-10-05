from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("firewall.cross_lingual")

class CrossLingualDetector:
    def __init__(self):
        self._initialized = False

    async def initialize(self):
        if not self._initialized:
            try:
                import langdetect
                from langdetect import DetectorFactory
                DetectorFactory.seed = 0
            except ImportError:
                logger.warning("langdetect not installed.")
            self._initialized = True

    async def detect(self, text: str) -> list[DetectionResult]:
        detections = []
        if not text or len(text) < 10:
            return detections
            
        try:
            import langdetect
            # Detect primary language
            lang = langdetect.detect(text)
            
            # If the language is NOT english, but contains known english jailbreak terms, flag it
            # This detects "Mixed Language" or translated DAN prompts
            if lang != 'en':
                english_jailbreaks = ["ignore previous", "jailbreak", "do anything now", "developer mode"]
                for phrase in english_jailbreaks:
                    if phrase in text.lower():
                        detections.append(DetectionResult(
                            detector="cross_lingual",
                            confidence=0.85,
                            category="injection.cross_lingual",
                            description=f"English jailbreak phrase '{phrase}' detected in a {lang} prompt.",
                            matched_content=phrase,
                            severity="high"
                        ))
        except Exception as e:
            logger.debug(f"Langdetect failed: {e}")
            
        return detections
