import re
import httpx
from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("firewall.supply_chain")

class SupplyChainValidator:
    def __init__(self):
        self._initialized = False

    async def initialize(self):
        self._initialized = True

    async def validate_output(self, text: str) -> list[DetectionResult]:
        """Scans LLM output for hallucinated packages."""
        detections = []
        if not text:
            return detections
            
        # Regex to find Python pip install commands
        pip_pattern = r"pip install\s+([a-zA-Z0-9_\-]+)"
        packages = re.findall(pip_pattern, text)
        
        if not packages:
            return detections
            
        async with httpx.AsyncClient(timeout=3.0) as client:
            for pkg in set(packages):
                if pkg in ("requests", "numpy", "pandas", "fastapi", "flask", "django"):
                    continue # Skip very common ones to save time
                try:
                    resp = await client.get(f"https://pypi.org/pypi/{pkg}/json")
                    if resp.status_code == 404:
                        detections.append(DetectionResult(
                            detector="supply_chain",
                            confidence=0.99,
                            category="supply_chain.hallucinated_package",
                            description=f"LLM generated a hallucinated Python package '{pkg}'. Potential supply chain vulnerability.",
                            matched_content=f"pip install {pkg}",
                            severity="high"
                        ))
                except Exception as e:
                    logger.debug(f"PyPI check failed for {pkg}: {e}")
                    
        return detections
