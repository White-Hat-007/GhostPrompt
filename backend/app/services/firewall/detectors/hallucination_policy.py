"""
Hallucination Detection Policy Engine
"""
from pydantic import BaseModel


class PolicyTier(BaseModel):
    name: str
    layers: list[str]
    max_latency_ms: int
    description: str

POLICIES = {
    "FAST": PolicyTier(
        name="FAST",
        layers=["layer_0_structural"],
        max_latency_ms=20,
        description="High-throughput, non-factual creative tasks."
    ),
    "STANDARD": PolicyTier(
        name="STANDARD",
        layers=["layer_0_structural", "layer_1_nli", "layer_5_rag_grounding"],
        max_latency_ms=250,
        description="Default for most RAG applications and customer support."
    ),
    "THOROUGH": PolicyTier(
        name="THOROUGH",
        layers=["layer_0_structural", "layer_1_nli", "layer_2_citation", "layer_3_wikipedia", "layer_4_llm_judge", "layer_5_rag_grounding"],
        max_latency_ms=1500,
        description="Medical, legal, financial, and compliance applications."
    ),
    "MAXIMUM": PolicyTier(
        name="MAXIMUM",
        layers=["layer_0_structural", "layer_1_nli", "layer_2_citation", "layer_3_wikipedia", "layer_4_llm_judge", "layer_5_rag_grounding", "layer_6_selfcheck"],
        max_latency_ms=5000,
        description="Critical factual queries and research tools."
    ),
    "ADAPTIVE": PolicyTier(
        name="ADAPTIVE",
        layers=["dynamic"],
        max_latency_ms=2000,
        description="Dynamically selects layers based on initial structural score."
    )
}

def determine_adaptive_layers(layer_0_score: float, detected_categories: list[str]) -> list[str]:
    """
    Decide which layers to run based on the initial fast structural check.
    """
    if layer_0_score < 0.1 and not any("factual" in c for c in detected_categories):
        return ["layer_0_structural"]
    elif layer_0_score < 0.4:
        return POLICIES["STANDARD"].layers
    elif layer_0_score >= 0.7 or any("factual" in c or "citation" in c for c in detected_categories):
        return POLICIES["MAXIMUM"].layers
    else:
        return POLICIES["THOROUGH"].layers
