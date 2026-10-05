"""
Multi-Layer Hallucination Engine Components
"""
import asyncio
import json
import re
import time
from typing import Any

import httpx
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("detector.hallucination_layers")
settings = get_settings()

class HallucinationScore(BaseModel):
    score: float
    method: str
    is_hallucination: bool
    details: dict[str, Any] = {}
    skipped: bool = False
    reason: str | None = None
    duration_ms: float = 0.0

def _extract_sentences(text: str) -> list[str]:
    """Fallback simple sentence extraction."""
    sentences = re.split(r'(?<=[.!?])\s+', text.replace('\n', ' '))
    return [s.strip() for s in sentences if len(s.split()) >= 4]

# ── LAYER 1: NLI Entailment ──────────────────────────────────────────────────
class NLIEntailmentLayer:
    def __init__(self):
        self._model = None
        self._torch = None
        
    def _ensure_model(self):
        if self._model is None:
            try:
                import torch
                from sentence_transformers import CrossEncoder
                self._torch = torch
                device = "cuda" if torch.cuda.is_available() else "cpu"
                logger.info(f"Loading NLI model on {device}")
                self._model = CrossEncoder(settings.HALLUCINATION_NLI_MODEL, device=device)
            except ImportError:
                logger.warning("sentence-transformers not installed, NLI skipped")
                self._model = "missing"
                
    async def check(self, response: str, context_documents: list[str]) -> HallucinationScore:
        t0 = time.perf_counter()
        if not context_documents:
            return HallucinationScore(score=0.0, method="nli_entailment", is_hallucination=False, skipped=True, reason="no_context")
            
        self._ensure_model()
        if self._model == "missing":
             return HallucinationScore(score=0.0, method="nli_entailment", is_hallucination=False, skipped=True, reason="model_not_installed")
        
        claims = _extract_sentences(response)
        context = " ".join(context_documents)
        
        results = []
        for claim in claims:
            # Predict returns [contradiction, neutral, entailment]
            score_out = self._model.predict([(context, claim)])
            probs = self._torch.softmax(self._torch.tensor(score_out[0]), dim=0)
            
            contradiction_prob = float(probs[0])
            entailment_prob = float(probs[2])
            
            results.append({
                "claim": claim,
                "entailment": entailment_prob,
                "contradiction": contradiction_prob,
                "verdict": "FAITHFUL" if entailment_prob > 0.6 else "HALLUCINATED" if contradiction_prob > 0.5 else "UNVERIFIABLE"
            })
            
        hallucinated = [r for r in results if r["verdict"] == "HALLUCINATED"]
        faithfulness = sum(r["entailment"] for r in results) / len(results) if results else 1.0
        
        return HallucinationScore(
            score=1.0 - faithfulness,
            method="nli_entailment",
            is_hallucination=len(hallucinated) > 0,
            details={"claim_results": results, "hallucinated_count": len(hallucinated)},
            duration_ms=(time.perf_counter()-t0)*1000
        )

# ── LAYER 2: DOI/URL Verification ──────────────────────────────────────────
class CitationVerificationLayer:
    async def check(self, response: str) -> HallucinationScore:
        t0 = time.perf_counter()
        dois = re.findall(r"\b10\.\d{4,}/[-._;()/:A-Za-z0-9]+\b", response)
        urls = re.findall(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+", response)
        
        if not dois and not urls:
             return HallucinationScore(score=0.0, method="citation_verify", is_hallucination=False, skipped=True, reason="no_citations")
             
        results = []
        async with httpx.AsyncClient(timeout=3.0) as client:
            for doi in dois[:3]:  # Max 3
                r = await client.get(f"https://api.crossref.org/works/{doi}")
                results.append({
                    "item": doi,
                    "type": "doi",
                    "verdict": "VERIFIED" if r.status_code == 200 else "FABRICATED" if r.status_code == 404 else "UNVERIFIABLE"
                })
            
            for url in urls[:3]: # Max 3
                try:
                    r = await client.head(url, follow_redirects=True)
                    results.append({
                        "item": url,
                        "type": "url",
                        "verdict": "VERIFIED" if r.status_code < 400 else "FABRICATED" if r.status_code == 404 else "UNVERIFIABLE"
                    })
                except Exception:
                    results.append({"item": url, "type": "url", "verdict": "UNVERIFIABLE"})
                    
        fabricated = [r for r in results if r["verdict"] == "FABRICATED"]
        
        return HallucinationScore(
            score=len(fabricated) / max(len(results), 1),
            method="citation_verify",
            is_hallucination=len(fabricated) > 0,
            details={"verification_results": results},
            duration_ms=(time.perf_counter()-t0)*1000
        )

# ── LAYER 3: Wikipedia Entity Verification ─────────────────────────────────
class WikipediaEntityLayer:
    def __init__(self):
        self._wiki = None
        self.nli_layer = NLIEntailmentLayer()
        
    def _ensure_api(self):
        if self._wiki is None:
            try:
                import wikipediaapi
                self._wiki = wikipediaapi.Wikipedia('GhostPrompt/1.0 (admin@ghostprompt.io)', 'en')
            except ImportError:
                self._wiki = "missing"
                
    async def check(self, response: str) -> HallucinationScore:
        t0 = time.perf_counter()
        self._ensure_api()
        if self._wiki == "missing":
             return HallucinationScore(score=0.0, method="wikipedia_verify", is_hallucination=False, skipped=True, reason="wikipedia_api_missing")
             
        # Extract potential entities using capitalized words (rough fallback if no spacy)
        entities = set(re.findall(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b", response))
        
        results = []
        claims = _extract_sentences(response)
        
        for entity in list(entities)[:2]:  # Check max 2 entities to save time
            try:
                page = await asyncio.to_thread(self._wiki.page, entity)
                if not page.exists():
                    continue
                    
                summary = page.summary[:1500]
                # Find a claim containing the entity
                target_claim = next((c for c in claims if entity in c), None)
                if not target_claim:
                    continue
                    
                # Cross-reference with NLI
                nli_res = await self.nli_layer.check(target_claim, [summary])
                if nli_res.skipped:
                    continue
                    
                claim_res = nli_res.details.get("claim_results", [])
                if claim_res:
                    res = claim_res[0]
                    results.append({
                        "entity": entity,
                        "claim": target_claim,
                        "verdict": res["verdict"],
                        "confidence": res.get("contradiction", 0.0)
                    })
            except Exception:
                pass
                
        contradicted = [r for r in results if r["verdict"] == "HALLUCINATED"]
        
        return HallucinationScore(
            score=len(contradicted) / max(len(results), 1) if results else 0.0,
            method="wikipedia_verify",
            is_hallucination=len(contradicted) > 0,
            details={"verification_results": results},
            duration_ms=(time.perf_counter()-t0)*1000
        )

# ── LAYER 4: LLM-as-Judge ──────────────────────────────────────────────────
class LLMJudgeLayer:
    
    SYSTEM_PROMPT = """You are a rigorous fact-checking assistant. Your ONLY job is to identify factually incorrect claims in AI-generated text. You do not evaluate style or tone — only factual accuracy.

IMPORTANT RULES:
- Check ALL factual claims: dates, names, events, scientific discoveries, organizations, publications.
- If a claim references a specific report, paper, or publication name, verify it exists.
- If a claim attributes a discovery or action to a specific entity, verify the attribution is correct.
- Fabricated publication names, fake report titles, and invented discoveries are INCORRECT.
- Be aggressive: when in doubt, mark as INCORRECT rather than UNVERIFIABLE.

Respond ONLY in this JSON format:
{
  "overall_hallucination_risk": 0.0 to 1.0,
  "verdict": "FAITHFUL" or "LIKELY_HALLUCINATED",
  "claims": [
    {
      "text": "exact claim text from the response",
      "assessment": "CORRECT" or "INCORRECT" or "UNVERIFIABLE",  
      "correction": "what is actually correct, or why this is fabricated",
      "confidence": 0.9,
      "type": "factual_error"
    }
  ]
}"""

    async def _try_openai(self, prompt: str) -> str:
        """Try OpenAI API. Raises on failure."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                json={
                    "model": settings.HALLUCINATION_JUDGE_MODEL,
                    "messages": [
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.0
                }
            )
            data = r.json()
            if "error" in data:
                raise Exception(f"OpenAI: {data['error'].get('message', data['error'])}")
            return data["choices"][0]["message"]["content"]

    async def _try_anthropic(self, prompt: str) -> str:
        """Try Anthropic API. Raises on failure."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": settings.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"},
                json={
                    "model": "claude-3-5-haiku-20241022",
                    "system": self.SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1500,
                    "temperature": 0.0
                }
            )
            data = r.json()
            if "error" in data:
                raise Exception(f"Anthropic: {data['error'].get('message', data['error'])}")
            return data["content"][0]["text"]

    async def _try_google(self, prompt: str) -> str:
        """Try Google Gemini API. Raises on failure."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={settings.GOOGLE_AI_API_KEY}",
                json={
                    "contents": [{"parts": [{"text": f"{self.SYSTEM_PROMPT}\n\n{prompt}"}]}],
                    "generationConfig": {"temperature": 0.0, "responseMimeType": "application/json"}
                }
            )
            data = r.json()
            if "error" in data:
                raise Exception(f"Google: {data['error'].get('message', data['error'])}")
            return data["candidates"][0]["content"]["parts"][0]["text"]

    async def check(self, response: str, original_query: str) -> HallucinationScore:
        t0 = time.perf_counter()
        
        available_keys = []
        if settings.OPENAI_API_KEY:
            available_keys.append("openai")
        if settings.ANTHROPIC_API_KEY:
            available_keys.append("anthropic")
        if settings.GOOGLE_AI_API_KEY:
            available_keys.append("google")
            
        if not available_keys:
            return HallucinationScore(score=0.0, method="llm_judge", is_hallucination=False, skipped=True, reason="no_api_key")
            
        prompt = f"Original user query: {original_query}\n\nAI-generated response to fact-check:\n{response}"
        
        # Cascading fallback: try each provider until one succeeds
        errors = []
        content = None
        
        for provider in available_keys:
            try:
                if provider == "openai":
                    content = await self._try_openai(prompt)
                elif provider == "anthropic":
                    content = await self._try_anthropic(prompt)
                elif provider == "google":
                    content = await self._try_google(prompt)
                    
                logger.info("llm_judge_provider_used", provider=provider)
                break  # Success — stop trying other providers
            except Exception as e:
                errors.append(f"{provider}: {e!s}")
                logger.warning("llm_judge_fallback", provider=provider, error=str(e))
                continue  # Try next provider
        
        if content is None:
            return HallucinationScore(
                score=0.0, method="llm_judge", is_hallucination=False, 
                skipped=True, reason=f"all_providers_failed: {'; '.join(errors)}"
            )
        
        try:
            result = json.loads(content)
            incorrect = [c for c in result.get("claims", []) if c.get("assessment") == "INCORRECT"]
            
            return HallucinationScore(
                score=float(result.get("overall_hallucination_risk", 0.0)),
                method="llm_judge",
                is_hallucination=result.get("verdict") == "LIKELY_HALLUCINATED",
                details={
                    "incorrect_claims": incorrect,
                    "all_claims": result.get("claims", [])
                },
                duration_ms=(time.perf_counter()-t0)*1000
            )
        except Exception as e:
            logger.error(f"LLM Judge JSON parse failed: {e}", raw_content=content[:500])
            return HallucinationScore(score=0.0, method="llm_judge", is_hallucination=False, skipped=True, reason=f"json_parse_error: {e!s}")

# ── LAYER 5: RAG Grounding ─────────────────────────────────────────────────
# Integrates NLI directly for RAG claims
class RAGGroundingLayer:
    def __init__(self):
        self.nli_layer = NLIEntailmentLayer()
        
    async def check(self, response: str, retrieved_chunks: list[str]) -> HallucinationScore:
        t0 = time.perf_counter()
        if not retrieved_chunks:
            return HallucinationScore(score=0.0, method="rag_grounding", is_hallucination=False, skipped=True, reason="no_rag_chunks")
            
        claims = _extract_sentences(response)
        claim_results = []
        
        for claim in claims:
            # Score against each chunk
            best_entailment = 0.0
            best_chunk = None
            max_contradiction = 0.0
            
            for chunk in retrieved_chunks:
                res = await self.nli_layer.check(claim, [chunk])
                if not res.skipped and "claim_results" in res.details:
                    c_res = res.details["claim_results"][0]
                    if c_res["entailment"] > best_entailment:
                        best_entailment = c_res["entailment"]
                        best_chunk = chunk
                    max_contradiction = max(max_contradiction, c_res["contradiction"])
            
            if best_entailment > 0.7:
                verdict = "GROUNDED"
            elif max_contradiction > 0.5:
                verdict = "CONTRADICTED"
            else:
                verdict = "UNGROUNDED"
                
            claim_results.append({
                "claim": claim,
                "verdict": verdict,
                "support_score": best_entailment,
                "contradiction_score": max_contradiction,
                "supporting_chunk": best_chunk[:100] if best_chunk else None
            })
            
        ungrounded = [c for c in claim_results if c["verdict"] in ["UNGROUNDED", "CONTRADICTED"]]
        grounding_score = len([c for c in claim_results if c["verdict"] == "GROUNDED"]) / max(len(claim_results), 1)
        
        return HallucinationScore(
            score=1.0 - grounding_score,
            method="rag_grounding",
            is_hallucination=len(ungrounded) > 0,
            details={"claim_results": claim_results, "ungrounded": ungrounded},
            duration_ms=(time.perf_counter()-t0)*1000
        )
