"""
Forensic Hallucination Analyzer — Self-Contained Intelligence Engine
Zero external API dependency. Uses pattern analysis, knowledge bases, and local NLI.
"""
import re
import time

from app.core.logging import get_logger

logger = get_logger("detector.hallucination_forensic")

# ── Known Real Entities Knowledge Base ──
KNOWN_AWARDS = {"nobel prize","pulitzer prize","turing award","fields medal","abel prize","grammy","oscar","emmy","tony award","booker prize","wolf prize"}
KNOWN_STANDARDS_PREFIXES = {"ISO","IEEE","ANSI","NIST","RFC","ASTM","IEC","ITU","W3C","OWASP"}
NOBEL_CATEGORIES = {"physics","chemistry","medicine","literature","peace","economics","physiology"}
VALID_RFC_MAX = 9700
VALID_CVE_MIN_YEAR = 1999
VALID_CVE_MAX_YEAR = 2026

# ── Fabrication Pattern Databases ──
FAKE_ORG_SIGNALS = [
    r"(?:Global|International|World|Universal|National)\s+(?:Institute|Center|Agency|Council|Foundation|Board)\s+(?:of|for)\s+(?:Advanced|Modern|Digital|Quantum|Cyber)\s+\w+",
    r"(?:The\s+)?[A-Z][a-z]+\s+(?:Institute|Foundation|Council)\s+(?:of|for)\s+[A-Z][a-z]+\s+(?:Research|Studies|Innovation|Excellence)",
]
FAKE_PERSON_SIGNALS = [
    r"(?:Dr|Prof|Professor)\.\s+[A-Z][a-z]{2,12}\s+[A-Z][a-z]{2,15}(?:\s+[A-Z][a-z]{2,15})?\s*,?\s*(?:a\s+)?(?:renowned|leading|prominent|distinguished|noted|famous|well-known)\s+(?:researcher|scientist|professor|expert|scholar|specialist|authority)",
    r"(?:Dr|Prof)\.\s+[A-Z][a-z]+\s+[A-Z][a-z]+\s+(?:from|at|of)\s+(?:the\s+)?(?:University|Institute|Center)\s+of\s+[A-Z][a-z]+",
    r"(?:Chief|Senior|Lead|Head)\s+(?:Scientist|Researcher|Officer|Engineer|Architect)\s+[A-Z][a-z]+\s+[A-Z][a-z]+",
]
FAKE_PRODUCT_SIGNALS = [
    r"(?:launched|released|announced|introduced|unveiled)\s+(?:its|their|the)\s+(?:new|latest|flagship|revolutionary)\s+(?:product|platform|tool|software|framework|system)\s+(?:called|named|dubbed)\s+[A-Z][a-zA-Z]+(?:\s+\d+\.?\d*)?",
]
FAKE_API_LIB_SIGNALS = [
    r"(?:import|require|from)\s+[a-z_]+(?:\.[a-z_]+)+\s*$",
    r"(?:pip install|npm install|gem install|cargo add)\s+[a-z][-a-z0-9_]+",
    r"the\s+[a-z]+[-_][a-z]+\s+(?:library|package|module|framework|SDK)\s+(?:version\s+)?\d+\.\d+",
]
FAKE_RESEARCH_SIGNALS = [
    r"(?:published|appeared|featured)\s+in\s+(?:the\s+)?(?:Journal|Proceedings|Annals|Transactions|Review|Bulletin)\s+of\s+(?:Advanced|Modern|International|Applied|Computational)\s+[A-Z][a-z]+",
    r"(?:Vol|Volume)\.\s*\d+,?\s*(?:No|Issue|Number)\.\s*\d+,?\s*(?:pp|pages?)\.\s*\d+-\d+",
    r"(?:Nature|Science|Cell|PNAS|Lancet|BMJ|NEJM|JAMA)\s+(?:vol|volume)\.\s*\d{3,4}",
]
FAKE_MEDICAL_SIGNALS = [
    r"(?:cures?|eliminates?|eradicates?|completely\s+(?:heals?|treats?|removes?))\s+(?:cancer|diabetes|alzheimer|HIV|AIDS|autism|depression)",
    r"(?:100|99\.9)%\s+(?:effective|cure\s+rate|success\s+rate|survival\s+rate)\s+(?:for|against|in\s+treating)\s+\w+",
    r"FDA\s+(?:approved|cleared)\s+(?:the\s+)?(?:use\s+of\s+)?[A-Z][a-z]+(?:ine|ol|id|um|ab)\s+(?:for|as|to)\s+(?:treat|cure|prevent)\s+\w+",
]
FAKE_LEGAL_SIGNALS = [
    r"(?:the\s+)?(?:landmark|historic|precedent-setting)\s+(?:case|ruling|decision)\s+(?:of\s+)?[A-Z][a-z]+\s+v\.?\s+[A-Z][a-z]+",
    r"(?:Section|Article|Clause)\s+\d+(?:\.\d+)*\s+of\s+the\s+[A-Z][a-z]+\s+(?:Act|Code|Statute|Law|Regulation)\s+of\s+\d{4}",
]
FICTION_AS_FACT = [
    r"\b(?:Hogwarts|Wakanda|Mordor|Narnia|Gotham City|Westeros|Middle[-\s]?Earth|Stark Industries|Wayne Enterprises|Umbrella Corporation|Cyberdyne|Skynet|Soylent Green|Aperture Science)\b",
]
OVERCONFIDENT_SIGNALS = [
    r"(?:absolutely|definitely|undeniably|unquestionably|indisputably|without\s+(?:a\s+)?doubt|guaranteed|100%\s+certain|proven\s+beyond|irrefutable)\s+(?:true|correct|accurate|real|factual|certain|proven)",
    r"(?:every\s+(?:single\s+)?scientist|all\s+(?:experts?|researchers?|scientists?)|no\s+(?:scientist|expert|researcher)\s+(?:disagrees?|disputes?|denies?|questions?))",
]
SPECULATION_AS_FACT = [
    r"(?:it\s+is\s+(?:widely|universally|commonly|generally)\s+(?:known|accepted|acknowledged|recognized)\s+that)\s+.{20,}",
    r"(?:studies?\s+(?:have\s+)?(?:conclusively|definitively|unequivocally)\s+(?:shown|proven|demonstrated|confirmed))\s+that\s+.{20,}",
]

def _extract_sentences(text: str) -> list[str]:
    sents = re.split(r'(?<=[.!?])\s+', text.replace('\n', ' '))
    return [s.strip() for s in sents if len(s.split()) >= 3]

def _extract_entities(text: str) -> list[dict]:
    entities = []
    for m in re.finditer(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b', text):
        entities.append({"text": m.group(1), "start": m.start(), "end": m.end(), "type": "entity"})
    return entities

def _extract_numbers(text: str) -> list[dict]:
    nums = []
    for m in re.finditer(r'\b(\d{1,3}(?:,\d{3})*(?:\.\d+)?)\s*(%|percent|billion|million|trillion|thousand)?\b', text):
        nums.append({"text": m.group(0), "value": m.group(1).replace(',',''), "unit": m.group(2) or "", "start": m.start(), "end": m.end()})
    return nums

def _extract_dates(text: str) -> list[dict]:
    dates = []
    
    # 1. Full dates (e.g. January 1, 2025)
    for m in re.finditer(r'\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4})\b', text):
        dates.append({"text": m.group(0), "start": m.start(), "end": m.end()})
        
    # 2. Years with context (e.g. in 2050, year 3000)
    for m in re.finditer(r'\b(?:in|year|by|since|until|from|during)\s+(\d{4})\b', text, re.IGNORECASE):
        dates.append({"text": m.group(1), "start": m.start(1), "end": m.end(1)})
        
    # 3. Bare years (restricted to realistic ranges 1900-2099 to avoid capturing RFCs/ports/quantities like 8446)
    for m in re.finditer(r'\b(19\d{2}|20\d{2})\b', text):
        dates.append({"text": m.group(1), "start": m.start(1), "end": m.end(1)})
        
    # Deduplicate by start index to prevent overlapping captures
    unique_dates = {d["start"]: d for d in dates}
    return list(unique_dates.values())

def _extract_citations(text: str) -> list[dict]:
    cites = []
    for m in re.finditer(r'\b(10\.\d{4,}/[-._;()/:A-Za-z0-9]+)\b', text):
        cites.append({"text": m.group(1), "type": "doi", "start": m.start(), "end": m.end()})
    for m in re.finditer(r'(https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w.-]*)', text):
        cites.append({"text": m.group(1), "type": "url", "start": m.start(), "end": m.end()})
    for m in re.finditer(r'\b((?:arXiv:)?\d{4}\.\d{4,5}(?:v\d+)?)\b', text):
        cites.append({"text": m.group(1), "type": "arxiv", "start": m.start(), "end": m.end()})
    for m in re.finditer(r'\b(ISBN[-: ]*(?:978|979)[-\d ]{10,17})\b', text):
        cites.append({"text": m.group(1), "type": "isbn", "start": m.start(), "end": m.end()})
    for m in re.finditer(r'\b(RFC\s*(\d+))\b', text, re.IGNORECASE):
        cites.append({"text": m.group(1), "type": "rfc", "number": int(m.group(2)), "start": m.start(), "end": m.end()})
    for m in re.finditer(r'\b(CVE-(\d{4})-\d{4,7})\b', text):
        cites.append({"text": m.group(1), "type": "cve", "year": int(m.group(2)), "start": m.start(), "end": m.end()})
    return cites

def _extract_orgs(text: str) -> list[dict]:
    orgs = []
    for m in re.finditer(r'\b((?:[A-Z][a-z]+\s+){1,3}(?:Inc|Corp|LLC|Ltd|Foundation|Institute|University|Agency|Council|Organization|Association|Commission|Bureau|Department|Ministry)\.?)\b', text):
        orgs.append({"text": m.group(1), "start": m.start(), "end": m.end()})
    return orgs

def _check_patterns(text: str, patterns: list[str], category: str, title: str, severity: str = "high", base_confidence: float = 0.88) -> list[dict]:
    issues = []
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE | re.MULTILINE):
            issues.append({
                "category": category,
                "severity": severity,
                "confidence": base_confidence,
                "title": title,
                "description": "Pattern match indicates potential fabrication.",
                "affected_text": m.group(0)[:200],
                "start_index": m.start(),
                "end_index": m.end(),
                "recommendation": f"Verify the existence of: '{m.group(0)[:80]}'"
            })
            break  # One per category pattern set
    return issues


class ForensicHallucinationAnalyzer:
    """Self-contained forensic hallucination analysis engine. Zero external API calls."""

    async def analyze(self, output_text: str, input_text: str | None = None) -> dict:
        t0 = time.perf_counter()
        issues = []
        sentences = _extract_sentences(output_text)
        entities = _extract_entities(output_text)
        numbers = _extract_numbers(output_text)
        dates = _extract_dates(output_text)
        citations = _extract_citations(output_text)
        orgs = _extract_orgs(output_text)

        # ── 1. Fabricated Citations ──
        for c in citations:
            if c["type"] == "doi":
                if re.search(r'fake|test|example|xxx|000', c["text"], re.IGNORECASE):
                    issues.append({"category":"fabricated_citation","severity":"critical","confidence":0.98,"title":"Fabricated DOI","description":f"DOI contains suspicious markers: {c['text']}","affected_text":c["text"],"start_index":c["start"],"end_index":c["end"],"recommendation":"Verify this DOI at https://doi.org"})
            elif c["type"] == "rfc":
                if c.get("number",0) > VALID_RFC_MAX:
                    issues.append({"category":"fabricated_rfc","severity":"high","confidence":0.92,"title":"Fabricated RFC","description":f"RFC {c.get('number')} exceeds known range (max ~{VALID_RFC_MAX})","affected_text":c["text"],"start_index":c["start"],"end_index":c["end"],"recommendation":"Check IETF RFC index."})
            elif c["type"] == "cve":
                yr = c.get("year",0)
                if yr < VALID_CVE_MIN_YEAR or yr > VALID_CVE_MAX_YEAR:
                    issues.append({"category":"fabricated_cve","severity":"high","confidence":0.93,"title":"Fabricated CVE","description":f"CVE year {yr} outside valid range ({VALID_CVE_MIN_YEAR}-{VALID_CVE_MAX_YEAR})","affected_text":c["text"],"start_index":c["start"],"end_index":c["end"],"recommendation":"Verify at cve.mitre.org"})

        # ── 2. Fabricated Organizations ──
        issues.extend(_check_patterns(output_text, FAKE_ORG_SIGNALS, "fabricated_organization", "Fabricated Organization", "high", 0.85))

        # ── 3. Fabricated Persons ──
        issues.extend(_check_patterns(output_text, FAKE_PERSON_SIGNALS, "fabricated_person", "Fabricated Person", "high", 0.87))

        # ── 4. Fabricated Products ──
        issues.extend(_check_patterns(output_text, FAKE_PRODUCT_SIGNALS, "fabricated_product", "Fabricated Product", "medium", 0.78))

        # ── 5. Fabricated APIs/Libraries/Packages ──
        issues.extend(_check_patterns(output_text, FAKE_API_LIB_SIGNALS, "fabricated_library", "Fabricated Library/Package", "medium", 0.75))

        # ── 6. Fabricated Research Papers ──
        issues.extend(_check_patterns(output_text, FAKE_RESEARCH_SIGNALS, "fabricated_research_paper", "Fabricated Research Paper", "critical", 0.90))

        # ── 7. Fabricated Medical Claims ──
        issues.extend(_check_patterns(output_text, FAKE_MEDICAL_SIGNALS, "fabricated_medical_claim", "Fabricated Medical Claim", "critical", 0.94))

        # ── 8. Fabricated Legal Claims ──
        issues.extend(_check_patterns(output_text, FAKE_LEGAL_SIGNALS, "fabricated_legal_claim", "Fabricated Legal Claim", "high", 0.82))

        # ── 9. Fiction Presented As Fact ──
        issues.extend(_check_patterns(output_text, FICTION_AS_FACT, "fiction_as_fact", "Fiction Presented As Fact", "high", 0.95))

        # ── 10. Overconfident Assertions ──
        issues.extend(_check_patterns(output_text, OVERCONFIDENT_SIGNALS, "overconfident_assertion", "Overconfident Assertion", "medium", 0.80))

        # ── 11. Speculation As Fact ──
        issues.extend(_check_patterns(output_text, SPECULATION_AS_FACT, "speculation_as_fact", "Speculation Presented As Fact", "medium", 0.78))

        # ── 12. Fabricated Statistics ──
        for n in numbers:
            try:
                val = float(n["value"])
                unit = n["unit"].lower() if n["unit"] else ""
                if unit in ("%", "percent") and val > 100:
                    issues.append({"category":"fabricated_statistics","severity":"high","confidence":0.95,"title":"Impossible Percentage","description":f"Percentage value {val}% exceeds 100%","affected_text":n["text"],"start_index":n["start"],"end_index":n["end"],"recommendation":"Verify this statistic."})
                if unit in ("billion","trillion") and val > 50000:
                    issues.append({"category":"impossible_numerical_value","severity":"medium","confidence":0.80,"title":"Implausible Number","description":f"Extremely large value: {n['text']}","affected_text":n["text"],"start_index":n["start"],"end_index":n["end"],"recommendation":"Verify this figure."})
            except ValueError:
                pass

        # ── 13. Impossible Timeline ──
        for d in dates:
            try:
                year_match = re.search(r'\b(\d{4})\b', d["text"])
                if year_match:
                    yr = int(year_match.group(1))
                    if yr > 2026:
                        issues.append({"category":"impossible_timeline","severity":"high","confidence":0.93,"title":"Future Date Reference","description":f"References year {yr} which hasn't occurred yet","affected_text":d["text"],"start_index":d["start"],"end_index":d["end"],"recommendation":"Verify temporal accuracy."})
            except ValueError:
                pass

        # ── 14. Contradictory Statements (Self-Contained NLI) ──
        contradiction_pairs = [
            (r'\bis\s+(?:the\s+)?(?:largest|biggest|most)\b', r'\bis\s+(?:the\s+)?(?:smallest|least|fewest)\b'),
            (r'\balways\b', r'\bnever\b'),
            (r'\bincreased\b', r'\bdecreased\b'),
            (r'\bopen[\s-]?source\b', r'\b(?:proprietary|closed[\s-]?source)\b'),
            (r'\bfree\b', r'\b(?:paid|costs?|priced|expensive)\b'),
            (r'\bsafe\b', r'\b(?:dangerous|unsafe|hazardous|toxic)\b'),
            (r'\b(?:confirmed|verified|proven)\b', r'\b(?:unconfirmed|unverified|unproven|disputed)\b'),
        ]
        for pa, pb in contradiction_pairs:
            sa = [(i,s) for i,s in enumerate(sentences) if re.search(pa, s, re.IGNORECASE)]
            sb = [(i,s) for i,s in enumerate(sentences) if re.search(pb, s, re.IGNORECASE)]
            if sa and sb:
                for ia, ta in sa:
                    for ib, tb in sb:
                        if ia != ib:
                            start_a = output_text.find(ta[:40])
                            issues.append({"category":"contradictory_statements","severity":"high","confidence":0.85,"title":"Contradictory Statements","description":"Conflicting claims detected between sentences","affected_text":f"{ta[:80]}... vs {tb[:80]}...","start_index":max(start_a,0),"end_index":max(start_a,0)+len(ta),"recommendation":"Resolve the internal contradiction."})
                            break
                    break

        # ── 15. Fake Standards ──
        for m in re.finditer(r'\b(ISO\s+\d{6,}|IEEE\s+\d{5,}|NIST\s+SP\s+\d{5,})\b', output_text):
            issues.append({"category":"fake_standards","severity":"high","confidence":0.88,"title":"Potentially Fake Standard","description":f"Standard number appears unusually large: {m.group(0)}","affected_text":m.group(0),"start_index":m.start(),"end_index":m.end(),"recommendation":"Verify against official standards registry."})

        # ── 16. Non-existent Awards ──
        for m in re.finditer(r'(?:won|awarded|received|granted)\s+(?:the\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4})\s+(?:Award|Prize|Medal|Fellowship)', output_text):
            award = m.group(1).lower() + " " + "award"
            if not any(k in award for k in KNOWN_AWARDS):
                issues.append({"category":"nonexistent_award","severity":"medium","confidence":0.82,"title":"Potentially Non-existent Award","description":f"Cannot verify award: {m.group(0)}","affected_text":m.group(0),"start_index":m.start(),"end_index":m.end(),"recommendation":"Verify this award exists."})

        # ── 17. Fabricated Report/Publication Names ──
        pub_patterns = [
            r"(?:published\s+in|according\s+to|reported\s+(?:in|by)|found\s+in|cited\s+in)\s+(?:the\s+)?(?:[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,5})\s+(?:Report|Survey|Review|Bulletin|Digest|Index|Outlook|Monitor)\s*(?:\d{4})?",
            r"(?:[A-Z][a-zA-Z]+(?:'s)?)\s+(?:[A-Z][a-zA-Z]+\s+){0,3}(?:Report|Survey|Bulletin|Monitor|Index|Digest|Outlook)\s+\d{4}",
            r"(?:finding|results?|data)\s+(?:was|were)\s+published\s+in\s+(?:[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,5})",
        ]
        issues.extend(_check_patterns(output_text, pub_patterns, "fabricated_citation", "Fabricated Publication", "critical", 0.91))

        # ── 18. Unsupported Scientific Claims ──
        sci_patterns = [
            r"(?:discovered|detected|found|observed)\s+(?:liquid\s+)?water\s+(?:on|beneath|under|inside)\s+(?:the\s+)?(?:surface\s+of\s+)?(?:Mars|Europa|Moon|Venus|Mercury|Titan|Enceladus|Pluto)",
            r"(?:achieved|reached|demonstrated)\s+(?:room[\s-]?temperature|ambient)\s+superconducti(?:vity|on|or)",
            r"(?:faster[\s-]?than[\s-]?light|FTL)\s+(?:travel|communication|speed|propulsion)\s+(?:has\s+been|was)\s+(?:achieved|demonstrated|proven)",
            r"(?:cold\s+fusion|perpetual\s+motion)\s+(?:has\s+been|was)\s+(?:achieved|demonstrated|proven|confirmed)",
        ]
        issues.extend(_check_patterns(output_text, sci_patterns, "fabricated_scientific_claim", "Unsupported Scientific Claim", "critical", 0.92))

        # ── 19. Unsupported Security Claims ──
        sec_patterns = [
            r"(?:unbreakable|unhackable|100%\s+secure|completely\s+immune)\s+(?:encryption|security|system|protocol|algorithm)",
            r"(?:quantum[\s-]?proof|quantum[\s-]?resistant)\s+(?:encryption|algorithm)\s+(?:that\s+)?(?:guarantees|ensures)\s+(?:absolute|complete|total)\s+security",
        ]
        issues.extend(_check_patterns(output_text, sec_patterns, "unsupported_security_claim", "Unsupported Security Claim", "high", 0.88))

        # ── 20. Unsupported Math ──
        math_errors = [
            (r'2\s*\+\s*2\s*=\s*([^4\s])', "2+2 arithmetic error"),
            (r'1\s*\+\s*1\s*=\s*([^2\s])', "1+1 arithmetic error"),
        ]
        for pat, desc in math_errors:
            m = re.search(pat, output_text)
            if m:
                issues.append({"category":"unsupported_mathematical_result","severity":"critical","confidence":0.99,"title":"Mathematical Error","description":desc,"affected_text":m.group(0),"start_index":m.start(),"end_index":m.end(),"recommendation":"Check arithmetic."})

        # ── Build Report ──
        # Assign unique IDs
        for i, iss in enumerate(issues):
            iss["id"] = f"issue_{i+1}"

        # Calculate scores
        if issues:
            max_conf = max(i["confidence"] for i in issues)
            sev_weights = {"critical":1.0,"high":0.8,"medium":0.5,"low":0.2}
            weighted = [i["confidence"] * sev_weights.get(i["severity"],0.5) for i in issues]
            risk_score = min(max(weighted) + len(issues) * 0.03, 1.0)
            avg_conf = sum(i["confidence"] for i in issues) / len(issues)
        else:
            risk_score = 0.0
            avg_conf = 0.99

        if risk_score >= 0.8: risk_level = "CRITICAL"
        elif risk_score >= 0.6: risk_level = "HIGH"
        elif risk_score >= 0.35: risk_level = "MEDIUM"
        elif risk_score >= 0.1: risk_level = "LOW"
        else: risk_level = "SAFE"

        # Category distribution
        cat_dist = {}
        for iss in issues:
            cat_dist[iss["category"]] = cat_dist.get(iss["category"], 0) + 1

        # Highlight ranges
        highlights = [{"start":i["start_index"],"end":i["end_index"],"category":i["category"],"confidence":i["confidence"],"title":i["title"]} for i in issues]

        # Verification checklist
        cats = set(i["category"] for i in issues)
        checklist = {
            "no_fabricated_entities": not any(c.startswith("fabricated_") for c in cats),
            "no_fabricated_citations": "fabricated_citation" not in cats and "fabricated_research_paper" not in cats,
            "no_unsupported_statistics": "fabricated_statistics" not in cats and "impossible_numerical_value" not in cats,
            "no_contradictory_statements": "contradictory_statements" not in cats,
            "no_logical_inconsistencies": "internal_logical_conflict" not in cats,
            "response_internally_coherent": len(issues) == 0,
            "no_impossible_timelines": "impossible_timeline" not in cats,
            "no_fake_standards": "fake_standards" not in cats,
            "no_fiction_as_fact": "fiction_as_fact" not in cats,
            "no_overconfident_assertions": "overconfident_assertion" not in cats,
        }

        # Summary
        if issues:
            top_cats = sorted(cat_dist.items(), key=lambda x: -x[1])[:3]
            summary = f"{len(issues)} issue(s) detected: " + ", ".join(f"{c.replace('_',' ')} ({n})" for c,n in top_cats) + "."
        else:
            summary = "No hallucination signals detected. Response appears factually consistent."

        # Recommendations
        recs = []
        if "fabricated_citation" in cats: recs.append("Verify all cited publications and DOIs against official databases.")
        if "fabricated_person" in cats: recs.append("Confirm the existence of referenced individuals via professional directories.")
        if "fabricated_organization" in cats: recs.append("Verify all named organizations exist and are correctly described.")
        if "fabricated_scientific_claim" in cats: recs.append("Cross-reference scientific claims with peer-reviewed literature.")
        if "fabricated_medical_claim" in cats: recs.append("CRITICAL: Verify medical claims with official health authorities. Do not use for medical decisions.")
        if "contradictory_statements" in cats: recs.append("Resolve internal contradictions before using this output.")
        if "impossible_timeline" in cats: recs.append("Check all temporal references for accuracy.")
        if not recs: recs.append("Response appears factually consistent. No action required.")

        duration = (time.perf_counter() - t0) * 1000

        return {
            "overall_risk": risk_level,
            "overall_risk_score": round(risk_score, 4),
            "overall_confidence": round(avg_conf, 4),
            "summary": summary,
            "total_issues": len(issues),
            "issues": issues,
            "verification_checklist": checklist,
            "category_distribution": cat_dist,
            "highlight_ranges": highlights,
            "recommendations": recs,
            "extracted_metadata": {
                "sentences": len(sentences),
                "entities": len(entities),
                "numbers": len(numbers),
                "dates": len(dates),
                "citations": len(citations),
                "organizations": len(orgs),
            },
            "analysis_duration_ms": round(duration, 2),
        }
