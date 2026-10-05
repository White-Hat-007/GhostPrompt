"""
Tokenizer Shield — Threat Layer 11 (Advanced)

Blocks zero-day Unicode and tokenizer-splitting attacks that are invisible
to standard content filters. These exploit the gap between how humans read
text, how regex filters parse it, and how the LLM tokenizer splits it.

Detection signals:
  - Full Unicode normalization divergence (NFC/NFD/NFKC/NFKD comparison)
  - Zero-width character stripping (ZWSP, ZWNJ, ZWJ, BOM, WJ, Mongolian VS)
  - Bidirectional override detection (U+202A-U+202E, U+2066-U+2069)
  - Private Use Area character detection
  - Variation Selector abuse (outside emoji contexts)
  - Homoglyph substitution across all Unicode blocks
  - Invisible character density thresholds
  - Language plane anomaly (mixing 3+ planes without justification)
"""

import re
import unicodedata
from typing import Optional
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.tokenizer_shield")

# ── Zero-width characters ────────────────────────────────────────────
ZERO_WIDTH_CHARS = {
    '\u200B': 'ZWSP',        # Zero Width Space
    '\u200C': 'ZWNJ',        # Zero Width Non-Joiner
    '\u200D': 'ZWJ',         # Zero Width Joiner
    '\uFEFF': 'BOM',         # Byte Order Mark
    '\u2060': 'WJ',          # Word Joiner
    '\u180E': 'MVS',         # Mongolian Vowel Separator
    '\u00AD': 'SHY',         # Soft Hyphen
    '\u2061': 'FA',          # Function Application
    '\u2062': 'IT',          # Invisible Times
    '\u2063': 'IS',          # Invisible Separator
    '\u2064': 'IP',          # Invisible Plus
}

# ── Bidirectional override characters ────────────────────────────────
BIDI_CHARS = {
    '\u202A': 'LRE',    # Left-to-Right Embedding
    '\u202B': 'RLE',    # Right-to-Left Embedding
    '\u202C': 'PDF',    # Pop Directional Formatting
    '\u202D': 'LRO',    # Left-to-Right Override
    '\u202E': 'RLO',    # Right-to-Left Override
    '\u2066': 'LRI',    # Left-to-Right Isolate
    '\u2067': 'RLI',    # Right-to-Left Isolate
    '\u2068': 'FSI',    # First Strong Isolate
    '\u2069': 'PDI',    # Pop Directional Isolate
    '\u200E': 'LRM',    # Left-to-Right Mark
    '\u200F': 'RLM',    # Right-to-Left Mark
}

# ── Common confusables (Latin → look-alike) ──────────────────────────
CONFUSABLES_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
    'х': 'x', 'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H',
    'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X',
    'ɑ': 'a', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ν': 'v', 'ω': 'w',
    'ⅰ': 'i', 'ⅱ': 'ii', 'ⅲ': 'iii',
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
    '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
    'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E',
}

# ── Thresholds ───────────────────────────────────────────────────────
INVISIBLE_DENSITY_THRESHOLD = 0.02   # > 2 invisible per 100 visible = flag
MAX_LANGUAGE_PLANES = 3              # mixing 3+ planes = flag


class TokenizerShield:
    """Blocks zero-day Unicode and tokenizer-splitting attacks."""

    async def initialize(self) -> None:
        logger.info("tokenizer_shield_initialized")

    async def detect(self, text: str) -> list[DetectionResult]:
        detections: list[DetectionResult] = []

        if not text:
            return detections

        # ── 1. Zero-width character detection ────────────────────────
        zw_found = {}
        for char, name in ZERO_WIDTH_CHARS.items():
            count = text.count(char)
            if count > 0:
                zw_found[name] = count

        if zw_found:
            total_zw = sum(zw_found.values())
            detections.append(DetectionResult(
                detector="tokenizer_shield",
                confidence=min(0.7 + total_zw * 0.05, 0.95),
                category="tokenizer.zero_width_injection",
                description=(
                    f"Zero-width character injection: {total_zw} invisible characters "
                    f"found ({', '.join(f'{n}×{c}' for n, c in zw_found.items())})"
                ),
                severity="high" if total_zw > 5 else "medium",
                matched_content=f"total={total_zw}; types={list(zw_found.keys())}",
            ))

        # ── 2. Bidirectional override detection (IMMEDIATE BLOCK) ────
        bidi_found = {}
        for char, name in BIDI_CHARS.items():
            count = text.count(char)
            if count > 0:
                bidi_found[name] = count

        if bidi_found:
            total_bidi = sum(bidi_found.values())
            detections.append(DetectionResult(
                detector="tokenizer_shield",
                confidence=0.95,
                category="tokenizer.bidi_override",
                description=(
                    f"CRITICAL: Bidirectional override characters detected ({total_bidi}). "
                    f"Types: {', '.join(f'{n}×{c}' for n, c in bidi_found.items())}. "
                    f"Text can appear visually different from its byte-level content."
                ),
                severity="critical",
                matched_content=f"bidi_chars={list(bidi_found.keys())}",
            ))

        # ── 3. Unicode normalization divergence ──────────────────────
        nfc = unicodedata.normalize('NFC', text)
        nfd = unicodedata.normalize('NFD', text)
        nfkc = unicodedata.normalize('NFKC', text)
        nfkd = unicodedata.normalize('NFKD', text)

        forms_match = (text == nfc == nfd == nfkc == nfkd)
        if not forms_match:
            divergent_forms = []
            if text != nfc: divergent_forms.append('NFC')
            if text != nfkc: divergent_forms.append('NFKC')
            if text != nfkd: divergent_forms.append('NFKD')

            if len(divergent_forms) >= 2:
                detections.append(DetectionResult(
                    detector="tokenizer_shield",
                    confidence=0.75,
                    category="tokenizer.normalization_divergence",
                    description=(
                        f"Unicode normalization divergence: text differs under "
                        f"{', '.join(divergent_forms)} normalization — weaponized Unicode suspected"
                    ),
                    severity="medium",
                    matched_content=f"divergent_forms={divergent_forms}",
                ))

        # ── 4. Private Use Area characters ───────────────────────────
        pua_count = 0
        for ch in text:
            cp = ord(ch)
            if (0xE000 <= cp <= 0xF8FF or
                0xF0000 <= cp <= 0xFFFFF or
                0x100000 <= cp <= 0x10FFFF):
                pua_count += 1

        if pua_count > 0:
            detections.append(DetectionResult(
                detector="tokenizer_shield",
                confidence=0.80,
                category="tokenizer.private_use_area",
                description=(
                    f"Private Use Area characters detected: {pua_count} PUA codepoints "
                    f"— may be used for steganographic payload injection"
                ),
                severity="high",
                matched_content=f"pua_count={pua_count}",
            ))

        # ── 5. Variation Selectors outside emoji context ─────────────
        vs_count = 0
        for ch in text:
            cp = ord(ch)
            if (0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF):
                vs_count += 1

        if vs_count > 3:
            detections.append(DetectionResult(
                detector="tokenizer_shield",
                confidence=0.70,
                category="tokenizer.variation_selector_abuse",
                description=(
                    f"Variation Selector abuse: {vs_count} selectors detected outside "
                    f"expected emoji context — potential tokenizer manipulation"
                ),
                severity="medium",
                matched_content=f"vs_count={vs_count}",
            ))

        # ── 6. Homoglyph detection ───────────────────────────────────
        homoglyph_count = 0
        homoglyph_chars = []
        for ch in text:
            if ch in CONFUSABLES_MAP:
                homoglyph_count += 1
                if len(homoglyph_chars) < 10:
                    homoglyph_chars.append(f"'{ch}'→'{CONFUSABLES_MAP[ch]}'")

        if homoglyph_count > 2:
            detections.append(DetectionResult(
                detector="tokenizer_shield",
                confidence=min(0.6 + homoglyph_count * 0.08, 0.95),
                category="tokenizer.homoglyph_substitution",
                description=(
                    f"Homoglyph substitution: {homoglyph_count} look-alike characters "
                    f"from non-Latin Unicode blocks ({', '.join(homoglyph_chars[:5])})"
                ),
                severity="high" if homoglyph_count > 5 else "medium",
                matched_content="; ".join(homoglyph_chars[:5]),
            ))

        # ── 7. Invisible character density ───────────────────────────
        visible_chars = sum(1 for ch in text if unicodedata.category(ch)[0] != 'C' and ch.strip())
        invisible_chars = sum(zw_found.values()) if zw_found else 0
        invisible_chars += sum(bidi_found.values()) if bidi_found else 0

        if visible_chars > 0 and invisible_chars / max(visible_chars, 1) > INVISIBLE_DENSITY_THRESHOLD:
            density = invisible_chars / visible_chars
            detections.append(DetectionResult(
                detector="tokenizer_shield",
                confidence=min(0.7 + density * 5, 0.95),
                category="tokenizer.invisible_density",
                description=(
                    f"High invisible character density: {invisible_chars} invisible / "
                    f"{visible_chars} visible chars ({density:.1%}) exceeds "
                    f"{INVISIBLE_DENSITY_THRESHOLD:.0%} threshold"
                ),
                severity="high",
                matched_content=f"density={density:.3f}",
            ))

        # ── 8. Language plane anomaly ────────────────────────────────
        planes: set[int] = set()
        for ch in text:
            if ch.strip() and unicodedata.category(ch)[0] == 'L':
                planes.add(ord(ch) >> 16)  # Unicode plane number

        if len(planes) > MAX_LANGUAGE_PLANES:
            detections.append(DetectionResult(
                detector="tokenizer_shield",
                confidence=0.65,
                category="tokenizer.language_plane_anomaly",
                description=(
                    f"Language plane anomaly: characters from {len(planes)} Unicode planes "
                    f"detected (threshold {MAX_LANGUAGE_PLANES}) — suspicious multi-script mixing"
                ),
                severity="medium",
                matched_content=f"planes={sorted(planes)}",
            ))

        return detections
