import base64
import codecs
import re
import unicodedata
import urllib.parse

from app.core.logging import get_logger

logger = get_logger("firewall.normalizer")

# Sensitive words for acrostic/reversed detection
_SENSITIVE_WORDS = {
    "ignore", "bypass", "override", "jailbreak", "hack", "inject", "exploit",
    "malware", "password", "secret", "admin", "system", "prompt", "instruction",
    "execute", "dangerous", "illegal", "weapon", "bomb", "kill", "virus",
    "ransomware", "trojan", "phishing", "backdoor", "keylogger", "rootkit",
    "delete", "destroy", "shell", "sudo", "drop", "purge",
}

class Normalizer:
    """
    Layer-1 Normalizer Engine.
    Intercepts the raw prompt and "flattens" it into a normalized string
    before pattern matching runs. Decodes Base64, Hex, URL, ROT13,
    strips zero-width chars, markdown code blocks, and applies NFKC normalization.
    Also detects acrostics and reversed words.
    """

    def __init__(self):
        # Base64 with minimum length to avoid false positives on random strings
        self._base64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
        self._hex_x_pattern = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
        self._hex_0x_pattern = re.compile(r"(?:0x[0-9a-fA-F]{2}\s*)+")
        self._url_pattern = re.compile(r"(?:%[0-9a-fA-F]{2})+")
        self._zero_width_pattern = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]+")
        self._rot13_indicator = re.compile(r"(rot13|caesar|rot-13|rot_13)", re.IGNORECASE)
        self._markdown_code_block = re.compile(r"```[\w]*\n(.*?)```", re.DOTALL)

    async def normalize(self, text: str) -> tuple[str, list[str]]:
        """
        Normalizes the input text and returns (normalized_text, evasion_flags).
        """
        evasion_flags = []
        original_text = text

        # 1. Zero-width character stripping
        if self._zero_width_pattern.search(text):
            text = self._zero_width_pattern.sub("", text)
            evasion_flags.append("zero_width_stripped")

        # 2. NFKC Normalization (handles homoglyphs like Cyrillic 'а' or full-width chars)
        normalized = unicodedata.normalize("NFKC", text)
        if normalized != text:
            text = normalized
            evasion_flags.append("unicode_normalized")

        # 2.5 Slang/shorthand normalization (ur → your, u → you, etc.)
        _slang_map = {
            r'\bur\b': 'your', r'\bu\b': 'you', r'\bpls\b': 'please',
            r'\bplz\b': 'please', r'\bwut\b': 'what', r'\bwat\b': 'what',
            r'\bteh\b': 'the', r'\bda\b': 'the', r'\bgimme\b': 'give me',
            r'\bkno\b': 'know', r'\byr\b': 'your', r'\bshud\b': 'should',
        }
        _orig = text
        for pat, repl in _slang_map.items():
            text = re.sub(pat, repl, text, flags=re.IGNORECASE)
        if text != _orig:
            evasion_flags.append("slang_normalized")

        # 3. URL Decoding
        if self._url_pattern.search(text):
            text = urllib.parse.unquote(text)
            evasion_flags.append("url_decoded")

        # 4. Hex Decoding (\xHH)
        def decode_hex_x(match):
            try:
                hex_str = match.group(0).replace("\\x", "")
                return bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
            except Exception:
                return match.group(0)

        if self._hex_x_pattern.search(text):
            text = self._hex_x_pattern.sub(decode_hex_x, text)
            evasion_flags.append("hex_x_decoded")

        # 5. Hex Decoding (0xHH)
        def decode_hex_0x(match):
            try:
                hex_str = match.group(0).replace("0x", "").replace(" ", "")
                return bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
            except Exception:
                return match.group(0)

        if self._hex_0x_pattern.search(text):
            text = self._hex_0x_pattern.sub(decode_hex_0x, text)
            evasion_flags.append("hex_0x_decoded")

        # 6. Base64 Decoding (only decode segments that are valid utf-8)
        def decode_base64(match):
            try:
                b64_str = match.group(0)
                decoded_bytes = base64.b64decode(b64_str)
                decoded_str = decoded_bytes.decode("utf-8")
                if any(c.isalpha() for c in decoded_str):
                    return decoded_str
            except Exception:
                pass
            return match.group(0)

        if self._base64_pattern.search(text):
            new_text = self._base64_pattern.sub(decode_base64, text)
            if new_text != text:
                text = new_text
                evasion_flags.append("base64_decoded")

        # 7. RTL Override reversal
        rtl_override = "\u202E"
        if rtl_override in original_text:
            text = text.replace(rtl_override, "")
            text = text[::-1]
            evasion_flags.append("rtl_reversed")

        # 8. ROT13 Decoding — if ROT13 indicator is present, decode adjacent text
        if self._rot13_indicator.search(text):
            rot13_decoded = codecs.decode(text, "rot_13")
            rot13_lower = rot13_decoded.lower()
            if any(w in rot13_lower for w in _SENSITIVE_WORDS):
                text = text + " [ROT13_DECODED] " + rot13_decoded
                evasion_flags.append("rot13_decoded")

        # 9. Markdown Code Block Extraction — strip code blocks and expose content
        code_blocks = self._markdown_code_block.findall(text)
        if code_blocks:
            for block in code_blocks:
                block_lower = block.lower()
                if any(w in block_lower for w in _SENSITIVE_WORDS):
                    text = text + " [CODE_BLOCK] " + block
                    evasion_flags.append("markdown_code_extracted")
                    break

        # 10. Acrostic Detection — check first letter of each line/sentence
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        if len(lines) >= 4:
            acrostic = "".join(l[0].lower() for l in lines if l)
            for word in _SENSITIVE_WORDS:
                if word in acrostic and len(word) >= 4:
                    text = text + " [ACROSTIC_DETECTED] " + acrostic
                    evasion_flags.append("acrostic_detected")
                    break

        # 11. Reversed Word Detection — check if any word reversed spells a sensitive term
        words = re.findall(r"\b[a-zA-Z]{4,}\b", text)
        reversed_hits = []
        for word in words:
            reversed_word = word[::-1].lower()
            if reversed_word in _SENSITIVE_WORDS and word.lower() not in _SENSITIVE_WORDS:
                reversed_hits.append(f"{word}->{reversed_word}")
        if reversed_hits:
            text = text + " [REVERSED] " + " ".join(reversed_hits)
            evasion_flags.append("reversed_word_detected")

        return text, evasion_flags

normalizer = Normalizer()
