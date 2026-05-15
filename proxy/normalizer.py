"""
Text normalization — Python mirror of extension/detector/normalizer.js.

Pipeline (same order as JS):
  1. Base64 fragment decode  — explicit "(base64-decode: xxx)" hints
  2. NFKC                    — fullwidth, ligatures, superscripts
  3. Zero-width strip        — ZWSP, ZWNJ, ZWJ, BOM, soft-hyphen
  4. Homoglyph substitution  — Cyrillic/Greek/Armenian → ASCII
  5. Leet reversal           — "!gn0r3 411" → "ignore all"
  6. Whitespace collapse     — ≥2 horizontal spaces → 1

Note: spaced-chars ("i g n o r e") is handled by H003 heuristic, not here.
"""
from __future__ import annotations

import base64
import re
import unicodedata

# ─── Homoglyph map ────────────────────────────────────────────────────────────

_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x",
    "і":"i","ј":"j","ѕ":"s","ԁ":"d","ɡ":"g","ƅ":"b",
    "у":"y","т":"t","В":"B","М":"M",
    # Greek
    "ο":"o","ρ":"p","ν":"v","ι":"i","α":"a","κ":"k",
    "ε":"e","υ":"u","Α":"A","Β":"B","Ε":"E","Ζ":"Z",
    "Η":"H","Ι":"I","Κ":"K","Μ":"M","Ν":"N","Ο":"O",
    "Ρ":"P","Τ":"T","Υ":"Y","Χ":"X",
    # Armenian
    "Օ":"P","ո":"o",
}

# ─── Regex constants ──────────────────────────────────────────────────────────

_ZW_RE     = re.compile(r"[​-‍﻿­⁠᠎͏]")
_HSPACE_RE = re.compile(r"[^\S\n]{2,}")
_B64_RE    = re.compile(
    r"\(?\s*base64[- ]?(?:decod[e|ed]?|encoded?)?[:\s]+([A-Za-z0-9+/]{4,}={0,2})\s*\)?",
    re.IGNORECASE,
)
# 3+ (single word-char + space) followed by one word-char
_SPACED_RE = re.compile(r"(?:\b\w ){3,}\w\b")

# ─── Leet map ─────────────────────────────────────────────────────────────────

_LEET_MAP: dict[str, str] = {
    "4":"a", "@":"a",
    "3":"e",
    "1":"l", "|":"l",
    "!":"i",
    "0":"o",
    "7":"t", "+":"t",
    "5":"s", "$":"s",
}
_LEET_CHARS = frozenset(_LEET_MAP)


# ─── Step functions ───────────────────────────────────────────────────────────

def _decode_base64_fragments(text: str) -> str:
    def _replace(m: re.Match) -> str:
        try:
            return base64.b64decode(m.group(1) + "==").decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            return m.group(0)
    return _B64_RE.sub(_replace, text)


def _collapse_spaced_chars(text: str) -> str:
    return _SPACED_RE.sub(lambda m: m.group(0).replace(" ", ""), text)


def _apply_leet(chars: list[str]) -> str:
    return "".join(_LEET_MAP.get(c, c) for c in chars)


def _reverse_leet(text: str) -> str:
    def _token(tok: str) -> str:
        chars = list(tok)
        letter_count = sum(1 for c in chars if c.isalpha())
        leet_count   = sum(1 for c in chars if c in _LEET_CHARS)

        # Case 1: mixed — real letters + ≥1 leet char
        if letter_count > 0 and leet_count >= 1:
            return _apply_leet(chars)

        # Case 2: starts with leet char + has ≥1 real letter
        if leet_count >= 1 and letter_count >= 1 and chars[0] in _LEET_CHARS:
            return _apply_leet(chars)

        # Case 3: pure-leet token → all-alpha after conversion
        if letter_count == 0 and leet_count == len(chars) >= 2:
            converted = _apply_leet(chars)
            if converted.isalpha():
                return converted

        return tok

    return re.sub(r"\S+", lambda m: _token(m.group(0)), text)


# ─── Public API ───────────────────────────────────────────────────────────────

def normalize(text: str) -> str:
    """
    Normalize text before injection classification.
    Returns input unchanged if falsy or not a string.
    """
    if not text:
        return text

    text = _decode_base64_fragments(text)          # 1. base64
    text = unicodedata.normalize("NFKC", text)     # 2. NFKC
    text = _ZW_RE.sub("", text)                    # 3. zero-width
    text = "".join(_CONFUSABLES.get(c, c) for c in text)  # 4. homoglyphs
    text = _reverse_leet(text)                     # 5. leet
    text = _HSPACE_RE.sub(" ", text)               # 6. whitespace

    return text
