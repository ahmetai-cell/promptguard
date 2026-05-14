"""
Text normalization — Python mirror of extension/detector/normalizer.js.

Applied to every prompt before it reaches the DeBERTa classifier and
embedding detector. Same four steps as the JS version so L1 and L2
operate on comparably cleaned text.
"""
from __future__ import annotations

import re
import unicodedata

# Cyrillic / Greek / Armenian → ASCII homoglyph map
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "ƅ": "b",
    "у": "y", "т": "t", "В": "B", "М": "M",
    # Greek
    "ο": "o", "ρ": "p", "ν": "v", "ι": "i",
    "α": "a", "κ": "k", "ε": "e", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
    # Armenian
    "Օ": "P", "ո": "o",
}

# Zero-width and invisible characters
_ZW_RE = re.compile(r"[​-‍﻿­⁠᠎͏]")

# Horizontal whitespace collapse (preserve newlines)
_HSPACE_RE = re.compile(r"[^\S\n]{2,}")


def normalize(text: str) -> str:
    """
    Normalize text before injection classification.

    Steps:
      1. NFKC — fullwidth → ASCII, ligatures, fractions, superscripts
      2. Strip zero-width / invisible characters
      3. Homoglyph substitution (Cyrillic/Greek/Armenian → ASCII)
      4. Collapse runs of horizontal whitespace
    """
    if not text:
        return text

    # 1. NFKC
    text = unicodedata.normalize("NFKC", text)

    # 2. Strip zero-width chars
    text = _ZW_RE.sub("", text)

    # 3. Homoglyph substitution
    text = "".join(_CONFUSABLES.get(ch, ch) for ch in text)

    # 4. Collapse horizontal whitespace
    text = _HSPACE_RE.sub(" ", text)

    return text
