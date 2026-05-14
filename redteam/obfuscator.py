"""
Obfuscation techniques applied to base attack payloads.

Each function takes a plain-text attack string and returns an obfuscated
variant that a naive regex/heuristic engine might miss.
"""
from __future__ import annotations

import base64
import random
import re

# ─── Techniques ───────────────────────────────────────────────────────────────

def zwsp(text: str) -> str:
    """Insert zero-width spaces between every character."""
    return "​".join(text)


def homoglyph(text: str) -> str:
    """Replace common ASCII letters with Cyrillic lookalikes."""
    _MAP = {
        "a": "а", "e": "е", "o": "о", "p": "р",
        "c": "с", "x": "х", "i": "і", "s": "ѕ",
    }
    return "".join(_MAP.get(c, c) for c in text)


def leet(text: str) -> str:
    """Apply l33tspeak substitution."""
    _MAP = {"a": "4", "e": "3", "l": "1", "o": "0", "t": "7", "s": "5", "i": "!"}
    return "".join(_MAP.get(c.lower(), c) for c in text)


def case_scramble(text: str) -> str:
    """Randomly alternate upper/lower case for each character."""
    rng = random.Random(42)  # deterministic for reproducibility
    return "".join(c.upper() if rng.random() > 0.5 else c.lower() for c in text)


def spaced_chars(text: str) -> str:
    """Insert a space between every character of keywords longer than 4 chars."""
    def space_word(w: str) -> str:
        return " ".join(w) if len(w) > 4 else w
    return " ".join(space_word(w) for w in text.split())


def base64_suffix(text: str) -> str:
    """Encode the last word in base64 with a decode hint."""
    words = text.split()
    if len(words) < 2:
        return text
    tail = words[-1]
    encoded = base64.b64encode(tail.encode()).decode()
    return " ".join(words[:-1]) + f" (base64-decode: {encoded})"


def markdown_hidden(text: str) -> str:
    """Wrap payload in a markdown comment (survives naive text extraction)."""
    return f"<!-- {text} -->"


def unicode_fullwidth(text: str) -> str:
    """Convert ASCII letters/digits to their Unicode fullwidth equivalents."""
    result = []
    for ch in text:
        if "A" <= ch <= "Z":
            result.append(chr(ord(ch) - ord("A") + 0xFF21))
        elif "a" <= ch <= "z":
            result.append(chr(ord(ch) - ord("a") + 0xFF41))
        elif "0" <= ch <= "9":
            result.append(chr(ord(ch) - ord("0") + 0xFF10))
        else:
            result.append(ch)
    return "".join(result)


def soft_hyphen(text: str) -> str:
    """Insert soft hyphens (U+00AD) inside each word."""
    return re.sub(r"(?<=\w)(?=\w)", "­", text)


# ─── Registry ─────────────────────────────────────────────────────────────────

ALL_TECHNIQUES: list[tuple[str, callable]] = [
    ("zwsp",             zwsp),
    ("homoglyph",        homoglyph),
    ("leet",             leet),
    ("case_scramble",    case_scramble),
    ("spaced_chars",     spaced_chars),
    ("base64_suffix",    base64_suffix),
    ("markdown_hidden",  markdown_hidden),
    ("unicode_fullwidth", unicode_fullwidth),
    ("soft_hyphen",      soft_hyphen),
]

TECHNIQUE_NAMES: list[str] = [name for name, _ in ALL_TECHNIQUES]
