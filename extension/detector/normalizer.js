/**
 * Text normalization before injection analysis.
 *
 * Pipeline:
 *   1. Base64 fragment decode  — "(base64-decode: xxx)" → decoded text
 *   2. NFKC                    — fullwidth, ligatures, superscripts
 *   3. Zero-width / invisible  — ZWSP, ZWNJ, ZWJ, BOM, soft-hyphen
 *   4. Homoglyph substitution  — Cyrillic/Greek/Armenian → ASCII
 *   5. Leet reversal           — "!gn0r3 411 y0ur" → "ignore all your"
 *   6. Whitespace collapse     — ≥2 horizontal spaces → 1
 *
 * Note: spaced-chars ("i g n o r e") detection is handled by H003 heuristic
 * in patterns.js rather than here, because collapsing multi-word spaced
 * sequences (e.g. "s y s t e m p r o m p t") merges word boundaries.
 */

// ─── Homoglyph map ────────────────────────────────────────────────────────────

const CONFUSABLES = new Map([
  // Cyrillic
  ["а","a"],["е","e"],["о","o"],["р","p"],["с","c"],["х","x"],
  ["і","i"],["ј","j"],["ѕ","s"],["ԁ","d"],["ɡ","g"],["ƅ","b"],
  ["у","y"],["т","t"],["В","B"],["М","M"],
  // Greek
  ["ο","o"],["ρ","p"],["ν","v"],["ι","i"],["α","a"],["κ","k"],
  ["ε","e"],["υ","u"],["Α","A"],["Β","B"],["Ε","E"],["Ζ","Z"],
  ["Η","H"],["Ι","I"],["Κ","K"],["Μ","M"],["Ν","N"],["Ο","O"],
  ["Ρ","P"],["Τ","T"],["Υ","Y"],["Χ","X"],
  // Armenian
  ["Օ","P"],["ո","o"],
]);

const ZW_RE = /[​-‍﻿­⁠᠎͏]/g;

// ─── Base64 fragment decoder ──────────────────────────────────────────────────
// Strips "(base64-decode: xxx)" hints, replacing them with decoded text.

const B64_FRAG_RE = /\(?\s*base64[- ]?(?:decod[e|ed]?|encoded?)?[:\s]+([A-Za-z0-9+/]{4,}={0,2})\s*\)?/gi;

function _decodeBase64Fragments(text) {
  return text.replace(B64_FRAG_RE, (_, encoded) => {
    try { return " " + atob(encoded) + " "; } catch { return " " + encoded + " "; }
  });
}

// ─── Leet reversal ───────────────────────────────────────────────────────────
// "!gn0r3 411 y0ur pr3v!0u5 !n57ruc7!0n5" → "ignore all your previous instructions"
//
// Maps: 1→l  4→a  0→o  3→e  7→t  5→s  !→i  @→a  $→s  |→l
//
// "1" maps to "l" (visual lookalike). A second pass (_fixInjectionLeet) handles
// the ambiguity where 1 is used as "i" in injection keywords ("1gnore" → "ignore").

const LEET_MAP = {
  "4":"a","@":"a","3":"e","1":"l","|":"l","!":"i",
  "0":"o","7":"t","+":"t","5":"s","$":"s",
};

// Word-level injection fix: "lgnore" (from 1→l) → "ignore" etc.
// Only exact whole-word matches to avoid over-substitution.
const LEET_INJECTION_FIX = new Map([
  ["lgnore","ignore"],["lgnoring","ignoring"],["lgnored","ignored"],
  ["lnstructions","instructions"],["lnstruction","instruction"],["lnstruct","instruct"],
  ["lnject","inject"],["lnjection","injection"],
  ["lnitial","initial"],["lnput","input"],
]);
const LEET_CHARS = new Set(Object.keys(LEET_MAP));

function _applyLeet(chars) {
  return chars.map((c) => LEET_MAP[c] ?? c).join("");
}

function _reverseLeet(text) {
  return text.replace(/\S+/g, (token) => {
    const chars = [...token];
    const letterCount = chars.filter((c) => /[a-zA-Z]/.test(c)).length;
    const leetCount   = chars.filter((c) => LEET_CHARS.has(c)).length;

    // Any token with at least one letter AND at least one leet char
    if (letterCount > 0 && leetCount >= 1) return _applyLeet(chars);

    // Pure-leet token (no real letters) that converts to an all-alpha word
    if (letterCount === 0 && leetCount === chars.length && chars.length >= 2) {
      const converted = _applyLeet(chars);
      if (/^[a-z]+$/i.test(converted)) return converted;
    }

    return token;
  });
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function normalizeText(text) {
  if (!text || typeof text !== "string") return text;

  let t = _decodeBase64Fragments(text);  // 1. base64
  t = t.normalize("NFKC");              // 2. NFKC
  t = t.replace(ZW_RE, "");             // 3. zero-width

  const chars = [...t];                  // 4. homoglyphs
  for (let i = 0; i < chars.length; i++) {
    const sub = CONFUSABLES.get(chars[i]);
    if (sub !== undefined) chars[i] = sub;
  }
  t = chars.join("");

  t = _reverseLeet(t);                  // 5. leet
  // 5b. injection keyword fix: "lgnore" → "ignore" (1→l ambiguity)
  t = t.replace(/\b[a-z]+\b/gi, (w) => LEET_INJECTION_FIX.get(w.toLowerCase()) ?? w);
  t = t.replace(/[^\S\n]{2,}/g, " ");  // 6. whitespace

  return t;
}

export { _reverseLeet, _decodeBase64Fragments };
