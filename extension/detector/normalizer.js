/**
 * Text normalization before injection analysis.
 *
 * Strips obfuscation layers that regex and heuristics would otherwise miss:
 *   1. NFKC  — collapses fullwidth, ligatures, superscripts, fractions
 *   2. Zero-width / invisible chars  — ZWSP, ZWNJ, ZWJ, BOM, soft-hyphen
 *   3. Homoglyph substitution  — Cyrillic/Greek/Armenian → ASCII lookalikes
 *   4. Horizontal whitespace collapse  — ≥2 spaces → 1 (newlines preserved)
 */

// Top Cyrillic, Greek, and Armenian chars that visually resemble ASCII letters.
// Covers the most common homoglyph attacks; not exhaustive by design.
const CONFUSABLES = new Map([
  // Cyrillic
  ["а", "a"], ["е", "e"], ["о", "o"], ["р", "p"],
  ["с", "c"], ["х", "x"], ["і", "i"], ["ј", "j"],
  ["ѕ", "s"], ["ԁ", "d"], ["ɡ", "g"], ["ƅ", "b"],
  ["у", "y"], ["т", "t"], ["В", "B"], ["М", "M"],
  // Greek
  ["ο", "o"], ["ρ", "p"], ["ν", "v"], ["ι", "i"],
  ["α", "a"], ["κ", "k"], ["ε", "e"], ["υ", "u"],
  ["Α", "A"], ["Β", "B"], ["Ε", "E"], ["Ζ", "Z"],
  ["Η", "H"], ["Ι", "I"], ["Κ", "K"], ["Μ", "M"],
  ["Ν", "N"], ["Ο", "O"], ["Ρ", "P"], ["Τ", "T"],
  ["Υ", "Y"], ["Χ", "X"],
  // Armenian
  ["Օ", "P"], ["ո", "o"],
  // Mathematical bold/italic variants (e.g., 𝒊𝒈𝒏𝒐𝒓𝒆)
  // NFKC handles most of these, but a few slip through
]);

// Zero-width and invisible characters
const ZW_RE = /[​-‍﻿­⁠᠎͏]/g;

/**
 * Normalize text before injection analysis.
 *
 * @param {string} text
 * @returns {string}
 */
export function normalizeText(text) {
  if (!text || typeof text !== "string") return text;

  // 1. NFKC: fullwidth → ASCII, ligatures, fractions, superscripts
  let t = text.normalize("NFKC");

  // 2. Strip zero-width / invisible characters
  t = t.replace(ZW_RE, "");

  // 3. Homoglyph substitution
  const chars = [...t];        // spread preserves astral-plane code points
  for (let i = 0; i < chars.length; i++) {
    const sub = CONFUSABLES.get(chars[i]);
    if (sub !== undefined) chars[i] = sub;
  }
  t = chars.join("");

  // 4. Collapse runs of horizontal whitespace (tabs, non-breaking spaces, etc.)
  t = t.replace(/[^\S\n]{2,}/g, " ");

  return t;
}
