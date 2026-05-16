import { PATTERNS, HEURISTICS } from "./patterns.js";
import { normalizeText } from "./normalizer.js";

const BLOCK_THRESHOLD = 0.75;
const WARN_THRESHOLD  = 0.45;

/**
 * @typedef {{ verdict: "BLOCK"|"WARN"|"ALLOW", score: number, matches: string[] }} AnalysisResult
 */

/**
 * Analyze a single text string for prompt injection signals.
 * @param {string} text
 * @returns {AnalysisResult}
 */
export function analyzeText(text) {
  if (!text || typeof text !== "string") {
    return { verdict: "ALLOW", score: 0, matches: [] };
  }

  // Normalize before pattern matching so homoglyphs / zero-width tricks don't evade.
  // Non-Latin patterns (Russian, Arabic, etc.) run on raw text too so normalization
  // doesn't destroy the language-specific characters.
  const normalized = normalizeText(text);

  const matches = [];
  let maxSeverity = 0;
  const seen = new Set();

  const testBoth = (id, pattern, severity, tag) => {
    if (seen.has(id)) return;
    if (pattern.test(normalized) || pattern.test(text)) {
      seen.add(id);
      matches.push(`${id}:${tag}`);
      if (severity > maxSeverity) maxSeverity = severity;
    }
  };

  // Pattern matching (normalized + raw for non-ASCII patterns)
  for (const { id, pattern, severity, tag } of PATTERNS) {
    testBoth(id, pattern, severity, tag);
  }

  // Heuristic checks:
  // H001/H002/H005 need raw text (they detect chars stripped by normalizer).
  // All others run on normalized text.
  const RAW_HEURISTICS = new Set(["H001","H002","H005"]);
  for (const h of HEURISTICS) {
    if (seen.has(h.id)) continue;
    const src = RAW_HEURISTICS.has(h.id) ? text : normalized;
    if (h.check(src)) {
      seen.add(h.id);
      matches.push(`${h.id}:${h.name}`);
      if (h.severity > maxSeverity) maxSeverity = h.severity;
    }
  }

  // Compound scoring: multiple matches push score up even when individual severities are moderate
  let score = maxSeverity;
  if (matches.length > 1) {
    const extra = matches.length * 0.04;
    score = Math.min(1.0, score + extra);
  }

  const verdict =
    score >= BLOCK_THRESHOLD ? "BLOCK" :
    score >= WARN_THRESHOLD  ? "WARN"  :
                               "ALLOW";

  return { verdict, score: parseFloat(score.toFixed(3)), matches };
}

/**
 * Analyze an extracted messages array (OpenAI / Anthropic format).
 * Returns the worst result found across all user-role messages.
 * @param {Array<{role: string, content: string|Array}>} messages
 * @returns {AnalysisResult}
 */
export function analyzeMessages(messages) {
  if (!Array.isArray(messages)) return { verdict: "ALLOW", score: 0, matches: [] };

  let worst = { verdict: "ALLOW", score: 0, matches: [] };

  for (const msg of messages) {
    if (msg.role !== "user") continue;

    const texts = extractTextFromContent(msg.content);
    for (const t of texts) {
      const result = analyzeText(t);
      if (result.score > worst.score) worst = result;
    }
  }

  return worst;
}

function extractTextFromContent(content) {
  if (typeof content === "string") return [content];
  if (Array.isArray(content)) {
    return content
      .filter((c) => c.type === "text" && typeof c.text === "string")
      .map((c) => c.text);
  }
  return [];
}
