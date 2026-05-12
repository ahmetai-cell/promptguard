import { PATTERNS, HEURISTICS } from "./patterns.js";

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

  const matches = [];
  let maxSeverity = 0;

  // Pattern matching
  for (const { id, pattern, severity, tag } of PATTERNS) {
    if (pattern.test(text)) {
      matches.push(`${id}:${tag}`);
      if (severity > maxSeverity) maxSeverity = severity;
    }
  }

  // Heuristic checks
  for (const h of HEURISTICS) {
    if (h.check(text)) {
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
