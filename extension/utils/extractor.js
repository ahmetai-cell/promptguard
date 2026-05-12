/**
 * Extracts the messages array from a raw request body,
 * supporting OpenAI, Anthropic, and AWS Bedrock formats.
 */

/**
 * @param {string} url  — the request URL
 * @param {string} body — raw JSON string
 * @returns {{ messages: Array, provider: string } | null}
 */
export function extractMessages(url, body) {
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }

  // OpenAI: api.openai.com/v1/chat/completions
  if (url.includes("openai.com") || url.includes("/v1/chat/completions")) {
    if (Array.isArray(parsed.messages)) {
      return { messages: parsed.messages, provider: "openai" };
    }
  }

  // Anthropic: api.anthropic.com/v1/messages
  if (url.includes("anthropic.com") || url.includes("/v1/messages")) {
    if (Array.isArray(parsed.messages)) {
      return { messages: parsed.messages, provider: "anthropic" };
    }
  }

  // AWS Bedrock — Anthropic models on Bedrock
  if (url.includes("bedrock-runtime") || url.includes("bedrock")) {
    // Bedrock wraps the payload differently
    const inner = parsed.body ? safeParseBase64Json(parsed.body) : parsed;
    if (inner && Array.isArray(inner.messages)) {
      return { messages: inner.messages, provider: "bedrock-anthropic" };
    }
    // Bedrock Titan / Jurassic: prompt is a flat string
    if (typeof inner?.inputText === "string") {
      return {
        messages: [{ role: "user", content: inner.inputText }],
        provider: "bedrock-titan",
      };
    }
  }

  // Generic fallback: look for any messages-like array
  if (Array.isArray(parsed.messages)) {
    return { messages: parsed.messages, provider: "generic" };
  }

  // Flat prompt string (older APIs)
  if (typeof parsed.prompt === "string") {
    return {
      messages: [{ role: "user", content: parsed.prompt }],
      provider: "generic-prompt",
    };
  }

  return null;
}

function safeParseBase64Json(str) {
  try {
    return JSON.parse(atob(str));
  } catch {
    return null;
  }
}
