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

/**
 * Extract a standard messages array from a WebSocket `send()` payload.
 * Handles:
 *   - OpenAI Realtime API  (type: "conversation.item.create")
 *   - ChatGPT web protocol (action: "next", messages: [...])
 *   - Generic JSON         (messages / text / content / prompt)
 *   - Binary frames        → returns null (can't parse)
 *
 * @param {string | ArrayBuffer | Blob} data — raw ws.send() argument
 * @returns {Array<{role: string, content: string}> | null}
 */
export function extractWsMessages(data) {
  if (typeof data !== "string") return null;   // binary frames — skip

  let msg;
  try { msg = JSON.parse(data); } catch { return null; }

  // OpenAI Realtime API  (wss://api.openai.com/v1/realtime)
  if (msg.type === "conversation.item.create") {
    const text = (msg.item?.content ?? [])
      .map((p) => p.text ?? p.transcript ?? "")
      .filter(Boolean)
      .join("\n");
    return text ? [{ role: "user", content: text }] : null;
  }

  // ChatGPT web  (action:"next" protocol over wss://chat.openai.com)
  if (msg.action === "next" && Array.isArray(msg.messages)) {
    const out = msg.messages
      .filter((m) => (m.author?.role ?? m.role) === "user")
      .map((m) => {
        const c = m.content;
        if (typeof c === "string") return { role: "user", content: c };
        if (c?.content_type === "text" && Array.isArray(c.parts))
          return { role: "user", content: c.parts.join("\n") };
        return null;
      })
      .filter(Boolean);
    return out.length ? out : null;
  }

  // Standard messages array (many custom proxies)
  if (Array.isArray(msg.messages)) return msg.messages;

  // Flat text fields
  const flat = msg.text ?? msg.content ?? msg.message ?? msg.prompt ?? msg.query ?? null;
  if (typeof flat === "string" && flat.trim()) return [{ role: "user", content: flat }];

  return null;
}
