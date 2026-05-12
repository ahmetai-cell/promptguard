import { describe, it, expect } from "vitest";
import { extractMessages } from "../extension/utils/extractor.js";

// ─── OpenAI format ────────────────────────────────────────────────────────────

describe("OpenAI format — /v1/chat/completions", () => {
  const url = "https://api.openai.com/v1/chat/completions";

  it("extracts messages array", () => {
    const body = JSON.stringify({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are helpful." },
        { role: "user", content: "Hello!" },
      ],
    });
    const result = extractMessages(url, body);
    expect(result).not.toBeNull();
    expect(result.provider).toBe("openai");
    expect(result.messages).toHaveLength(2);
    expect(result.messages[1].role).toBe("user");
  });

  it("returns null when messages field is missing", () => {
    const body = JSON.stringify({ model: "gpt-4o", prompt: "Hello" });
    // no messages array — falls through to generic-prompt
    const result = extractMessages(url, body);
    // generic fallback for prompt string
    expect(result).not.toBeNull();
    expect(result.provider).toBe("generic-prompt");
  });

  it("returns null for invalid JSON", () => {
    expect(extractMessages(url, "{bad json")).toBeNull();
  });

  it("matches on URL substring /v1/chat/completions", () => {
    const proxyUrl = "https://my-proxy.example.com/v1/chat/completions";
    const body = JSON.stringify({
      messages: [{ role: "user", content: "hi" }],
    });
    const result = extractMessages(proxyUrl, body);
    expect(result).not.toBeNull();
    expect(result.provider).toBe("openai");
  });
});

// ─── Anthropic format ─────────────────────────────────────────────────────────

describe("Anthropic format — /v1/messages", () => {
  const url = "https://api.anthropic.com/v1/messages";

  it("extracts messages array", () => {
    const body = JSON.stringify({
      model: "claude-sonnet-4-6",
      max_tokens: 1024,
      messages: [{ role: "user", content: "Explain quantum physics." }],
    });
    const result = extractMessages(url, body);
    expect(result).not.toBeNull();
    expect(result.provider).toBe("anthropic");
    expect(result.messages[0].content).toBe("Explain quantum physics.");
  });

  it("matches on /v1/messages path for proxy URLs", () => {
    const proxyUrl = "https://internal.company.com/v1/messages";
    const body = JSON.stringify({
      messages: [{ role: "user", content: "test" }],
    });
    const result = extractMessages(proxyUrl, body);
    expect(result).not.toBeNull();
    expect(result.provider).toBe("anthropic");
  });
});

// ─── AWS Bedrock format ───────────────────────────────────────────────────────

describe("AWS Bedrock — Anthropic model", () => {
  const url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-v2/invoke";

  it("extracts messages from Bedrock Anthropic payload", () => {
    const inner = {
      messages: [{ role: "user", content: "What is AI?" }],
    };
    const body = JSON.stringify({ body: btoa(JSON.stringify(inner)) });
    const result = extractMessages(url, body);
    expect(result).not.toBeNull();
    expect(result.provider).toBe("bedrock-anthropic");
    expect(result.messages[0].content).toBe("What is AI?");
  });

  it("extracts inputText from Bedrock Titan flat payload", () => {
    const inner = { inputText: "Tell me a joke." };
    const body = JSON.stringify({ body: btoa(JSON.stringify(inner)) });
    const result = extractMessages(url, body);
    expect(result).not.toBeNull();
    expect(result.provider).toBe("bedrock-titan");
    expect(result.messages[0].content).toBe("Tell me a joke.");
  });

  it("handles malformed base64 body gracefully", () => {
    const body = JSON.stringify({ body: "!!not_valid_base64!!" });
    // safeParseBase64Json returns null, falls through to generic
    const result = extractMessages(url, body);
    // No messages or inputText found → null
    expect(result).toBeNull();
  });
});

// ─── Generic fallback ─────────────────────────────────────────────────────────

describe("generic fallback", () => {
  const url = "https://my-custom-llm.example.com/chat";

  it("extracts generic messages array", () => {
    const body = JSON.stringify({
      messages: [{ role: "user", content: "hello" }],
    });
    const result = extractMessages(url, body);
    expect(result).not.toBeNull();
    expect(result.provider).toBe("generic");
  });

  it("extracts flat prompt string as generic-prompt", () => {
    const body = JSON.stringify({ prompt: "Tell me about Paris." });
    const result = extractMessages(url, body);
    expect(result).not.toBeNull();
    expect(result.provider).toBe("generic-prompt");
    expect(result.messages[0].role).toBe("user");
    expect(result.messages[0].content).toBe("Tell me about Paris.");
  });

  it("returns null when no recognizable structure", () => {
    const body = JSON.stringify({ query: "hello", context: "world" });
    const result = extractMessages(url, body);
    expect(result).toBeNull();
  });
});

// ─── Edge cases ───────────────────────────────────────────────────────────────

describe("edge cases", () => {
  it("returns null for empty body", () =>
    expect(extractMessages("https://api.openai.com/v1/chat/completions", "")).toBeNull());

  it("returns null for non-JSON body", () =>
    expect(extractMessages("https://api.openai.com/v1/chat/completions", "plain text")).toBeNull());

  it("handles messages with array content parts", () => {
    const url = "https://api.openai.com/v1/chat/completions";
    const body = JSON.stringify({
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "Describe this image." },
            { type: "image_url", image_url: { url: "https://example.com/img.png" } },
          ],
        },
      ],
    });
    const result = extractMessages(url, body);
    expect(result).not.toBeNull();
    expect(result.messages[0].content).toBeInstanceOf(Array);
  });
});
