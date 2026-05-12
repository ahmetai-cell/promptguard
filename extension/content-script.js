/**
 * PromptGuard content script — runs in MAIN world (world: "MAIN" in manifest).
 * Intercepts fetch + XMLHttpRequest before they leave the browser.
 *
 * Why MAIN world: we need to patch the page's own fetch/XHR, not an isolated copy.
 * Trade-off: no access to chrome.* APIs here — we use window.postMessage to talk
 * to the service worker.
 */

import { extractMessages } from "./utils/extractor.js";
import { analyzeMessages } from "./detector/index.js";

const LLM_URL_PATTERNS = [
  "openai.com/v1/chat/completions",
  "anthropic.com/v1/messages",
  "bedrock-runtime",
  "/api/chat",           // common self-hosted / proxy paths
  "/v1/completions",
];

function isLLMRequest(url) {
  return LLM_URL_PATTERNS.some((p) => url.includes(p));
}

function postVerdict(verdict, score, matches, url, prompt = null) {
  window.postMessage(
    { source: "promptguard", type: "VERDICT", verdict, score, matches, url, prompt },
    "*"
  );
}

function extractPromptText(messages) {
  return messages
    .filter((m) => m.role === "user")
    .map((m) => (typeof m.content === "string" ? m.content : ""))
    .join("\n")
    .slice(0, 2000); // cap at 2000 chars — enough for classifier, avoids large payloads
}

// ─── Fetch intercept ───────────────────────────────────────────────────────────

const _fetch = window.fetch.bind(window);
window.fetch = async function (input, init = {}) {
  const url = typeof input === "string" ? input : input?.url ?? "";

  if (!isLLMRequest(url)) return _fetch(input, init);

  const body =
    init.body instanceof ReadableStream
      ? await streamToString(init.body)
      : typeof init.body === "string"
      ? init.body
      : init.body
      ? JSON.stringify(init.body)
      : null;

  if (body) {
    const extracted = extractMessages(url, body);
    if (extracted) {
      const result = analyzeMessages(extracted.messages);

      if (result.verdict === "BLOCK") {
        postVerdict("BLOCK", result.score, result.matches, url);
        return Promise.reject(
          Object.assign(new DOMException("PromptGuard blocked this request.", "AbortError"), {
            promptguard: true,
          })
        );
      }

      if (result.verdict === "WARN") {
        const prompt = extractPromptText(extracted.messages);
        postVerdict("WARN", result.score, result.matches, url, prompt);
        init.headers = {
          ...(init.headers || {}),
          "X-PromptGuard-Flag": "warn",
          "X-PromptGuard-Score": String(result.score),
        };
      }
    }
  }

  return _fetch(input, init);
};

// ─── XMLHttpRequest intercept ─────────────────────────────────────────────────

const _open = XMLHttpRequest.prototype.open;
const _send = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.open = function (method, url, ...rest) {
  this._pgUrl = url;
  return _open.call(this, method, url, ...rest);
};

XMLHttpRequest.prototype.send = function (body) {
  const url = this._pgUrl ?? "";
  if (isLLMRequest(url) && body) {
    const rawBody = typeof body === "string" ? body : null;
    if (rawBody) {
      const extracted = extractMessages(url, rawBody);
      if (extracted) {
        const result = analyzeMessages(extracted.messages);

        if (result.verdict === "BLOCK") {
          postVerdict("BLOCK", result.score, result.matches, url);
          this.abort();
          return;
        }

        if (result.verdict === "WARN") {
          const prompt = extractPromptText(extracted.messages);
          postVerdict("WARN", result.score, result.matches, url, prompt);
          this.setRequestHeader("X-PromptGuard-Flag", "warn");
          this.setRequestHeader("X-PromptGuard-Score", String(result.score));
        }
      }
    }
  }
  return _send.call(this, body);
};

// ─── Verdict listener — relay to service worker ───────────────────────────────

window.addEventListener("message", (e) => {
  if (e.source !== window || e.data?.source !== "promptguard") return;
  const { type, verdict, score, matches, url, prompt } = e.data;
  if (type === "VERDICT") {
    chrome.runtime.sendMessage({ type: "VERDICT", verdict, score, matches, url, prompt });
  }
});

// ─── Utility ──────────────────────────────────────────────────────────────────

async function streamToString(stream) {
  const reader = stream.getReader();
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return new TextDecoder().decode(
    chunks.reduce((a, b) => {
      const merged = new Uint8Array(a.length + b.length);
      merged.set(a);
      merged.set(b, a.length);
      return merged;
    }, new Uint8Array(0))
  );
}
