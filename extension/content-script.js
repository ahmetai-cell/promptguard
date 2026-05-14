/**
 * PromptGuard content script — runs in MAIN world (world: "MAIN" in manifest).
 * Intercepts fetch + XMLHttpRequest before they leave the browser.
 *
 * Why MAIN world: we need to patch the page's own fetch/XHR, not an isolated copy.
 * Trade-off: no access to most chrome.* APIs here — but chrome.runtime.sendMessage
 * is available in MAIN world content scripts since Chrome 116.
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

/**
 * Send a WARN event to the service worker and wait up to 400ms for an L2 verdict.
 * Returns "ALLOW" on timeout, error, or any non-BLOCK response — fail open.
 *
 * Requires Chrome 116+ for chrome.runtime.sendMessage in MAIN world.
 */
async function queryL2(prompt, score, matches, url) {
  try {
    const l2Promise = chrome.runtime.sendMessage({
      type: "L2_CHECK", prompt, score, matches, url,
    });
    const timeoutPromise = new Promise((resolve) =>
      setTimeout(() => resolve(null), 400)
    );
    const response = await Promise.race([l2Promise, timeoutPromise]);
    return response?.verdict === "BLOCK" ? "BLOCK" : "ALLOW";
  } catch {
    return "ALLOW";  // chrome.runtime unavailable or SW crashed → fail open
  }
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

        // Hold the request up to 400ms for an L2 semantic verdict.
        // If the proxy confirms injection → block; otherwise allow through.
        const l2Verdict = await queryL2(prompt, result.score, result.matches, url);

        if (l2Verdict === "BLOCK") {
          postVerdict("BLOCK", result.score, result.matches, url, prompt);
          return Promise.reject(
            Object.assign(new DOMException("PromptGuard blocked this request.", "AbortError"), {
              promptguard: true,
            })
          );
        }

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
// Note: XHR.send() is synchronous — L2 hold is not possible here.
// L1 BLOCK verdicts still abort XHR; WARN events are logged fire-and-forget.

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
