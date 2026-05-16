/**
 * PromptGuard content script — runs in MAIN world (world: "MAIN" in manifest).
 * Intercepts fetch + XMLHttpRequest before they leave the browser.
 *
 * Why MAIN world: we need to patch the page's own fetch/XHR, not an isolated copy.
 * Trade-off: no access to most chrome.* APIs here — but chrome.runtime.sendMessage
 * is available in MAIN world content scripts since Chrome 116.
 */

import { extractMessages, extractWsMessages } from "./utils/extractor.js";
import { analyzeMessages } from "./detector/index.js";

const LLM_URL_PATTERNS = [
  "openai.com/v1/chat/completions",
  "anthropic.com/v1/messages",
  "chatgpt.com/backend-api/conversation",
  "claude.ai/api/organizations",
  "bedrock-runtime",
  "/api/chat",
  "/v1/completions",
];

const _OVERRIDE_KEY = "_pg_override";

// ─── Enabled state ─────────────────────────────────────────────────────────────

let _pgEnabled = true;
const _rt = (typeof chrome !== "undefined") && chrome.runtime;
if (_rt) {
  _rt.sendMessage({ type: "GET_ENABLED" }, (r) => {
    if (_rt?.lastError) return;
    if (r) _pgEnabled = r.enabled;
  });
  _rt.onMessage.addListener((msg) => {
    if (msg.type === "PG_ENABLED") _pgEnabled = msg.enabled;
  });
}

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
    .slice(0, 2000);
}

// ─── Block overlay ─────────────────────────────────────────────────────────────
// Rendered in a Shadow DOM so page styles can't bleed in or out.

function showBlockOverlay(score, matches) {
  document.getElementById("_pg_host")?.remove();

  const host = document.createElement("div");
  host.id = "_pg_host";
  // All layout styles on host itself so shadow boundary is clean
  Object.assign(host.style, {
    position: "fixed", bottom: "20px", right: "20px",
    zIndex: "2147483647", all: "initial",
  });
  document.body?.appendChild(host);

  const shadow = host.attachShadow({ mode: "closed" });

  const topTags = matches
    .slice(0, 3)
    .map((m) => `<span class="tag">${m.split(":")[1] ?? m}</span>`)
    .join("");

  shadow.innerHTML = `
    <style>
      * { box-sizing: border-box; }
      .card {
        font-family: system-ui, -apple-system, sans-serif;
        background: #12122a; color: #e8e8f0;
        border: 1px solid #2a2a50; border-radius: 14px;
        padding: 16px 18px; width: 310px;
        box-shadow: 0 12px 40px rgba(0,0,0,0.55);
        animation: up 0.22s ease-out;
      }
      @keyframes up {
        from { opacity: 0; transform: translateY(14px); }
        to   { opacity: 1; transform: translateY(0); }
      }
      .row   { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
      .icon  { font-size: 19px; line-height: 1; }
      .title { font-size: 14px; font-weight: 650; flex: 1; }
      .x     { background: none; border: none; color: #666; font-size: 16px;
                cursor: pointer; padding: 0; line-height: 1; }
      .x:hover { color: #ccc; }
      .score { font-size: 12px; color: #ff7070; margin-bottom: 7px; }
      .tags  { margin-bottom: 13px; line-height: 1.8; }
      .tag   { display: inline-block; background: #1e1e42; color: #8a92ff;
                font-size: 11px; padding: 2px 7px; border-radius: 5px; margin-right: 4px; }
      .btns  { display: flex; gap: 8px; }
      .send  { flex: 1; padding: 8px; border-radius: 8px;
                border: 1px solid #ff5555; background: transparent;
                color: #ff7070; font-size: 12px; cursor: pointer; }
      .send:hover  { background: rgba(255,85,85,0.1); }
      .ok    { flex: 1; padding: 8px; border-radius: 8px; border: none;
                background: #252548; color: #ccc; font-size: 12px; cursor: pointer; }
      .ok:hover { background: #2e2e58; }
    </style>
    <div class="card">
      <div class="row">
        <span class="icon">🛡</span>
        <span class="title">Injection blocked</span>
        <button class="x" aria-label="Dismiss">✕</button>
      </div>
      <div class="score">Risk score: ${(score * 100).toFixed(0)}%</div>
      ${topTags ? `<div class="tags">${topTags}</div>` : ""}
      <div class="btns">
        <button class="send">Send anyway</button>
        <button class="ok">Dismiss</button>
      </div>
    </div>
  `;

  const autoClose = setTimeout(() => host.remove(), 8000);
  const close = () => { clearTimeout(autoClose); host.remove(); };

  shadow.querySelector(".x").addEventListener("click", close);
  shadow.querySelector(".ok").addEventListener("click", close);
  shadow.querySelector(".send").addEventListener("click", () => {
    // Grant one override pass-through; user must re-submit their message
    try { sessionStorage.setItem(_OVERRIDE_KEY, "1"); } catch { /* private browsing */ }
    close();
  });
}

// ─── L2 escalation ────────────────────────────────────────────────────────────

async function queryL2(prompt, score, matches, url) {
  try {
    if (!_rt) return null;
    const l2Promise = _rt.sendMessage({
      type: "L2_CHECK", prompt, score, matches, url,
    });
    const timeout = new Promise((resolve) => setTimeout(() => resolve(null), 400));
    const response = await Promise.race([l2Promise, timeout]);
    return response?.verdict === "BLOCK" ? "BLOCK" : "ALLOW";
  } catch {
    return "ALLOW";
  }
}

// ─── Fetch intercept ──────────────────────────────────────────────────────────

const _fetch = window.fetch.bind(window);
window.fetch = async function (input, init = {}) {
  const url = typeof input === "string" ? input : input?.url ?? "";

  if (!isLLMRequest(url)) return _fetch(input, init);
  if (!_pgEnabled) return _fetch(input, init);

  // One-shot override: user clicked "Send anyway" in the block overlay
  try {
    if (sessionStorage.getItem(_OVERRIDE_KEY)) {
      sessionStorage.removeItem(_OVERRIDE_KEY);
      return _fetch(input, init);
    }
  } catch { /* private browsing — skip override check */ }

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
        showBlockOverlay(result.score, result.matches);
        return Promise.reject(
          Object.assign(new DOMException("PromptGuard blocked this request.", "AbortError"), {
            promptguard: true,
          })
        );
      }

      if (result.verdict === "WARN") {
        const prompt = extractPromptText(extracted.messages);
        const l2Verdict = await queryL2(prompt, result.score, result.matches, url);

        if (l2Verdict === "BLOCK") {
          postVerdict("BLOCK", result.score, result.matches, url, prompt);
          showBlockOverlay(result.score, result.matches);
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

  const response = await _fetch(input, init);

  // ── SSE response scan (indirect injection detection) ─────────────────────
  // If the LLM streams back content that looks like it's relaying an injection
  // (e.g. model was tricked by a poisoned RAG document), alert the user.
  // Fire-and-forget: we scan the tee'd stream without blocking page delivery.
  if (response.body && response.headers.get("content-type")?.includes("text/event-stream")) {
    try {
      const [pageStream, scanStream] = response.body.tee();
      _scanSSE(scanStream, url).catch(() => {});
      return new Response(pageStream, {
        status:     response.status,
        statusText: response.statusText,
        headers:    response.headers,
      });
    } catch { /* tee not supported — skip */ }
  }

  return response;
};

// ─── SSE output scanner ───────────────────────────────────────────────────────
// Reads a tee'd SSE response stream and fires a WARN postMessage if the model's
// output contains injection-relay signals. Detection only — cannot retroactively
// block streamed content already delivered to the page.

async function _scanSSE(stream, url) {
  const reader  = stream.getReader();
  const decoder = new TextDecoder();
  let   buf     = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });

      const lines = buf.split("\n");
      buf = lines.pop();   // keep incomplete last line

      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const raw = line.slice(6).trim();
        if (raw === "[DONE]" || !raw) continue;
        try {
          const chunk = JSON.parse(raw);
          // OpenAI streaming delta
          const delta = chunk?.choices?.[0]?.delta?.content
                     ?? chunk?.choices?.[0]?.text
                     ?? null;
          if (delta) {
            const result = analyzeText(delta);
            if (result.verdict === "BLOCK") {
              postVerdict("BLOCK", result.score, result.matches, url);
              showBlockOverlay(result.score, result.matches);
              reader.cancel();
              return;
            }
          }
        } catch { /* non-JSON SSE line */ }
      }
    }
  } catch { /* stream cancelled or ended */ }
}

// ─── XMLHttpRequest intercept ─────────────────────────────────────────────────
// XHR.send() is synchronous — L2 hold not possible.
// Override check + L1 BLOCK (abort + overlay) still work.

const _open = XMLHttpRequest.prototype.open;
const _send = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.open = function (method, url, ...rest) {
  this._pgUrl = url;
  return _open.call(this, method, url, ...rest);
};

XMLHttpRequest.prototype.send = function (body) {
  const url = this._pgUrl ?? "";

  if (isLLMRequest(url) && _pgEnabled) {
    try {
      if (sessionStorage.getItem(_OVERRIDE_KEY)) {
        sessionStorage.removeItem(_OVERRIDE_KEY);
        return _send.call(this, body);
      }
    } catch { /* private browsing */ }

    if (body) {
      const rawBody = typeof body === "string" ? body : null;
      if (rawBody) {
        const extracted = extractMessages(url, rawBody);
        if (extracted) {
          const result = analyzeMessages(extracted.messages);

          if (result.verdict === "BLOCK") {
            postVerdict("BLOCK", result.score, result.matches, url);
            showBlockOverlay(result.score, result.matches);
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
  }

  return _send.call(this, body);
};

// ─── WebSocket intercept ──────────────────────────────────────────────────────
// Covers ChatGPT web (action:"next"), OpenAI Realtime API, and generic proxies.
// ws.send() is synchronous — L2 hold is not possible (same constraint as XHR).
// L1 BLOCK → message dropped + overlay shown. WARN → logged, message passes.
//
// Rolling buffer: accumulates user content per-socket over a 30-second window.
// Catches incremental attacks where each chunk is benign alone (e.g. "ignore" +
// " previous" + " instructions" sent as three separate messages).

// Per-socket accumulator: ws → { text: string, timer: id }
const _wsBuffers = new WeakMap();
const _WS_BUFFER_MAX  = 4000;   // chars, prevents unbounded memory
const _WS_BUFFER_TTL  = 30_000; // ms — reset after 30s of inactivity

function _wsAccumulate(ws, userText) {
  let buf = _wsBuffers.get(ws) ?? { text: "", timer: null };
  clearTimeout(buf.timer);
  const combined = (buf.text + "\n" + userText).slice(-_WS_BUFFER_MAX);
  buf.timer = setTimeout(() => _wsBuffers.delete(ws), _WS_BUFFER_TTL);
  buf.text = combined;
  _wsBuffers.set(ws, buf);
  return combined;
}

const _WS = window.WebSocket;

window.WebSocket = function PGWebSocket(url, protocols) {
  const ws = protocols !== undefined ? new _WS(url, protocols) : new _WS(url);

  if (!isLLMRequest(String(url)) || !_pgEnabled) return ws;

  try {
    if (sessionStorage.getItem(_OVERRIDE_KEY)) {
      sessionStorage.removeItem(_OVERRIDE_KEY);
      return ws;
    }
  } catch { /* private browsing */ }

  const _send = ws.send.bind(ws);
  ws.send = function pgSend(data) {
    const messages = extractWsMessages(data);
    if (messages) {
      // ── Single-message analysis (existing behaviour) ──────────────────────
      const result = analyzeMessages(messages);

      if (result.verdict === "BLOCK") {
        postVerdict("BLOCK", result.score, result.matches, String(url));
        showBlockOverlay(result.score, result.matches);
        return;   // drop — do not forward to server
      }

      // ── Rolling-buffer analysis (incremental injection detection) ─────────
      const userText = extractPromptText(messages);
      if (userText) {
        const accumulated = _wsAccumulate(ws, userText);
        const bufResult   = analyzeMessages([{ role: "user", content: accumulated }]);

        if (bufResult.verdict === "BLOCK" && result.verdict !== "BLOCK") {
          postVerdict("BLOCK", bufResult.score, bufResult.matches, String(url));
          showBlockOverlay(bufResult.score, bufResult.matches);
          return;   // incremental attack — drop this message
        }
      }

      if (result.verdict === "WARN") {
        const prompt = extractPromptText(messages);
        postVerdict("WARN", result.score, result.matches, String(url), prompt);
      }
    }
    return _send(data);
  };

  return ws;
};

// Preserve prototype chain so `instanceof WebSocket` keeps working
window.WebSocket.prototype = _WS.prototype;
["CONNECTING", "OPEN", "CLOSING", "CLOSED"].forEach((k) => {
  window.WebSocket[k] = _WS[k];
});

// ─── Verdict listener — relay to service worker ───────────────────────────────

window.addEventListener("message", (e) => {
  if (e.source !== window || e.data?.source !== "promptguard") return;
  const { type, verdict, score, matches, url, prompt } = e.data;
  if (type === "VERDICT" && _rt) {
    _rt.sendMessage({ type: "VERDICT", verdict, score, matches, url, prompt });
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
