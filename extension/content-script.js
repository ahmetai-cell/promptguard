/**
 * PromptGuard content script — runs in MAIN world (world: "MAIN" in manifest).
 * Intercepts fetch + XMLHttpRequest before they leave the browser.
 *
 * Why MAIN world: we need to patch the page's own fetch/XHR, not an isolated copy.
 * Trade-off: no access to most chrome.* APIs here — but chrome.runtime.sendMessage
 * is available in MAIN world content scripts since Chrome 116.
 */

import { extractMessages, extractWsMessages } from "./utils/extractor.js";
import { analyzeMessages, analyzeText } from "./detector/index.js";

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

// ─── Conversation buffer — stateful multi-turn attack detection ────────────────
//
// Keeps a sliding window of unique user messages seen this page session.
// Each new request is analyzed against the full buffer, catching injection
// attacks that are split across multiple API calls (multi-turn injection).
//
// Design: buffer stores only user-role messages, deduped by djb2 hash.
// Before analysis, history not already present in the current request is
// prepended so analyzeMessages() sees the full conversation context.

const _BUFFER_MAX = 15;
const _convBuffer  = [];   // { role: "user", content: string }[]
const _seenHashes  = new Set();

function _djb2(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h) ^ str.charCodeAt(i);
  return (h >>> 0).toString(36);
}

function _bufferAdd(messages) {
  for (const m of messages) {
    if (m.role !== "user" && m.role !== "human") continue;
    const text = typeof m.content === "string" ? m.content : JSON.stringify(m.content);
    const hash = _djb2(text);
    if (_seenHashes.has(hash)) continue;
    _seenHashes.add(hash);
    _convBuffer.push({ role: "user", content: text });
    if (_convBuffer.length > _BUFFER_MAX) _convBuffer.shift();
  }
}

function _analyzeWithBuffer(messages) {
  // Prepend buffer history that is NOT already in the current request
  const currentHashes = new Set(
    messages
      .filter((m) => m.role === "user" || m.role === "human")
      .map((m) => _djb2(typeof m.content === "string" ? m.content : JSON.stringify(m.content)))
  );
  const history = _convBuffer.filter((b) => !currentHashes.has(_djb2(b.content)));
  return analyzeMessages([...history, ...messages]);
}

// ─── Session risk engine v3 — SAGE (Stable Adversarial Graph Engine) ──────────
//
// Four-component temporal model:
//
//   1. Short EMA (α=0.35): burst/spike detector
//   2. Long EMA  (α=0.85): drift/escalation detector
//   3. Velocity:  rate-of-change bonus (rising only, capped at 0.30)
//   4. Log-damped tag frequency: ln(1 + count) × 0.06 per tag type, caps 0.10
//
// Explicit state machine (governor):
//   SAFE       sessionRisk < 0.15  — normal operation
//   SUSPICIOUS sessionRisk 0.15–0.45 — elevated vigilance
//   ACTIVE     sessionRisk > 0.45  — maximum hardening
//
// Time-based decay: if ≥60 s of silence, long-term risk decays 20% per tick.
// Prevents stale risk from persisting across benign browsing sessions.
//
// All reductions are bounded: effectiveBlock never drops below 0.50.

const _SAGE_STATE = { SAFE: "SAFE", SUSPICIOUS: "SUSPICIOUS", ACTIVE: "ACTIVE" };

let _shortRisk   = 0;
let _longRisk    = 0;
let _riskPrev    = 0;
let _sessionRisk = 0;
let _sageState   = _SAGE_STATE.SAFE;
let _lastRiskTs  = 0;   // timestamp of last _updateSessionRisk call

const _SESSION_REDUCTION_MAX = 0.25;
const _RISK_DECAY_IDLE_MS    = 60_000;   // decay after 60 s of silence
const _RISK_DECAY_RATE       = 0.80;     // long risk × 0.80 per decay tick

const _tagCounts = Object.create(null);

function _decayIfIdle() {
  const now = Date.now();
  if (_lastRiskTs > 0 && now - _lastRiskTs > _RISK_DECAY_IDLE_MS) {
    _longRisk  = _longRisk  * _RISK_DECAY_RATE;
    _shortRisk = _shortRisk * _RISK_DECAY_RATE;
  }
  _lastRiskTs = now;
}

function _updateSessionRisk(score, matches = []) {
  _decayIfIdle();

  for (const m of matches) {
    const tag = m.split(":")[1] ?? m;
    _tagCounts[tag] = (_tagCounts[tag] ?? 0) + 1;
  }

  _shortRisk = Math.min(1.0, _shortRisk * 0.35 + score * 0.65);
  _longRisk  = Math.min(1.0, _longRisk  * 0.85 + score * 0.15);

  const base     = Math.max(_shortRisk, _longRisk);
  // Velocity: cap contribution at 0.30 to prevent single-spike amplification
  const velocity = Math.min(0.30, Math.max(0, base - _riskPrev) * 0.40);
  _riskPrev      = base;
  _sessionRisk   = Math.min(1.0, base + velocity);

  // Update explicit state
  if (_sessionRisk >= 0.45)      _sageState = _SAGE_STATE.ACTIVE;
  else if (_sessionRisk >= 0.15) _sageState = _SAGE_STATE.SUSPICIOUS;
  else                           _sageState = _SAGE_STATE.SAFE;

  _reportSageState();
}

function _tagFrequencyBoost() {
  // Log-damped: ln(1 + count) × 0.06 — smooth, bounded at 0.10
  const maxCount = Math.max(0, ...Object.values(_tagCounts));
  return Math.min(0.10, Math.log1p(maxCount) * 0.06);
}

function _applyDynamicThresholds(result) {
  // In SAFE state, velocity contribution is already minimal — no extra damping.
  // In ACTIVE state, full reduction applies.
  const stateMultiplier = _sageState === _SAGE_STATE.SAFE ? 0.5 : 1.0;
  const reduction = Math.min(
    _SESSION_REDUCTION_MAX,
    _sessionRisk * _SESSION_REDUCTION_MAX * stateMultiplier + _tagFrequencyBoost()
  );
  const block = Math.max(0.50, (_pgSettings.blockThreshold ?? 0.75) - reduction);
  const warn  = Math.max(0.30, (_pgSettings.warnThreshold  ?? 0.45) - reduction * 0.80);
  const v = result.score >= block ? "BLOCK" : result.score >= warn ? "WARN" : "ALLOW";
  return v === result.verdict ? result : { ...result, verdict: v };
}

// Expose current session state to popup via service worker
function _reportSageState() {
  _swSend({ type: "VERDICT",
    verdict: "SAGE_STATE",
    score: _sessionRisk,
    matches: [_sageState],
    url: location.href });
}

// ─── Settings (loaded from service worker on init) ─────────────────────────────

let _pgSettings = {
  blockThreshold: 0.75,
  warnThreshold:  0.45,
  l2Enabled:      true,
  whitelist:      [],
};

chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (r) => {
  if (chrome.runtime.lastError) return;
  if (r?.settings) _pgSettings = { ..._pgSettings, ...r.settings };
});

function _isWhitelisted(url) {
  try {
    const host = new URL(url).hostname;
    return (_pgSettings.whitelist ?? []).some(
      (d) => host === d || host.endsWith("." + d)
    );
  } catch { return false; }
}

function _applyThresholds(result) {
  const block = _pgSettings.blockThreshold ?? 0.75;
  const warn  = _pgSettings.warnThreshold  ?? 0.45;
  const v = result.score >= block ? "BLOCK" : result.score >= warn ? "WARN" : "ALLOW";
  return v === result.verdict ? result : { ...result, verdict: v };
}

// ─── Enabled state ─────────────────────────────────────────────────────────────

let _pgEnabled = true;

// Send a fire-and-forget message to the service worker via the ISOLATED world
// relay (relay.js). MAIN world → DOM CustomEvent → ISOLATED world → sendMessage.
function _swSend(msg) {
  try {
    document.dispatchEvent(new CustomEvent("_pg_msg", { detail: msg }));
  } catch { /* ignore */ }
}

function postVerdict(verdict, score, matches, url, prompt = null) {
  _swSend({ type: "VERDICT", verdict, score, matches, url, prompt });
}

// Receive PG_ENABLED broadcasts relayed from service worker via relay.js
document.addEventListener("_pg_enabled", (e) => { _pgEnabled = e.detail; });

function isLLMRequest(url) {
  return LLM_URL_PATTERNS.some((p) => url.includes(p));
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

const _TAG_EXPLAIN = {
  override:           "Instruction override attempt",
  "context-end":      "Instruction override attempt",
  "context-reset":    "Instruction override attempt",
  "override-de":      "Instruction override attempt",
  "override-es":      "Instruction override attempt",
  "override-tr":      "Instruction override attempt",
  jailbreak:          "Jailbreak technique detected",
  "jailbreak-tr":     "Jailbreak technique detected",
  bypass:             "Safety bypass attempt",
  "bypass-tr":        "Safety bypass attempt",
  persona:            "AI persona hijacking",
  "persona-de":       "AI persona hijacking",
  "persona-tr":       "AI persona hijacking",
  exfiltration:       "Data exfiltration attempt",
  "exfiltration-tr":  "Data exfiltration attempt",
  credential:         "Credential theft attempt",
  encoding:           "Encoding-based obfuscation",
  indirect:           "Indirect prompt injection",
  "soft-switch":      "Task-switch manipulation",
  social_engineering: "Social engineering attempt",
  "social-eng":       "Social engineering attempt",
  "translate-trick":  "Translation obfuscation",
  "output-control":   "Output manipulation attempt",
  "dev-mode":         "Developer mode jailbreak",
  harmful:            "Harmful content request",
};

const _THREAT_ICONS = {
  override:           "🔀",
  "context-end":      "🔀",
  "context-reset":    "🔀",
  "override-de":      "🔀",
  "override-es":      "🔀",
  "override-tr":      "🔀",
  jailbreak:          "🔓",
  "jailbreak-tr":     "🔓",
  bypass:             "🚧",
  "bypass-tr":        "🚧",
  persona:            "👤",
  "persona-de":       "👤",
  "persona-tr":       "👤",
  exfiltration:       "📤",
  "exfiltration-tr":  "📤",
  credential:         "🔑",
  encoding:           "🔢",
  indirect:           "🔗",
  "soft-switch":      "↩️",
  social_engineering: "🎭",
  "social-eng":       "🎭",
  "translate-trick":  "🌐",
  "output-control":   "📝",
  "dev-mode":         "⚙️",
  harmful:            "⛔",
};

function _overlayExplain(matches) {
  for (const m of matches) {
    const tag = m.split(":")[1] ?? m;
    if (_TAG_EXPLAIN[tag]) return _TAG_EXPLAIN[tag];
  }
  return "Prompt injection attempt detected";
}

function _overlayIcon(matches) {
  for (const m of matches) {
    const tag = m.split(":")[1] ?? m;
    if (_THREAT_ICONS[tag]) return _THREAT_ICONS[tag];
  }
  return "🛡";
}

function _riskLevel(score) {
  if (score >= 0.90) return { label: "CRITICAL", color: "#ff3b3b" };
  if (score >= 0.75) return { label: "HIGH",     color: "#f97316" };
  return                     { label: "MEDIUM",   color: "#eab308" };
}

function showBlockOverlay(score, matches, url = "", layer = "L1", prompt = null) {
  document.getElementById("_pg_host")?.remove();

  const host = document.createElement("div");
  host.id = "_pg_host";
  Object.assign(host.style, {
    position: "fixed", bottom: "20px", right: "20px",
    zIndex: "2147483647", all: "initial",
  });
  document.body?.appendChild(host);

  const shadow = host.attachShadow({ mode: "closed" });

  const pct        = Math.round(score * 100);
  const explain    = _overlayExplain(matches);
  const icon       = _overlayIcon(matches);
  const risk       = _riskLevel(score);
  const site       = url ? url.replace(/^https?:\/\//, "").split("/")[0].slice(0, 40) : location.hostname;
  const layerLbl   = layer === "L2" ? "L1 + L2 DeBERTa" : "L1 Pattern Engine";
  const promptSnip = prompt ? prompt.slice(0, 80) + (prompt.length > 80 ? "…" : "") : null;

  const topTags = matches
    .slice(0, 3)
    .map((m) => {
      const tag = m.split(":")[1] ?? m;
      const pid = m.split(":")[0];
      return `<span class="tag" title="${pid}">${tag}</span>`;
    })
    .join("");

  shadow.innerHTML = `
    <style>
      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
      .card {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
        background: #0d0f1c;
        border: 1px solid #1e2235;
        border-top: 3px solid ${risk.color};
        border-radius: 12px;
        width: 320px;
        box-shadow: 0 16px 48px rgba(0,0,0,0.65), 0 0 0 1px rgba(255,255,255,0.04);
        animation: up 0.20s cubic-bezier(0.16,1,0.3,1);
        overflow: hidden;
      }
      @keyframes up {
        from { opacity: 0; transform: translateY(12px) scale(0.98); }
        to   { opacity: 1; transform: translateY(0) scale(1); }
      }

      /* ── Header ── */
      .hdr {
        display: flex; align-items: flex-start; gap: 10px;
        padding: 14px 14px 10px;
      }
      .hdr-icon {
        width: 34px; height: 34px; flex-shrink: 0;
        background: rgba(239,68,68,0.15);
        border-radius: 9px;
        display: flex; align-items: center; justify-content: center;
        font-size: 17px;
      }
      .hdr-body { flex: 1; min-width: 0; }
      .hdr-title {
        font-size: 13px; font-weight: 700;
        color: #f1f5f9; letter-spacing: -0.01em;
      }
      .hdr-site {
        font-size: 11px; color: #64748b;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        margin-top: 1px;
      }
      .risk-badge {
        flex-shrink: 0;
        font-size: 9px; font-weight: 800;
        letter-spacing: 0.08em;
        padding: 3px 7px; border-radius: 4px;
        background: rgba(239,68,68,0.15);
        color: ${risk.color};
        margin-top: 1px;
      }
      .x {
        flex-shrink: 0;
        background: none; border: none;
        color: #475569; font-size: 15px;
        cursor: pointer; padding: 0; line-height: 1;
        margin-top: 1px;
      }
      .x:hover { color: #94a3b8; }

      /* ── Threat detail ── */
      .threat {
        display: flex; align-items: center; gap: 8px;
        padding: 9px 14px;
        background: rgba(239,68,68,0.07);
        border-top: 1px solid rgba(239,68,68,0.15);
        border-bottom: 1px solid rgba(239,68,68,0.15);
      }
      .threat-icon { font-size: 13px; flex-shrink: 0; }
      .threat-desc { font-size: 12px; color: #fca5a5; font-weight: 500; }

      /* ── Score bar ── */
      .score-wrap { padding: 10px 14px 0; }
      .score-meta {
        display: flex; justify-content: space-between; align-items: center;
        margin-bottom: 5px;
      }
      .score-lbl { font-size: 10px; color: #64748b; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; }
      .score-val { font-size: 12px; font-weight: 700; color: ${risk.color}; }
      .bar-track {
        height: 5px; background: #1e2235; border-radius: 3px; overflow: hidden;
      }
      .bar-fill {
        height: 100%; width: ${pct}%;
        background: linear-gradient(90deg, ${risk.color}99, ${risk.color});
        border-radius: 3px;
      }

      /* ── Tags + layer ── */
      .meta { padding: 9px 14px 10px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
      .tag {
        font-size: 10px; font-weight: 600;
        padding: 2px 7px; border-radius: 4px;
        background: rgba(99,102,241,0.15); color: #818cf8;
        cursor: default;
      }
      .layer-badge {
        margin-left: auto;
        font-size: 9px; font-weight: 700; letter-spacing: 0.05em;
        padding: 2px 6px; border-radius: 4px;
        background: rgba(255,255,255,0.05); color: #475569;
      }

      /* ── Buttons ── */
      .btns {
        display: flex; gap: 7px;
        padding: 0 14px 13px;
      }
      .cancel {
        flex: 1.4; padding: 8px 10px; border-radius: 8px; border: none;
        background: #ef4444; color: #fff;
        font-size: 12px; font-weight: 600; cursor: pointer;
        transition: background 0.15s;
      }
      .cancel:hover { background: #dc2626; }
      .override {
        flex: 1; padding: 8px 10px; border-radius: 8px;
        border: 1px solid #1e2235; background: transparent;
        color: #64748b; font-size: 12px; cursor: pointer;
        transition: all 0.15s;
      }
      .override:hover { border-color: #374151; color: #94a3b8; }

      /* Prompt preview */
      .prompt-preview {
        margin: 0 14px 10px;
        background: rgba(255,255,255,0.03);
        border: 1px solid #1e2235;
        border-radius: 7px;
        padding: 7px 10px;
        font-size: 10px;
        font-family: "SF Mono", "Fira Mono", "Consolas", monospace;
        color: #64748b;
        line-height: 1.5;
        word-break: break-word;
      }
      .prompt-preview-lbl {
        font-size: 9px;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #334155;
        margin-bottom: 3px;
      }

      /* Timer bar */
      .timer-bar {
        height: 3px;
        background: ${risk.color}44;
        border-radius: 0 0 12px 12px;
        overflow: hidden;
      }
      .timer-fill {
        height: 100%;
        background: ${risk.color};
        border-radius: 0 0 12px 12px;
        animation: drain 10s linear forwards;
      }
      @keyframes drain { from { width: 100%; } to { width: 0%; } }
    </style>
    <div class="card">
      <div class="hdr">
        <div class="hdr-icon">${icon}</div>
        <div class="hdr-body">
          <div class="hdr-title">Prompt Injection Blocked</div>
          <div class="hdr-site">on ${site}</div>
        </div>
        <div class="risk-badge">${risk.label}</div>
        <button class="x" aria-label="Dismiss">✕</button>
      </div>

      <div class="threat">
        <span class="threat-icon">⚠️</span>
        <span class="threat-desc">${explain}</span>
      </div>

      <div class="score-wrap">
        <div class="score-meta">
          <span class="score-lbl">Risk Score</span>
          <span class="score-val">${pct}%</span>
        </div>
        <div class="bar-track"><div class="bar-fill"></div></div>
      </div>

      <div class="meta">
        ${topTags || ""}
        <span class="layer-badge">${layerLbl}</span>
      </div>

      ${promptSnip ? `
      <div class="prompt-preview">
        <div class="prompt-preview-lbl">Blocked prompt</div>
        ${promptSnip}
      </div>` : ""}

      <div class="btns">
        <button class="cancel">Cancel Request</button>
        <button class="override">⚠ Override</button>
      </div>

      <div class="timer-bar"><div class="timer-fill"></div></div>
    </div>
  `;

  const autoClose = setTimeout(() => close(), 10000);
  const close = () => {
    clearTimeout(autoClose);
    const card = shadow.querySelector(".card");
    if (card) {
      card.style.transition = "opacity 0.15s ease, transform 0.15s ease";
      card.style.opacity = "0";
      card.style.transform = "translateY(8px) scale(0.97)";
      setTimeout(() => host.remove(), 160);
    } else {
      host.remove();
    }
  };

  shadow.querySelector(".x").addEventListener("click", close);
  shadow.querySelector(".cancel").addEventListener("click", close);
  shadow.querySelector(".override").addEventListener("click", () => {
    try { sessionStorage.setItem(_OVERRIDE_KEY, "1"); } catch { /* private browsing */ }
    close();
  });
}

// ─── L2 escalation ────────────────────────────────────────────────────────────

async function queryL2(prompt, score, matches, url) {
  try {
    const l2Promise = chrome.runtime.sendMessage({
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
let _patchedFetch;

window.fetch = _patchedFetch = async function pgFetch(input, init = {}) {
  const url = typeof input === "string" ? input : input?.url ?? "";

  if (!isLLMRequest(url)) return _fetch(input, init);
  if (!_pgEnabled) return _fetch(input, init);
  if (_isWhitelisted(url)) return _fetch(input, init);

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
      const singleResult = analyzeMessages(extracted.messages);
      _updateSessionRisk(singleResult.score, singleResult.matches);
      _bufferAdd(extracted.messages);
      const result = _applyDynamicThresholds(_analyzeWithBuffer(extracted.messages));

      if (result.verdict === "BLOCK") {
        const prompt = extractPromptText(extracted.messages);
        postVerdict("BLOCK", result.score, result.matches, url, prompt);
        showBlockOverlay(result.score, result.matches, url, "L1", prompt);
        return Promise.reject(
          Object.assign(new DOMException("PromptGuard blocked this request.", "AbortError"), {
            promptguard: true,
          })
        );
      }

      if (result.verdict === "WARN") {
        const prompt = extractPromptText(extracted.messages);
        const l2Verdict = _pgSettings.l2Enabled !== false
          ? await queryL2(prompt, result.score, result.matches, url)
          : "ALLOW";

        if (l2Verdict === "BLOCK") {
          postVerdict("BLOCK", result.score, result.matches, url, prompt);
          showBlockOverlay(result.score, result.matches, url, "L2", prompt);
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

// ─── Hook watchdog ────────────────────────────────────────────────────────────
// Re-applies our fetch patch if page JS overwrites window.fetch.
// Checks every 2 seconds; logs a tamper event if the hook was replaced.

setInterval(() => {
  if (window.fetch !== _patchedFetch) {
    window.fetch = _patchedFetch;
    _swSend({
      type: "VERDICT",
      verdict: "WARN",
      score: 0.5,
      matches: ["hook-tamper"],
      url: location.href,
      prompt: null,
    });
  }
}, 2000);

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
              showBlockOverlay(result.score, result.matches, url, "L1");
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

  if (isLLMRequest(url) && _pgEnabled && !_isWhitelisted(url)) {
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
          const singleResult = analyzeMessages(extracted.messages);
          _updateSessionRisk(singleResult.score, singleResult.matches);
          _bufferAdd(extracted.messages);
          const result = _applyDynamicThresholds(_analyzeWithBuffer(extracted.messages));

          if (result.verdict === "BLOCK") {
            const prompt = extractPromptText(extracted.messages);
            postVerdict("BLOCK", result.score, result.matches, url, prompt);
            showBlockOverlay(result.score, result.matches, url, "L1", prompt);
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
      // ── Conversation buffer + session risk + analysis ────────────────────
      const _wsSingle = analyzeMessages(messages);
      _updateSessionRisk(_wsSingle.score);
      _bufferAdd(messages);
      const result = _applyDynamicThresholds(_analyzeWithBuffer(messages));

      if (result.verdict === "BLOCK") {
        postVerdict("BLOCK", result.score, result.matches, String(url));
        showBlockOverlay(result.score, result.matches, String(url), "L1");
        return;   // drop — do not forward to server
      }

      // ── Rolling-buffer analysis (incremental injection detection) ─────────
      const userText = extractPromptText(messages);
      if (userText) {
        const accumulated = _wsAccumulate(ws, userText);
        const bufResult   = analyzeMessages([{ role: "user", content: accumulated }]);

        if (bufResult.verdict === "BLOCK" && result.verdict !== "BLOCK") {
          postVerdict("BLOCK", bufResult.score, bufResult.matches, String(url));
          showBlockOverlay(bufResult.score, bufResult.matches, String(url), "L1");
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


// ─── DOM input monitoring — catches sites using service workers (ChatGPT, Claude.ai) ──

function _getInputText(el) {
  if (!el) return "";
  if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") return el.value ?? "";
  if (el.isContentEditable) return el.innerText ?? "";
  return "";
}

document.addEventListener("keydown", (e) => {
  if (!_pgEnabled) return;
  if (e.key !== "Enter" || e.shiftKey || e.altKey || e.metaKey) return;
  const text = _getInputText(document.activeElement).trim();
  if (text.length < 10) return;

  const result = analyzeText(text);
  if (result.verdict === "ALLOW") return;

  postVerdict(result.verdict, result.score, result.matches, location.href, text);

  if (result.verdict === "BLOCK") {
    e.preventDefault();
    e.stopImmediatePropagation();
  }
  showBlockOverlay(result.score, result.matches, location.href, "L1");
}, true); // capture phase — runs before page handlers

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
