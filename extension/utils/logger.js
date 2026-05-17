import { cacheGet, cacheSet } from "./cache.js";

const DEFAULT_PROXY = "https://promptguard-l2-production.up.railway.app";

// Injected at build time by esbuild --define:PG_TOKEN='"..."'
// Falls back to empty string in dev builds without a token configured.
/* global PG_TOKEN */
const _TOKEN = typeof PG_TOKEN !== "undefined" ? PG_TOKEN : "";

const _HEADERS = {
  "Content-Type": "application/json",
  ...(_TOKEN ? { "X-PG-Token": _TOKEN } : {}),
};

async function _proxyEndpoint() {
  try {
    const r = await chrome.storage.local.get("pg_settings");
    const base = r.pg_settings?.proxyUrl?.replace(/\/$/, "") ?? DEFAULT_PROXY;
    return `${base}/events`;
  } catch {
    return `${DEFAULT_PROXY}/events`;
  }
}

/**
 * Send a detection event to the proxy — fire-and-forget audit log.
 * Called for BLOCK verdicts and as a fallback when L2 is unavailable.
 *
 * Note: sendBeacon cannot set custom headers (X-PG-Token), so we use
 * fetch with keepalive:true which survives page unload in modern browsers.
 *
 * @param {{ verdict: string, score: number, matches: string[], url: string, prompt?: string }} event
 */
export function logEvent(event) {
  const payload = {
    ts: Date.now(),
    verdict: event.verdict,
    score: event.score,
    matches: event.matches,
    url: event.url,
    prompt: event.prompt ?? null,
    ua: typeof navigator !== "undefined" ? navigator.userAgent.slice(0, 120) : "",
  };

  _proxyEndpoint().then((endpoint) => {
    fetch(endpoint, {
      method: "POST",
      headers: _HEADERS,
      body: JSON.stringify(payload),
      keepalive: true,
    }).catch(() => {});
  });
}

/**
 * Send a WARN event to the proxy and await the L2 verdict.
 * Called by the service worker in response to an L2_CHECK message.
 * Timeout: 350ms (leaves buffer for the 400ms client-side deadline).
 * Always returns "ALLOW" on any error — fail open.
 *
 * @param {{ score: number, matches: string[], url: string, prompt?: string }} event
 * @returns {Promise<"BLOCK" | "ALLOW">}
 */
export async function checkL2(event) {
  const prompt = event.prompt ?? null;

  // Cache hit — skip proxy call entirely
  if (prompt) {
    const cached = await cacheGet(prompt);
    if (cached !== null) return cached;
  }

  const payload = {
    ts: Date.now(),
    verdict: "WARN",
    score: event.score,
    matches: event.matches ?? [],
    url: event.url ?? "",
    prompt,
    ua: typeof navigator !== "undefined" ? navigator.userAgent.slice(0, 120) : "",
  };

  try {
    const endpoint = await _proxyEndpoint();
    const resp = await fetch(endpoint, {
      method: "POST",
      headers: _HEADERS,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(350),
    });
    if (!resp.ok) return "ALLOW";
    const data = await resp.json();
    const verdict = data.final_verdict === "BLOCK" ? "BLOCK" : "ALLOW";

    // Store verdict for future identical prompts
    if (prompt) await cacheSet(prompt, verdict);

    return verdict;
  } catch {
    return "ALLOW";  // network error, timeout, proxy down → fail open
  }
}

/**
 * Persist event to chrome.storage for popup display (last 50 events).
 */
export async function storeEvent(event) {
  try {
    const stored = await chrome.storage.local.get("events");
    const events = Array.isArray(stored.events) ? stored.events : [];
    events.unshift({ ts: Date.now(), ...event });
    if (events.length > 50) events.length = 50;
    await chrome.storage.local.set({ events });
  } catch {
    // storage unavailable in MAIN world content scripts — SW handles this
  }
}
