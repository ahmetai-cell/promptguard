const PROXY_ENDPOINT = "https://promptguard-l2-production.up.railway.app/events";

// Injected at build time by esbuild --define:PG_TOKEN='"..."'
// Falls back to empty string in dev builds without a token configured.
/* global PG_TOKEN */
const _TOKEN = typeof PG_TOKEN !== "undefined" ? PG_TOKEN : "";

const _HEADERS = {
  "Content-Type": "application/json",
  ...(_TOKEN ? { "X-PG-Token": _TOKEN } : {}),
};

/**
 * Send a detection event to the proxy (ELK forwarding happens server-side).
 * Fire-and-forget — never awaited, never blocks the request pipeline.
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
    ua: navigator.userAgent.slice(0, 120),
  };

  fetch(PROXY_ENDPOINT, {
    method: "POST",
    headers: _HEADERS,
    body: JSON.stringify(payload),
    keepalive: true,
  }).catch(() => {
    // Swallow — logging should never break the extension
  });
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
