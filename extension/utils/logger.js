const PROXY_ENDPOINT = "https://promptguard-proxy.example.com/events"; // swap with real endpoint

/**
 * Send a detection event to the proxy (ELK forwarding happens server-side).
 * Fire-and-forget — never awaited, never blocks the request pipeline.
 *
 * @param {{ verdict: string, score: number, matches: string[], url: string, provider: string }} event
 */
export function logEvent(event) {
  const payload = {
    ts: Date.now(),
    ...event,
    ua: navigator.userAgent.slice(0, 120),
  };

  // Use sendBeacon when available — survives page unload, no CORS preflight issue
  if (navigator.sendBeacon) {
    navigator.sendBeacon(PROXY_ENDPOINT, JSON.stringify(payload));
    return;
  }

  // Fallback
  fetch(PROXY_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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
