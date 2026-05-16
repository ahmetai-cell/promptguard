// ISOLATED world relay — MAIN world content scripts cannot reliably call
// chrome.runtime.sendMessage on all hosts. ISOLATED world can. Both worlds
// share the DOM, so CustomEvents bridge the gap.

document.addEventListener("_pg_msg", (e) => {
  const msg = e.detail;
  if (!msg) return;
  chrome.runtime.sendMessage(msg).catch(() => {});
});

// Forward PG_ENABLED broadcasts from service worker back to MAIN world
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "PG_ENABLED") {
    document.dispatchEvent(new CustomEvent("_pg_enabled", { detail: msg.enabled }));
  }
});
