const $ = (id) => document.getElementById(id);

async function render() {
  // Stats
  chrome.runtime.sendMessage({ type: "GET_STATS" }, (stats) => {
    if (!stats) return;
    $("stat-blocked").textContent = stats.blocked ?? 0;
    $("stat-warned").textContent  = stats.warned  ?? 0;
    $("stat-allowed").textContent = stats.allowed ?? 0;
  });

  // Events
  const { events } = await chrome.storage.local.get("events");
  const list = $("event-list");
  const emptyMsg = $("empty-msg");

  if (!events || events.length === 0) {
    emptyMsg.style.display = "block";
    return;
  }

  emptyMsg.style.display = "none";

  // Keep only the last 20 in the popup
  const recent = events.slice(0, 20);
  for (const ev of recent) {
    const el = document.createElement("div");
    el.className = "event-item";

    const shortUrl = ev.url
      ? ev.url.replace(/https?:\/\//, "").slice(0, 50)
      : "unknown";

    const matchStr = Array.isArray(ev.matches)
      ? ev.matches.slice(0, 3).join(", ") + (ev.matches.length > 3 ? "…" : "")
      : "";

    el.innerHTML = `
      <span class="badge ${ev.verdict}">${ev.verdict}</span>
      <div class="event-detail">
        <div class="event-url">${shortUrl}</div>
        ${matchStr ? `<div class="event-matches">${matchStr}</div>` : ""}
      </div>
    `;
    list.appendChild(el);
  }
}

$("clear-btn").addEventListener("click", async () => {
  await chrome.storage.local.set({ events: [] });
  // Re-render
  const list = $("event-list");
  [...list.querySelectorAll(".event-item")].forEach((el) => el.remove());
  $("empty-msg").style.display = "block";
});

render();
