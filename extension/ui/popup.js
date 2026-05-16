// PromptGuard popup dashboard — vanilla JS (not bundled, no ES imports).

// ─── Category display names ───────────────────────────────────────────────────

const CAT_LABEL = {
  override:                    "Instruction Override",
  "context-end":               "Instruction Override",
  "context-reset":             "Instruction Override",
  jailbreak:                   "Jailbreak",
  bypass:                      "Bypass Attempt",
  "dev-mode":                  "Dev Mode Trick",
  persona:                     "Persona Hijack",
  role_hijack:                 "Persona Hijack",
  exfiltration:                "Data Exfiltration",
  credential:                  "Credential Theft",
  memory_poisoning:            "Memory Poisoning",
  tool_abuse:                  "Tool Abuse",
  execution:                   "Tool Execution",
  social_engineering:          "Social Engineering",
  indirect:                    "Indirect Injection",
  encoding:                    "Encoding Attack",
  "injection-token":           "Token Injection",
  homoglyph_substitution:      "Homoglyph Attack",
  zero_width_chars:            "Zero-Width Attack",
  excessive_whitespace_injection: "Spaced-Char Attack",
  unicode_direction_override:  "Unicode Attack",
  command:                     "Command Injection",
  harmful:                     "Harmful Request",
  "translate-trick":           "Translate Trick",
  "output-control":            "Output Manipulation",
  delimiter:                   "Delimiter Trick",
  "soft-switch":               "Topic Switch",
  "prompt_token_stuffing":     "Token Stuffing",
  "nested_instruction_brackets": "Nested Instructions",
  "suspicious_length_spike":   "Suspicious Length",
  "override-de":               "Instruction Override",
  "override-es":               "Instruction Override",
  "persona-de":                "Persona Hijack",
};

// Bar accent colors (cycled)
const BAR_COLORS = ["#7c3aed","#4f46e5","#2563eb","#0891b2","#059669"];

// ─── Helpers ──────────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

function fmt(n) {
  if (n === undefined || n === null) return "0";
  if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
  if (n >= 1000)    return (n / 1000).toFixed(1) + "K";
  return String(n);
}

function ago(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60)   return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h";
  return Math.floor(s / 86400) + "d";
}

// ─── Category bars ────────────────────────────────────────────────────────────

function mergeCats(raw) {
  const merged = {};
  for (const [tag, count] of Object.entries(raw)) {
    const label = CAT_LABEL[tag] ?? tag;
    merged[label] = (merged[label] ?? 0) + count;
  }
  return merged;
}

function renderCategories(rawCats) {
  const el = $("cat-list");
  el.innerHTML = "";

  const merged = mergeCats(rawCats);
  const sorted = Object.entries(merged).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = sorted[0]?.[1] ?? 1;

  if (sorted.length === 0) {
    el.innerHTML = '<div class="no-data">No attacks detected in this period.</div>';
    return;
  }

  sorted.forEach(([label, count], i) => {
    const pct = Math.max(4, Math.round((count / max) * 100));
    const row = document.createElement("div");
    row.className = "cat-row";
    row.innerHTML = `
      <span class="cat-name" title="${label}">${label}</span>
      <div class="bar-track">
        <div class="bar-fill" style="width:${pct}%;background:${BAR_COLORS[i % BAR_COLORS.length]}"></div>
      </div>
      <span class="cat-count">${count}</span>
    `;
    el.appendChild(row);
  });
}

// ─── 7-day SVG bar chart ──────────────────────────────────────────────────────

function renderChart(days) {
  const svg = $("chart-svg");
  svg.innerHTML = "";

  const W = 348, H = 60, PAD_BOTTOM = 16, BAR_W = 30, GAP = 8;
  const chartH = H - PAD_BOTTOM;

  // Build last 7 days array (oldest → newest)
  const today = new Date();
  const dayData = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const entry = days[key] ?? { blocked: 0, warned: 0 };
    const label = ["Su","Mo","Tu","We","Th","Fr","Sa"][d.getDay()];
    dayData.push({ label, blocked: entry.blocked, warned: entry.warned });
  }

  const maxVal = Math.max(1, ...dayData.map((d) => d.blocked + d.warned));

  // Total width of bars = 7 * BAR_W + 6 * GAP
  const totalBarsW = 7 * BAR_W + 6 * GAP;
  const startX = (W - totalBarsW) / 2;

  dayData.forEach((d, i) => {
    const x = startX + i * (BAR_W + GAP);
    const mid = x + BAR_W / 2;
    const totalH = Math.round(((d.blocked + d.warned) / maxVal) * chartH);
    const blockH = Math.round((d.blocked / maxVal) * chartH);
    const warnH  = totalH - blockH;

    // Background bar (track)
    const track = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    track.setAttribute("x", x);
    track.setAttribute("y", 0);
    track.setAttribute("width", BAR_W);
    track.setAttribute("height", chartH);
    track.setAttribute("rx", 4);
    track.setAttribute("fill", "#1f2937");
    svg.appendChild(track);

    if (totalH > 0) {
      // Warn portion (bottom)
      if (warnH > 0) {
        const wr = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        wr.setAttribute("x", x);
        wr.setAttribute("y", chartH - totalH);
        wr.setAttribute("width", BAR_W);
        wr.setAttribute("height", warnH);
        wr.setAttribute("fill", "#f97316");
        wr.setAttribute("opacity", "0.7");
        svg.appendChild(wr);
      }

      // Block portion (top, rounded top corners)
      if (blockH > 0) {
        const br = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        br.setAttribute("x", x);
        br.setAttribute("y", chartH - totalH);
        br.setAttribute("width", BAR_W);
        br.setAttribute("height", blockH);
        br.setAttribute("rx", 4);
        br.setAttribute("fill", "#ef4444");
        svg.appendChild(br);
      }
    }

    // Day label
    const txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
    txt.setAttribute("x", mid);
    txt.setAttribute("y", H - 2);
    txt.setAttribute("text-anchor", "middle");
    txt.setAttribute("font-size", "9");
    txt.setAttribute("font-family", "system-ui, sans-serif");
    txt.setAttribute("fill", "#475569");
    txt.textContent = d.label;
    svg.appendChild(txt);
  });
}

// ─── Recent events ────────────────────────────────────────────────────────────

function renderEvents(events) {
  const list = $("event-list");
  const emptyMsg = $("empty-msg");

  const threats = (events ?? []).filter((e) => e.verdict !== "ALLOW");

  if (threats.length === 0) {
    emptyMsg.style.display = "block";
    return;
  }
  emptyMsg.style.display = "none";

  threats.slice(0, 15).forEach((ev) => {
    const el = document.createElement("div");
    el.className = "ev";

    const shortUrl = (ev.url ?? "unknown")
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .slice(0, 40);

    const tagStr = (ev.matches ?? [])
      .slice(0, 3)
      .map((m) => {
        const raw = m.split(":")[1] ?? m;
        return CAT_LABEL[raw] ?? raw;
      })
      .join(" · ");

    el.innerHTML = `
      <span class="badge ${ev.verdict}">${ev.verdict}</span>
      <div class="ev-body">
        <div class="ev-url">${shortUrl}</div>
        ${tagStr ? `<div class="ev-tags">${tagStr}</div>` : ""}
      </div>
      <span class="ev-age">${ago(ev.ts)}</span>
    `;
    list.appendChild(el);
  });
}

// ─── Period toggle ────────────────────────────────────────────────────────────

let _statsCache = null;
let _period = "today";

function applyPeriod() {
  if (!_statsCache) return;
  const { categories, days } = _statsCache;

  if (_period === "today") {
    const todayKey = new Date().toISOString().slice(0, 10);
    const todayCats = days[todayKey]?.categories ?? {};
    renderCategories(todayCats);
  } else {
    renderCategories(categories);
  }
}

document.querySelectorAll(".period-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".period-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    _period = btn.dataset.p;
    applyPeriod();
  });
});

// ─── Enabled toggle ───────────────────────────────────────────────────────────

chrome.runtime.sendMessage({ type: "GET_ENABLED" }, (r) => {
  if (chrome.runtime.lastError) return;
  const enabled = r?.enabled ?? true;
  $("enabled-toggle").checked = enabled;
  $("toggle-lbl").textContent = enabled ? "Active" : "Paused";
  $("toggle-lbl").style.color = enabled ? "" : "#f97316";
});

$("enabled-toggle").addEventListener("change", (e) => {
  const enabled = e.target.checked;
  chrome.runtime.sendMessage({ type: "SET_ENABLED", enabled });
  $("toggle-lbl").textContent = enabled ? "Active" : "Paused";
  $("toggle-lbl").style.color = enabled ? "" : "#f97316";
});

// ─── Clear button ─────────────────────────────────────────────────────────────

$("clear-btn").addEventListener("click", async () => {
  chrome.runtime.sendMessage({ type: "CLEAR_STATS" });
  // Reset UI
  ["s-blocked","s-warned","s-scanned"].forEach((id) => { $(id).textContent = "0"; });
  $("cat-list").innerHTML = '<div class="no-data">No attacks detected in this period.</div>';
  $("event-list").querySelectorAll(".ev").forEach((e) => e.remove());
  $("empty-msg").style.display = "block";
  renderChart({});
  _statsCache = null;
});

// ─── Main render ──────────────────────────────────────────────────────────────

async function render() {
  // Stats
  chrome.runtime.sendMessage({ type: "GET_STATS" }, (stats) => {
    if (chrome.runtime.lastError || !stats) return;
    $("s-blocked").textContent = fmt(stats.totals?.blocked ?? 0);
    $("s-warned").textContent  = fmt(stats.totals?.warned  ?? 0);
    $("s-scanned").textContent = fmt(stats.totals?.scanned ?? 0);

    _statsCache = stats;
    applyPeriod();
    renderChart(stats.days ?? {});
  });

  // Events
  const stored = await chrome.storage.local.get("events");
  renderEvents(stored.events);
}

render();
