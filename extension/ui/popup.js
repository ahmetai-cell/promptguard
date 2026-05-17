// PromptGuard popup dashboard — vanilla JS (not bundled, no ES imports).

const PROXY_BASE = "https://promptguard-l2-production.up.railway.app";

// ─── Category icons ───────────────────────────────────────────────────────────

const CAT_ICON = {
  "Instruction Override": "🔀",
  "Jailbreak":            "🔓",
  "Bypass Attempt":       "🚧",
  "Dev Mode Trick":       "⚙️",
  "Persona Hijack":       "👤",
  "Data Exfiltration":    "📤",
  "Credential Theft":     "🔑",
  "Encoding Attack":      "🔢",
  "Indirect Injection":   "🔗",
  "Topic Switch":         "↩️",
  "Social Engineering":   "🎭",
  "Translate Trick":      "🌐",
  "Output Manipulation":  "📝",
  "Homoglyph Attack":     "👁",
  "Zero-Width Attack":    "🔡",
  "Unicode Attack":       "🌐",
  "Harmful Request":      "⛔",
};

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
  "override-tr":               "Instruction Override",
  "exfiltration-tr":           "Data Exfiltration",
  "persona-tr":                "Persona Hijack",
  "bypass-tr":                 "Bypass Attempt",
  "jailbreak-tr":              "Jailbreak",
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
    const pct  = Math.max(4, Math.round((count / max) * 100));
    const icon = CAT_ICON[label] ?? "";
    const row  = document.createElement("div");
    row.className = "cat-row";
    row.innerHTML = `
      ${icon ? `<span class="cat-icon">${icon}</span>` : ""}
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

  const W = 348, H = 72, PAD_BOTTOM = 16, BAR_W = 30, GAP = 8;
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

// ─── Attack explanation (mirrors content-script TAG_EXPLAIN) ─────────────────

const TAG_EXPLAIN = {
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

function explainMatches(matches) {
  for (const m of (matches ?? [])) {
    const tag = m.split(":")[1] ?? m;
    if (TAG_EXPLAIN[tag]) return TAG_EXPLAIN[tag];
  }
  return "Prompt injection attempt";
}

function scoreColor(score) {
  if (score >= 0.90) return "#ef4444";
  if (score >= 0.75) return "#f97316";
  return "#eab308";
}

function fmtTs(ts) {
  const d = new Date(ts);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return sameDay ? `Today ${time}` : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + time;
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

    const reason = explainMatches(ev.matches);
    const pct    = Math.round((ev.score ?? 0) * 100);
    const color  = scoreColor(ev.score ?? 0);
    const riskLabel = (ev.score ?? 0) >= 0.90 ? "CRITICAL" : (ev.score ?? 0) >= 0.75 ? "HIGH" : "MEDIUM";

    // Pattern chips — show pattern IDs + category
    const chips = (ev.matches ?? []).slice(0, 5).map((m) => {
      const pid = m.split(":")[0];
      const tag = m.split(":")[1] ?? m;
      const label = CAT_LABEL[tag] ?? tag;
      return `<span class="ev-pattern-chip" title="${label}">${pid}: ${tag}</span>`;
    }).join("");

    // Prompt preview (first 120 chars)
    const promptPreview = ev.prompt
      ? ev.prompt.slice(0, 120) + (ev.prompt.length > 120 ? "…" : "")
      : null;

    el.innerHTML = `
      <div class="ev-row">
        <span class="badge ${ev.verdict}">${ev.verdict} ${pct}%</span>
        <div class="ev-body">
          <div class="ev-url">${shortUrl}</div>
          <div class="ev-reason">${reason}</div>
        </div>
        <span class="ev-age">${ago(ev.ts)}</span>
        <span class="ev-arrow">▶</span>
      </div>
      <div class="ev-detail">
        <div class="ev-detail-row">
          <span class="ev-detail-lbl">Site</span>
          <span class="ev-detail-val">${ev.url ?? "—"}</span>
        </div>
        <div class="ev-detail-row">
          <span class="ev-detail-lbl">Risk</span>
          <div class="ev-score-wrap">
            <div style="display:flex;align-items:center;gap:7px">
              <span class="ev-detail-val" style="color:${color};font-weight:700">${pct}% — ${riskLabel}</span>
              <span class="ev-layer">L1 Pattern Engine</span>
            </div>
            <div class="ev-score-bar-track">
              <div class="ev-score-bar-fill" style="width:${pct}%;background:${color}"></div>
            </div>
          </div>
        </div>
        <div class="ev-detail-row">
          <span class="ev-detail-lbl">Why</span>
          <span class="ev-detail-val">${reason}</span>
        </div>
        ${chips ? `
        <div class="ev-detail-row">
          <span class="ev-detail-lbl">Patterns</span>
          <div class="ev-detail-val">${chips}</div>
        </div>` : ""}
        ${promptPreview ? `
        <div class="ev-detail-row">
          <span class="ev-detail-lbl">Prompt</span>
          <div class="ev-detail-val">
            <div class="ev-prompt-preview">${promptPreview}</div>
          </div>
        </div>` : ""}
        <div class="ev-detail-row">
          <span class="ev-detail-lbl">Time</span>
          <span class="ev-detail-val">${fmtTs(ev.ts)}</span>
        </div>
        ${ev.prompt ? `
        <div class="ev-detail-row" style="margin-top:8px">
          <span class="ev-detail-lbl"></span>
          <div class="ev-detail-val">
            <button class="copy-prompt-btn" data-prompt="${encodeURIComponent(ev.prompt)}">📋 Copy blocked prompt</button>
          </div>
        </div>` : ""}
      </div>
    `;

    // Toggle detail on click
    el.addEventListener("click", (e) => {
      if (e.target.closest(".copy-prompt-btn")) return;
      el.classList.toggle("open");
    });

    // Copy prompt button
    const copyBtn = el.querySelector(".copy-prompt-btn");
    if (copyBtn) {
      copyBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const text = decodeURIComponent(copyBtn.dataset.prompt);
        navigator.clipboard.writeText(text).then(() => {
          copyBtn.textContent = "✓ Copied!";
          setTimeout(() => { copyBtn.textContent = "📋 Copy blocked prompt"; }, 1500);
        });
      });
    }

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

// ─── Gear button (Settings) ───────────────────────────────────────────────────

$("gear-btn").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

// ─── Delta stats ──────────────────────────────────────────────────────────────

function renderDelta(id, todayVal, yesterdayVal) {
  const el = $(id);
  if (!el) return;
  const delta = (todayVal ?? 0) - (yesterdayVal ?? 0);
  if (delta > 0) {
    el.textContent = `+${delta} today`;
    el.className = "delta pos";
  } else if (todayVal > 0) {
    el.textContent = `${todayVal} today`;
    el.className = "delta";
  } else {
    el.textContent = "";
  }
}

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

// ─── Global stats (Supabase via proxy) ───────────────────────────────────────

async function fetchGlobalStats() {
  try {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), 2000);
    const resp = await fetch(`${PROXY_BASE}/stats/aggregate`, { signal: ctrl.signal });
    clearTimeout(tid);
    if (!resp.ok) return;
    const data = await resp.json();
    const totals = data.totals ?? {};
    const blocked = totals.blocked ?? 0;
    const total   = totals.total   ?? 0;
    if (total === 0) return;
    $("g-blocked").textContent = fmt(blocked);
    $("g-total").textContent   = fmt(total);
    $("global-strip").style.display = "flex";
  } catch {
    // fail-open: proxy unreachable or timed out — hide strip silently
  }
}

// ─── Session state pill ───────────────────────────────────────────────────────

function renderSessionState() {
  chrome.runtime.sendMessage({ type: "GET_SESSION_STATE" }, (r) => {
    if (chrome.runtime.lastError) return;
    const pill  = $("session-pill");
    const label = $("session-label");
    const risk  = $("session-risk");
    const sess  = r?.session;

    if (!sess) {
      pill.className = "session-pill unknown";
      label.textContent = "No activity";
      risk.textContent = "";
      return;
    }

    const stateMap = {
      SAFE:       { cls: "safe",       txt: "Safe"       },
      SUSPICIOUS: { cls: "suspicious", txt: "Suspicious" },
      ACTIVE:     { cls: "active",     txt: "Active Threat" },
    };
    const s = stateMap[sess.state] ?? { cls: "unknown", txt: sess.state ?? "—" };
    pill.className = `session-pill ${s.cls}`;
    label.textContent = s.txt;
    risk.textContent  = `risk ${(sess.risk * 100).toFixed(0)}%`;
  });
}

// ─── Main render ──────────────────────────────────────────────────────────────

async function render() {
  // Local stats
  chrome.runtime.sendMessage({ type: "GET_STATS" }, (stats) => {
    if (chrome.runtime.lastError || !stats) return;
    $("s-blocked").textContent = fmt(stats.totals?.blocked ?? 0);
    $("s-warned").textContent  = fmt(stats.totals?.warned  ?? 0);
    $("s-scanned").textContent = fmt(stats.totals?.scanned ?? 0);

    // Delta stats: today vs yesterday
    const todayKey = new Date().toISOString().slice(0, 10);
    const yday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const today = stats.days?.[todayKey] ?? {};
    const yesterday = stats.days?.[yday] ?? {};
    renderDelta("d-blocked", today.blocked, yesterday.blocked);
    renderDelta("d-warned",  today.warned,  yesterday.warned);
    renderDelta("d-scanned", (today.blocked ?? 0) + (today.warned ?? 0), null);

    _statsCache = stats;
    applyPeriod();
    renderChart(stats.days ?? {});
  });

  // Events
  const stored = await chrome.storage.local.get("events");
  renderEvents(stored.events);

  // Global stats (non-blocking)
  fetchGlobalStats();

  // Session state
  renderSessionState();
}

render();
