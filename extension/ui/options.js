// PromptGuard Settings Page

const DEFAULT_PROXY = "https://promptguard-l2-production.up.railway.app";

const DEFAULT_SETTINGS = {
  blockThreshold: 0.75,
  warnThreshold:  0.45,
  l2Enabled:      true,
  l3Enabled:      true,
  whitelist:      [],
  proxyUrl:       DEFAULT_PROXY,
};

let _settings = { ...DEFAULT_SETTINGS };

// ─── Load ─────────────────────────────────────────────────────────────────────

async function load() {
  const stored = await chrome.storage.local.get("pg_settings");
  _settings = { ...DEFAULT_SETTINGS, ...(stored.pg_settings ?? {}) };
  applyToUI();
}

function applyToUI() {
  const blockPct = Math.round(_settings.blockThreshold * 100);
  const warnPct  = Math.round(_settings.warnThreshold  * 100);

  document.getElementById("block-slider").value = blockPct;
  document.getElementById("warn-slider").value  = warnPct;
  document.getElementById("block-val").textContent = _settings.blockThreshold.toFixed(2);
  document.getElementById("warn-val").textContent  = _settings.warnThreshold.toFixed(2);

  document.getElementById("l2-toggle").checked = _settings.l2Enabled;
  document.getElementById("l3-toggle").checked = _settings.l3Enabled;

  document.getElementById("proxy-input").value = _settings.proxyUrl ?? DEFAULT_PROXY;

  renderChips();
}

// ─── Whitelist chips ──────────────────────────────────────────────────────────

function renderChips() {
  const container = document.getElementById("chips-container");
  const noMsg     = document.getElementById("no-domains-msg");
  const list      = _settings.whitelist ?? [];

  // Remove existing chips (but not the no-domains-msg node)
  container.querySelectorAll(".chip").forEach((c) => c.remove());

  if (list.length === 0) {
    noMsg.style.display = "";
    return;
  }
  noMsg.style.display = "none";

  for (const domain of list) {
    const chip = document.createElement("div");
    chip.className = "chip";
    chip.innerHTML = `<span>${domain}</span><button class="chip-x" data-domain="${domain}" title="Remove">✕</button>`;
    chip.querySelector(".chip-x").addEventListener("click", (e) => {
      const d = e.currentTarget.dataset.domain;
      _settings.whitelist = _settings.whitelist.filter((x) => x !== d);
      renderChips();
    });
    container.appendChild(chip);
  }
}

document.getElementById("add-domain-btn").addEventListener("click", () => {
  const input = document.getElementById("domain-input");
  const raw   = input.value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!raw || _settings.whitelist.includes(raw)) { input.value = ""; return; }
  _settings.whitelist = [...(_settings.whitelist ?? []), raw];
  renderChips();
  input.value = "";
});

document.getElementById("domain-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("add-domain-btn").click();
});

// ─── Sliders ─────────────────────────────────────────────────────────────────

document.getElementById("block-slider").addEventListener("input", (e) => {
  const v = parseInt(e.target.value) / 100;
  _settings.blockThreshold = v;
  document.getElementById("block-val").textContent = v.toFixed(2);
  // Ensure warn < block
  if (_settings.warnThreshold >= v) {
    _settings.warnThreshold = Math.max(0.30, v - 0.10);
    document.getElementById("warn-slider").value = Math.round(_settings.warnThreshold * 100);
    document.getElementById("warn-val").textContent = _settings.warnThreshold.toFixed(2);
  }
});

document.getElementById("warn-slider").addEventListener("input", (e) => {
  const v = parseInt(e.target.value) / 100;
  _settings.warnThreshold = Math.min(v, _settings.blockThreshold - 0.10);
  document.getElementById("warn-val").textContent = _settings.warnThreshold.toFixed(2);
  document.getElementById("warn-slider").value = Math.round(_settings.warnThreshold * 100);
});

// ─── Proxy URL ────────────────────────────────────────────────────────────────

document.getElementById("reset-proxy-btn").addEventListener("click", () => {
  document.getElementById("proxy-input").value = DEFAULT_PROXY;
  _settings.proxyUrl = DEFAULT_PROXY;
});

// ─── Toggles ─────────────────────────────────────────────────────────────────

document.getElementById("l2-toggle").addEventListener("change", (e) => {
  _settings.l2Enabled = e.target.checked;
});
document.getElementById("l3-toggle").addEventListener("change", (e) => {
  _settings.l3Enabled = e.target.checked;
});

// ─── Save ─────────────────────────────────────────────────────────────────────

document.getElementById("save-btn").addEventListener("click", async () => {
  _settings.proxyUrl = document.getElementById("proxy-input").value.trim() || DEFAULT_PROXY;
  await chrome.storage.local.set({ pg_settings: _settings });

  const toast = document.getElementById("save-toast");
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2000);
});

// ─── Clear data ───────────────────────────────────────────────────────────────

document.getElementById("clear-data-btn").addEventListener("click", async () => {
  if (!confirm("Clear all detection history and stats? This cannot be undone.")) return;
  await chrome.storage.local.remove(["events", "pg_stats"]);
  alert("Detection history cleared.");
});

// ─── Init ─────────────────────────────────────────────────────────────────────

load();
