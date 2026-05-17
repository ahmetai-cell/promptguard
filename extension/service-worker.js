import { logEvent, storeEvent, checkL2 } from "./utils/logger.js";
import { recordStats, getStats, clearStats } from "./utils/stats.js";

// Extension enabled state — persisted to storage, cached in memory
let _enabled = true;
chrome.storage.local.get("pg_enabled", (r) => {
  _enabled = r.pg_enabled ?? true;
});

// Open onboarding on first install
chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL("ui/onboarding.html") });
  }
});

// Session state per tab — updated by SAGE_STATE verdicts from content-script
const _tabSessionState = new Map();   // tabId → { state, risk, ts }

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {
    case "VERDICT": {
      const { verdict, score, matches, url, prompt } = msg;

      // SAGE_STATE is a special internal verdict — store it, don't log as event
      if (verdict === "SAGE_STATE") {
        const tabId = sender.tab?.id;
        if (tabId != null) {
          _tabSessionState.set(tabId, { state: matches[0], risk: score, ts: Date.now() });
        }
        sendResponse({ ok: true });
        return true;
      }

      updateBadge(verdict);

      const event = { verdict, score, matches, url, prompt, tabId: sender.tab?.id };
      storeEvent(event);

      // return true keeps the port open so the service worker stays alive
      // until the async storage write in recordStats completes
      recordStats({ verdict, matches })
        .then(() => sendResponse({ ok: true }))
        .catch(() => sendResponse({ ok: false }));

      if (verdict === "BLOCK") {
        logEvent(event);
        if (_enabled) showBlockNotification(url, score);
      }
      return true;
    }

    case "L2_CHECK": {
      checkL2(msg)
        .then((verdict) => sendResponse({ verdict }))
        .catch(() => sendResponse({ verdict: "ALLOW" }));
      return true;
    }

    case "GET_STATS": {
      getStats().then(sendResponse);
      return true;
    }

    case "GET_SETTINGS": {
      chrome.storage.local.get("pg_settings", (r) => {
        sendResponse({ settings: r.pg_settings ?? {} });
      });
      return true;
    }

    case "CLEAR_STATS": {
      clearStats();
      chrome.storage.local.remove("events");
      break;
    }

    case "GET_ENABLED": {
      sendResponse({ enabled: _enabled });
      break;
    }

    case "GET_SESSION_STATE": {
      // Popup asks for the current tab's SAGE session state
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tabId = tabs[0]?.id;
        const sess = tabId != null ? (_tabSessionState.get(tabId) ?? null) : null;
        sendResponse({ session: sess });
      });
      return true;
    }

    case "SET_ENABLED": {
      _enabled = msg.enabled;
      chrome.storage.local.set({ pg_enabled: msg.enabled });
      chrome.action.setBadgeText({ text: msg.enabled ? "" : "OFF" });
      chrome.action.setBadgeBackgroundColor({ color: msg.enabled ? "#e53e3e" : "#475569" });
      // Broadcast to all content scripts
      chrome.tabs.query({}, (tabs) => {
        for (const tab of tabs) {
          chrome.tabs.sendMessage(tab.id, { type: "PG_ENABLED", enabled: msg.enabled })
            .catch(() => {});
        }
      });
      break;
    }
  }
});

function updateBadge(verdict) {
  if (verdict === "BLOCK") {
    chrome.action.setBadgeText({ text: "🛑" });
    chrome.action.setBadgeBackgroundColor({ color: "#e53e3e" });
  } else if (verdict === "WARN") {
    chrome.action.setBadgeText({ text: "⚠" });
    chrome.action.setBadgeBackgroundColor({ color: "#dd6b20" });
  }
  // Reset badge after 4 seconds
  setTimeout(() => chrome.action.setBadgeText({ text: "" }), 4000);
}

function showBlockNotification(url, score) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon48.png",
    title: "PromptGuard: Injection Blocked",
    message: `A prompt injection attack was blocked. Score: ${score}`,
    priority: 2,
  });
}
