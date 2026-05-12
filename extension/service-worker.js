import { logEvent, storeEvent } from "./utils/logger.js";

// Stats kept in memory for the popup badge
let sessionStats = { blocked: 0, warned: 0, allowed: 0 };

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type !== "VERDICT") return;

  const { verdict, score, matches, url } = msg;

  sessionStats[verdict.toLowerCase()] =
    (sessionStats[verdict.toLowerCase()] ?? 0) + 1;

  updateBadge(verdict);

  const event = { verdict, score, matches, url, tabId: sender.tab?.id };
  storeEvent(event);
  if (verdict === "WARN") logEvent(event);

  if (verdict === "BLOCK") {
    showBlockNotification(url, score);
    logEvent(event);
  }
});

// Popup asks for stats
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "GET_STATS") {
    sendResponse(sessionStats);
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
