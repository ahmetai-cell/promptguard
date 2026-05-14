import { logEvent, storeEvent, checkL2 } from "./utils/logger.js";

// Stats kept in memory for the popup badge
let sessionStats = { blocked: 0, warned: 0, allowed: 0 };

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {
    case "VERDICT": {
      const { verdict, score, matches, url, prompt } = msg;
      sessionStats[verdict.toLowerCase()] =
        (sessionStats[verdict.toLowerCase()] ?? 0) + 1;
      updateBadge(verdict);

      const event = { verdict, score, matches, url, prompt, tabId: sender.tab?.id };
      storeEvent(event);

      // Log BLOCK verdicts to proxy audit. WARN verdicts that went through
      // L2_CHECK are already logged by the proxy during L2 analysis.
      if (verdict === "BLOCK") {
        logEvent(event);
        showBlockNotification(url, score);
      }
      break;
    }

    case "L2_CHECK": {
      // Content script is holding a WARN request for up to 400ms waiting for
      // this verdict. Return true to keep sendResponse alive for async reply.
      checkL2(msg)
        .then((verdict) => sendResponse({ verdict }))
        .catch(() => sendResponse({ verdict: "ALLOW" }));
      return true;
    }

    case "GET_STATS": {
      sendResponse(sessionStats);
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
