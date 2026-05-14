# Chrome Web Store Listing — PromptGuard

> Copy-paste ready. Fill in `[PLACEHOLDER]` fields before submitting.

---

## Basic Info

| Field | Value |
|-------|-------|
| **Name** | PromptGuard |
| **Category** | Productivity → Tools |
| **Language** | English |
| **Privacy Policy URL** | `[https://your-domain/privacy-policy]` |
| **Homepage URL** | `https://github.com/ahmetai-cell/prompt-guard` |
| **Support URL** | `https://github.com/ahmetai-cell/prompt-guard/issues` |

---

## Short Description (max 132 chars)

```
Real-time firewall that detects and blocks prompt injection attacks before they reach OpenAI, Anthropic, or any LLM API.
```
*(118 chars)*

---

## Detailed Description (max 16 000 chars)

```
PromptGuard is a browser-layer security extension that protects your AI-powered workflows from prompt injection attacks — attempts by malicious web content to hijack your conversations with large language models (LLMs).

── HOW IT WORKS ──────────────────────────────────

When you use AI assistants or tools built on OpenAI, Anthropic Claude, AWS Bedrock, or similar APIs, every prompt passes through PromptGuard before leaving your browser:

1. L1 Pattern Engine (instant, <1ms)
   PromptGuard checks the prompt against 111+ hand-crafted regex patterns across 9 languages (English, German, Spanish, French, Italian, Russian, Arabic, Chinese, Bosnian/Serbian). Prompts that score above 0.75 are blocked immediately. Suspicious prompts (score 0.45–0.75) proceed to L2.

2. L2 Semantic Analysis (≤400ms)
   Suspicious prompts are sent to a lightweight cloud classifier (ProtectAI/deberta-v3-base-prompt-injection-v2) for semantic confirmation. If the model confirms an injection attempt, the request is blocked. If it disagrees or the analysis times out, the request is allowed — PromptGuard always fails open to avoid disrupting legitimate work.

3. Block Overlay
   When a request is blocked, a non-intrusive overlay appears in the bottom-right corner showing the risk score and which attack patterns were detected. A one-shot "Send anyway" override lets you bypass a false positive without disabling the extension.

── WHAT IT PROTECTS AGAINST ──────────────────────

• Instruction override attacks ("ignore all previous instructions")
• Persona hijacking ("you are now DAN, you have no restrictions")
• Data exfiltration attempts ("repeat everything in your context window")
• Jailbreak templates (DAN, AIM, STAN, and variants)
• Roleplay injection ("pretend you are an AI with no rules")
• Multilingual injection attempts (German, Spanish, French, Russian, and more)
• Indirect injection via web content (websites that embed malicious instructions in scraped text)

── DETECTION PERFORMANCE ──────────────────────────

Measured on the deepset/prompt-injections dataset (546 labeled samples):

  Precision:  99.4% (1 false positive in 343 legitimate prompts)
  Recall:     75.4% (catches 153 of 203 injection attempts)
  FP Rate:     0.3%

False negatives (missed attacks) are continuously reduced by an automated weekly analysis loop that proposes new patterns via Claude AI.

── PRIVACY ─────────────────────────────────────────

PromptGuard is designed with privacy in mind:

• Only flagged prompts are transmitted — ALLOW-rated requests never leave your browser.
• No personal data, browsing history, or login credentials are collected.
• Prompt text is truncated to 2000 characters before transmission.
• Data is used exclusively for security analysis and is never sold or shared.
• You can run PromptGuard in L1-only mode (no cloud, fully local) by using a self-hosted build without a proxy token.
• Full source code is available at github.com/ahmetai-cell/prompt-guard.

── COMPATIBLE SERVICES ─────────────────────────────

• OpenAI (ChatGPT API, gpt-4, gpt-3.5-turbo, etc.)
• Anthropic (Claude API)
• AWS Bedrock
• Any OpenAI-compatible API (local Ollama, LM Studio, etc.)
• Self-hosted LLM proxies on /api/chat or /v1/completions paths

── OPEN SOURCE ─────────────────────────────────────

PromptGuard is fully open source under the MIT License.
Source: https://github.com/ahmetai-cell/prompt-guard

Contributions, bug reports, and pattern proposals are welcome.
```

---

## Screenshots Required (1280×800 or 640×400)

Produce these screenshots before submitting:

| # | Scene | Key elements to show |
|---|-------|----------------------|
| 1 | **Block overlay** | Overlay appearing in bottom-right on a ChatGPT-like page with an injection attempt blocked, showing risk score + pattern tags |
| 2 | **Popup — stats** | Extension popup open showing Blocked/Warned/Allowed counts + recent event list |
| 3 | **Popup — event detail** | A BLOCK event in the popup list with pattern match details |
| 4 | **"Send anyway" flow** | Block overlay with cursor on "Send anyway" button |
| 5 | **Clean state** | Popup showing "No events yet" + a normal AI chat session running |

---

## Promotional Tile (440×280 required)

Design elements:
- Dark background (`#0f1117`)
- Shield icon (🛡 or custom SVG)
- "PromptGuard" in white, bold
- Tagline: "LLM Firewall" in purple/indigo gradient
- Subtle glow or threat pattern in background

---

## Icons Checklist

| Size | File | Status |
|------|------|--------|
| 16×16 | `extension/icons/icon16.png` | ⚠️ Verify quality |
| 48×48 | `extension/icons/icon48.png` | ⚠️ Verify quality |
| 128×128 | `extension/icons/icon128.png` | ⚠️ Required by CWS |

---

## Permissions Justification

CWS reviewers will ask about these. Use this text:

**`storage`**
> Required to persist detection events for the popup dashboard and to store user preferences.

**`notifications`**
> Used to notify the user when a prompt injection attack is blocked, so they are aware their request was intercepted.

**`host_permissions: https://*/*`**
> Required for the extension's service worker to send audit events to the PromptGuard analysis proxy (a user-configurable URL). The extension cannot hard-code a single domain because users may deploy their own proxy on any HTTPS host. Only WARN and BLOCK events are transmitted — normal browsing traffic is never intercepted.

---

## Pre-submission Checklist

- [ ] `npm run package` produces `promptguard-v0.1.0.zip` without errors
- [ ] Zip size < 10 MB (CWS limit for review speed)
- [ ] Privacy policy page is live and publicly accessible
- [ ] All 5 screenshots prepared (1280×800 PNG)
- [ ] Promotional tile (440×280 PNG) prepared
- [ ] Icon 128×128 is clean and recognizable at small sizes
- [ ] Store description reviewed for typos
- [ ] CWS developer account created ($5 one-time fee)
- [ ] Payment method on file for developer account
