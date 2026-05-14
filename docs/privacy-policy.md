# PromptGuard Privacy Policy

**Last updated: 2026-05-14**

## Overview

PromptGuard is a browser extension that protects you from prompt injection attacks — attempts by malicious content on web pages to hijack your conversations with AI assistants. This policy explains what data is collected, why, and how it is handled.

---

## What Data Is Collected

When PromptGuard detects a suspicious prompt, it may collect and transmit the following:

| Field | Description | When collected |
|-------|-------------|----------------|
| `ts` | Unix timestamp of the event | Every flagged request |
| `url` | URL of the LLM API endpoint called (e.g. `https://api.openai.com/v1/chat/completions`) | Every flagged request |
| `verdict` | Detection result: `WARN` or `BLOCK` | Every flagged request |
| `score` | Numerical risk score (0–1) | Every flagged request |
| `matches` | Pattern IDs that triggered (e.g. `["P001:override"]`) | Every flagged request |
| `prompt` | The user's prompt text (truncated to 2000 characters) | Only for `WARN`-level events sent to L2 analysis |
| `ua` | Your browser's user-agent string (first 120 characters) | Only for L2 analysis requests |

**PromptGuard does NOT collect:**
- Your name, email, or any account information
- Browsing history unrelated to LLM API calls
- Contents of LLM API responses
- Data from non-LLM websites

---

## Where Data Goes

Data is sent to the **PromptGuard L2 proxy**, a server operated by the extension developer, hosted on [Railway](https://railway.app). The proxy:

1. Runs a semantic ML classifier (ProtectAI/deberta-v3-base-prompt-injection-v2) to confirm whether the flagged prompt is a genuine injection attempt.
2. Returns a final verdict (BLOCK or ALLOW) within 400 milliseconds.
3. Writes an audit log entry to a PostgreSQL database (Supabase) for security analysis.

The proxy endpoint is: `https://promptguard-l2-production.up.railway.app`

**Data is never:**
- Sold to third parties
- Used for advertising
- Shared with LLM providers (OpenAI, Anthropic, etc.)

---

## Data Retention

- **Audit log entries** are retained for up to **90 days** for security analysis and model improvement.
- No prompt text is retained beyond the L2 classifier analysis unless explicitly configured by a self-hosted deployment.
- Session statistics (blocked/warned/allowed counts) are stored locally in `chrome.storage.local` and cleared when you clear extension data.

---

## Local Storage

PromptGuard stores the following locally in your browser (never transmitted):
- **Recent events** (`chrome.storage.local`): last 50 detection events for the popup display. You can clear these at any time via the extension popup's "Clear" button.
- **Override flag** (`sessionStorage`): a single-use flag set when you click "Send anyway" in the block overlay. Cleared after one use or when you close the tab.

---

## Self-Hosting

If you deploy your own PromptGuard proxy (open source at [github.com/ahmetai-cell/prompt-guard](https://github.com/ahmetai-cell/prompt-guard)), you control all data storage. In that case, this policy applies only to the default developer-operated proxy.

---

## Your Rights

- You can **disable L2 analysis** by not configuring a proxy (run the extension in L1-only mode by building without a `PG_TOKEN`).
- You can **clear all local data** via Chrome → Extensions → PromptGuard → Clear storage.
- You can **uninstall** the extension at any time to stop all data collection.

---

## Contact

For privacy concerns or data deletion requests:  
**Email:** [your-email@example.com]  
**GitHub Issues:** https://github.com/ahmetai-cell/prompt-guard/issues

---

## Changes to This Policy

We will update this policy as the extension evolves. The date at the top reflects the most recent revision. Significant changes will be announced via the extension's GitHub repository.
