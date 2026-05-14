/**
 * PromptGuard L2 verdict cache — chrome.storage.local backed.
 *
 * Caches final_verdict per prompt so repeated identical requests skip
 * the proxy entirely (~300 ms → <5 ms for cache hits).
 *
 * TTL: 24 h   Max entries: 500 (evicts oldest on overflow)
 * Storage key: _pg_l2_cache  →  { [hash]: { verdict, expires } }
 *
 * Falls back to a no-op when chrome.storage is unavailable
 * (Node test environment, private-browsing edge cases).
 */

const STORE_KEY  = "_pg_l2_cache";
const TTL_MS     = 24 * 60 * 60 * 1000;   // 24 h
const MAX_ENTRIES = 500;

// Guard for non-extension environments (Node tests, etc.)
const _storage =
  typeof chrome !== "undefined" && chrome.storage?.local
    ? chrome.storage.local
    : null;

// ─── Hash ─────────────────────────────────────────────────────────────────────
// djb2 variant — fast, sync, good distribution for short strings

function _hash(text) {
  let h = 5381;
  for (let i = 0; i < text.length; i++) {
    h = ((h << 5) + h) ^ text.charCodeAt(i);
    h = h >>> 0;   // keep unsigned 32-bit
  }
  return h.toString(36);   // ~7-char base-36 string
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Look up a cached L2 verdict for the given prompt.
 * Returns "BLOCK" | "ALLOW" on hit, null on miss or error.
 *
 * @param {string} prompt
 * @returns {Promise<"BLOCK" | "ALLOW" | null>}
 */
export async function cacheGet(prompt) {
  if (!_storage || !prompt) return null;
  try {
    const stored = await _storage.get(STORE_KEY);
    const cache  = stored[STORE_KEY] ?? {};
    const key    = _hash(prompt);
    const entry  = cache[key];

    if (!entry) return null;

    if (Date.now() > entry.expires) {
      // Lazy eviction of expired entry
      delete cache[key];
      await _storage.set({ [STORE_KEY]: cache });
      return null;
    }

    return entry.verdict;
  } catch {
    return null;
  }
}

/**
 * Store an L2 verdict for the given prompt.
 * Evicts the oldest entries when MAX_ENTRIES is exceeded.
 *
 * @param {string} prompt
 * @param {"BLOCK" | "ALLOW"} verdict
 */
export async function cacheSet(prompt, verdict) {
  if (!_storage || !prompt) return;
  try {
    const stored = await _storage.get(STORE_KEY);
    let cache    = stored[STORE_KEY] ?? {};
    const key    = _hash(prompt);

    cache[key] = { verdict, expires: Date.now() + TTL_MS };

    // Evict oldest entries when over limit
    const entries = Object.entries(cache);
    if (entries.length > MAX_ENTRIES) {
      entries.sort((a, b) => a[1].expires - b[1].expires);
      cache = Object.fromEntries(entries.slice(entries.length - MAX_ENTRIES));
    }

    await _storage.set({ [STORE_KEY]: cache });
  } catch {
    // storage write failed — silent, next request will re-populate
  }
}

/**
 * Clear all cached verdicts (useful for testing and user "clear data").
 */
export async function cacheClear() {
  if (!_storage) return;
  try {
    await _storage.remove(STORE_KEY);
  } catch { /* ignore */ }
}

// Exported for unit tests
export { _hash };
