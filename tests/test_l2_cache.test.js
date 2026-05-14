import { describe, it, expect, beforeEach, vi } from "vitest";

// ─── Mock chrome.storage.local ────────────────────────────────────────────────
// Simulate the chrome.storage.local API with an in-memory store.

let _store = {};

const chromeMock = {
  storage: {
    local: {
      get: vi.fn(async (key) => ({ [key]: _store[key] })),
      set: vi.fn(async (obj) => { Object.assign(_store, obj); }),
      remove: vi.fn(async (key) => { delete _store[key]; }),
    },
  },
};

vi.stubGlobal("chrome", chromeMock);

// Import AFTER stubbing chrome
const { cacheGet, cacheSet, cacheClear, _hash } = await import("../extension/utils/cache.js");

// ─── Helpers ──────────────────────────────────────────────────────────────────

beforeEach(() => {
  _store = {};
  vi.clearAllMocks();
});

// ─── _hash ────────────────────────────────────────────────────────────────────

describe("_hash", () => {
  it("returns a non-empty string", () => {
    expect(typeof _hash("hello")).toBe("string");
    expect(_hash("hello").length).toBeGreaterThan(0);
  });

  it("is deterministic", () => {
    expect(_hash("ignore all previous instructions")).toBe(
      _hash("ignore all previous instructions")
    );
  });

  it("differs for different inputs", () => {
    expect(_hash("foo")).not.toBe(_hash("bar"));
  });

  it("handles empty string without throwing", () => {
    expect(() => _hash("")).not.toThrow();
  });
});

// ─── cacheGet — miss ─────────────────────────────────────────────────────────

describe("cacheGet — miss", () => {
  it("returns null when cache is empty", async () => {
    expect(await cacheGet("some prompt")).toBeNull();
  });

  it("returns null for prompt not in cache", async () => {
    await cacheSet("other prompt", "BLOCK");
    expect(await cacheGet("some prompt")).toBeNull();
  });
});

// ─── cacheGet / cacheSet — hit ────────────────────────────────────────────────

describe("cacheGet / cacheSet — hit", () => {
  it("returns BLOCK after storing BLOCK", async () => {
    await cacheSet("inject me", "BLOCK");
    expect(await cacheGet("inject me")).toBe("BLOCK");
  });

  it("returns ALLOW after storing ALLOW", async () => {
    await cacheSet("safe prompt", "ALLOW");
    expect(await cacheGet("safe prompt")).toBe("ALLOW");
  });

  it("overwrites an existing entry", async () => {
    await cacheSet("flip", "ALLOW");
    await cacheSet("flip", "BLOCK");
    expect(await cacheGet("flip")).toBe("BLOCK");
  });
});

// ─── TTL expiry ───────────────────────────────────────────────────────────────

describe("cacheGet — TTL expiry", () => {
  it("returns null for an expired entry and removes it", async () => {
    const STORE_KEY = "_pg_l2_cache";
    const key = _hash("old prompt");

    // Manually inject an already-expired entry
    _store[STORE_KEY] = { [key]: { verdict: "BLOCK", expires: Date.now() - 1000 } };

    expect(await cacheGet("old prompt")).toBeNull();

    // Entry should have been lazily removed
    const stored = _store[STORE_KEY] ?? {};
    expect(stored[key]).toBeUndefined();
  });

  it("returns the verdict for a non-expired entry", async () => {
    const STORE_KEY = "_pg_l2_cache";
    const key = _hash("fresh prompt");

    _store[STORE_KEY] = { [key]: { verdict: "ALLOW", expires: Date.now() + 60_000 } };

    expect(await cacheGet("fresh prompt")).toBe("ALLOW");
  });
});

// ─── MAX_ENTRIES eviction ─────────────────────────────────────────────────────

describe("cacheSet — eviction", () => {
  it("caps cache at 500 entries", async () => {
    // Fill 501 unique prompts
    for (let i = 0; i < 501; i++) {
      await cacheSet(`prompt-${i}`, "ALLOW");
    }
    const stored = _store["_pg_l2_cache"] ?? {};
    expect(Object.keys(stored).length).toBeLessThanOrEqual(500);
  });

  it("evicts oldest (soonest-expiring) entries first", async () => {
    const STORE_KEY = "_pg_l2_cache";

    // Seed cache with 500 entries expiring far in the future
    const initial = {};
    for (let i = 0; i < 500; i++) {
      initial[_hash(`base-${i}`)] = { verdict: "ALLOW", expires: Date.now() + 100_000 + i };
    }
    _store[STORE_KEY] = initial;

    // The oldest entry has the smallest expires value
    const oldestKey = _hash("base-0");

    // Adding one more triggers eviction
    await cacheSet("new-prompt", "BLOCK");

    const stored = _store[STORE_KEY] ?? {};
    expect(stored[oldestKey]).toBeUndefined();  // oldest evicted
    expect(stored[_hash("new-prompt")]).toBeDefined();  // new entry present
  });
});

// ─── cacheClear ───────────────────────────────────────────────────────────────

describe("cacheClear", () => {
  it("removes all cached entries", async () => {
    await cacheSet("a", "BLOCK");
    await cacheSet("b", "ALLOW");
    await cacheClear();
    expect(await cacheGet("a")).toBeNull();
    expect(await cacheGet("b")).toBeNull();
  });
});

// ─── Edge cases ───────────────────────────────────────────────────────────────

describe("edge cases", () => {
  it("cacheGet returns null for empty prompt", async () => {
    expect(await cacheGet("")).toBeNull();
  });

  it("cacheSet is a no-op for empty prompt", async () => {
    await cacheSet("", "BLOCK");
    expect(chromeMock.storage.local.set).not.toHaveBeenCalled();
  });
});
