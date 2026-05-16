/**
 * Persistent stats for popup dashboard.
 *
 * Schema (chrome.storage.local key "pg_stats"):
 * {
 *   totals:     { blocked, warned, scanned },
 *   categories: { [tag]: count },            // all-time
 *   days: {
 *     "YYYY-MM-DD": { blocked, warned, categories: { [tag]: count } }
 *   }
 * }
 */

const STATS_KEY = "pg_stats";
const MAX_DAYS  = 8;

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

export async function recordStats({ verdict, matches = [] }) {
  let stored;
  try {
    stored = await chrome.storage.local.get(STATS_KEY);
  } catch {
    return;
  }

  const s = stored[STATS_KEY] ?? { totals: {}, categories: {}, days: {} };
  s.totals.scanned = (s.totals.scanned ?? 0) + 1;
  if (verdict === "BLOCK") s.totals.blocked = (s.totals.blocked ?? 0) + 1;
  if (verdict === "WARN")  s.totals.warned  = (s.totals.warned  ?? 0) + 1;

  // Extract tags from "P009:persona" match strings
  const tags = matches
    .map((m) => m.split(":")[1])
    .filter(Boolean)
    .filter((t) => !t.startsWith("suspicious"));

  for (const tag of tags) {
    s.categories[tag] = (s.categories[tag] ?? 0) + 1;
  }

  const today = todayKey();
  if (!s.days[today]) s.days[today] = { blocked: 0, warned: 0, categories: {} };
  const day = s.days[today];
  if (verdict === "BLOCK") day.blocked++;
  if (verdict === "WARN")  day.warned++;
  for (const tag of tags) {
    day.categories[tag] = (day.categories[tag] ?? 0) + 1;
  }

  // Keep only last MAX_DAYS
  const dayKeys = Object.keys(s.days).sort();
  while (dayKeys.length > MAX_DAYS) delete s.days[dayKeys.shift()];

  try {
    await chrome.storage.local.set({ [STATS_KEY]: s });
  } catch { /* ignore */ }
}

export async function getStats() {
  try {
    const stored = await chrome.storage.local.get(STATS_KEY);
    return stored[STATS_KEY] ?? { totals: {}, categories: {}, days: {} };
  } catch {
    return { totals: {}, categories: {}, days: {} };
  }
}

export async function clearStats() {
  try {
    await chrome.storage.local.remove(STATS_KEY);
  } catch { /* ignore */ }
}
