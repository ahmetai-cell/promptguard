/**
 * PromptGuard Packaging Script
 *
 * Produces a CWS-ready zip from the production build.
 * Run after: npm run build:prod
 *
 * Usage:
 *   npm run package          # build:prod then zip
 *   node scripts/package.js  # zip only (build must already exist)
 */

import { execSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const DIST = join(ROOT, "dist");

const { version } = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const OUT = join(ROOT, `promptguard-v${version}.zip`);

// ─── Verify dist exists ───────────────────────────────────────────────────────

if (!existsSync(DIST)) {
  console.error("❌  dist/ not found — run npm run build:prod first");
  process.exit(1);
}

const required = ["manifest.json", "content-script.js", "service-worker.js"];
for (const f of required) {
  if (!existsSync(join(DIST, f))) {
    console.error(`❌  dist/${f} missing — run npm run build:prod first`);
    process.exit(1);
  }
}

// ─── Verify manifest has no "type":"module" in background ────────────────────

const mf = JSON.parse(readFileSync(join(DIST, "manifest.json"), "utf8"));
if (mf.background?.type) {
  console.error('❌  dist/manifest.json still has background.type — build issue');
  process.exit(1);
}

// ─── Create zip ───────────────────────────────────────────────────────────────

try {
  execSync(`cd "${DIST}" && zip -r "${OUT}" . --exclude "*.map"`, { stdio: "inherit" });
} catch {
  console.error("❌  zip failed — ensure zip is installed (brew install zip on macOS)");
  process.exit(1);
}

const { size } = (await import("fs")).statSync(OUT);
const kb = (size / 1024).toFixed(1);

console.log(`
📦  Package ready: promptguard-v${version}.zip  (${kb} KB)

Next steps:
  1. Go to https://chrome.google.com/webstore/devconsole/
  2. New item → Upload ZIP → select promptguard-v${version}.zip
  3. Fill in store listing from docs/store-listing.md
  4. Add privacy policy URL (host docs/privacy-policy.md on GitHub Pages)
  5. Submit for review
`);
