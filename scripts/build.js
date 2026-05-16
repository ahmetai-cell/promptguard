/**
 * PromptGuard Extension Build Script
 *
 * Bundles ES-module source files into a Chrome MV3-compatible dist/.
 * Content scripts run in MAIN world and cannot use native ES imports
 * — esbuild inlines all dependencies into a single IIFE per entry point.
 *
 * Usage:
 *   node scripts/build.js           # development (source maps, no minify)
 *   node scripts/build.js --prod    # production  (minified, no source maps)
 *   node scripts/build.js --watch   # dev + watch mode
 */

import * as esbuild from "esbuild";
import {
  cpSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  rmSync,
  existsSync,
} from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT  = join(__dirname, "..");
const SRC   = join(ROOT, "extension");
const DIST  = join(ROOT, "dist");

const isProd  = process.argv.includes("--prod");
const isWatch = process.argv.includes("--watch");

// ─── Clean ────────────────────────────────────────────────────────────────────

if (existsSync(DIST)) rmSync(DIST, { recursive: true });
mkdirSync(join(DIST, "ui"),    { recursive: true });
mkdirSync(join(DIST, "icons"), { recursive: true });

// ─── Shared esbuild options ───────────────────────────────────────────────────

// PG_TOKEN is baked in at build time. Set the env var before building:
//   PG_TOKEN=your_secret npm run build
// Omitting PG_TOKEN produces a bundle without auth (dev/test builds are fine).
const pgToken = process.env.PG_TOKEN ?? "";

const BASE = {
  bundle:    true,
  platform:  "browser",
  target:    ["chrome110"],
  sourcemap: isProd ? false : "inline",
  minify:    isProd,
  logLevel:  "info",
  define: {
    PG_TOKEN: JSON.stringify(pgToken),
  },
};

// ─── Entry points ─────────────────────────────────────────────────────────────

const entries = [
  {
    // Content script: MUST be IIFE — MAIN world has no native module support
    entryPoints: [join(SRC, "content-script.js")],
    outfile: join(DIST, "content-script.js"),
    format: "iife",
    // chrome.* is a global injected by the browser; don't try to bundle it
    external: [],
  },
  {
    // Service worker: IIFE so manifest doesn't need "type":"module"
    entryPoints: [join(SRC, "service-worker.js")],
    outfile: join(DIST, "service-worker.js"),
    format: "iife",
  },
];

// ─── Build or Watch ───────────────────────────────────────────────────────────

async function build() {
  if (isWatch) {
    // Watch mode: keep contexts alive, rebuild on change
    const ctxs = await Promise.all(
      entries.map((e) => esbuild.context({ ...BASE, ...e }))
    );
    await Promise.all(ctxs.map((ctx) => ctx.watch()));
    console.log("👁  Watching for changes in extension/...");
  } else {
    await Promise.all(entries.map((e) => esbuild.build({ ...BASE, ...e })));
  }

  // ─── Copy static assets (only on initial build) ───────────────────────────

  // popup.js and relay.js use only chrome.* and DOM globals — no bundling needed
  cpSync(join(SRC, "ui"),    join(DIST, "ui"),    { recursive: true });
  cpSync(join(SRC, "icons"), join(DIST, "icons"), { recursive: true });
  cpSync(join(SRC, "relay.js"), join(DIST, "relay.js"));

  // ─── Generate dist/manifest.json ─────────────────────────────────────────
  // Remove "type":"module" from background — bundled SW is plain IIFE script

  const manifest = JSON.parse(readFileSync(join(SRC, "manifest.json"), "utf8"));
  delete manifest.background.type;

  writeFileSync(
    join(DIST, "manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n"
  );

  if (!isWatch) {
    console.log("\n✅  Build complete →", DIST);
    console.log("    Load dist/ as an unpacked extension in chrome://extensions");
  }
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
