/**
 * Thin Node.js bridge: reads a JSON array of prompt strings from stdin,
 * runs each through the L1 detector, and writes results JSON to stdout.
 *
 * Usage: echo '["prompt1","prompt2"]' | node redteam/_l1_bridge.mjs
 */
import { analyzeText } from "../extension/detector/index.js";

const raw = await new Promise((resolve) => {
  let buf = "";
  process.stdin.on("data", (chunk) => { buf += chunk; });
  process.stdin.on("end",  () => resolve(buf));
});

const prompts = JSON.parse(raw);
const results = prompts.map((text) => analyzeText(String(text)));
process.stdout.write(JSON.stringify(results));
