// Fails if the Base44 copy of the engine differs from this package's engine.
// Usage: node scripts/check-engine.mjs /path/to/base44-app/base44/shared/ruleEngine.ts
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const target = process.argv[2];
if (!target) {
  console.error("Usage: node scripts/check-engine.mjs <path to base44/shared/ruleEngine.ts>");
  process.exit(2);
}
const hash = (p) => createHash("sha256").update(readFileSync(p, "utf8").replace(/\r\n/g, "\n")).digest("hex");
const a = hash(new URL("../src/engine.ts", import.meta.url));
const b = hash(target);
if (a !== b) {
  console.error(`Engine drift: ${target} differs from src/engine.ts. Copy src/engine.ts over it (and test/vectors.json next to it).`);
  process.exit(1);
}
console.log("Engines match.");
