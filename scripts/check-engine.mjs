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
// The engine imports the linear-time matcher, which must be copied alongside it.
const matcher = new URL("linearRegex.ts", new URL(target, `file://${process.cwd()}/`));
try {
  if (hash(new URL("../src/linearRegex.ts", import.meta.url)) !== hash(matcher)) {
    console.error(`Matcher drift: ${matcher.pathname} differs from src/linearRegex.ts. Copy it over.`);
    process.exit(1);
  }
} catch {
  console.error(`Missing ${matcher.pathname}: copy src/linearRegex.ts next to the engine.`);
  process.exit(1);
}
console.log("Engines match.");
