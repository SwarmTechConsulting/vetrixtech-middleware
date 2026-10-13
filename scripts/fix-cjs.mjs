// Post-build fixes:
// 1. Mark the CommonJS build so Node treats its .js files as CommonJS inside a "type": "module" package.
// 2. Point relative imports in .d.ts files at .js (tsc keeps the source .ts extension there).
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dist = fileURLToPath(new URL("../dist", import.meta.url));
writeFileSync(join(dist, "cjs", "package.json"), JSON.stringify({ type: "commonjs" }) + "\n");

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (p.endsWith(".d.ts")) {
      const src = readFileSync(p, "utf8");
      const out = src.replace(/(from\s+["'])(\.{1,2}\/[^"']+)\.ts(["'])/g, "$1$2.js$3");
      if (out !== src) writeFileSync(p, out);
    }
  }
}
walk(dist);
