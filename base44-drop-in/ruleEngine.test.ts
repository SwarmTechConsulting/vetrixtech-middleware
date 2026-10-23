// Run in the Base44 project with:  deno test --allow-read base44/shared/ruleEngine.test.ts
// Uses the same vectors.json as the @swarmtechshield/middleware package, so both engines must agree.
import { evaluate } from "./ruleEngine.ts";

const file = JSON.parse(await Deno.readTextFile(new URL("./vectors.json", import.meta.url)));
const now = Date.parse(file.now);

function fail(msg: string): never {
  throw new Error(msg);
}

for (const v of file.vectors) {
  Deno.test(`[${v.plan_item}] ${v.name}`, () => {
    const counts = v.counts as Record<string, number> | undefined;
    const d = evaluate(v.request, {
      rules: v.rules,
      blocklist: v.blocklist,
      now,
      rateCount: counts ? (win: number) => counts[String(win)] ?? counts.default ?? 0 : undefined,
    });
    if (d.verdict !== v.expected.verdict) fail(`verdict ${d.verdict}, expected ${v.expected.verdict}`);
    if (v.expected.triggered !== undefined && d.triggered?.name !== v.expected.triggered) {
      fail(`triggered ${d.triggered?.name}, expected ${v.expected.triggered}`);
    }
    if (v.expected.auto_block !== undefined && (d.autoBlock?.type ?? null) !== v.expected.auto_block) {
      fail(`auto_block ${d.autoBlock?.type}, expected ${v.expected.auto_block}`);
    }
    if (d.trace[d.trace.length - 1].action !== d.verdict) fail("trace disagrees with verdict");
  });
}
