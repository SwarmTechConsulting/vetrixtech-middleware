import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { compileLinear, linearRegexProblem } from "../src/linearRegex.ts";
import { matchRule, evaluate } from "../src/engine.ts";
import { VirtualPatches } from "../src/defence.ts";

test("agrees with RegExp on rule-style patterns", () => {
  const cases: [string, string[]][] = [
    ["^/api/v[12]/users/\\d+$", ["/api/v1/users/42", "/API/V2/USERS/7", "/api/v3/users/1"]],
    ["(union|select)\\s+", ["UNION all", "selected"]],
    ["\\bor\\b\\s+1=1", ["a or 1=1", "floor 1=1"]],
    ["a{2,3}b", ["aab", "ab"]],
    ["[^a-z]", ["abc", "ab1"]],
    ["(?<v>\\d+)\\.\\d+", ["1.2", "v."]],
  ];
  for (const [p, inputs] of cases) {
    const ours = compileLinear(p);
    const native = new RegExp(p, "i");
    for (const s of inputs) assert.equal(ours.test(s), native.test(s), `${p} on ${s}`);
  }
});

test("a catastrophic rule pattern can't stall a request", () => {
  const rule = { id: "r", name: "evil", type: "pattern", action: "block", active: true, criteria: { path: "^(a+)+$" } };
  const start = Date.now();
  const hit = matchRule(rule as never, { source_ip: "1.2.3.4", path: "/" + "a".repeat(4000) + "!" } as never);
  assert.equal(hit, false);
  assert.ok(Date.now() - start < 1500, "linear time");
  const loose = { ...rule, criteria: { path: "(a+)+$" } };
  const d = evaluate({ source_ip: "1.2.3.4", method: "GET", path: "/aaaa" } as never, { rules: [loose] as never });
  assert.equal(d.verdict, "blocked", "and it still matches what it should");
});

test("a virtual patch with lookahead is reported, not loaded", () => {
  const vp = new VirtualPatches();
  vp.setDependencies({ "lib": "1.0.0" });
  const errors = vp.load([
    { id: "vp-1", package: "lib", affected: "<2.0.0", rule: { pattern: "(?=evil)" } },
    { id: "vp-2", package: "lib", affected: "<2.0.0", rule: { pattern: "(e+)+vil" } },
  ] as never);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /vp-1: lookahead/);
  assert.ok(vp.match({ path: "/x?q=" + "e".repeat(3000) + "vil" }), "nested repeat runs safely");
});

test("refusals say why", () => {
  assert.match(linearRegexProblem("(a)\\1")!, /back-references/);
  assert.equal(linearRegexProblem("^/login$"), null);
});

test("matches the Shield copy when it is checked out next to this repo", () => {
  const shield = new URL("../../swarmtech-shield/base44/shared/linearRegex.ts", import.meta.url);
  if (!existsSync(shield)) return;
  assert.equal(readFileSync(shield, "utf8"), readFileSync(new URL("../src/linearRegex.ts", import.meta.url), "utf8"));
});
