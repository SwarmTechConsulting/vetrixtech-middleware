import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  evaluate,
  ipMatches,
  isValidIpSpec,
  normalizePath,
  explainRule,
  detectConflicts,
  matchRule,
  traceRequest,
  ipToInt,
  type RateCounter,
} from "../src/engine.ts";

interface Vector {
  name: string;
  plan_item: string;
  request: Record<string, unknown>;
  rules?: unknown[];
  blocklist?: unknown[];
  counts?: Record<string, number>;
  expected: { verdict: string; triggered?: string; auto_block?: string | null; observed?: string[] };
}

const file = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const now = Date.parse(file.now);

function counterFrom(counts?: Record<string, number>): RateCounter | undefined {
  if (!counts) return undefined;
  return (win) => counts[String(win)] ?? counts.default ?? 0;
}

for (const v of file.vectors as Vector[]) {
  test(`vector [${v.plan_item}] ${v.name}`, () => {
    const d = evaluate(v.request as never, {
      rules: v.rules as never,
      blocklist: v.blocklist as never,
      now,
      rateCount: counterFrom(v.counts),
    });
    assert.equal(d.verdict, v.expected.verdict, `verdict; trace: ${JSON.stringify(d.trace, null, 1)}`);
    if (v.expected.triggered !== undefined) assert.equal(d.triggered?.name, v.expected.triggered);
    if (v.expected.auto_block !== undefined) assert.equal(d.autoBlock?.type ?? null, v.expected.auto_block);
    if (v.expected.observed) assert.deepEqual(d.observed.map((o) => o.name), v.expected.observed);

    // The trace must never disagree with the verdict (bug #5 in the 10 Oct review).
    const last = d.trace[d.trace.length - 1];
    assert.equal(last.action, d.verdict, "last trace step must carry the final verdict");
  });
}

test("ipMatches: IPv4, CIDR, ranges, IPv6, mapped", () => {
  assert.ok(ipMatches("10.1.2.3", "10.0.0.0/8"));
  assert.ok(!ipMatches("11.1.2.3", "10.0.0.0/8"));
  assert.ok(ipMatches("1.2.3.4", "0.0.0.0/0"));
  assert.ok(ipMatches("192.168.1.255", "192.168.1.0/24"));
  assert.ok(ipMatches("10.0.0.20", "10.0.0.50-10.0.0.1"), "reversed range");
  assert.ok(ipMatches("2001:db8:abcd::42", "2001:db8::/32"));
  assert.ok(ipMatches("::1", "::1/128"));
  assert.ok(!ipMatches("::1", "127.0.0.1"), "families do not mix");
  assert.ok(ipMatches("::ffff:10.0.0.1", "10.0.0.0/8"));
  assert.ok(ipMatches("fe80::1%eth0", "fe80::/10"));
  assert.ok(!ipMatches("not-an-ip", "0.0.0.0/0"));
  assert.ok(!ipMatches("1.2.3.4", "garbage"));
});

test("isValidIpSpec validates form input", () => {
  for (const ok of ["203.0.113.5", "10.0.0.0/8", "10.0.0.1-10.0.0.50", "2001:db8::/32", "::1", "::ffff:1.2.3.4"]) {
    assert.ok(isValidIpSpec(ok), ok);
  }
  for (const bad of ["300.1.1.1", "10.0.0.0/33", "2001:db8::/129", "1.2.3", "10.0.0.1-2001:db8::1", "", "abc"]) {
    assert.ok(!isValidIpSpec(bad), bad);
  }
});

test("ipToInt keeps its legacy IPv4 behaviour", () => {
  assert.equal(ipToInt("0.0.0.1"), 1);
  assert.equal(ipToInt("255.255.255.255"), 4294967295);
  assert.equal(ipToInt("2001:db8::1"), null);
});

test("normalizePath decodes twice, lowercases, collapses slashes", () => {
  assert.equal(normalizePath("/A%252Fb//C"), "/a/b/c");
  assert.equal(normalizePath("/x?q=a+b"), "/x?q=a b");
  assert.equal(normalizePath("/bad%zzpath%41"), "/bad%zzpatha", "bad escapes do not throw");
  assert.equal(normalizePath("..\\..\\x"), "../../x");
});

test("explainRule describes rate limits and actions", () => {
  assert.match(
    explainRule({ type: "rate_limit", action: "throttle", criteria: { max_requests: 10, window_seconds: 60, path: "^/login" } }),
    /Throttles an IP after 10 requests in 60 seconds/,
  );
  assert.match(explainRule({ type: "geo", action: "allow", criteria: { countries: ["ZA"] } }), /^Allows/);
  assert.match(explainRule({ type: "pattern", criteria: {} }), /will not match any traffic/);
});

test("matchRule without a counter never matches rate_limit (server callers like previewRuleImpact)", () => {
  assert.equal(
    matchRule({ type: "rate_limit", criteria: { max_requests: 1, window_seconds: 60 } }, { source_ip: "1.2.3.4" }),
    false,
  );
});

test("traceRequest stays compatible and agrees with allow precedence", () => {
  const trace = traceRequest(
    { source_ip: "10.0.0.5", path: "/wp-admin", user_agent: "curl/8" },
    [{ ip_or_range: "10.0.0.5" }],
    [{ name: "Allow", type: "ip_allow", action: "allow", criteria: { ips: ["10.0.0.5"] } }],
  );
  assert.equal(trace[trace.length - 1].action, "allowed");
});

test("detectConflicts warns about overlapping allow and block rules", () => {
  const w = detectConflicts(
    { type: "ip_block", action: "block", app_id: "a", criteria: { cidrs: ["10.0.0.0/8"] } },
    [{ id: "x", name: "Office", type: "ip_allow", action: "allow", active: true, app_id: "a", criteria: { ips: ["10.1.1.1"] } }],
  );
  assert.equal(w.length, 1);
  assert.match(w[0], /Office/);
});
