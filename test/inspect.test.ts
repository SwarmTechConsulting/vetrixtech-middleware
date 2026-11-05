import { test } from "node:test";
import assert from "node:assert/strict";
import {
  inspect,
  collectParts,
  parseBody,
  variants,
  describeFinding,
  INSPECTION_RULES,
  type InspectionInput,
} from "../src/inspect.ts";

// A representative attack per category. Each should block at paranoia 1 (score >= 5).
// These are the standard forms a WAF test suite checks; they are inert as data here.
const ATTACKS: { cat: string; input: InspectionInput }[] = [
  { cat: "sqli", input: { path: "/i?id=1'%20OR%20'1'%3D'1" } },
  { cat: "sqli", input: { path: "/i?id=1", body: { id: "1 UNION SELECT a,b FROM users" }, contentType: "application/json" } },
  { cat: "sqli", input: { path: "/i?id=1;DROP%20TABLE%20t" } },
  { cat: "sqli", input: { path: "/i?id=1%20AND%20SLEEP(5)" } },
  { cat: "sqli", input: { path: "/i", headers: { cookie: "uid=1' OR '1'='1" } } },
  { cat: "xss", input: { path: "/s?q=%3Cscript%3Ealert(1)%3C/script%3E" } },
  { cat: "xss", input: { path: "/s?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" } },
  { cat: "xss", input: { path: "/s", body: { bio: "<svg/onload=alert(1)>" } } },
  { cat: "xss", input: { path: "/s?u=javascript:alert(document.cookie)" } },
  { cat: "lfi", input: { path: "/f?p=../../../../etc/passwd" } },
  { cat: "lfi", input: { path: "/f?p=%2e%2e%2f%2e%2e%2fetc%2fshadow" } },
  { cat: "lfi", input: { path: "/f?p=php://filter/convert.base64-encode/resource=x" } },
  { cat: "rce", input: { path: "/p?host=127.0.0.1;%20id" } },
  { cat: "rce", input: { path: "/p?host=%24(whoami)" } },
  { cat: "rce", input: { path: "/p", headers: { "user-agent": "${jndi:ldap://h/a}" } } },
  { cat: "ssrf", input: { path: "/fetch?url=http://169.254.169.254/latest/meta-data/" } },
  { cat: "ssti", input: { path: "/t?name=%7B%7B7*7%7D%7D" } },
  { cat: "ssti", input: { path: "/t?name=%7B%7B''.__class__.__mro__%7D%7D" } },
  { cat: "xxe", input: { path: "/x", contentType: "application/xml", body: '<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>' } },
  { cat: "nosql", input: { path: "/l", body: { username: { $ne: null }, password: { $ne: null } } } },
  { cat: "proto", input: { path: "/u", body: "{\"__proto__\":{\"isAdmin\":true}}", contentType: "application/json" } },
  { cat: "protocol", input: { path: "/h?x=a%0d%0aSet-Cookie:%20s%3D1" } },
  { cat: "probe", input: { path: "/.env" } },
  { cat: "probe", input: { path: "/.git/config" } },
];

// Normal requests. None may reach the block threshold at paranoia 1.
const NORMAL: InspectionInput[] = [
  { path: "/", headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/search?q=how+to+learn+javascript", headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/products?category=shoes&sort=price&order=asc", headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/articles/2026/10/moving-off-base44", headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/api/users?select=id,name,email&limit=50", headers: { "user-agent": "curl/8.0" } },
  { path: "/post", body: { title: "My SELECT of favourite books", body: "Here's a list of 1 OR 2 options to consider." }, contentType: "application/json", headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/comment", body: { text: "Use the <b>bold</b> button. I rated it 5/5 and said \"great\"." }, headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/checkout", body: { card: "4111111111111111", address: "12 O'Brien Street & Co." }, contentType: "application/json", headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/docs/guide.html?section=and-or-logic", headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/i?path=C:\\Users\\me\\file.txt", headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/search?q=unionized+workers+and+rights", headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/profile", body: { bio: "I love C++ and shell scripting; my cat is called `tiny`." }, headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/feedback", body: { msg: "Please select from the menu and order by Friday." }, headers: { "user-agent": "Mozilla/5.0" } },
  { path: "/u/alice?tab=settings", headers: { "user-agent": "Mozilla/5.0", referer: "https://app.example/dashboard" } },
];

test("every attack category is blocked at paranoia 1", () => {
  const missed: string[] = [];
  for (const { cat, input } of ATTACKS) {
    const r = inspect(input, { paranoia: 1 });
    if (!r.matched) missed.push(`${cat}: ${JSON.stringify(input).slice(0, 70)}`);
    else assert.equal(r.findings[0].category, r.findings[0].category); // finding recorded
  }
  assert.deepEqual(missed, [], `missed attacks: ${missed.join(" | ")}`);
});

test("normal requests are not blocked at paranoia 1", () => {
  const flagged: string[] = [];
  for (const input of NORMAL) {
    const r = inspect(input, { paranoia: 1 });
    if (r.matched) flagged.push(`${JSON.stringify(input).slice(0, 70)} -> ${r.findings.map((f) => f.rule).join(",")}`);
  }
  assert.deepEqual(flagged, [], `false positives: ${flagged.join(" | ")}`);
});

test("detection and false-positive rates meet the bar", () => {
  const detected = ATTACKS.filter((a) => inspect(a.input, { paranoia: 1 }).matched).length;
  const fp = NORMAL.filter((n) => inspect(n, { paranoia: 1 }).matched).length;
  const detectionRate = detected / ATTACKS.length;
  const fpRate = fp / NORMAL.length;
  assert.ok(detectionRate >= 0.95, `detection rate ${(detectionRate * 100).toFixed(1)}% below 95%`);
  assert.ok(fpRate <= 0.02, `false-positive rate ${(fpRate * 100).toFixed(1)}% above 2%`);
});

test("mode off skips all work", () => {
  const r = inspect({ path: "/s?q=<script>alert(1)</script>" }, { mode: "off" });
  assert.equal(r.matched, false);
  assert.equal(r.findings.length, 0);
});

test("observe mode records the score without being asked to block", () => {
  const r = inspect({ path: "/s?q=%3Cscript%3Ealert(1)%3C/script%3E" }, { mode: "observe" });
  assert.equal(r.mode, "observe");
  assert.ok(r.matched, "still reports what would have blocked");
  assert.ok(r.score >= 5);
});

test("threshold combines weaker findings", () => {
  // Two paranoia-2/3 findings together, each below the block score on its own.
  const low = inspect({ path: "/f?p=../config" }, { paranoia: 2, threshold: 5 });
  assert.ok(low.score < 5, "a single ../ is not blocked on its own");
  const combined = inspect({ path: "/f?p=../a&q=../b&r=select x from y where z" }, { paranoia: 2, threshold: 5 });
  assert.ok(combined.score >= 5, "several weaker hints together reach the threshold");
});

test("higher paranoia catches more but is off by default", () => {
  const input = { path: "/q?s=' or username like 'a" };
  assert.equal(inspect(input, { paranoia: 1 }).findings.some((f) => f.rule === "sqli-quote-keyword"), false);
  assert.ok(inspect(input, { paranoia: 3 }).score >= inspect(input, { paranoia: 1 }).score);
});

test("exclusions suppress a known false positive", () => {
  const input: InspectionInput = { path: "/wiki/edit", body: { content: "The <script> element runs JavaScript." } };
  assert.ok(inspect(input).matched, "flagged without an exclusion");
  const cfg = { exclusions: [{ path: "^/wiki/edit", locations: ["body" as const], names: ["content"], rules: ["xss"] }] };
  assert.equal(inspect(input, cfg).matched, false, "exclusion clears it");
});

test("disabledRules turn a rule off everywhere", () => {
  const input = { path: "/.env" };
  assert.ok(inspect(input).matched);
  assert.equal(inspect(input, { disabledRules: ["probe-sensitive-path"] }).matched, false);
});

test("sensitive values are redacted in findings", () => {
  const r = inspect({ path: "/login", body: { password: "' OR '1'='1" } });
  const f = r.findings.find((x) => x.name.includes("password"));
  assert.ok(f);
  assert.equal(f!.sample, "[redacted]");
});

test("inspection is bounded and never throws on odd input", () => {
  const deep: Record<string, unknown> = {};
  let cur = deep;
  for (let i = 0; i < 100; i++) cur = cur.next = {} as Record<string, unknown>;
  assert.doesNotThrow(() => inspect({ path: "/x", body: deep }));
  const big = "a".repeat(2_000_000);
  const r = inspect({ path: "/x", body: { big } }, { maxParts: 500 });
  assert.ok(r.inspected <= 501);
  assert.doesNotThrow(() => inspect({ path: "/x", body: { n: null, u: undefined, fn: 5 } as never }));
});

test("parseBody understands JSON and form bodies", () => {
  assert.deepEqual(parseBody('{"a":1}', "application/json"), { a: 1 });
  assert.deepEqual(parseBody("a=1&b=2", "application/x-www-form-urlencoded"), { a: "1", b: "2" });
  assert.equal(parseBody("plain text", "text/plain"), "plain text");
  assert.equal(parseBody("{bad json", "application/json"), "{bad json");
});

test("variants decode percent, entity and unicode escapes", () => {
  assert.ok(variants("%3Cscript%3E").includes("<script>"));
  assert.ok(variants("&lt;script&gt;").includes("<script>"));
  assert.ok(variants("\\u003cscript\\u003e").includes("<script>"));
});

test("collectParts separates path, query, headers, cookies and body", () => {
  const parts = collectParts({
    path: "/a/b?x=1&y=2",
    headers: { "x-test": "v", cookie: "c1=a; c2=b" },
    body: { nested: { k: "v" } },
  });
  const locs = new Set(parts.map((p) => p.location));
  assert.ok(locs.has("path") && locs.has("query") && locs.has("header") && locs.has("cookie") && locs.has("body"));
});

test("describeFinding reads naturally", () => {
  const r = inspect({ path: "/s", body: { q: "<script>alert(1)</script>" } });
  assert.match(describeFinding(r.findings[0]), /Cross-site scripting.*body\.q/);
});

test("rule ids are unique", () => {
  const ids = INSPECTION_RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

// ---- engine integration ----
import { evaluate } from "../src/engine.ts";

function inspToData(input: InspectionInput, cfg = {}) {
  const r = inspect(input, cfg);
  return { matched: r.matched, mode: r.mode, score: r.score, threshold: r.threshold, autoBlock: r.score >= 10, findings: r.findings };
}

test("engine blocks on an inspection hit in block mode", () => {
  const input = { path: "/s?q=%3Cscript%3Ealert(1)%3C/script%3E" };
  const d = evaluate(
    { source_ip: "203.0.113.5", path: input.path },
    { inspection: inspToData(input, { mode: "block" }) },
  );
  assert.equal(d.verdict, "blocked");
  assert.ok(d.inspectionFindings && d.inspectionFindings.length >= 1);
});

test("engine does not block in observe mode but records the finding", () => {
  const input = { path: "/s?q=%3Cscript%3Ealert(1)%3C/script%3E" };
  const d = evaluate(
    { source_ip: "203.0.113.5", path: input.path },
    { inspection: inspToData(input, { mode: "observe" }), burst: false, autoDetection: false },
  );
  assert.equal(d.verdict, "allowed");
  assert.ok(d.observed.some((o) => o.id.startsWith("insp:")));
});

test("an allow rule still wins over an inspection hit", () => {
  const input = { path: "/s?q=%3Cscript%3Ealert(1)%3C/script%3E" };
  const d = evaluate(
    { source_ip: "203.0.113.5", path: input.path },
    {
      rules: [{ id: "a1", name: "Allow QA", type: "ip_allow", action: "allow", deployment_state: "enforced", criteria: { ips: ["203.0.113.5"] } }],
      inspection: inspToData(input, { mode: "block" }),
    },
  );
  assert.equal(d.verdict, "allowed");
  assert.match(d.reason, /Allow/);
});

test("the client inspects bodies end to end", async () => {
  const { createClient } = await import("../src/client.ts");
  const { startMock } = await import("./mock-server.ts");
  const mock = await startMock();
  try {
    mock.state.key = "vtx_conn_inspect";
    const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: undefined, inspection: true });
    // allow the first sync
    await client.check({ ip: "198.51.100.1", path: "/" });
    const blocked = await client.check({
      ip: "198.51.100.1",
      method: "POST",
      path: "/login",
      body: { username: "admin' OR '1'='1", password: "x" },
    });
    assert.equal(blocked.verdict, "blocked");
    assert.ok(blocked.reason.includes("Request inspection"));
    const clean = await client.check({ ip: "198.51.100.1", method: "POST", path: "/login", body: { username: "alice", password: "hunter2" } });
    assert.equal(clean.verdict, "allowed");
  } finally {
    await mock.close();
  }
});

test("a high-scoring request locally blocks the IP, a single hit does not", async () => {
  const { createClient } = await import("../src/client.ts");
  const { startMock } = await import("./mock-server.ts");
  const mock = await startMock();
  try {
    mock.state.key = "vtx_conn_block";
    const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: undefined, inspection: true });
    await client.check({ ip: "198.51.100.2", path: "/" });
    // One score-5 hit: request blocked, IP not blocklisted.
    await client.check({ ip: "198.51.100.3", method: "POST", path: "/x", body: { q: "1' OR '1'='1" } });
    assert.equal((await client.check({ ip: "198.51.100.3", path: "/" })).verdict, "allowed", "a single hit does not blocklist the IP");
    // A request with several serious findings (score >= 10): IP blocklisted locally.
    await client.check({ ip: "198.51.100.4", method: "POST", path: "/x?a=<script>alert(1)</script>", body: { q: "1' OR '1'='1", cmd: "; cat /etc/passwd" } });
    const after = await client.check({ ip: "198.51.100.4", path: "/" });
    assert.equal(after.verdict, "blocked", "the high-scoring IP is now locally blocked");
  } finally {
    await mock.close();
  }
});
