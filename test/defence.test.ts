import { test } from "node:test";
import assert from "node:assert/strict";
import { createClient } from "../src/client.ts";
import { satisfies, signProbe, honeypotFieldHtml, Decoys, OutcomeTracker, VirtualPatches } from "../src/defence.ts";
import { SwarmTechShield } from "../src/index.ts";
import { detectDependencies } from "../src/node.ts";
import { startMock, type Mock } from "./mock-server.ts";

function clock(start = Date.parse("2026-10-29T10:00:00Z")) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

let n = 0;
async function setup(extra: Record<string, unknown> = {}, init: Record<string, unknown> = {}) {
  const mock: Mock = await startMock(init as never);
  mock.state.key = `sts_conn_def_${++n}`;
  const c = clock();
  const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, logBatchSize: 1, now: c.now, ...extra });
  await client.check({ ip: "198.51.100.200", path: "/" }); // first sync
  return { mock, client, c };
}

/* ---------------- decoys ---------------- */

test("a decoy route is blocked, serves bait, and blocks the IP on this server", async (t) => {
  const { mock, client } = await setup();
  t.after(() => mock.close());
  const r = await client.check({ ip: "203.0.113.50", path: "/.env" });
  assert.equal(r.verdict, "blocked");
  assert.match(r.reason, /Decoy route/);
  assert.equal(r.decoy?.status, 200, "bait is served, so the attacker takes the canary");
  assert.ok(client.canaryValues().some((c) => r.decoy!.body.includes(c)), "bait contains a canary credential");
  assert.equal((await client.check({ ip: "203.0.113.50", path: "/" })).verdict, "blocked", "IP blocked afterwards");
  assert.equal((await client.check({ ip: "198.51.100.9", path: "/" })).verdict, "allowed", "other visitors unaffected");
});

test("a non-bait decoy answers 404", async (t) => {
  const { mock, client } = await setup();
  t.after(() => mock.close());
  const r = await client.check({ ip: "203.0.113.51", path: "/wp-admin/install.php" });
  assert.equal(r.verdict, "blocked");
  assert.equal(r.decoy?.status, 404);
});

test("using a canary credential anywhere in a request is caught", async (t) => {
  const { mock, client } = await setup();
  t.after(() => mock.close());
  const [token] = client.canaryValues();
  const r = await client.check({ ip: "203.0.113.52", path: "/api/data", headers: { authorization: `Bearer ${token}` } });
  assert.equal(r.verdict, "blocked");
  assert.match(r.reason, /canary credential/);
});

test("canaries are stable for one connection key and differ between keys", async () => {
  const a = new Decoys("key-one");
  const b = new Decoys("key-one");
  const c = new Decoys("key-two");
  await Promise.all([a.whenReady(), b.whenReady(), c.whenReady()]);
  assert.deepEqual(a.canaryValues(), b.canaryValues());
  assert.notDeepEqual(a.canaryValues(), c.canaryValues());
});

test("a filled hidden form field blocks the submission but not the IP", async (t) => {
  const { mock, client } = await setup();
  t.after(() => mock.close());
  const r = await client.check({ ip: "203.0.113.53", method: "POST", path: "/contact", body: { email: "a@b.co", website_url: "http://spam.example" } });
  assert.equal(r.verdict, "blocked");
  assert.match(r.reason, /Hidden form field/);
  assert.equal((await client.check({ ip: "203.0.113.53", method: "POST", path: "/contact", body: { email: "a@b.co", website_url: "" } })).verdict, "allowed");
  assert.match(honeypotFieldHtml(), /name="website_url"/);
});

test("allow rules win over decoys, and decoys can be switched off", async (t) => {
  const allow = [{ id: "a", name: "Allow scanner", type: "ip_allow", action: "allow", deployment_state: "enforced", criteria: { ips: ["203.0.113.60"] } }];
  const { mock, client } = await setup({}, { rules: allow });
  t.after(() => mock.close());
  assert.equal((await client.check({ ip: "203.0.113.60", path: "/.env" })).verdict, "allowed");
  const off = await setup({ decoys: false });
  t.after(() => off.mock.close());
  assert.equal((await off.client.check({ ip: "203.0.113.61", path: "/.env" })).decoy, undefined);
});

/* ---------------- outcomes ---------------- */

test("failed logins for one account are throttled on login paths only", async (t) => {
  const { mock, client } = await setup();
  t.after(() => mock.close());
  for (let i = 0; i < 8; i++) client.reportOutcome({ type: "login", ip: `198.51.100.${i + 10}`, user: "Alice@Example.com", success: false });
  const r = await client.check({ ip: "198.51.100.99", method: "POST", path: "/login", user: "alice@example.com" });
  assert.equal(r.verdict, "throttled", "spread across many IPs, still caught by account");
  assert.match(r.reason, /Login protection: 8 failed login attempts for this account/);
  assert.equal((await client.check({ ip: "198.51.100.99", path: "/products", user: "alice@example.com" })).verdict, "allowed", "other pages unaffected");
});

test("one IP trying many accounts is stopped (credential stuffing)", async (t) => {
  const { mock, client } = await setup();
  t.after(() => mock.close());
  for (let i = 0; i < 10; i++) client.reportOutcome({ type: "login", ip: "203.0.113.70", user: `user${i}`, success: i === 0 });
  const r = await client.check({ ip: "203.0.113.70", method: "POST", path: "/api/auth/login" });
  assert.equal(r.verdict, "throttled");
  assert.match(r.reason, /10 different accounts/);
});

test("card testing (many cards from one IP) is blocked on checkout", async (t) => {
  const { mock, client } = await setup();
  t.after(() => mock.close());
  for (let i = 0; i < 4; i++) client.reportOutcome({ type: "payment", ip: "203.0.113.80", success: false, fingerprint: `fp_${i}` });
  const r = await client.check({ ip: "203.0.113.80", method: "POST", path: "/checkout/pay" });
  assert.equal(r.verdict, "blocked");
  assert.match(r.reason, /card testing/);
});

test("outcome limits expire after their window, and a good login clears an account", () => {
  const c = clock();
  const tr = new OutcomeTracker(undefined, c.now);
  for (let i = 0; i < 8; i++) tr.report({ type: "login", user: "bob", success: false });
  assert.ok(tr.check("/login", "", "bob"));
  tr.report({ type: "login", user: "bob", success: true });
  assert.equal(tr.check("/login", "", "bob"), null, "success resets the account");
  for (let i = 0; i < 20; i++) tr.report({ type: "login", ip: "10.1.1.1", success: false });
  assert.ok(tr.check("/login", "10.1.1.1"));
  c.advance(16 * 60 * 1000);
  assert.equal(tr.check("/login", "10.1.1.1"), null, "window passed");
});

test("SwarmTechShield.reportOutcome reaches the shared client", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  mock.state.key = "sts_conn_shared_outcome";
  const opts = { connectionKey: mock.state.key, syncUrl: mock.syncUrl };
  for (let i = 0; i < 8; i++) SwarmTechShield.reportOutcome(opts, { type: "login", user: "carol", success: false });
  const r = await SwarmTechShield.getClient(opts).check({ ip: "198.51.100.5", path: "/login", user: "carol" });
  assert.equal(r.verdict, "throttled");
});

/* ---------------- virtual patches ---------------- */

test("semver ranges", () => {
  assert.ok(satisfies("4.17.20", "<4.17.21"));
  assert.ok(!satisfies("4.17.21", "<4.17.21"));
  assert.ok(satisfies("2.1.0", ">=2.0.0 <2.3.1 || 3.0.0"));
  assert.ok(satisfies("3.0.0", ">=2.0.0 <2.3.1 || 3.0.0"));
  assert.ok(!satisfies("2.3.1", ">=2.0.0 <2.3.1 || 3.0.0"));
  assert.ok(satisfies("1.4.9", "^1.2.0"));
  assert.ok(!satisfies("2.0.0", "^1.2.0"));
  assert.ok(satisfies("1.2.9", "~1.2.3"));
  assert.ok(!satisfies("1.3.0", "~1.2.3"));
  assert.ok(satisfies("1.0.0-beta.1", "<1.0.0"));
});

const PATCHES = [
  { id: "vp-test-1", advisory: "TEST-2026-0001", package: "example-parser", affected: "<2.4.1", fixed: "2.4.1", rule: { pattern: "evilmarker[0-9]+", locations: ["query", "body"], description: "Test patch" } },
  { id: "vp-test-2", advisory: "TEST-2026-0002", package: "other-lib", affected: "<1.0.0", rule: { pattern: "othermarker" } },
];

test("a virtual patch only applies when the installed version is affected", () => {
  const vp = new VirtualPatches();
  vp.setDependencies({ "example-parser": "2.3.0", "other-lib": "1.2.0" });
  vp.load(PATCHES as never);
  assert.deepEqual(vp.active().map((a) => a.id), ["vp-test-1"]);
  assert.ok(vp.match({ path: "/x?q=evilmarker42" }));
  assert.equal(vp.match({ path: "/x?q=othermarker" }), null);
  vp.setDependencies({ "example-parser": "2.4.1" });
  vp.load(PATCHES as never);
  assert.equal(vp.active().length, 0, "patched version: nothing active");
});

test("virtual patches arrive through sync, block requests, and dependencies are reported", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  mock.state.key = "sts_conn_patch";
  let syncBody: Record<string, unknown> | null = null;
  const realFetch = globalThis.fetch;
  const c = clock();
  const client = createClient({
    connectionKey: mock.state.key,
    syncUrl: mock.syncUrl,
    now: c.now,
    dependencies: { "example-parser": "2.3.0" },
    fetch: async (url, init) => {
      const res = await realFetch(url, init);
      if (String(url).includes("syncRuleCache")) {
        syncBody = JSON.parse(String(init?.body));
        const data = await res.json();
        return new Response(JSON.stringify({ ...data, virtual_patches: PATCHES }), { status: res.status, headers: { "content-type": "application/json" } });
      }
      return res;
    },
  });
  await client.check({ ip: "198.51.100.1", path: "/" });
  assert.deepEqual((syncBody as unknown as { dependencies: unknown }).dependencies, { "example-parser": "2.3.0" });
  assert.equal(client.status().virtualPatches.length, 1);
  const r = await client.check({ ip: "198.51.100.1", path: "/search?q=evilmarker7" });
  assert.equal(r.verdict, "blocked");
  assert.match(r.reason, /Virtual patch TEST-2026-0001: example-parser@2.3.0 is affected; upgrade to 2.4.1/);
  assert.equal(r.patch?.id, "vp-test-1");
});

test("detectDependencies reads installed versions and never throws", async () => {
  assert.deepEqual(await detectDependencies("/definitely/not/a/dir"), {});
  const deps = await detectDependencies(process.cwd());
  assert.equal(typeof deps, "object");
});

/* ---------------- verification probes ---------------- */

test("a signed test-block probe answers 403 with a verification header and is not logged", async (t) => {
  const { mock, client, c } = await setup();
  t.after(() => mock.close());
  const header = await signProbe(mock.state.key, "GET", "/account", "test-block", c.now());
  await client.flush();
  const before = mock.state.logBatches.length;
  const r = await client.check({ ip: "198.51.100.30", method: "GET", path: "/account", headers: { "x-shield-probe": header! } });
  assert.equal(r.verdict, "blocked");
  assert.equal(r.verification?.headers["x-shield-test"], "blocked");
  assert.match(r.verification!.headers["x-shield-status"], /^active; sdk=/);
  const res = SwarmTechShield.toResponse(r)!;
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("x-shield-test"), "blocked");
  await client.flush();
  assert.equal(mock.state.logBatches.length, before, "probe not logged as an attack");
});

test("a status probe passes through and decorate() adds the header", async (t) => {
  const { mock, client, c } = await setup();
  t.after(() => mock.close());
  const header = await signProbe(mock.state.key, "GET", "/", "status", c.now());
  const r = await client.check({ ip: "198.51.100.31", method: "GET", path: "/", headers: { "x-shield-probe": header! } });
  assert.equal(r.verdict, "allowed");
  const res = SwarmTechShield.decorate(new Response("ok"), r);
  assert.match(res.headers.get("x-shield-status") || "", /active/);
});

test("forged, replayed, stale or mismatched probes are ignored", async (t) => {
  const { mock, client, c } = await setup();
  t.after(() => mock.close());
  const wrongKey = await signProbe("not-the-key", "GET", "/a", "test-block", c.now());
  assert.equal((await client.check({ ip: "198.51.100.32", path: "/a", headers: { "x-shield-probe": wrongKey! } })).verification, undefined);
  const good = await signProbe(mock.state.key, "GET", "/a", "test-block", c.now());
  assert.equal((await client.check({ ip: "198.51.100.32", path: "/a", headers: { "x-shield-probe": good! } })).verdict, "blocked");
  assert.equal((await client.check({ ip: "198.51.100.32", path: "/a", headers: { "x-shield-probe": good! } })).verdict, "allowed", "replay ignored");
  const otherPath = await signProbe(mock.state.key, "GET", "/a", "test-block", c.now());
  assert.equal((await client.check({ ip: "198.51.100.32", path: "/b", headers: { "x-shield-probe": otherPath! } })).verdict, "allowed", "signed for another path");
  const old = await signProbe(mock.state.key, "GET", "/a", "test-block", c.now() - 10 * 60 * 1000);
  assert.equal((await client.check({ ip: "198.51.100.32", path: "/a", headers: { "x-shield-probe": old! } })).verdict, "allowed", "stale");
});

/* ---------------- adapters ---------------- */

test("Express serves decoy bait and sets verification headers", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  mock.state.key = "sts_conn_express_decoy";
  const mw = SwarmTechShield.express({ connectionKey: mock.state.key, syncUrl: mock.syncUrl });
  const run = (url: string, headers: Record<string, string> = {}) =>
    new Promise<{ status: number; body: unknown; headers: Record<string, string>; next: boolean }>((resolve) => {
      const res = {
        statusCode: 200, body: undefined as unknown, headers: {} as Record<string, string>,
        status(c: number) { this.statusCode = c; return this; },
        set(k: string, v: string) { this.headers[k.toLowerCase()] = v; return this; },
        send(b: unknown) { this.body = b; resolve({ status: this.statusCode, body: b, headers: this.headers, next: false }); return this; },
      };
      mw({ ip: "203.0.113.90", method: "GET", originalUrl: url, headers: { "user-agent": "x", ...headers } } as never, res as never, () =>
        resolve({ status: res.statusCode, body: res.body, headers: res.headers, next: true }));
    });
  const bait = await run("/.env");
  assert.equal(bait.next, false);
  assert.equal(bait.status, 200);
  assert.match(String(bait.body), /APP_SECRET=tok_/);
  const probe = await signProbe(mock.state.key, "GET", "/home", "status");
  const ok = await run("/home", { "x-shield-probe": probe! });
  // The IP that read the bait is now blocked locally, so use the probe result headers either way.
  assert.match(ok.headers["x-shield-status"] || "", /active/);
});
