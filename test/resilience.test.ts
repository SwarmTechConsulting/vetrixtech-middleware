import { test } from "node:test";
import assert from "node:assert/strict";
import { createClient } from "../src/client.ts";
import { Resilience } from "../src/resilience.ts";
import { SwarmTechShield } from "../src/index.ts";
import { startMock } from "./mock-server.ts";

function clock(start = Date.parse("2026-10-29T12:00:00Z")) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

/** Feed `rps` requests per second for `seconds` seconds. */
function feed(r: Resilience, c: ReturnType<typeof clock>, rps: number, seconds: number) {
  for (let s = 0; s < seconds; s++) {
    for (let i = 0; i < rps; i++) r.record(c.now());
    c.advance(1000);
  }
}

test("under-attack mode switches on automatically when traffic jumps, and off when it calms", () => {
  const c = clock();
  const r = new Resilience({}, c.now);
  feed(r, c, 20, 300); // 5 minutes of normal traffic: 20 req/s
  assert.equal(r.underAttack(), false);
  feed(r, c, 200, 40); // a flood: 10x the baseline for 40 s
  assert.equal(r.underAttack(), true);
  assert.equal(r.state().underAttackSource, "auto");
  feed(r, c, 20, 90); // back to normal for 90 s
  assert.equal(r.underAttack(), false, "released after a calm minute");
});

test("a modest rise, or low absolute traffic, does not trigger it", () => {
  const c = clock();
  const r = new Resilience({}, c.now);
  feed(r, c, 20, 300);
  feed(r, c, 60, 60); // 3x: a busy period, not an attack
  assert.equal(r.underAttack(), false);
  const quiet = new Resilience({}, c.now);
  feed(quiet, c, 1, 300);
  feed(quiet, c, 30, 60); // 30x, but only 30 req/s (under the 50 req/s floor)
  assert.equal(quiet.underAttack(), false);
});

test("load shedding keeps priority paths and signed-in users", () => {
  let load = 0;
  const r = new Resilience({ loadProbe: () => load }, Date.now);
  assert.equal(r.shouldShed("/products"), false, "not overloaded");
  load = 500;
  assert.equal(r.shouldShed("/products"), true);
  assert.equal(r.shouldShed("/checkout/pay"), false, "checkout kept");
  assert.equal(r.shouldShed("/login"), false, "login kept");
  assert.equal(r.shouldShed("/healthz"), false, "health check kept");
  assert.equal(r.shouldShed("/products", "alice"), false, "signed-in user kept");
  const off = new Resilience({ loadProbe: () => 999, loadShedding: false }, Date.now);
  assert.equal(off.shouldShed("/products"), false);
});

test("the client sheds with a 503 and Retry-After, and logs one summary instead of every request", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  mock.state.key = "sts_conn_shed";
  let load = 0;
  const c = clock();
  const client = createClient({
    connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, now: c.now, logAllowed: false,
    resilience: { loadProbe: () => load, loadShedding: { retryAfterSeconds: 7 } },
  });
  await client.check({ ip: "198.51.100.1", path: "/" });
  load = 400;
  const results = [];
  for (let i = 0; i < 50; i++) results.push(await client.check({ ip: `198.51.100.${i + 2}`, path: "/products" }));
  assert.ok(results.every((r) => r.shed && r.verdict === "throttled"));
  const res = SwarmTechShield.toResponse(results[0])!;
  assert.equal(res.status, 503);
  assert.equal(res.headers.get("retry-after"), "7");
  assert.equal((await client.check({ ip: "198.51.100.90", path: "/checkout" })).shed, undefined, "checkout still served");
  await client.flush();
  const events = mock.state.logBatches.flat() as { path: string; reason: string }[];
  const summaries = events.filter((e) => e.path === "(load shedding)");
  assert.equal(summaries.length, 1, "one summary event");
  assert.match(summaries[0].reason, /Shed \d+ low-priority/);
  assert.equal(client.status().resilience?.shedRequests, 50);
});

test("allow rules (e.g. a monitor) are never shed", async (t) => {
  const mock = await startMock({
    rules: [{ id: "m", name: "Uptime monitor", type: "ip_allow", action: "allow", deployment_state: "enforced", criteria: { ips: ["203.0.113.200"] } }],
  });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_shed_allow";
  const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, resilience: { loadProbe: () => 999 } });
  const r = await client.check({ ip: "203.0.113.200", path: "/products" });
  assert.equal(r.verdict, "allowed");
});

test("under attack: tighter burst limit, and inspection blocks instead of observing", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  mock.state.key = "sts_conn_attack";
  const c = clock();
  const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, now: c.now });
  // Inspection is in observe mode by default; a payload in the body is only seen by inspection.
  const bodyAttack = { ip: "198.51.100.3", method: "POST", path: "/comment", body: { text: "<svg/onload=alert(1)>" } };
  assert.equal((await client.check(bodyAttack)).verdict, "allowed", "observe mode by default");
  client.setUnderAttack(true);
  assert.equal(client.status().resilience?.underAttack, true);
  assert.equal((await client.check({ ...bodyAttack, ip: "198.51.100.4" })).verdict, "blocked", "inspection enforced under attack");
  // Burst: 60 requests a minute per IP under attack (normally 120).
  let last;
  for (let i = 0; i < 61; i++) last = await client.check({ ip: "198.51.100.5", path: `/p/${i}` });
  assert.equal(last!.verdict, "blocked");
  assert.match(last!.reason, /rate burst/);
  client.setUnderAttack(false);
});

test("the console can switch under-attack mode on through sync", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  mock.state.key = "sts_conn_console_attack";
  const realFetch = globalThis.fetch;
  const client = createClient({
    connectionKey: mock.state.key,
    syncUrl: mock.syncUrl,
    fetch: async (url, init) => {
      const res = await realFetch(url, init);
      if (!String(url).includes("syncRuleCache")) return res;
      const data = await res.json();
      return new Response(JSON.stringify({ ...data, under_attack: true }), { status: res.status, headers: { "content-type": "application/json" } });
    },
  });
  await client.check({ ip: "198.51.100.1", path: "/" });
  assert.equal(client.status().resilience?.underAttack, true);
  assert.equal(client.status().resilience?.underAttackSource, "console");
});

test("a blocked IP is rejected before the body is read", async (t) => {
  const mock = await startMock({ blocklist: [{ ip_or_range: "203.0.113.66", reason: "abuse" }] });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_early";
  const opts = { connectionKey: mock.state.key, syncUrl: mock.syncUrl };
  await SwarmTechShield.getClient(opts).check({ ip: "198.51.100.1", path: "/" });
  let bodyRead = false;
  const stream = new ReadableStream({
    pull(ctrl) {
      bodyRead = true;
      ctrl.enqueue(new TextEncoder().encode('{"a":1}'));
      ctrl.close();
    },
  }, { highWaterMark: 0 });
  const req = new Request("https://app.test/api", {
    method: "POST",
    body: stream,
    headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.66" },
    duplex: "half",
  } as RequestInit);
  const r = await SwarmTechShield.base44(req, opts);
  assert.equal(r.verdict, "blocked");
  assert.equal(bodyRead, false, "body never read for a blocked IP");

  let cleanRead = false;
  const cleanStream = new ReadableStream({
    pull(ctrl) {
      cleanRead = true;
      ctrl.enqueue(new TextEncoder().encode('{"a":1}'));
      ctrl.close();
    },
  }, { highWaterMark: 0 });
  const clean = new Request("https://app.test/api", {
    method: "POST",
    body: cleanStream,
    headers: { "content-type": "application/json", "x-forwarded-for": "198.51.100.7" },
    duplex: "half",
  } as RequestInit);
  assert.equal((await SwarmTechShield.base44(clean, opts)).verdict, "allowed");
  assert.equal(cleanRead, true, "a normal request's body is read for inspection");
});
