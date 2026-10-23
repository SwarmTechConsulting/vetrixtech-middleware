import { test } from "node:test";
import assert from "node:assert/strict";
import { createClient, retryAfterMs, type ShieldOptions } from "../src/client.ts";
import { startMock, type Mock } from "./mock-server.ts";

function clock(start = Date.parse("2026-10-10T12:00:00Z")) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

function opts(mock: Mock, c: ReturnType<typeof clock>, extra: Partial<ShieldOptions> = {}): ShieldOptions {
  return { connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, now: c.now, ...extra };
}

const blockRule = (ip: string) => ({
  id: "r1",
  name: "Block bad IP",
  type: "ip_block",
  action: "block",
  priority: 10,
  deployment_state: "enforced",
  criteria: { ips: [ip] },
});

test("cold start syncs once, then judges locally without network calls", async (t) => {
  const mock = await startMock({ rules: [blockRule("203.0.113.9")] });
  t.after(() => mock.close());
  const c = clock();
  const client = createClient(opts(mock, c, { logUrl: undefined }));

  const r1 = await client.check({ ip: "203.0.113.9", path: "/" });
  assert.equal(r1.verdict, "blocked");
  assert.equal(r1.source, "rules");
  for (let i = 0; i < 50; i++) await client.check({ ip: "198.51.100.1", path: `/p/${i}` });
  assert.equal(mock.state.syncCalls.length, 1, "only the first sync hit the network");
  assert.ok(r1.durationMs < 1000);
});

test("refreshes after the sync interval and picks up new rules", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  const c = clock();
  const client = createClient(opts(mock, c, { logUrl: undefined }));
  assert.equal((await client.check({ ip: "203.0.113.9" })).verdict, "allowed");

  mock.state.rules = [blockRule("203.0.113.9")];
  mock.state.version = 2;
  c.advance(31_000);
  const r = await client.check({ ip: "203.0.113.9" });
  await r.background; // refresh runs in the background
  assert.equal((await client.check({ ip: "203.0.113.9" })).verdict, "blocked");
  assert.equal(mock.state.syncCalls[1].client_version, 1, "sent its version");
});

test("forces a full download periodically even if the version number never changes", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  const c = clock();
  const client = createClient(opts(mock, c, { logUrl: undefined }));
  await client.check({ ip: "203.0.113.9" });
  mock.state.rules = [blockRule("203.0.113.9")]; // server forgot to bump version (the 0.3 bug)
  c.advance(31_000);
  await (await client.check({ ip: "1.1.1.1" })).background;
  assert.equal((await client.check({ ip: "203.0.113.9" })).verdict, "allowed", "up_to_date reply keeps old rules");
  c.advance(300_000);
  await (await client.check({ ip: "1.1.1.1" })).background;
  assert.equal(mock.state.syncCalls.at(-1)!.client_version, null, "full sync requested");
  assert.equal((await client.check({ ip: "203.0.113.9" })).verdict, "blocked");
});

test("fail open by default when SwarmTech Shield is unreachable at start", async (t) => {
  const mock = await startMock({ down: true });
  t.after(() => mock.close());
  const errors: string[] = [];
  const client = createClient(opts(mock, clock(), { onError: (e, ctx) => errors.push(ctx) }));
  const r = await client.check({ ip: "203.0.113.9", path: "/.env" });
  assert.equal(r.verdict, "allowed");
  assert.equal(r.source, "fail_open");
  assert.ok(errors.includes("sync"));
});

test("fail closed when configured", async (t) => {
  const mock = await startMock({ down: true });
  t.after(() => mock.close());
  const client = createClient(opts(mock, clock(), { failMode: "closed" }));
  const r = await client.check({ ip: "203.0.113.9" });
  assert.equal(r.verdict, "blocked");
  assert.equal(r.source, "fail_closed");
});

test("keeps enforcing last good rules during an outage, then applies the app's fail mode", async (t) => {
  const mock = await startMock({ rules: [blockRule("203.0.113.9")], failMode: "fail_closed" });
  t.after(() => mock.close());
  const c = clock();
  const client = createClient(opts(mock, c, { logUrl: undefined }));
  assert.equal((await client.check({ ip: "198.51.100.1" })).verdict, "allowed");

  mock.state.down = true;
  c.advance(10 * 60_000);
  const during = await client.check({ ip: "203.0.113.9" });
  await during.background;
  assert.equal(during.source, "rules", "still using cached rules after 10 minutes");
  assert.equal(during.verdict, "blocked");

  c.advance(6 * 60_000); // now 16 min stale (> 15 min default)
  const after = await client.check({ ip: "198.51.100.1" });
  assert.equal(after.source, "fail_closed", "app's own fail mode from the server is used");
  assert.equal(after.verdict, "blocked");
});

test("a rejected key or paused app lets traffic through and recovers when fixed", async (t) => {
  const mock = await startMock({ appStatus: "paused" });
  t.after(() => mock.close());
  const c = clock();
  const errors: Error[] = [];
  const client = createClient(opts(mock, c, { failMode: "closed", onError: (e) => errors.push(e) }));
  const r = await client.check({ ip: "203.0.113.9", path: "/.env" });
  assert.equal(r.source, "disabled");
  assert.equal(r.verdict, "allowed", "pausing must never block the customer's site");
  assert.match(errors[0].message, /rejected/);

  mock.state.appStatus = "active";
  c.advance(31_000);
  await (await client.check({ ip: "1.1.1.1" })).background;
  const later = await client.check({ ip: "203.0.113.9", path: "/.env" });
  assert.equal(later.source, "rules");
  assert.equal(later.verdict, "blocked");
});

test("rate-limit rules count requests locally per IP and path", async (t) => {
  const mock = await startMock({
    rules: [{
      id: "rl",
      name: "Login limit",
      type: "rate_limit",
      action: "throttle",
      deployment_state: "enforced",
      criteria: { max_requests: 3, window_seconds: 60, path: "^/login", method: "POST" },
    }],
  });
  t.after(() => mock.close());
  const c = clock();
  const client = createClient(opts(mock, c, { logUrl: undefined }));
  const login = () => client.check({ ip: "198.51.100.1", method: "POST", path: "/login" });
  for (let i = 0; i < 3; i++) assert.equal((await login()).verdict, "allowed");
  await client.check({ ip: "198.51.100.1", method: "GET", path: "/home" }); // other paths don't count
  assert.equal((await login()).verdict, "throttled");
  assert.equal((await client.check({ ip: "198.51.100.2", method: "POST", path: "/login" })).verdict, "allowed", "per IP");
  c.advance(61_000);
  assert.equal((await login()).verdict, "allowed", "window slides");
});

test("burst detection blocks floods but can be turned off", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  const client = createClient(opts(mock, clock(), { logUrl: undefined, burst: { maxRequests: 5, windowSeconds: 60 } }));
  const verdicts: string[] = [];
  for (let i = 0; i < 7; i++) verdicts.push((await client.check({ ip: "198.51.100.1", path: `/${i}` })).verdict);
  assert.deepEqual(verdicts, ["allowed", "allowed", "allowed", "allowed", "allowed", "blocked", "blocked"]);

  const off = createClient(opts(mock, clock(), { logUrl: undefined, burst: false }));
  for (let i = 0; i < 200; i++) assert.equal((await off.check({ ip: "198.51.100.1" })).verdict, "allowed");
});

test("an IP caught by auto-detection is blocked locally for a while, even on clean requests", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  const c = clock();
  const client = createClient(opts(mock, c, { logUrl: undefined, localBlockSeconds: 60 }));
  assert.equal((await client.check({ ip: "198.51.100.66", path: "/wp-login.php" })).verdict, "blocked");
  const clean = await client.check({ ip: "198.51.100.66", path: "/" });
  assert.equal(clean.verdict, "blocked");
  assert.equal(clean.decision?.triggered?.name, "Blocklist");
  assert.equal((await client.check({ ip: "198.51.100.67", path: "/" })).verdict, "allowed");
  c.advance(61_000);
  assert.equal((await client.check({ ip: "198.51.100.66", path: "/" })).verdict, "allowed", "local block expires");
});

test("logs are batched, strip query strings, and send at most one incident per IP+rule", async (t) => {
  const mock = await startMock({ rules: [blockRule("203.0.113.9")] });
  t.after(() => mock.close());
  const c = clock();
  const client = createClient(opts(mock, c, { logBatchSize: 10, logFlushIntervalMs: 60_000 }));
  await client.check({ ip: "198.51.100.1", path: "/search?token=secret123" });
  for (let i = 0; i < 9; i++) {
    const r = await client.check({ ip: "203.0.113.9", path: "/x", userAgent: "UA" });
    await r.background;
  }
  assert.equal(mock.state.logBatches.length, 1, "one batch of 10");
  const batch = mock.state.logBatches[0] as Record<string, unknown>[];
  assert.equal(batch.length, 10);
  const allowedEvent = batch.find((e) => e.verdict === "allowed")!;
  assert.equal(allowedEvent.path, "/search", "query string stripped");
  assert.equal(allowedEvent.trace, undefined, "no trace for allowed requests");
  assert.equal(batch[0].verdict, "blocked", "blocked events go first");
  const blocked = batch.filter((e) => e.verdict === "blocked");
  assert.equal(blocked.length, 9);
  assert.equal(blocked.filter((e) => e.is_incident).length, 1, "incident deduplicated");
  assert.ok(typeof blocked[0].trace === "string");
  assert.equal((blocked[0].details as Record<string, unknown>).source, "middleware");
  assert.ok(!JSON.stringify(batch).includes(mock.state.key), "connection key never appears in log events");
});

test("blocklist hits are logged but never flagged as incidents", async (t) => {
  const mock = await startMock({ blocklist: [{ ip_or_range: "203.0.113.9", reason: "known bad" }] });
  t.after(() => mock.close());
  const client = createClient(opts(mock, clock(), { logBatchSize: 1 }));
  await (await client.check({ ip: "203.0.113.9" })).background;
  const e = mock.state.logBatches[0][0] as Record<string, unknown>;
  assert.equal(e.verdict, "blocked");
  assert.equal(e.is_incident, false);
});

test("failed log uploads are retried, not lost", async (t) => {
  const mock = await startMock({ logStatus: 503 });
  t.after(() => mock.close());
  const c = clock();
  const client = createClient(opts(mock, c, { logBatchSize: 2 }));
  await (await client.check({ ip: "198.51.100.1" })).background;
  await (await client.check({ ip: "198.51.100.2" })).background;
  assert.equal(mock.state.logBatches.length, 0);
  assert.equal(client.status().queuedLogs, 2);
  mock.state.logStatus = null;
  c.advance(11_000); // past the 10 s backoff
  await (await client.check({ ip: "198.51.100.3" })).background;
  assert.equal(mock.state.logBatches.flat().length, 2);
  await client.close();
  assert.equal(mock.state.logBatches.flat().length, 3, "close() flushes the rest");
});

test("allowed-request sampling and logAllowed:false", async (t) => {
  const mock = await startMock({ rules: [blockRule("203.0.113.9")] });
  t.after(() => mock.close());
  const client = createClient(opts(mock, clock(), { logAllowed: false, logBatchSize: 1 }));
  await (await client.check({ ip: "198.51.100.1" })).background;
  await (await client.check({ ip: "203.0.113.9" })).background;
  const all = mock.state.logBatches.flat() as Record<string, unknown>[];
  assert.deepEqual(all.map((e) => e.verdict), ["blocked"]);
});

test("check() never throws, even if fetch itself throws", async () => {
  const client = createClient({
    connectionKey: "k",
    syncUrl: "http://invalid.invalid/sync",
    fetch: (() => {
      throw new Error("boom");
    }) as unknown as typeof fetch,
  });
  const r = await client.check({ ip: "1.2.3.4" });
  assert.equal(r.verdict, "allowed");
  assert.equal(r.source, "fail_open");
});

test("constructor validates required options", () => {
  assert.throws(() => createClient({ connectionKey: "", syncUrl: "x" }), /connectionKey/);
  assert.throws(() => createClient({ connectionKey: "k", syncUrl: "" }), /syncUrl/);
});

test("when the queue overflows, allowed events are dropped before blocked ones", async (t) => {
  const mock = await startMock({ rules: [blockRule("203.0.113.9")], logStatus: 503 });
  t.after(() => mock.close());
  const client = createClient(opts(mock, clock(), { maxQueue: 10, logFlushIntervalMs: 3_600_000 }));
  for (let i = 0; i < 5; i++) await client.check({ ip: "203.0.113.9", path: `/b${i}` });
  for (let i = 0; i < 50; i++) await client.check({ ip: "198.51.100.1", path: `/a${i}` });
  const s = client.status();
  assert.equal(s.queuedLogs, 10);
  assert.equal(s.droppedLogs, 45);
  mock.state.logStatus = null;
  await client.close();
  const sent = mock.state.logBatches.flat() as Record<string, unknown>[];
  assert.equal(sent.filter((e) => e.verdict === "blocked").length, 5, "every blocked event survived");
  assert.equal(sent[0].verdict, "blocked", "blocked events are sent first");
});

test("close() waits for an in-flight upload and then sends everything", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  const client = createClient(opts(mock, clock(), { logBatchSize: 10 }));
  for (let i = 0; i < 95; i++) await client.check({ ip: "198.51.100.1", path: `/${i}` });
  await client.close();
  assert.equal(mock.state.logBatches.flat().length, 95);
  assert.equal(client.status().queuedLogs, 0);
});

test("during a cold-start outage only the first request waits for rules", async (t) => {
  const mock = await startMock({ down: true });
  t.after(() => mock.close());
  const client = createClient(opts(mock, clock(), { logUrl: undefined, firstSyncTimeoutMs: 300, fetch: (async () => {
    await new Promise((r) => setTimeout(r, 5_000)); // a hanging server
    return new Response("{}", { status: 503 });
  }) as typeof fetch, requestTimeoutMs: 10_000 }));
  const t1 = performance.now();
  assert.equal((await client.check({ ip: "1.1.1.1" })).source, "fail_open");
  const first = performance.now() - t1;
  const t2 = performance.now();
  for (let i = 0; i < 20; i++) await client.check({ ip: "1.1.1.1" });
  const rest = performance.now() - t2;
  assert.ok(first >= 250 && first < 1000, `first request waited ~300 ms (${first.toFixed(0)})`);
  assert.ok(rest < 100, `later requests did not wait (${rest.toFixed(0)} ms for 20)`);
});

test("a rate-limited sync keeps the last good rules and waits as long as the server asks", async (t) => {
  const mock = await startMock({ rules: [blockRule("203.0.113.9")] });
  t.after(() => mock.close());
  const c = clock();
  const errors: string[] = [];
  const client = createClient(opts(mock, c, { logUrl: undefined, onError: (e) => errors.push(e.message) }));
  assert.equal((await client.check({ ip: "203.0.113.9" })).verdict, "blocked");

  mock.state.syncStatus = 429;
  mock.state.syncRetryAfter = "120";
  c.advance(31_000);
  await (await client.check({ ip: "1.1.1.1" })).background;
  const callsAfter429 = mock.state.syncCalls.length;
  assert.match(errors.at(-1) ?? "", /rate-limited/);
  assert.equal((await client.check({ ip: "203.0.113.9" })).verdict, "blocked", "last good rules still enforced");

  c.advance(60_000); // past the normal 30 s interval, inside the 120 s Retry-After
  await (await client.check({ ip: "1.1.1.1" })).background;
  assert.equal(mock.state.syncCalls.length, callsAfter429, "no sync during the Retry-After window");

  mock.state.syncStatus = null;
  c.advance(61_000);
  await (await client.check({ ip: "1.1.1.1" })).background;
  assert.equal(mock.state.syncCalls.length, callsAfter429 + 1, "syncs again once the window has passed");
  assert.equal(client.status().disabled, false);
});

test("Retry-After is read as seconds or a date and kept within 5 s to 5 min", () => {
  assert.equal(retryAfterMs("120", 1000), 120_000);
  assert.equal(retryAfterMs("1", 1000), 5_000);
  assert.equal(retryAfterMs("99999", 1000), 300_000);
  assert.equal(retryAfterMs(null, 30_000), 30_000);
  assert.equal(retryAfterMs("Fri, 23 Oct 2026 10:01:00 GMT", 1000, Date.parse("2026-10-23T10:00:00Z")), 60_000);
});
