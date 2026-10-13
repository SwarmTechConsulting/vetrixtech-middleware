import { test } from "node:test";
import assert from "node:assert/strict";
import { VetrixTech } from "../src/index.ts";
import { clientIpFromHeaders, fromForwardedFor, cleanIp } from "../src/ip.ts";
import { startMock } from "./mock-server.ts";

const rules = [{ id: "r1", name: "Block bad", type: "ip_block", action: "block", deployment_state: "enforced", criteria: { ips: ["203.0.113.9"] } }];

let keyN = 0;
const freshKey = () => `vtx_conn_adapter_${++keyN}`;

test("X-Forwarded-For: the client-written first value is never trusted", () => {
  // Attacker sends "X-Forwarded-For: 10.0.0.5" hoping to look allowlisted; the proxy appends the real IP.
  assert.equal(fromForwardedFor("10.0.0.5, 203.0.113.9"), "203.0.113.9");
  assert.equal(fromForwardedFor("10.0.0.5, 203.0.113.9, 172.16.0.2", 2), "203.0.113.9");
  assert.equal(fromForwardedFor(""), "");
  assert.equal(cleanIp("203.0.113.9:4431"), "203.0.113.9");
  assert.equal(cleanIp("[2001:db8::1]:443"), "2001:db8::1");
  assert.equal(cleanIp("not an ip"), "");
  const h: Record<string, string> = { "x-real-ip": "198.51.100.4", "x-forwarded-for": "1.1.1.1, 198.51.100.4" };
  assert.equal(clientIpFromHeaders((n) => h[n], {}, ["x-real-ip"]), "198.51.100.4");
  assert.equal(clientIpFromHeaders((n) => h[n], { trustedHeader: "X-Real-IP" }), "198.51.100.4");
});

function fakeExpress(ip: string, url = "/") {
  const req = { ip, method: "GET", originalUrl: url, headers: { "user-agent": "Mozilla/5.0" } as Record<string, string> };
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    headers: {} as Record<string, string>,
    status(c: number) {
      this.statusCode = c;
      return this;
    },
    set(k: string, v: string) {
      this.headers[k] = v;
      return this;
    },
    send(b: unknown) {
      this.body = b;
      return this;
    },
  };
  return { req, res };
}

function runExpress(mw: ReturnType<typeof VetrixTech.express>, ip: string, url = "/") {
  const { req, res } = fakeExpress(ip, url);
  return new Promise<{ nextCalled: boolean; res: typeof res; req: typeof req }>((resolve) => {
    mw(req as never, res as never, () => resolve({ nextCalled: true, res, req }));
    const origSend = res.send.bind(res);
    res.send = (b: unknown) => {
      origSend(b);
      resolve({ nextCalled: false, res, req });
      return res;
    };
  });
}

test("Express: blocks with 403, passes allowed requests to next(), uses req.ip", async (t) => {
  const mock = await startMock({ rules });
  t.after(() => mock.close());
  mock.state.key = freshKey();
  const mw = VetrixTech.express({ connectionKey: mock.state.key, syncUrl: mock.syncUrl });
  const blocked = await runExpress(mw, "::ffff:203.0.113.9");
  assert.equal(blocked.nextCalled, false);
  assert.equal(blocked.res.statusCode, 403);
  assert.equal(blocked.res.body, "Forbidden", "never reveals the rule name");
  const ok = await runExpress(mw, "198.51.100.1");
  assert.equal(ok.nextCalled, true);
  assert.equal((ok.req as Record<string, unknown> & { vetrixtech?: { verdict: string } }).vetrixtech?.verdict, "allowed");
});

test("Express: throttled requests get 429 with Retry-After", async (t) => {
  const mock = await startMock({
    rules: [{ id: "t", name: "Throttle all", type: "pattern", action: "throttle", deployment_state: "enforced", criteria: { path: "^/" } }],
  });
  t.after(() => mock.close());
  mock.state.key = freshKey();
  const mw = VetrixTech.express({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, retryAfterSeconds: 30 });
  const r = await runExpress(mw, "198.51.100.1");
  assert.equal(r.res.statusCode, 429);
  assert.equal(r.res.headers["Retry-After"], "30");
});

test("Next.js: returns a 403 Response when blocked and undefined to continue", async (t) => {
  const mock = await startMock({ rules });
  t.after(() => mock.close());
  mock.state.key = freshKey();
  const mw = VetrixTech.nextjs({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, logBatchSize: 1 });
  const waited: Promise<unknown>[] = [];
  const event = { waitUntil: (p: Promise<unknown>) => void waited.push(p) };
  const blocked = await mw(new Request("https://app.test/x", { headers: { "x-real-ip": "203.0.113.9" } }), event);
  assert.equal(blocked?.status, 403);
  const ok = await mw(new Request("https://app.test/x", { headers: { "x-real-ip": "198.51.100.1" } }), event);
  assert.equal(ok, undefined);
  assert.ok(waited.length >= 1, "background work handed to waitUntil");
  await Promise.all(waited);
});

test("Cloudflare: uses CF-Connecting-IP and request.cf.country", async (t) => {
  const mock = await startMock({
    rules: [{ id: "g", name: "Geo", type: "geo", action: "block", deployment_state: "enforced", criteria: { countries: ["KP"] } }],
  });
  t.after(() => mock.close());
  mock.state.key = freshKey();
  const req = new Request("https://app.test/", { headers: { "cf-connecting-ip": "198.51.100.8", "x-forwarded-for": "10.0.0.1" } });
  Object.defineProperty(req, "cf", { value: { country: "KP" } });
  const ctx = { waitUntil: (_p: Promise<unknown>) => {} };
  const r = await VetrixTech.cloudflare(req, { connectionKey: mock.state.key, syncUrl: mock.syncUrl }, ctx);
  assert.equal(r.verdict, "blocked");
  assert.equal(VetrixTech.toResponse(r)?.status, 403);
});

test("Base44/Deno: right-most X-Forwarded-For defeats a spoofed first value", async (t) => {
  const mock = await startMock({ rules });
  t.after(() => mock.close());
  mock.state.key = freshKey();
  const o = { connectionKey: mock.state.key, syncUrl: mock.syncUrl };
  const spoofed = new Request("https://fn.test/", { headers: { "x-forwarded-for": "198.51.100.1, 203.0.113.9" } });
  assert.equal((await VetrixTech.base44(spoofed, o)).verdict, "blocked");
  const clean = new Request("https://fn.test/", { headers: { "x-forwarded-for": "198.51.100.1" } });
  assert.equal((await VetrixTech.base44(clean, o)).verdict, "allowed");
});

test("skip() bypasses screening", async (t) => {
  const mock = await startMock({ rules });
  t.after(() => mock.close());
  mock.state.key = freshKey();
  const r = await VetrixTech.screenRequest(new Request("https://x.test/healthz", { headers: { "x-forwarded-for": "203.0.113.9" } }), {
    connectionKey: mock.state.key,
    syncUrl: mock.syncUrl,
    skip: (req) => new URL(req.url).pathname === "/healthz",
  });
  assert.equal(r.verdict, "allowed");
  assert.equal(r.reason, "Skipped");
});

test("a missing connection key fails open and is reported once, instead of crashing every request", async () => {
  const errors: string[] = [];
  const mw = VetrixTech.nextjs({ connectionKey: "", syncUrl: "https://x.test/sync", onError: (e) => errors.push(e.message) });
  const a = await mw(new Request("https://app.test/.env"));
  const b = await mw(new Request("https://app.test/.env"));
  assert.equal(a, undefined);
  assert.equal(b, undefined);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /connectionKey/);
});

test("Express: an error thrown downstream goes to next(err), not an unhandled rejection", async (t) => {
  const mock = await startMock();
  t.after(() => mock.close());
  mock.state.key = freshKey();
  const mw = VetrixTech.express({ connectionKey: mock.state.key, syncUrl: mock.syncUrl });
  const { req, res } = fakeExpress("198.51.100.1");
  const args: unknown[] = [];
  await new Promise<void>((resolve) => {
    mw(req as never, res as never, (err?: unknown) => {
      args.push(err);
      if (args.length === 1) throw new Error("handler blew up");
      resolve();
    });
  });
  assert.equal(args.length, 2);
  assert.equal(args[0], undefined);
  assert.match(String(args[1]), /handler blew up/);
});

test("IPv4-mapped addresses are normalised to plain IPv4", () => {
  assert.equal(cleanIp("::ffff:203.0.113.9"), "203.0.113.9");
});
