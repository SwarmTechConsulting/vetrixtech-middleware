import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createClient, type ShieldOptions } from "../src/client.ts";
import { SERVICE_HEADER } from "../src/defence.ts";
import { startMock, type Mock } from "./mock-server.ts";

const SERVICE_TOKEN = "sts_svc_backend_jobs_0123456789abcdef";
const SYNTHETIC_TOKEN = "sts_svc_uptime_monitor_fedcba987654321";
const hash = (t: string) => "sha256:" + createHash("sha256").update(t).digest("hex");

function clock(start = Date.parse("2026-11-14T08:00:00Z")) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}
function opts(mock: Mock, c: ReturnType<typeof clock>, extra: Partial<ShieldOptions> = {}): ShieldOptions {
  return { connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, now: c.now, flushIntervalMs: 0, ...extra } as ShieldOptions;
}
const identities = [
  { id: "si1", name: "Backend jobs", kind: "service", token_hash: hash(SERVICE_TOKEN) },
  { id: "si2", name: "Uptime monitor", kind: "synthetic", token_hash: hash(SYNTHETIC_TOKEN) },
];
const blockIp = { id: "r1", name: "Block", type: "ip_block", action: "block", priority: 1, deployment_state: "enforced", criteria: { ips: ["203.0.113.7"] } };

test("a service identity skips screening, even from a blocked IP or with an attack-looking path", async (t) => {
  const mock = await startMock({ rules: [blockIp], serviceIdentities: identities });
  t.after(() => mock.close());
  const client = createClient(opts(mock, clock(), { logUrl: undefined }));
  const r = await client.check({ ip: "203.0.113.7", path: "/functions/../etc/passwd", headers: { [SERVICE_HEADER]: SERVICE_TOKEN } });
  assert.equal(r.verdict, "allowed");
  assert.equal(r.identity?.kind, "service");
  assert.match(r.reason, /Service identity: Backend jobs/);
});

test("an unknown or missing token is screened as usual", async (t) => {
  const mock = await startMock({ rules: [blockIp], serviceIdentities: identities });
  t.after(() => mock.close());
  const client = createClient(opts(mock, clock(), { logUrl: undefined }));
  assert.equal((await client.check({ ip: "203.0.113.7", headers: { [SERVICE_HEADER]: "sts_svc_guess" } })).verdict, "blocked");
  assert.equal((await client.check({ ip: "203.0.113.7" })).verdict, "blocked");
  assert.equal((await client.check({ ip: "203.0.113.7", headers: { [SERVICE_HEADER]: SERVICE_TOKEN } })).identity?.name, "Backend jobs");
});

test("synthetic traffic is screened for real but never counted or IP-blocked", async (t) => {
  const mock = await startMock({ rules: [blockIp], serviceIdentities: identities });
  t.after(() => mock.close());
  const c = clock();
  const client = createClient(opts(mock, c, { logUrl: undefined }));
  const h = { [SERVICE_HEADER]: SYNTHETIC_TOKEN };
  // Screened normally: the rule still blocks it, so a self-test sees the real verdict.
  assert.equal((await client.check({ ip: "203.0.113.7", headers: h })).verdict, "blocked");
  // A burst from a monitor never trips the burst limit or an IP block.
  for (let i = 0; i < 300; i++) {
    const r = await client.check({ ip: "198.51.100.50", path: "/health", headers: h });
    assert.equal(r.verdict, "allowed", `request ${i}`);
  }
  // A signature hit is blocked, but the monitor's IP isn't blocked afterwards.
  assert.equal((await client.check({ ip: "198.51.100.50", path: "/x?q=' or '1'='1", headers: h })).verdict, "blocked");
  assert.equal((await client.check({ ip: "198.51.100.50", path: "/health" })).verdict, "allowed");
});

test("service and synthetic requests are logged with their class and never as incidents", async (t) => {
  const mock = await startMock({ rules: [blockIp], serviceIdentities: identities });
  t.after(() => mock.close());
  const client = createClient(opts(mock, clock()));
  await client.check({ ip: "203.0.113.7", path: "/a", headers: { [SERVICE_HEADER]: SERVICE_TOKEN } });
  await client.check({ ip: "203.0.113.7", path: "/b", headers: { [SERVICE_HEADER]: SYNTHETIC_TOKEN } });
  await client.check({ ip: "203.0.113.7", path: "/c" });
  await client.flush();
  const logs = mock.state.logBatches.flat() as any[];
  const byPath = Object.fromEntries(logs.map((l) => [l.path, l]));
  assert.equal(byPath["/a"].traffic_class, "service");
  assert.equal(byPath["/a"].details.service_identity, "Backend jobs");
  assert.equal(byPath["/b"].traffic_class, "synthetic");
  assert.equal(byPath["/b"].is_incident, false);
  assert.equal(byPath["/c"].traffic_class, undefined);
  assert.equal(byPath["/c"].is_incident, true);
  assert.ok(!JSON.stringify(logs).includes(SERVICE_TOKEN), "tokens are never logged");
});

test("revoking an identity on the server takes effect at the next full sync", async (t) => {
  const mock = await startMock({ rules: [blockIp], serviceIdentities: identities });
  t.after(() => mock.close());
  const c = clock();
  const client = createClient(opts(mock, c, { logUrl: undefined }));
  const h = { [SERVICE_HEADER]: SERVICE_TOKEN };
  assert.equal((await client.check({ ip: "203.0.113.7", headers: h })).verdict, "allowed");
  mock.state.serviceIdentities = [];
  mock.state.version = 2;
  c.advance(31_000);
  await (await client.check({ ip: "198.51.100.1" })).background;
  assert.equal((await client.check({ ip: "203.0.113.7", headers: h })).verdict, "blocked");
});
