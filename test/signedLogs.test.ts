import { test } from "node:test";
import assert from "node:assert/strict";
import { createClient } from "../src/client.ts";
import { signBatch } from "../src/defence.ts";
import { startMock, verifySignature } from "./mock-server.ts";

test("every log upload carries a valid signature", async (t) => {
  const mock = await startMock({ requireSignature: true });
  t.after(() => mock.close());
  const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl });
  await client.check({ ip: "203.0.113.1", path: "/a" });
  await client.check({ ip: "203.0.113.2", path: "/b" });
  await client.flush();
  assert.ok(mock.state.signatureChecks.length >= 1);
  assert.ok(mock.state.signatureChecks.every((c) => c === "ok"), mock.state.signatureChecks.join(","));
  assert.equal(mock.state.logBatches.flat().length, 2);
});

test("a tampered, replayed, stale or foreign batch is refused", async () => {
  const key = "sts_conn_signing_test";
  const body = JSON.stringify({ connection_key: key, logs: [{ source_ip: "1.2.3.4" }] });
  const now = Date.parse("2026-11-14T10:00:00Z");
  const sig = (await signBatch(key, body, now))!;
  const seen = new Set<string>();
  assert.equal(verifySignature(sig, body.replace("1.2.3.4", "6.6.6.6"), key, seen, now), "bad_signature");
  assert.equal(verifySignature(sig, body, "sts_conn_other", seen, now), "bad_signature");
  assert.equal(verifySignature(sig, body, key, seen, now + 301_000), "stale_signature");
  assert.equal(verifySignature("", body, key, seen, now), "unsigned_batch");
  assert.equal(verifySignature(sig, body, key, seen, now), "ok");
  assert.equal(verifySignature(sig, body, key, seen, now), "replayed_batch");
});

test("nonces differ between batches", async () => {
  const a = await signBatch("k", "{}", 0);
  const b = await signBatch("k", "{}", 0);
  assert.notEqual(a, b);
});
