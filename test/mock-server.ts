// A local stand-in for the two Base44 functions the middleware talks to.
// Request/response shapes mirror base44/functions/syncRuleCache and submitTrafficLog.

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export interface MockState {
  key: string;
  appStatus: "active" | "paused";
  failMode: "fail_open" | "fail_closed";
  version: number;
  rules: unknown[];
  blocklist: unknown[];
  down: boolean;
  syncCalls: { client_version: unknown }[];
  logBatches: unknown[][];
  logStatus: number | null;
  /** Force syncRuleCache to answer with this status (and Retry-After, if set). */
  syncStatus: number | null;
  syncRetryAfter: string | null;
}

export interface Mock {
  state: MockState;
  syncUrl: string;
  logUrl: string;
  close(): Promise<void>;
}

export async function startMock(init: Partial<MockState> = {}): Promise<Mock> {
  const state: MockState = {
    key: "vtx_conn_test",
    appStatus: "active",
    failMode: "fail_open",
    version: 1,
    rules: [],
    blocklist: [],
    down: false,
    syncCalls: [],
    logBatches: [],
    logStatus: null,
    syncStatus: null,
    syncRetryAfter: null,
    ...init,
  };

  const server: Server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const send = (status: number, body: unknown, extra: Record<string, string> = {}) => {
        res.writeHead(status, { "content-type": "application/json", ...extra });
        res.end(JSON.stringify(body));
      };
      if (state.down) return send(503, { error: "unavailable" });
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(raw);
      } catch {
        return send(400, { error: "Invalid request body" });
      }
      const authorised = body.connection_key === state.key && state.appStatus === "active";

      if (req.url === "/functions/syncRuleCache") {
        state.syncCalls.push({ client_version: body.client_version });
        if (state.syncStatus) {
          return send(state.syncStatus, { error: "forced" }, state.syncRetryAfter ? { "retry-after": state.syncRetryAfter } : {});
        }
        if (!body.connection_key) return send(401, { error: "Missing connection_key" });
        if (!authorised) return send(401, { error: "Invalid or inactive connection key" });
        if (body.client_version != null && body.client_version === state.version) {
          return send(200, { up_to_date: true, version: state.version, fail_mode: state.failMode });
        }
        return send(200, {
          up_to_date: false,
          version: state.version,
          fail_mode: state.failMode,
          app_name: "Test app",
          rules: state.rules,
          blocklist: state.blocklist,
          generated_at: new Date().toISOString(),
        });
      }
      if (req.url === "/functions/submitTrafficLog") {
        if (state.logStatus) return send(state.logStatus, { error: "forced" });
        if (!authorised) return send(401, { error: "Invalid or inactive connection key" });
        const logs = body.logs as unknown[];
        if (!Array.isArray(logs) || !logs.length) return send(400, { error: "Missing logs array" });
        const batch = logs.slice(0, 100);
        state.logBatches.push(batch);
        return send(200, { ok: true, accepted: batch.length });
      }
      send(404, { error: "not found" });
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${port}/functions`;
  return {
    state,
    syncUrl: `${base}/syncRuleCache`,
    logUrl: `${base}/submitTrafficLog`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
