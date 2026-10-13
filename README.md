# @vetrixtech/middleware

Drop-in VetrixTech request screening for Express, Next.js, Cloudflare Workers and Base44/Deno functions.

Your app keeps a local copy of its VetrixTech rules and judges every request on the spot. There is no network call per request, so screening adds well under a millisecond. Traffic logs go to VetrixTech in the background, and the console shows them as usual.

```
                 every 30 s (background)
  your app  ───────────────────────────────▶  syncRuleCache    (rules + blocklist)
     │
     │  each request: judged locally by the same engine VetrixTech's server uses
     │
     └──── every 5 s or 100 events ───────▶  submitTrafficLog (traffic logs)
```

## Install

```bash
npm install @vetrixtech/middleware
```

No runtime dependencies. Requires Node 18+, or any runtime with `fetch` (Deno, Bun, Cloudflare Workers, edge runtimes).

You need three values from the VetrixTech console (**Admin Console → Connections** and the **Integration** page):

| Value | Where it goes |
|---|---|
| Connection key (`vtx_conn_…`) | An environment variable, e.g. `VETRIXTECH_KEY`. Never put it in browser code or commit it. |
| Sync URL (`…/functions/syncRuleCache`) | `syncUrl` |
| Log URL (`…/functions/submitTrafficLog`) | `logUrl` |

## Usage

### Express

```js
import express from "express";
import { VetrixTech } from "@vetrixtech/middleware"; // or: const { VetrixTech } = require("@vetrixtech/middleware");

const app = express();
app.set("trust proxy", 1); // one load balancer in front of the app; makes req.ip the real client

app.use(VetrixTech.express({
  connectionKey: process.env.VETRIXTECH_KEY,
  syncUrl: process.env.VETRIXTECH_SYNC_URL,
  logUrl: process.env.VETRIXTECH_LOG_URL,
}));
```

Blocked requests get `403 Forbidden`, throttled ones `429` with `Retry-After`. The result is also on `req.vetrixtech` if you want to inspect it.

### Next.js (`middleware.ts`)

```ts
import { VetrixTech } from "@vetrixtech/middleware";

export const middleware = VetrixTech.nextjs({
  connectionKey: process.env.VETRIXTECH_KEY!,
  syncUrl: process.env.VETRIXTECH_SYNC_URL!,
  logUrl: process.env.VETRIXTECH_LOG_URL,
});

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
```

On Vercel the client IP comes from `x-real-ip` and the country from `x-vercel-ip-country`, both set by Vercel.

### Cloudflare Workers

```ts
import { VetrixTech } from "@vetrixtech/middleware";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const result = await VetrixTech.cloudflare(request, {
      connectionKey: env.VETRIXTECH_KEY,
      syncUrl: env.VETRIXTECH_SYNC_URL,
      logUrl: env.VETRIXTECH_LOG_URL,
    }, ctx);
    if (!result.allowed) return VetrixTech.toResponse(result)!;
    return fetch(request);
  },
};
```

The client IP comes from `CF-Connecting-IP` and the country from `request.cf`.

### Base44 backend functions (Deno)

```ts
import { VetrixTech } from "npm:@vetrixtech/middleware@0.1.1";

export default async function (req: Request): Promise<Response> {
  const result = await VetrixTech.base44(req, {
    connectionKey: Deno.env.get("VETRIXTECH_KEY")!,
    syncUrl: Deno.env.get("VETRIXTECH_SYNC_URL")!,
    logUrl: Deno.env.get("VETRIXTECH_LOG_URL"),
  });
  if (!result.allowed) return VetrixTech.toResponse(result)!;

  // ... your handler
  return Response.json({ ok: true });
}
```

There is no `waitUntil` in this environment. So on the requests where a log flush is due, the function waits for it, for at most `backgroundWaitMs` (default 500 ms). The other requests don't wait at all.

### Anything else (Deno.serve, Bun.serve, Hono, custom servers)

```ts
const result = await VetrixTech.screenRequest(request, { connectionKey, syncUrl, logUrl, trustedHeader: "x-real-ip" });
// or, with your own request parsing:
const client = VetrixTech.getClient({ connectionKey, syncUrl, logUrl });
const result = await client.check({ ip, method, path, userAgent, bodySize, country });
```

## The client IP: read this

Every IP-based feature depends on getting the real client IP. Requests can include their own `X-Forwarded-For`, so **the first value in that header can be faked**. If you used it, an attacker could pose as an allowlisted IP. Defaults per adapter:

| Adapter | Default source | Override |
|---|---|---|
| Express | `req.ip`, which follows `app.set("trust proxy", …)` | `trustedHeader`, `trustedProxyCount`, `getClientIp` |
| Next.js | `x-real-ip`, then `X-Forwarded-For` counted from the right | same |
| Cloudflare | `CF-Connecting-IP` | same |
| Base44 / generic | `X-Forwarded-For` counted from the right (`trustedProxyCount`, default 1) | same |

`trustedProxyCount` is the number of proxies **you** run that append to `X-Forwarded-For`. Only set `trustedHeader` to a header your own infrastructure writes and overwrites.

If no IP can be found, IP rules, the blocklist and rate limits are skipped for that request. Attack-pattern checks still run, and `onError` is called once with a warning.

## How a request is judged

The engine (`src/engine.ts`) runs these checks in order:

1. **Allow rules.** A matching allow rule ends evaluation; nothing later can block that request.
2. **Blocklist.** Expired entries are ignored. IPs caught by auto-detection are also blocked locally for `localBlockSeconds`.
3. **Block and throttle rules**, by priority. Observe-only rules are logged, never enforced. Rolled-back and inactive rules are skipped.
4. **Auto-detection.** Known attack patterns in the path or user agent are checked after URL-decoding (twice), so encoded attacks are caught. So are dedicated scanner tools (`sqlmap`, `nikto`, `nuclei`…). General clients like `curl` and `python-requests` are **not** blocked.
5. **Rate burst.** More than 120 requests from one IP in 60 s is blocked; configure with `burst`.

`result.decision.trace` lists every step with a plain-English reason, and the trace always ends on the actual verdict.

## Options

| Option | Default | What it does |
|---|---|---|
| `connectionKey` | required | The app's connection key. |
| `syncUrl` | required | URL of `syncRuleCache`. |
| `logUrl` | none | URL of `submitTrafficLog`. Omit to turn off logging. |
| `failMode` | `"open"` | `"open"` allows or `"closed"` blocks requests while no usable rules exist. Replaced by the app's own setting after the first sync. |
| `syncIntervalMs` | 30,000 | How often to check for rule changes. |
| `fullSyncEveryMs` | 300,000 | Download all rules at least this often, even if the version looks unchanged. |
| `maxStaleMs` | 900,000 | How long to keep enforcing the last good rules during an outage before applying the fail mode. |
| `firstSyncTimeoutMs` | 1,500 | Longest a cold start waits for rules. |
| `requestTimeoutMs` | 3,000 | Timeout for sync and log calls. |
| `logAllowed` | `true` | Log allowed requests: `true`, `false`, or a sample rate such as `0.1`. Blocked and throttled requests are always logged. |
| `logQueryString` | `false` | Include query strings in logged paths. Off because they often carry tokens. |
| `logBatchSize` / `logFlushIntervalMs` | 100 / 5,000 | Log batching. |
| `maxQueue` | 5,000 | Log events kept in memory during an outage; the oldest are dropped first. |
| `localBlockSeconds` | 900 | How long this server remembers an IP that auto-detection caught. |
| `burst` | `{ maxRequests: 120, windowSeconds: 60 }` | Burst auto-block; `false` disables it. |
| `autoDetection` | `true` | Attack-pattern and scanner detection. |
| `onError` | none | `(error, context) => void` for sync, log and configuration problems. |
| Response: `blockedStatus`, `blockedBody`, `throttledStatus`, `retryAfterSeconds` | 403, `"Forbidden"`, 429, 60 | What blocked visitors receive. The body never names the rule. |
| Adapters: `skip`, `getClientIp`, `trustedHeader`, `trustedProxyCount`, `countryHeader`, `onBlocked` (Express) | | See above. |

## When VetrixTech is unreachable

| Situation | What happens |
|---|---|
| Cold start, VetrixTech down | The first request waits up to 1.5 s for rules; after that no request waits. `failMode` applies and a retry runs every 5 s in the background. |
| Outage after rules loaded | Keeps enforcing the last good rules for `maxStaleMs` (15 min), then applies the app's fail mode. |
| Key rejected or app paused | **Lets all traffic through** (`source: "disabled"`), calls `onError`, and retries every 30 s. A wrong key or a paused app never takes your site down. |
| Log upload fails | Events stay queued (up to `maxQueue`) and are retried after 10 s. |
| Any internal error | `check()` never throws; the fail mode applies. |
| Missing connection key or URL (edge/Base44 adapters) | Requests are let through and the problem is reported once via `onError` (or `console.error`). The Express adapter throws at startup instead, so you see it immediately. |

## Limits worth knowing

- **Counts are per server.** Rate limits and burst detection count requests in each server's memory. An app running on 3 servers allows up to 3× a limit. Use VetrixTech's server-side screening, or a shared store, if you need exact global limits.
- **Not in the middleware yet:** the adaptive safe-throttle (it needs the app's profile, which `syncRuleCache` doesn't send), port-scan detection, and block escalation. Escalation happens on the server when it receives the logs.
- **Log volume:** each upload carries up to 100 events, and one upload runs at a time per server. If more traffic arrives than that can carry (or the server's upload limit is reached), allowed events are dropped first; blocked and throttled events are kept and sent first. `client.status().droppedLogs` shows the count. For busy apps, set `logAllowed` to a sample rate such as `0.1`.
- **Incidents:** each server flags at most one incident per IP and rule every 30 minutes, and never for blocklist hits. This keeps AI alert costs bounded even before the server-side fixes in the plan land.

## Keeping the server and the middleware identical

`src/engine.ts` is written to drop straight into the Base44 app as `base44/shared/ruleEngine.ts`. That file is in `base44-drop-in/`, next to `vectors.json` and a Deno test. It keeps every export your backend functions use today (`matchRule`, `traceRequest`, `detectSignals`, `detectConflicts`, `explainRule`, `ipMatches`…) and adds `evaluate()`, which Phase 1.1 switches `screenRequest` to.

```bash
node scripts/check-engine.mjs ../vetrixtech-app/base44/shared/ruleEngine.ts   # fails if the two copies differ
```

Both copies run `test/vectors.json` (59 cases). Change a rule in one engine without copying it to the other, and a test fails.

## Development

```bash
npm test          # 96 tests: engine vectors, client (against a local mock of the two endpoints), adapters
npm run typecheck
npm run build     # dist/esm + dist/cjs + type declarations
```

See `PUBLISHING.md` for releasing to npm.

## Licence

MIT. See `LICENSE`.
