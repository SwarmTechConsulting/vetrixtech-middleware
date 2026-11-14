# @swarmtechshield/middleware

Drop-in SwarmTech Shield request screening for Express, Next.js, Cloudflare Workers and Base44/Deno functions.

Your app keeps a local copy of its SwarmTech Shield rules and judges every request on the spot. There is no network call per request, so screening adds well under a millisecond. Traffic logs go to SwarmTech Shield in the background, and the console shows them as usual.

```
                 every 30 s (background)
  your app  ───────────────────────────────▶  syncRuleCache    (rules + blocklist)
     │
     │  each request: judged locally by the same engine SwarmTech Shield's server uses
     │
     └──── every 5 s or 100 events ───────▶  submitTrafficLog (traffic logs)
```

## Install

```bash
npm install @swarmtechshield/middleware
```

No runtime dependencies. Requires Node 18+, or any runtime with `fetch` (Deno, Bun, Cloudflare Workers, edge runtimes).

You need three values from the SwarmTech Shield console (**Admin Console → Connections** and the **Integration** page):

| Value | Where it goes |
|---|---|
| Connection key (`sts_conn_…`) | An environment variable, e.g. `SWARMTECH_SHIELD_KEY`. Never put it in browser code or commit it. |
| Sync URL (`…/functions/syncRuleCache`) | `syncUrl` |
| Log URL (`…/functions/submitTrafficLog`) | `logUrl` |

## Usage

### Express

```js
import express from "express";
import { SwarmTechShield } from "@swarmtechshield/middleware"; // or: const { SwarmTechShield } = require("@swarmtechshield/middleware");

const app = express();
app.set("trust proxy", 1); // one load balancer in front of the app; makes req.ip the real client

app.use(SwarmTechShield.express({
  connectionKey: process.env.SWARMTECH_SHIELD_KEY,
  syncUrl: process.env.SWARMTECH_SHIELD_SYNC_URL,
  logUrl: process.env.SWARMTECH_SHIELD_LOG_URL,
}));
```

Blocked requests get `403 Forbidden`, throttled ones `429` with `Retry-After`. The result is also on `req.swarmtechshield` if you want to inspect it.

### Next.js (`middleware.ts`)

```ts
import { SwarmTechShield } from "@swarmtechshield/middleware";

export const middleware = SwarmTechShield.nextjs({
  connectionKey: process.env.SWARMTECH_SHIELD_KEY!,
  syncUrl: process.env.SWARMTECH_SHIELD_SYNC_URL!,
  logUrl: process.env.SWARMTECH_SHIELD_LOG_URL,
});

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
```

On Vercel the client IP comes from `x-real-ip` and the country from `x-vercel-ip-country`, both set by Vercel.

### Cloudflare Workers

```ts
import { SwarmTechShield } from "@swarmtechshield/middleware";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const result = await SwarmTechShield.cloudflare(request, {
      connectionKey: env.SWARMTECH_SHIELD_KEY,
      syncUrl: env.SWARMTECH_SHIELD_SYNC_URL,
      logUrl: env.SWARMTECH_SHIELD_LOG_URL,
    }, ctx);
    if (!result.allowed) return SwarmTechShield.toResponse(result)!;
    return fetch(request);
  },
};
```

The client IP comes from `CF-Connecting-IP` and the country from `request.cf`.

### Base44 backend functions (Deno)

```ts
import { SwarmTechShield } from "npm:@swarmtechshield/middleware@0.5.0";

export default async function (req: Request): Promise<Response> {
  const result = await SwarmTechShield.base44(req, {
    connectionKey: Deno.env.get("SWARMTECH_SHIELD_KEY")!,
    syncUrl: Deno.env.get("SWARMTECH_SHIELD_SYNC_URL")!,
    logUrl: Deno.env.get("SWARMTECH_SHIELD_LOG_URL"),
  });
  if (!result.allowed) return SwarmTechShield.toResponse(result)!;

  // ... your handler
  return Response.json({ ok: true });
}
```

There is no `waitUntil` in this environment. So on the requests where a log flush is due, the function waits for it, for at most `backgroundWaitMs` (default 500 ms). The other requests don't wait at all.

### Anything else (Deno.serve, Bun.serve, Hono, custom servers)

```ts
const result = await SwarmTechShield.screenRequest(request, { connectionKey, syncUrl, logUrl, trustedHeader: "x-real-ip" });
// or, with your own request parsing:
const client = SwarmTechShield.getClient({ connectionKey, syncUrl, logUrl });
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
4. **Deep request inspection.** The path, query string, headers, cookies and body are scored for attack payloads (see below). A matching request is blocked when it is in block mode; in observe mode it is only recorded. When inspection is actively blocking, it supersedes the legacy path-signature scan.
5. **Scanner tools.** Dedicated attack tools (`sqlmap`, `nikto`, `nuclei`…) are blocked by user agent. General clients like `curl` and `python-requests` are **not**.
6. **Rate burst.** More than 120 requests from one IP in 60 s is blocked; configure with `burst`.

`result.decision.trace` lists every step with a plain-English reason, and the trace always ends on the actual verdict.

## Deep request inspection

Inspection looks inside the whole request, not just the URL, so an injection sent in a POST body or a cookie is caught. It covers SQL injection, cross-site scripting, path traversal and file inclusion, command injection, SSRF, template injection (SSTI), XXE, NoSQL injection, prototype pollution, Log4Shell-style `${jndi:}` lookups, and probes for sensitive files such as `.env` and `.git`.

Each finding adds to an anomaly score, the way the OWASP Core Rule Set works. One high-confidence finding (score 5) blocks on its own; weaker hints only block when several appear together. This keeps both evasion and false alarms low.

```js
app.use(SwarmTechShield.express({
  connectionKey: process.env.SWARMTECH_SHIELD_KEY,
  syncUrl: process.env.SWARMTECH_SHIELD_SYNC_URL,
  logUrl: process.env.SWARMTECH_SHIELD_LOG_URL,
  inspection: true, // block; omit for observe-only, the default
}));
```

**Roll it out in observe mode first.** By default (`inspection` left unset) it runs in observe mode: every would-be block is logged to the console as an incident, but nothing is blocked. Watch those for a week, add exclusions for any false positives, then switch to `inspection: true`.

`inspection` accepts a config object:

| Field | Default | What it does |
|---|---|---|
| `mode` | `"observe"` (`"block"` when you pass `inspection: true`) | `"block"`, `"observe"` or `"off"`. |
| `paranoia` | `1` | 1 to 4. Level 1 is high-confidence only. Higher levels catch more but flag more; raise per app after watching observe mode. |
| `threshold` | `5` | Block when the score reaches this. |
| `autoBlockScore` | `10` | Also blocklist the IP on this server (for `localBlockSeconds`) when a single request scores this high. `0` disables. |
| `exclusions` | none | Known false positives to ignore, by path, location, parameter name and/or rule. |
| `disabledRules` | none | Rule ids or categories (e.g. `"xss"`) switched off everywhere. |
| `maxBodyBytes` | `65536` | How much of the body to read for inspection (adapter option). `0` turns body reading off. |

An exclusion silences one known-good case without weakening the rest:

```js
inspection: {
  mode: "block",
  exclusions: [
    // A markdown editor whose "content" field legitimately contains HTML and code.
    { path: "^/posts/.*/edit", locations: ["body"], names: ["content"], rules: ["xss"] },
  ],
}
```

Call `SwarmTechShield.inspect(request, config)` directly if you want to score a request yourself. Findings redact values of sensitive fields (passwords, tokens, cards) before they reach logs.

## Active defences

These use what only middleware running inside your app can see.

### Decoys and canary credentials (on by default)

Requests for trap paths that real visitors never ask for (`/.env`, `/.git/config`, `/wp-admin`, `/phpmyadmin`, `/backup.sql` and others in `DEFAULT_DECOY_PATHS`) are blocked, and the IP is blocked on that server for `localBlockSeconds`. Bait paths such as `/.env` answer with a believable fake file carrying **canary credentials**. If anyone later presents one of those values anywhere in a request, they read the bait, and they are blocked.

Add a hidden field to your forms to catch bots that fill in every input:

```js
import { honeypotFieldHtml } from "@swarmtechshield/middleware";
// inside each <form>:  ${honeypotFieldHtml()}
```

Options: `decoys: { paths, bait, formField, blockIp }`, or `decoys: false`. Allow rules still win.

### Login, payment and sign-up protection

Tell the middleware how attempts went, and it stops abuse by account as well as by IP:

```js
const shield = { connectionKey: process.env.SWARMTECH_SHIELD_KEY, syncUrl: process.env.SWARMTECH_SHIELD_SYNC_URL };
app.use(SwarmTechShield.express({ ...shield, getUser: (req) => req.body?.email }));

app.post("/login", async (req, res) => {
  const ok = await signIn(req.body.email, req.body.password);
  SwarmTechShield.reportOutcome(shield, { type: "login", ip: req.ip, user: req.body.email, success: ok });
  // ...
});
```

| Type | Guarded paths (default) | Stops |
|---|---|---|
| `login` | `/login`, `/signin`, `/api/auth*`, `/auth*`… | 8 failures for one account, 20 failures or 10 accounts from one IP, per 15 min (throttle) |
| `payment` | `/checkout*`, `/pay*`, `/payment*`, `/orders*`… | 6 failures, or 4 different cards from one IP or account, per hour (block). Pass your payment provider's card `fingerprint`, never card numbers |
| `signup` | `/signup`, `/register`… | 5 sign-ups or 20 failures from one IP per hour (throttle) |

Override any of these with `outcomes: { login: { paths, maxFailuresPerUser, … } }`.

### Virtual patches matched to your dependencies

```js
import { detectDependencies } from "@swarmtechshield/middleware/node";
const dependencies = await detectDependencies(); // { "some-package": "2.3.0", ... }
app.use(SwarmTechShield.express({ ...shield, dependencies }));
```

The dependency names and versions go to SwarmTech Shield with each full sync (turn off with `reportDependencies: false`). When a package you have installed has a known vulnerability, the server sends a virtual patch, and the middleware applies it only if your installed version is affected. The block reason names the advisory and the version to upgrade to.

### Verification probes

The SwarmTech Shield checker can prove each route is protected. Its probes are signed with your connection key, valid for 5 minutes and single-use; anything else is ignored. A `test-block` probe gets `403` with `x-shield-test: blocked` and is not logged as an attack. On Cloudflare Workers and Base44 functions, wrap allowed responses with `SwarmTechShield.decorate(response, result)` so status probes see the `x-shield-status` header (Express does this for you).

## Service identities and synthetic traffic

Your own backend calls, scheduled jobs, webhooks and uptime monitors are not attackers, but they can look like them: a job that walks every record trips rate limits, and a monitor that hits `/health` every few seconds inflates your traffic. Give each one a **service identity** in the SwarmTech Shield console (**Settings → Service identities**) and send its token on every request:

```http
x-shield-service-token: sts_svc_…
```

There are two kinds:

- **Service.** The request skips screening entirely and is logged as service traffic. Use it for your own backends and jobs.
- **Synthetic.** The request is screened normally, so a self-test sees the real verdict. It is never counted towards rate limits or bursts, never gets its IP blocked, and never raises an incident. Use it for health checks, uptime monitors and test suites.

The console shows the token once. The middleware receives only its SHA-256 hash on sync, so there is no extra secret to configure. A request carrying an unknown token is screened as usual. Revoking an identity takes effect at the next rule refresh (every 30 seconds by default). Treat a service token like a password: anyone holding one bypasses screening for that app.

`SERVICE_HEADER` is exported if you want the header name in code, and `result.identity` tells you which identity a request used.

## Staying up under a flood

The middleware can't absorb a network-level DDoS: that needs an edge network such as Cloudflare in front of your app. It does keep your app working when a flood of requests reaches it.

- **Under-attack mode** turns on from the console, from your code (`SwarmTechShield.getClient(opts).setUnderAttack(true)`), or by itself when traffic runs at 5 times its recent level (and at least 50 requests a second) for 20 seconds. It halves the per-IP burst limit and makes inspection block rather than observe, then switches off after a calm minute.
- **Load shedding** watches event-loop lag on long-running servers. Above 200 ms it answers low-priority anonymous requests with a fast `503` and `Retry-After`, and keeps serving logins, checkout, health checks, signed-in users and allow-listed IPs.
- **Early rejection** skips reading the body of any request that will be blocked anyway.

```js
app.use(SwarmTechShield.express({
  ...shield,
  getUser: (req) => req.user?.id,                 // signed-in users are never shed
  resilience: {
    loadShedding: { maxLagMs: 150, priorityPaths: ["/login", "/checkout*", "/api/orders*"] },
  },
}));
```

Set `resilience: false` to turn all of this off.

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
| `autoDetection` | `true` | Legacy path-signature and scanner-UA detection. |
| `inspection` | observe mode | Deep request inspection. `true` to block, `false` to turn off, or a config object (see above). |
| `maxBodyBytes` | `65536` | Bytes of the request body read for inspection and decoys. `0` turns body reading off. |
| `decoys` | on | Trap routes, bait with canary credentials, hidden form field. `false` disables. |
| `outcomes` | on | Login, payment and sign-up limits fed by `reportOutcome()`. |
| `dependencies` / `reportDependencies` | none / `true` | Installed package versions, for dependency-matched virtual patches. |
| `verification` | `true` | Answer signed probes from the SwarmTech Shield checker. |
| `resilience` | on | Under-attack mode, load shedding and early rejection: `{ underAttack, auto, burst, enforceInspection, loadShedding, loadProbe }`, or `false`. |
| Adapters: `getUser` | none | Return the signed-in account for per-account limits. |
| `onError` | none | `(error, context) => void` for sync, log and configuration problems. |
| Response: `blockedStatus`, `blockedBody`, `throttledStatus`, `retryAfterSeconds` | 403, `"Forbidden"`, 429, 60 | What blocked visitors receive. The body never names the rule. |
| Adapters: `skip`, `getClientIp`, `trustedHeader`, `trustedProxyCount`, `countryHeader`, `onBlocked` (Express) | | See above. |

## When SwarmTech Shield is unreachable

| Situation | What happens |
|---|---|
| Cold start, SwarmTech Shield down | The first request waits up to 1.5 s for rules; after that no request waits. `failMode` applies and a retry runs every 5 s in the background. |
| Outage after rules loaded | Keeps enforcing the last good rules for `maxStaleMs` (15 min), then applies the app's fail mode. |
| Key rejected or app paused | **Lets all traffic through** (`source: "disabled"`), calls `onError`, and retries every 30 s. A wrong key or a paused app never takes your site down. |
| Sync rate-limited (HTTP 429) | Keeps enforcing the last good rules and waits for the server's `Retry-After` (5 s to 5 min) before trying again. |
| Log upload fails | Events stay queued (up to `maxQueue`) and are retried after 10 s. |
| Any internal error | `check()` never throws; the fail mode applies. |
| Missing connection key or URL (edge/Base44 adapters) | Requests are let through and the problem is reported once via `onError` (or `console.error`). The Express adapter throws at startup instead, so you see it immediately. |

## Limits worth knowing

- **Counts are per server.** Rate limits and burst detection count requests in each server's memory. An app running on 3 servers allows up to 3× a limit. Use SwarmTech Shield's server-side screening, or a shared store, if you need exact global limits.
- **Not in the middleware yet:** the adaptive safe-throttle (it needs the app's profile, which `syncRuleCache` doesn't send), port-scan detection, and block escalation. Escalation happens on the server when it receives the logs.
- **Log volume:** each upload carries up to 100 events, and one upload runs at a time per server. If more traffic arrives than that can carry (or the server's upload limit is reached), allowed events are dropped first; blocked and throttled events are kept and sent first. `client.status().droppedLogs` shows the count. For busy apps, set `logAllowed` to a sample rate such as `0.1`.
- **Incidents:** each server flags at most one incident per IP and rule every 30 minutes, and never for blocklist hits. This keeps AI alert costs bounded even before the server-side fixes in the plan land.

## Keeping the server and the middleware identical

`src/engine.ts` is written to drop straight into the Base44 app as `base44/shared/ruleEngine.ts`. That file is in `base44-drop-in/`, next to `vectors.json` and a Deno test. It keeps every export your backend functions use today (`matchRule`, `traceRequest`, `detectSignals`, `detectConflicts`, `explainRule`, `ipMatches`…) and adds `evaluate()`, which Phase 1.1 switches `screenRequest` to.

```bash
node scripts/check-engine.mjs ../swarmtechshield-app/base44/shared/ruleEngine.ts   # fails if the two copies differ
```

Both copies run `test/vectors.json` (59 cases). Change a rule in one engine without copying it to the other, and a test fails.

## Development

```bash
npm test          # 120 tests: engine vectors, client (against a local mock of the two endpoints), adapters
npm run typecheck
npm run build     # dist/esm + dist/cjs + type declarations
```

See `PUBLISHING.md` for releasing to npm.

## Licence

MIT. See `LICENSE`.
