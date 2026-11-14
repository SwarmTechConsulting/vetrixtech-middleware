# Changelog

## Unreleased

- **Old-name aliases removed.** Only the SwarmTech Shield names remain: `SwarmTechShield`, `ShieldClient`, `ShieldOptions` and Express's `req.swarmtechshield`. The GitHub repository is now `SwarmTechConsulting/swarmtechshield-middleware`.
- The README now shows the real connection-key prefix, `sts_conn_…`.

Rule patterns can no longer slow requests down.

- **Linear-time pattern matching.** Path and signature patterns in rules, virtual-patch patterns and inspection-exclusion paths now run on a built-in linear-time matcher (`src/linearRegex.ts`) instead of `RegExp`. JavaScript's `RegExp` backtracks, so a pattern such as `(a+)+$` could take seconds on a short request; now every pattern costs time in proportion to the request, whatever it looks like. Matching is still case-insensitive.
- Supported syntax is the usual subset: classes, groups (including named and non-capturing), alternation, `\d \w \s \b`, anchors and every quantifier. Lookahead/lookbehind and back-references aren't supported: a rule pattern that uses them falls back to a plain substring check (as invalid patterns always have), and a virtual patch that uses them is reported by `load()` and skipped. The SwarmTech Shield console refuses such patterns when they are written.
- Plain-text patterns (no regex features) are matched as substrings directly.

Service identities and synthetic traffic.

- **Service identities.** A request carrying `x-shield-service-token` with a token issued in the console is recognised by its SHA-256 hash, which arrives in the sync response as `service_identities`. A **service** identity skips screening; a **synthetic** identity is screened normally but is never counted towards rate limits, bursts or the flood baseline, never causes an IP block, and never raises an incident. Both are logged with `traffic_class`, so the console keeps them out of attack statistics. Unknown tokens are ignored. `result.identity` reports the identity; `SERVICE_HEADER` is exported.

## 0.5.0 (2026-10-29)

Resilience against application-layer floods. (Network-level DDoS needs an edge network in front; see the roadmap's Phase G.)

- **Under-attack mode.** Switched on by the console (`under_attack` in the sync response), from your code (`client.setUnderAttack(true)` or `resilience: { underAttack: true }`), or automatically when traffic runs at 5x its recent median and at least 50 requests a second for 20 seconds. It switches off after a calm minute. While on, the per-IP burst limit drops from 120 to 60 requests a minute, and request inspection blocks instead of only observing.
- **Load shedding.** On long-running servers (Express, or any client with `timers: true`), the middleware watches event-loop lag. Above 200 ms, anonymous requests to low-priority paths get a fast `503` with `Retry-After`; login, checkout, health checks, signed-in users (`getUser`) and allow-listed IPs are kept. Bring your own load metric with `resilience.loadProbe`. Shed requests are summarised in one log event every 30 seconds instead of one event each.
- **Early rejection.** A request from a blocked IP, or one that will be shed, no longer has its body read, so rejecting a flood costs almost nothing.
- `status().resilience` reports the request rate, baseline, load, under-attack state and shed count.

## 0.4.0 (2026-10-29)

Active defences that only an in-app middleware can provide.

- **Decoys and canary credentials.** Trap routes (`/.env`, `/.git/config`, `/wp-admin`, `/phpmyadmin` and similar) that no real visitor requests. Touching one blocks the request and the IP on that server. Bait paths answer with a believable fake file carrying canary credentials derived from the connection key; anyone who later presents one of those values in any request is identified with near certainty. A hidden form field (`website_url` by default, see `honeypotFieldHtml()`) catches automated form submissions. On by default; `decoys: false` turns it off. Allow rules still win, and explicit rules and the blocklist are untouched.
- **Login, payment and sign-up protection.** The app reports outcomes with `reportOutcome({ type, ip, user, success, fingerprint })`. The middleware then limits failed logins per account (catching credential stuffing spread across many IPs), the number of accounts tried from one IP, card testing (many cards from one IP or account on checkout paths) and sign-up bursts. Adapters take a `getUser(req)` option. Inert until you report outcomes.
- **Dependency-matched virtual patches.** Pass `dependencies` (or use `detectDependencies()` from the new `@swarmtechshield/middleware/node` entry). The client sends the list with full syncs and applies `virtual_patches` from the sync response only when the installed version is in the affected range, with the advisory and the fixed version in the block reason.
- **Signed verification probes.** The SwarmTech Shield checker can prove a route is protected: a probe signed with the connection key (HMAC-SHA256, 5-minute window, single use) gets `x-shield-status`, and a `test-block` probe gets a 403 with `x-shield-test: blocked`, without being logged as an attack. Unsigned or replayed probes are ignored. `decorate(response, result)` adds the header on allowed responses.
- `status()` now reports the inspection mode, whether decoys are on, and the active virtual patches.

## 0.3.0 (2026-10-23)

- **Deep request inspection.** A new scoring engine (`inspect`) checks the path, query string, headers, cookies and body for SQL injection, cross-site scripting, path traversal, command injection, SSRF, template injection, XXE, NoSQL injection, prototype pollution, Log4Shell-style lookups and probes for sensitive files. Findings are scored the way the OWASP Core Rule Set works: one high-confidence finding, or several weaker ones together, cross the block threshold.
  - On by default in **observe mode**, so it reports what it would block without changing any verdict. Set `inspection: true` to block, or pass a config object (`{ mode, paranoia, threshold, autoBlockScore, exclusions, disabledRules }`).
  - Four paranoia levels. Level 1 (default) is high-confidence only; higher levels catch more and flag more, so raise them per app after watching observe-mode output.
  - The Express and fetch adapters now read the request body (within a 64 KB cap, configurable with `maxBodyBytes`) and pass the headers, so inspection sees the whole request. The original body is never consumed.
  - A high-scoring request (score 10+) also blocklists the IP on that server for `localBlockSeconds`; a single threshold hit blocks only that request.
  - Allow rules still win over inspection, and the legacy path-signature scan is superseded only when inspection is actively blocking, so enabling it never reduces protection.
  - A built-in attack/normal test corpus checks detection stays at or above 95% and false positives at or below 2%.

## 0.2.0 (2026-10-23)

- **Published as `@swarmtechshield/middleware`.** The main export is `SwarmTechShield`, with `ShieldClient` and `ShieldOptions`. Express puts the result on `req.swarmtechshield`.
- A rate-limited sync (HTTP 429) now keeps the last good rules and waits for the server's `Retry-After` (5 s to 5 min) instead of retrying every 30 seconds. Log uploads honour `Retry-After` too.
- The SDK header is now `x-swarmtechshield-sdk`.
- Release workflow fixed so publishing from GitHub uses trusted publishing (0.1.1 was tagged on GitHub but never published).
- GitHub Actions updated to Node 24.

## 0.1.1 (2026-10-13)

- Tagged on GitHub but never published to npm (the release workflow failed; fixed in 0.2.0).
- `npm version patch|minor|major` now updates `SDK_VERSION`, the changelog and the README in one step.

## 0.1.0 (2026-10-13)

First version. MIT licence.

- Local rule evaluation from a synced cache (`syncRuleCache`), with background log upload (`submitTrafficLog`).
- Adapters: Express, Next.js middleware, Cloudflare Workers, Base44/Deno functions, and a generic `Request` handler.
- Shared engine (`src/engine.ts`), written to drop into the Base44 app, with the Phase 1 fixes:
  - allow rules are checked first and can't be overridden;
  - expired blocks are ignored;
  - max-size pattern rules work;
  - `rate_limit` rules work;
  - paths are URL-decoded before signature matching;
  - `curl` and `python-requests` are no longer auto-blocked;
  - IPv6 and IPv4-mapped addresses are supported.
- Fail open or fail closed, keeps the last good rules through outages, and lets traffic through when the key is rejected or the app is paused.
- Incident flags are deduplicated per IP and rule; query strings are left out of logs by default.
- Blocked and throttled log events are queued separately and sent first, so they're never dropped before allowed ones.
- 59 shared engine test vectors, plus client and adapter tests (96 in total).
