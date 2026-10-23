# Changelog

## Unreleased

## 0.2.0 (2026-10-23)

- **Renamed to `@swarmtechshield/middleware`**, following the product's rename from VetrixTech to SwarmTech Shield. The main export is now `SwarmTechShield`, with `ShieldClient` and `ShieldOptions`. Express puts the result on `req.swarmtechshield`. The old names (`VetrixTech`, `VetrixClient`, `VetrixOptions`, `req.vetrixtech`) still work as aliases.
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
