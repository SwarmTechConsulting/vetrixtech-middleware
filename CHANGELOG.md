# Changelog

## Unreleased

- First release published from GitHub (trusted publishing with provenance).
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
