// SwarmTech Shield active defences that only an in-app middleware can provide.
//
//  - Decoys: trap routes and hidden form fields a real visitor never touches, plus bait
//    files carrying canary credentials. Touching a trap, or later presenting a canary
//    credential, identifies an attacker with near certainty.
//  - Outcome tracking: the app reports login, payment and sign-up results, so the
//    middleware can stop credential stuffing and card testing by account as well as IP.
//  - Virtual patches matched to the app's real dependencies: a patch only switches on
//    when the installed version of a package is affected.
//  - Verification probes: signed requests from the SwarmTech Shield checker prove a route
//    is protected, without letting anyone else learn anything about the configuration.
//
// Runtime-agnostic (Node, Deno, Bun, Workers). Only WebCrypto is used, when present.

import { collectParts, variants, type InspectionInput, type Location } from "./inspect.ts";

/* ------------------------------------------------------------------ */
/* Hashing helpers                                                     */
/* ------------------------------------------------------------------ */

function subtle(): SubtleCrypto | null {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  return c && c.subtle ? c.subtle : null;
}

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(bytes: number): string {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  const arr = new Uint8Array(bytes);
  if (c && c.getRandomValues) c.getRandomValues(arr);
  else for (let i = 0; i < bytes; i++) arr[i] = Math.floor(Math.random() * 256);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(text: string): Promise<string | null> {
  const s = subtle();
  if (!s) return null;
  return toHex(await s.digest("SHA-256", new TextEncoder().encode(text)));
}

export async function hmacSha256Hex(key: string, message: string): Promise<string | null> {
  const s = subtle();
  if (!s) return null;
  const k = await s.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await s.sign("HMAC", k, new TextEncoder().encode(message)));
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ------------------------------------------------------------------ */
/* Decoys and canary credentials                                       */
/* ------------------------------------------------------------------ */

export interface DecoyOptions {
  /** Trap paths (exact, or ending in "*" for a prefix). Defaults cover common probe targets. */
  paths?: string[];
  /** Serve believable bait (a fake .env with canary credentials) on bait paths instead of a 404. Default true. */
  bait?: boolean;
  /** Name of a hidden form field your forms include and people never fill in. Default "website_url". false disables. */
  formField?: string | false;
  /** Also block the IP on this server after a trap is touched. Default true. */
  blockIp?: boolean;
}

export const DEFAULT_DECOY_PATHS = [
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.git/config",
  "/wp-login.php",
  "/wp-admin*",
  "/phpmyadmin*",
  "/administrator*",
  "/admin.php",
  "/config.json.bak",
  "/backup.sql",
  "/.aws/credentials",
  "/server-status",
];

/** Paths that answer with bait files rather than a plain 404. */
const BAIT_PATHS: Record<string, "env" | "aws" | "git"> = {
  "/.env": "env",
  "/.env.local": "env",
  "/.env.production": "env",
  "/.aws/credentials": "aws",
  "/.git/config": "git",
};

export interface DecoyResponse {
  status: number;
  body: string;
  contentType: string;
}

export interface DecoyHit {
  kind: "trap" | "canary" | "form_field";
  reason: string;
  response?: DecoyResponse;
}

export class Decoys {
  readonly opts: Required<DecoyOptions>;
  private canaries: string[] = [];
  private ready: Promise<void>;

  constructor(seed: string, options: DecoyOptions = {}) {
    this.opts = {
      paths: options.paths ?? DEFAULT_DECOY_PATHS,
      bait: options.bait ?? true,
      formField: options.formField ?? "website_url",
      blockIp: options.blockIp ?? true,
    };
    // Canary values are derived from the connection key with SHA-256, so every server
    // running this app plants and recognises the same values, and the values reveal
    // nothing about the key. Without WebCrypto they are random per process.
    this.ready = (async () => {
      const a = (await sha256Hex(`swarmtechshield:decoy:a:${seed}`)) ?? randomHex(32);
      const b = (await sha256Hex(`swarmtechshield:decoy:b:${seed}`)) ?? randomHex(32);
      this.canaries = [`tok_${a.slice(0, 32)}`, `pw_${b.slice(0, 24)}`, `AKC${a.slice(32, 48).toUpperCase()}`];
    })().catch(() => {
      this.canaries = [`tok_${randomHex(16)}`, `pw_${randomHex(12)}`, `AKC${randomHex(8).toUpperCase()}`];
    });
  }

  whenReady(): Promise<void> {
    return this.ready;
  }

  /** The canary values (for tests and for the console to register). */
  canaryValues(): string[] {
    return [...this.canaries];
  }

  isTrap(path: string): boolean {
    const p = (path.split("?")[0] || "/").toLowerCase().replace(/\/{2,}/g, "/");
    return this.opts.paths.some((t) => {
      const target = t.toLowerCase();
      return target.endsWith("*") ? p.startsWith(target.slice(0, -1)) : p === target || p === `${target}/`;
    });
  }

  private bait(path: string): DecoyResponse {
    const p = path.split("?")[0].toLowerCase();
    const kind = BAIT_PATHS[p];
    const [tok, pw, akc] = this.canaries;
    if (this.opts.bait && kind === "env") {
      return {
        status: 200,
        contentType: "text/plain; charset=utf-8",
        body: [
          "APP_ENV=production",
          "APP_DEBUG=false",
          `APP_SECRET=${tok}`,
          `DATABASE_URL=postgres://app_admin:${pw}@db.internal:5432/app`,
          `API_TOKEN=${tok}`,
          "MAIL_HOST=smtp.internal",
          "",
        ].join("\n"),
      };
    }
    if (this.opts.bait && kind === "aws") {
      return {
        status: 200,
        contentType: "text/plain; charset=utf-8",
        body: `[default]\naccess_key_id = ${akc}\nsecret_access_key = ${tok}\n`,
      };
    }
    if (this.opts.bait && kind === "git") {
      return {
        status: 200,
        contentType: "text/plain; charset=utf-8",
        body: `[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://deploy:${pw}@git.internal/app.git\n`,
      };
    }
    return { status: 404, contentType: "text/plain; charset=utf-8", body: "Not Found" };
  }

  /** Check one request against traps, the hidden form field and the canary credentials. */
  check(input: InspectionInput, rawHeaders: Record<string, string | string[] | undefined> = {}): DecoyHit | null {
    const path = input.path || "/";
    if (this.isTrap(path)) {
      return { kind: "trap", reason: `Decoy route touched: ${path.split("?")[0]}`, response: this.bait(path) };
    }
    const field = this.opts.formField;
    if (field && input.body && typeof input.body === "object" && !Array.isArray(input.body)) {
      const v = (input.body as Record<string, unknown>)[field];
      if (typeof v === "string" ? v.trim() !== "" : v !== undefined && v !== null && v !== "") {
        return { kind: "form_field", reason: `Hidden form field "${field}" was filled in (automated submission)` };
      }
    }
    if (this.canaries.length) {
      const hay: string[] = [];
      for (const v of Object.values(rawHeaders)) hay.push(Array.isArray(v) ? v.join(",") : v ?? "");
      for (const part of collectParts({ ...input, headers: undefined }, 500)) hay.push(part.value);
      for (const h of hay) {
        if (!h) continue;
        for (const form of variants(h)) {
          if (this.canaries.some((c) => form.includes(c))) {
            return { kind: "canary", reason: "A canary credential from a decoy file was used: this client read the bait" };
          }
        }
      }
    }
    return null;
  }
}

/** HTML for the hidden form field. Put it inside every form you want protected. */
export function honeypotFieldHtml(name = "website_url"): string {
  return `<div style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden" aria-hidden="true"><label>Leave this empty<input type="text" name="${name}" tabindex="-1" autocomplete="off"></label></div>`;
}

/* ------------------------------------------------------------------ */
/* Outcome tracking: logins, payments, sign-ups                        */
/* ------------------------------------------------------------------ */

export type OutcomeType = "login" | "payment" | "signup";

export interface OutcomeReport {
  type: OutcomeType;
  /** Client IP (the same value the adapter uses). */
  ip?: string;
  /** The account the attempt was for: username, email or user id. */
  user?: string;
  success: boolean;
  /** Payments: a non-sensitive card fingerprint from your payment provider (never the card number). */
  fingerprint?: string;
}

export interface OutcomeRule {
  /** Paths this protection guards (exact, or ending in "*"). */
  paths: string[];
  windowSeconds: number;
  /** Failed attempts from one IP before it is stopped on these paths. */
  maxFailuresPerIp?: number;
  /** Failed attempts for one account before it is stopped on these paths. */
  maxFailuresPerUser?: number;
  /** Distinct accounts tried from one IP (account enumeration / stuffing). */
  maxUsersPerIp?: number;
  /** Payments: distinct cards tried from one IP or account (card testing). */
  maxCardsPerIp?: number;
  /** Sign-ups: successful sign-ups from one IP. */
  maxSuccessesPerIp?: number;
  action?: "throttle" | "block";
}

export type OutcomeConfig = Partial<Record<OutcomeType, Partial<OutcomeRule> | false>>;

export const DEFAULT_OUTCOME_RULES: Record<OutcomeType, OutcomeRule> = {
  login: {
    paths: ["/login", "/signin", "/sign-in", "/api/auth*", "/auth*", "/session*", "/oauth/token"],
    windowSeconds: 900,
    maxFailuresPerIp: 20,
    maxFailuresPerUser: 8,
    maxUsersPerIp: 10,
    action: "throttle",
  },
  payment: {
    paths: ["/checkout*", "/pay*", "/payment*", "/api/payment*", "/api/checkout*", "/orders*"],
    windowSeconds: 3600,
    maxFailuresPerIp: 6,
    maxFailuresPerUser: 6,
    maxCardsPerIp: 4,
    action: "block",
  },
  signup: {
    paths: ["/signup", "/sign-up", "/register", "/api/register*", "/api/signup*"],
    windowSeconds: 3600,
    maxSuccessesPerIp: 5,
    maxFailuresPerIp: 20,
    action: "throttle",
  },
};

interface Event {
  t: number;
  ok: boolean;
  user?: string;
  card?: string;
}

const MAX_KEYS = 50_000;
const MAX_EVENTS_PER_KEY = 500;

export interface OutcomeVerdict {
  type: OutcomeType;
  action: "throttle" | "block";
  reason: string;
}

export class OutcomeTracker {
  readonly rules: Partial<Record<OutcomeType, OutcomeRule>> = {};
  private byIp = new Map<string, Event[]>();
  private byUser = new Map<string, Event[]>();

  private clock: () => number;

  constructor(config: OutcomeConfig | undefined, clock: () => number) {
    this.clock = clock;
    for (const type of Object.keys(DEFAULT_OUTCOME_RULES) as OutcomeType[]) {
      const c = config?.[type];
      if (c === false) continue;
      this.rules[type] = { ...DEFAULT_OUTCOME_RULES[type], ...(c || {}) } as OutcomeRule;
    }
  }

  private push(map: Map<string, Event[]>, key: string, ev: Event) {
    let list = map.get(key);
    if (!list) {
      if (map.size >= MAX_KEYS) {
        let n = Math.ceil(MAX_KEYS / 10);
        for (const k of map.keys()) {
          map.delete(k);
          if (--n <= 0) break;
        }
      }
      list = [];
      map.set(key, list);
    }
    list.push(ev);
    if (list.length > MAX_EVENTS_PER_KEY) list.splice(0, list.length - MAX_EVENTS_PER_KEY);
  }

  report(r: OutcomeReport) {
    if (!this.rules[r.type]) return;
    const ev: Event = { t: this.clock(), ok: !!r.success, user: r.user ? r.user.trim().toLowerCase().slice(0, 200) : undefined, card: r.fingerprint?.slice(0, 100) };
    if (r.ip) this.push(this.byIp, `${r.type}|${r.ip}`, ev);
    if (ev.user) this.push(this.byUser, `${r.type}|${ev.user}`, ev);
    // A successful login clears that account's failure count.
    if (r.type === "login" && r.success && ev.user) {
      const list = this.byUser.get(`login|${ev.user}`);
      if (list) for (const e of list) if (!e.ok) e.ok = true;
    }
  }

  private recent(map: Map<string, Event[]>, key: string, since: number): Event[] {
    const list = map.get(key);
    if (!list) return [];
    let i = 0;
    while (i < list.length && list[i].t < since) i++;
    if (i) list.splice(0, i);
    return list;
  }

  /** Is this request to a protected path from an IP or account that has crossed a limit? */
  check(path: string, ip: string, user?: string): OutcomeVerdict | null {
    const p = (path.split("?")[0] || "/").toLowerCase();
    for (const type of Object.keys(this.rules) as OutcomeType[]) {
      const rule = this.rules[type]!;
      const guarded = rule.paths.some((t) => {
        const target = t.toLowerCase();
        return target.endsWith("*") ? p.startsWith(target.slice(0, -1)) : p === target || p === `${target}/`;
      });
      if (!guarded) continue;
      const since = this.clock() - rule.windowSeconds * 1000;
      const action = rule.action ?? "throttle";
      const mins = Math.round(rule.windowSeconds / 60);
      if (ip) {
        const evs = this.recent(this.byIp, `${type}|${ip}`, since);
        const fails = evs.filter((e) => !e.ok).length;
        if (rule.maxFailuresPerIp && fails >= rule.maxFailuresPerIp) {
          return { type, action, reason: `${fails} failed ${type} attempts from this IP in ${mins} min` };
        }
        if (rule.maxUsersPerIp) {
          const users = new Set(evs.filter((e) => e.user).map((e) => e.user)).size;
          if (users >= rule.maxUsersPerIp) return { type, action, reason: `${users} different accounts tried from this IP in ${mins} min` };
        }
        if (rule.maxCardsPerIp) {
          const cards = new Set(evs.filter((e) => e.card).map((e) => e.card)).size;
          if (cards >= rule.maxCardsPerIp) return { type, action, reason: `${cards} different cards tried from this IP in ${mins} min (card testing)` };
        }
        if (rule.maxSuccessesPerIp) {
          const ok = evs.filter((e) => e.ok).length;
          if (ok >= rule.maxSuccessesPerIp) return { type, action, reason: `${ok} ${type}s from this IP in ${mins} min` };
        }
      }
      if (user) {
        const key = user.trim().toLowerCase();
        const evs = this.recent(this.byUser, `${type}|${key}`, since);
        const fails = evs.filter((e) => !e.ok).length;
        if (rule.maxFailuresPerUser && fails >= rule.maxFailuresPerUser) {
          return { type, action, reason: `${fails} failed ${type} attempts for this account in ${mins} min` };
        }
        if (rule.maxCardsPerIp) {
          const cards = new Set(evs.filter((e) => e.card).map((e) => e.card)).size;
          if (cards >= rule.maxCardsPerIp) return { type, action, reason: `${cards} different cards tried for this account in ${mins} min (card testing)` };
        }
      }
    }
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Dependency-matched virtual patches                                  */
/* ------------------------------------------------------------------ */

export interface VirtualPatch {
  /** Stable id, e.g. "vp-2026-0012". */
  id: string;
  /** Advisory reference shown to the owner, e.g. a CVE or GHSA id. */
  advisory?: string;
  /** npm package name the patch is for. */
  package: string;
  /** Affected versions as a semver range, e.g. "<4.17.21" or ">=2.0.0 <2.3.1 || 3.0.0". */
  affected: string;
  /** Version that fixes it, for the upgrade advice. */
  fixed?: string;
  /** What to block while the app is unpatched. */
  rule: {
    /** Regular expression (max 1000 characters), matched case-insensitively. */
    pattern: string;
    locations?: Location[];
    description?: string;
  };
}

export interface ActivePatch {
  id: string;
  advisory?: string;
  package: string;
  installed: string;
  fixed?: string;
  description: string;
}

type Ver = [number, number, number, string];

function parseVer(v: string): Ver | null {
  const m = /^\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(?:-([0-9A-Za-z.-]+))?/.exec(v);
  if (!m) return null;
  const n = (s: string | undefined) => (s === undefined || s === "x" || s === "*" ? 0 : Number(s));
  return [Number(m[1]), n(m[2]), n(m[3]), m[4] || ""];
}

function cmp(a: Ver, b: Ver): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return (a[i] as number) < (b[i] as number) ? -1 : 1;
  if (a[3] === b[3]) return 0;
  if (!a[3]) return 1; // a release is newer than its pre-releases
  if (!b[3]) return -1;
  return a[3] < b[3] ? -1 : 1;
}

function satisfiesComparator(v: Ver, comp: string): boolean {
  const c = comp.trim();
  if (!c || c === "*" || c === "x") return true;
  const m = /^(<=|>=|<|>|=|\^|~)?\s*(.+)$/.exec(c);
  if (!m) return false;
  const op = m[1] || "=";
  const target = parseVer(m[2]);
  if (!target) return false;
  const r = cmp(v, target);
  switch (op) {
    case "<": return r < 0;
    case "<=": return r <= 0;
    case ">": return r > 0;
    case ">=": return r >= 0;
    case "=": return r === 0;
    case "^": {
      if (r < 0) return false;
      if (target[0] > 0) return v[0] === target[0];
      if (target[1] > 0) return v[0] === 0 && v[1] === target[1];
      return v[0] === 0 && v[1] === 0 && v[2] === target[2];
    }
    case "~": return r >= 0 && v[0] === target[0] && v[1] === target[1];
  }
  return false;
}

/** Minimal semver range check: comparators joined by spaces (AND) and "||" (OR). */
export function satisfies(version: string, range: string): boolean {
  const v = parseVer(version);
  if (!v) return false;
  return range.split("||").some((set) => {
    const comps = set.trim().split(/\s+/).filter(Boolean);
    return comps.length === 0 || comps.every((c) => satisfiesComparator(v, c));
  });
}

interface CompiledPatch {
  patch: VirtualPatch;
  re: RegExp;
  installed: string;
}

export class VirtualPatches {
  private compiled: CompiledPatch[] = [];
  private deps: Record<string, string> = {};

  setDependencies(deps: Record<string, string> | undefined) {
    this.deps = {};
    for (const [k, v] of Object.entries(deps || {}).slice(0, 2000)) {
      if (typeof v === "string") this.deps[k] = v.replace(/^[\^~=v\s]+/, "");
    }
  }

  dependencies(): Record<string, string> {
    return { ...this.deps };
  }

  /** Load patches (from the sync response) and keep only those affecting installed versions. */
  load(patches: VirtualPatch[] | undefined): string[] {
    const errors: string[] = [];
    this.compiled = [];
    for (const p of (patches || []).slice(0, 500)) {
      const installed = this.deps[p?.package];
      if (!installed || !p.rule?.pattern || !p.affected) continue;
      if (!satisfies(installed, p.affected)) continue;
      if (p.rule.pattern.length > 1000) {
        errors.push(`${p.id}: pattern too long`);
        continue;
      }
      try {
        this.compiled.push({ patch: p, re: new RegExp(p.rule.pattern, "i"), installed });
      } catch {
        errors.push(`${p.id}: invalid pattern`);
      }
    }
    return errors;
  }

  active(): ActivePatch[] {
    return this.compiled.map(({ patch, installed }) => ({
      id: patch.id,
      advisory: patch.advisory,
      package: patch.package,
      installed,
      fixed: patch.fixed,
      description: patch.rule.description || `Virtual patch for ${patch.package}`,
    }));
  }

  match(input: InspectionInput): ActivePatch | null {
    if (!this.compiled.length) return null;
    const parts = collectParts(input, 500);
    for (const c of this.compiled) {
      const locs = c.patch.rule.locations;
      for (const part of parts) {
        if (locs && !locs.includes(part.location)) continue;
        for (const form of variants(part.value)) {
          if (c.re.test(form)) {
            return this.active().find((a) => a.id === c.patch.id) || null;
          }
        }
      }
    }
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Verification probes                                                 */
/* ------------------------------------------------------------------ */

export const PROBE_HEADER = "x-shield-probe";
const PROBE_WINDOW_S = 300;

export interface ProbeResult {
  /** "status": report that this route is protected. "test-block": answer as a block would. */
  mode: "status" | "test-block";
}

/**
 * Verifies a signed probe from the SwarmTech Shield checker:
 *   x-shield-probe: t=<unix seconds>,m=<status|test-block>,sig=<hex>
 *   sig = HMAC-SHA256(connectionKey, "<t>.<m>.<METHOD>.<path without query>")
 * Probes are accepted once, within 5 minutes of their timestamp. Anything else is ignored,
 * so the header gives nothing away to someone without the connection key.
 */
export class ProbeVerifier {
  private seen = new Map<string, number>();
  private key: string;
  private clock: () => number;
  constructor(key: string, clock: () => number) {
    this.key = key;
    this.clock = clock;
  }

  async verify(headerValue: string | null | undefined, method: string, path: string): Promise<ProbeResult | null> {
    if (!headerValue || headerValue.length > 300) return null;
    const fields: Record<string, string> = {};
    for (const kv of headerValue.split(",")) {
      const i = kv.indexOf("=");
      if (i > 0) fields[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
    }
    const t = Number(fields.t);
    const m = fields.m;
    const sig = (fields.sig || "").toLowerCase();
    if (!Number.isFinite(t) || (m !== "status" && m !== "test-block") || !/^[0-9a-f]{64}$/.test(sig)) return null;
    const now = Math.floor(this.clock() / 1000);
    if (Math.abs(now - t) > PROBE_WINDOW_S) return null;
    if (this.seen.has(sig)) return null;
    const p = (path.split("?")[0] || "/");
    const expected = await hmacSha256Hex(this.key, `${t}.${m}.${method.toUpperCase()}.${p}`);
    if (!expected || !timingSafeEqualHex(expected, sig)) return null;
    this.seen.set(sig, now);
    if (this.seen.size > 10_000) {
      for (const [k, at] of this.seen) if (now - at > PROBE_WINDOW_S) this.seen.delete(k);
    }
    return { mode: m };
  }
}

/** Build a probe header value (used by the checker, and by tests). */
export async function signProbe(key: string, method: string, path: string, mode: "status" | "test-block", nowMs = Date.now()): Promise<string | null> {
  const t = Math.floor(nowMs / 1000);
  const sig = await hmacSha256Hex(key, `${t}.${mode}.${method.toUpperCase()}.${path.split("?")[0] || "/"}`);
  return sig ? `t=${t},m=${mode},sig=${sig}` : null;
}
