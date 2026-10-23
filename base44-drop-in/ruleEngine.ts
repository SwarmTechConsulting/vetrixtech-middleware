// SwarmTech Shield rule engine.
//
// This one file is the single source of truth for how a request is judged.
// It is used by the @swarmtechshield/middleware package AND is written to drop into
// the Base44 app as base44/shared/ruleEngine.ts (it keeps every export the
// existing backend functions import). Keep it free of runtime-specific APIs so
// it runs unchanged in Node, Deno, Bun, Cloudflare Workers and edge runtimes.
//
// Evaluation order (see evaluate()):
//   1. Allow rules           – an allow match ends evaluation; nothing later can block.
//   2. Blocklist             – expired entries are ignored.
//   3. Block / throttle rules by priority (rate_limit rules included).
//   4. Auto-detection        – malicious signatures, known scanner user agents.
//   5. Rate burst            – too many requests from one IP.
//   6. Adaptive throttle     – optional bounded safe limit.

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

export type Verdict = "allowed" | "blocked" | "throttled";
export type DeploymentState = "enforced" | "observe_only" | "staged" | "rolled_back";

export interface RuleCriteria {
  ips?: string[];
  cidrs?: string[];
  countries?: string[];
  path?: string;
  method?: string;
  max_size?: number | string;
  signatures?: string[];
  port?: number | string;
  max_requests?: number | string;
  window_seconds?: number | string;
  [key: string]: unknown;
}

export interface Rule {
  id?: string;
  name?: string;
  type: string;
  criteria?: RuleCriteria;
  action?: "block" | "allow" | "throttle" | string;
  priority?: number;
  active?: boolean;
  deployment_state?: DeploymentState | string;
  app_id?: string;
  [key: string]: unknown;
}

export interface BlockEntry {
  id?: string;
  ip_or_range: string;
  app_id?: string | null;
  reason?: string;
  source?: string;
  expires_at?: string | null;
  status?: string;
  [key: string]: unknown;
}

export interface RequestContext {
  app_id?: string;
  source_ip: string;
  method?: string;
  path?: string;
  port?: number | string | null;
  country?: string;
  user_agent?: string;
  body_size?: number | string;
  headers?: Record<string, string>;
}

/** Counts requests from the current IP in the last `windowSeconds`, INCLUDING the current one. */
export type RateCounter = (windowSeconds: number, scope?: { method?: string; path?: string }) => number;

export interface EvaluateData {
  rules?: Rule[];
  blocklist?: BlockEntry[];
  /** Current time in ms (defaults to Date.now()). */
  now?: number;
  /** Request counter for rate_limit rules, burst detection and adaptive throttle. */
  rateCount?: RateCounter;
  /** Burst auto-block threshold. Set false to disable. Default 120 requests / 60 s. */
  burst?: { maxRequests: number; windowSeconds: number } | false;
  /** Adaptive safe-throttle (from an enabled AdaptiveProfile). */
  adaptive?: { maxRequests: number; windowSeconds: number } | null;
  /** Signature and scanner auto-detection. Default true. */
  autoDetection?: boolean;
}

export interface TraceStep {
  check: string;
  matched: boolean;
  reason: string;
  action?: string;
}

export interface Triggered {
  id: string;
  name: string;
  type: string;
  action: string;
}

export interface Decision {
  verdict: Verdict;
  reason: string;
  triggered: Triggered | null;
  /** Set when auto-detection blocked the request (the server may add the IP to the blocklist). */
  autoBlock: { type: "signature" | "scanner" | "rate_burst"; reason: string } | null;
  adaptiveThrottled: boolean;
  /** Observe-only rules that matched (they never change the verdict). */
  observed: { id: string; name: string; action: string }[];
  trace: TraceStep[];
}

export const DEFAULT_BURST = { maxRequests: 120, windowSeconds: 60 };
const MAX_MATCH_LENGTH = 4096;

/* ------------------------------------------------------------------ */
/* IP addresses (IPv4 + IPv6)                                          */
/* ------------------------------------------------------------------ */

interface ParsedIp {
  v: 4 | 6;
  n: bigint;
}

function parseV4(s: string): bigint | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const x = Number(p);
    if (x > 255) return null;
    n = (n << 8n) | BigInt(x);
  }
  return n;
}

function parseV6(input: string): bigint | null {
  let s = input;
  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  if (!s.includes(":")) return null;

  // Embedded IPv4 tail, e.g. ::ffff:203.0.113.5
  let tail: bigint | null = null;
  const lastColon = s.lastIndexOf(":");
  const maybeV4 = s.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    tail = parseV4(maybeV4);
    if (tail === null) return null;
    s = s.slice(0, lastColon + 1) + "0:0";
  }

  const dbl = s.split("::");
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(":") : [];
  const rest = dbl.length === 2 && dbl[1] ? dbl[1].split(":") : [];
  const missing = 8 - head.length - rest.length;
  if (dbl.length === 1 && head.length !== 8) return null;
  if (dbl.length === 2 && missing < 1) return null;
  const groups = dbl.length === 2 ? [...head, ...Array(missing).fill("0"), ...rest] : head;
  if (groups.length !== 8) return null;

  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  if (tail !== null) n = (n & ~0xffffffffn) | tail;
  return n;
}

/** Parse an IPv4 or IPv6 address. IPv4-mapped IPv6 (::ffff:a.b.c.d) is returned as IPv4. */
export function parseIp(ip: string): ParsedIp | null {
  if (!ip || typeof ip !== "string") return null;
  const s = ip.trim();
  const v4 = parseV4(s);
  if (v4 !== null) return { v: 4, n: v4 };
  const v6 = parseV6(s);
  if (v6 === null) return null;
  if (v6 >> 32n === 0xffffn) return { v: 4, n: v6 & 0xffffffffn };
  return { v: 6, n: v6 };
}

/** Legacy helper kept for existing callers: IPv4 only, returns a number. */
export function ipToInt(ip: string): number | null {
  const p = parseIp(ip);
  if (!p || p.v !== 4) return null;
  return Number(p.n);
}

/** Is this a valid single IP, CIDR ("10.0.0.0/8", "2001:db8::/32") or dash range ("a-b")? */
export function isValidIpSpec(spec: string): boolean {
  if (!spec || typeof spec !== "string") return false;
  const v = spec.trim();
  if (v.includes("/")) {
    const [base, bitsStr] = v.split("/");
    const p = parseIp(base);
    if (!p || !/^\d{1,3}$/.test(bitsStr)) return false;
    const bits = Number(bitsStr);
    return bits >= 0 && bits <= (p.v === 4 ? 32 : 128);
  }
  if (v.includes("-")) {
    const [a, b] = v.split("-");
    const pa = parseIp(a);
    const pb = parseIp(b);
    return !!pa && !!pb && pa.v === pb.v;
  }
  return parseIp(v) !== null;
}

/** Does `source` (a single IP) fall within `spec` (IP, CIDR or dash range)? Works for IPv4 and IPv6. */
export function ipMatches(source: string, spec: string): boolean {
  if (!source || !spec) return false;
  const s = source.trim();
  const v = spec.trim();
  if (s === v) return true;
  const src = parseIp(s);
  if (!src) return false;

  if (v.includes("/")) {
    const [base, bitsStr] = v.split("/");
    const b = parseIp(base);
    if (!b || b.v !== src.v || !/^\d{1,3}$/.test(bitsStr)) return false;
    const width = src.v === 4 ? 32n : 128n;
    const bits = BigInt(Number(bitsStr));
    if (bits > width) return false;
    if (bits === 0n) return true;
    const all = (1n << width) - 1n;
    const mask = (all << (width - bits)) & all;
    return (src.n & mask) === (b.n & mask);
  }
  if (v.includes("-")) {
    const [aStr, bStr] = v.split("-");
    const a = parseIp(aStr);
    const b = parseIp(bStr);
    if (!a || !b || a.v !== src.v || b.v !== src.v) return false;
    const lo = a.n < b.n ? a.n : b.n;
    const hi = a.n < b.n ? b.n : a.n;
    return src.n >= lo && src.n <= hi;
  }
  const single = parseIp(v);
  return !!single && single.v === src.v && single.n === src.n;
}

/* ------------------------------------------------------------------ */
/* Request normalisation and signatures                                */
/* ------------------------------------------------------------------ */

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s.replace(/%([0-9a-fA-F]{2})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)));
  }
}

/** Canonical form used for signature matching: decoded (twice), + as space, / separators, lower case. */
export function normalizePath(path: string): string {
  let s = String(path || "").slice(0, MAX_MATCH_LENGTH).replace(/\+/g, " ");
  for (let i = 0; i < 2; i++) {
    const d = safeDecode(s);
    if (d === s) break;
    s = d;
  }
  return s.replace(/\\/g, "/").replace(/\/{2,}/g, "/").toLowerCase();
}

export const BAD_SIGNATURES: { name: string; pattern: RegExp }[] = [
  { name: "SQL injection", pattern: /(\bunion\b\s+(all\s+)?\bselect\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'|--\s|\/\*|\*\/|;\s*drop\b)/i },
  { name: "XSS probe", pattern: /(<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+src\s*=)/i },
  { name: "Path traversal", pattern: /(\.\.\/|\.\.\\|%2e%2e|\/etc\/passwd|\/etc\/shadow)/i },
  { name: "Command injection", pattern: /(\|\s*\w+\s|;\s*(cat|ls|wget|curl|rm|bash|sh)\b|`|\$\()/i },
  { name: "Shellshock", pattern: /\(\)\s*\{\s*:;?\s*\}\s*;/i },
  { name: "Common exploit path", pattern: /(\/wp-admin|\/wp-login|\/\.env|\/\.git\/|phpmyadmin|\/vendor\/phpunit)/i },
];

/** Returns the first malicious signature found in the text (checked raw and normalised), else null. */
export function detectSignature(text: string): string | null {
  if (!text) return null;
  const raw = String(text).slice(0, MAX_MATCH_LENGTH);
  const norm = normalizePath(raw);
  for (const sig of BAD_SIGNATURES) {
    if (sig.pattern.test(raw) || sig.pattern.test(norm)) return sig.name;
  }
  return null;
}

/** Dedicated attack tools only. General HTTP clients (curl, python-requests) are NOT auto-blocked. */
export const BAD_UA_PATTERNS: RegExp[] = [
  /sqlmap/i, /nikto/i, /\bnmap\b/i, /masscan/i, /dirbuster/i, /gobuster/i, /wpscan/i, /acunetix/i,
  /nessus/i, /zgrab/i, /nuclei/i, /\bffuf\b/i,
];

export function isSuspiciousUA(ua: string): boolean {
  if (!ua) return false;
  return BAD_UA_PATTERNS.some((p) => p.test(ua));
}

export const AUTH_PATH_PATTERNS: RegExp[] = [
  /\/(login|signin|sign-in|auth|authenticate|oauth\/token|password|reset-password|forgot-password|account\/login)/i,
];

/** Automation tools: used for advisory bot-behaviour signals only, never auto-blocked. */
export const HEADLESS_UA_PATTERNS: RegExp[] = [
  /headless/i, /phantomjs/i, /selenium/i, /puppeteer/i, /playwright/i, /webdriver/i, /chromedriver/i,
  /pyppeteer/i, /mechanize/i, /scrapy/i, /httpx/i, /go-http-client/i, /java\//i, /okhttp/i, /libwww/i,
  /lwp-/i, /winhttp/i, /httpclient/i, /go-resty/i, /curl\//i, /python-requests/i, /wget\//i,
];

export function isAuthPath(path: string): boolean {
  if (!path) return false;
  return AUTH_PATH_PATTERNS.some((p) => p.test(path));
}

export function isHeadlessUA(ua: string): boolean {
  if (!ua) return false;
  return HEADLESS_UA_PATTERNS.some((p) => p.test(ua));
}

/* ------------------------------------------------------------------ */
/* Rule matching                                                       */
/* ------------------------------------------------------------------ */

const regexCache = new Map<string, RegExp | null>();

function userRegex(src: string): RegExp | null {
  if (regexCache.has(src)) return regexCache.get(src)!;
  let re: RegExp | null = null;
  try {
    re = new RegExp(src, "i");
  } catch {
    re = null;
  }
  if (regexCache.size > 500) regexCache.clear();
  regexCache.set(src, re);
  return re;
}

/** Regex match with substring fallback for invalid patterns. */
function textMatches(pattern: string, text: string): boolean {
  const re = userRegex(pattern);
  const t = text.slice(0, MAX_MATCH_LENGTH);
  return re ? re.test(t) : t.toLowerCase().includes(pattern.toLowerCase());
}

function methodMatches(ruleMethod: unknown, method: string | undefined): boolean {
  if (!ruleMethod || ruleMethod === "*") return true;
  return String(ruleMethod).toUpperCase() === String(method || "GET").toUpperCase();
}

function pathMatches(rulePath: unknown, path: string | undefined): boolean {
  if (!rulePath || rulePath === "*") return true;
  return textMatches(String(rulePath), String(path || "/"));
}

/** Does a recorded request fall inside a rate-limit scope? Used by request counters. */
export function scopeMatches(scope: { method?: string; path?: string } | undefined, method: string, path: string): boolean {
  if (!scope) return true;
  return methodMatches(scope.method, method) && pathMatches(scope.path, path);
}

function toNum(x: unknown): number | null {
  if (x === null || x === undefined || x === "") return null;
  const n = Number(x);
  return Number.isFinite(n) ? n : null;
}

/**
 * Does a single rule match the request? Every criterion that is set must match.
 * rate_limit rules need `rateCount`; without it they never match.
 */
export function matchRule(rule: Rule, ctx: RequestContext, rateCount?: RateCounter): boolean {
  const c: RuleCriteria = rule.criteria || {};
  switch (rule.type) {
    case "ip_block":
    case "ip_allow": {
      const specs = [...(c.ips || []), ...(c.cidrs || [])];
      return specs.some((spec) => ipMatches(ctx.source_ip, spec));
    }
    case "geo": {
      const countries = (c.countries || []).map((x) => String(x).trim().toUpperCase()).filter(Boolean);
      if (!countries.length || !ctx.country) return false;
      return countries.includes(String(ctx.country).trim().toUpperCase());
    }
    case "pattern": {
      const hasMethod = !!c.method && c.method !== "*";
      const hasPath = !!c.path && c.path !== "*";
      const maxSize = toNum(c.max_size);
      const sigs = (c.signatures || []).filter(Boolean);
      if (!hasMethod && !hasPath && maxSize === null && !sigs.length) return false;
      if (!methodMatches(c.method, ctx.method)) return false;
      if (!pathMatches(c.path, ctx.path)) return false;
      if (maxSize !== null && !((toNum(ctx.body_size) ?? 0) > maxSize)) return false;
      if (sigs.length) {
        const raw = `${ctx.path || ""} ${ctx.user_agent || ""}`;
        const text = `${raw} ${normalizePath(ctx.path || "")}`;
        if (!sigs.some((s) => textMatches(String(s), text))) return false;
      }
      return true;
    }
    case "port": {
      if (c.port === null || c.port === undefined || c.port === "") return false;
      const ports = String(c.port).split(",").map((p) => parseInt(p.trim(), 10)).filter((n) => !isNaN(n));
      return ports.includes(Number(ctx.port));
    }
    case "rate_limit": {
      const max = toNum(c.max_requests);
      const win = toNum(c.window_seconds);
      if (!rateCount || max === null || win === null || win <= 0) return false;
      if (!methodMatches(c.method, ctx.method)) return false;
      if (!pathMatches(c.path, ctx.path)) return false;
      const scope: { method?: string; path?: string } = {};
      if (c.method && c.method !== "*") scope.method = String(c.method);
      if (c.path && c.path !== "*") scope.path = String(c.path);
      return rateCount(win, scope) > max;
    }
    default:
      return false;
  }
}

/* ------------------------------------------------------------------ */
/* Explanations                                                        */
/* ------------------------------------------------------------------ */

export function explainRule(rule: Rule): string {
  const c: RuleCriteria = rule.criteria || {};
  const verb = rule.action === "allow" ? "Allows" : rule.action === "throttle" ? "Throttles" : "Blocks";
  const parts: string[] = [];
  switch (rule.type) {
    case "ip_block":
    case "ip_allow": {
      const v = rule.type === "ip_allow" ? "Allows" : verb;
      if (c.ips?.length) parts.push(`${v} requests from IPs: ${c.ips.join(", ")}`);
      if (c.cidrs?.length) parts.push(`${v} requests from ranges: ${c.cidrs.join(", ")}`);
      break;
    }
    case "geo":
      if (c.countries?.length) parts.push(`${verb} requests from countries: ${c.countries.join(", ")}`);
      break;
    case "pattern":
      if (c.method && c.method !== "*") parts.push(`Matches ${c.method} requests`);
      if (c.path && c.path !== "*") parts.push(`Path matches pattern: ${c.path}`);
      if (toNum(c.max_size) !== null) parts.push(`Body size exceeds ${c.max_size} bytes`);
      if (c.signatures?.length) parts.push(`Contains signatures: ${c.signatures.join(", ")}`);
      break;
    case "port":
      if (c.port) parts.push(`${verb} requests on ports: ${c.port}`);
      break;
    case "rate_limit": {
      const scope = [c.method && c.method !== "*" ? c.method : "", c.path && c.path !== "*" ? `path ${c.path}` : ""]
        .filter(Boolean)
        .join(" ");
      if (toNum(c.max_requests) !== null && toNum(c.window_seconds) !== null) {
        parts.push(
          `${verb} an IP after ${c.max_requests} requests in ${c.window_seconds} seconds${scope ? ` (${scope})` : ""}`,
        );
      }
      break;
    }
  }
  if (parts.length === 0) return "No criteria defined — this rule will not match any traffic.";
  return parts.join(". ") + ".";
}

/* ------------------------------------------------------------------ */
/* evaluate(): the one decision function                               */
/* ------------------------------------------------------------------ */

function sortedRules(rules: Rule[]): Rule[] {
  return rules
    .map((r, i) => ({ r, i }))
    .sort((a, b) => (Number(a.r.priority ?? 100) - Number(b.r.priority ?? 100)) || a.i - b.i)
    .map((x) => x.r);
}

function isLive(rule: Rule): boolean {
  if (rule.active === false) return false;
  return rule.deployment_state !== "rolled_back";
}

export function isBlockActive(entry: BlockEntry, now: number = Date.now()): boolean {
  if (entry.status && entry.status !== "active") return false;
  if (entry.expires_at) {
    const t = Date.parse(entry.expires_at);
    if (!Number.isNaN(t) && t <= now) return false;
  }
  return true;
}

function trig(rule: Rule): Triggered {
  return {
    id: String(rule.id || ""),
    name: String(rule.name || rule.type),
    type: String(rule.type),
    action: String(rule.action || "block"),
  };
}

export function evaluate(ctx: RequestContext, data: EvaluateData = {}): Decision {
  const now = data.now ?? Date.now();
  const rules = sortedRules((data.rules || []).filter(isLive));
  const trace: TraceStep[] = [];
  const observed: Decision["observed"] = [];
  const stateLabel = (r: Rule) =>
    r.deployment_state === "observe_only" ? " (observe-only)" : r.deployment_state === "staged" ? " (staged)" : "";
  const done = (verdict: Verdict, reason: string, extra: Partial<Decision> = {}): Decision => ({
    verdict,
    reason,
    triggered: null,
    autoBlock: null,
    adaptiveThrottled: false,
    observed,
    trace,
    ...extra,
  });

  // 1. Allow rules
  for (const rule of rules) {
    if (rule.action !== "allow") continue;
    if (!matchRule(rule, ctx, data.rateCount)) continue;
    if (rule.deployment_state === "observe_only") {
      observed.push({ id: String(rule.id || ""), name: String(rule.name || ""), action: "allow" });
      trace.push({
        check: `Allow rule: ${rule.name}${stateLabel(rule)}`,
        matched: true,
        reason: `${explainRule(rule)} Matched, but observe-only, so it did not change the verdict.`,
        action: "observed",
      });
      continue;
    }
    trace.push({
      check: `Allow rule: ${rule.name}${stateLabel(rule)}`,
      matched: true,
      reason: `${explainRule(rule)} Allow rules are checked first; the request is allowed and no later check can block it.`,
      action: "allowed",
    });
    return done("allowed", `Allowed by rule: ${rule.name}`, { triggered: trig(rule) });
  }
  trace.push({ check: "Allow rules", matched: false, reason: "No allow rule matched this request." });

  // 2. Blocklist
  for (const entry of data.blocklist || []) {
    if (entry.app_id && ctx.app_id && entry.app_id !== ctx.app_id) continue;
    if (!isBlockActive(entry, now)) continue;
    if (!ipMatches(ctx.source_ip, entry.ip_or_range)) continue;
    const reason = entry.reason || "IP on blocklist";
    trace.push({
      check: "Blocklist",
      matched: true,
      reason: `${ctx.source_ip} matches blocklist entry ${entry.ip_or_range}${entry.app_id ? " (this app)" : " (global)"}${
        entry.expires_at ? `, until ${entry.expires_at}` : ""
      }. Reason: ${reason}.`,
      action: "blocked",
    });
    return done("blocked", reason, {
      triggered: { id: String(entry.id || ""), name: "Blocklist", type: "ip_block", action: "block" },
    });
  }
  trace.push({ check: "Blocklist", matched: false, reason: `${ctx.source_ip} is not on the blocklist.` });

  // 3. Block / throttle rules by priority
  for (const rule of rules) {
    if (rule.action === "allow") continue;
    const matched = matchRule(rule, ctx, data.rateCount);
    if (!matched) {
      trace.push({
        check: `Rule: ${rule.name}${stateLabel(rule)}`,
        matched: false,
        reason: `${explainRule(rule)} Did not match.`,
      });
      continue;
    }
    if (rule.deployment_state === "observe_only") {
      observed.push({ id: String(rule.id || ""), name: String(rule.name || ""), action: String(rule.action || "block") });
      trace.push({
        check: `Rule: ${rule.name}${stateLabel(rule)}`,
        matched: true,
        reason: `${explainRule(rule)} Matched, but observe-only, so it only logged the match.`,
        action: "observed",
      });
      continue;
    }
    const verdict: Verdict = rule.action === "throttle" ? "throttled" : "blocked";
    trace.push({
      check: `Rule: ${rule.name}${stateLabel(rule)}`,
      matched: true,
      reason: `${explainRule(rule)} Matched; action is ${rule.action || "block"}.`,
      action: verdict,
    });
    return done(verdict, `${verdict === "throttled" ? "Throttled" : "Blocked"} by rule: ${rule.name}`, {
      triggered: trig(rule),
    });
  }

  // 4. Auto-detection
  if (data.autoDetection !== false) {
    const sig = detectSignature(ctx.path || "") || detectSignature(ctx.user_agent || "");
    if (sig) {
      const reason = `Automatic block: malicious signature (${sig})`;
      trace.push({ check: "Auto-detection: signature", matched: true, reason: `Found a known attack pattern: ${sig}.`, action: "blocked" });
      return done("blocked", reason, {
        triggered: { id: "auto", name: `Auto: ${sig}`, type: "pattern", action: "block" },
        autoBlock: { type: "signature", reason },
      });
    }
    trace.push({ check: "Auto-detection: signature", matched: false, reason: "No known attack patterns in the path or user agent." });

    if (isSuspiciousUA(ctx.user_agent || "")) {
      const reason = "Automatic block: known scanner user agent";
      trace.push({ check: "Auto-detection: scanner", matched: true, reason: `User agent "${ctx.user_agent}" is a known attack tool.`, action: "blocked" });
      return done("blocked", reason, {
        triggered: { id: "auto", name: "Auto: scanner UA", type: "pattern", action: "block" },
        autoBlock: { type: "scanner", reason },
      });
    }
    trace.push({ check: "Auto-detection: scanner", matched: false, reason: "User agent is not a known attack tool." });
  }

  // 5. Rate burst
  const burst = data.burst === undefined ? DEFAULT_BURST : data.burst;
  if (burst && data.rateCount) {
    const count = data.rateCount(burst.windowSeconds);
    if (count > burst.maxRequests) {
      const reason = `Automatic block: rate burst (${count} requests in ${burst.windowSeconds}s)`;
      trace.push({ check: "Rate burst", matched: true, reason: `${count} requests in ${burst.windowSeconds}s, over the ${burst.maxRequests} limit.`, action: "blocked" });
      return done("blocked", reason, {
        triggered: { id: "auto", name: "Auto: rate burst", type: "rate_limit", action: "block" },
        autoBlock: { type: "rate_burst", reason },
      });
    }
    trace.push({ check: "Rate burst", matched: false, reason: `${count} requests in ${burst.windowSeconds}s, within the ${burst.maxRequests} limit.` });
  }

  // 6. Adaptive throttle
  if (data.adaptive && data.rateCount) {
    const count = data.rateCount(data.adaptive.windowSeconds);
    if (count > data.adaptive.maxRequests) {
      trace.push({
        check: "Adaptive safe-throttle",
        matched: true,
        reason: `${count} requests in ${data.adaptive.windowSeconds}s, over the safe limit of ${data.adaptive.maxRequests}.`,
        action: "throttled",
      });
      return done("throttled", "Adaptive safe-throttle: rate limit exceeded", {
        triggered: { id: "adaptive", name: "Adaptive safe-throttle", type: "rate_limit", action: "throttle" },
        adaptiveThrottled: true,
      });
    }
  }

  trace.push({ check: "Final verdict", matched: true, reason: "Nothing blocked or throttled this request.", action: "allowed" });
  return done("allowed", "Allowed");
}

/** Back-compat wrapper for explainRequest/screenRequest: the trace from evaluate(). */
export function traceRequest(ctx: RequestContext, blocklist: BlockEntry[], rules: Rule[]): TraceStep[] {
  return evaluate(ctx, { blocklist, rules, burst: false }).trace;
}

/* ------------------------------------------------------------------ */
/* Server-side helpers (kept for the Base44 backend functions)         */
/* ------------------------------------------------------------------ */

export interface SignalResult {
  signal_type: string;
  evidence: string;
  severity: string;
  recommended_action: string;
  request_count: number;
  sample_paths: string[];
}

// deno-lint-ignore no-explicit-any
export function detectSignals(events: any[], profile?: any): SignalResult[] {
  const results: SignalResult[] = [];
  if (!events.length) return results;

  const enableCred = !profile || profile.credential_stuffing_detection !== false;
  const enableScraping = !profile || profile.scraping_detection !== false;
  const enableBot = !profile || profile.bot_detection !== false;

  if (enableCred) {
    const authPosts = events.filter((e) => e.method === "POST" && isAuthPath(e.path || ""));
    if (authPosts.length >= 5) {
      results.push({
        signal_type: "credential_stuffing",
        evidence: `${authPosts.length} POST requests to authentication endpoints from this IP. Pattern consistent with credential stuffing or brute-force login attempts.`,
        severity: authPosts.length >= 15 ? "critical" : "high",
        recommended_action: "Consider blocking this IP or adding a rate-limit rule for auth endpoints. Review whether any login attempts succeeded.",
        request_count: authPosts.length,
        sample_paths: authPosts.map((e) => e.path).slice(0, 5),
      });
    }
  }

  if (enableScraping) {
    const gets = events.filter((e) => !e.method || e.method === "GET");
    const distinctPaths = new Set(gets.map((e) => e.path));
    if (gets.length >= 30 && distinctPaths.size >= 20) {
      results.push({
        signal_type: "scraping",
        evidence: `${gets.length} GET requests across ${distinctPaths.size} distinct paths. High path diversity with sustained volume is typical of content scraping.`,
        severity: gets.length >= 80 ? "high" : "medium",
        recommended_action: "Consider adding a rate-limit rule or challenging requests from this IP. Check whether sensitive data was accessed.",
        request_count: gets.length,
        sample_paths: Array.from(distinctPaths).slice(0, 5) as string[],
      });
    }
  }

  if (enableBot) {
    const botEvents = events.filter((e) => isHeadlessUA(e.user_agent || ""));
    if (botEvents.length >= 3) {
      results.push({
        signal_type: "bot_behavior",
        evidence: `${botEvents.length} requests from headless browser or automation tool user agents. Automated traffic may be benign (monitoring) or hostile (scanning).`,
        severity: botEvents.length >= 10 ? "high" : "medium",
        recommended_action: "Verify whether this IP belongs to a known monitoring tool. If not, consider blocking or challenging.",
        request_count: botEvents.length,
        sample_paths: botEvents.map((e) => e.path).slice(0, 5),
      });
    }
  }

  if (events.length >= 50) {
    results.push({
      signal_type: "request_burst",
      evidence: `${events.length} requests from this IP in the analysis window. Sustained high volume may indicate a flood or DDoS precursor.`,
      severity: events.length >= 150 ? "high" : "medium",
      recommended_action: "If traffic is unwanted, add a rate-limit rule. The adaptive safe-throttle may already be engaging.",
      request_count: events.length,
      sample_paths: events.slice(0, 5).map((e) => e.path),
    });
  }

  return results;
}

/** Warn about conflicts between a proposed rule and existing rules. */
export function detectConflicts(proposedRule: Rule, existingRules: Rule[]): string[] {
  const warnings: string[] = [];
  for (const existing of existingRules) {
    if (existing.id === proposedRule.id) continue;
    if (existing.app_id !== proposedRule.app_id) continue;
    if (!existing.active) continue;
    if (proposedRule.action === "block" && existing.action === "allow" && rulesOverlap(proposedRule, existing)) {
      warnings.push(`Overlaps allow rule "${existing.name}" — allow rules are checked first, so matching traffic will still be allowed.`);
    }
    if (proposedRule.action === "block" && existing.action === "block" && proposedRule.type === existing.type && rulesOverlap(proposedRule, existing)) {
      warnings.push(`Overlaps with existing rule "${existing.name}" — may create redundant blocks.`);
    }
  }
  return warnings;
}

function specsOverlap(x: string, y: string): boolean {
  if (x === y) return true;
  if (ipMatches(x, y) || ipMatches(y, x)) return true;
  const base = (s: string) => s.split(/[/-]/)[0];
  return ipMatches(base(x), y) || ipMatches(base(y), x);
}

function rulesOverlap(a: Rule, b: Rule): boolean {
  const ca = a.criteria || {};
  const cb = b.criteria || {};
  if (a.type === "ip_block" || a.type === "ip_allow") {
    const aIps = [...(ca.ips || []), ...(ca.cidrs || [])];
    const bIps = [...(cb.ips || []), ...(cb.cidrs || [])];
    return aIps.some((x) => bIps.some((y) => specsOverlap(x, y)));
  }
  if (a.type === "geo") {
    const ac = (ca.countries || []).map((c) => String(c).toUpperCase());
    const bc = (cb.countries || []).map((c) => String(c).toUpperCase());
    return ac.some((c) => bc.includes(c));
  }
  if (a.type === "port") return String(ca.port) === String(cb.port);
  return false;
}
