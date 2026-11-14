// SwarmTech Shield client: keeps a local copy of the app's rules, judges each request locally
// with the shared engine, and ships traffic logs in the background.
//
// Nothing here makes a network call on the request path, except the very first sync
// after a cold start (bounded by `firstSyncTimeoutMs`).

import {
  evaluate,
  ipMatches,
  isBlockActive,
  scopeMatches,
  type BlockEntry,
  type Decision,
  type Rule,
  type Verdict,
} from "./engine.ts";
import { inspect, type InspectionConfig, type InspectionMode, type Finding } from "./inspect.ts";
import {
  Decoys,
  OutcomeTracker,
  ProbeVerifier,
  VirtualPatches,
  PROBE_HEADER,
  SERVICE_HEADER,
  LOG_SIGNATURE_HEADER,
  ServiceIdentities,
  signBatch,
  type ActivePatch,
  type DecoyOptions,
  type DecoyResponse,
  type OutcomeConfig,
  type OutcomeReport,
  type ProbeResult,
  type ServiceIdentity,
  type VirtualPatch,
} from "./defence.ts";
import { Resilience, type ResilienceOptions, type ResilienceState } from "./resilience.ts";

export const SDK_VERSION = "0.5.0";

export type FailMode = "open" | "closed";

export interface ShieldOptions {
  /** The app's connection key (Admin Console → Connections). Keep it in an environment variable. */
  connectionKey: string;
  /** Full URL of the syncRuleCache function. */
  syncUrl: string;
  /** Full URL of the submitTrafficLog function. Omit to disable traffic logging. */
  logUrl?: string;
  /** What to do before rules have ever loaded, or when they are older than `maxStaleMs`.
   *  Replaced by the app's own setting once the first sync succeeds. Default "open". */
  failMode?: FailMode;
  /** How often to check for rule changes. Default 30 s. */
  syncIntervalMs?: number;
  /** Ask for a full rule download at least this often, even if the version looks unchanged. Default 5 min. */
  fullSyncEveryMs?: number;
  /** Keep enforcing the last good rules for this long if SwarmTech Shield is unreachable. Default 15 min. */
  maxStaleMs?: number;
  /** Timeout for sync and log calls. Default 3 s. */
  requestTimeoutMs?: number;
  /** On a cold start, wait at most this long for the first rules before applying the fail mode. Default 1.5 s. */
  firstSyncTimeoutMs?: number;
  /** Send queued logs every this many ms (checked on each request, and by a timer where `timers` is on). Default 5 s. */
  logFlushIntervalMs?: number;
  /** Max events per log call (the server accepts up to 100). Default 100. */
  logBatchSize?: number;
  /** Max events held in memory while SwarmTech Shield is unreachable; oldest are dropped. Default 5,000. */
  maxQueue?: number;
  /** Log allowed requests: true (all), false (none) or a sample rate 0–1. Blocked and throttled are always logged. Default true. */
  logAllowed?: boolean | number;
  /** Include the query string in logged paths. Off by default because query strings often carry tokens. */
  logQueryString?: boolean;
  /** Remember an IP that auto-detection blocked for this many seconds on this server. Default 900. */
  localBlockSeconds?: number;
  /** Burst auto-block threshold per IP. Default 120 requests / 60 s. false disables it. */
  burst?: { maxRequests: number; windowSeconds: number } | false;
  /** Signature and scanner auto-detection. Default true. */
  autoDetection?: boolean;
  /** Deep request inspection (SQLi, XSS, RCE, traversal, SSRF and more) over the path, query,
   *  headers, cookies and body. Pass true for defaults, false to turn it off, or a config object.
   *  Default: on in observe mode, so it reports without blocking until you raise it to "block". */
  inspection?: boolean | InspectionConfig;
  /** Decoy routes, a hidden form field and canary credentials. Default on. false disables. */
  decoys?: boolean | DecoyOptions;
  /** Login, payment and sign-up protection fed by reportOutcome(). Default on (inert until you report outcomes). */
  outcomes?: boolean | OutcomeConfig;
  /** Installed package versions ({ name: version }), so virtual patches only switch on for affected versions.
   *  On Node, fill it with detectDependencies() from "@swarmtechshield/middleware/node". */
  dependencies?: Record<string, string>;
  /** Send the dependency list (names and versions only) with full rule syncs, so the server can send matching
   *  virtual patches. Default true. */
  reportDependencies?: boolean;
  /** Answer signed verification probes from the SwarmTech Shield checker. Default true. */
  verification?: boolean;
  /** Under-attack mode and load shedding for application-layer floods. Default on. false disables. */
  resilience?: ResilienceOptions | false;
  /** Run background timers for sync and log flushing (long-running servers only). Default false. */
  timers?: boolean;
  /** Called on sync/log failures and configuration problems. Never throws into your app. */
  onError?: (error: Error, context: string) => void;
  /** Override fetch (tests, custom agents). */
  fetch?: typeof fetch;
  /** Override the clock (tests). */
  now?: () => number;
}

export interface RequestInfo {
  ip: string;
  method?: string;
  /** Path including the query string, e.g. "/search?q=x". */
  path?: string;
  userAgent?: string;
  bodySize?: number;
  country?: string;
  port?: number;
  /** Request headers, for deep inspection. Optional; inspection still runs on the URL without them. */
  headers?: Record<string, string | string[] | undefined>;
  /** Parsed body (object/array) or raw text, for deep inspection. Read it with a size cap in your adapter. */
  body?: unknown;
  /** The body's content type, used to parse a string body. */
  contentType?: string;
  /** The signed-in account (id, username or email), for per-account login and payment limits. */
  user?: string;
}

export type CheckSource = "rules" | "fail_open" | "fail_closed" | "disabled";

export interface CheckResult {
  verdict: Verdict;
  allowed: boolean;
  blocked: boolean;
  throttled: boolean;
  reason: string;
  /** Where the verdict came from: the rules, a fail mode, or "disabled" (key rejected or app paused). */
  source: CheckSource;
  decision: Decision | null;
  durationMs: number;
  /** Background work (rule refresh, log flush). Pass to waitUntil() on serverless platforms. */
  background?: Promise<void>;
  /** Set when a decoy was touched: the response to send (a 404, or bait carrying canary credentials). */
  decoy?: DecoyResponse;
  /** Set for a verified probe from the SwarmTech Shield checker. */
  verification?: ProbeResult & { headers: Record<string, string> };
  /** Set when a dependency-matched virtual patch blocked the request. */
  patch?: ActivePatch;
  /** Set when the request carried a valid service-identity token (see SERVICE_HEADER). */
  identity?: { id: string; name: string; kind: "service" | "synthetic" };
  /** Set when the request was shed because the server is overloaded (send a 503). */
  shed?: boolean;
  /** Seconds to put in Retry-After for a shed request. */
  retryAfterSeconds?: number;
}

interface LogEvent {
  source_ip: string;
  method: string;
  path: string;
  port: number | null;
  country: string;
  user_agent: string;
  body_size: number;
  verdict: Verdict;
  screening_ms: number;
  rule_id: string;
  rule_name: string;
  rule_type: string;
  reason: string;
  is_incident: boolean;
  /** "service" or "synthetic" for requests from a service identity; real traffic leaves it out. */
  traffic_class?: "service" | "synthetic";
  trace?: string;
  details: Record<string, unknown>;
}

interface SyncResponse {
  up_to_date?: boolean;
  version?: string | number;
  fail_mode?: string;
  rules?: Rule[];
  blocklist?: BlockEntry[];
  /** Under-attack mode switched on from the console. */
  under_attack?: boolean;
  /** Virtual patches; the client keeps those that affect its installed dependencies. */
  virtual_patches?: VirtualPatch[];
  /** Service identities (token hashes only) for this app. */
  service_identities?: ServiceIdentity[];
  error?: string;
}

type Hit = [time: number, method: string, path: string];

const MAX_HITS_PER_IP = 2000;
const MAX_TRACKED_IPS = 50000;
const INCIDENT_DEDUPE_MS = 30 * 60 * 1000;

function nowPerf(): number {
  return typeof performance !== "undefined" && performance.now ? performance.now() : Date.now();
}

/** Retry-After (seconds or an HTTP date) as milliseconds, kept between 5 s and 5 min. */
export function retryAfterMs(value: string | null | undefined, fallbackMs: number, nowMs = Date.now()): number {
  let ms = fallbackMs;
  if (value) {
    const seconds = Number(value);
    if (Number.isFinite(seconds)) ms = seconds * 1000;
    else {
      const date = Date.parse(value);
      if (Number.isFinite(date)) ms = date - nowMs;
    }
  }
  return Math.min(300_000, Math.max(5_000, ms));
}

function trunc(s: unknown, n: number): string {
  const str = s === undefined || s === null ? "" : String(s);
  return str.length > n ? str.slice(0, n) : str;
}

function headerOf(headers: RequestInfo["headers"], name: string): string | undefined {
  if (!headers) return undefined;
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() === name) return Array.isArray(v) ? v[0] : v;
  return undefined;
}

/** Turn the `inspection` option into a config, or null when off.
 *  Default (undefined): on in observe mode, so new installs report without blocking. */
function resolveInspection(opt: boolean | InspectionConfig | undefined): InspectionConfig | null {
  if (opt === false) return null;
  if (opt === true || opt === undefined) return { mode: opt === true ? "block" : "observe", autoBlockScore: 10 };
  if (opt.mode === "off") return null;
  return { autoBlockScore: 10, ...opt };
}

export class ShieldClient {
  readonly opts: Required<
    Omit<ShieldOptions, "logUrl" | "onError" | "fetch" | "now" | "burst" | "inspection" | "decoys" | "outcomes" | "dependencies" | "reportDependencies" | "verification" | "resilience">
  > & Pick<ShieldOptions, "logUrl" | "onError" | "burst">;

  /** Resolved inspection config, or null when inspection is off. */
  readonly inspectionConfig: InspectionConfig | null;
  private decoys: Decoys | null;
  private outcomes: OutcomeTracker | null;
  private patches = new VirtualPatches();
  private services = new ServiceIdentities();
  private probes: ProbeVerifier | null;
  private reportDeps: boolean;
  private resilience: Resilience | null;
  private shedLog = { count: 0, at: 0 };

  private fetchImpl: typeof fetch;
  private clock: () => number;

  private rules: Rule[] = [];
  private blocklist: BlockEntry[] = [];
  private version: string | number | null = null;
  private serverFailMode: FailMode | null = null;
  private lastSyncOk = 0;
  private lastSyncAttempt = 0;
  private lastFullSync = 0;
  private syncing: Promise<void> | null = null;
  private disabled = false;
  private maxWindowSec = 60;
  private checks = 0;
  private warnedNoIp = false;
  private firstSyncWaited = false;

  private hits = new Map<string, Hit[]>();
  private localBlocks = new Map<string, { until: number; reason: string }>();
  private incidentSeen = new Map<string, number>();

  /** Blocked/throttled events: sent first and dropped last. */
  private priorityQueue: LogEvent[] = [];
  /** Allowed events. */
  private allowedQueue: LogEvent[] = [];
  private droppedLogs = 0;
  private flushing: Promise<void> | null = null;
  private lastFlush = 0;
  private logBackoffUntil = 0;
  private syncBackoffUntil = 0;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(options: ShieldOptions) {
    if (!options || !options.connectionKey) throw new Error("SwarmTech Shield: connectionKey is required");
    if (!options.syncUrl) throw new Error("SwarmTech Shield: syncUrl is required");
    this.opts = {
      connectionKey: options.connectionKey,
      syncUrl: options.syncUrl,
      logUrl: options.logUrl,
      failMode: options.failMode ?? "open",
      syncIntervalMs: options.syncIntervalMs ?? 30_000,
      fullSyncEveryMs: options.fullSyncEveryMs ?? 300_000,
      maxStaleMs: options.maxStaleMs ?? 900_000,
      requestTimeoutMs: options.requestTimeoutMs ?? 3_000,
      firstSyncTimeoutMs: options.firstSyncTimeoutMs ?? 1_500,
      logFlushIntervalMs: options.logFlushIntervalMs ?? 5_000,
      logBatchSize: Math.min(100, Math.max(1, options.logBatchSize ?? 100)),
      maxQueue: options.maxQueue ?? 5_000,
      logAllowed: options.logAllowed ?? true,
      logQueryString: options.logQueryString ?? false,
      localBlockSeconds: options.localBlockSeconds ?? 900,
      burst: options.burst,
      autoDetection: options.autoDetection ?? true,
      timers: options.timers ?? false,
      onError: options.onError,
    };
    this.inspectionConfig = resolveInspection(options.inspection);
    this.decoys = options.decoys === false ? null : new Decoys(options.connectionKey, options.decoys === true ? {} : options.decoys || {});
    this.outcomes = options.outcomes === false ? null : new OutcomeTracker(options.outcomes === true ? undefined : options.outcomes, () => this.clock());
    this.patches.setDependencies(options.dependencies);
    this.reportDeps = options.reportDependencies !== false;
    this.probes = options.verification === false ? null : new ProbeVerifier(options.connectionKey, () => this.clock());
    this.resilience = options.resilience === false ? null : new Resilience(options.resilience || {}, () => this.clock());
    const f = options.fetch ?? (typeof fetch !== "undefined" ? fetch : undefined);
    if (!f) throw new Error("SwarmTech Shield: no fetch implementation available; pass options.fetch");
    this.fetchImpl = f.bind(globalThis) as typeof fetch;
    this.clock = options.now ?? (() => Date.now());
    this.lastFlush = this.clock();
    if (this.opts.timers) {
      this.startTimers();
      this.resilience?.startMonitor();
    }
  }

  /* ---------------- public API ---------------- */

  /** Judge one request. Never throws. */
  async check(info: RequestInfo): Promise<CheckResult> {
    const t0 = nowPerf();
    try {
      await this.ensureFirstSync();
      if (this.decoys) await this.decoys.whenReady();
      const background: Promise<void>[] = [];
      const refresh = this.maybeRefresh();
      if (refresh) background.push(refresh);

      const now = this.clock();
      const ip = info.ip || "";
      const method = (info.method || "GET").toUpperCase();
      const path = info.path || "/";

      // A valid service-identity token: "service" skips screening, "synthetic" is screened
      // but never counted, blocked by IP or raised as an incident.
      const identity = this.disabled ? null : await this.services.identify(headerOf(info.headers, SERVICE_HEADER));
      const synthetic = identity?.kind === "synthetic";

      let result: Omit<CheckResult, "durationMs" | "background">;
      if (this.disabled) {
        result = this.simple("allowed", "SwarmTech Shield disabled: connection key rejected or app paused", "disabled");
      } else if (!this.lastSyncOk || now - this.lastSyncOk > this.opts.maxStaleMs) {
        const mode = this.serverFailMode ?? this.opts.failMode;
        result = mode === "closed"
          ? this.simple("blocked", "Fail closed: rules unavailable", "fail_closed")
          : this.simple("allowed", "Fail open: rules unavailable", "fail_open");
      } else if (identity && identity.kind === "service") {
        result = this.simple("allowed", `Service identity: ${identity.name}`, "rules");
      } else {
        if (!ip && !this.warnedNoIp) {
          this.warnedNoIp = true;
          this.report(new Error("Could not determine the client IP; IP rules, blocklist and rate limits are skipped for such requests. Check your proxy/IP settings."), "client_ip");
        }
        if (++this.checks % 1000 === 0) this.evictHits(now);
        if (ip && !synthetic) this.recordHit(ip, method, path, now);
        const local = ip ? this.localBlocks.get(ip) : undefined;
        const blocklist = local && local.until > now
          ? [...this.blocklist, { ip_or_range: ip, reason: local.reason, expires_at: new Date(local.until).toISOString(), source: "local" }]
          : this.blocklist;
        if (!synthetic) this.resilience?.record(now);
        const underAttack = this.resilience?.underAttack() ?? false;

        // Load shedding: when the server is overloaded, low-priority anonymous requests get a
        // cheap 503 before any inspection work. Allow rules (e.g. your health checks) still pass.
        if (this.resilience?.shouldShed(path, info.user)) {
          const pre = evaluate(
            { source_ip: ip, method, path, country: info.country || "", user_agent: info.userAgent || "" },
            { rules: this.rules, blocklist, now, burst: false, autoDetection: false },
          );
          if (!(pre.verdict === "allowed" && pre.triggered?.action === "allow")) {
            this.resilience.shedCount++;
            this.noteShed(now);
            const flush = this.maybeFlush();
            if (flush) background.push(flush);
            return {
              ...this.simple("throttled", "Load shedding: server overloaded", "rules"),
              shed: true,
              retryAfterSeconds: this.resilience.retryAfterSeconds,
              durationMs: Math.round((nowPerf() - t0) * 100) / 100,
              background: background.length ? Promise.all(background).then(() => undefined) : undefined,
            };
          }
        }

        // Under attack, inspection blocks instead of only observing.
        const inspectionConfig =
          this.inspectionConfig && underAttack && this.resilience!.enforceInspection && this.inspectionConfig.mode === "observe"
            ? { ...this.inspectionConfig, mode: "block" as const }
            : this.inspectionConfig;
        let inspection = null;
        if (inspectionConfig) {
          const r = inspect(
            { method, path, headers: info.headers, body: info.body, contentType: info.contentType },
            inspectionConfig,
          );
          const autoBlockScore = inspectionConfig.autoBlockScore ?? 10;
          inspection = {
            matched: r.matched,
            mode: r.mode,
            score: r.score,
            threshold: r.threshold,
            autoBlock: autoBlockScore > 0 && r.score >= autoBlockScore,
            findings: r.findings.map((f: Finding) => ({ rule: f.rule, category: f.category, description: f.description, score: f.score, location: f.location, name: f.name })),
          };
        }
        const decision = evaluate(
          {
            source_ip: ip,
            method,
            path,
            port: info.port ?? null,
            country: info.country || "",
            user_agent: info.userAgent || "",
            body_size: info.bodySize ?? 0,
          },
          {
            rules: this.rules,
            blocklist,
            now,
            rateCount: ip ? (win, scope) => this.countHits(ip, win, scope, now) : undefined,
            burst: underAttack ? this.resilience!.burst : this.opts.burst,
            autoDetection: this.opts.autoDetection,
            inspection,
          },
        );
        if (decision.autoBlock && ip && !synthetic) {
          this.localBlocks.set(ip, { until: now + this.opts.localBlockSeconds * 1000, reason: decision.autoBlock.reason });
        }
        result = {
          verdict: decision.verdict,
          allowed: decision.verdict === "allowed",
          blocked: decision.verdict === "blocked",
          throttled: decision.verdict === "throttled",
          reason: decision.reason,
          source: "rules",
          decision,
        };

        // Active defences. An allow rule still wins; a request already blocked stays blocked.
        const allowRuleWon = decision.verdict === "allowed" && decision.triggered?.action === "allow";
        // Automatic detection (signatures, inspection) may already have blocked a trap path. A decoy
        // still answers it, because serving bait is worth more than a plain 403. Explicit rules and
        // the blocklist are left alone.
        const autoBlocked = decision.verdict === "blocked" && decision.triggered?.id === "auto";
        const input = { method, path, headers: info.headers, body: info.body, contentType: info.contentType };
        if (autoBlocked && this.decoys) {
          const decoy = this.decoys.check(input, info.headers || {});
          if (decoy && decoy.kind === "trap") {
            result = this.override(decision, "blocked", decoy.reason, { id: "decoy", name: `Decoy: ${decoy.kind}`, type: "pattern", action: "block" }, "Decoy");
            if (decoy.response) result.decoy = decoy.response;
            if (ip && !synthetic && this.decoys.opts.blockIp) this.localBlocks.set(ip, { until: now + this.opts.localBlockSeconds * 1000, reason: decoy.reason });
          }
        }
        if (decision.verdict === "allowed" && !allowRuleWon) {
          const decoy = this.decoys?.check(input, info.headers || {}) ?? null;
          const patch = decoy ? null : this.patches.match(input);
          const outcome = decoy || patch ? null : this.outcomes?.check(path, ip, info.user) ?? null;
          if (decoy) {
            if (ip && !synthetic && this.decoys!.opts.blockIp && decoy.kind !== "form_field") {
              this.localBlocks.set(ip, { until: now + this.opts.localBlockSeconds * 1000, reason: decoy.reason });
            }
            result = this.override(decision, "blocked", decoy.reason, { id: "decoy", name: `Decoy: ${decoy.kind}`, type: "pattern", action: "block" }, "Decoy");
            if (decoy.response) result.decoy = decoy.response;
          } else if (patch) {
            const reason = `Virtual patch ${patch.advisory || patch.id}: ${patch.package}@${patch.installed} is affected${patch.fixed ? `; upgrade to ${patch.fixed}` : ""}`;
            result = this.override(decision, "blocked", reason, { id: patch.id, name: `Virtual patch: ${patch.package}`, type: "pattern", action: "block" }, "Virtual patch");
            result.patch = patch;
          } else if (outcome) {
            const verdict = outcome.action === "block" ? "blocked" : "throttled";
            result = this.override(decision, verdict, `${outcome.type === "payment" ? "Payment" : outcome.type === "login" ? "Login" : "Sign-up"} protection: ${outcome.reason}`, { id: `outcome:${outcome.type}`, name: `${outcome.type} protection`, type: "rate_limit", action: outcome.action }, "Outcome protection");
          }
        }
      }

      // Signed probes from the checker: prove this route is protected, without logging an attack.
      let verification: CheckResult["verification"];
      if (this.probes && result.source !== "disabled") {
        const probe = await this.probes.verify(headerOf(info.headers, PROBE_HEADER), method, path);
        if (probe) {
          const inspectionMode = this.inspectionConfig?.mode ?? "off";
          verification = {
            ...probe,
            headers: { "x-shield-status": `active; sdk=${SDK_VERSION}; rules=${this.version ?? "none"}; inspection=${inspectionMode}; source=${result.source}` },
          };
          if (probe.mode === "test-block") {
            verification.headers["x-shield-test"] = "blocked";
            const durationMs = Math.round((nowPerf() - t0) * 100) / 100;
            return { ...this.simple("blocked", "Verification test (signed probe)", result.source), durationMs, verification };
          }
        }
      }

      if (identity) result.identity = { id: identity.id, name: identity.name, kind: identity.kind };
      const durationMs = Math.round((nowPerf() - t0) * 100) / 100;
      if (result.source !== "disabled") this.enqueue(info, result, durationMs, now);
      const flush = this.maybeFlush();
      if (flush) background.push(flush);

      return {
        ...result,
        ...(verification ? { verification } : {}),
        durationMs,
        background: background.length ? Promise.all(background).then(() => undefined) : undefined,
      };
    } catch (err) {
      this.report(err as Error, "check");
      const mode = this.serverFailMode ?? this.opts.failMode;
      const r = mode === "closed"
        ? this.simple("blocked", "Fail closed: internal error", "fail_closed")
        : this.simple("allowed", "Fail open: internal error", "fail_open");
      return { ...r, durationMs: Math.round((nowPerf() - t0) * 100) / 100 };
    }
  }

  /** Switch under-attack mode on or off from your code (the console can also switch it). */
  setUnderAttack(on: boolean): void {
    this.resilience?.setLocalFlag(on);
  }

  /**
   * True when this request will be rejected whatever its body says (blocked IP, or shed under
   * load). Adapters use it to skip reading the body, so rejecting a flood costs almost nothing.
   */
  rejectsEarly(ip: string, path: string, user?: string): boolean {
    const now = this.clock();
    if (!ip) return !!this.resilience?.shouldShed(path, user);
    const local = this.localBlocks.get(ip);
    if (local && local.until > now) return true;
    for (const e of this.blocklist) {
      if (e.app_id) continue;
      if (isBlockActive(e, now) && ipMatches(ip, e.ip_or_range)) return true;
    }
    return !!this.resilience?.shouldShed(path, user);
  }

  /** One summary log event per 30 s while shedding, instead of one per shed request. */
  private noteShed(now: number) {
    if (!this.opts.logUrl || !this.resilience) return;
    if (now - this.shedLog.at < 30_000) return;
    const count = this.resilience.shedCount - this.shedLog.count;
    this.shedLog = { count: this.resilience.shedCount, at: now };
    if (count <= 0) return;
    const st = this.resilience.state();
    this.priorityQueue.push({
      source_ip: "",
      method: "-",
      path: "(load shedding)",
      port: null,
      country: "",
      user_agent: "",
      body_size: 0,
      verdict: "throttled",
      screening_ms: 0,
      rule_id: "load-shedding",
      rule_name: "Load shedding",
      rule_type: "rate_limit",
      reason: `Shed ${count} low-priority request(s): server overloaded (load ${st.loadMs} ms)`,
      is_incident: true,
      details: { source: "middleware", sdk_version: SDK_VERSION, shed_count: count, under_attack: st.underAttack },
    });
    this.trimQueues();
  }

  /** Tell the middleware how a login, payment or sign-up attempt went. Never throws. */
  reportOutcome(report: OutcomeReport): void {
    try {
      this.outcomes?.report(report);
    } catch (err) {
      this.report(err as Error, "outcome");
    }
  }

  /** Replace the installed-dependency list (e.g. after detectDependencies() resolves). */
  setDependencies(deps: Record<string, string>): void {
    this.patches.setDependencies(deps);
  }

  /** The canary credential values planted in bait files (to register with alerting). */
  canaryValues(): string[] {
    return this.decoys?.canaryValues() ?? [];
  }

  private override(
    decision: Decision,
    verdict: Verdict,
    reason: string,
    triggered: NonNullable<Decision["triggered"]>,
    check: string,
  ): Omit<CheckResult, "durationMs" | "background"> {
    const trace = decision.trace.filter((t) => t.check !== "Final verdict");
    trace.push({ check, matched: true, reason, action: verdict });
    const d: Decision = { ...decision, verdict, reason, triggered, trace };
    return {
      verdict,
      allowed: false,
      blocked: verdict === "blocked",
      throttled: verdict === "throttled",
      reason,
      source: "rules",
      decision: d,
    };
  }

  /** Download rules now. Resolves when done; never throws. */
  sync(force = false): Promise<void> {
    if (this.syncing) return this.syncing;
    this.syncing = this.doSync(force).finally(() => {
      this.syncing = null;
    });
    return this.syncing;
  }

  /** Send queued logs now. Never throws. */
  flush(): Promise<void> {
    if (this.flushing) return this.flushing;
    if (!this.queuedCount() || !this.opts.logUrl) return Promise.resolve();
    this.flushing = this.doFlush().finally(() => {
      this.flushing = null;
    });
    return this.flushing;
  }

  /** Stop timers and send remaining logs (call on shutdown). */
  async close(): Promise<void> {
    this.resilience?.stop();
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.flushing) await this.flushing;
    while (this.queuedCount() && this.opts.logUrl && this.clock() >= this.logBackoffUntil) {
      const before = this.queuedCount();
      await this.flush();
      if (this.queuedCount() >= before) break;
    }
  }

  /** Snapshot of the client's state, for health endpoints and debugging. */
  status() {
    return {
      sdkVersion: SDK_VERSION,
      ready: this.lastSyncOk > 0,
      disabled: this.disabled,
      ruleVersion: this.version,
      rules: this.rules.length,
      blocklist: this.blocklist.length,
      lastSyncOk: this.lastSyncOk ? new Date(this.lastSyncOk).toISOString() : null,
      failMode: this.serverFailMode ?? this.opts.failMode,
      queuedLogs: this.queuedCount(),
      droppedLogs: this.droppedLogs,
      inspection: this.inspectionConfig?.mode ?? "off",
      decoys: !!this.decoys,
      virtualPatches: this.patches.active(),
      resilience: this.resilience?.state() ?? null,
    };
  }

  /* ---------------- sync ---------------- */

  private async ensureFirstSync(): Promise<void> {
    if (this.lastSyncOk || this.disabled) return;
    // Wait only for the initial attempt (requests arriving during it share the wait).
    // After that, requests never wait: the fail mode applies until a background retry succeeds.
    if (this.firstSyncWaited) return;
    const attempt = this.sync();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, this.opts.firstSyncTimeoutMs);
    });
    await Promise.race([attempt, timeout]);
    if (timer) clearTimeout(timer);
    this.firstSyncWaited = true;
  }

  private maybeRefresh(): Promise<void> | null {
    const now = this.clock();
    // Retry faster (every 5 s) while we have no rules at all.
    const interval = this.lastSyncOk ? this.opts.syncIntervalMs : Math.min(5_000, this.opts.syncIntervalMs);
    if (this.syncing || now - this.lastSyncAttempt < interval || now < this.syncBackoffUntil) return null;
    return this.sync();
  }

  private async doSync(force: boolean): Promise<void> {
    const now = this.clock();
    this.lastSyncAttempt = now;
    const full = force || !this.lastSyncOk || now - this.lastFullSync >= this.opts.fullSyncEveryMs;
    try {
      const deps = this.patches.dependencies();
      const res = await this.post(this.opts.syncUrl, {
        connection_key: this.opts.connectionKey,
        client_version: full ? null : this.version,
        sdk_version: SDK_VERSION,
        ...(full && this.reportDeps && Object.keys(deps).length ? { dependencies: deps } : {}),
      });
      if (res.status === 401 || res.status === 403) {
        this.disabled = true;
        this.report(new Error(`Sync rejected (${res.status}): connection key invalid, rotated, or app paused. Traffic is allowed through until this is fixed.`), "sync");
        return;
      }
      if (res.status === 429) {
        // The server is rate-limiting this app's syncs. Keep enforcing the rules we have
        // and wait as long as it asks (bounded), instead of retrying every few seconds.
        const waitMs = retryAfterMs(res.headers.get("retry-after"), 60_000);
        this.syncBackoffUntil = this.clock() + waitMs;
        this.report(new Error(`Sync rate-limited (429); next attempt in ${Math.round(waitMs / 1000)} s. Last good rules stay in force.`), "sync");
        return;
      }
      if (!res.ok) throw new Error(`Sync failed with HTTP ${res.status}`);
      const body = (await res.json()) as SyncResponse;
      this.disabled = false;
      if (body.fail_mode === "fail_closed") this.serverFailMode = "closed";
      else if (body.fail_mode === "fail_open") this.serverFailMode = "open";
      if (typeof body.under_attack === "boolean") this.resilience?.setConsoleFlag(body.under_attack);
      if (!body.up_to_date) {
        if (!Array.isArray(body.rules) || !Array.isArray(body.blocklist)) throw new Error("Sync response missing rules or blocklist");
        this.rules = body.rules;
        this.blocklist = body.blocklist;
        this.services.load(Array.isArray(body.service_identities) ? body.service_identities : []);
        if (Array.isArray(body.virtual_patches)) {
          const errors = this.patches.load(body.virtual_patches);
          if (errors.length) this.report(new Error(`Some virtual patches were skipped: ${errors.slice(0, 5).join("; ")}`), "sync");
        }
        this.lastFullSync = this.clock();
        this.recomputeWindow();
      }
      if (body.version !== undefined) this.version = body.version;
      this.lastSyncOk = this.clock();
    } catch (err) {
      this.report(err as Error, "sync");
    }
  }

  private recomputeWindow() {
    let max = 60;
    const burst = this.opts.burst;
    if (burst) max = Math.max(max, burst.windowSeconds);
    for (const r of this.rules) {
      if (r.type === "rate_limit") {
        const w = Number(r.criteria?.window_seconds);
        if (Number.isFinite(w) && w > 0) max = Math.max(max, w);
      }
    }
    this.maxWindowSec = Math.min(max, 3600);
  }

  /* ---------------- request counting ---------------- */

  private recordHit(ip: string, method: string, path: string, now: number) {
    let list = this.hits.get(ip);
    if (!list) {
      if (this.hits.size >= MAX_TRACKED_IPS) this.evictHits(now);
      list = [];
      this.hits.set(ip, list);
    }
    list.push([now, method, path]);
    const cutoff = now - this.maxWindowSec * 1000;
    let drop = 0;
    while (drop < list.length && list[drop][0] < cutoff) drop++;
    if (drop) list.splice(0, drop);
    if (list.length > MAX_HITS_PER_IP) list.splice(0, list.length - MAX_HITS_PER_IP);
  }

  private evictHits(now: number) {
    const cutoff = now - this.maxWindowSec * 1000;
    for (const [ip, list] of this.hits) {
      if (!list.length || list[list.length - 1][0] < cutoff) this.hits.delete(ip);
    }
    if (this.hits.size >= MAX_TRACKED_IPS) {
      let n = Math.ceil(MAX_TRACKED_IPS / 10);
      for (const ip of this.hits.keys()) {
        this.hits.delete(ip);
        if (--n <= 0) break;
      }
    }
    for (const [ip, b] of this.localBlocks) if (b.until <= now) this.localBlocks.delete(ip);
    for (const [k, t] of this.incidentSeen) if (now - t > INCIDENT_DEDUPE_MS) this.incidentSeen.delete(k);
  }

  private countHits(ip: string, windowSeconds: number, scope: { method?: string; path?: string } | undefined, now: number): number {
    const list = this.hits.get(ip);
    if (!list) return 0;
    const cutoff = now - windowSeconds * 1000;
    let n = 0;
    for (let i = list.length - 1; i >= 0; i--) {
      const [t, m, p] = list[i];
      if (t < cutoff) break;
      if (!scope || scopeMatches(scope, m, p)) n++;
    }
    return n;
  }

  /* ---------------- logging ---------------- */

  private enqueue(info: RequestInfo, result: Omit<CheckResult, "durationMs" | "background">, durationMs: number, now: number) {
    if (!this.opts.logUrl) return;
    if (result.verdict === "allowed") {
      const la = this.opts.logAllowed;
      if (la === false) return;
      if (typeof la === "number" && Math.random() >= la) return;
    }
    const d = result.decision;
    const rawPath = info.path || "/";
    const path = this.opts.logQueryString ? rawPath : rawPath.split("?")[0];
    const fromBlocklist = d?.triggered?.name === "Blocklist";
    // Service and synthetic traffic never raises an incident.
    let incident = result.verdict === "blocked" && result.source === "rules" && !fromBlocklist && !result.identity;
    if (incident) {
      // At most one incident per IP + rule every 30 minutes from this server.
      const key = `${info.ip}|${d?.triggered?.name || ""}`;
      const seen = this.incidentSeen.get(key);
      if (seen && now - seen < INCIDENT_DEDUPE_MS) incident = false;
      else this.incidentSeen.set(key, now);
    }
    const event: LogEvent = {
      source_ip: info.ip || "",
      method: (info.method || "GET").toUpperCase(),
      path: trunc(path, 2000),
      port: info.port ?? null,
      country: trunc(info.country, 8),
      user_agent: trunc(info.userAgent, 2000),
      body_size: info.bodySize ?? 0,
      verdict: result.verdict,
      screening_ms: durationMs,
      rule_id: trunc(d?.triggered?.id, 100),
      rule_name: trunc(d?.triggered?.name, 200),
      rule_type: trunc(d?.triggered?.type, 50),
      reason: trunc(result.reason, 500),
      is_incident: incident,
      ...(result.identity ? { traffic_class: result.identity.kind } : {}),
      details: {
        source: "middleware",
        sdk_version: SDK_VERSION,
        verdict_source: result.source,
        ...(result.identity ? { service_identity: result.identity.name, service_identity_id: result.identity.id } : {}),
        auto_block_type: d?.autoBlock?.type ?? null,
        observe_matches: d?.observed.map((o) => o.name) ?? [],
        inspection: d?.inspectionFindings?.length
          ? { score: d.inspectionFindings.reduce((s, f) => s + f.score, 0), findings: d.inspectionFindings.map((f) => ({ rule: f.rule, category: f.category, location: f.location, name: f.name })) }
          : undefined,
        defence: d?.triggered && /^(decoy|outcome:|vp-)/.test(d.triggered.id) ? d.triggered.name : undefined,
        under_attack: this.resilience?.underAttack() || undefined,
        virtual_patch: result.patch ? { id: result.patch.id, advisory: result.patch.advisory, package: result.patch.package, installed: result.patch.installed } : undefined,
      },
    };
    if (d && result.verdict !== "allowed") event.trace = JSON.stringify(d.trace);
    (result.verdict === "allowed" ? this.allowedQueue : this.priorityQueue).push(event);
    this.trimQueues();
  }

  private queuedCount(): number {
    return this.priorityQueue.length + this.allowedQueue.length;
  }

  /** Keep total queued events within maxQueue, dropping allowed events before blocked ones. */
  private trimQueues() {
    let excess = this.queuedCount() - this.opts.maxQueue;
    if (excess <= 0) return;
    const fromAllowed = Math.min(excess, this.allowedQueue.length);
    if (fromAllowed) this.allowedQueue.splice(0, fromAllowed);
    excess -= fromAllowed;
    if (excess > 0) this.priorityQueue.splice(0, excess);
    this.droppedLogs += fromAllowed + Math.max(0, excess);
  }

  private requeue(batch: LogEvent[]) {
    this.priorityQueue.unshift(...batch.filter((e) => e.verdict !== "allowed"));
    this.allowedQueue.unshift(...batch.filter((e) => e.verdict === "allowed"));
    this.trimQueues();
  }

  private maybeFlush(): Promise<void> | null {
    if (!this.opts.logUrl || !this.queuedCount() || this.flushing) return null;
    const now = this.clock();
    if (now < this.logBackoffUntil) return null;
    const due = this.queuedCount() >= this.opts.logBatchSize || now - this.lastFlush >= this.opts.logFlushIntervalMs;
    return due ? this.flush() : null;
  }

  private async doFlush(): Promise<void> {
    this.lastFlush = this.clock();
    const batch = this.priorityQueue.splice(0, this.opts.logBatchSize);
    if (batch.length < this.opts.logBatchSize) batch.push(...this.allowedQueue.splice(0, this.opts.logBatchSize - batch.length));
    try {
      const res = await this.post(this.opts.logUrl!, { connection_key: this.opts.connectionKey, logs: batch }, true);
      if (res.status === 401 || res.status === 403) {
        this.report(new Error(`Log upload rejected (${res.status}); dropping ${batch.length} events`), "log");
        this.logBackoffUntil = this.clock() + 60_000;
        return;
      }
      if (res.status === 429) {
        this.requeue(batch);
        this.logBackoffUntil = this.clock() + retryAfterMs(res.headers.get("retry-after"), 30_000);
        return;
      }
      if (!res.ok) throw new Error(`Log upload failed with HTTP ${res.status}`);
    } catch (err) {
      this.requeue(batch);
      this.logBackoffUntil = this.clock() + 10_000;
      this.report(err as Error, "log");
    }
  }

  /* ---------------- helpers ---------------- */

  private async post(url: string, body: unknown, sign = false): Promise<Response> {
    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), this.opts.requestTimeoutMs) : undefined;
    try {
      const text = JSON.stringify(body);
      const headers: Record<string, string> = { "content-type": "application/json", "x-swarmtechshield-sdk": SDK_VERSION };
      // Log batches are signed so the server can refuse replays (see signBatch).
      if (sign) {
        const signature = await signBatch(this.opts.connectionKey, text, Date.now());
        if (signature) headers[LOG_SIGNATURE_HEADER] = signature;
      }
      return await this.fetchImpl(url, {
        method: "POST",
        headers,
        body: text,
        signal: ctrl?.signal,
      });
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private simple(verdict: Verdict, reason: string, source: CheckSource): Omit<CheckResult, "durationMs" | "background"> {
    return {
      verdict,
      allowed: verdict === "allowed",
      blocked: verdict === "blocked",
      throttled: verdict === "throttled",
      reason,
      source,
      decision: null,
    };
  }

  private report(err: Error, context: string) {
    try {
      this.opts.onError?.(err instanceof Error ? err : new Error(String(err)), context);
    } catch {
      /* never let a logging hook break the app */
    }
  }

  private startTimers() {
    if (typeof setInterval === "undefined") return;
    this.timer = setInterval(() => {
      void this.maybeRefresh();
      void this.maybeFlush();
    }, Math.min(this.opts.syncIntervalMs, this.opts.logFlushIntervalMs));
    // Do not keep a Node process alive just for this timer.
    (this.timer as unknown as { unref?: () => void }).unref?.();
  }
}

/* One client per key+URL, so serverless isolates reuse their cache between requests. */
const clients = new Map<string, ShieldClient>();

export function getClient(options: ShieldOptions): ShieldClient {
  const key = `${options.syncUrl}|${options.connectionKey}`;
  let c = clients.get(key);
  if (!c) {
    c = new ShieldClient(options);
    clients.set(key, c);
  }
  return c;
}

export function createClient(options: ShieldOptions): ShieldClient {
  return new ShieldClient(options);
}

