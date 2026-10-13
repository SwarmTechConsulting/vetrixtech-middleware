// VetrixTech client: keeps a local copy of the app's rules, judges each request locally
// with the shared engine, and ships traffic logs in the background.
//
// Nothing here makes a network call on the request path, except the very first sync
// after a cold start (bounded by `firstSyncTimeoutMs`).

import {
  evaluate,
  scopeMatches,
  type BlockEntry,
  type Decision,
  type Rule,
  type Verdict,
} from "./engine.ts";

export const SDK_VERSION = "0.1.0";

export type FailMode = "open" | "closed";

export interface VetrixOptions {
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
  /** Keep enforcing the last good rules for this long if VetrixTech is unreachable. Default 15 min. */
  maxStaleMs?: number;
  /** Timeout for sync and log calls. Default 3 s. */
  requestTimeoutMs?: number;
  /** On a cold start, wait at most this long for the first rules before applying the fail mode. Default 1.5 s. */
  firstSyncTimeoutMs?: number;
  /** Send queued logs every this many ms (checked on each request, and by a timer where `timers` is on). Default 5 s. */
  logFlushIntervalMs?: number;
  /** Max events per log call (the server accepts up to 100). Default 100. */
  logBatchSize?: number;
  /** Max events held in memory while VetrixTech is unreachable; oldest are dropped. Default 5,000. */
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
  trace?: string;
  details: Record<string, unknown>;
}

interface SyncResponse {
  up_to_date?: boolean;
  version?: string | number;
  fail_mode?: string;
  rules?: Rule[];
  blocklist?: BlockEntry[];
  error?: string;
}

type Hit = [time: number, method: string, path: string];

const MAX_HITS_PER_IP = 2000;
const MAX_TRACKED_IPS = 50000;
const INCIDENT_DEDUPE_MS = 30 * 60 * 1000;

function nowPerf(): number {
  return typeof performance !== "undefined" && performance.now ? performance.now() : Date.now();
}

function trunc(s: unknown, n: number): string {
  const str = s === undefined || s === null ? "" : String(s);
  return str.length > n ? str.slice(0, n) : str;
}

export class VetrixClient {
  readonly opts: Required<
    Omit<VetrixOptions, "logUrl" | "onError" | "fetch" | "now" | "burst">
  > & Pick<VetrixOptions, "logUrl" | "onError" | "burst">;

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
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(options: VetrixOptions) {
    if (!options || !options.connectionKey) throw new Error("VetrixTech: connectionKey is required");
    if (!options.syncUrl) throw new Error("VetrixTech: syncUrl is required");
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
    const f = options.fetch ?? (typeof fetch !== "undefined" ? fetch : undefined);
    if (!f) throw new Error("VetrixTech: no fetch implementation available; pass options.fetch");
    this.fetchImpl = f.bind(globalThis) as typeof fetch;
    this.clock = options.now ?? (() => Date.now());
    this.lastFlush = this.clock();
    if (this.opts.timers) this.startTimers();
  }

  /* ---------------- public API ---------------- */

  /** Judge one request. Never throws. */
  async check(info: RequestInfo): Promise<CheckResult> {
    const t0 = nowPerf();
    try {
      await this.ensureFirstSync();
      const background: Promise<void>[] = [];
      const refresh = this.maybeRefresh();
      if (refresh) background.push(refresh);

      const now = this.clock();
      const ip = info.ip || "";
      const method = (info.method || "GET").toUpperCase();
      const path = info.path || "/";

      let result: Omit<CheckResult, "durationMs" | "background">;
      if (this.disabled) {
        result = this.simple("allowed", "VetrixTech disabled: connection key rejected or app paused", "disabled");
      } else if (!this.lastSyncOk || now - this.lastSyncOk > this.opts.maxStaleMs) {
        const mode = this.serverFailMode ?? this.opts.failMode;
        result = mode === "closed"
          ? this.simple("blocked", "Fail closed: rules unavailable", "fail_closed")
          : this.simple("allowed", "Fail open: rules unavailable", "fail_open");
      } else {
        if (!ip && !this.warnedNoIp) {
          this.warnedNoIp = true;
          this.report(new Error("Could not determine the client IP; IP rules, blocklist and rate limits are skipped for such requests. Check your proxy/IP settings."), "client_ip");
        }
        if (++this.checks % 1000 === 0) this.evictHits(now);
        if (ip) this.recordHit(ip, method, path, now);
        const local = ip ? this.localBlocks.get(ip) : undefined;
        const blocklist = local && local.until > now
          ? [...this.blocklist, { ip_or_range: ip, reason: local.reason, expires_at: new Date(local.until).toISOString(), source: "local" }]
          : this.blocklist;
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
            burst: this.opts.burst,
            autoDetection: this.opts.autoDetection,
          },
        );
        if (decision.autoBlock && ip) {
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
      }

      const durationMs = Math.round((nowPerf() - t0) * 100) / 100;
      if (result.source !== "disabled") this.enqueue(info, result, durationMs, now);
      const flush = this.maybeFlush();
      if (flush) background.push(flush);

      return {
        ...result,
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
    if (this.syncing || now - this.lastSyncAttempt < interval) return null;
    return this.sync();
  }

  private async doSync(force: boolean): Promise<void> {
    const now = this.clock();
    this.lastSyncAttempt = now;
    const full = force || !this.lastSyncOk || now - this.lastFullSync >= this.opts.fullSyncEveryMs;
    try {
      const res = await this.post(this.opts.syncUrl, {
        connection_key: this.opts.connectionKey,
        client_version: full ? null : this.version,
        sdk_version: SDK_VERSION,
      });
      if (res.status === 401 || res.status === 403) {
        this.disabled = true;
        this.report(new Error(`Sync rejected (${res.status}): connection key invalid, rotated, or app paused. Traffic is allowed through until this is fixed.`), "sync");
        return;
      }
      if (!res.ok) throw new Error(`Sync failed with HTTP ${res.status}`);
      const body = (await res.json()) as SyncResponse;
      this.disabled = false;
      if (body.fail_mode === "fail_closed") this.serverFailMode = "closed";
      else if (body.fail_mode === "fail_open") this.serverFailMode = "open";
      if (!body.up_to_date) {
        if (!Array.isArray(body.rules) || !Array.isArray(body.blocklist)) throw new Error("Sync response missing rules or blocklist");
        this.rules = body.rules;
        this.blocklist = body.blocklist;
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
    let incident = result.verdict === "blocked" && result.source === "rules" && !fromBlocklist;
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
      details: {
        source: "middleware",
        sdk_version: SDK_VERSION,
        verdict_source: result.source,
        auto_block_type: d?.autoBlock?.type ?? null,
        observe_matches: d?.observed.map((o) => o.name) ?? [],
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
      const res = await this.post(this.opts.logUrl!, { connection_key: this.opts.connectionKey, logs: batch });
      if (res.status === 401 || res.status === 403) {
        this.report(new Error(`Log upload rejected (${res.status}); dropping ${batch.length} events`), "log");
        this.logBackoffUntil = this.clock() + 60_000;
        return;
      }
      if (res.status === 429) {
        this.requeue(batch);
        this.logBackoffUntil = this.clock() + 30_000;
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

  private async post(url: string, body: unknown): Promise<Response> {
    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), this.opts.requestTimeoutMs) : undefined;
    try {
      return await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json", "x-vetrixtech-sdk": SDK_VERSION },
        body: JSON.stringify(body),
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
const clients = new Map<string, VetrixClient>();

export function getClient(options: VetrixOptions): VetrixClient {
  const key = `${options.syncUrl}|${options.connectionKey}`;
  let c = clients.get(key);
  if (!c) {
    c = new VetrixClient(options);
    clients.set(key, c);
  }
  return c;
}

export function createClient(options: VetrixOptions): VetrixClient {
  return new VetrixClient(options);
}
