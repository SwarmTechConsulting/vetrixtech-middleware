// SwarmTech Shield resilience: keep an app working through application-layer floods.
//
// This cannot stop a volumetric (network-level) DDoS: that needs an edge network such as
// SwarmTech Shield Edge or Cloudflare in front. What it does is protect the app itself when
// a flood of expensive requests reaches it:
//
//  - Under-attack mode: switched on by the console (sync), by your code, or automatically
//    when traffic jumps well above its recent baseline. While on, the per-IP burst limit is
//    tighter and request inspection blocks instead of only observing.
//  - Load shedding: when the server is overloaded (event-loop lag on Node, Deno and Bun),
//    low-priority anonymous requests get a cheap 503 so logins, checkout and signed-in users
//    keep working.
//
// Runtime-agnostic. The lag monitor only runs where setInterval exists and timers are allowed.

export interface ResilienceOptions {
  /** Force under-attack mode on from your code. The console can also switch it on through sync. */
  underAttack?: boolean;
  /** Switch under-attack mode on automatically when traffic jumps. Default on. false disables. */
  auto?: { multiplier?: number; minRequestsPerSecond?: number } | false;
  /** Per-IP burst limit while under attack. Default 60 requests / 60 s (normally 120). */
  burst?: { maxRequests: number; windowSeconds: number };
  /** Make request inspection block (not just observe) while under attack. Default true. */
  enforceInspection?: boolean;
  /** Shed low-priority requests when the server is overloaded. Default on. false disables. */
  loadShedding?: { maxLagMs?: number; priorityPaths?: string[]; retryAfterSeconds?: number } | false;
  /** Custom load metric in milliseconds (replaces the built-in event-loop lag monitor). */
  loadProbe?: () => number;
}

export const DEFAULT_PRIORITY_PATHS = [
  "/login", "/signin", "/sign-in", "/auth*", "/api/auth*", "/session*",
  "/checkout*", "/pay*", "/payment*", "/api/payment*", "/api/checkout*",
  "/health*", "/healthz", "/ready*", "/status",
];

const BUCKET_MS = 10_000;
const BASELINE_BUCKETS = 60; // 10 minutes of 10-second buckets
const RELEASE_MS = 60_000;

function matchPath(list: string[], path: string): boolean {
  const p = (path.split("?")[0] || "/").toLowerCase();
  return list.some((t) => {
    const target = t.toLowerCase();
    return target.endsWith("*") ? p.startsWith(target.slice(0, -1)) : p === target || p === `${target}/`;
  });
}

export interface ResilienceState {
  underAttack: boolean;
  /** Why under-attack mode is on: "console", "local" or "auto". */
  underAttackSource: "console" | "local" | "auto" | null;
  requestsPerSecond: number;
  baselinePerSecond: number;
  loadMs: number;
  overloaded: boolean;
  shedRequests: number;
}

export class Resilience {
  readonly burst: { maxRequests: number; windowSeconds: number };
  readonly enforceInspection: boolean;
  readonly retryAfterSeconds: number;
  private clock: () => number;
  private localFlag: boolean;
  private consoleFlag = false;
  private auto: { multiplier: number; minRequestsPerSecond: number } | null;
  private shedding: { maxLagMs: number; priorityPaths: string[] } | null;
  private loadProbe: (() => number) | null;

  private buckets: { start: number; count: number }[] = [];
  private autoOn = false;
  private autoHot = 0;
  private calmSince = 0;
  private lagMs = 0;
  private timer: ReturnType<typeof setInterval> | null = null;
  shedCount = 0;

  constructor(options: ResilienceOptions = {}, clock: () => number = () => Date.now()) {
    this.clock = clock;
    this.localFlag = !!options.underAttack;
    this.auto =
      options.auto === false
        ? null
        : { multiplier: options.auto?.multiplier ?? 5, minRequestsPerSecond: options.auto?.minRequestsPerSecond ?? 50 };
    this.burst = options.burst ?? { maxRequests: 60, windowSeconds: 60 };
    this.enforceInspection = options.enforceInspection !== false;
    this.shedding =
      options.loadShedding === false
        ? null
        : {
            maxLagMs: options.loadShedding?.maxLagMs ?? 200,
            priorityPaths: options.loadShedding?.priorityPaths ?? DEFAULT_PRIORITY_PATHS,
          };
    this.retryAfterSeconds = (options.loadShedding && options.loadShedding.retryAfterSeconds) || 5;
    this.loadProbe = options.loadProbe ?? null;
  }

  /** Start the event-loop lag monitor (long-running servers only). */
  startMonitor() {
    if (this.timer || this.loadProbe || !this.shedding || typeof setInterval === "undefined") return;
    const interval = 250;
    let expected = Date.now() + interval;
    this.timer = setInterval(() => {
      const now = Date.now();
      const lag = Math.max(0, now - expected);
      // Smooth it so one slow tick doesn't trigger shedding.
      this.lagMs = this.lagMs * 0.6 + lag * 0.4;
      expected = now + interval;
    }, interval);
    (this.timer as unknown as { unref?: () => void }).unref?.();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  setConsoleFlag(on: boolean) {
    this.consoleFlag = !!on;
  }

  setLocalFlag(on: boolean) {
    this.localFlag = !!on;
  }

  /** Count one request and update the automatic under-attack state. */
  record(now = this.clock()) {
    const start = Math.floor(now / BUCKET_MS) * BUCKET_MS;
    const last = this.buckets[this.buckets.length - 1];
    if (last && last.start === start) last.count++;
    else {
      if (last) this.evaluateAuto(last, now);
      this.buckets.push({ start, count: 1 });
      if (this.buckets.length > BASELINE_BUCKETS + 1) this.buckets.splice(0, this.buckets.length - BASELINE_BUCKETS - 1);
    }
  }

  private baseline(excludeLast: boolean): number {
    const list = excludeLast ? this.buckets.slice(0, -1) : this.buckets;
    if (!list.length) return 0;
    const counts = list.map((b) => b.count).sort((a, b) => a - b);
    // The median is robust: the attack itself doesn't drag the baseline up.
    return counts[Math.floor(counts.length / 2)] / (BUCKET_MS / 1000);
  }

  private evaluateAuto(finished: { start: number; count: number }, now: number) {
    if (!this.auto) return;
    const rps = finished.count / (BUCKET_MS / 1000);
    const base = this.baseline(true);
    const hot = rps >= this.auto.minRequestsPerSecond && (base === 0 ? rps >= this.auto.minRequestsPerSecond * 2 : rps >= base * this.auto.multiplier);
    if (hot) {
      this.autoHot++;
      this.calmSince = 0;
      if (this.autoHot >= 2) this.autoOn = true; // two hot buckets in a row (20 s) to switch on
    } else {
      this.autoHot = 0;
      if (this.autoOn) {
        if (!this.calmSince) this.calmSince = now;
        if (now - this.calmSince >= RELEASE_MS) {
          this.autoOn = false;
          this.calmSince = 0;
        }
      }
    }
  }

  underAttack(): boolean {
    return this.localFlag || this.consoleFlag || this.autoOn;
  }

  load(): number {
    if (this.loadProbe) {
      try {
        return Number(this.loadProbe()) || 0;
      } catch {
        return 0;
      }
    }
    return this.lagMs;
  }

  overloaded(): boolean {
    return !!this.shedding && this.load() > this.shedding.maxLagMs;
  }

  /** Should this request be shed? Priority paths and signed-in users are kept. */
  shouldShed(path: string, user?: string): boolean {
    if (!this.shedding || !this.overloaded()) return false;
    if (user) return false;
    return !matchPath(this.shedding.priorityPaths, path);
  }

  state(): ResilienceState {
    const last = this.buckets[this.buckets.length - 1];
    return {
      underAttack: this.underAttack(),
      underAttackSource: this.consoleFlag ? "console" : this.localFlag ? "local" : this.autoOn ? "auto" : null,
      requestsPerSecond: last ? Math.round((last.count / (BUCKET_MS / 1000)) * 10) / 10 : 0,
      baselinePerSecond: Math.round(this.baseline(true) * 10) / 10,
      loadMs: Math.round(this.load()),
      overloaded: this.overloaded(),
      shedRequests: this.shedCount,
    };
  }
}
