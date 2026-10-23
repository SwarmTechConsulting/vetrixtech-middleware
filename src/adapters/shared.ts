import type { CheckResult, ShieldOptions } from "../client.ts";
import type { IpOptions } from "../ip.ts";

export interface ResponseOptions {
  /** HTTP status for blocked requests. Default 403. */
  blockedStatus?: number;
  /** Body for blocked requests. Default "Forbidden". Never reveals which rule matched. */
  blockedBody?: string;
  /** HTTP status for throttled requests. Default 429. */
  throttledStatus?: number;
  /** Retry-After seconds sent with throttled responses. Default 60. */
  retryAfterSeconds?: number;
}

export interface AdapterOptions extends ShieldOptions, IpOptions, ResponseOptions {
  /** Header carrying the visitor's ISO country code, if your platform sets one. */
  countryHeader?: string;
}

/** Build the response a blocked or throttled request should get. Returns null when allowed. */
export function toResponse(result: CheckResult, opts: ResponseOptions = {}): Response | null {
  if (result.allowed) return null;
  if (result.throttled) {
    return new Response("Too Many Requests", {
      status: opts.throttledStatus ?? 429,
      headers: { "retry-after": String(opts.retryAfterSeconds ?? 60), "content-type": "text/plain; charset=utf-8" },
    });
  }
  return new Response(opts.blockedBody ?? "Forbidden", {
    status: opts.blockedStatus ?? 403,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

export function pathFromUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url || "/";
  }
}

export function bodySizeFrom(header: string | null | undefined): number {
  const n = Number(header);
  return Number.isFinite(n) && n > 0 ? n : 0;
}
