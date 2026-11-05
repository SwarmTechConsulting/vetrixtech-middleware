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
  /** Read the request body for deep inspection, up to this many bytes. Default 65536. 0 turns off body reading.
   *  Only used when `inspection` is on. The original body is never consumed; a clone is read. */
  maxBodyBytes?: number;
  /** Return the signed-in account for a request (id, username or email), for per-account login and payment limits. */
  getUser?: (req: any) => string | undefined;
}

/** Content types worth reading for inspection: text, JSON, form and XML bodies. */
export function inspectableContentType(ct: string): boolean {
  const t = ct.toLowerCase();
  return (
    t.includes("json") ||
    t.includes("x-www-form-urlencoded") ||
    t.includes("xml") ||
    t.startsWith("text/") ||
    t.includes("+json")
  );
}

/** Build the response a blocked or throttled request should get. Returns null when allowed. */
export function toResponse(result: CheckResult, opts: ResponseOptions = {}): Response | null {
  if (result.allowed) return null;
  const extra = result.verification?.headers ?? {};
  if (result.shed) {
    return new Response("Service Unavailable", {
      status: 503,
      headers: { "retry-after": String(result.retryAfterSeconds ?? 5), "content-type": "text/plain; charset=utf-8", ...extra },
    });
  }
  if (result.decoy) {
    return new Response(result.decoy.body, {
      status: result.decoy.status,
      headers: { "content-type": result.decoy.contentType, "cache-control": "no-store", ...extra },
    });
  }
  if (result.throttled) {
    return new Response("Too Many Requests", {
      status: opts.throttledStatus ?? 429,
      headers: { "retry-after": String(opts.retryAfterSeconds ?? 60), "content-type": "text/plain; charset=utf-8", ...extra },
    });
  }
  return new Response(opts.blockedBody ?? "Forbidden", {
    status: opts.blockedStatus ?? 403,
    headers: { "content-type": "text/plain; charset=utf-8", ...extra },
  });
}

/** Add the verification headers (for a signed checker probe) to your own response on allowed requests. */
export function decorate(response: Response, result: CheckResult): Response {
  const h = result.verification?.headers;
  if (!h) return response;
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(h)) headers.set(k, v);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
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
