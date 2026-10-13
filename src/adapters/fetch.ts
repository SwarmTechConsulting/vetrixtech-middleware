// Adapters for runtimes built on the standard Request/Response API:
// Next.js middleware, Cloudflare Workers, Base44 (Deno) functions.

import { getClient, type CheckResult } from "../client.ts";
import { cleanIp, clientIpFromHeaders } from "../ip.ts";
import { bodySizeFrom, pathFromUrl, toResponse, type AdapterOptions } from "./shared.ts";

export interface FetchAdapterOptions extends AdapterOptions {
  /** Return the client IP yourself. */
  getClientIp?: (req: Request) => string;
  /** Skip screening for some requests. */
  skip?: (req: Request) => boolean;
}

export interface WaitUntilContext {
  waitUntil(promise: Promise<unknown>): void;
}

const ALLOWED_SKIPPED: CheckResult = {
  verdict: "allowed",
  allowed: true,
  blocked: false,
  throttled: false,
  reason: "Skipped",
  source: "rules",
  decision: null,
  durationMs: 0,
};

let reportedConfigError = false;

async function screen(
  req: Request,
  options: FetchAdapterOptions,
  defaults: { ipHeaders: string[]; countryHeader?: string; country?: string },
): Promise<CheckResult> {
  if (options.skip?.(req)) return ALLOWED_SKIPPED;
  let client;
  try {
    client = getClient({ ...options, timers: false });
  } catch (err) {
    // Missing connection key or URL: never take the site down; report once.
    if (!reportedConfigError) {
      reportedConfigError = true;
      const e = err instanceof Error ? err : new Error(String(err));
      if (options.onError) options.onError(e, "config");
      else console.error(`[vetrixtech] ${e.message}. Requests are NOT being screened.`);
    }
    return { ...ALLOWED_SKIPPED, source: "disabled", reason: "VetrixTech misconfigured" };
  }
  const get = (h: string) => req.headers.get(h);
  let ip = "";
  try {
    ip = options.getClientIp
      ? cleanIp(options.getClientIp(req))
      : clientIpFromHeaders(get, options, options.trustedHeader ? [] : defaults.ipHeaders);
  } catch {
    ip = "";
  }
  const countryHeader = options.countryHeader ?? defaults.countryHeader;
  return client.check({
    ip,
    method: req.method,
    path: pathFromUrl(req.url),
    userAgent: get("user-agent") || "",
    bodySize: bodySizeFrom(get("content-length")),
    country: defaults.country || (countryHeader ? get(countryHeader) || "" : ""),
  });
}

/* ---------------- Next.js ---------------- */

/**
 * Next.js middleware (middleware.ts):
 *   export const middleware = VetrixTech.nextjs({ connectionKey: process.env.VETRIXTECH_KEY!, syncUrl, logUrl });
 *
 * Client IP defaults to x-real-ip (set by Vercel), then X-Forwarded-For counted from the right.
 * Self-hosting behind your own proxy? Make sure it overwrites x-real-ip, or set trustedHeader.
 */
export function nextjs(options: FetchAdapterOptions) {
  return async function vetrixtechMiddleware(request: Request, event?: WaitUntilContext): Promise<Response | undefined> {
    const result = await screen(request, options, { ipHeaders: ["x-real-ip"], countryHeader: "x-vercel-ip-country" });
    if (result.background) event?.waitUntil(result.background);
    return toResponse(result, options) ?? undefined;
  };
}

/* ---------------- Cloudflare Workers ---------------- */

/**
 * Cloudflare Workers:
 *   const result = await VetrixTech.cloudflare(request, { connectionKey: env.VETRIXTECH_KEY, syncUrl, logUrl }, ctx);
 *   if (!result.allowed) return VetrixTech.toResponse(result);
 *
 * Client IP comes from CF-Connecting-IP and country from request.cf, both set by Cloudflare.
 */
export async function cloudflare(
  request: Request,
  options: FetchAdapterOptions,
  ctx?: WaitUntilContext,
): Promise<CheckResult> {
  const cf = (request as unknown as { cf?: { country?: string } }).cf;
  const result = await screen(request, options, {
    ipHeaders: ["cf-connecting-ip"],
    countryHeader: "cf-ipcountry",
    country: cf?.country,
  });
  if (result.background) ctx?.waitUntil(result.background);
  return result;
}

/* ---------------- Base44 / Deno functions ---------------- */

/**
 * Base44 backend functions (Deno):
 *   const result = await VetrixTech.base44(req, { connectionKey: Deno.env.get("VETRIXTECH_KEY")!, syncUrl, logUrl });
 *   if (!result.allowed) return VetrixTech.toResponse(result);
 *
 * There is no waitUntil here, so when a log flush is due this waits for it (at most
 * `backgroundWaitMs`, default 500 ms). Most requests do not wait at all.
 * Client IP defaults to X-Forwarded-For counted from the right (trustedProxyCount, default 1).
 */
export async function base44(
  request: Request,
  options: FetchAdapterOptions & { backgroundWaitMs?: number },
): Promise<CheckResult> {
  const result = await screen(request, options, { ipHeaders: [] });
  if (result.background) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      result.background,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, options.backgroundWaitMs ?? 500);
      }),
    ]);
    if (timer) clearTimeout(timer);
  }
  return result;
}

/** Generic: screen any standard Request (Deno.serve, Bun.serve, Hono, etc.). */
export async function screenRequest(request: Request, options: FetchAdapterOptions): Promise<CheckResult> {
  return screen(request, options, { ipHeaders: [] });
}
