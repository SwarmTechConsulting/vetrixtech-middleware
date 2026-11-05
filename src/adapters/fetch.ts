// Adapters for runtimes built on the standard Request/Response API:
// Next.js middleware, Cloudflare Workers, Base44 (Deno) functions.

import { getClient, type CheckResult } from "../client.ts";
import { cleanIp, clientIpFromHeaders } from "../ip.ts";
import { bodySizeFrom, inspectableContentType, pathFromUrl, toResponse, type AdapterOptions } from "./shared.ts";

/** Read a request body (from a clone, so the original is untouched) up to a byte cap. */
async function readBodyForInspection(
  req: Request,
  options: AdapterOptions,
): Promise<{ body?: string; contentType?: string }> {
  if (options.inspection === false && options.decoys === false) return {};
  const cap = options.maxBodyBytes ?? 65536;
  if (cap <= 0) return {};
  const method = req.method.toUpperCase();
  if (method === "GET" || method === "HEAD") return {};
  const ct = req.headers.get("content-type") || "";
  if (!inspectableContentType(ct)) return {};
  const len = Number(req.headers.get("content-length") || "0");
  if (Number.isFinite(len) && len > cap) return { contentType: ct }; // too big to read; URL/headers still inspected
  try {
    if (!req.body && !req.bodyUsed && typeof req.clone !== "function") return { contentType: ct };
    const text = await req.clone().text();
    return { body: text.length > cap ? text.slice(0, cap) : text, contentType: ct };
  } catch {
    return { contentType: ct };
  }
}

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
      else console.error(`[swarmtechshield] ${e.message}. Requests are NOT being screened.`);
    }
    return { ...ALLOWED_SKIPPED, source: "disabled", reason: "SwarmTech Shield misconfigured" };
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
  const headers: Record<string, string> = {};
  req.headers.forEach((v, k) => {
    headers[k] = v;
  });
  let user: string | undefined;
  try {
    user = options.getUser?.(req);
  } catch {
    user = undefined;
  }
  const path = pathFromUrl(req.url);
  // A request that will be rejected anyway (blocked IP, or shed under load) skips the body read.
  const { body, contentType } = client.rejectsEarly(ip, path, user) ? { body: undefined, contentType: undefined } : await readBodyForInspection(req, options);
  return client.check({
    ip,
    method: req.method,
    path,
    userAgent: get("user-agent") || "",
    bodySize: bodySizeFrom(get("content-length")),
    country: defaults.country || (countryHeader ? get(countryHeader) || "" : ""),
    headers,
    body,
    contentType,
    user,
  });
}

/* ---------------- Next.js ---------------- */

/**
 * Next.js middleware (middleware.ts):
 *   export const middleware = SwarmTechShield.nextjs({ connectionKey: process.env.SWARMTECH_SHIELD_KEY!, syncUrl, logUrl });
 *
 * Client IP defaults to x-real-ip (set by Vercel), then X-Forwarded-For counted from the right.
 * Self-hosting behind your own proxy? Make sure it overwrites x-real-ip, or set trustedHeader.
 */
export function nextjs(options: FetchAdapterOptions) {
  return async function swarmTechShieldMiddleware(request: Request, event?: WaitUntilContext): Promise<Response | undefined> {
    const result = await screen(request, options, { ipHeaders: ["x-real-ip"], countryHeader: "x-vercel-ip-country" });
    if (result.background) event?.waitUntil(result.background);
    return toResponse(result, options) ?? undefined;
  };
}

/* ---------------- Cloudflare Workers ---------------- */

/**
 * Cloudflare Workers:
 *   const result = await SwarmTechShield.cloudflare(request, { connectionKey: env.SWARMTECH_SHIELD_KEY, syncUrl, logUrl }, ctx);
 *   if (!result.allowed) return SwarmTechShield.toResponse(result);
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
 *   const result = await SwarmTechShield.base44(req, { connectionKey: Deno.env.get("SWARMTECH_SHIELD_KEY")!, syncUrl, logUrl });
 *   if (!result.allowed) return SwarmTechShield.toResponse(result);
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
