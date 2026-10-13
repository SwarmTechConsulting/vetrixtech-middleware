// Express / Connect middleware.
//
//   app.set("trust proxy", 1);           // so req.ip is the real client behind your load balancer
//   app.use(VetrixTech.express({ connectionKey, syncUrl, logUrl }));
//
// By default the client IP is Express's req.ip, which follows your "trust proxy" setting.
// Pass trustedHeader / trustedProxyCount / getClientIp to override.

import { getClient, type CheckResult } from "../client.ts";
import { cleanIp, clientIpFromHeaders } from "../ip.ts";
import { bodySizeFrom, type AdapterOptions } from "./shared.ts";

// Minimal structural types so the package has no dependency on @types/express.
export interface ExpressLikeRequest {
  ip?: string;
  method?: string;
  originalUrl?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string; localPort?: number };
  vetrixtech?: CheckResult;
}
export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  set?(field: string, value: string): ExpressLikeResponse;
  setHeader?(field: string, value: string): unknown;
  type?(t: string): ExpressLikeResponse;
  send(body?: unknown): unknown;
  headersSent?: boolean;
}
export type NextFunction = (err?: unknown) => void;

export interface ExpressOptions extends AdapterOptions {
  /** Return the client IP yourself. */
  getClientIp?: (req: ExpressLikeRequest) => string;
  /** Skip screening for some requests (e.g. your own health check). */
  skip?: (req: ExpressLikeRequest) => boolean;
  /** Custom handling for blocked or throttled requests. */
  onBlocked?: (req: ExpressLikeRequest, res: ExpressLikeResponse, next: NextFunction, result: CheckResult) => void;
}

function header(req: ExpressLikeRequest, name: string): string | undefined {
  const v = req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v.join(",") : v;
}

export function express(options: ExpressOptions) {
  const client = getClient({ timers: true, ...options });
  const useHeaders = !!(options.trustedHeader || options.trustedProxyCount);

  return function vetrixtech(req: ExpressLikeRequest, res: ExpressLikeResponse, next: NextFunction): void {
    // Errors thrown by later handlers go to Express's error handling (as Express itself does),
    // never into this promise chain, where they would become unhandled rejections.
    const proceed = () => {
      try {
        next();
      } catch (err) {
        next(err);
      }
    };
    if (options.skip?.(req)) return proceed();

    let ip: string;
    try {
      ip = options.getClientIp
        ? cleanIp(options.getClientIp(req))
        : useHeaders
          ? clientIpFromHeaders((h) => header(req, h), options, [], req.socket?.remoteAddress)
          : cleanIp(req.ip || req.socket?.remoteAddress);
    } catch {
      ip = "";
    }

    client
      .check({
        ip,
        method: req.method,
        path: req.originalUrl || req.url || "/",
        userAgent: header(req, "user-agent"),
        bodySize: bodySizeFrom(header(req, "content-length")),
        country: options.countryHeader ? header(req, options.countryHeader) : undefined,
        port: req.socket?.localPort,
      })
      .then((result) => {
        req.vetrixtech = result;
        if (result.allowed) return proceed();
        if (options.onBlocked) return options.onBlocked(req, res, next, result);
        if (res.headersSent) return;
        if (result.throttled) {
          const retry = String(options.retryAfterSeconds ?? 60);
          if (res.set) res.set("Retry-After", retry);
          else res.setHeader?.("Retry-After", retry);
          res.status(options.throttledStatus ?? 429).send("Too Many Requests");
          return;
        }
        res.status(options.blockedStatus ?? 403).send(options.blockedBody ?? "Forbidden");
      }, () => proceed());
  };
}
