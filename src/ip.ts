// Client IP extraction.
//
// Getting the real client IP is the most security-sensitive part of the integration.
// Headers like X-Forwarded-For can be written by the client, so the first value must
// never be trusted. Each adapter picks a safe default for its platform; you can
// override it with `trustedHeader` or `trustedProxyCount`, or pass `getClientIp`.

import { parseIp } from "./engine.ts";

export interface IpOptions {
  /** Read the client IP from this single header (e.g. "cf-connecting-ip", "x-real-ip"). Only set this
   *  when your own infrastructure sets the header and strips any client-supplied value. */
  trustedHeader?: string;
  /** Number of proxies you run in front of the app that append to X-Forwarded-For. Default 1. */
  trustedProxyCount?: number;
}

type HeaderGetter = (name: string) => string | null | undefined;

/** Strip a port and brackets, validate. Returns "" when the value is not an IP address. */
export function cleanIp(value: string | null | undefined): string {
  if (!value) return "";
  let s = String(value).trim();
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end > 0) s = s.slice(1, end);
  } else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(s)) {
    s = s.slice(0, s.lastIndexOf(":"));
  }
  if (!parseIp(s)) return "";
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  return mapped ? mapped[1] : s;
}

/** The entry `trustedProxyCount` positions from the right of X-Forwarded-For. */
export function fromForwardedFor(xff: string | null | undefined, trustedProxyCount = 1): string {
  if (!xff) return "";
  const list = xff.split(",").map((s) => s.trim()).filter(Boolean);
  if (!list.length) return "";
  const count = Math.max(1, Math.floor(trustedProxyCount));
  const idx = Math.max(0, list.length - count);
  return cleanIp(list[idx]);
}

/**
 * Resolve the client IP from request headers.
 * Order: `trustedHeader` (if configured) → platform defaults given in `defaults` → X-Forwarded-For
 * counted from the right → `fallback` (e.g. the socket address).
 */
export function clientIpFromHeaders(
  get: HeaderGetter,
  opts: IpOptions = {},
  defaults: string[] = [],
  fallback?: string | null,
): string {
  if (opts.trustedHeader) {
    const v = get(opts.trustedHeader.toLowerCase());
    return cleanIp(v ? v.split(",")[0] : "");
  }
  for (const h of defaults) {
    const v = cleanIp((get(h) || "").split(",")[0]);
    if (v) return v;
  }
  const xff = fromForwardedFor(get("x-forwarded-for"), opts.trustedProxyCount ?? 1);
  if (xff) return xff;
  return cleanIp(fallback || "");
}
