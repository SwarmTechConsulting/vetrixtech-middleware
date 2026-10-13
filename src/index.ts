// @vetrixtech/middleware
//
// Drop-in request screening for VetrixTech. Rules are checked locally from a synced
// cache, so no network call sits on the request path; traffic logs are sent in the
// background.

import { express } from "./adapters/express.ts";
import { base44, cloudflare, nextjs, screenRequest } from "./adapters/fetch.ts";
import { toResponse } from "./adapters/shared.ts";
import { createClient, getClient } from "./client.ts";
import * as engine from "./engine.ts";

export const VetrixTech = {
  express,
  nextjs,
  cloudflare,
  base44,
  screenRequest,
  toResponse,
  createClient,
  getClient,
  engine,
};

export default VetrixTech;

export { express, nextjs, cloudflare, base44, screenRequest, toResponse, createClient, getClient, engine };
export { VetrixClient, SDK_VERSION } from "./client.ts";
export type { VetrixOptions, RequestInfo, CheckResult, CheckSource, FailMode } from "./client.ts";
export type { ExpressOptions } from "./adapters/express.ts";
export type { FetchAdapterOptions, WaitUntilContext } from "./adapters/fetch.ts";
export type { AdapterOptions, ResponseOptions } from "./adapters/shared.ts";
export type { Decision, Rule, BlockEntry, TraceStep, Verdict } from "./engine.ts";
export { cleanIp, clientIpFromHeaders, fromForwardedFor } from "./ip.ts";
