// @swarmtechshield/middleware
//
// Drop-in request screening for SwarmTech Shield. Rules are checked locally from a
// synced cache, so no network call sits on the request path; traffic logs are sent
// in the background.

import { express } from "./adapters/express.ts";
import { base44, cloudflare, nextjs, screenRequest } from "./adapters/fetch.ts";
import { decorate, toResponse } from "./adapters/shared.ts";
import { createClient, getClient } from "./client.ts";
import * as engine from "./engine.ts";
import type { ShieldOptions } from "./client.ts";
import type { OutcomeReport } from "./defence.ts";

/** Report a login, payment or sign-up outcome for the client these options identify. */
function reportOutcome(options: ShieldOptions, report: OutcomeReport): void {
  try {
    getClient(options).reportOutcome(report);
  } catch {
    /* misconfigured: nothing to record */
  }
}

export const SwarmTechShield = {
  express,
  nextjs,
  cloudflare,
  base44,
  screenRequest,
  toResponse,
  decorate,
  reportOutcome,
  createClient,
  getClient,
  engine,
};

/**
 * @deprecated The product is now SwarmTech Shield. `VetrixTech` is the same object as
 * `SwarmTechShield`, kept so code written against @vetrixtech/middleware keeps working.
 */
export const VetrixTech = SwarmTechShield;

export default SwarmTechShield;

export { express, nextjs, cloudflare, base44, screenRequest, toResponse, decorate, reportOutcome, createClient, getClient, engine };
export { ShieldClient, VetrixClient, SDK_VERSION } from "./client.ts";
export type { ShieldOptions, VetrixOptions, RequestInfo, CheckResult, CheckSource, FailMode } from "./client.ts";
export type { ExpressOptions } from "./adapters/express.ts";
export type { FetchAdapterOptions, WaitUntilContext } from "./adapters/fetch.ts";
export type { AdapterOptions, ResponseOptions } from "./adapters/shared.ts";
export type { Decision, Rule, BlockEntry, TraceStep, Verdict } from "./engine.ts";
export { cleanIp, clientIpFromHeaders, fromForwardedFor } from "./ip.ts";
export { inspect, collectParts, parseBody, INSPECTION_RULES } from "./inspect.ts";
export type {
  InspectionConfig,
  InspectionInput,
  InspectionResult,
  InspectionMode,
  InspectionExclusion,
  Finding,
  Location,
  Paranoia,
} from "./inspect.ts";
export { honeypotFieldHtml, signProbe, satisfies, DEFAULT_DECOY_PATHS, DEFAULT_OUTCOME_RULES, PROBE_HEADER } from "./defence.ts";
export type {
  DecoyOptions,
  DecoyResponse,
  OutcomeConfig,
  OutcomeReport,
  OutcomeRule,
  OutcomeType,
  VirtualPatch,
  ActivePatch,
  ProbeResult,
} from "./defence.ts";
export { DEFAULT_PRIORITY_PATHS } from "./resilience.ts";
export type { ResilienceOptions, ResilienceState } from "./resilience.ts";
