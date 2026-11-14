// SwarmTech Shield request inspection.
//
// Looks inside the whole request (path, query parameters, headers, cookies and body)
// for attack payloads, and scores what it finds. A request is blocked when its score
// reaches the threshold, the way the OWASP Core Rule Set's anomaly scoring works:
// one high-confidence finding (score 5) blocks on its own, while weaker hints only
// block when several appear together.
//
// Rules carry a paranoia level. Level 1 holds only high-confidence rules and is the
// default. Levels 2 to 4 add broader rules that catch more but also flag more normal
// traffic, so raise the level per app after watching it in observe mode.
//
// Pure TypeScript with no runtime-specific APIs: it runs unchanged in Node, Deno, Bun,
// Cloudflare Workers and edge runtimes. Every regular expression is bounded so that a
// crafted value can't make matching slow.

import { compileLinear, type LinearRegex } from "./linearRegex.ts";

export type Location = "path" | "query" | "header" | "cookie" | "body";
export type InspectionMode = "block" | "observe" | "off";
export type Paranoia = 1 | 2 | 3 | 4;

export interface InspectionInput {
  method?: string;
  /** Path including the query string, e.g. "/search?q=x". */
  path?: string;
  /** Request headers, any case. Cookie values are taken from the "cookie" header. */
  headers?: Record<string, string | string[] | undefined>;
  /** Parsed body (object or array from JSON or a form), or raw text. */
  body?: unknown;
  /** The body's content type, used to parse a string body. */
  contentType?: string;
}

export interface InspectionExclusion {
  /** Regular expression matched against the path (without the query string). */
  path?: string;
  /** Only for these locations. Default: all. */
  locations?: Location[];
  /** Only for these parameter names (exact, or ending in "*" for a prefix), e.g. "content", "post.*". */
  names?: string[];
  /** Only these rule ids or categories, e.g. "xss" or "xss-tag". Default: all rules. */
  rules?: string[];
}

export interface InspectionConfig {
  /** "block" (default) blocks at the threshold; "observe" logs what would be blocked; "off" skips inspection. */
  mode?: InspectionMode;
  /** 1 (default) to 4. Higher levels add broader rules. */
  paranoia?: Paranoia;
  /** Block when the score reaches this. Default 5: one high-confidence finding. */
  threshold?: number;
  /** Also block the IP on this server for `localBlockSeconds` when the score reaches this. Default 10. 0 disables. */
  autoBlockScore?: number;
  /** Known false positives to ignore. */
  exclusions?: InspectionExclusion[];
  /** Rule ids or categories switched off everywhere. */
  disabledRules?: string[];
  /** Most values inspected per request. Default 500. */
  maxParts?: number;
}

export interface Finding {
  rule: string;
  category: string;
  description: string;
  score: number;
  location: Location;
  name: string;
  /** A short, redacted excerpt of what matched. */
  sample: string;
}

export interface InspectionResult {
  score: number;
  threshold: number;
  mode: InspectionMode;
  paranoia: Paranoia;
  /** True when the score reached the threshold (whatever the mode). */
  matched: boolean;
  findings: Finding[];
  /** Values inspected. */
  inspected: number;
}

interface Part {
  location: Location;
  name: string;
  value: string;
  /** A parameter or JSON key name rather than a value. */
  isKey?: boolean;
}

interface InspectionRule {
  id: string;
  category: string;
  description: string;
  paranoia: Paranoia;
  score: number;
  /** Locations this rule applies to. Default: all. */
  locations?: Location[];
  /** Test names (keys) instead of values. */
  keys?: boolean;
  /** Test the SQL-normalised form (comments removed). */
  sql?: boolean;
  pattern?: RegExp;
  test?: (value: string, part: Part, input: InspectionInput) => boolean;
}

export const CRITICAL = 5;
export const ERROR = 4;
export const WARNING = 3;
export const NOTICE = 2;

const MAX_VALUE = 4096;
const MAX_TOTAL_CHARS = 262_144;
const MAX_DEPTH = 32;
const SAMPLE_LEN = 80;

const URL_LOCS: Location[] = ["path", "query"];
const NOT_PATH: Location[] = ["query", "header", "cookie", "body"];

const SHELL_CMDS =
  "cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|netcat|bash|sh|zsh|dash|python[23]?|perl|php|ruby|powershell|pwsh|cmd(?:\\.exe)?|ping|nslookup|dig|rm|chmod|chown|env|printenv|sleep|telnet|tftp|base64";

/* ------------------------------------------------------------------ */
/* Rules                                                               */
/* ------------------------------------------------------------------ */

export const INSPECTION_RULES: InspectionRule[] = [
  // ---- SQL injection ----
  {
    id: "sqli-union",
    category: "sqli",
    description: "SQL injection: UNION SELECT",
    paranoia: 1,
    score: CRITICAL,
    sql: true,
    pattern: /\bunion\b[\s(+]{1,20}(?:all\s+|distinct\s+)?\(?\s*select\b/i,
  },
  {
    id: "sqli-tautology",
    category: "sqli",
    description: "SQL injection: always-true condition",
    paranoia: 1,
    score: CRITICAL,
    sql: true,
    pattern: /['"`]\s{0,10}\)?\s{0,10}(?:or|and|\|\||&&)\s{1,10}\(?\s{0,10}(?:(['"`]?)([\w.]{1,40})\1\s{0,10}(?:=|<>|!=|\blike\b)\s{0,10}['"`]?\s{0,10}(?:\2\b|\d)|\d{1,10}\s{0,10}(?:=|<>|!=|>|<)\s{0,10}\d|['"`]{2}\s{0,10}=\s{0,10}['"`]|(?:true|false|not\s+false)\b|[\w.]{1,40}\s+is\s+(?:not\s+)?null\b)/i,
  },
  {
    id: "sqli-numeric-tautology",
    category: "sqli",
    description: "SQL injection: numeric always-true condition",
    paranoia: 1,
    score: CRITICAL,
    sql: true,
    pattern: /(?:^|[\s(])\d{1,10}\s{0,10}\)?\s{1,10}(?:or|and)\s{1,10}\(?\s{0,10}(\d{1,10})\s{0,10}=\s{0,10}\1\b/i,
  },
  {
    id: "sqli-comment",
    category: "sqli",
    description: "SQL injection: quote followed by a comment",
    paranoia: 1,
    score: CRITICAL,
    pattern: /['"`]\s{0,10}\)?\s{0,10}(?:--(?:\s|$)|#\s*$|\/\*)/,
  },
  {
    id: "sqli-stacked",
    category: "sqli",
    description: "SQL injection: stacked query",
    paranoia: 1,
    score: CRITICAL,
    sql: true,
    pattern: /;\s{0,10}(?:drop\s+(?:table|database)|delete\s+from|insert\s+into|update\s+\w{1,64}\s+set|truncate\s+table|alter\s+table|create\s+(?:table|user)|exec(?:ute)?\s*(?:\(|\s+xp_|\s+sp_)|shutdown\b|declare\s+@)/i,
  },
  {
    id: "sqli-function",
    category: "sqli",
    description: "SQL injection: database function or system table",
    paranoia: 1,
    score: CRITICAL,
    sql: true,
    pattern: /\b(?:sleep\s*\(\s*\d|benchmark\s*\(\s*\d|pg_sleep\s*\(|waitfor\s+delay\s+['"]|load_file\s*\(|into\s+(?:out|dump)file\b|information_schema\b|xp_cmdshell|mysql\.user\b|extractvalue\s*\(|updatexml\s*\(|dbms_pipe\.receive_message|utl_inaddr|sqlite_master\b|pg_catalog\b)/i,
  },
  {
    id: "sqli-select-from",
    category: "sqli",
    description: "SQL injection: SELECT ... FROM with a clause",
    paranoia: 2,
    score: WARNING,
    sql: true,
    pattern: /\bselect\b[\s\S]{1,200}?\bfrom\b[\s\S]{1,200}?\b(?:where|limit|order\s+by|group\s+by)\b/i,
  },
  {
    id: "sqli-quote-keyword",
    category: "sqli",
    description: "SQL injection: quote followed by a SQL keyword",
    paranoia: 3,
    score: NOTICE,
    sql: true,
    pattern: /['"`]\s{0,10}(?:or|and|union|select|having|order\s+by)\b/i,
  },

  // ---- Cross-site scripting ----
  {
    id: "xss-script",
    category: "xss",
    description: "Cross-site scripting: <script> tag",
    paranoia: 1,
    score: CRITICAL,
    pattern: /<\s{0,10}\/?\s{0,10}script[\s>\/]/i,
  },
  {
    id: "xss-event-handler",
    category: "xss",
    description: "Cross-site scripting: HTML event handler",
    paranoia: 1,
    score: CRITICAL,
    pattern: /<[a-z][a-z0-9-]{0,30}[\s\/][^>]{0,500}?\bon[a-z]{3,25}\s{0,10}=/i,
  },
  {
    id: "xss-js-uri",
    category: "xss",
    description: "Cross-site scripting: javascript: URL",
    paranoia: 1,
    score: CRITICAL,
    pattern: /(?:^|[\s"'`=(<,\[])(?:java|vb|live)script\s{0,10}:\s{0,3}(?:alert|prompt|confirm|eval|fetch|import|document|window|location|this|top|self|parent|void|\(|\[|'|"|`|%|&#|\\|\/)/i,
  },
  {
    id: "xss-data-html",
    category: "xss",
    description: "Cross-site scripting: data:text/html URL",
    paranoia: 1,
    score: CRITICAL,
    pattern: /\bdata\s{0,10}:\s{0,10}text\/html/i,
  },
  {
    id: "xss-tag",
    category: "xss",
    description: "Cross-site scripting: dangerous HTML tag",
    paranoia: 2,
    score: ERROR,
    pattern: /<\s{0,10}(?:iframe|frame|frameset|object|embed|applet|base|meta|svg|math|form|isindex|link|style|template)\b/i,
  },
  {
    id: "xss-dom",
    category: "xss",
    description: "Cross-site scripting: JavaScript DOM or eval call",
    paranoia: 2,
    score: WARNING,
    pattern: /\b(?:document\s*\.\s*(?:cookie|domain|write)|window\s*\.\s*location|\.innerHTML\s*=|String\s*\.\s*fromCharCode|(?:alert|prompt|confirm|eval|atob)\s*\()/i,
  },

  // ---- Path traversal and file inclusion ----
  {
    id: "lfi-traversal",
    category: "lfi",
    description: "Path traversal: repeated ../",
    paranoia: 1,
    score: CRITICAL,
    pattern: /(?:\.\.[\/\\]){2,}/,
  },
  {
    id: "lfi-sensitive-file",
    category: "lfi",
    description: "Path traversal: system file",
    paranoia: 1,
    score: CRITICAL,
    pattern: /(?:^|[\/\\=:])(?:etc[\/\\](?:passwd|shadow|group|hosts)\b|proc[\/\\]self[\/\\](?:environ|cmdline|fd)|windows[\/\\](?:win\.ini|system32)|boot\.ini\b|c:[\/\\]windows[\/\\])/i,
  },
  {
    id: "lfi-wrapper",
    category: "lfi",
    description: "File inclusion: stream wrapper",
    paranoia: 1,
    score: CRITICAL,
    locations: NOT_PATH,
    pattern: /\b(?:php|phar|zip|expect|glob|file):\/\//i,
  },
  {
    id: "lfi-null-byte",
    category: "lfi",
    description: "Null byte in the URL",
    paranoia: 1,
    score: CRITICAL,
    locations: URL_LOCS,
    pattern: /\u0000/,
  },
  {
    id: "lfi-dotdot",
    category: "lfi",
    description: "Path traversal: ../",
    paranoia: 2,
    score: WARNING,
    pattern: /\.\.[\/\\]/,
  },

  // ---- Command injection ----
  {
    id: "rce-shell-chain",
    category: "rce",
    description: "Command injection: chained shell command",
    paranoia: 1,
    score: CRITICAL,
    pattern: new RegExp(`(?:;|\\|{1,2}|&&)\\s{0,10}(?:${SHELL_CMDS})(?:\\s+[-\\/$'"\\d]|\\s*[;&\`]|\\s*$)`, "i"),
  },
  {
    id: "rce-subshell",
    category: "rce",
    description: "Command injection: $( ) subshell",
    paranoia: 1,
    score: CRITICAL,
    pattern: new RegExp(`\\$\\(\\s{0,10}(?:${SHELL_CMDS})\\b`, "i"),
  },
  {
    id: "rce-shell-path",
    category: "rce",
    description: "Command injection: shell binary or IFS trick",
    paranoia: 1,
    score: CRITICAL,
    pattern: /\/bin\/(?:ba|z|da|k)?sh\b|\$\{IFS\}|\$IFS\b|\b(?:nc|ncat|netcat)\s+-[a-z]{0,5}[ec]\b/i,
  },
  {
    id: "rce-shellshock",
    category: "rce",
    description: "Shellshock",
    paranoia: 1,
    score: CRITICAL,
    pattern: /\(\s{0,10}\)\s{0,10}\{[^}]{0,200};\s{0,10}\}\s{0,10};/,
  },
  {
    id: "rce-backtick",
    category: "rce",
    description: "Command injection: backtick command",
    paranoia: 2,
    score: ERROR,
    pattern: new RegExp(`\`\\s{0,10}(?:${SHELL_CMDS})\\b[^\`]{0,200}\``, "i"),
  },
  {
    id: "rce-newline-cmd",
    category: "rce",
    description: "Command injection: command after a line break",
    paranoia: 3,
    score: WARNING,
    pattern: new RegExp(`[\\r\\n]\\s{0,10}(?:${SHELL_CMDS})(?:\\s+[-\\/$]|\\s*$)`, "i"),
  },

  // ---- Server-side request forgery ----
  {
    id: "ssrf-metadata",
    category: "ssrf",
    description: "SSRF: cloud metadata address",
    paranoia: 1,
    score: CRITICAL,
    pattern: /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|169\.254\.170\.2\b|fd00:ec2::254/i,
  },
  {
    id: "ssrf-scheme",
    category: "ssrf",
    description: "SSRF: unusual URL scheme",
    paranoia: 1,
    score: CRITICAL,
    locations: NOT_PATH,
    pattern: /^\s*(?:gopher|dict|ldap|ldaps|tftp|jar|netdoc|sftp):\/\//i,
  },
  {
    id: "ssrf-internal",
    category: "ssrf",
    description: "SSRF: URL pointing at an internal address",
    paranoia: 2,
    score: ERROR,
    locations: NOT_PATH,
    pattern: /^\s*https?:\/\/(?:[^\/@\s]{0,100}@)?(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[?::1\]?|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?:[:\/?#]|$)/i,
  },

  // ---- Code and template injection ----
  {
    id: "jndi-lookup",
    category: "rce",
    description: "Log4Shell-style ${jndi:} lookup",
    paranoia: 1,
    score: CRITICAL,
    pattern: /\$\{\s{0,10}(?:jndi|\$\{|lower:|upper:|::-|env:|sys:|java:|base64:|ctx:|date:|main:|bundle:|k8s:|docker:)/i,
  },
  {
    id: "ssti-probe",
    category: "ssti",
    description: "Template injection probe",
    paranoia: 1,
    score: CRITICAL,
    pattern: /\{\{\s{0,10}\d{1,6}\s{0,10}[*+]\s{0,10}\d{1,6}\s{0,10}\}\}|\$\{\s{0,10}\d{1,6}\s{0,10}\*\s{0,10}\d{1,6}\s{0,10}\}|<%=?\s{0,10}\d{1,6}\s{0,10}\*\s{0,10}\d{1,6}\s{0,10}%>|#\{\s{0,10}\d{1,6}\s{0,10}\*\s{0,10}\d{1,6}\s{0,10}\}/,
  },
  {
    id: "ssti-object-walk",
    category: "ssti",
    description: "Template injection: object traversal",
    paranoia: 1,
    score: CRITICAL,
    pattern: /\{\{[^}]{0,300}?(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|__init__|config\.items|request\.application|lipsum|cycler|joiner)|\$\{\s{0,10}T\s{0,10}\(\s{0,10}java|freemarker\.template\.utility\.Execute/i,
  },
  {
    id: "xxe-entity",
    category: "xxe",
    description: "XML external entity",
    paranoia: 1,
    score: CRITICAL,
    locations: ["body"],
    pattern: /<!ENTITY\s+%?\s{0,10}\S{1,100}\s+(?:SYSTEM|PUBLIC)\b|<!DOCTYPE\s+\S{1,100}\s*\[/i,
  },

  // ---- NoSQL injection and prototype pollution (parameter names and JSON keys) ----
  {
    id: "nosql-operator",
    category: "nosql",
    description: "NoSQL injection: query operator in input",
    paranoia: 1,
    score: CRITICAL,
    keys: true,
    locations: ["query", "body"],
    pattern: /(?:^|[.\[]\s{0,3})\$(?:where|ne|gt|gte|lt|lte|regex|exists|in|nin|expr|function|accumulator|or|and|not|nor|elemMatch|lookup)\s{0,3}\]?$/,
  },
  {
    id: "proto-pollution",
    category: "proto",
    description: "Prototype pollution",
    paranoia: 1,
    score: CRITICAL,
    keys: true,
    locations: ["query", "body", "cookie"],
    pattern: /(?:^|[.\[])\s{0,3}(?:__proto__|constructor\s{0,3}[.\]\[]+\s{0,3}prototype)\b/,
  },

  // ---- Protocol attacks ----
  {
    id: "crlf-injection",
    category: "protocol",
    description: "Header injection: line break followed by a header",
    paranoia: 1,
    score: CRITICAL,
    locations: ["path", "query", "header"],
    pattern: /[\r\n]\s{0,10}(?:set-cookie|location|content-(?:type|length)|x-[\w-]{1,40}|http\/1\.[01])\s{0,10}:?/i,
  },
  {
    id: "method-trace",
    category: "protocol",
    description: "TRACE or TRACK method",
    paranoia: 1,
    score: CRITICAL,
    locations: ["path"],
    test: (_v, _p, input) => /^(?:TRACE|TRACK|DEBUG)$/i.test(input.method || ""),
  },
  {
    id: "method-unusual",
    category: "protocol",
    description: "Unusual HTTP method",
    paranoia: 2,
    score: WARNING,
    locations: ["path"],
    test: (_v, _p, input) =>
      !!input.method && !/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|TRACK|DEBUG)$/i.test(input.method),
  },

  // ---- Probes for sensitive files ----
  {
    id: "probe-sensitive-path",
    category: "probe",
    description: "Probe for a sensitive file or admin endpoint",
    paranoia: 1,
    score: CRITICAL,
    locations: ["path"],
    pattern: /\/(?:\.git|\.svn|\.hg|\.ssh|\.aws|cgi-bin)\/|\/actuator\/(?:env|heapdump|gateway|jolokia|threaddump)\b|\/\.vscode\/sftp\.json|\/(?:\.env(?:\.[\w-]{1,20})?|\.DS_Store|id_rsa|wp-config\.php(?:\.bak|~|\.old|\.save|\.swp)?|config\.php\.(?:bak|old)|web\.config|\.htpasswd|\.htaccess|server-status|phpinfo\.php|xmlrpc\.php|boaform|HNAP1|docker-compose\.ya?ml|\.npmrc|\.dockerenv)(?:$|[\/?#;])/i,
  },
  {
    id: "probe-backup-file",
    category: "probe",
    description: "Probe for a backup or archive file",
    paranoia: 2,
    score: WARNING,
    locations: ["path"],
    pattern: /\.(?:bak|old|orig|save|swp|sql|tar|tgz|gz|zip|7z|rar|log|ini|conf)(?:$|[?#])/i,
  },
  {
    id: "header-missing-ua",
    category: "protocol",
    description: "No User-Agent header",
    paranoia: 3,
    score: NOTICE,
    locations: ["path"],
    test: (_v, _p, input) => !headerValue(input.headers, "user-agent"),
  },
];

/* ------------------------------------------------------------------ */
/* Normalisation                                                       */
/* ------------------------------------------------------------------ */

function decodePercent(s: string): string {
  if (!s.includes("%")) return s;
  try {
    return decodeURIComponent(s);
  } catch {
    return s.replace(/%([0-9a-f]{2})/gi, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
  }
}

const NAMED_ENTITIES: Record<string, string> = {
  lt: "<", gt: ">", quot: '"', apos: "'", amp: "&", colon: ":", lpar: "(", rpar: ")", sol: "/",
  bsol: "\\", tab: "\t", newline: "\n", semi: ";", equals: "=", grave: "`", num: "#", lsqb: "[", rsqb: "]",
};

function decodeEntities(s: string): string {
  if (!s.includes("&")) return s;
  return s.replace(/&(?:#x([0-9a-f]{1,6})|#(\d{1,7})|([a-z]{2,8}));?/gi, (m, hex: string, dec: string, name: string) => {
    const code = hex ? parseInt(hex, 16) : dec ? parseInt(dec, 10) : -1;
    if (code >= 0) return code <= 0x10ffff ? String.fromCodePoint(code) : m;
    return NAMED_ENTITIES[name.toLowerCase()] ?? m;
  });
}

function decodeEscapes(s: string): string {
  if (!s.includes("\\")) return s;
  return s
    .replace(/\\u\{?([0-9a-f]{4,6})\}?/gi, (_m, h: string) => String.fromCodePoint(Math.min(parseInt(h, 16), 0x10ffff)))
    .replace(/\\x([0-9a-f]{2})/gi, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
}

/** The forms of a value worth matching: as sent, URL-decoded (twice), entity-decoded and escape-decoded. */
export function variants(value: string): string[] {
  const out = new Set<string>([value]);
  let d = value;
  for (let i = 0; i < 2; i++) {
    const next = decodePercent(d.replace(/\+/g, " "));
    if (next === d) break;
    d = next;
    out.add(d);
  }
  for (const v of [...out]) {
    const e = decodeEscapes(decodeEntities(v));
    if (e !== v) out.add(e);
  }
  return [...out];
}

/** SQL comments become spaces, so UNION, an empty comment, then SELECT reads as "UNION SELECT". */
function sqlNormal(v: string): string {
  return v.replace(/\/\*![0-9]{0,6}|\/\*[\s\S]{0,200}?\*\//g, " ");
}

/* ------------------------------------------------------------------ */
/* Collecting the parts of a request                                   */
/* ------------------------------------------------------------------ */

const SKIP_HEADERS = new Set([
  "authorization", "proxy-authorization", "cookie", "content-length", "connection", "keep-alive",
  "accept", "accept-encoding", "accept-language", "if-none-match", "if-modified-since", "cache-control",
  "pragma", "upgrade-insecure-requests", "dnt", "priority", "te",
]);

function headerValue(headers: InspectionInput["headers"], name: string): string {
  if (!headers) return "";
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === name) return Array.isArray(v) ? v.join(", ") : v ?? "";
  }
  return "";
}

/** Parse a body string by content type: JSON, form-encoded, or left as text. */
export function parseBody(text: string, contentType = ""): unknown {
  const ct = contentType.toLowerCase();
  const t = text.trim();
  if (ct.includes("json") || ((t.startsWith("{") || t.startsWith("[")) && !ct.includes("form"))) {
    try {
      return JSON.parse(t);
    } catch {
      return text;
    }
  }
  if (ct.includes("application/x-www-form-urlencoded")) {
    const obj: Record<string, string> = {};
    try {
      for (const [k, v] of new URLSearchParams(text)) obj[k] = obj[k] === undefined ? v : `${obj[k]}\n${v}`;
      return obj;
    } catch {
      return text;
    }
  }
  return text;
}

class Collector {
  parts: Part[] = [];
  chars = 0;
  max: number;
  constructor(max: number) {
    this.max = max;
  }
  get full() {
    return this.parts.length >= this.max || this.chars >= MAX_TOTAL_CHARS;
  }
  add(location: Location, name: string, value: unknown, isKey = false) {
    if (this.full || value === null || value === undefined) return;
    if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") return;
    const s = String(value).slice(0, MAX_VALUE);
    if (!s) return;
    this.chars += s.length;
    this.parts.push({ location, name: name.slice(0, 200), value: s, isKey });
  }
  walk(location: Location, name: string, value: unknown, depth: number) {
    if (this.full) return;
    if (Array.isArray(value)) {
      if (depth >= MAX_DEPTH) return;
      value.forEach((v, i) => this.walk(location, `${name}[${i}]`, v, depth + 1));
      return;
    }
    if (value && typeof value === "object") {
      if (depth >= MAX_DEPTH) return;
      for (const key of Object.keys(value as object)) {
        const child = name ? `${name}.${key}` : key;
        this.add(location, child, child, true);
        this.walk(location, child, (value as Record<string, unknown>)[key], depth + 1);
      }
      return;
    }
    this.add(location, name || "(body)", value);
  }
}

export function collectParts(input: InspectionInput, maxParts = 500): Part[] {
  const c = new Collector(maxParts);
  const full = input.path || "/";
  const q = full.indexOf("?");
  const path = q >= 0 ? full.slice(0, q) : full;
  const query = q >= 0 ? full.slice(q + 1) : "";
  c.add("path", "(path)", path);
  if (query) {
    let parsed = 0;
    try {
      for (const [k, v] of new URLSearchParams(query)) {
        c.add("query", k, k, true);
        c.add("query", k, v);
        parsed++;
      }
    } catch {
      parsed = 0;
    }
    // Only inspect the raw query as a whole when it did not parse into parameters,
    // so a value is never counted twice (once in its parameter, once in the aggregate).
    if (parsed === 0) c.add("query", "(query)", query);
  }
  for (const [k, raw] of Object.entries(input.headers || {})) {
    const name = k.toLowerCase();
    if (SKIP_HEADERS.has(name)) continue;
    c.add("header", name, Array.isArray(raw) ? raw.join(", ") : raw);
  }
  const cookie = headerValue(input.headers, "cookie");
  if (cookie) {
    for (const pair of cookie.split(";")) {
      const eq = pair.indexOf("=");
      if (eq <= 0) continue;
      const k = pair.slice(0, eq).trim();
      c.add("cookie", k, k, true);
      c.add("cookie", k, decodePercent(pair.slice(eq + 1).trim()));
    }
  }
  if (input.body !== undefined && input.body !== null && input.body !== "") {
    const body = typeof input.body === "string" ? parseBody(input.body, input.contentType) : input.body;
    c.walk("body", "", body, 0);
  }
  return c.parts;
}

/* ------------------------------------------------------------------ */
/* Inspection                                                          */
/* ------------------------------------------------------------------ */

const SENSITIVE_NAME = /pass(word|wd)?|secret|token|api[-_]?key|auth|session|card|cvv|pin\b/i;

function redact(part: Part, matched: string): string {
  if (!part.isKey && SENSITIVE_NAME.test(part.name)) return "[redacted]";
  return matched.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, SAMPLE_LEN);
}

function ruleSelected(rule: InspectionRule, list: string[] | undefined): boolean {
  return !!list && (list.includes(rule.id) || list.includes(rule.category));
}

function nameMatches(names: string[] | undefined, name: string): boolean {
  if (!names || !names.length) return true;
  return names.some((n) => (n.endsWith("*") ? name.startsWith(n.slice(0, -1)) : n === name));
}

function excluded(exclusions: CompiledExclusion[], rule: InspectionRule, part: Part, path: string): boolean {
  for (const ex of exclusions) {
    if (ex.path && !ex.path.test(path)) continue;
    if (ex.locations && !ex.locations.includes(part.location)) continue;
    if (!nameMatches(ex.names, part.name)) continue;
    if (ex.rules && !ruleSelected(rule, ex.rules)) continue;
    return true;
  }
  return false;
}

interface CompiledExclusion {
  path: LinearRegex | null;
  locations?: Location[];
  names?: string[];
  rules?: string[];
}

const compiledCache = new WeakMap<InspectionExclusion[], CompiledExclusion[]>();

/** Compile exclusions once. An exclusion whose path pattern is invalid is ignored. */
export function compileExclusions(list: InspectionExclusion[] | undefined): CompiledExclusion[] {
  if (!list || !list.length) return [];
  const cached = compiledCache.get(list);
  if (cached) return cached;
  const out: CompiledExclusion[] = [];
  for (const ex of list) {
    let path: LinearRegex | null = null;
    if (ex.path) {
      // Linear-time matcher, like rule patterns; an unusable pattern drops the exclusion.
      try {
        path = compileLinear(ex.path);
      } catch {
        continue;
      }
    }
    out.push({ path, locations: ex.locations, names: ex.names, rules: ex.rules });
  }
  compiledCache.set(list, out);
  return out;
}

/** Inspect a request. Pure and synchronous; never throws. */
export function inspect(input: InspectionInput, config: InspectionConfig = {}): InspectionResult {
  const mode = config.mode ?? "block";
  const paranoia = (config.paranoia ?? 1) as Paranoia;
  const threshold = config.threshold ?? CRITICAL;
  const result: InspectionResult = { score: 0, threshold, mode, paranoia, matched: false, findings: [], inspected: 0 };
  if (mode === "off") return result;
  try {
    const parts = collectParts(input, config.maxParts ?? 500);
    result.inspected = parts.length;
    const exclusions = compileExclusions(config.exclusions);
    const path = (input.path || "/").split("?")[0];
    const rules = INSPECTION_RULES.filter((r) => r.paranoia <= paranoia && !ruleSelected(r, config.disabledRules));
    const seen = new Set<string>();
    // In block mode, stop once the request is certainly blocked and the IP-block score is
    // reached: the rest of the work can't change the outcome.
    const stopAt = mode === "block" ? Math.max(threshold, config.autoBlockScore || 0) : Infinity;

    // Request-level rules (method, missing User-Agent) are limited to the path part, so they run once.
    for (const part of parts) {
      const forms = variants(part.value);
      let sqlForms: string[] | null = null;
      for (const rule of rules) {
        if (rule.locations && !rule.locations.includes(part.location)) continue;
        if (!!rule.keys !== !!part.isKey) continue;
        const key = `${rule.id}|${part.location}|${part.name}`;
        if (seen.has(key)) continue;
        let hit: string | null = null;
        if (rule.test) {
          if (rule.test(part.value, part, input)) hit = part.value;
        } else if (rule.pattern) {
          const candidates = rule.sql ? (sqlForms ??= forms.map(sqlNormal)) : forms;
          for (const f of candidates) {
            const m = rule.pattern.exec(f);
            if (m) {
              hit = m[0];
              break;
            }
          }
        }
        if (hit === null) continue;
        if (excluded(exclusions, rule, part, path)) continue;
        seen.add(key);
        result.score += rule.score;
        result.findings.push({
          rule: rule.id,
          category: rule.category,
          description: rule.description,
          score: rule.score,
          location: part.location,
          name: part.name,
          sample: redact(part, hit),
        });
        if (result.score >= stopAt) break;
      }
      if (result.score >= stopAt) break;
    }
    result.findings.sort((a, b) => b.score - a.score);
    result.matched = result.score >= threshold;
  } catch {
    // Inspection never breaks a request.
  }
  return result;
}

/** One line for logs and traces: "SQL injection: UNION SELECT in query.q". */
export function describeFinding(f: Finding): string {
  const where = f.location === "path" ? "the path" : f.name.startsWith("(") ? `the ${f.location}` : `${f.location}.${f.name}`;
  return `${f.description} in ${where}`;
}
