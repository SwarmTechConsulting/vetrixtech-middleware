// Linear-time regular expressions for user-authored patterns.
//
// JavaScript's RegExp backtracks, so a pattern such as (a+)+$ can take
// exponential time on a short input, and a rule pattern runs on every screened
// request. This module compiles the common subset of JavaScript regex syntax to
// a state machine and runs it as a Pike VM: every input character is visited
// once per program state, so matching takes O(text × pattern) time whatever the
// pattern looks like.
//
// Supported: literals and escapes, ., [classes] with ranges and negation,
// \d \w \s \D \W \S \b \B, ^ $, groups ( ) (?: ) (?<name> ), alternation |,
// and the quantifiers * + ? {n} {n,} {n,m}, greedy or lazy. Matching is
// case-insensitive by default, as rules always have been.
// Not supported (rejected with a message): back-references (\1, \k<name>) and
// lookaround (?= (?! (?<= (?<!, which no linear-time engine can run.
//
// Only test() is offered: rules ask "does it match", never "what matched".
// The same file is shipped in SwarmTech Shield (base44/shared/linearRegex.ts)
// and in @swarmtechshield/middleware (src/linearRegex.ts); keep them identical.

export const MAX_PATTERN_LENGTH = 1000;
export const MAX_PROGRAM_SIZE = 5000;

export class LinearRegexError extends Error {}

type Range = [number, number];
interface CharSet { ranges: Range[]; neg: boolean }

type Node =
  | { t: "set"; set: CharSet }
  | { t: "empty" }
  | { t: "cat"; items: Node[] }
  | { t: "alt"; items: Node[] }
  | { t: "rep"; node: Node; min: number; max: number }
  | { t: "assert"; kind: Assertion };

type Assertion = "bol" | "eol" | "wb" | "nwb";

const DIGIT: Range[] = [[48, 57]];
const WORD: Range[] = [[48, 57], [65, 90], [95, 95], [97, 122]];
const SPACE: Range[] = [
  [9, 13], [32, 32], [160, 160], [5760, 5760], [8192, 8202], [8232, 8233],
  [8239, 8239], [8287, 8287], [12288, 12288], [65279, 65279],
];
const LINE_TERMINATORS: Range[] = [[10, 10], [13, 13], [8232, 8233]];

function normalise(ranges: Range[]): Range[] {
  const sorted = ranges.map((r) => [r[0], r[1]] as Range).sort((a, b) => a[0] - b[0]);
  const out: Range[] = [];
  for (const r of sorted) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else out.push(r);
  }
  return out;
}

function complement(ranges: Range[]): Range[] {
  const out: Range[] = [];
  let next = 0;
  for (const [lo, hi] of normalise(ranges)) {
    if (lo > next) out.push([next, lo - 1]);
    next = hi + 1;
  }
  if (next <= 0xffff) out.push([next, 0xffff]);
  return out;
}

function inRanges(ranges: Range[], c: number): boolean {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (c < ranges[mid][0]) hi = mid - 1;
    else if (c > ranges[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

function foldVariants(c: number): number[] {
  const s = String.fromCharCode(c);
  const out = [c];
  for (const v of [s.toLowerCase(), s.toUpperCase()]) {
    if (v.length === 1) {
      const code = v.charCodeAt(0);
      // As in JavaScript: a non-ASCII character never folds onto an ASCII one (ſ is not s).
      if (code !== c && !(c >= 128 && code < 128)) out.push(code);
    }
  }
  return out;
}

function setMatches(set: CharSet, c: number, ignoreCase: boolean): boolean {
  let hit = inRanges(set.ranges, c);
  if (!hit && ignoreCase) {
    if (c < 128) {
      // ASCII: the other case without building strings (the common path).
      if (c >= 65 && c <= 90) hit = inRanges(set.ranges, c + 32);
      else if (c >= 97 && c <= 122) hit = inRanges(set.ranges, c - 32);
    } else {
      for (const v of foldVariants(c)) if (v !== c && inRanges(set.ranges, v)) { hit = true; break; }
    }
  }
  return set.neg ? !hit : hit;
}

function isWordChar(c: number): boolean {
  return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || c === 95 || (c >= 97 && c <= 122);
}

/* ---------------- parser ---------------- */

class Parser {
  i = 0;
  src: string;
  constructor(src: string) {
    this.src = src;
  }

  fail(msg: string): never {
    throw new LinearRegexError(msg);
  }

  peek(): string {
    return this.src[this.i];
  }

  parse(): Node {
    const node = this.alt();
    if (this.i < this.src.length) this.fail("unmatched ')'");
    return node;
  }

  alt(): Node {
    const items = [this.seq()];
    while (this.peek() === "|") {
      this.i++;
      items.push(this.seq());
    }
    return items.length === 1 ? items[0] : { t: "alt", items };
  }

  seq(): Node {
    const items: Node[] = [];
    while (this.i < this.src.length && this.peek() !== "|" && this.peek() !== ")") {
      const atom = this.atom();
      items.push(this.quantified(atom));
    }
    if (items.length === 0) return { t: "empty" };
    return items.length === 1 ? items[0] : { t: "cat", items };
  }

  // A quantifier after an atom: * + ? {n} {n,} {n,m}, each optionally lazy.
  quantified(atom: Node): Node {
    let min = -1;
    let max = -1;
    const ch = this.peek();
    if (ch === "*") { min = 0; max = Infinity; this.i++; }
    else if (ch === "+") { min = 1; max = Infinity; this.i++; }
    else if (ch === "?") { min = 0; max = 1; this.i++; }
    else if (ch === "{") {
      const m = /^\{(\d+)(,(\d*))?\}/.exec(this.src.slice(this.i));
      if (!m) return atom; // a lone "{" is a literal, as in JavaScript
      min = Number(m[1]);
      max = m[2] === undefined ? min : m[3] === "" ? Infinity : Number(m[3]);
      if (max < min) this.fail("numbers out of order in {} quantifier");
      this.i += m[0].length;
    } else {
      return atom;
    }
    if (atom.t === "assert") this.fail("nothing to repeat");
    if (this.peek() === "?") this.i++; // lazy: same answer for test()
    const next = this.peek();
    if (next === "*" || next === "+" || next === "?") this.fail("nothing to repeat");
    if (next === "{" && /^\{\d+(,\d*)?\}/.test(this.src.slice(this.i))) this.fail("nothing to repeat");
    return { t: "rep", node: atom, min, max };
  }

  atom(): Node {
    const ch = this.src[this.i++];
    switch (ch) {
      case "(": {
        if (this.peek() === "?") {
          const rest = this.src.slice(this.i + 1);
          if (rest.startsWith(":")) {
            this.i += 2;
          } else if (/^<[A-Za-z_$][\w$]*>/.test(rest)) {
            this.i += 1 + rest.indexOf(">") + 1;
          } else if (/^(=|!|<=|<!)/.test(rest)) {
            this.fail("lookahead and lookbehind ((?= (?! (?<= (?<!) aren't supported in rules");
          } else {
            this.fail("invalid group");
          }
        }
        const inner = this.alt();
        if (this.src[this.i] !== ")") this.fail("missing ')'");
        this.i++;
        return inner;
      }
      case ")":
        return this.fail("unmatched ')'");
      case "[":
        return { t: "set", set: this.cls() };
      case ".":
        return { t: "set", set: { ranges: LINE_TERMINATORS, neg: true } };
      case "^":
        return { t: "assert", kind: "bol" };
      case "$":
        return { t: "assert", kind: "eol" };
      case "*":
      case "+":
      case "?":
        return this.fail("nothing to repeat");
      case "{":
        if (/^\d+(,\d*)?\}/.test(this.src.slice(this.i))) this.fail("nothing to repeat");
        return lit(123);
      case "\\":
        return this.escape();
      default:
        return lit(ch.charCodeAt(0));
    }
  }

  escape(): Node {
    if (this.i >= this.src.length) this.fail("\\ at end of pattern");
    const ch = this.src[this.i++];
    switch (ch) {
      case "b": return { t: "assert", kind: "wb" };
      case "B": return { t: "assert", kind: "nwb" };
      case "k":
        if (this.peek() === "<") this.fail("back-references aren't supported in rules");
        return lit(107);
    }
    if (ch >= "1" && ch <= "9") this.fail("back-references (\\1 and so on) aren't supported in rules");
    return { t: "set", set: this.escapeSet(ch, false) };
  }

  // The set for an escape. `inClass` changes \b (backspace inside a class).
  escapeSet(ch: string, inClass: boolean): CharSet {
    switch (ch) {
      case "d": return { ranges: DIGIT, neg: false };
      case "D": return { ranges: DIGIT, neg: true };
      case "w": return { ranges: WORD, neg: false };
      case "W": return { ranges: WORD, neg: true };
      case "s": return { ranges: SPACE, neg: false };
      case "S": return { ranges: SPACE, neg: true };
      case "n": return one(10);
      case "r": return one(13);
      case "t": return one(9);
      case "f": return one(12);
      case "v": return one(11);
      case "0":
        if (/[0-9]/.test(this.peek() || "")) this.fail("octal escapes aren't supported in rules");
        return one(0);
      case "x": {
        const m = /^[0-9a-fA-F]{2}/.exec(this.src.slice(this.i));
        if (!m) return one(120);
        this.i += 2;
        return one(parseInt(m[0], 16));
      }
      case "u": {
        const m = /^[0-9a-fA-F]{4}/.exec(this.src.slice(this.i));
        if (!m) return one(117);
        this.i += 4;
        return one(parseInt(m[0], 16));
      }
      case "c": {
        const next = this.peek();
        if (next && /[A-Za-z]/.test(next)) {
          this.i++;
          return one(next.charCodeAt(0) % 32);
        }
        return this.fail("invalid \\c escape");
      }
      case "b":
        if (inClass) return one(8);
        return one(98);
      default:
        if (ch >= "1" && ch <= "9" && inClass) this.fail("octal escapes aren't supported in rules");
        return one(ch.charCodeAt(0));
    }
  }

  cls(): CharSet {
    let neg = false;
    if (this.peek() === "^") { neg = true; this.i++; }
    const ranges: Range[] = [];
    for (;;) {
      if (this.i >= this.src.length) this.fail("missing ']'");
      if (this.peek() === "]") { this.i++; break; }
      const a = this.classAtom();
      if (this.peek() === "-" && this.src[this.i + 1] !== "]" && this.i + 1 < this.src.length) {
        this.i++;
        const b = this.classAtom();
        if (a.single === null || b.single === null) {
          // A class escape at either end makes "-" a literal (JavaScript's rule).
          ranges.push(...a.ranges, [45, 45], ...b.ranges);
        } else {
          if (a.single > b.single) this.fail("range out of order in character class");
          ranges.push([a.single, b.single]);
        }
      } else {
        ranges.push(...a.ranges);
      }
    }
    return { ranges: normalise(ranges), neg };
  }

  // One class member: a character (single) or a class escape (ranges only).
  classAtom(): { single: number | null; ranges: Range[] } {
    const ch = this.src[this.i++];
    if (ch !== "\\") return { single: ch.charCodeAt(0), ranges: [[ch.charCodeAt(0), ch.charCodeAt(0)]] };
    if (this.i >= this.src.length) this.fail("\\ at end of pattern");
    const e = this.src[this.i++];
    const set = this.escapeSet(e, true);
    const ranges = set.neg ? complement(set.ranges) : set.ranges;
    const single = !set.neg && ranges.length === 1 && ranges[0][0] === ranges[0][1] && !"dDwWsS".includes(e) ? ranges[0][0] : null;
    return { single, ranges };
  }
}

function one(...codes: number[]): CharSet {
  return { ranges: normalise(codes.map((c) => [c, c] as Range)), neg: false };
}

function lit(code: number): Node {
  return { t: "set", set: one(code) };
}

/* ---------------- compiler ---------------- */

const Op = { Set: 0, Split: 1, Jmp: 2, Assert: 3, Match: 4 } as const;
interface Instr { op: number; set?: CharSet; x?: number; y?: number; kind?: Assertion }

function compileProgram(node: Node): Instr[] {
  const prog: Instr[] = [];
  const push = (ins: Instr) => {
    if (prog.length >= MAX_PROGRAM_SIZE) {
      throw new LinearRegexError("pattern is too large once repeats are expanded; use smaller {n,m} counts");
    }
    prog.push(ins);
    return prog.length - 1;
  };
  const emit = (n: Node): void => {
    switch (n.t) {
      case "empty":
        return;
      case "set":
        push({ op: Op.Set, set: n.set });
        return;
      case "assert":
        push({ op: Op.Assert, kind: n.kind });
        return;
      case "cat":
        for (const item of n.items) emit(item);
        return;
      case "alt": {
        const jumps: number[] = [];
        n.items.forEach((item, idx) => {
          if (idx < n.items.length - 1) {
            const split = push({ op: Op.Split });
            prog[split].x = prog.length;
            emit(item);
            jumps.push(push({ op: Op.Jmp }));
            prog[split].y = prog.length;
          } else {
            emit(item);
          }
        });
        for (const j of jumps) prog[j].x = prog.length;
        return;
      }
      case "rep": {
        for (let k = 0; k < n.min; k++) emit(n.node);
        if (n.max === Infinity) {
          const split = push({ op: Op.Split });
          prog[split].x = prog.length;
          emit(n.node);
          push({ op: Op.Jmp, x: split });
          prog[split].y = prog.length;
        } else {
          const splits: number[] = [];
          for (let k = n.min; k < n.max; k++) {
            const split = push({ op: Op.Split });
            prog[split].x = prog.length;
            splits.push(split);
            emit(n.node);
          }
          for (const s of splits) prog[s].y = prog.length;
        }
        return;
      }
    }
  };
  emit(node);
  push({ op: Op.Match });
  return prog;
}

/* ---------------- matcher ---------------- */

export interface LinearRegex {
  readonly source: string;
  test(text: string): boolean;
}

// A pattern with no regex features at all is matched as a plain substring.
function literalOf(node: Node): string | null {
  const items = node.t === "cat" ? node.items : [node];
  let out = "";
  for (const item of items) {
    if (item.t !== "set" || item.set.neg || item.set.ranges.length !== 1) return null;
    const [lo, hi] = item.set.ranges[0];
    if (lo !== hi) return null;
    out += String.fromCharCode(lo);
  }
  return out;
}

/** Compile a pattern, or throw LinearRegexError saying what isn't allowed. */
export function compileLinear(source: string, ignoreCase = true): LinearRegex {
  if (typeof source !== "string") throw new LinearRegexError("pattern must be text");
  if (source.length > MAX_PATTERN_LENGTH) throw new LinearRegexError(`pattern is longer than ${MAX_PATTERN_LENGTH} characters`);
  const ast = new Parser(source).parse();

  const literal = literalOf(ast);
  if (literal !== null && literal.length > 0) {
    const needle = ignoreCase ? literal.toLowerCase() : literal;
    return {
      source,
      test: (text: string) => (ignoreCase ? String(text).toLowerCase() : String(text)).includes(needle),
    };
  }

  const prog = compileProgram(ast);
  const size = prog.length;
  return {
    source,
    test(input: string): boolean {
      const text = String(input);
      const len = text.length;
      const mark = new Int32Array(size).fill(-1);
      let clist = new Int32Array(size);
      let nlist = new Int32Array(size);
      let ccount = 0;
      let ncount = 0;
      const stack: number[] = [];
      let gen = 0;

      const holds = (kind: Assertion, pos: number) => {
        switch (kind) {
          case "bol": return pos === 0;
          case "eol": return pos === len;
          default: {
            const before = pos > 0 && isWordChar(text.charCodeAt(pos - 1));
            const after = pos < len && isWordChar(text.charCodeAt(pos));
            return kind === "wb" ? before !== after : before === after;
          }
        }
      };

      // Follow empty moves from pc at pos; true when a match is reached.
      const add = (list: Int32Array, count: number, pc0: number, pos: number): number => {
        stack.push(pc0);
        while (stack.length) {
          const pc = stack.pop()!;
          if (mark[pc] === gen) continue;
          mark[pc] = gen;
          const ins = prog[pc];
          switch (ins.op) {
            case Op.Jmp: stack.push(ins.x!); break;
            case Op.Split: stack.push(ins.y!, ins.x!); break;
            case Op.Assert: if (holds(ins.kind!, pos)) stack.push(pc + 1); break;
            case Op.Match: stack.length = 0; return -1;
            case Op.Set: list[count++] = pc; break;
          }
        }
        return count;
      };

      ccount = add(clist, 0, 0, 0);
      if (ccount < 0) return true;
      for (let i = 0; i < len; i++) {
        const c = text.charCodeAt(i);
        gen++;
        ncount = 0;
        for (let k = 0; k < ccount; k++) {
          const pc = clist[k];
          if (setMatches(prog[pc].set!, c, ignoreCase)) {
            ncount = add(nlist, ncount, pc + 1, i + 1);
            if (ncount < 0) return true;
          }
        }
        // A match may also start at the next position.
        ncount = add(nlist, ncount, 0, i + 1);
        if (ncount < 0) return true;
        const t = clist; clist = nlist; nlist = t;
        ccount = ncount;
      }
      return false;
    },
  };
}

/** Why a pattern can't be used in a rule, or null when it can. */
export function linearRegexProblem(source: string): string | null {
  try {
    compileLinear(source);
    return null;
  } catch (e) {
    return e instanceof LinearRegexError ? e.message : "pattern is not a valid regular expression";
  }
}

const cache = new Map<string, LinearRegex | null>();

/** Cached compile: the matcher, or null if the pattern isn't usable. */
export function cachedLinear(source: string): LinearRegex | null {
  if (cache.has(source)) return cache.get(source)!;
  let re: LinearRegex | null = null;
  try {
    re = compileLinear(source);
  } catch {
    re = null;
  }
  if (cache.size >= 1000) cache.delete(cache.keys().next().value as string);
  cache.set(source, re);
  return re;
}
