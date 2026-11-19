/**
 * Static scanner for raw SQL that touches encrypted columns.
 *
 * Raw queries ($queryRaw, $queryRawUnsafe, $executeRaw, $executeRawUnsafe) bypass the Prisma extension: a SELECT
 * returns ciphertext and an INSERT/UPDATE stores plaintext, both silently. This finds them in the source, using the
 * real database names from the schema (`@map`/`@@map`), and says so when it cannot tell (SQL built at runtime).
 *
 * Findings:
 *   error   the SQL mentions an encrypted column (or selects every column / inserts without a column list) of an encrypted table
 *   dynamic the SQL is assembled at runtime from something other than literals, so it cannot be analyzed
 *   info    direct driver use (`pg`) that is not analyzed at all
 *
 * Silence a reviewed call with a comment on the line before it: `// cryplus-ignore-next-line: <reason>`,
 * or put `/* cryplus:handled *\/` inside the SQL text. `// cryplus-ignore-file` at the top skips a whole file.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import * as path from "node:path";
import { analyzeSql } from "./sqlscan.ts";
import type { Schema } from "./schema.ts";

export interface ScanFinding {
  file: string;
  line: number;
  column: number;
  severity: "error" | "dynamic" | "info";
  call: string;
  message: string;
}

// ---- lexer -------------------------------------------------------------------

type Tok =
  | { t: "id"; v: string; i: number }
  | { t: "str"; v: string; i: number }
  | { t: "tpl"; quasis: string[]; exprs: string[]; i: number }
  | { t: "p"; v: string; i: number }
  | { t: "num"; v: string; i: number };

const ID_START = /[A-Za-z_$]/;
const ID_PART = /[\w$]/;

function lex(src: string): { toks: Tok[]; ignoreLines: Set<number>; ignoreFile: boolean } {
  const toks: Tok[] = [];
  const ignoreLines = new Set<number>();
  let ignoreFile = false;
  let i = 0;
  const n = src.length;
  const lineOf = (pos: number) => {
    let l = 1;
    for (let k = 0; k < pos; k++) if (src.charCodeAt(k) === 10) l++;
    return l;
  };

  // lines of the source, to attach "ignore-next-line" comments to the following line
  const noteComment = (text: string, at: number) => {
    if (/cryplus-ignore-file/.test(text)) ignoreFile = true;
    if (/cryplus-ignore-next-line/.test(text)) ignoreLines.add(lineOf(at) + 1);
  };

  function readTemplate(start: number): { tok: Tok; end: number } {
    // src[start] === "`"
    const quasis: string[] = [];
    const exprs: string[] = [];
    let cur = "";
    let k = start + 1;
    while (k < n) {
      const c = src[k]!;
      if (c === "\\") {
        cur += src.slice(k, k + 2);
        k += 2;
      } else if (c === "`") {
        quasis.push(cur);
        return { tok: { t: "tpl", quasis, exprs, i: start }, end: k + 1 };
      } else if (c === "$" && src[k + 1] === "{") {
        quasis.push(cur);
        cur = "";
        let depth = 1;
        let e = k + 2;
        const exprStart = e;
        while (e < n && depth > 0) {
          const d = src[e]!;
          if (d === "`") e = readTemplate(e).end;
          else if (d === '"' || d === "'") e = skipString(e);
          else {
            if (d === "{") depth++;
            else if (d === "}") depth--;
            e++;
          }
        }
        exprs.push(src.slice(exprStart, e - 1).trim());
        k = e;
      } else {
        cur += c;
        k++;
      }
    }
    quasis.push(cur);
    return { tok: { t: "tpl", quasis, exprs, i: start }, end: n };
  }

  function skipString(start: number): number {
    const q = src[start]!;
    let k = start + 1;
    while (k < n && src[k] !== q) k += src[k] === "\\" ? 2 : 1;
    return k + 1;
  }

  while (i < n) {
    const c = src[i]!;
    if (c === "/" && src[i + 1] === "/") {
      const e = src.indexOf("\n", i);
      const end = e < 0 ? n : e;
      noteComment(src.slice(i, end), i);
      i = end;
    } else if (c === "/" && src[i + 1] === "*") {
      const e = src.indexOf("*/", i + 2);
      const end = e < 0 ? n : e + 2;
      noteComment(src.slice(i, end), i);
      i = end;
    } else if (c === '"' || c === "'") {
      const end = skipString(i);
      toks.push({ t: "str", v: src.slice(i + 1, end - 1).replace(/\\(.)/g, "$1"), i });
      i = end;
    } else if (c === "`") {
      const r = readTemplate(i);
      toks.push(r.tok);
      i = r.end;
    } else if (ID_START.test(c)) {
      let e = i + 1;
      while (e < n && ID_PART.test(src[e]!)) e++;
      toks.push({ t: "id", v: src.slice(i, e), i });
      i = e;
    } else if (/\d/.test(c)) {
      let e = i + 1;
      while (e < n && /[\w.]/.test(src[e]!)) e++;
      toks.push({ t: "num", v: src.slice(i, e), i });
      i = e;
    } else if (/\s/.test(c)) {
      i++;
    } else {
      toks.push({ t: "p", v: c, i });
      i++;
    }
  }
  return { toks, ignoreLines, ignoreFile };
}

// ---- analysis ----------------------------------------------------------------

const RAW_NAMES = new Set(["$queryRaw", "$queryRawUnsafe", "$executeRaw", "$executeRawUnsafe"]);

interface Operand {
  /** Literal SQL text when known. */
  text?: string;
  /** Why it is not fully literal. */
  dynamic?: string;
}

const tplStatic = (t: Extract<Tok, { t: "tpl" }>, tagged: boolean): Operand => {
  const parts: string[] = [];
  let dyn: string | undefined;
  t.quasis.forEach((q, idx) => {
    parts.push(q);
    if (idx < t.exprs.length) {
      const e = t.exprs[idx]!;
      if (/^Prisma\.(raw|sql|join)\b|^sql\b/.test(e)) {
        parts.push(" ");
        dyn ??= `\${${e.length > 40 ? e.slice(0, 40) + "…" : e}} injects SQL text`;
      } else if (tagged) {
        parts.push("$" + (idx + 1)); // a bound parameter: safe
      } else {
        parts.push(" ");
        dyn ??= `\${${e.length > 40 ? e.slice(0, 40) + "…" : e}} is interpolated into SQL text`;
      }
    }
  });
  return { text: parts.join(""), dynamic: dyn };
};

/** Resolve `const NAME = <literal>` declared in the same file. */
function constantsOf(toks: Tok[]): Map<string, Operand> {
  const out = new Map<string, Operand>();
  for (let k = 0; k + 3 < toks.length; k++) {
    const a = toks[k]!, b = toks[k + 1]!, c = toks[k + 2]!;
    if (a.t === "id" && (a.v === "const" || a.v === "let" || a.v === "var") && b.t === "id" && c.t === "p" && c.v === "=") {
      // only simple `NAME = literal ;` (or a `+` chain of literals)
      let m = k + 3;
      let text = "";
      let ok = false;
      let dyn: string | undefined;
      for (;;) {
        const x = toks[m];
        if (x?.t === "str") text += x.v;
        else if (x?.t === "tpl") {
          const s = tplStatic(x, false);
          text += s.text ?? "";
          dyn ??= s.dynamic;
        } else if (x?.t === "id" && out.has(x.v) && !(toks[m + 1]?.t === "p" && ["(", ".", "["].includes((toks[m + 1] as any).v))) {
          // a constant built from an earlier constant
          const prev = out.get(x.v)!;
          text += prev.text ?? "";
          dyn ??= prev.dynamic;
        } else break;
        ok = true;
        const nx = toks[m + 1];
        if (nx?.t === "p" && nx.v === "+") m += 2;
        else {
          m += 1;
          break;
        }
      }
      const end = toks[m];
      if (ok && (!end || (end.t === "p" && (end.v === ";" || end.v === ",")) || end.t === "id")) out.set(b.v, { text, dynamic: dyn });
    }
  }
  return out;
}

/** Parse the first call argument starting at toks[k] (just after "("). */
function firstArg(toks: Tok[], k: number, consts: Map<string, Operand>): Operand {
  let text = "";
  let dyn: string | undefined;
  let sawAny = false;
  let m = k;
  for (;;) {
    const x = toks[m];
    if (!x) return { dynamic: "unterminated call" };
    let piece: Operand | undefined;
    if (x.t === "str") piece = { text: x.v };
    else if (x.t === "tpl") piece = tplStatic(x, false);
    else if (x.t === "id" && x.v === "Prisma" && (toks[m + 1] as any)?.v === "." && (toks[m + 2] as any)?.v === "sql" && toks[m + 3]?.t === "tpl") {
      piece = tplStatic(toks[m + 3] as Extract<Tok, { t: "tpl" }>, true);
      m += 3;
    } else if (x.t === "id" && x.v === "sql" && toks[m + 1]?.t === "tpl") {
      piece = tplStatic(toks[m + 1] as Extract<Tok, { t: "tpl" }>, true);
      m += 1;
    } else if (x.t === "id" && consts.has(x.v) && !(toks[m + 1]?.t === "p" && ["(", ".", "["].includes((toks[m + 1] as any).v))) {
      piece = consts.get(x.v)!;
    } else if (x.t === "id") {
      // variable, call or member expression: consume the rest of this operand
      let depth = 0;
      let e = m;
      while (toks[e]) {
        const y = toks[e]!;
        if (y.t === "p" && "([{".includes(y.v)) depth++;
        else if (y.t === "p" && ")]}".includes(y.v)) {
          if (depth === 0) break;
          depth--;
        } else if (depth === 0 && y.t === "p" && (y.v === "," || y.v === "+")) break;
        e++;
      }
      const names = toks.slice(m, e).map((y) => ("v" in y ? y.v : "…")).join("").slice(0, 40);
      piece = { dynamic: `SQL comes from \`${names}\`` };
      m = e - 1;
    } else return { text: sawAny ? text : undefined, dynamic: dyn ?? "unsupported expression" };
    sawAny = true;
    text += piece.text ?? " ";
    dyn ??= piece.dynamic;
    const nx = toks[m + 1];
    if (nx?.t === "p" && nx.v === "+") {
      m += 2;
      continue;
    }
    break;
  }
  return { text, dynamic: dyn };
}

export function scanSource(schema: Schema, source: string, file: string): ScanFinding[] {
  const { toks, ignoreLines, ignoreFile } = lex(source);
  if (ignoreFile) return [];
  const consts = constantsOf(toks);
  const findings: ScanFinding[] = [];
  const pos = (offset: number) => {
    let line = 1, col = 1;
    for (let k = 0; k < offset; k++) {
      if (source.charCodeAt(k) === 10) {
        line++;
        col = 1;
      } else col++;
    }
    return { line, col };
  };
  const add = (offset: number, severity: ScanFinding["severity"], call: string, message: string) => {
    const { line, col } = pos(offset);
    if (ignoreLines.has(line)) return;
    findings.push({ file, line, column: col, severity, call, message });
  };

  for (let k = 0; k < toks.length; k++) {
    const t = toks[k]!;
    if (t.t !== "id" || !RAW_NAMES.has(t.v)) continue;
    const next = toks[k + 1];
    const tagged = next?.t === "tpl";
    let op: Operand;
    if (tagged) op = tplStatic(next as Extract<Tok, { t: "tpl" }>, !t.v.endsWith("Unsafe"));
    else if (next?.t === "p" && next.v === "(") op = firstArg(toks, k + 2, consts);
    else continue; // a bare mention (e.g. `const q = prisma.$queryRaw;` or a property name)
    // For the safe tagged forms interpolations are bound parameters; for Unsafe/call forms they are SQL text.
    if (op.text) {
      for (const f of analyzeSql(schema, op.text)) {
        add(t.i, "error", t.v, `${f.model} (${f.table}): ${f.reason}`);
      }
    }
    if (op.dynamic) {
      add(t.i, "dynamic", t.v, `cannot analyze: ${op.dynamic}. Review by hand, then add \`// cryplus-ignore-next-line: <reason>\``);
    }
  }
  if (/require\(\s*['"]pg['"]\s*\)|from\s+['"]pg['"]|require\(\s*['"]mysql2?['"]\s*\)/.test(source)) {
    const m = /require\(\s*['"]pg['"]|from\s+['"]pg['"]/.exec(source);
    add(m?.index ?? 0, "info", "pg", "direct database driver in use: SQL sent through it is not analyzed by this scanner");
  }
  return findings;
}

const SOURCE_EXT = /\.(?:[cm]?[jt]sx?)$/;

export function listSourceFiles(root: string, ignore: string[] = ["node_modules", ".git", "dist", "build", "generated", "coverage"]): string[] {
  const out: string[] = [];
  const walk = (p: string) => {
    const st = statSync(p);
    if (st.isDirectory()) {
      for (const e of readdirSync(p)) if (!ignore.includes(e)) walk(path.join(p, e));
    } else if (SOURCE_EXT.test(p) && !/\.d\.ts$/.test(p)) out.push(p);
  };
  walk(root);
  return out;
}

export function scanPaths(schema: Schema, roots: string[], ignore?: string[]): { findings: ScanFinding[]; files: number } {
  const findings: ScanFinding[] = [];
  let files = 0;
  for (const r of roots) {
    for (const f of listSourceFiles(r, ignore)) {
      files++;
      findings.push(...scanSource(schema, readFileSync(f, "utf8"), f));
    }
  }
  return { findings, files };
}
