import type { Schema } from "./schema.ts";

/** A raw SQL statement that touches an encrypted column of an encrypted table. */
export interface SqlFinding {
  model: string;
  table: string;
  /** Encrypted columns (database names) the SQL mentions; ["*"] when it selects everything from the table. */
  columns: string[];
  reason: string;
}

export const HANDLED_MARKER = "cryplus:handled";

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Identifier match: not part of a longer word, optionally quoted, optionally schema-qualified. */
function identRe(name: string): RegExp {
  return new RegExp(`(^|[^\\w$])"?${esc(name)}"?(?![\\w$])`, "i");
}

function stripComments(sql: string): string {
  return sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ");
}

/**
 * Find encrypted columns of encrypted tables referenced by a SQL text, using the real database names
 * (`@map` / `@@map`). Static text analysis: it can over-report (a common word that is also a column name) but it is
 * meant to err on that side. A reviewed statement is silenced by the marker `/* cryplus:handled *\/` inside it.
 */
export function analyzeSql(schema: Schema, sql: string): SqlFinding[] {
  if (sql.includes(HANDLED_MARKER)) return [];
  const text = stripComments(sql);
  const out: SqlFinding[] = [];
  for (const m of schema.values()) {
    if (m.encrypted.size === 0) continue;
    if (!identRe(m.dbTable).test(text)) continue;
    const cols = [...m.encrypted.values()].filter((e) => identRe(e.dbName).test(text)).map((e) => e.dbName);
    // count(*) is not "every column": blank it out before looking for a star
    const noCount = text.replace(/\bcount\s*\(\s*(?:distinct\s+)?(?:\w+\.)?\*\s*\)/gi, " count_all ");
    const star = /\bselect\b[\s\S]*?(?:^|[\s,(])(?:\w+\.)?\*(?=[\s,)]|$)[\s\S]*?\bfrom\b/i.test(noCount) || /\breturning\s+\*/i.test(noCount);
    const insertNoCols = new RegExp(`\\binsert\\s+into\\s+(?:\\w+\\.)?"?${esc(m.dbTable)}"?\\s*(values|select|default)`, "i").test(text);
    if (cols.length) {
      out.push({ model: m.name, table: m.dbTable, columns: cols, reason: `mentions encrypted column(s) ${cols.join(", ")}` });
    } else if (star) {
      out.push({ model: m.name, table: m.dbTable, columns: ["*"], reason: "selects every column, including encrypted ones" });
    } else if (insertNoCols) {
      out.push({ model: m.name, table: m.dbTable, columns: ["*"], reason: "inserts without a column list into a table with encrypted columns" });
    }
  }
  return out;
}

/** Best-effort extraction of the SQL text from the arguments Prisma hands to a raw-query hook. */
export function sqlTextOf(args: unknown): string | undefined {
  if (typeof args === "string") return args;
  if (Array.isArray(args)) {
    const a0: any = args[0];
    if (typeof a0 === "string") return a0;
    if (Array.isArray(a0)) return a0.join("?"); // tagged template: TemplateStringsArray
    if (a0 && typeof a0 === "object") return sqlTextOf(a0);
    return undefined;
  }
  if (args && typeof args === "object") {
    const o: any = args;
    if (typeof o.sql === "string") return o.sql;
    if (typeof o.text === "string") return o.text;
    if (Array.isArray(o.strings)) return o.strings.join("?");
    if (Array.isArray(o.values) && typeof o.sql === "string") return o.sql;
    if (Array.isArray(o.query)) return o.query.join("?");
    if (typeof o.query === "string") return o.query;
  }
  return undefined;
}
