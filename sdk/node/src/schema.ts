/**
 * Reader for the parts of schema.prisma that Cryplus needs: which fields are marked `/// @encrypted`,
 * how models relate, and the real database names (`@map` / `@@map`). It deliberately does not depend on
 * Prisma internals (DMMF), so it works the same in the runtime extension, in migration scripts and in the scanner.
 *
 * Directive syntax (a triple-slash comment on the line above, or at the end of the field line):
 *
 *   /// @encrypted
 *   /// @encrypted(searchable, digits)                     equality search, needs  <field>Idx  String?
 *   /// @encrypted(global)                                 equality search across tenants, needs  <field>GIdx  String?
 *   /// @encrypted(suffix(4), suffix(8), br-phone-canonical)  endsWith search, needs  <field>Sfx4 / <field>Sfx8  String?
 *   /// @encrypted(max(14))                                max plaintext characters (checked against @db.VarChar)
 *
 * Supported column types: String, String[] (each element encrypted), Json (stored as an encrypted JSON string).
 */
import { applyNormalizers, NORMALIZER_NAMES, type Normalizer } from "./normalize.ts";

export { applyNormalizers, type Normalizer } from "./normalize.ts";

export type FieldKind = "string" | "string[]" | "json";

export interface FieldInfo {
  name: string;
  /** Column name in the database (`@map`, else the field name). */
  dbName: string;
  type: string;
  list: boolean;
  optional: boolean;
  isId: boolean;
  /** Target model name when this field is a relation. */
  relation?: string;
  native?: { name: "VarChar" | "Char"; length: number };
}

export interface SuffixIndex {
  n: number;
  field: string;
}

export interface EncryptedField {
  name: string;
  dbName: string;
  kind: FieldKind;
  searchable: boolean;
  /** Per-tenant equality index column (`<name>Idx`). */
  indexField?: string;
  /** Platform-scoped equality index (`<name>GIdx`): the same value gives the same index in every tenant. */
  global: boolean;
  globalIndexField?: string;
  suffixes: SuffixIndex[];
  normalize: Normalizer[];
  maxLength?: number;
}

export interface ModelInfo {
  name: string;
  /** Table name in the database (`@@map`, else the model name). */
  dbTable: string;
  fields: Map<string, FieldInfo>;
  idField?: string;
  encrypted: Map<string, EncryptedField>;
  /** Names of all companion index columns (hidden from results, never set by the app). */
  indexFields: Set<string>;
  /**
   * Compound unique keys whose uniqueness moved to a blind-index column, e.g. `@@unique([tenantId, cpfIdx])`.
   * Maps the key the app already uses (`tenantId_cpf`) to the key Prisma now expects (`tenantId_cpfIdx`).
   */
  compound: Map<string, { realKey: string }>;
}

export type Schema = Map<string, ModelInfo>;

export interface SchemaProblem {
  model: string;
  field: string;
  message: string;
  /** Exact SQL to run first, when there is one. */
  fix?: string;
}

export class SchemaError extends Error {
  problems: SchemaProblem[];
  constructor(problems: SchemaProblem[]) {
    super(
      "cryplus: invalid @encrypted configuration:\n" +
        problems.map((p) => `  - ${p.model}.${p.field}: ${p.message}${p.fix ? `\n      run first: ${p.fix}` : ""}`).join("\n"),
    );
    this.name = "SchemaError";
    this.problems = problems;
  }
}

// ---- ciphertext sizing -------------------------------------------------------

/** Length of a blind-index value as stored: "bi1." + base64url(32 bytes). */
export const INDEX_TEXT_LENGTH = 4 + Math.ceil((32 * 4) / 3); // 47

/**
 * Exact length (characters) of the stored ciphertext text for a plaintext of `plainBytes` UTF-8 bytes.
 *
 *   raw  = 1 (format) + 1 (algorithm) + 4 (KEK version) + 2 (wrapped-DEK length)
 *        + 72 (wrapped DEK: 24 nonce + 32 key + 16 tag) + nonce (24 for xchacha20, 12 for aes256gcm)
 *        + plainBytes + 16 (tag)
 *   text = "cp1." + base64url(raw) without padding = 4 + ceil(raw * 4 / 3)
 *
 * Example: a 14-character ASCII CPF with xchacha20 is 183 characters.
 * Values written through String[] elements and Json (as a JSON string) use the same formula per element/document.
 */
export function ciphertextLength(plainBytes: number, alg: "xchacha20" | "aes256gcm" = "xchacha20"): number {
  const nonce = alg === "xchacha20" ? 24 : 12;
  const raw = 1 + 1 + 4 + 2 + 72 + nonce + plainBytes + 16;
  return 4 + Math.ceil((raw * 4) / 3);
}

// ---- parsing -----------------------------------------------------------------

const FIELD = /^(\w+)\s+(\w+)(\[\])?(\?)?(\s.*)?$/;
const MAX_BYTES_PER_CHAR = 4; // worst case UTF-8

function extractDirective(docs: string): string | null {
  const i = docs.indexOf("@encrypted");
  if (i < 0) return null;
  let j = i + "@encrypted".length;
  while (j < docs.length && (docs[j] === " " || docs[j] === "\t")) j++;
  if (docs[j] !== "(") return "";
  let depth = 0;
  for (let k = j; k < docs.length; k++) {
    if (docs[k] === "(") depth++;
    else if (docs[k] === ")" && --depth === 0) return docs.slice(j + 1, k);
  }
  throw new Error("cryplus: unbalanced parentheses in @encrypted(...)");
}

function splitTopLevel(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of s) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out.filter(Boolean);
}

interface RawField {
  model: string;
  name: string;
  type: string;
  list: boolean;
  optional: boolean;
  rest: string;
  docs: string;
}

/** Parse and validate. Throws SchemaError listing every problem. */
export function parseSchema(text: string): Schema {
  const { schema, problems } = checkSchema(text);
  if (problems.length) throw new SchemaError(problems);
  return schema;
}

/** Parse without throwing on configuration problems (used by the scanner CLI). */
export function checkSchema(text: string): { schema: Schema; problems: SchemaProblem[] } {
  const models = new Map<string, ModelInfo>();
  const rawFields: RawField[] = [];
  const problems: SchemaProblem[] = [];
  const uniques: { model: string; fields: string[]; name?: string }[] = [];

  const lines = text.split(/\r?\n/);
  let inModel: string | null = null;
  let inOther = false;
  let docs: string[] = [];

  for (const raw of lines) {
    const line = raw.trim();
    if (!inModel && !inOther) {
      const m = /^model\s+(\w+)\s*\{/.exec(line);
      if (m) {
        inModel = m[1]!;
        models.set(inModel, { name: inModel, dbTable: inModel, fields: new Map(), encrypted: new Map(), indexFields: new Set(), compound: new Map() });
        docs = [];
      } else if (/^(enum|type|view|datasource|generator)\s+\w+\s*\{/.test(line)) {
        inOther = true;
      }
      continue;
    }
    if (line === "}") {
      inModel = null;
      inOther = false;
      docs = [];
      continue;
    }
    if (!inModel) continue;
    if (line.startsWith("///")) {
      docs.push(line.slice(3));
      continue;
    }
    if (line === "" || line.startsWith("//")) continue;
    if (line.startsWith("@@")) {
      const mm = /^@@map\(\s*(?:name:\s*)?"([^"]+)"\s*\)/.exec(line);
      if (mm) models.get(inModel)!.dbTable = mm[1]!;
      const um = /^@@(?:unique|id)\(\s*\[([^\]]+)\](?:[^)]*?name:\s*"([^"]+)")?/.exec(line);
      if (um) uniques.push({ model: inModel, fields: um[1]!.split(",").map((x) => x.trim()), name: um[2] });
      docs = [];
      continue;
    }
    let body = line;
    let trailing = "";
    const idx = line.indexOf("///");
    if (idx >= 0) {
      body = line.slice(0, idx).trim();
      trailing = line.slice(idx + 3);
    }
    body = body.replace(/\/\/.*$/, "").trim();
    const f = FIELD.exec(body);
    if (f) {
      rawFields.push({
        model: inModel,
        name: f[1]!,
        type: f[2]!,
        list: !!f[3],
        optional: !!f[4],
        rest: f[5] ?? "",
        docs: [...docs, trailing].join("\n"),
      });
    }
    docs = [];
  }

  for (const rf of rawFields) {
    const m = models.get(rf.model)!;
    const mapMatch = /@map\(\s*(?:name:\s*)?"([^"]+)"\s*\)/.exec(rf.rest);
    const nat = /@db\.(VarChar|Char)\(\s*(\d+)\s*\)/.exec(rf.rest);
    m.fields.set(rf.name, {
      name: rf.name,
      dbName: mapMatch ? mapMatch[1]! : rf.name,
      type: rf.type,
      list: rf.list,
      optional: rf.optional,
      isId: /@id\b/.test(rf.rest),
      relation: models.has(rf.type) ? rf.type : undefined,
      native: nat ? { name: nat[1] as "VarChar" | "Char", length: Number(nat[2]) } : undefined,
    });
    if (/@id\b/.test(rf.rest)) m.idField = rf.name;
  }

  const bad = (model: string, field: string, message: string, fix?: string) => problems.push({ model, field, message, fix });

  for (const rf of rawFields) {
    let directive: string | null;
    try {
      directive = extractDirective(rf.docs);
    } catch (e) {
      bad(rf.model, rf.name, (e as Error).message);
      continue;
    }
    if (directive === null) continue;
    const m = models.get(rf.model)!;
    const fi = m.fields.get(rf.name)!;

    // ---- type
    let kind: FieldKind;
    if (models.has(rf.type)) {
      bad(rf.model, rf.name, "is a relation, not a column");
      continue;
    } else if (rf.type === "String" && !rf.list) kind = "string";
    else if (rf.type === "String" && rf.list) kind = "string[]";
    else if (rf.type === "Json" && !rf.list) kind = "json";
    else {
      const hint =
        rf.type === "DateTime"
          ? "a DateTime column cannot hold ciphertext. Add a String column (e.g. `" + rf.name + "Enc String? /// @encrypted`), store the ISO date there, and migrate"
          : "supported types are String, String[] and Json";
      bad(rf.model, rf.name, `@encrypted does not support type ${rf.type}${rf.list ? "[]" : ""}: ${hint}`);
      continue;
    }

    // ---- options
    let searchable = false;
    let global = false;
    const normalize: Normalizer[] = [];
    const suffixNs: number[] = [];
    let maxLength: number | undefined;
    for (const o of splitTopLevel(directive)) {
      let mm: RegExpExecArray | null;
      if (o === "searchable") searchable = true;
      else if (o === "global") global = true;
      else if ((mm = /^suffix\(\s*(\d+)\s*\)$/.exec(o))) suffixNs.push(Number(mm[1]));
      else if ((mm = /^max\(\s*(\d+)\s*\)$/.exec(o))) maxLength = Number(mm[1]);
      else if ((NORMALIZER_NAMES as readonly string[]).includes(o)) normalize.push(o as Normalizer);
      else bad(rf.model, rf.name, `unknown @encrypted option "${o}"`);
    }
    const wantsIndex = searchable || global || suffixNs.length > 0;
    if (wantsIndex && kind !== "string") {
      bad(rf.model, rf.name, `search options are only available on String columns, not ${kind}`);
      continue;
    }
    if (normalize.length && !wantsIndex) {
      bad(rf.model, rf.name, "normalizers only apply to searchable / global / suffix fields");
    }
    if (suffixNs.some((n) => n < 1 || n > 64)) bad(rf.model, rf.name, "suffix(n) needs 1 <= n <= 64");

    const ef: EncryptedField = {
      name: rf.name,
      dbName: fi.dbName,
      kind,
      searchable,
      global,
      suffixes: [],
      normalize,
      maxLength,
    };

    // ---- companion index columns
    const companion = (colName: string, why: string): string | undefined => {
      const c = m.fields.get(colName);
      if (!c || c.type !== "String" || c.list) {
        bad(rf.model, rf.name, `${why} needs a column ${rf.model}.${colName} (String?), which is missing`);
        return undefined;
      }
      if (c.native && c.native.length < INDEX_TEXT_LENGTH) {
        bad(
          rf.model,
          colName,
          `index column is @db.${c.native.name}(${c.native.length}) but a blind index is ${INDEX_TEXT_LENGTH} characters`,
          `ALTER TABLE "${m.dbTable}" ALTER COLUMN "${c.dbName}" TYPE text;`,
        );
      }
      m.indexFields.add(colName);
      return colName;
    };
    if (searchable) ef.indexField = companion(`${rf.name}Idx`, "@encrypted(searchable)");
    if (global) ef.globalIndexField = companion(`${rf.name}GIdx`, "@encrypted(global)");
    for (const n of [...new Set(suffixNs)].sort((a, b) => a - b)) {
      const col = companion(`${rf.name}Sfx${n}`, `@encrypted(suffix(${n}))`);
      if (col) ef.suffixes.push({ n, field: col });
    }

    // ---- column size: ciphertext does not fit short VarChar/Char columns
    if (fi.native && kind !== "json") {
      const maxChars = maxLength ?? fi.native.length;
      const required = ciphertextLength(maxChars * MAX_BYTES_PER_CHAR);
      if (fi.native.length < required) {
        bad(
          rf.model,
          rf.name,
          `column is @db.${fi.native.name}(${fi.native.length}) but an encrypted value of up to ${maxChars} characters needs ${required}` +
            ` (ciphertext = 4 + ceil(4 * (120 + 4*chars) / 3)). Change the column to text`,
          `ALTER TABLE "${m.dbTable}" ALTER COLUMN "${fi.dbName}" TYPE text;`,
        );
      }
    }
    m.encrypted.set(rf.name, ef);
  }

  // compound unique keys that now live on a blind-index column
  for (const u of uniques) {
    const m = models.get(u.model)!;
    const idxToField = new Map<string, string>();
    for (const e of m.encrypted.values()) if (e.indexField) idxToField.set(e.indexField, e.name);
    if (!u.fields.some((f) => idxToField.has(f))) continue;
    const legacy = u.fields.map((f) => idxToField.get(f) ?? f);
    const realKey = u.name ?? u.fields.join("_");
    const legacyKey = u.name ?? legacy.join("_");
    if (legacyKey !== realKey) m.compound.set(legacyKey, { realKey });
    m.compound.set(realKey, { realKey }); // the new key may also contain the plaintext field name in its inner object
  }
  return { schema: models, problems };
}

/** @deprecated use applyNormalizers */
export function normalizeValue(v: string, ops: Normalizer[]): string {
  return applyNormalizers(v, ops);
}

export function hasEncryptedFields(schema: Schema): boolean {
  for (const m of schema.values()) if (m.encrypted.size) return true;
  return false;
}
