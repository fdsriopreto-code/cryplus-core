/**
 * Minimal reader for the parts of schema.prisma that Cryplus needs: which
 * fields are marked `/// @encrypted`, and how models relate. It deliberately
 * does not depend on Prisma internals (DMMF), so it works the same in the
 * runtime extension and in migration scripts.
 */

export type Normalizer = "lowercase" | "digits" | "trim";

export interface FieldInfo {
  name: string;
  type: string;
  list: boolean;
  optional: boolean;
  isId: boolean;
  /** Target model name when this field is a relation. */
  relation?: string;
}

export interface EncryptedField {
  name: string;
  searchable: boolean;
  /** Companion column that stores the blind index (`<name>Idx`). */
  indexField?: string;
  normalize: Normalizer[];
}

export interface ModelInfo {
  name: string;
  fields: Map<string, FieldInfo>;
  idField?: string;
  encrypted: Map<string, EncryptedField>;
  /** Names of index companion columns, to hide them from results. */
  indexFields: Set<string>;
}

export type Schema = Map<string, ModelInfo>;

const DIRECTIVE = /@encrypted(?:\(([^)]*)\))?/;
const FIELD = /^(\w+)\s+(\w+)(\[\])?(\?)?(\s.*)?$/;

export function parseSchema(text: string): Schema {
  const models = new Map<string, ModelInfo>();
  const rawFields: { model: string; name: string; type: string; list: boolean; optional: boolean; rest: string; docs: string }[] = [];

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
        models.set(inModel, { name: inModel, fields: new Map(), encrypted: new Map(), indexFields: new Set() });
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
    if (line === "" || line.startsWith("//") || line.startsWith("@@")) {
      if (line.startsWith("@@")) docs = [];
      continue;
    }
    // split trailing doc comment
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
    m.fields.set(rf.name, {
      name: rf.name,
      type: rf.type,
      list: rf.list,
      optional: rf.optional,
      isId: /@id\b/.test(rf.rest),
      relation: models.has(rf.type) ? rf.type : undefined,
    });
    if (/@id\b/.test(rf.rest)) m.idField = rf.name;
  }

  for (const rf of rawFields) {
    const d = DIRECTIVE.exec(rf.docs);
    if (!d) continue;
    const m = models.get(rf.model)!;
    const where = `${rf.model}.${rf.name}`;
    if (rf.type !== "String" || rf.list || models.has(rf.type)) {
      throw new Error(`cryplus: ${where} is marked @encrypted but is not a plain String column`);
    }
    const opts = (d[1] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    const normalize: Normalizer[] = [];
    let searchable = false;
    for (const o of opts) {
      if (o === "searchable") searchable = true;
      else if (o === "lowercase" || o === "digits" || o === "trim") normalize.push(o);
      else throw new Error(`cryplus: ${where}: unknown @encrypted option "${o}"`);
    }
    if (normalize.length && !searchable) {
      throw new Error(`cryplus: ${where}: normalization options only apply to searchable fields`);
    }
    const ef: EncryptedField = { name: rf.name, searchable, normalize };
    if (searchable) {
      const idxName = `${rf.name}Idx`;
      const idxField = m.fields.get(idxName);
      if (!idxField || idxField.type !== "String" || idxField.list) {
        throw new Error(`cryplus: ${where} is @encrypted(searchable) but ${rf.model}.${idxName} (String?) is missing`);
      }
      ef.indexField = idxName;
      m.indexFields.add(idxName);
    }
    m.encrypted.set(rf.name, ef);
  }
  return models;
}

export function normalizeValue(v: string, ops: Normalizer[]): string {
  let out = v;
  // trim by default for searchable values so "x " and "x" match
  out = out.trim();
  for (const o of ops) {
    if (o === "lowercase") out = out.toLowerCase();
    else if (o === "digits") out = out.replace(/\D+/g, "");
  }
  return out;
}

export function hasEncryptedFields(schema: Schema): boolean {
  for (const m of schema.values()) if (m.encrypted.size) return true;
  return false;
}
