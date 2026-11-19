import { readFileSync } from "node:fs";
import { applyNormalizers, hasEncryptedFields, parseSchema, type EncryptedField, type ModelInfo, type Schema } from "./schema.ts";
import { currentTenant } from "./tenant.ts";
import { createRawHelpers, rawGuardHooks, type RawGuardMode } from "./raw.ts";
import type { MetricsSink } from "./metrics.ts";

/** The part of the client the extension needs (satisfied by Cryplus and by the in-memory client). */
export interface CryptoLike {
  encrypt(ctx: { tenant: string; collection?: string; field?: string; recordId?: string }, plaintext: string | Uint8Array): Promise<string>;
  decrypt(ctx: { tenant: string; collection?: string; field?: string; recordId?: string }, ciphertext: string): Promise<string>;
  blindIndex(ctx: { tenant: string; collection?: string; field?: string; recordId?: string }, value: string): Promise<string>;
}

/** Tenant used for platform-scoped (`@encrypted(global)`) blind indexes. */
export const GLOBAL_TENANT = "__global__";

export interface PrismaOptions {
  cryplus: CryptoLike;
  /** Path to schema.prisma (read once at startup). */
  schemaPath?: string;
  /** Or the schema text itself. */
  schemaText?: string;
  /**
   * Resolve the tenant for a model. Called once per model touched by an operation,
   * with `model` set to the model whose field is being encrypted/decrypted (so nested
   * writes and included relations are resolved per model). Return undefined to fall
   * back to the ambient tenant set by withTenant(). If neither yields a tenant, the
   * operation fails closed. Typical use: platform tables that exist before any tenant,
   * e.g. `tenant: ({ model }) => (model === "Tenant" ? "__platform__" : undefined)`.
   */
  tenant?: (info: { model: string; operation: string; args: any }) => string | undefined | Promise<string | undefined>;
  /**
   * How to treat a plaintext value found in an @encrypted column on read.
   * "allow" (default) returns it as is, which keeps a half-migrated table
   * working; use "reject" once migration is done so plaintext can't hide.
   */
  plaintext?: "allow" | "reject";
  /** Remove companion index columns from results (default true). */
  hideIndexFields?: boolean;
  /**
   * What to do when a raw query ($queryRaw / $executeRaw, tagged or Unsafe) mentions an encrypted column
   * of an encrypted table: "throw" (default) refuses it, "warn" logs, "off" ignores. Mark a reviewed query
   * as handled by putting the comment marker `/* cryplus:handled *\/` inside the SQL text.
   */
  rawGuard?: RawGuardMode;
  /** Receives `prisma_errors_total{code,model,operation}` with code no_tenant | decryption_failed | raw_blocked | unsupported_query | plaintext_rejected | other. */
  metrics?: MetricsSink;
}

const CT_PREFIX = "cp1.";
export const isCiphertext = (v: unknown): v is string => typeof v === "string" && v.startsWith(CT_PREFIX);

export class CryplusPrismaError extends Error {
  constructor(message: string) {
    super("cryplus: " + message);
    this.name = "CryplusPrismaError";
  }
}

const isPlainObject = (v: unknown): v is Record<string, any> => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
};

const maybeArray = async <T>(v: T | T[], fn: (e: T) => Promise<T>): Promise<T | T[]> =>
  Array.isArray(v) ? Promise.all(v.map(fn)) : fn(v);

export interface TransformerOptions {
  plaintext: "allow" | "reject";
  hideIndexFields: boolean;
}

export class Transformer {
  readonly c: CryptoLike;
  readonly schema: Schema;
  private resolveTenant: (model: string) => Promise<string>;
  readonly opts: TransformerOptions;

  constructor(c: CryptoLike, schema: Schema, resolveTenant: (model: string) => Promise<string>, opts: TransformerOptions) {
    this.c = c;
    this.schema = schema;
    this.resolveTenant = resolveTenant;
    this.opts = opts;
  }

  model(name: string): ModelInfo {
    const m = this.schema.get(name);
    if (!m) throw new CryplusPrismaError(`unknown model ${name}`);
    return m;
  }

  // ---- primitives (also used by the raw-SQL helpers) --------------------------

  async ctx(model: string, field: string) {
    return { tenant: await this.resolveTenant(model), collection: model, field };
  }

  async encryptScalar(model: ModelInfo, enc: EncryptedField, plain: string) {
    return this.c.encrypt(await this.ctx(model.name, enc.name), plain);
  }

  async decryptScalar(model: ModelInfo, enc: EncryptedField, ct: string) {
    return this.c.decrypt(await this.ctx(model.name, enc.name), ct);
  }

  /** Blind-index value under one scope. `scope` selects the key domain: per-tenant equality, global, or suffix(n). */
  async indexOf(model: ModelInfo, enc: EncryptedField, plain: string, scope: "tenant" | "global" | { suffix: number }) {
    const norm = applyNormalizers(plain, enc.normalize);
    if (scope === "global") return this.c.blindIndex({ tenant: GLOBAL_TENANT, collection: model.name, field: enc.name + "#g" }, norm);
    if (scope === "tenant") return this.c.blindIndex(await this.ctx(model.name, enc.name), norm);
    if (norm.length < scope.suffix) return null;
    return this.c.blindIndex(await this.ctx(model.name, `${enc.name}#sfx${scope.suffix}`), norm.slice(-scope.suffix));
  }

  /** All companion index values for a plaintext, keyed by column name. */
  async indexesFor(model: ModelInfo, enc: EncryptedField, plain: string | null): Promise<Record<string, string | null>> {
    const out: Record<string, string | null> = {};
    if (enc.indexField) out[enc.indexField] = plain === null ? null : await this.indexOf(model, enc, plain, "tenant");
    if (enc.globalIndexField) out[enc.globalIndexField] = plain === null ? null : await this.indexOf(model, enc, plain, "global");
    for (const s of enc.suffixes) out[s.field] = plain === null ? null : await this.indexOf(model, enc, plain, { suffix: s.n });
    return out;
  }

  /** App value -> stored value, for any supported kind. */
  async encryptValue(model: ModelInfo, enc: EncryptedField, v: unknown): Promise<unknown> {
    if (v === null || v === undefined) return v;
    const where = `${model.name}.${enc.name}`;
    if (enc.kind === "string") {
      if (typeof v !== "string") throw new CryplusPrismaError(`${where} is @encrypted and only accepts string values`);
      if (isCiphertext(v)) throw new CryplusPrismaError(`${where}: refusing to store a value that already looks like ciphertext`);
      return this.encryptScalar(model, enc, v);
    }
    if (enc.kind === "string[]") {
      if (!Array.isArray(v) || v.some((e) => typeof e !== "string")) {
        throw new CryplusPrismaError(`${where} is an encrypted String[] and only accepts arrays of strings`);
      }
      return Promise.all(v.map((e) => this.encryptScalar(model, enc, e)));
    }
    // json: stored as an encrypted JSON string
    return this.encryptScalar(model, enc, JSON.stringify(v));
  }

  /** Stored value -> app value. Plaintext found where ciphertext is expected follows the `plaintext` policy. */
  async decryptValue(model: ModelInfo, enc: EncryptedField, v: unknown): Promise<unknown> {
    const where = `${model.name}.${enc.name}`;
    const legacy = (x: unknown) => {
      if (this.opts.plaintext === "reject") throw new CryplusPrismaError(`${where} holds a plaintext value but plaintext reads are rejected`);
      return x;
    };
    if (v === null || v === undefined) return v;
    if (enc.kind === "string") {
      if (typeof v !== "string") return v;
      return isCiphertext(v) ? this.decryptScalar(model, enc, v) : legacy(v);
    }
    if (enc.kind === "string[]") {
      if (!Array.isArray(v)) return v;
      return Promise.all(v.map((e) => (isCiphertext(e) ? this.decryptScalar(model, enc, e) : legacy(e))));
    }
    if (isCiphertext(v)) return JSON.parse(await this.decryptScalar(model, enc, v));
    return legacy(v);
  }

  // ---- writes --------------------------------------------------------------

  async data(model: ModelInfo, data: any): Promise<any> {
    if (Array.isArray(data)) return Promise.all(data.map((d) => this.data(model, d)));
    if (!isPlainObject(data)) return data;
    const out: Record<string, any> = {};
    const tasks: Promise<void>[] = [];
    for (const [k, v] of Object.entries(data)) {
      if (model.indexFields.has(k)) {
        throw new CryplusPrismaError(`${model.name}.${k} is managed automatically; do not set it`);
      }
      const enc = model.encrypted.get(k);
      const rel = model.fields.get(k)?.relation;
      if (enc) {
        tasks.push(this.encryptField(model, enc, v, out));
      } else if (rel && isPlainObject(v)) {
        tasks.push(this.nested(this.model(rel), v).then((r) => void (out[k] = r)));
      } else {
        out[k] = v;
      }
    }
    await Promise.all(tasks);
    return out;
  }

  private async encryptField(model: ModelInfo, enc: EncryptedField, v: unknown, out: Record<string, any>) {
    if (v === undefined) return;
    const where = `${model.name}.${enc.name}`;

    if (enc.kind === "string") {
      const wrapped = isPlainObject(v) && Object.keys(v).length === 1 && "set" in v;
      const raw = wrapped ? (v as any).set : v;
      if (raw === undefined) return;
      if (raw === null) {
        out[enc.name] = wrapped ? { set: null } : null;
        Object.assign(out, await this.indexesFor(model, enc, null));
        return;
      }
      const [ct, idx] = await Promise.all([this.encryptValue(model, enc, raw), this.indexesFor(model, enc, raw as string)]);
      out[enc.name] = wrapped ? { set: ct } : ct;
      Object.assign(out, idx);
      return;
    }

    if (enc.kind === "string[]") {
      if (v === null) {
        out[enc.name] = null;
      } else if (Array.isArray(v)) {
        out[enc.name] = await this.encryptValue(model, enc, v);
      } else if (isPlainObject(v) && Object.keys(v).length === 1 && "set" in v) {
        out[enc.name] = { set: await this.encryptValue(model, enc, (v as any).set) };
      } else if (isPlainObject(v) && Object.keys(v).length === 1 && "push" in v) {
        const p = (v as any).push;
        out[enc.name] = { push: await this.encryptValue(model, enc, Array.isArray(p) ? p : [p]) };
      } else {
        throw new CryplusPrismaError(`${where}: unsupported write for an encrypted String[] (use an array, { set } or { push })`);
      }
      return;
    }

    // json
    if (v === null) {
      out[enc.name] = null;
    } else if (typeof v === "object" && !Array.isArray(v) && !isPlainObject(v)) {
      out[enc.name] = v; // Prisma.JsonNull / DbNull and other sentinels pass through untouched
    } else {
      out[enc.name] = await this.encryptValue(model, enc, v);
    }
  }

  private async nested(target: ModelInfo, v: Record<string, any>): Promise<Record<string, any>> {
    const out: Record<string, any> = {};
    for (const [k, val] of Object.entries(v)) {
      switch (k) {
        case "create":
          out[k] = await this.data(target, val);
          break;
        case "createMany":
          out[k] = { ...val, data: await this.data(target, val.data) };
          break;
        case "connectOrCreate":
          out[k] = await maybeArray(val, async (e: any) => ({
            ...e,
            where: await this.where(target, e.where),
            create: await this.data(target, e.create),
          }));
          break;
        case "update":
          out[k] = await maybeArray(val, (e: any) => this.updateEntry(target, e));
          break;
        case "updateMany":
          out[k] = await maybeArray(val, async (e: any) => ({
            ...e,
            where: await this.where(target, e.where),
            data: await this.data(target, e.data),
          }));
          break;
        case "upsert":
          out[k] = await maybeArray(val, async (e: any) => ({
            ...e,
            ...(e.where ? { where: await this.where(target, e.where) } : {}),
            create: await this.data(target, e.create),
            update: await this.data(target, e.update),
          }));
          break;
        case "connect":
        case "disconnect":
        case "delete":
        case "deleteMany":
          out[k] = typeof val === "boolean" ? val : await maybeArray(val, (e: any) => this.where(target, e));
          break;
        default:
          out[k] = val;
      }
    }
    return out;
  }

  private async updateEntry(target: ModelInfo, e: any): Promise<any> {
    // to-many: { where, data }; to-one: data fields directly, or { where?, data }
    if (isPlainObject(e) && "data" in e && !target.fields.has("data")) {
      return {
        ...e,
        ...(e.where ? { where: await this.where(target, e.where) } : {}),
        data: await this.data(target, e.data),
      };
    }
    return this.data(target, e);
  }

  // ---- filters -------------------------------------------------------------

  async where(model: ModelInfo, where: any): Promise<any> {
    if (Array.isArray(where)) return Promise.all(where.map((w) => this.where(model, w)));
    if (!isPlainObject(where)) return where;
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(where)) {
      if (k === "AND" || k === "OR" || k === "NOT") {
        out[k] = await this.where(model, v);
        continue;
      }
      const enc = model.encrypted.get(k);
      if (enc) {
        Object.assign(out, await this.encCondition(model, enc, v));
        continue;
      }
      // compound unique key (findUnique / upsert / update by `tenantId_cpf`) whose uniqueness lives on the blind index
      const cu = model.compound.get(k);
      if (cu && isPlainObject(v)) {
        const inner: Record<string, any> = {};
        for (const [f, val] of Object.entries(v)) {
          const e = model.encrypted.get(f);
          if (e) Object.assign(inner, await this.encCondition(model, e, val));
          else inner[f] = val;
        }
        out[cu.realKey] = inner;
        continue;
      }
      const rel = model.fields.get(k)?.relation;
      if (rel && isPlainObject(v)) {
        const target = this.model(rel);
        const relKeys = ["some", "every", "none", "is", "isNot"];
        const ks = Object.keys(v);
        if (ks.length > 0 && ks.every((x) => relKeys.includes(x))) {
          const o: Record<string, any> = {};
          for (const kk of ks) o[kk] = await this.where(target, (v as any)[kk]);
          out[k] = o;
        } else {
          out[k] = await this.where(target, v);
        }
        continue;
      }
      out[k] = v;
    }
    return out;
  }

  private async encCondition(model: ModelInfo, enc: EncryptedField, v: any): Promise<Record<string, any>> {
    const where = `${model.name}.${enc.name}`;
    if (v === null) return { [enc.name]: null };
    if (enc.kind !== "string") {
      if (enc.kind === "string[]" && isPlainObject(v) && Object.keys(v).length === 1 && "isEmpty" in v) return { [enc.name]: v };
      throw new CryplusPrismaError(`cannot filter on encrypted ${enc.kind} field ${where}`);
    }

    // suffix match: { endsWith: "..." }
    if (isPlainObject(v) && Object.keys(v).length === 1 && "endsWith" in v) {
      if (enc.suffixes.length === 0) {
        throw new CryplusPrismaError(`cannot use endsWith on encrypted field ${where}; add suffix(n) to its @encrypted(...) options`);
      }
      if (typeof v.endsWith !== "string") throw new CryplusPrismaError(`${where}: endsWith needs a string`);
      const norm = applyNormalizers(v.endsWith, enc.normalize);
      const s = enc.suffixes.find((x) => x.n === norm.length);
      if (!s) {
        throw new CryplusPrismaError(
          `${where}: endsWith values must have exactly one of the indexed lengths [${enc.suffixes.map((x) => x.n).join(", ")}] after normalization (got ${norm.length})`,
        );
      }
      return { [s.field]: await this.indexOf(model, enc, v.endsWith, { suffix: s.n }) };
    }

    const scope: "tenant" | "global" | null = enc.indexField ? "tenant" : enc.globalIndexField ? "global" : null;
    const col = scope === "tenant" ? enc.indexField! : scope === "global" ? enc.globalIndexField! : null;
    if (!scope || !col) {
      throw new CryplusPrismaError(
        `cannot filter on encrypted field ${where}; mark it @encrypted(searchable) for equality search`,
      );
    }
    const bi = (s: unknown) => {
      if (typeof s !== "string") throw new CryplusPrismaError(`${where}: filter values must be strings`);
      return this.indexOf(model, enc, s, scope);
    };
    const cond = async (x: any): Promise<any> => {
      if (x === null) return null;
      if (typeof x === "string") return bi(x);
      if (!isPlainObject(x)) throw new CryplusPrismaError(`${where}: unsupported filter`);
      const o: Record<string, any> = {};
      for (const [op, val] of Object.entries(x)) {
        if (op === "equals" || op === "not") o[op] = await cond(val);
        else if (op === "in" || op === "notIn") o[op] = await Promise.all((val as unknown[]).map(bi));
        else
          throw new CryplusPrismaError(
            `operator "${op}" is not supported on encrypted field ${where} (only equals, in, not, notIn${enc.suffixes.length ? ", endsWith" : ""})`,
          );
      }
      return o;
    };
    return { [col]: await cond(v) };
  }

  /** Walk select/include so filters inside nested relations are rewritten too. */
  async selection(model: ModelInfo, sel: any): Promise<any> {
    if (!isPlainObject(sel)) return sel;
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(sel)) {
      const rel = model.fields.get(k)?.relation;
      if (rel && isPlainObject(v)) {
        const target = this.model(rel);
        const o: Record<string, any> = { ...v };
        if (v.where) o.where = await this.where(target, v.where);
        if (v.cursor) o.cursor = await this.where(target, v.cursor);
        this.checkOrder(target, v.orderBy);
        if (v.select) o.select = await this.selection(target, v.select);
        if (v.include) o.include = await this.selection(target, v.include);
        out[k] = o;
      } else {
        out[k] = v;
      }
    }
    return out;
  }

  checkOrder(model: ModelInfo, orderBy: any) {
    if (!orderBy) return;
    for (const o of Array.isArray(orderBy) ? orderBy : [orderBy]) {
      if (!isPlainObject(o)) continue;
      for (const k of Object.keys(o)) {
        if (model.encrypted.has(k)) {
          throw new CryplusPrismaError(`cannot order by encrypted field ${model.name}.${k}; ciphertext order is meaningless`);
        }
      }
    }
  }

  /** aggregate / groupBy must not compute over ciphertext. */
  checkAggregate(model: ModelInfo, operation: string, a: any) {
    const bad = (f: string) => {
      throw new CryplusPrismaError(`cannot ${operation} on encrypted field ${model.name}.${f}`);
    };
    for (const key of ["_min", "_max", "_sum", "_avg"]) {
      if (isPlainObject(a[key])) for (const f of Object.keys(a[key])) if (model.encrypted.has(f)) bad(f);
    }
    if (operation === "groupBy") {
      for (const f of [a.by].flat()) if (typeof f === "string" && model.encrypted.has(f)) bad(f);
      if (isPlainObject(a.having)) for (const f of Object.keys(a.having)) if (model.encrypted.has(f)) bad(f);
    }
  }

  // ---- reads ---------------------------------------------------------------

  async result(model: ModelInfo, value: any): Promise<any> {
    if (Array.isArray(value)) {
      await Promise.all(value.map((v) => this.result(model, v)));
      return value;
    }
    if (!isPlainObject(value)) return value;
    const tasks: Promise<void>[] = [];
    for (const k of Object.keys(value)) {
      const v = value[k];
      const enc = model.encrypted.get(k);
      if (enc) {
        tasks.push(this.decryptValue(model, enc, v).then((p) => void (value[k] = p)));
      } else if (this.opts.hideIndexFields && model.indexFields.has(k)) {
        delete value[k];
      } else {
        const rel = model.fields.get(k)?.relation;
        if (rel && v && typeof v === "object") tasks.push(this.result(this.model(rel), v).then(() => undefined));
      }
    }
    await Promise.all(tasks);
    return value;
  }
}

/** Shared by the query hooks and the raw-SQL helpers. */
export function makeTenantResolver(o: PrismaOptions) {
  return (forModel: string, operation = "raw", args: any = undefined): Promise<string> =>
    (async () => {
      const t = (o.tenant ? await o.tenant({ model: forModel, operation, args }) : undefined) ?? currentTenant();
      if (!t) {
        throw new CryplusPrismaError(
          `no tenant for ${forModel} (${operation}); wrap the call in withTenant("<id>", …) or pass a tenant resolver`,
        );
      }
      return t;
    })();
}

const NO_RESULT_DECRYPT = new Set(["count", "aggregate", "groupBy"]);

/** Build the Prisma Client extension definition (use with client.$extends). */
export function cryplusExtension(o: PrismaOptions) {
  const text = o.schemaText ?? (o.schemaPath ? readFileSync(o.schemaPath, "utf8") : undefined);
  if (!text) throw new CryplusPrismaError("provide schemaPath or schemaText");
  const schema = parseSchema(text);
  const active = hasEncryptedFields(schema);
  const topts: TransformerOptions = { plaintext: o.plaintext ?? "allow", hideIndexFields: o.hideIndexFields ?? true };
  const resolver = makeTenantResolver(o);
  const helpers = createRawHelpers(o.cryplus, schema, (m) => resolver(m), topts);

  const ext = {
    name: "cryplus",
    client: { $cryplus: helpers },
    query: {
      ...(active ? rawGuardHooks(schema, o.rawGuard ?? "throw") : {}),
      $allModels: {
        async $allOperations({ model, operation, args, query }: { model: string; operation: string; args: any; query: (a: any) => Promise<any> }) {
          const m = schema.get(model);
          if (!active || !m) return query(args);

          const tenants = new Map<string, Promise<string>>();
          const resolveTenant = (forModel: string) => {
            let p = tenants.get(forModel);
            if (!p) {
              p = resolver(forModel, `${model}.${operation}`, args);
              tenants.set(forModel, p);
            }
            return p;
          };
          const x = new Transformer(o.cryplus, schema, resolveTenant, topts);

          const a: any = { ...(args ?? {}) };
          if (a.where) a.where = await x.where(m, a.where);
          if (a.cursor) a.cursor = await x.where(m, a.cursor);
          x.checkOrder(m, a.orderBy);
          if (operation === "aggregate" || operation === "groupBy") x.checkAggregate(m, operation, a);
          if (Array.isArray(a.distinct) ? a.distinct.some((f: string) => m.encrypted.has(f)) : m.encrypted.has(a.distinct)) {
            throw new CryplusPrismaError(`cannot use distinct on an encrypted field of ${model}`);
          }
          if (a.select) a.select = await x.selection(m, a.select);
          if (a.include) a.include = await x.selection(m, a.include);

          switch (operation) {
            case "create":
            case "createMany":
            case "createManyAndReturn":
            case "update":
            case "updateMany":
            case "updateManyAndReturn":
              if (a.data) a.data = await x.data(m, a.data);
              break;
            case "upsert":
              if (a.create) a.create = await x.data(m, a.create);
              if (a.update) a.update = await x.data(m, a.update);
              break;
          }

          const res = await query(a);
          if (NO_RESULT_DECRYPT.has(operation)) return res;
          return x.result(m, res);
        },
      },
    },
  };

  // Metrics: count what goes wrong, by cause, so a dashboard can alert on "no tenant" or "decryption_failed" bursts.
  if (o.metrics) {
    const sink = o.metrics;
    const inner = ext.query.$allModels.$allOperations;
    ext.query.$allModels.$allOperations = async (p: any) => {
      try {
        return await inner(p);
      } catch (e) {
        const m = e instanceof Error ? e.message : String(e);
        const code = /no tenant/.test(m)
          ? "no_tenant"
          : /decryption_failed/.test(m)
            ? "decryption_failed"
            : /raw SQL touches/.test(m)
              ? "raw_blocked"
              : /cannot|not supported|searchable|indexed lengths/.test(m)
                ? "unsupported_query"
                : /plaintext reads are rejected/.test(m)
                  ? "plaintext_rejected"
                  : "other";
        sink.inc("prisma_errors_total", { code, model: p?.model ?? "", operation: p?.operation ?? "" });
        throw e;
      }
    };
  }
  return ext;
}

/** Convenience: `const prisma = withCryplus(new PrismaClient(...), { cryplus, schemaPath })`. */
export function withCryplus<T extends { $extends: (ext: any) => any }>(client: T, opts: PrismaOptions): T {
  return client.$extends(cryplusExtension(opts)) as T;
}
