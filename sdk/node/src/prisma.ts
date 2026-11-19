import { readFileSync } from "node:fs";
import type { Cryplus } from "./client.ts";
import {
  hasEncryptedFields,
  normalizeValue,
  parseSchema,
  type EncryptedField,
  type ModelInfo,
  type Schema,
} from "./schema.ts";
import { currentTenant } from "./tenant.ts";

type CryptoLike = Pick<Cryplus, "encrypt" | "decrypt" | "blindIndex">;

export interface PrismaOptions {
  cryplus: CryptoLike;
  /** Path to schema.prisma (read once at startup). */
  schemaPath?: string;
  /** Or the schema text itself. */
  schemaText?: string;
  /**
   * Resolve the tenant for an operation. Defaults to the ambient tenant set by
   * withTenant(). Throwing/returning nothing makes encrypted operations fail.
   */
  tenant?: (info: { model: string; operation: string; args: any }) => string | undefined | Promise<string | undefined>;
  /**
   * How to treat a plaintext value found in an @encrypted column on read.
   * "allow" (default) returns it as is, which keeps a half-migrated table
   * working; use "reject" once migration is done so plaintext can't hide.
   */
  plaintext?: "allow" | "reject";
  /** Remove `<field>Idx` blind-index columns from results (default true). */
  hideIndexFields?: boolean;
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

export class Transformer {
  readonly c: CryptoLike;
  readonly schema: Schema;
  private resolveTenant: () => Promise<string>;
  readonly opts: { plaintext: "allow" | "reject"; hideIndexFields: boolean };

  constructor(
    c: CryptoLike,
    schema: Schema,
    resolveTenant: () => Promise<string>,
    opts: { plaintext: "allow" | "reject"; hideIndexFields: boolean },
  ) {
    this.c = c;
    this.schema = schema;
    this.resolveTenant = resolveTenant;
    this.opts = opts;
  }

  private model(name: string): ModelInfo {
    const m = this.schema.get(name);
    if (!m) throw new CryplusPrismaError(`unknown model ${name}`);
    return m;
  }

  private async ctx(model: string, field: string) {
    return { tenant: await this.resolveTenant(), collection: model, field };
  }

  async encryptValue(model: ModelInfo, enc: EncryptedField, plain: string) {
    return this.c.encrypt(await this.ctx(model.name, enc.name), plain);
  }

  async indexValue(model: ModelInfo, enc: EncryptedField, plain: string) {
    return this.c.blindIndex(await this.ctx(model.name, enc.name), normalizeValue(plain, enc.normalize));
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
    const wrapped = isPlainObject(v) && Object.keys(v).length === 1 && "set" in v;
    const raw = wrapped ? (v as any).set : v;
    if (raw === undefined) return;
    if (raw === null) {
      out[enc.name] = wrapped ? { set: null } : null;
      if (enc.indexField) out[enc.indexField] = null;
      return;
    }
    if (typeof raw !== "string") {
      throw new CryplusPrismaError(`${model.name}.${enc.name} is @encrypted and only accepts string values`);
    }
    if (isCiphertext(raw)) {
      throw new CryplusPrismaError(`${model.name}.${enc.name}: refusing to store a value that already looks like ciphertext`);
    }
    const [ct, idx] = await Promise.all([
      this.encryptValue(model, enc, raw),
      enc.indexField ? this.indexValue(model, enc, raw) : Promise.resolve(undefined),
    ]);
    out[enc.name] = wrapped ? { set: ct } : ct;
    if (enc.indexField) out[enc.indexField] = idx;
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
    if (v === null) return { [enc.name]: null };
    if (!enc.searchable || !enc.indexField) {
      throw new CryplusPrismaError(
        `cannot filter on encrypted field ${model.name}.${enc.name}; mark it @encrypted(searchable) for equality search`,
      );
    }
    const bi = (s: unknown) => {
      if (typeof s !== "string") throw new CryplusPrismaError(`${model.name}.${enc.name}: filter values must be strings`);
      return this.indexValue(model, enc, s);
    };
    const cond = async (x: any): Promise<any> => {
      if (x === null) return null;
      if (typeof x === "string") return bi(x);
      if (!isPlainObject(x)) throw new CryplusPrismaError(`${model.name}.${enc.name}: unsupported filter`);
      const o: Record<string, any> = {};
      for (const [op, val] of Object.entries(x)) {
        if (op === "equals" || op === "not") o[op] = await cond(val);
        else if (op === "in" || op === "notIn") o[op] = await Promise.all((val as unknown[]).map(bi));
        else
          throw new CryplusPrismaError(
            `operator "${op}" is not supported on encrypted field ${model.name}.${enc.name} (only equals, in, not, notIn)`,
          );
      }
      return o;
    };
    return { [enc.indexField]: await cond(v) };
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
        if (typeof v !== "string") continue;
        if (isCiphertext(v)) {
          tasks.push(
            this.ctx(model.name, k).then((cx) => this.c.decrypt(cx, v)).then((p) => void (value[k] = p)),
          );
        } else if (this.opts.plaintext === "reject") {
          throw new CryplusPrismaError(`${model.name}.${k} holds a plaintext value but plaintext reads are rejected`);
        }
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

const NO_RESULT_DECRYPT = new Set(["count", "aggregate", "groupBy"]);

/** Build the Prisma Client extension definition (use with client.$extends). */
export function cryplusExtension(o: PrismaOptions) {
  const text = o.schemaText ?? (o.schemaPath ? readFileSync(o.schemaPath, "utf8") : undefined);
  if (!text) throw new CryplusPrismaError("provide schemaPath or schemaText");
  const schema = parseSchema(text);
  const active = hasEncryptedFields(schema);
  const topts = { plaintext: o.plaintext ?? "allow", hideIndexFields: o.hideIndexFields ?? true } as const;

  return {
    name: "cryplus",
    query: {
      $allModels: {
        async $allOperations({ model, operation, args, query }: { model: string; operation: string; args: any; query: (a: any) => Promise<any> }) {
          const m = schema.get(model);
          if (!active || !m) return query(args);

          let tenantP: Promise<string> | undefined;
          const resolveTenant = () =>
            (tenantP ??= (async () => {
              const t = (o.tenant ? await o.tenant({ model, operation, args }) : undefined) ?? currentTenant();
              if (!t) {
                throw new CryplusPrismaError(
                  `no tenant for ${model}.${operation}; wrap the call in withTenant("<id>", …) or pass a tenant resolver`,
                );
              }
              return t;
            })());
          const x = new Transformer(o.cryplus, schema, resolveTenant, topts);

          const a: any = { ...(args ?? {}) };
          if (a.where) a.where = await x.where(m, a.where);
          if (a.cursor) a.cursor = await x.where(m, a.cursor);
          x.checkOrder(m, a.orderBy);
          if (operation === "groupBy") {
            for (const f of [a.by].flat()) {
              if (typeof f === "string" && m.encrypted.has(f)) {
                throw new CryplusPrismaError(`cannot groupBy encrypted field ${model}.${f}`);
              }
            }
          }
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
}

/** Convenience: `const prisma = withCryplus(new PrismaClient(...), { cryplus, schemaPath })`. */
export function withCryplus<T extends { $extends: (ext: any) => any }>(client: T, opts: PrismaOptions): T {
  return client.$extends(cryplusExtension(opts)) as T;
}
