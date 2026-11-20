import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { applyNormalizers, hasEncryptedFields, parseSchema, type EncryptedField, type ModelInfo, type Schema } from "./schema.ts";
import { currentTenant } from "./tenant.ts";
import { createRawHelpers, rawGuardHooks, type RawGuardMode } from "./raw.ts";
import type { MetricsSink } from "./metrics.ts";
import { createTenantDeriver, type TenantDeriver, type TenantFromRule } from "./tenantfrom.ts";

export type { TenantFromRule } from "./tenantfrom.ts";
export type PlaintextPolicy = "allow" | "reject";
/** One policy for everything, or `{ default: "allow", Mensagem: "reject" }` for a staged rollout. */
export type PlaintextOption = PlaintextPolicy | ({ default?: PlaintextPolicy } & Record<string, PlaintextPolicy>);
/** Bind every ciphertext to its row: `off` (default), `on` (new writes are bound, legacy unbound values still read), `strict` (unbound values are refused). */
export type RowBinding = "off" | "on" | "strict";

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
  plaintext?: PlaintextOption;
  /**
   * Bind each ciphertext to the primary key of its row (it goes into the AAD), so that swapping the stored values of
   * two rows of the same tenant and field is detected instead of silently returning the other row's data.
   * Applies to models with a single `String` @id. Consequences, on purpose: the extension generates the id before encrypting
   * (`uuid()`/`cuid()` defaults), `update`/`upsert` that write an encrypted value must identify the row by `where: { id }`, and
   * `updateMany` cannot write an encrypted value (each row needs its own ciphertext; update by id). Turn it on, then run
   * `rotateModel({ rowBinding: "on" })` to bind existing rows, then switch to "strict". Default "off".
   */
  rowBinding?: RowBinding;
  /**
   * `"fallback"`: while a table is half-migrated, an equality filter `{ f: X }` is rewritten to
   * `OR [{ fIdx: idx(X) }, { f: X }]` so rows that are still plaintext are found too. Only equality (`equals`, `in`) is
   * supported in this mode; anything else on an encrypted field throws. Turn it off once the table is migrated.
   */
  legacy?: "off" | "fallback";
  /** Tenant for models without a tenant column, e.g. `{ Mensagem: { via: "conversaId", model: "Conversa" } }`. */
  tenantFrom?: Record<string, TenantFromRule>;
  /** Name of the tenant column (default `tenantId`). */
  tenantField?: string;
  /**
   * Derive the tenant of models that have a tenant column from `data.tenantId` / `where.tenantId` / `create.tenantId` (and, with only
   * `where: { id }`, by looking the row up) when no tenant is ambient. Default false, deliberately: the ambient tenant (withTenant) is what
   * makes a handler that forgot to set it FAIL instead of reading another tenant's data. Models listed in `tenantFrom` always derive.
   */
  tenantFromArgs?: boolean;
  /** Base Prisma client for tenantFrom lookups (set automatically by withCryplus). */
  lookupClient?: any;
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
  plaintext: PlaintextOption;
  hideIndexFields: boolean;
  rowBinding?: RowBinding;
  legacy?: "off" | "fallback";
}

type Strip = { self?: boolean; rel?: Record<string, Strip> };
type Write = { kind: "create"; id?: string } | { kind: "update"; rid?: string };

const B36 = "0123456789abcdefghijklmnopqrstuvwxyz";
const CROCK = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const URLSAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const pick = (alphabet: string, n: number) => Array.from(randomBytes(n), (b) => alphabet[b % alphabet.length]).join("");
/** Generate an id the way the schema's `@default(...)` would (Prisma generates them after our hook runs, so we must do it first). */
export function newId(kind: "uuid" | "cuid" | "ulid" | "nanoid"): string {
  if (kind === "uuid") return randomUUID();
  if (kind === "cuid") return "c" + Date.now().toString(36) + pick(B36, 25 - 1 - Date.now().toString(36).length);
  if (kind === "ulid") return pick(CROCK, 26);
  return pick(URLSAFE, 21);
}

export const plaintextPolicy = (p: PlaintextOption | undefined, model: string): PlaintextPolicy =>
  typeof p === "string" ? p : ((p as any)?.[model] ?? (p as any)?.default ?? "allow");

/** Row id from a `where` that selects exactly by primary key (`{ id: "x" }` or `{ id: { equals: "x" } }`). */
function idFromWhere(model: ModelInfo, where: unknown): string | undefined {
  if (!model.idField || !isPlainObject(where)) return undefined;
  const v = (where as any)[model.idField];
  if (typeof v === "string") return v;
  if (isPlainObject(v) && typeof (v as any).equals === "string" && Object.keys(v).length === 1) return (v as any).equals;
  return undefined;
}

export class Transformer {
  readonly c: CryptoLike;
  readonly schema: Schema;
  private resolveTenant: (model: string) => Promise<string>;
  readonly opts: TransformerOptions;
  /** ciphertext -> plaintext of values THIS operation just encrypted: reading them back after the write needs no decrypt call. */
  private known = new Map<string, string>();
  /** Conditions the rewriter itself produced on a plaintext column (legacy fallback); the post-rewrite check lets those through. */
  private trusted = new WeakSet<object>();

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

  /** Are this model's ciphertexts bound to the row id? */
  bound(model: ModelInfo): boolean {
    return (this.opts.rowBinding ?? "off") !== "off" && model.bindable;
  }

  // ---- primitives (also used by the raw-SQL helpers and migrations) ----------------

  async ctx(model: string, field: string, recordId?: string) {
    return { tenant: await this.resolveTenant(model), collection: model, field, ...(recordId !== undefined ? { recordId } : {}) };
  }

  async encryptScalar(model: ModelInfo, enc: EncryptedField, plain: string, rid?: string) {
    const bind = this.bound(model);
    if (bind && rid === undefined) {
      throw new CryplusPrismaError(`${model.name}.${enc.name}: rowBinding needs the row id to encrypt (write by id, or supply the id yourself)`);
    }
    const ct = await this.c.encrypt(await this.ctx(model.name, enc.name, bind ? rid : undefined), plain);
    this.known.set(ct, plain);
    return ct;
  }

  /**
   * Decrypt one stored value. With rowBinding the row id is part of the AAD: in "on" mode a value that does not open with the
   * id is tried without it (a row written before binding was switched on); in "strict" mode that is refused.
   */
  async decryptScalar(model: ModelInfo, enc: EncryptedField, ct: string, rid?: string): Promise<string> {
    return (await this.openScalar(model, enc, ct, rid)).plain;
  }

  async openScalar(model: ModelInfo, enc: EncryptedField, ct: string, rid?: string): Promise<{ plain: string; bound: boolean }> {
    const hit = this.known.get(ct);
    if (hit !== undefined) return { plain: hit, bound: this.bound(model) };
    const base = await this.ctx(model.name, enc.name);
    if (!this.bound(model)) return { plain: await this.c.decrypt(base, ct), bound: false };
    const strict = this.opts.rowBinding === "strict";
    if (rid === undefined) {
      if (strict) throw new CryplusPrismaError(`${model.name}.${enc.name}: rowBinding is strict and the row id is not available to decrypt (select the id column)`);
      return { plain: await this.c.decrypt(base, ct), bound: false };
    }
    try {
      return { plain: await this.c.decrypt({ ...base, recordId: rid }, ct), bound: true };
    } catch (e) {
      if (!strict && /decryption_failed/.test(String((e as Error)?.message))) return { plain: await this.c.decrypt(base, ct), bound: false };
      throw e;
    }
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

  /** App value -> stored value, for any supported kind. `rid` is the row id (needed when the model is bound). */
  async encryptValue(model: ModelInfo, enc: EncryptedField, v: unknown, rid?: string): Promise<unknown> {
    if (v === null || v === undefined) return v;
    const where = `${model.name}.${enc.name}`;
    if (enc.kind === "string") {
      if (typeof v !== "string") throw new CryplusPrismaError(`${where} is @encrypted and only accepts string values`);
      if (isCiphertext(v)) throw new CryplusPrismaError(`${where}: refusing to store a value that already looks like ciphertext`);
      return this.encryptScalar(model, enc, v, rid);
    }
    if (enc.kind === "string[]") {
      if (!Array.isArray(v) || v.some((e) => typeof e !== "string")) {
        throw new CryplusPrismaError(`${where} is an encrypted String[] and only accepts arrays of strings`);
      }
      return Promise.all(v.map((e) => this.encryptScalar(model, enc, e, rid)));
    }
    // json: stored as an encrypted JSON string
    return this.encryptScalar(model, enc, JSON.stringify(v), rid);
  }

  /** Stored value -> app value. Plaintext found where ciphertext is expected follows the `plaintext` policy. */
  async decryptValue(model: ModelInfo, enc: EncryptedField, v: unknown, rid?: string): Promise<unknown> {
    const where = `${model.name}.${enc.name}`;
    const legacy = (x: unknown) => {
      if (plaintextPolicy(this.opts.plaintext, model.name) === "reject") throw new CryplusPrismaError(`${where} holds a plaintext value but plaintext reads are rejected`);
      return x;
    };
    if (v === null || v === undefined) return v;
    if (enc.kind === "string") {
      if (typeof v !== "string") return v;
      return isCiphertext(v) ? this.decryptScalar(model, enc, v, rid) : legacy(v);
    }
    if (enc.kind === "string[]") {
      if (!Array.isArray(v)) return v;
      return Promise.all(v.map((e) => (isCiphertext(e) ? this.decryptScalar(model, enc, e, rid) : legacy(e))));
    }
    if (isCiphertext(v)) return JSON.parse(await this.decryptScalar(model, enc, v, rid));
    return legacy(v);
  }

  // ---- writes --------------------------------------------------------------

  /** The id a created row will have: the one supplied, or one generated the way the schema's default would. */
  private createId(model: ModelInfo, d: Record<string, any>, forced?: string): { id?: string; generated: boolean } {
    if (!this.bound(model) || !model.idField) return { generated: false };
    const cur = d[model.idField];
    if (typeof cur === "string") return { id: cur, generated: false };
    if (cur !== undefined) return { generated: false };
    if (forced) return { id: forced, generated: true };
    const kind = model.fields.get(model.idField)?.idDefault;
    if (kind === "uuid" || kind === "cuid" || kind === "ulid" || kind === "nanoid") return { id: newId(kind), generated: true };
    return { generated: false };
  }

  async data(model: ModelInfo, data: any, w: Write = { kind: "create" }): Promise<any> {
    if (Array.isArray(data)) return Promise.all(data.map((d) => this.data(model, d, w)));
    if (!isPlainObject(data)) return data;
    let rid: string | undefined;
    let generated: string | undefined;
    if (w.kind === "create") {
      const r = this.createId(model, data, w.id);
      rid = r.id;
      if (r.generated) generated = r.id;
    } else rid = w.rid;
    const out: Record<string, any> = {};
    const tasks: Promise<void>[] = [];
    for (const [k, v] of Object.entries(data)) {
      if (model.indexFields.has(k)) {
        throw new CryplusPrismaError(`${model.name}.${k} is managed automatically; do not set it`);
      }
      const enc = model.encrypted.get(k);
      const rel = model.fields.get(k)?.relation;
      if (enc) {
        tasks.push(this.encryptField(model, enc, v, out, rid));
      } else if (rel && isPlainObject(v)) {
        tasks.push(this.nested(this.model(rel), v).then((r) => void (out[k] = r)));
      } else {
        out[k] = v;
      }
    }
    await Promise.all(tasks);
    if (generated !== undefined && model.idField) out[model.idField] = generated;
    return out;
  }

  private async encryptField(model: ModelInfo, enc: EncryptedField, v: unknown, out: Record<string, any>, rid?: string) {
    if (v === undefined) return;
    const where = `${model.name}.${enc.name}`;
    const needId = () => {
      if (this.bound(model) && rid === undefined) {
        throw new CryplusPrismaError(
          `${where}: rowBinding is on, so this write must identify the row: use update/upsert with where: { ${model.idField} }, or create with an id. ` +
            `(updateMany cannot write an encrypted value because every row needs its own ciphertext.)`,
        );
      }
    };

    if (enc.kind === "string") {
      const wrapped = isPlainObject(v) && Object.keys(v).length === 1 && "set" in v;
      const raw = wrapped ? (v as any).set : v;
      if (raw === undefined) return;
      if (raw === null) {
        out[enc.name] = wrapped ? { set: null } : null;
        Object.assign(out, await this.indexesFor(model, enc, null));
        return;
      }
      needId();
      const [ct, idx] = await Promise.all([this.encryptValue(model, enc, raw, rid), this.indexesFor(model, enc, raw as string)]);
      out[enc.name] = wrapped ? { set: ct } : ct;
      Object.assign(out, idx);
      return;
    }

    if (enc.kind === "string[]") {
      if (v === null) {
        out[enc.name] = null;
        return;
      }
      needId();
      if (Array.isArray(v)) {
        out[enc.name] = await this.encryptValue(model, enc, v, rid);
      } else if (isPlainObject(v) && Object.keys(v).length === 1 && "set" in v) {
        out[enc.name] = { set: await this.encryptValue(model, enc, (v as any).set, rid) };
      } else if (isPlainObject(v) && Object.keys(v).length === 1 && "push" in v) {
        const p = (v as any).push;
        out[enc.name] = { push: await this.encryptValue(model, enc, Array.isArray(p) ? p : [p], rid) };
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
      needId();
      out[enc.name] = await this.encryptValue(model, enc, v, rid);
    }
  }

  private async nested(target: ModelInfo, v: Record<string, any>): Promise<Record<string, any>> {
    const out: Record<string, any> = {};
    const creating = (where: any) => ({ kind: "create", id: idFromWhere(target, where) }) as Write;
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
            create: await this.data(target, e.create, creating(e.where)),
          }));
          break;
        case "update":
          out[k] = await maybeArray(val, (e: any) => this.updateEntry(target, e));
          break;
        case "updateMany":
          out[k] = await maybeArray(val, async (e: any) => ({
            ...e,
            where: await this.where(target, e.where),
            data: await this.data(target, e.data, { kind: "update" }),
          }));
          break;
        case "upsert":
          out[k] = await maybeArray(val, async (e: any) => ({
            ...e,
            ...(e.where ? { where: await this.where(target, e.where) } : {}),
            create: await this.data(target, e.create, creating(e.where)),
            update: await this.data(target, e.update, { kind: "update", rid: idFromWhere(target, e.where) }),
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
        data: await this.data(target, e.data, { kind: "update", rid: idFromWhere(target, e.where) }),
      };
    }
    return this.data(target, e, { kind: "update" });
  }

  // ---- filters -------------------------------------------------------------

  /** Rewrite a filter on `model`. Anything that touches an encrypted field is rewritten or refused: nothing passes through untouched. */
  async where(model: ModelInfo, where: any): Promise<any> {
    if (Array.isArray(where)) return Promise.all(where.filter((w) => w !== undefined).map((w) => this.where(model, w)));
    if (!isPlainObject(where)) return where;
    const out: Record<string, any> = {};
    const extra: any[] = [];
    for (const [k, v] of Object.entries(where)) {
      if (v === undefined) continue; // Prisma: undefined means "no filter"
      if (k === "AND" || k === "OR" || k === "NOT") {
        out[k] = await this.where(model, v);
        continue;
      }
      const enc = model.encrypted.get(k);
      if (enc) {
        Object.assign(out, await this.encCondition(model, enc, v, extra));
        continue;
      }
      // compound unique key (findUnique / upsert / update by `tenantId_cpf`) whose uniqueness lives on the blind index
      const cu = model.compound.get(k);
      if (cu && isPlainObject(v)) {
        const inner: Record<string, any> = {};
        for (const [f, val] of Object.entries(v)) {
          if (val === undefined) continue;
          const e = model.encrypted.get(f);
          if (e) Object.assign(inner, await this.encCondition(model, e, val, undefined));
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
          for (const kk of ks) if ((v as any)[kk] !== undefined) o[kk] = await this.where(target, (v as any)[kk]);
          out[k] = o;
        } else {
          out[k] = await this.where(target, v);
        }
        continue;
      }
      out[k] = v;
    }
    if (extra.length) out.AND = [...(out.AND === undefined ? [] : Array.isArray(out.AND) ? out.AND : [out.AND]), ...extra];
    return out;
  }

  /**
   * Last line of defence: walk a filter AFTER rewriting and refuse it if a condition on an encrypted column is still there.
   * (Only `null` and `isEmpty` legitimately stay on the encrypted column itself.) A bug in the rewriter, or a shape it does not
   * know, therefore fails loudly instead of comparing plaintext with ciphertext and quietly matching the wrong rows.
   */
  assertRewritten(model: ModelInfo, where: unknown, path = model.name): void {
    if (Array.isArray(where)) return where.forEach((w, i) => this.assertRewritten(model, w, `${path}[${i}]`));
    if (!isPlainObject(where) || this.trusted.has(where)) return;
    for (const [k, v] of Object.entries(where)) {
      if (v === undefined) continue;
      if (k === "AND" || k === "OR" || k === "NOT") {
        this.assertRewritten(model, v, `${path}.${k}`);
        continue;
      }
      const enc = model.encrypted.get(k);
      if (enc) {
        const ok = v === null || (isPlainObject(v) && Object.keys(v).length === 1 && ("isEmpty" in v || ("equals" in v && v.equals === null)));
        if (!ok) throw new CryplusPrismaError(`${path}.${k}: filter on an encrypted field was not rewritten (internal check); refusing to send it`);
        continue;
      }
      const rel = model.fields.get(k)?.relation;
      if (rel && isPlainObject(v)) {
        const target = this.model(rel);
        for (const [kk, vv] of Object.entries(v)) {
          if (["some", "every", "none", "is", "isNot"].includes(kk)) this.assertRewritten(target, vv, `${path}.${k}.${kk}`);
          else this.assertRewritten(target, { [kk]: vv }, `${path}.${k}`);
        }
      }
    }
  }

  private legacyCond<T extends object>(c: T): T {
    this.trusted.add(c);
    return c;
  }

  private async encCondition(model: ModelInfo, enc: EncryptedField, v: any, extra: any[] | undefined): Promise<Record<string, any>> {
    const where = `${model.name}.${enc.name}`;
    if (v === undefined) return {};
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

    // legacy window: rows that are still plaintext have no index yet, so also match the plaintext column
    if (this.opts.legacy === "fallback" && extra) {
      const ops = isPlainObject(v) ? Object.entries(v).filter(([, x]) => x !== undefined) : ([["equals", v]] as [string, unknown][]);
      if (ops.length === 0) return {};
      const bad = ops.find(([op, x]) => !(op === "equals" || op === "in") || (op === "equals" && x === null));
      if (bad) {
        throw new CryplusPrismaError(
          `${where}: legacy "fallback" supports only equality (equals, in) on encrypted fields (got ${bad[0]}); finish the migration (migrateModel) or filter on something else`,
        );
      }
      for (const [op, x] of ops) {
        if (op === "equals") {
          if (typeof x !== "string") throw new CryplusPrismaError(`${where}: filter values must be strings`);
          extra.push({ OR: [{ [col]: await bi(x) }, this.legacyCond({ [enc.name]: x })] });
        } else {
          const list = x as unknown[];
          if (!Array.isArray(list)) throw new CryplusPrismaError(`${where}: "in" needs an array`);
          extra.push({ OR: [{ [col]: { in: await Promise.all(list.map(bi)) } }, this.legacyCond({ [enc.name]: { in: list } })] });
        }
      }
      return {};
    }

    const cond = async (x: any): Promise<any> => {
      if (x === null) return null;
      if (typeof x === "string") return bi(x);
      if (!isPlainObject(x)) throw new CryplusPrismaError(`${where}: unsupported filter`);
      const o: Record<string, any> = {};
      for (const [op, val] of Object.entries(x)) {
        if (val === undefined) continue; // Prisma ignores undefined operands
        if (op === "equals" || op === "not") o[op] = await cond(val);
        else if (op === "in" || op === "notIn") {
          if (!Array.isArray(val)) throw new CryplusPrismaError(`${where}: "${op}" needs an array`);
          o[op] = await Promise.all(val.map(bi));
        } else
          throw new CryplusPrismaError(
            `operator "${op}" is not supported on encrypted field ${where} (only equals, in, not, notIn${enc.suffixes.length ? ", endsWith" : ""})`,
          );
      }
      return o;
    };
    return { [col]: await cond(v) };
  }

  /** Walk select/include so filters inside nested relations (and in `_count`) are rewritten too. */
  async selection(model: ModelInfo, sel: any): Promise<any> {
    if (!isPlainObject(sel)) return sel;
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(sel)) {
      if (k === "_count") {
        out[k] = await this.countSelection(model, v);
        continue;
      }
      const rel = model.fields.get(k)?.relation;
      if (rel && isPlainObject(v)) {
        const target = this.model(rel);
        const o: Record<string, any> = { ...v };
        if (v.where) o.where = await this.where(target, v.where);
        if (v.cursor) o.cursor = await this.where(target, v.cursor);
        this.checkOrder(target, v.orderBy);
        if (v.distinct && (Array.isArray(v.distinct) ? v.distinct : [v.distinct]).some((f: string) => target.encrypted.has(f))) {
          throw new CryplusPrismaError(`cannot use distinct on an encrypted field of ${target.name}`);
        }
        if (v.select) o.select = await this.selection(target, v.select);
        if (v.include) o.include = await this.selection(target, v.include);
        out[k] = o;
      } else {
        out[k] = v;
      }
    }
    return out;
  }

  private async countSelection(model: ModelInfo, v: any): Promise<any> {
    if (!isPlainObject(v) || !isPlainObject(v.select)) return v;
    const sel: Record<string, any> = {};
    for (const [rel, rv] of Object.entries(v.select)) {
      const target = model.fields.get(rel)?.relation;
      sel[rel] = target && isPlainObject(rv) && rv.where ? { ...rv, where: await this.where(this.model(target), rv.where) } : rv;
    }
    return { ...v, select: sel };
  }

  checkOrder(model: ModelInfo, orderBy: any) {
    if (!orderBy) return;
    for (const o of Array.isArray(orderBy) ? orderBy : [orderBy]) {
      if (!isPlainObject(o)) continue;
      for (const [k, v] of Object.entries(o)) {
        if (model.encrypted.has(k)) {
          throw new CryplusPrismaError(`cannot order by encrypted field ${model.name}.${k}; ciphertext order is meaningless`);
        }
        const rel = model.fields.get(k)?.relation;
        if (rel && isPlainObject(v)) this.checkOrder(this.model(rel), v);
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

  /**
   * With rowBinding the row id is needed to decrypt. When the caller `select`s fields without it, ask for it and
   * remember where, so it can be removed again afterwards. Mutates `args` (a copy owned by the extension).
   */
  injectIds(model: ModelInfo, args: any): Strip | undefined {
    if (!isPlainObject(args)) return undefined;
    const strip: Strip = {};
    let any = false;
    for (const key of ["select", "include"] as const) {
      const sel = args[key];
      if (!isPlainObject(sel)) continue;
      const copy: Record<string, any> = { ...sel };
      args[key] = copy;
      if (key === "select" && this.bound(model) && model.idField && [...model.encrypted.keys()].some((f) => copy[f]) && !copy[model.idField]) {
        copy[model.idField] = true;
        strip.self = true;
        any = true;
      }
      for (const [k, v] of Object.entries(copy)) {
        const rel = model.fields.get(k)?.relation;
        if (!rel || !isPlainObject(v)) continue;
        const o = { ...v };
        const sub = this.injectIds(this.model(rel), o);
        copy[k] = o;
        if (sub) {
          (strip.rel ??= {})[k] = sub;
          any = true;
        }
      }
    }
    return any ? strip : undefined;
  }

  applyStrip(model: ModelInfo, value: any, strip: Strip | undefined) {
    if (!strip || value === null || typeof value !== "object") return;
    if (Array.isArray(value)) return value.forEach((v) => this.applyStrip(model, v, strip));
    if (strip.self && model.idField) delete value[model.idField];
    for (const [k, sub] of Object.entries(strip.rel ?? {})) {
      const rel = model.fields.get(k)?.relation;
      if (rel) this.applyStrip(this.model(rel), value[k], sub);
    }
  }

  async result(model: ModelInfo, value: any): Promise<any> {
    if (Array.isArray(value)) {
      await Promise.all(value.map((v) => this.result(model, v)));
      return value;
    }
    if (!isPlainObject(value)) return value;
    const rid = this.bound(model) && model.idField && typeof value[model.idField] === "string" ? (value[model.idField] as string) : undefined;
    const tasks: Promise<void>[] = [];
    for (const k of Object.keys(value)) {
      const v = value[k];
      const enc = model.encrypted.get(k);
      if (enc) {
        tasks.push(this.decryptValue(model, enc, v, rid).then((p) => void (value[k] = p)));
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
export function makeTenantResolver(o: PrismaOptions, deriver?: TenantDeriver) {
  return (forModel: string, operation = "raw", args: any = undefined, opModel?: string): Promise<string> =>
    (async () => {
      const t =
        (o.tenant ? await o.tenant({ model: forModel, operation, args }) : undefined) ??
        currentTenant() ??
        (deriver ? await deriver(forModel, opModel ?? forModel, args) : undefined);
      if (!t) {
        throw new CryplusPrismaError(
          `no tenant for ${forModel} (${operation}); wrap the call in withTenant("<id>", …), declare tenantFrom for this model, or pass a tenant resolver`,
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
  const topts: TransformerOptions = {
    plaintext: o.plaintext ?? "allow",
    hideIndexFields: o.hideIndexFields ?? true,
    rowBinding: o.rowBinding ?? "off",
    legacy: o.legacy ?? "off",
  };
  const deriver = createTenantDeriver(schema, { tenantFrom: o.tenantFrom, tenantField: o.tenantField, fromArgs: o.tenantFromArgs, client: () => o.lookupClient });
  const resolver = makeTenantResolver(o, deriver);
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
              p = resolver(forModel, `${model}.${operation}`, args, model);
              tenants.set(forModel, p);
            }
            return p;
          };
          const x = new Transformer(o.cryplus, schema, resolveTenant, topts);

          const a: any = { ...(args ?? {}) };
          // ids that identify the row being written (needed to bind ciphertexts to it); read BEFORE the filter is rewritten
          const whereId = idFromWhere(m, a.where);
          if (a.where) a.where = await x.where(m, a.where);
          if (a.cursor) a.cursor = await x.where(m, a.cursor);
          if (a.having) x.assertRewritten(m, a.having);
          x.checkOrder(m, a.orderBy);
          if (operation === "aggregate" || operation === "groupBy") x.checkAggregate(m, operation, a);
          if (Array.isArray(a.distinct) ? a.distinct.some((f: string) => m.encrypted.has(f)) : m.encrypted.has(a.distinct)) {
            throw new CryplusPrismaError(`cannot use distinct on an encrypted field of ${model}`);
          }
          if (a.select) a.select = await x.selection(m, a.select);
          if (a.include) a.include = await x.selection(m, a.include);
          if (a._count && isPlainObject(a._count)) a._count = await x.selection(m, { _count: a._count }).then((r: any) => r._count);
          const strip = x.injectIds(m, a);

          switch (operation) {
            case "create":
            case "createMany":
            case "createManyAndReturn":
              if (a.data) a.data = await x.data(m, a.data, { kind: "create" });
              break;
            case "update":
              if (a.data) a.data = await x.data(m, a.data, { kind: "update", rid: whereId });
              break;
            case "updateMany":
            case "updateManyAndReturn":
              if (a.data) a.data = await x.data(m, a.data, { kind: "update" });
              break;
            case "upsert":
              if (a.create) a.create = await x.data(m, a.create, { kind: "create", id: whereId });
              if (a.update) a.update = await x.data(m, a.update, { kind: "update", rid: whereId });
              break;
          }

          // fail closed: nothing that still conditions on an encrypted column may reach the database
          x.assertRewritten(m, a.where);
          x.assertRewritten(m, a.cursor);

          const res = await query(a);
          if (NO_RESULT_DECRYPT.has(operation)) return res;
          const out = await x.result(m, res);
          x.applyStrip(m, out, strip);
          return out;
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
  // `client` is the base client: tenantFrom lookups go through it (plain columns only, no decryption needed)
  return client.$extends(cryplusExtension({ lookupClient: client, ...opts })) as T;
}
