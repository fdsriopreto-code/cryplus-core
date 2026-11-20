import { analyzeSql, sqlTextOf } from "./sqlscan.ts";
import type { CryptoLike, TransformerOptions } from "./prisma.ts";
import { CryplusPrismaError, Transformer } from "./prisma.ts";
import type { EncryptedField, ModelInfo, Schema } from "./schema.ts";

export type RawGuardMode = "throw" | "warn" | "off";

const RAW_OPS = ["$queryRaw", "$queryRawUnsafe", "$executeRaw", "$executeRawUnsafe"] as const;

/**
 * Query hooks that look at raw SQL before it runs. If the text mentions an encrypted column of an encrypted
 * table (and is not marked `cryplus:handled`), it is refused (or logged), because raw SQL sees ciphertext and
 * writes plaintext: both are silent data bugs.
 */
export function rawGuardHooks(schema: Schema, mode: RawGuardMode) {
  if (mode === "off") return {};
  const hooks: Record<string, (p: { args: any; query: (a: any) => Promise<any>; operation?: string }) => Promise<any>> = {};
  for (const op of RAW_OPS) {
    hooks[op] = async ({ args, query }) => {
      const sql = sqlTextOf(args);
      if (sql !== undefined) {
        const findings = analyzeSql(schema, sql);
        if (findings.length) {
          const msg =
            `raw SQL touches encrypted data: ` +
            findings.map((f) => `${f.model} (${f.table}): ${f.reason}`).join("; ") +
            `. Use the Prisma model API, or $cryplus.decryptRows / $cryplus.index / $cryplus.encryptValue and add /* cryplus:handled */ to the SQL.`;
          if (mode === "throw") throw new CryplusPrismaError(msg);
          console.warn("cryplus: " + msg);
        }
      }
      return query(args);
    };
  }
  return hooks;
}

export interface RawTenantOpt {
  /** Tenant to use instead of the resolver / ambient tenant. */
  tenant?: string;
  /** Primary key of the row (required to encrypt/decrypt for a model bound with `rowBinding`). */
  recordId?: string;
}

function findField(model: ModelInfo, nameOrColumn: string): EncryptedField | undefined {
  const direct = model.encrypted.get(nameOrColumn);
  if (direct) return direct;
  for (const e of model.encrypted.values()) if (e.dbName === nameOrColumn) return e;
  return undefined;
}

/**
 * Helpers for the places raw SQL cannot be avoided. Exposed on the extended client as `prisma.$cryplus`.
 */
export function createRawHelpers(c: CryptoLike, schema: Schema, resolveTenant: (model: string) => Promise<string>, topts: TransformerOptions) {
  const tx = (override?: string) => new Transformer(c, schema, override ? async () => override : resolveTenant, topts);
  const target = (model: string, field: string) => {
    const m = schema.get(model);
    if (!m) throw new CryplusPrismaError(`unknown model ${model}`);
    const e = findField(m, field);
    if (!e) throw new CryplusPrismaError(`${model}.${field} is not an @encrypted field`);
    return { m, e };
  };

  return {
    /**
     * Blind-index value to use in a raw `WHERE <field>Idx = $1` (or the column returned for `global` / `suffix`).
     * Default: the per-tenant equality index. `{ global: true }` uses the platform-scoped index (cross-tenant equality
     * becomes visible: use only for lookups made before the tenant is known). `{ suffix: n }` the suffix(n) index.
     */
    async index(model: string, field: string, value: string, opts: RawTenantOpt & { global?: boolean; suffix?: number } = {}): Promise<string | null> {
      const { m, e } = target(model, field);
      if (opts.global) {
        if (!e.globalIndexField) throw new CryplusPrismaError(`${model}.${field} has no @encrypted(global) index`);
        return tx(opts.tenant).indexOf(m, e, value, "global");
      }
      if (opts.suffix !== undefined) {
        if (!e.suffixes.some((s) => s.n === opts.suffix)) throw new CryplusPrismaError(`${model}.${field} has no suffix(${opts.suffix}) index`);
        return tx(opts.tenant).indexOf(m, e, value, { suffix: opts.suffix });
      }
      if (!e.indexField) throw new CryplusPrismaError(`${model}.${field} is not @encrypted(searchable)`);
      return tx(opts.tenant).indexOf(m, e, value, "tenant");
    },

    /** Value to write into the column in a raw INSERT/UPDATE (the app value in, the stored value out). */
    async encryptValue(model: string, field: string, value: unknown, opts: RawTenantOpt = {}): Promise<unknown> {
      const { m, e } = target(model, field);
      return tx(opts.tenant).encryptValue(m, e, value, opts.recordId);
    },

    /** All index column values that must be written together with the encrypted column. */
    async indexColumns(model: string, field: string, value: string | null, opts: RawTenantOpt = {}): Promise<Record<string, string | null>> {
      const { m, e } = target(model, field);
      return tx(opts.tenant).indexesFor(m, e, value);
    },

    async decryptValue(model: string, field: string, stored: unknown, opts: RawTenantOpt = {}): Promise<unknown> {
      const { m, e } = target(model, field);
      return tx(opts.tenant).decryptValue(m, e, stored, opts.recordId);
    },

    /**
     * Decrypt encrypted columns in rows returned by a raw SELECT. Columns are matched by Prisma field name or database
     * column name; use `columns` to map an alias: `{ columns: { secret_value: "secret" } }`. Batched, tenant-aware.
     * Rows are modified in place and returned.
     */
    async decryptRows<T extends Record<string, any>>(model: string, rows: T[], opts: RawTenantOpt & { columns?: Record<string, string> } = {}): Promise<T[]> {
      const m = schema.get(model);
      if (!m) throw new CryplusPrismaError(`unknown model ${model}`);
      const t = tx(opts.tenant);
      const tasks: Promise<void>[] = [];
      const idField = m.idField ? m.fields.get(m.idField) : undefined;
      for (const row of rows) {
        // with rowBinding the primary key is part of what was encrypted: it must be in the row (select it)
        const idKey = Object.keys(row).find((k) => (opts.columns?.[k] ?? k) === idField?.name || (opts.columns?.[k] ?? k) === idField?.dbName);
        const rid = idKey && typeof row[idKey] === "string" ? (row[idKey] as string) : undefined;
        for (const key of Object.keys(row)) {
          const e = findField(m, opts.columns?.[key] ?? key);
          if (!e) continue;
          tasks.push(t.decryptValue(m, e, row[key], rid).then((p) => void ((row as any)[key] = p)));
        }
      }
      await Promise.all(tasks);
      return rows;
    },

    /**
     * Substring / arbitrary search over encrypted fields: page through a candidate set (narrowed by `where` on
     * non-encrypted columns, e.g. the conversation id), decrypt it, and filter in memory. Refuses to scan more than
     * `maxScan` rows so a missing `where` cannot read a whole table. `delegate` is a model delegate of the EXTENDED
     * client (`prisma.mensagem`), so rows arrive decrypted.
     */
    async searchDecrypted<T = any>(
      delegate: { findMany(args: any): Promise<T[]> },
      model: string,
      opts: { where: any; predicate: (row: T) => boolean; limit?: number; maxScan?: number; pageSize?: number; orderBy?: any; select?: any },
    ): Promise<T[]> {
      const m = schema.get(model);
      if (!m || !m.idField) throw new CryplusPrismaError(`searchDecrypted needs model ${model} with a single @id`);
      if (!opts.where || typeof opts.where !== "object" || Object.keys(opts.where).length === 0) {
        throw new CryplusPrismaError("searchDecrypted needs a non-empty `where` (it decrypts and scans every candidate row)");
      }
      const limit = opts.limit ?? 50;
      const maxScan = opts.maxScan ?? 5000;
      const pageSize = Math.min(opts.pageSize ?? 500, maxScan);
      const idField = m.idField;
      const hits: T[] = [];
      let scanned = 0;
      let cursor: unknown;
      for (;;) {
        const page: any[] = await delegate.findMany({
          where: opts.where,
          orderBy: opts.orderBy ?? { [idField]: "asc" },
          take: pageSize,
          ...(opts.select ? { select: { ...opts.select, [idField]: true } } : {}),
          ...(cursor !== undefined ? { skip: 1, cursor: { [idField]: cursor } } : {}),
        });
        for (const row of page) {
          if (opts.predicate(row)) hits.push(row);
          if (hits.length >= limit) return hits;
        }
        scanned += page.length;
        if (page.length < pageSize) return hits;
        if (scanned >= maxScan) {
          throw new CryplusPrismaError(`searchDecrypted scanned ${scanned} rows without finishing; narrow \`where\` or raise maxScan deliberately`);
        }
        cursor = page[page.length - 1][idField];
      }
    },
  };
}

export type RawHelpers = ReturnType<typeof createRawHelpers>;
