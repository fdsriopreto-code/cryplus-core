import type { CryplusApi } from "./client.ts";
import { isCiphertext, Transformer } from "./prisma.ts";
import type { EncryptedField, ModelInfo, Schema } from "./schema.ts";

export interface MigrateOptions {
  model: string;
  /** Tenant owning a row (e.g. row => row.organizationId). */
  tenantOf: (row: any) => string | Promise<string>;
  batchSize?: number;
  /** Compute what would change without writing. */
  dryRun?: boolean;
  /**
   * `all` (default): encrypt plaintext, re-wrap ciphertexts on an old KEK version, backfill index columns.
   * `rewrap-only`: only move ciphertexts to the current KEK version (key rotation, see rotateModel).
   * `index-only`: only fill missing index columns (after adding a searchable/suffix/global option to a column that is already encrypted).
   */
  mode?: "all" | "rewrap-only" | "index-only";
  /** Sleep this long after every batch, so a migration can run next to real traffic (default 0). */
  throttleMs?: number;
  /** After writing a row, read it back and check that every changed field decrypts to the value we meant to store. */
  verify?: boolean;
  /** Resume: only rows after this id (use `lastId` from a previous run). */
  startAfter?: unknown;
  /** Stop after this many failures instead of scanning the whole table (default: never). */
  maxFailures?: number;
  onProgress?: (s: MigrateStats) => void;
}

export interface MigrateStats {
  scanned: number;
  encrypted: number; // plaintext values that were encrypted
  rewrapped: number; // ciphertexts moved to the current KEK version
  indexed: number; // fields whose missing index columns were filled in
  verified: number; // fields confirmed by the read-back
  failures: { id: unknown; field: string; error: string }[];
  /** Id of the last row scanned: pass it as `startAfter` to resume. */
  lastId?: unknown;
  /** True when the run stopped early because of maxFailures. */
  aborted?: boolean;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function lookup(schema: Schema, prisma: any, name: string): { model: ModelInfo; delegate: any; idField: string } {
  const model = schema.get(name);
  if (!model) throw new Error(`cryplus: unknown model ${name}`);
  if (!model.encrypted.size) throw new Error(`cryplus: model ${name} has no @encrypted fields`);
  const idField = model.idField;
  if (!idField) throw new Error(`cryplus: model ${name} needs a single-column @id for migration`);
  const delegate = prisma[name.charAt(0).toLowerCase() + name.slice(1)];
  if (!delegate) throw new Error(`cryplus: prisma client has no delegate for ${name}`);
  return { model, delegate, idField };
}

/**
 * Bring a table in line with the schema: encrypt existing plaintext in @encrypted columns, re-wrap ciphertexts still on an
 * old KEK version, and backfill blind-index columns (equality, suffix and global). Idempotent and resumable: run it again
 * any time, e.g. after cryplus.rotateKeys().
 *
 * Pass the BASE Prisma client (not the one with the cryplus extension), so values are read and written raw.
 * Run it in batches during business hours with `throttleMs`; every failure is listed per row and field, never swallowed.
 */
export async function migrateModel(prisma: any, cryplus: CryplusApi, schema: Schema, o: MigrateOptions): Promise<MigrateStats> {
  const { model, delegate, idField } = lookup(schema, prisma, o.model);
  const mode = o.mode ?? "all";
  const stats: MigrateStats = { scanned: 0, encrypted: 0, rewrapped: 0, indexed: 0, verified: 0, failures: [], lastId: o.startAfter };
  const batch = o.batchSize ?? 200;
  let cursor: unknown = o.startAfter;

  for (;;) {
    const rows: any[] = await delegate.findMany({
      take: batch,
      orderBy: { [idField]: "asc" },
      ...(cursor !== undefined ? { skip: 1, cursor: { [idField]: cursor } } : {}),
    });
    if (rows.length === 0) break;

    const updates = await Promise.all(rows.map((row) => planRow(row)));
    if (!o.dryRun) {
      for (const u of updates) {
        if (!u) continue;
        await delegate.update({ where: { [idField]: u.id }, data: u.data });
        if (o.verify) await verifyRow(u);
      }
    }
    stats.scanned += rows.length;
    cursor = rows[rows.length - 1][idField];
    stats.lastId = cursor;
    o.onProgress?.(stats);
    if (o.maxFailures !== undefined && stats.failures.length >= o.maxFailures) {
      stats.aborted = true;
      break;
    }
    if (rows.length < batch) break;
    if (o.throttleMs) await sleep(o.throttleMs);
  }
  return stats;

  // ---- one row: decide what to write ------------------------------------------------------------

  async function planRow(row: any): Promise<{ id: unknown; data: Record<string, unknown>; expect: Record<string, unknown>; tenant: string } | null> {
    let tenant: string;
    try {
      tenant = await o.tenantOf(row);
    } catch (e) {
      stats.failures.push({ id: row[idField], field: "*", error: "tenantOf: " + (e as Error).message });
      return null;
    }
    const tr = new Transformer(cryplus, schema, async () => tenant, { plaintext: "allow", hideIndexFields: false });
    const data: Record<string, unknown> = {};
    const expect: Record<string, unknown> = {}; // field -> plaintext we expect to read back
    for (const enc of model.encrypted.values()) {
      const v = row[enc.name];
      if (v === null || v === undefined) continue;
      try {
        await planField(tr, tenant, row, enc, v, data, expect);
      } catch (e) {
        stats.failures.push({ id: row[idField], field: enc.name, error: (e as Error).message });
      }
    }
    return Object.keys(data).length ? { id: row[idField], data, expect, tenant } : null;
  }

  async function planField(tr: Transformer, tenant: string, row: any, enc: EncryptedField, v: unknown, data: Record<string, unknown>, expect: Record<string, unknown>) {
    const ctx = { tenant, collection: model.name, field: enc.name };
    const wantEncrypt = mode === "all";
    const wantRewrap = mode === "all" || mode === "rewrap-only";
    const wantIndex = mode === "all" || mode === "index-only";

    if (enc.kind === "string") {
      if (typeof v !== "string") return;
      let plain: string | undefined;
      let wroteNew = false;
      if (!isCiphertext(v)) {
        if (!wantEncrypt) return;
        plain = v;
        data[enc.name] = await tr.encryptValue(model, enc, v);
        stats.encrypted++;
        wroteNew = true;
      } else if (wantRewrap) {
        const r = await cryplus.rewrap(ctx, v);
        if (r.changed) {
          data[enc.name] = r.ciphertext;
          stats.rewrapped++;
        }
      }
      const cols = [enc.indexField, enc.globalIndexField, ...enc.suffixes.map((s) => s.field)].filter((c): c is string => !!c);
      if (wantIndex && cols.length) {
        const missing = cols.filter((c) => row[c] === null || row[c] === undefined);
        // Short values legitimately have no suffix index; only a missing equality/global index is always a gap.
        if (wroteNew || missing.length) {
          plain ??= await tr.decryptScalar(model, enc, v);
          const idx = await tr.indexesFor(model, enc, plain);
          let wrote = false;
          for (const c of cols) {
            const next = idx[c] ?? null;
            if (wroteNew || (row[c] === null || row[c] === undefined ? next !== null : false)) {
              data[c] = next;
              wrote = true;
            }
          }
          if (wrote && !wroteNew) stats.indexed++;
        }
      }
      if (plain !== undefined && (data[enc.name] !== undefined || wroteNew)) expect[enc.name] = plain;
      return;
    }

    if (enc.kind === "string[]") {
      if (!Array.isArray(v)) return;
      let changed = false;
      const out: string[] = [];
      for (const el of v as unknown[]) {
        if (typeof el !== "string") {
          out.push(el as any);
          continue;
        }
        if (!isCiphertext(el)) {
          if (!wantEncrypt) {
            out.push(el);
            continue;
          }
          out.push(await tr.encryptScalar(model, enc, el));
          changed = true;
          stats.encrypted++;
        } else if (wantRewrap) {
          const r = await cryplus.rewrap(ctx, el);
          out.push(r.ciphertext);
          if (r.changed) {
            changed = true;
            stats.rewrapped++;
          }
        } else out.push(el);
      }
      if (changed) {
        data[enc.name] = out;
        expect[enc.name] = await Promise.all(out.map((x) => (isCiphertext(x) ? cryplus.decrypt(ctx, x) : x)));
      }
      return;
    }

    // json
    if (isCiphertext(v)) {
      if (!wantRewrap) return;
      const r = await cryplus.rewrap(ctx, v);
      if (r.changed) {
        data[enc.name] = r.ciphertext;
        stats.rewrapped++;
        expect[enc.name] = JSON.parse(await cryplus.decrypt(ctx, r.ciphertext));
      }
    } else if (wantEncrypt) {
      data[enc.name] = await tr.encryptValue(model, enc, v);
      expect[enc.name] = v;
      stats.encrypted++;
    }
  }

  async function verifyRow(u: { id: unknown; data: Record<string, unknown>; expect: Record<string, unknown>; tenant: string }) {
    const back = await delegate.findUnique({ where: { [idField]: u.id } });
    for (const [field, want] of Object.entries(u.expect)) {
      const enc = model.encrypted.get(field)!;
      const ctx = { tenant: u.tenant, collection: model.name, field };
      try {
        let got: unknown;
        const stored = back?.[field];
        if (enc.kind === "string") got = typeof stored === "string" && isCiphertext(stored) ? await cryplus.decrypt(ctx, stored) : stored;
        else if (enc.kind === "string[]") got = await Promise.all((stored as string[]).map((x) => (isCiphertext(x) ? cryplus.decrypt(ctx, x) : x)));
        else got = typeof stored === "string" && isCiphertext(stored) ? JSON.parse(await cryplus.decrypt(ctx, stored)) : stored;
        if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error("read-back does not match");
        stats.verified++;
      } catch (e) {
        stats.failures.push({ id: u.id, field, error: "verify: " + (e as Error).message });
      }
    }
  }
}

/**
 * KEY ROTATION: move every ciphertext of a model to the current KEK version without touching anything else. Call it after
 * `cryplus.rotateKeys()`, per model, in batches. Resumable (`startAfter` / `lastId`) and safe to repeat.
 */
export function rotateModel(prisma: any, cryplus: CryplusApi, schema: Schema, o: Omit<MigrateOptions, "mode">): Promise<MigrateStats> {
  return migrateModel(prisma, cryplus, schema, { ...o, mode: "rewrap-only" });
}

export interface RevertStats {
  scanned: number;
  decrypted: number;
  failures: { id: unknown; field: string; error: string }[];
}

/**
 * ROLLBACK: write the plaintext of every @encrypted column back into the table (blind-index columns are left
 * in place, so you can encrypt again later). Use it if you must remove Cryplus from a model. It puts secrets
 * back in clear text in the database, so run it deliberately, take a backup first, and encrypt again afterwards.
 * Pass the BASE Prisma client. Rows that fail to decrypt are reported and left untouched.
 */
export async function revertModel(prisma: any, cryplus: CryplusApi, schema: Schema, o: Omit<MigrateOptions, "mode" | "verify"> & { dryRun?: boolean }): Promise<RevertStats> {
  const { model, delegate, idField } = lookup(schema, prisma, o.model);
  const stats: RevertStats = { scanned: 0, decrypted: 0, failures: [] };
  const batch = o.batchSize ?? 200;
  let cursor: unknown = o.startAfter;
  for (;;) {
    const rows: any[] = await delegate.findMany({
      take: batch,
      orderBy: { [idField]: "asc" },
      ...(cursor !== undefined ? { skip: 1, cursor: { [idField]: cursor } } : {}),
    });
    if (rows.length === 0) break;
    for (const row of rows) {
      const data: Record<string, unknown> = {};
      let tenant: string | undefined;
      try {
        tenant = await o.tenantOf(row);
      } catch (e) {
        stats.failures.push({ id: row[idField], field: "*", error: "tenantOf: " + (e as Error).message });
        continue;
      }
      const t = tenant;
      const tr = new Transformer(cryplus, schema, async () => t, { plaintext: "allow", hideIndexFields: false });
      for (const enc of model.encrypted.values()) {
        const v = row[enc.name];
        const has = enc.kind === "string[]" ? Array.isArray(v) && v.some(isCiphertext) : isCiphertext(v);
        if (!has) continue;
        try {
          data[enc.name] = await tr.decryptValue(model, enc, v);
          stats.decrypted++;
        } catch (e) {
          stats.failures.push({ id: row[idField], field: enc.name, error: (e as Error).message });
        }
      }
      if (!o.dryRun && Object.keys(data).length) await delegate.update({ where: { [idField]: row[idField] }, data });
    }
    stats.scanned += rows.length;
    cursor = rows[rows.length - 1][idField];
    if (rows.length < batch) break;
    if (o.throttleMs) await sleep(o.throttleMs);
  }
  return stats;
}
