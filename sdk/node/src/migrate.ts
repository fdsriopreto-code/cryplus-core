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
   * `index-only`: only fill missing index columns. Works on rows that are still PLAINTEXT too (it computes the index from the
   *   plaintext and leaves the value alone), so the safe order for a new searchable column is: add the index column,
   *   run index-only, deploy the equality code, then run `all` to encrypt.
   */
  mode?: "all" | "rewrap-only" | "index-only";
  /** Sleep this long after every batch, so a migration can run next to real traffic (default 0). */
  throttleMs?: number;
  /**
   * After writing a row, read it back (through a fresh client state: no caching) and check that every changed field decrypts
   * to the value we meant to store. `true` checks every row; `{ sample: 0.05 }` checks about 5 % of them.
   */
  verify?: boolean | { sample: number };
  /** Resume: only rows after this id (use `lastId` from a previous run). */
  startAfter?: unknown;
  /** Stop after this many failures instead of scanning the whole table (default: never). */
  maxFailures?: number;
  /** Rows written in parallel inside a batch (default 1: strictly sequential). Mind the connection pool of the Prisma client. */
  concurrency?: number;
  /**
   * Bind every ciphertext to its row id (see `rowBinding` in the Prisma options): values written without the binding are re-encrypted
   * with it, values already bound are re-wrapped as usual. Run it (modes `all` or `rewrap-only`) before switching rowBinding to "strict".
   */
  bindRows?: boolean;
  /** Count the table once at the start so progress can report a percentage and an ETA (default true). */
  countTotal?: boolean;
  onProgress?: (s: MigrateStats) => void;
}

export interface MigrateStats {
  scanned: number;
  encrypted: number; // plaintext values that were encrypted
  rewrapped: number; // ciphertexts moved to the current KEK version
  rebound: number; // ciphertexts re-encrypted so that they are bound to their row id (bindRows)
  indexed: number; // fields whose missing index columns were filled in
  verified: number; // fields confirmed by the read-back
  failures: { id: unknown; field: string; error: string }[];
  /** Id of the last row scanned: pass it as `startAfter` to resume. */
  lastId?: unknown;
  /** True when the run stopped early because of maxFailures. */
  aborted?: boolean;
  /** Rows in the table when the run started (when countTotal), and timing for a progress display. */
  total?: number;
  elapsedMs: number;
  rowsPerSec: number;
  /** Estimated seconds left (needs `total`; not meaningful when resuming with startAfter). */
  etaSec?: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Run fn over items with at most `n` in flight; errors propagate after the pool drains. */
async function pool<T>(items: T[], n: number, fn: (x: T) => Promise<void>): Promise<void> {
  const limit = Math.max(1, Math.floor(n));
  let i = 0;
  let firstErr: unknown;
  const worker = async () => {
    while (i < items.length && firstErr === undefined) {
      const x = items[i++]!;
      try {
        await fn(x);
      } catch (e) {
        firstErr ??= e;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  if (firstErr !== undefined) throw firstErr;
}

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
  const stats: MigrateStats = { scanned: 0, encrypted: 0, rewrapped: 0, rebound: 0, indexed: 0, verified: 0, failures: [], lastId: o.startAfter, elapsedMs: 0, rowsPerSec: 0 };
  const batch = o.batchSize ?? 200;
  const conc = o.concurrency ?? 1;
  const verifyRate = o.verify === true ? 1 : o.verify ? Math.min(1, Math.max(0, o.verify.sample)) : 0;
  const t0 = Date.now();
  let cursor: unknown = o.startAfter;
  if (o.countTotal !== false) {
    try {
      stats.total = await delegate.count();
    } catch {
      /* progress without a total is fine */
    }
  }
  const tick = () => {
    stats.elapsedMs = Date.now() - t0;
    stats.rowsPerSec = stats.elapsedMs > 0 ? Math.round((stats.scanned / stats.elapsedMs) * 1000 * 10) / 10 : 0;
    if (stats.total !== undefined && stats.rowsPerSec > 0 && o.startAfter === undefined) stats.etaSec = Math.max(0, Math.round((stats.total - stats.scanned) / stats.rowsPerSec));
  };

  for (;;) {
    const rows: any[] = await delegate.findMany({
      take: batch,
      orderBy: { [idField]: "asc" },
      ...(cursor !== undefined ? { skip: 1, cursor: { [idField]: cursor } } : {}),
    });
    if (rows.length === 0) break;

    const updates = (await Promise.all(rows.map((row) => planRow(row)))).filter((u): u is NonNullable<typeof u> => !!u);
    if (!o.dryRun) {
      await pool(updates, conc, async (u) => {
        await delegate.update({ where: { [idField]: u.id }, data: u.data });
        if (verifyRate > 0 && (verifyRate >= 1 || Math.random() < verifyRate)) await verifyRow(u);
      });
    }
    stats.scanned += rows.length;
    cursor = rows[rows.length - 1][idField];
    stats.lastId = cursor;
    tick();
    o.onProgress?.(stats);
    if (o.maxFailures !== undefined && stats.failures.length >= o.maxFailures) {
      stats.aborted = true;
      break;
    }
    if (rows.length < batch) break;
    if (o.throttleMs) await sleep(o.throttleMs);
  }
  tick();
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
    const tr = new Transformer(cryplus, schema, async () => tenant, { plaintext: "allow", hideIndexFields: false, rowBinding: o.bindRows ? "on" : "off" });
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
    const rid = typeof row[idField] === "string" ? (row[idField] as string) : undefined;
    const wantEncrypt = mode === "all";
    const wantRewrap = mode === "all" || mode === "rewrap-only";
    const wantIndex = mode === "all" || mode === "index-only";
    const binding = tr.bound(model);
    if (binding && rid === undefined) throw new Error("bindRows needs a String primary key");

    /** Move one ciphertext to the current KEK version and (bindRows) bind it to the row; says what it did. */
    const refresh = async (ct: string): Promise<{ ct: string; kind: "same" | "rewrapped" | "rebound"; plain?: string }> => {
      if (!binding) {
        try {
          const r = await cryplus.rewrap(ctx, ct);
          return { ct: r.ciphertext, kind: r.changed ? "rewrapped" : "same" };
        } catch (e) {
          // a value bound to its row (rowBinding was switched on) re-wraps only with the row id in the context
          if (model.bindable && rid !== undefined && /decryption_failed/.test(String((e as Error)?.message))) {
            const r = await cryplus.rewrap({ ...ctx, recordId: rid }, ct);
            return { ct: r.ciphertext, kind: r.changed ? "rewrapped" : "same" };
          }
          throw e;
        }
      }
      const opened = await tr.openScalar(model, enc, ct, rid);
      if (!opened.bound) return { ct: await tr.encryptScalar(model, enc, opened.plain, rid), kind: "rebound", plain: opened.plain };
      const r = await cryplus.rewrap({ ...ctx, recordId: rid }, ct);
      return { ct: r.ciphertext, kind: r.changed ? "rewrapped" : "same" };
    };
    const count = (k: "rewrapped" | "rebound") => void (stats[k] += 1);

    if (enc.kind === "string") {
      if (typeof v !== "string") return;
      const cols = [enc.indexField, enc.globalIndexField, ...enc.suffixes.map((s) => s.field)].filter((c): c is string => !!c);
      const isMissing = (c: string) => row[c] === null || row[c] === undefined;
      let plain: string | undefined;
      let wroteNew = false;
      if (!isCiphertext(v)) {
        if (!wantEncrypt) {
          // index-only on a row that is still plaintext: compute the index from the plaintext, leave the value alone
          if (mode === "index-only" && cols.some(isMissing)) {
            const idx = await tr.indexesFor(model, enc, v);
            let wrote = false;
            for (const c of cols) {
              const next = idx[c] ?? null;
              if (isMissing(c) && next !== null) {
                data[c] = next;
                wrote = true;
              }
            }
            if (wrote) stats.indexed++;
          }
          return;
        }
        plain = v;
        data[enc.name] = await tr.encryptValue(model, enc, v, rid);
        stats.encrypted++;
        wroteNew = true;
      } else if (wantRewrap) {
        const r = await refresh(v);
        if (r.kind !== "same") {
          data[enc.name] = r.ct;
          count(r.kind);
          plain = r.plain;
          if (plain !== undefined) expect[enc.name] = plain;
        }
      }
      if (wantIndex && cols.length) {
        const missing = cols.filter(isMissing);
        // Short values legitimately have no suffix index; only a missing equality/global index is always a gap.
        if (wroteNew || missing.length) {
          plain ??= await tr.decryptScalar(model, enc, v, rid);
          const idx = await tr.indexesFor(model, enc, plain);
          let wrote = false;
          for (const c of cols) {
            const next = idx[c] ?? null;
            if (wroteNew || (isMissing(c) ? next !== null : false)) {
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
          out.push((await tr.encryptScalar(model, enc, el, rid)) as string);
          changed = true;
          stats.encrypted++;
        } else if (wantRewrap) {
          const r = await refresh(el);
          out.push(r.ct);
          if (r.kind !== "same") {
            changed = true;
            count(r.kind);
          }
        } else out.push(el);
      }
      if (changed) {
        data[enc.name] = out;
        // what a read-back must return (values this run produced are known; untouched ones are decrypted)
        expect[enc.name] = await Promise.all(out.map((x) => (isCiphertext(x) ? tr.decryptScalar(model, enc, x, rid) : x)));
      }
      return;
    }

    // json
    if (isCiphertext(v)) {
      if (!wantRewrap) return;
      const r = await refresh(v);
      if (r.kind !== "same") {
        data[enc.name] = r.ct;
        count(r.kind);
        expect[enc.name] = JSON.parse(r.plain ?? (await tr.decryptScalar(model, enc, r.ct, rid)));
      }
    } else if (wantEncrypt) {
      data[enc.name] = await tr.encryptValue(model, enc, v, rid);
      expect[enc.name] = v;
      stats.encrypted++;
    }
  }

  async function verifyRow(u: { id: unknown; data: Record<string, unknown>; expect: Record<string, unknown>; tenant: string }) {
    const back = await delegate.findUnique({ where: { [idField]: u.id } });
    // a FRESH transformer: nothing it decrypts can come from what the planning step just encrypted
    const vt = new Transformer(cryplus, schema, async () => u.tenant, { plaintext: "allow", hideIndexFields: false, rowBinding: o.bindRows ? "strict" : "off" });
    const rid = typeof u.id === "string" ? u.id : undefined;
    for (const [field, want] of Object.entries(u.expect)) {
      const enc = model.encrypted.get(field)!;
      try {
        const got = await vt.decryptValue(model, enc, back?.[field], rid);
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
 * With `bindRows: true` it also binds values to their rows, which is how existing data is moved to `rowBinding`.
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
 * Values are opened with the row binding when they have one and without it when they do not, so it works before and after `rowBinding`.
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
      const tr = new Transformer(cryplus, schema, async () => t, { plaintext: "allow", hideIndexFields: false, rowBinding: "on" });
      const rid = typeof row[idField] === "string" ? (row[idField] as string) : undefined;
      for (const enc of model.encrypted.values()) {
        const v = row[enc.name];
        const has = enc.kind === "string[]" ? Array.isArray(v) && v.some(isCiphertext) : isCiphertext(v);
        if (!has) continue;
        try {
          data[enc.name] = await tr.decryptValue(model, enc, v, rid);
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
