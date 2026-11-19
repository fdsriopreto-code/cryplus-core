import type { Cryplus } from "./client.ts";
import { isCiphertext } from "./prisma.ts";
import { normalizeValue, type Schema } from "./schema.ts";

export interface MigrateOptions {
  model: string;
  /** Tenant owning a row (e.g. row => row.organizationId). */
  tenantOf: (row: any) => string | Promise<string>;
  batchSize?: number;
  /** Compute what would change without writing. */
  dryRun?: boolean;
  onProgress?: (s: MigrateStats) => void;
}

export interface MigrateStats {
  scanned: number;
  encrypted: number; // plaintext values that were encrypted
  rewrapped: number; // ciphertexts moved to the current KEK version
  indexed: number; // missing blind indexes filled in
  failures: { id: unknown; field: string; error: string }[];
}

/**
 * Bring a table in line with the schema: encrypt existing plaintext in
 * @encrypted columns, re-wrap ciphertexts still on an old KEK version, and
 * backfill blind indexes. Idempotent and resumable: run it again any time,
 * e.g. after cryplus.rotateKeys().
 *
 * Pass the BASE Prisma client (not the one with the cryplus extension), so
 * values are read and written raw.
 */
export async function migrateModel(prisma: any, cryplus: Cryplus, schema: Schema, o: MigrateOptions): Promise<MigrateStats> {
  const model = schema.get(o.model);
  if (!model) throw new Error(`cryplus: unknown model ${o.model}`);
  if (!model.encrypted.size) throw new Error(`cryplus: model ${o.model} has no @encrypted fields`);
  const idField = model.idField;
  if (!idField) throw new Error(`cryplus: model ${o.model} needs a single-column @id for migration`);
  const delegate = prisma[o.model.charAt(0).toLowerCase() + o.model.slice(1)];
  if (!delegate) throw new Error(`cryplus: prisma client has no delegate for ${o.model}`);

  const stats: MigrateStats = { scanned: 0, encrypted: 0, rewrapped: 0, indexed: 0, failures: [] };
  const batch = o.batchSize ?? 200;
  let cursor: unknown = undefined;

  for (;;) {
    const rows: any[] = await delegate.findMany({
      take: batch,
      orderBy: { [idField]: "asc" },
      ...(cursor !== undefined ? { skip: 1, cursor: { [idField]: cursor } } : {}),
    });
    if (rows.length === 0) break;

    const updates = await Promise.all(
      rows.map(async (row) => {
        const data: Record<string, unknown> = {};
        let tenant: string;
        try {
          tenant = await o.tenantOf(row);
        } catch (e) {
          stats.failures.push({ id: row[idField], field: "*", error: "tenantOf: " + (e as Error).message });
          return null;
        }
        for (const enc of model.encrypted.values()) {
          const v = row[enc.name];
          if (v == null || typeof v !== "string") continue;
          const ctx = { tenant, collection: model.name, field: enc.name };
          try {
            let plain: string | undefined;
            if (!isCiphertext(v)) {
              plain = v;
              data[enc.name] = await cryplus.encrypt(ctx, v);
              stats.encrypted++;
            } else {
              const r = await cryplus.rewrap(ctx, v);
              if (r.changed) {
                data[enc.name] = r.ciphertext;
                stats.rewrapped++;
              }
              if (enc.indexField && row[enc.indexField] == null) plain = await cryplus.decrypt(ctx, v);
            }
            if (enc.indexField && plain !== undefined) {
              data[enc.indexField] = await cryplus.blindIndex(ctx, normalizeValue(plain, enc.normalize));
              if (isCiphertext(v)) stats.indexed++;
            }
          } catch (e) {
            stats.failures.push({ id: row[idField], field: enc.name, error: (e as Error).message });
          }
        }
        return Object.keys(data).length ? { id: row[idField], data } : null;
      }),
    );

    if (!o.dryRun) {
      for (const u of updates) {
        if (u) await delegate.update({ where: { [idField]: u.id }, data: u.data });
      }
    }
    stats.scanned += rows.length;
    cursor = rows[rows.length - 1][idField];
    o.onProgress?.(stats);
    if (rows.length < batch) break;
  }
  return stats;
}
