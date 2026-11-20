import { CryplusError, type Context } from "./client.ts";

export interface KeyCacheOptions {
  /** How long a fetched key is used without asking the service again (default 300 000 ms). Bounds how long a revoked service or tenant keeps working, and how long a rotation takes to reach this process. */
  ttlMs?: number;
  /**
   * Extra time, beyond `ttlMs`, during which an expired key may still be used IF the service cannot be reached
   * (default 0 = never use an expired key). After that, calls fail closed.
   */
  staleMs?: number;
  /** Maximum cached keys (default 1000); the oldest are wiped first. */
  maxEntries?: number;
  /**
   * After a failed refresh of an expired key that is still inside the stale window, do not ask the service again for this long
   * (default 1000 ms); keep serving the stale key meanwhile. Without it every operation during an outage would try, and wait for, a
   * connection to a service that is down.
   */
  retryMs?: number;
}

interface Entry<T> {
  value: T;
  at: number;
  /** When the last refresh of this (expired) entry failed. */
  failedAt?: number;
}

export interface TenantKeyReply {
  version: number;
  current: number;
  key: Buffer;
}

export interface KeyCacheStats {
  hits: number;
  misses: number;
  staleServed: number;
  fetchErrors: number;
  /** Keys held in memory (including expired ones not yet evicted). */
  entries: number;
  /** Keys that can still be used right now: within ttl + stale window. */
  usable: number;
}

const unavailable = (e: unknown) => e instanceof CryplusError && (e.code.startsWith("unreachable") || e.code === "circuit_open");

/**
 * Keeps tenant KEKs and blind-index keys in process memory, fetched from the service on demand.
 *
 * Security trade-off (read this): a cached key lets this process encrypt and decrypt that tenant's data without asking the
 * service, which is the point (latency and availability), but it also means the key lives in this process's memory and that
 * those operations are no longer individually audited by the service (only the key fetches are). Keep `ttlMs` short, give
 * the service a narrow `tenants` allowlist, and run it only where you would already trust the process with the data.
 */
export class KeyCache {
  private ttl: number;
  private stale: number;
  private max: number;
  private retry: number;
  private keks = new Map<string, Entry<Buffer>>();
  private current = new Map<string, Entry<number>>();
  private index = new Map<string, Entry<Buffer>>();
  private inflight = new Map<string, Promise<unknown>>();
  private s = { hits: 0, misses: 0, staleServed: 0, fetchErrors: 0 };
  private fetchTenant: (tenant: string, version?: number) => Promise<TenantKeyReply>;
  private fetchIndex: (ctx: Context) => Promise<Buffer>;
  private emit: (event: "hit" | "miss" | "stale" | "fetch_error") => void;

  constructor(
    o: KeyCacheOptions,
    fetchTenant: (tenant: string, version?: number) => Promise<TenantKeyReply>,
    fetchIndex: (ctx: Context) => Promise<Buffer>,
    emit: (event: "hit" | "miss" | "stale" | "fetch_error") => void = () => {},
  ) {
    this.fetchTenant = fetchTenant;
    this.fetchIndex = fetchIndex;
    this.emit = emit;
    this.ttl = o.ttlMs ?? 300_000;
    this.stale = o.staleMs ?? 0;
    this.max = o.maxEntries ?? 1000;
    this.retry = o.retryMs ?? 1000;
  }

  stats(): KeyCacheStats {
    const now = Date.now();
    const limit = this.ttl + this.stale;
    let usable = 0;
    for (const e of this.keks.values()) if (now - e.at < limit) usable++;
    for (const e of this.index.values()) if (now - e.at < limit) usable++;
    return { ...this.s, entries: this.keks.size + this.index.size, usable };
  }

  clear() {
    for (const e of this.keks.values()) e.value.fill(0);
    for (const e of this.index.values()) e.value.fill(0);
    this.keks.clear();
    this.index.clear();
    this.current.clear();
  }

  private evict<T extends Buffer | number>(m: Map<string, Entry<T>>) {
    while (m.size > this.max) {
      const k = m.keys().next().value as string;
      const e = m.get(k)!;
      if (Buffer.isBuffer(e.value)) e.value.fill(0);
      m.delete(k);
    }
  }

  /** The generic fetch-or-serve logic shared by all three key kinds. */
  private async get<T>(map: Map<string, Entry<T>>, key: string, fetcher: () => Promise<T>, put: (v: T, at: number) => void): Promise<T> {
    const now = Date.now();
    const e = map.get(key);
    if (e && now - e.at < this.ttl) {
      this.s.hits++;
      this.emit("hit");
      return e.value;
    }
    // an expired key whose refresh just failed: keep serving it (inside the stale window) without hammering the service
    if (e && e.failedAt !== undefined && now - e.failedAt < this.retry && now - e.at < this.ttl + this.stale) {
      this.s.staleServed++;
      this.emit("stale");
      return e.value;
    }
    this.s.misses++;
    this.emit("miss");
    let p = this.inflight.get(key) as Promise<T> | undefined;
    if (!p) {
      p = fetcher().finally(() => this.inflight.delete(key));
      this.inflight.set(key, p);
    }
    try {
      const v = await p;
      put(v, Date.now());
      return v;
    } catch (err) {
      this.s.fetchErrors++;
      this.emit("fetch_error");
      if (unavailable(err)) {
        if (e) e.failedAt = Date.now();
        if (e && now - e.at < this.ttl + this.stale) {
          this.s.staleServed++;
          this.emit("stale");
          return e.value;
        }
        throw new CryplusError("key_service_unavailable");
      }
      throw err;
    }
  }

  /** KEK + version to use for NEW data under a tenant. */
  async currentKek(tenant: string): Promise<{ version: number; kek: Buffer }> {
    const version = await this.get(
      this.current,
      tenant,
      async () => {
        const r = await this.fetchTenant(tenant);
        this.keks.set(`${tenant}\0${r.version}`, { value: r.key, at: Date.now() });
        this.evict(this.keks);
        return r.version;
      },
      (v, at) => this.current.set(tenant, { value: v, at }),
    );
    return { version, kek: await this.kek(tenant, version) };
  }

  /** KEK for a specific version (needed to read older data). */
  async kek(tenant: string, version: number): Promise<Buffer> {
    const k = `${tenant}\0${version}`;
    return this.get(
      this.keks,
      k,
      async () => (await this.fetchTenant(tenant, version)).key,
      (v, at) => {
        this.keks.set(k, { value: v, at });
        this.evict(this.keks);
      },
    );
  }

  async indexKey(ctx: Context): Promise<Buffer> {
    const k = `${ctx.tenant}\0${ctx.collection ?? ""}\0${ctx.field ?? ""}`;
    return this.get(
      this.index,
      k,
      () => this.fetchIndex(ctx),
      (v, at) => {
        this.index.set(k, { value: v, at });
        this.evict(this.index);
      },
    );
  }
}
