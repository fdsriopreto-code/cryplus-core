/**
 * In-process Cryplus for TESTS. Same API as the real client, no key service, no network.
 *
 *  - It is NOT interoperable with the real service on purpose: its ciphertexts carry a different format byte, so a real
 *    core refuses them, and it refuses to start when NODE_ENV=production.
 *  - Ciphertext LENGTH matches the real service exactly (120 bytes of overhead), so column-size problems show up in tests too.
 *  - Keys are derived from a seed, so test runs are repeatable. `deterministic: true` also makes encryption itself
 *    repeatable (same input -> same ciphertext), which is handy for snapshots and never appropriate outside tests.
 */
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { Readable } from "node:stream";
import { CryplusError, type Context, type CryplusApi } from "./client.ts";

export interface InMemoryOptions {
  /** Seed for the derived master keys (default: a fixed test seed). */
  seed?: string;
  /** Explicit master keys by version; anything not listed is derived from the seed. */
  keys?: Record<number, string | Buffer>;
  /** Version used for new data (default 1). */
  current?: number;
  /** Make encryption repeatable (tests only). */
  deterministic?: boolean;
  /** Allow use when NODE_ENV=production. Don't. */
  allowInProduction?: boolean;
}

const FORMAT = 0xfe; // never equal to the real format byte (1)
const ALG = 2;
const CHUNK = 64 * 1024;

const lp = (s: string) => {
  const b = Buffer.from(s, "utf8");
  const h = Buffer.alloc(4);
  h.writeUInt32BE(b.length);
  return Buffer.concat([h, b]);
};
const ctxAad = (c: Context) => Buffer.concat([lp(c.tenant), lp(c.collection ?? ""), lp(c.field ?? ""), lp(c.recordId ?? "")]);
const u32 = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const b64u = (b: Buffer) => b.toString("base64url");
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest();

function seal(key: Buffer, nonce: Buffer, aad: Buffer, pt: Buffer): Buffer {
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]);
}
function open(key: Buffer, nonce: Buffer, aad: Buffer, ctTag: Buffer): Buffer {
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAAD(aad);
  d.setAuthTag(ctTag.subarray(ctTag.length - 16));
  return Buffer.concat([d.update(ctTag.subarray(0, ctTag.length - 16)), d.final()]);
}

export class InMemoryCryplus implements CryplusApi {
  readonly url = "memory://";
  private seed: string;
  private masters = new Map<number, Buffer>();
  private cur: number;
  private det: boolean;
  private indexMaster: Buffer;

  constructor(o: InMemoryOptions = {}) {
    if (process.env.NODE_ENV === "production" && !o.allowInProduction) {
      throw new Error("cryplus: the in-memory mode is for tests only and refuses to run with NODE_ENV=production");
    }
    this.seed = o.seed ?? "cryplus-in-memory-test-seed";
    this.det = !!o.deterministic;
    this.cur = o.current ?? 1;
    for (const [v, k] of Object.entries(o.keys ?? {})) this.masters.set(Number(v), typeof k === "string" ? sha(k) : sha(k));
    this.master(this.cur);
    this.indexMaster = sha(`${this.seed}:index`);
  }

  private master(v: number): Buffer {
    let m = this.masters.get(v);
    if (!m) {
      m = sha(`${this.seed}:master:${v}`);
      this.masters.set(v, m);
    }
    return m;
  }

  private kek(v: number, tenant: string): Buffer {
    return Buffer.from(hkdfSync("sha256", this.master(v), Buffer.alloc(0), `cryplus/kek/v1\0${tenant}`, 32));
  }

  private rand(n: number, label: string, ...parts: Buffer[]): Buffer {
    if (!this.det) return randomBytes(n);
    const h = createHmac("sha256", this.master(this.cur)).update(label);
    for (const p of parts) h.update(p).update("\0");
    return h.digest().subarray(0, n);
  }

  private wrapAad(v: number, tenant: string, aad: Buffer) {
    return Buffer.concat([Buffer.from("cryplus/wrap/v1"), u32(v), lp(tenant), lp(aad.toString("latin1"))]);
  }

  // ---- values ------------------------------------------------------------------

  async encrypt(ctx: Context, plaintext: string | Uint8Array): Promise<string> {
    if (!ctx.tenant) throw new CryplusError("tenant_required");
    const pt = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : Buffer.from(plaintext);
    const aad = ctxAad(ctx);
    const dek = this.rand(32, "dek", aad, pt);
    const wNonce = this.rand(12, "wnonce", aad, pt);
    const dNonce = this.rand(12, "dnonce", aad, pt);
    const v = this.cur;
    // wrapped DEK padded to 72 bytes and nonce to 24 so the total length equals the real format's
    const wrapped = Buffer.concat([wNonce, seal(this.kek(v, ctx.tenant), wNonce, this.wrapAad(v, ctx.tenant, aad), dek), Buffer.alloc(72 - 12 - 48)]);
    const body = seal(dek, dNonce, Buffer.concat([Buffer.from([FORMAT, ALG]), aad]), pt);
    const head = Buffer.concat([Buffer.from([FORMAT, ALG]), u32(v), Buffer.from([0, 72]), wrapped, dNonce, Buffer.alloc(12)]);
    return "cp1." + b64u(Buffer.concat([head, body]));
  }

  private parse(text: string) {
    if (!text.startsWith("cp1.")) throw new CryplusError("malformed_ciphertext");
    const raw = Buffer.from(text.slice(4), "base64url");
    if (raw.length < 8 + 72 + 24 + 16 || raw[0] !== FORMAT || raw[1] !== ALG) throw new CryplusError("malformed_ciphertext");
    const wl = raw.readUInt16BE(6);
    if (wl !== 72) throw new CryplusError("malformed_ciphertext");
    return {
      v: raw.readUInt32BE(2),
      wrapped: raw.subarray(8, 8 + 72),
      dNonce: raw.subarray(8 + 72, 8 + 72 + 12),
      body: raw.subarray(8 + 72 + 24),
    };
  }

  private openDek(ctx: Context, p: { v: number; wrapped: Buffer }): Buffer {
    try {
      const aad = ctxAad(ctx);
      return open(this.kek(p.v, ctx.tenant), p.wrapped.subarray(0, 12), this.wrapAad(p.v, ctx.tenant, aad), p.wrapped.subarray(12, 60));
    } catch {
      throw new CryplusError("decryption_failed");
    }
  }

  async decryptBytes(ctx: Context, ciphertext: string): Promise<Uint8Array> {
    if (!ctx.tenant) throw new CryplusError("tenant_required");
    const p = this.parse(ciphertext);
    const dek = this.openDek(ctx, p);
    try {
      return open(dek, p.dNonce, Buffer.concat([Buffer.from([FORMAT, ALG]), ctxAad(ctx)]), p.body);
    } catch {
      throw new CryplusError("decryption_failed");
    }
  }

  async decrypt(ctx: Context, ciphertext: string): Promise<string> {
    return Buffer.from(await this.decryptBytes(ctx, ciphertext)).toString("utf8");
  }

  async blindIndex(ctx: Context, value: string): Promise<string> {
    if (!ctx.tenant) throw new CryplusError("tenant_required");
    const key = Buffer.from(hkdfSync("sha256", this.indexMaster, Buffer.alloc(0), `cryplus/idx/v1\0${ctx.tenant}\0${ctx.collection ?? ""}\0${ctx.field ?? ""}`, 32));
    return "bi1." + b64u(createHmac("sha256", key).update(value, "utf8").digest());
  }

  async rewrap(ctx: Context, ciphertext: string): Promise<{ ciphertext: string; changed: boolean }> {
    const p = this.parse(ciphertext);
    if (p.v === this.cur) return { ciphertext, changed: false };
    const dek = this.openDek(ctx, p);
    // prove the payload opens before moving it
    try {
      open(dek, p.dNonce, Buffer.concat([Buffer.from([FORMAT, ALG]), ctxAad(ctx)]), p.body);
    } catch {
      throw new CryplusError("decryption_failed");
    }
    const aad = ctxAad(ctx);
    const wNonce = this.rand(12, "wnonce2", aad, p.wrapped);
    const wrapped = Buffer.concat([wNonce, seal(this.kek(this.cur, ctx.tenant), wNonce, this.wrapAad(this.cur, ctx.tenant, aad), dek), Buffer.alloc(12)]);
    const raw = Buffer.from(ciphertext.slice(4), "base64url");
    const out = Buffer.concat([raw.subarray(0, 2), u32(this.cur), raw.subarray(6, 8), wrapped, raw.subarray(8 + 72)]);
    return { ciphertext: "cp1." + b64u(out), changed: true };
  }

  async keys() {
    return { provider: "memory", current: this.cur, versions: [...new Set([...this.masters.keys(), this.cur])].sort((a, b) => a - b).map((version) => ({ version, current: version === this.cur })) };
  }

  async rotateKeys(): Promise<number> {
    this.cur = Math.max(this.cur, ...this.masters.keys()) + 1;
    this.master(this.cur);
    return this.cur;
  }

  async health() {
    return true;
  }
  close() {}

  // ---- streams (chunked AES-GCM; same guarantees: tamper, truncation and reorder are errors) ----

  async encryptStream(ctx: Context, input: Readable): Promise<Readable> {
    if (!ctx.tenant) throw new CryplusError("tenant_required");
    const aad = ctxAad(ctx);
    const dek = randomBytes(32);
    const wNonce = randomBytes(12);
    const v = this.cur;
    const wrapped = Buffer.concat([wNonce, seal(this.kek(v, ctx.tenant), wNonce, this.wrapAad(v, ctx.tenant, aad), dek), Buffer.alloc(12)]);
    const prefix = randomBytes(7);
    const header = Buffer.concat([Buffer.from("CPSM"), u32(v), wrapped, prefix]);
    const nonce = (i: number, last: boolean) => Buffer.concat([prefix, u32(i), Buffer.from([last ? 1 : 0])]);
    const cAad = Buffer.concat([Buffer.from("cp/sm"), prefix, aad]);
    async function* gen() {
      yield header;
      let buf = Buffer.alloc(0);
      let i = 0;
      for await (const piece of input) {
        buf = Buffer.concat([buf, piece as Buffer]);
        while (buf.length > CHUNK) {
          yield seal(dek, nonce(i++, false), cAad, buf.subarray(0, CHUNK));
          buf = buf.subarray(CHUNK);
        }
      }
      yield seal(dek, nonce(i, true), cAad, buf);
    }
    return Readable.from(gen(), { objectMode: false });
  }

  async decryptStream(ctx: Context, input: Readable): Promise<Readable> {
    if (!ctx.tenant) throw new CryplusError("tenant_required");
    const aad = ctxAad(ctx);
    const it = input[Symbol.asyncIterator]();
    let pending = Buffer.alloc(0);
    let ended = false;
    const need = async (n: number): Promise<boolean> => {
      while (pending.length < n && !ended) {
        const r = await it.next();
        if (r.done) ended = true;
        else pending = Buffer.concat([pending, r.value as Buffer]);
      }
      return pending.length >= n;
    };
    const HEAD = 4 + 4 + 72 + 7;
    if (!(await need(HEAD)) || pending.subarray(0, 4).toString() !== "CPSM") throw new CryplusError("malformed_stream");
    const v = pending.readUInt32BE(4);
    const wrapped = pending.subarray(8, 80);
    const prefix = Buffer.from(pending.subarray(80, 87));
    pending = pending.subarray(HEAD);
    let dek: Buffer;
    try {
      dek = open(this.kek(v, ctx.tenant), wrapped.subarray(0, 12), this.wrapAad(v, ctx.tenant, aad), wrapped.subarray(12, 60));
    } catch {
      throw new CryplusError("decryption_failed");
    }
    const cAad = Buffer.concat([Buffer.from("cp/sm"), prefix, aad]);
    const nonce = (i: number, last: boolean) => Buffer.concat([prefix, u32(i), Buffer.from([last ? 1 : 0])]);
    async function* gen() {
      let i = 0;
      for (;;) {
        const full = await need(CHUNK + 16 + 1); // one byte of lookahead tells us whether this is the last chunk
        const take = full ? CHUNK + 16 : pending.length;
        if (take < 16) throw new CryplusError("stream_truncated");
        const chunk = pending.subarray(0, take);
        const last = !full;
        try {
          yield open(dek, nonce(i++, last), cAad, chunk);
        } catch {
          throw new CryplusError("decryption_failed");
        }
        pending = pending.subarray(take);
        if (last) return;
      }
    }
    return Readable.from(gen(), { objectMode: false });
  }

  async rewrapStream(_ctx: Context, input: Readable): Promise<Readable> {
    return input; // test mode: nothing to re-wrap that matters
  }
}
