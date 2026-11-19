import * as http from "node:http";
import * as https from "node:https";
import { Readable } from "node:stream";

/** Scopes a ciphertext. The same context must be used to decrypt. */
export interface Context {
  tenant: string;
  collection?: string;
  field?: string;
  recordId?: string;
}

export interface ClientOptions {
  /** Base URL of cryplus-core, e.g. http://127.0.0.1:7788 */
  url?: string;
  /** Bearer token (CRYPLUS_TOKEN). */
  token?: string;
  timeoutMs?: number;
  /** Max operations merged into a single HTTP batch. */
  maxBatch?: number;
}

const NO_KEEPALIVE_HTTP = new http.Agent({ keepAlive: false });
const NO_KEEPALIVE_HTTPS = new https.Agent({ keepAlive: false });

export class CryplusError extends Error {
  code: string;
  status?: number;
  constructor(code: string, status?: number) {
    super(`cryplus: ${code}`);
    this.name = "CryplusError";
    this.code = code;
    this.status = status;
  }
}

type Op = "encrypt" | "decrypt" | "blind" | "rewrap";
interface Pending {
  op: Op;
  context: Context;
  data: string;
  resolve: (r: { data: string; changed?: boolean }) => void;
  reject: (e: unknown) => void;
}

export class Cryplus {
  readonly url: string;
  private token: string;
  private timeoutMs: number;
  private maxBatch: number;
  private queue: Pending[] = [];
  private scheduled = false;

  constructor(opts: ClientOptions = {}) {
    this.url = (opts.url ?? process.env.CRYPLUS_URL ?? "http://127.0.0.1:7788").replace(/\/$/, "");
    const t = opts.token ?? process.env.CRYPLUS_TOKEN;
    if (!t) throw new Error("cryplus: token required (opts.token or CRYPLUS_TOKEN)");
    this.token = t;
    this.timeoutMs = opts.timeoutMs ?? 15_000;
    this.maxBatch = opts.maxBatch ?? 500;
  }

  // ---- single-value API (auto-batched) -------------------------------------

  /** Encrypt a string or bytes; returns the "cp1.…" ciphertext string. */
  async encrypt(ctx: Context, plaintext: string | Uint8Array): Promise<string> {
    const b = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : Buffer.from(plaintext);
    return (await this.enqueue("encrypt", ctx, b.toString("base64"))).data;
  }

  /** Decrypt to a UTF-8 string. */
  async decrypt(ctx: Context, ciphertext: string): Promise<string> {
    return Buffer.from(await this.decryptBytes(ctx, ciphertext)).toString("utf8");
  }

  async decryptBytes(ctx: Context, ciphertext: string): Promise<Uint8Array> {
    return Buffer.from((await this.enqueue("decrypt", ctx, ciphertext)).data, "base64");
  }

  /** Deterministic keyed index for equality search over encrypted columns. */
  async blindIndex(ctx: Context, value: string): Promise<string> {
    return (await this.enqueue("blind", ctx, Buffer.from(value, "utf8").toString("base64"))).data;
  }

  /** Move a ciphertext to the current KEK version without touching the payload. */
  async rewrap(ctx: Context, ciphertext: string): Promise<{ ciphertext: string; changed: boolean }> {
    const r = await this.enqueue("rewrap", ctx, ciphertext);
    return { ciphertext: r.data, changed: !!r.changed };
  }

  private enqueue(op: Op, context: Context, data: string) {
    return new Promise<{ data: string; changed?: boolean }>((resolve, reject) => {
      this.queue.push({ op, context, data, resolve, reject });
      if (!this.scheduled) {
        this.scheduled = true;
        // Everything requested in the same tick travels in one HTTP call.
        setImmediate(() => void this.flush());
      }
    });
  }

  private async flush() {
    this.scheduled = false;
    const all = this.queue.splice(0);
    for (let i = 0; i < all.length; i += this.maxBatch) {
      const chunk = all.slice(i, i + this.maxBatch);
      try {
        const res = await this.json<{ results: { data?: string; changed?: boolean; error?: string }[] }>(
          "POST",
          "/v1/batch",
          { ops: chunk.map(({ op, context, data }) => ({ op, context, data })) },
        );
        chunk.forEach((p, j) => {
          const r = res.results[j];
          if (!r) p.reject(new CryplusError("missing_result"));
          else if (r.error) p.reject(new CryplusError(r.error));
          else p.resolve({ data: r.data ?? "", changed: r.changed });
        });
      } catch (e) {
        chunk.forEach((p) => p.reject(e));
      }
    }
  }

  // ---- admin ---------------------------------------------------------------

  async keys(): Promise<{ provider: string; current: number; versions: { version: number; current: boolean }[] }> {
    return this.json("GET", "/v1/keys");
  }

  /** Create a new KEK version. Existing data stays readable; run rewrap to migrate it. */
  async rotateKeys(): Promise<number> {
    return (await this.json<{ version: number }>("POST", "/v1/keys/rotate", {})).version;
  }

  async health(): Promise<boolean> {
    try {
      await this.json("GET", "/healthz", undefined, false);
      return true;
    } catch {
      return false;
    }
  }

  // ---- streaming -----------------------------------------------------------

  /** Encrypt a byte stream (files, S3 bodies) without buffering it. */
  encryptStream(ctx: Context, input: Readable): Promise<Readable> {
    return this.stream("/v1/stream/encrypt", ctx, input);
  }

  /**
   * Decrypt a stream. Chunks are released only after they authenticate; if the
   * data was truncated or tampered with, the returned stream emits an error
   * instead of ending cleanly.
   */
  decryptStream(ctx: Context, input: Readable): Promise<Readable> {
    return this.stream("/v1/stream/decrypt", ctx, input);
  }

  /** Re-wrap the key header of an encrypted stream under the current KEK. */
  rewrapStream(ctx: Context, input: Readable): Promise<Readable> {
    return this.stream("/v1/stream/rewrap", ctx, input);
  }

  private stream(path: string, ctx: Context, input: Readable): Promise<Readable> {
    return new Promise((resolve, reject) => {
      const u = new URL(this.url + path);
      const lib = u.protocol === "https:" ? https : http;
      const req = lib.request(
        u,
        {
          method: "POST",
          // The server aborts the connection on tampering, so never reuse
          // sockets for streams (a pooled dead socket would fail the next call).
          agent: u.protocol === "https:" ? NO_KEEPALIVE_HTTPS : NO_KEEPALIVE_HTTP,
          headers: {
            Authorization: `Bearer ${this.token}`,
            "Content-Type": "application/octet-stream",
            "X-Cryplus-Tenant": ctx.tenant,
            "X-Cryplus-Collection": ctx.collection ?? "",
            "X-Cryplus-Field": ctx.field ?? "",
            "X-Cryplus-Record": ctx.recordId ?? "",
          },
        },
        (res) => {
          if (res.statusCode !== 200) {
            const chunks: Buffer[] = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => {
              let code = "http_" + res.statusCode;
              try {
                code = JSON.parse(Buffer.concat(chunks).toString()).error ?? code;
              } catch {}
              reject(new CryplusError(code, res.statusCode));
            });
            return;
          }
          // Surface mid-transfer aborts as stream errors (tamper / truncation).
          res.on("aborted", () => res.destroy(new CryplusError("stream_aborted")));
          resolve(res);
        },
      );
      req.on("error", reject);
      input.on("error", (e) => req.destroy(e));
      input.pipe(req);
    });
  }

  // ---- plumbing ------------------------------------------------------------

  private async json<T>(method: string, path: string, body?: unknown, auth = true): Promise<T> {
    let res: Response;
    try {
      res = await fetch(this.url + path, {
        method,
        headers: {
          ...(auth ? { Authorization: `Bearer ${this.token}` } : {}),
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      throw new CryplusError("unreachable: " + (e as Error).message);
    }
    const text = await res.text();
    let parsed: any = undefined;
    try {
      parsed = text ? JSON.parse(text) : undefined;
    } catch {}
    if (!res.ok) throw new CryplusError(parsed?.error ?? `http_${res.status}`, res.status);
    return parsed as T;
  }
}
