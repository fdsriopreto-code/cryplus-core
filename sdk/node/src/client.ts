import { readFileSync } from "node:fs";
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

export interface TlsOptions {
  /** CA certificate(s) (PEM text/Buffer) that signed the server certificate. */
  ca?: string | Buffer;
  /** Client certificate + key (PEM) for mutual TLS. */
  cert?: string | Buffer;
  key?: string | Buffer;
  /** Override the name checked against the server certificate (e.g. when connecting by IP). */
  servername?: string;
}

export interface ClientOptions {
  /**
   * Base URL of cryplus-core, e.g. https://cryplus.internal:7788 (CRYPLUS_URL). For high availability
   * pass several (array, or comma-separated in CRYPLUS_URL): JSON calls fail over to the next instance
   * when one is unreachable. Streams do not fail over (their input is already being consumed).
   */
  url?: string | string[];
  /** Bearer token for this service (CRYPLUS_TOKEN). */
  token?: string;
  /**
   * TLS settings. Also read from files named by CRYPLUS_CA, CRYPLUS_CLIENT_CERT and
   * CRYPLUS_CLIENT_KEY. Certificates are always verified: there is deliberately no
   * "skip verification" switch.
   */
  tls?: TlsOptions;
  timeoutMs?: number;
  /** Max operations merged into a single HTTP batch. */
  maxBatch?: number;
}

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

const readEnvFile = (name: string): Buffer | undefined => {
  const p = process.env[name];
  return p ? readFileSync(p) : undefined;
};

export class Cryplus {
  /** First configured URL (kept for compatibility). */
  readonly url: string;
  readonly urls: string[];
  private preferred = 0;
  private token: string;
  private timeoutMs: number;
  private maxBatch: number;
  private queue: Pending[] = [];
  private scheduled = false;
  private tlsOpts: TlsOptions;
  private jsonAgent: http.Agent;
  private streamAgent: http.Agent;

  constructor(opts: ClientOptions = {}) {
    const raw = opts.url ?? process.env.CRYPLUS_URL ?? "http://127.0.0.1:7788";
    this.urls = (Array.isArray(raw) ? raw : raw.split(","))
      .map((u) => u.trim().replace(/\/$/, ""))
      .filter(Boolean);
    if (this.urls.length === 0) throw new Error("cryplus: no URL configured");
    this.url = this.urls[0]!;
    const t = opts.token ?? process.env.CRYPLUS_TOKEN;
    if (!t) throw new Error("cryplus: token required (opts.token or CRYPLUS_TOKEN)");
    this.token = t;
    this.timeoutMs = opts.timeoutMs ?? 15_000;
    this.maxBatch = opts.maxBatch ?? 500;

    this.tlsOpts = {
      ca: opts.tls?.ca ?? readEnvFile("CRYPLUS_CA"),
      cert: opts.tls?.cert ?? readEnvFile("CRYPLUS_CLIENT_CERT"),
      key: opts.tls?.key ?? readEnvFile("CRYPLUS_CLIENT_KEY"),
      servername: opts.tls?.servername,
    };
    const schemes = new Set(this.urls.map((u) => new URL(u).protocol));
    if (schemes.size > 1) throw new Error("cryplus: all URLs must use the same scheme (all http or all https)");
    const https_ = schemes.has("https:");
    if (!https_ && (this.tlsOpts.cert || this.tlsOpts.ca)) {
      throw new Error("cryplus: TLS options were given but the URL is not https://");
    }
    const agentOpts = { ...this.tlsOpts };
    // JSON calls reuse connections; streams never do (the server aborts the connection on tampering,
    // so a pooled socket could be dead for the next call).
    this.jsonAgent = https_ ? new https.Agent({ keepAlive: true, ...agentOpts }) : new http.Agent({ keepAlive: true });
    this.streamAgent = https_ ? new https.Agent({ keepAlive: false, ...agentOpts }) : new http.Agent({ keepAlive: false });
  }

  /** Close idle pooled connections (call on shutdown so the process can exit promptly). */
  close() {
    this.jsonAgent.destroy();
    this.streamAgent.destroy();
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

  /** Create a new KEK version. Existing data stays readable; run rewrap/migrate to move it. Needs the admin role. */
  async rotateKeys(): Promise<number> {
    // Only the leader can rotate. Try every instance until one accepts; followers answer 409.
    let last: unknown;
    for (let i = 0; i < this.urls.length; i++) {
      const base = this.urls[(this.preferred + i) % this.urls.length]!;
      try {
        return (await this.jsonOnce<{ version: number }>(base, "POST", "/v1/keys/rotate", {}, true)).version;
      } catch (e) {
        last = e;
        const retryable = e instanceof CryplusError && (e.code === "read_only_instance" || e.code.startsWith("unreachable"));
        if (!retryable) throw e;
      }
    }
    throw last;
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
      const u = new URL(this.urls[this.preferred]! + path);
      const lib = u.protocol === "https:" ? https : http;
      const req = lib.request(
        u,
        {
          method: "POST",
          agent: this.streamAgent,
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
    let last: unknown;
    // Walk the instances starting at the last one that worked; move on only when unreachable.
    for (let i = 0; i < this.urls.length; i++) {
      const idx = (this.preferred + i) % this.urls.length;
      try {
        const out = await this.jsonRetry<T>(this.urls[idx]!, method, path, body, auth);
        this.preferred = idx;
        return out;
      } catch (e) {
        last = e;
        if (!(e instanceof CryplusError && e.code.startsWith("unreachable"))) throw e;
      }
    }
    throw last;
  }

  private async jsonRetry<T>(base: string, method: string, path: string, body: unknown, auth: boolean): Promise<T> {
    try {
      return await this.jsonOnce<T>(base, method, path, body, auth);
    } catch (e) {
      // A pooled keep-alive socket can be closed by the server between calls; the request then
      // fails before any response. Retry once on a fresh socket.
      if (e instanceof CryplusError && /unreachable:.*(ECONNRESET|socket hang up|EPIPE)/.test(e.code)) {
        return this.jsonOnce<T>(base, method, path, body, auth);
      }
      throw e;
    }
  }

  private jsonOnce<T>(base: string, method: string, path: string, body: unknown, auth: boolean): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const u = new URL(base + path);
      const lib = u.protocol === "https:" ? https : http;
      const payload = body !== undefined ? Buffer.from(JSON.stringify(body)) : undefined;
      const req = lib.request(
        u,
        {
          method,
          agent: this.jsonAgent,
          headers: {
            ...(auth ? { Authorization: `Bearer ${this.token}` } : {}),
            ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("error", (e) => reject(new CryplusError("unreachable: " + e.message)));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            let parsed: any = undefined;
            try {
              parsed = text ? JSON.parse(text) : undefined;
            } catch {}
            const status = res.statusCode ?? 0;
            if (status < 200 || status >= 300) reject(new CryplusError(parsed?.error ?? `http_${status}`, status));
            else resolve(parsed as T);
          });
        },
      );
      req.setTimeout(this.timeoutMs, () => req.destroy(new Error("timeout")));
      req.on("error", (e) => reject(new CryplusError("unreachable: " + e.message)));
      if (payload) req.write(payload);
      req.end();
    });
  }
}
