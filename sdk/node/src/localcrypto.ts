/**
 * In-process implementation of the cryplus envelope format, used when tenant keys are cached in the SDK
 * (`keyCache`). It reads and writes EXACTLY the same bytes as the Go service (so data written either way opens
 * either way); that is verified against the real binary in the test suite.
 *
 *   [0] format 1   [1] algorithm (1 = XChaCha20-Poly1305, 2 = AES-256-GCM)   [2:6] KEK version (u32 BE)
 *   [6:8] wrapped length (u16 BE)   [..] wrapped DEK = nonce(24) || XChaCha20-Poly1305(KEK_tenant, DEK)
 *   [..] data nonce   [..] ciphertext || tag
 * text = "cp1." + base64url(raw), unpadded.
 */
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import type { Context } from "./client.ts";

export const ALG_XCHACHA = 1;
export const ALG_AESGCM = 2;
export type LocalAlg = "aes256gcm" | "xchacha20";

const lp = (b: Buffer) => {
  const h = Buffer.alloc(4);
  h.writeUInt32BE(b.length);
  return Buffer.concat([h, b]);
};
const s = (x: string | undefined) => Buffer.from(x ?? "", "utf8");

export const ctxAad = (c: Context) => Buffer.concat([lp(s(c.tenant)), lp(s(c.collection)), lp(s(c.field)), lp(s(c.recordId))]);

const u32 = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};

const wrapAad = (version: number, tenant: string, aad: Buffer) =>
  Buffer.concat([Buffer.from("cryplus/wrap/v1"), u32(version), lp(s(tenant)), lp(aad)]);

const dataAad = (alg: number, aad: Buffer) => Buffer.concat([Buffer.from([0x63, 0x70, 0x2f, 0x64, 1, alg]), aad]); // "cp/d" 1 alg

// ---- XChaCha20-Poly1305 on top of Node's chacha20-poly1305 -----------------------

const rotl = (v: number, n: number) => ((v << n) | (v >>> (32 - n))) >>> 0;

/** HChaCha20 (draft-irtf-cfrg-xchacha, section 2.2): derives a subkey from a key and the first 16 bytes of an XChaCha nonce. */
export function hchacha20(key: Buffer, nonce16: Buffer): Buffer {
  const st = new Uint32Array(16);
  st[0] = 0x61707865;
  st[1] = 0x3320646e;
  st[2] = 0x79622d32;
  st[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) st[4 + i] = key.readUInt32LE(i * 4);
  for (let i = 0; i < 4; i++) st[12 + i] = nonce16.readUInt32LE(i * 4);
  const qr = (a: number, b: number, c: number, d: number) => {
    st[a] = (st[a]! + st[b]!) >>> 0; st[d] = rotl(st[d]! ^ st[a]!, 16);
    st[c] = (st[c]! + st[d]!) >>> 0; st[b] = rotl(st[b]! ^ st[c]!, 12);
    st[a] = (st[a]! + st[b]!) >>> 0; st[d] = rotl(st[d]! ^ st[a]!, 8);
    st[c] = (st[c]! + st[d]!) >>> 0; st[b] = rotl(st[b]! ^ st[c]!, 7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
    qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeUInt32LE(st[i]!, i * 4);
  for (let i = 0; i < 4; i++) out.writeUInt32LE(st[12 + i]!, 16 + i * 4);
  return out;
}

function xchachaKeyNonce(key: Buffer, nonce24: Buffer) {
  return { k: hchacha20(key, nonce24.subarray(0, 16)), n: Buffer.concat([Buffer.alloc(4), nonce24.subarray(16, 24)]) };
}

export function xchachaSeal(key: Buffer, nonce24: Buffer, aad: Buffer, pt: Buffer): Buffer {
  const { k, n } = xchachaKeyNonce(key, nonce24);
  const c = createCipheriv("chacha20-poly1305", k, n, { authTagLength: 16 });
  c.setAAD(aad, { plaintextLength: pt.length });
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}

export function xchachaOpen(key: Buffer, nonce24: Buffer, aad: Buffer, ctTag: Buffer): Buffer {
  if (ctTag.length < 16) throw new Error("short");
  const { k, n } = xchachaKeyNonce(key, nonce24);
  const d = createDecipheriv("chacha20-poly1305", k, n, { authTagLength: 16 });
  d.setAAD(aad, { plaintextLength: ctTag.length - 16 });
  d.setAuthTag(ctTag.subarray(ctTag.length - 16));
  return Buffer.concat([d.update(ctTag.subarray(0, ctTag.length - 16)), d.final()]);
}

const gcmSeal = (key: Buffer, nonce: Buffer, aad: Buffer, pt: Buffer) => {
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(aad);
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
};
const gcmOpen = (key: Buffer, nonce: Buffer, aad: Buffer, ctTag: Buffer) => {
  if (ctTag.length < 16) throw new Error("short");
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAAD(aad);
  d.setAuthTag(ctTag.subarray(ctTag.length - 16));
  return Buffer.concat([d.update(ctTag.subarray(0, ctTag.length - 16)), d.final()]);
};

// ---- envelope ---------------------------------------------------------------------

export interface ParsedEnvelope {
  alg: number;
  version: number;
  wrapped: Buffer;
  nonce: Buffer;
  ct: Buffer;
}

export class LocalCryptoError extends Error {
  code: "malformed_ciphertext" | "decryption_failed";
  constructor(code: "malformed_ciphertext" | "decryption_failed") {
    super(code);
    this.code = code;
  }
}

export function parseEnvelope(text: string): ParsedEnvelope {
  if (!text.startsWith("cp1.")) throw new LocalCryptoError("malformed_ciphertext");
  const raw = Buffer.from(text.slice(4), "base64url");
  if (raw.length < 8 || raw[0] !== 1) throw new LocalCryptoError("malformed_ciphertext");
  const alg = raw[1]!;
  const ns = alg === ALG_XCHACHA ? 24 : alg === ALG_AESGCM ? 12 : 0;
  if (!ns) throw new LocalCryptoError("malformed_ciphertext");
  const wl = raw.readUInt16BE(6);
  if (raw.length < 8 + wl + ns + 16) throw new LocalCryptoError("malformed_ciphertext");
  return {
    alg,
    version: raw.readUInt32BE(2),
    wrapped: raw.subarray(8, 8 + wl),
    nonce: raw.subarray(8 + wl, 8 + wl + ns),
    ct: raw.subarray(8 + wl + ns),
  };
}

/** Encrypt under a tenant KEK (as fetched from the service) with a fresh data key. */
export function encryptLocal(kek: Buffer, version: number, ctx: Context, pt: Buffer, alg: LocalAlg = "aes256gcm"): string {
  const aad = ctxAad(ctx);
  const dek = randomBytes(32);
  try {
    const wNonce = randomBytes(24);
    const wrapped = Buffer.concat([wNonce, xchachaSeal(kek, wNonce, wrapAad(version, ctx.tenant, aad), dek)]);
    const a = alg === "xchacha20" ? ALG_XCHACHA : ALG_AESGCM;
    const nonce = randomBytes(a === ALG_XCHACHA ? 24 : 12);
    const body = a === ALG_XCHACHA ? xchachaSeal(dek, nonce, dataAad(a, aad), pt) : gcmSeal(dek, nonce, dataAad(a, aad), pt);
    const wl = Buffer.alloc(2);
    wl.writeUInt16BE(wrapped.length);
    const raw = Buffer.concat([Buffer.from([1, a]), u32(version), wl, wrapped, nonce, body]);
    return "cp1." + raw.toString("base64url");
  } finally {
    dek.fill(0);
  }
}

/** Decrypt with the KEK for `p.version` and tenant `ctx.tenant`. Every failure is `decryption_failed`. */
export function openLocal(kek: Buffer, p: ParsedEnvelope, ctx: Context): Buffer {
  const aad = ctxAad(ctx);
  let dek: Buffer | undefined;
  try {
    if (p.wrapped.length < 24 + 16) throw new Error("short");
    dek = xchachaOpen(kek, p.wrapped.subarray(0, 24), wrapAad(p.version, ctx.tenant, aad), p.wrapped.subarray(24));
    return p.alg === ALG_XCHACHA ? xchachaOpen(dek, p.nonce, dataAad(p.alg, aad), p.ct) : gcmOpen(dek, p.nonce, dataAad(p.alg, aad), p.ct);
  } catch {
    throw new LocalCryptoError("decryption_failed");
  } finally {
    dek?.fill(0);
  }
}

/** Blind index with an index key fetched from the service: "bi1." + base64url(HMAC-SHA256(key, value)). */
export function blindIndexLocal(indexKey: Buffer, value: string): string {
  return "bi1." + createHmac("sha256", indexKey).update(value, "utf8").digest().toString("base64url");
}
