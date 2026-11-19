import { Readable } from "node:stream";
import type { Cryplus } from "./client.ts";

/** The pieces of @aws-sdk/client-s3 (and optionally lib-storage) this helper needs. */
export interface S3Deps {
  client: { send(cmd: any): Promise<any> };
  PutObjectCommand: new (input: any) => any;
  GetObjectCommand: new (input: any) => any;
  /** From @aws-sdk/lib-storage. Recommended: lets large streams upload without buffering. */
  Upload?: new (opts: { client: any; params: any }) => { done(): Promise<any> };
}

/**
 * Client-side encrypted S3: bytes are encrypted by cryplus-core before they
 * leave your process, so S3 (and anyone with bucket access) only sees
 * ciphertext. The object's bucket and key are bound into the encryption
 * context, so an object copied or renamed to another key stops decrypting.
 */
export class EncryptedS3 {
  private cryplus: Cryplus;
  private s3: S3Deps;

  constructor(cryplus: Cryplus, s3: S3Deps) {
    this.cryplus = cryplus;
    this.s3 = s3;
  }

  private ctx(tenant: string, bucket: string, key: string) {
    return { tenant, collection: bucket, field: key };
  }

  async put(tenant: string, bucket: string, key: string, body: Readable | Uint8Array | string, extra: Record<string, unknown> = {}) {
    const input = body instanceof Readable ? body : Readable.from([typeof body === "string" ? Buffer.from(body) : Buffer.from(body)]);
    const enc = await this.cryplus.encryptStream(this.ctx(tenant, bucket, key), input);
    const params = { Bucket: bucket, Key: key, Metadata: { cryplus: "stream-v1" }, ...extra };
    if (this.s3.Upload) {
      return new this.s3.Upload({ client: this.s3.client, params: { ...params, Body: enc } }).done();
    }
    // Fallback without lib-storage: PutObject needs a known length, so buffer.
    const chunks: Buffer[] = [];
    for await (const c of enc) chunks.push(c as Buffer);
    return this.s3.client.send(new this.s3.PutObjectCommand({ ...params, Body: Buffer.concat(chunks) }));
  }

  /** Returns a stream of plaintext. It errors (never ends cleanly) on tampering or truncation. */
  async get(tenant: string, bucket: string, key: string): Promise<Readable> {
    const res = await this.s3.client.send(new this.s3.GetObjectCommand({ Bucket: bucket, Key: key }));
    return this.cryplus.decryptStream(this.ctx(tenant, bucket, key), res.Body as Readable);
  }
}
