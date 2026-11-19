// Client-side encrypted S3: real cryplus-core + AWS SDK v3 (+ lib-storage multipart)
// against a local S3-compatible emulator (bin/fakes3.exe, NOT AWS).
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { CreateBucketCommand, GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import { Cryplus, EncryptedS3 } from "cryplus";

const here = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(here, "../../bin");
const TOKEN = "s3-token-0123456789abcdef";
// S3_SERVER=gostore runs the suite against gostore-s3 (real SigV4 server) instead of the emulator.
const USE_GOSTORE = process.env.S3_SERVER === "gostore";
const S3_KEY = USE_GOSTORE ? "testadmin" : "test";
const S3_SECRET = USE_GOSTORE ? "testsecret-123456" : "test";

const freePort = () =>
  new Promise<number>((res) => {
    const s = createServer().listen(0, "127.0.0.1", () => {
      const p = (s.address() as any).port;
      s.close(() => res(p));
    });
  });

async function waitFor(url: string) {
  for (let i = 0; i < 100; i++) {
    try {
      await fetch(url);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  throw new Error("not up: " + url);
}

const collect = async (r: Readable) => {
  const out: Buffer[] = [];
  for await (const c of r) out.push(c as Buffer);
  return Buffer.concat(out);
};
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

let procs: ChildProcess[] = [];
let tmp: string;
let s3: S3Client;
let cp: Cryplus;
let enc: EncryptedS3;
const BUCKET = "vault";

before(async () => {
  tmp = mkdtempSync(path.join(tmpdir(), "cryplus-s3-"));
  const [corePort, s3Port] = [await freePort(), await freePort()];
  procs.push(
    spawn(path.join(BIN, "cryplus-core.exe"), ["--listen", `127.0.0.1:${corePort}`, "--keyfile", path.join(tmp, "k.json"), "--audit-log", ""], {
      env: { ...process.env, CRYPLUS_TOKEN: TOKEN },
      stdio: "ignore",
    }),
    USE_GOSTORE
      ? spawn(path.join(BIN, "gostore.exe"), ["server", path.join(tmp, "gostore-data")], {
          env: { ...process.env, GOSTORE_ROOT_USER: S3_KEY, GOSTORE_ROOT_PASSWORD: S3_SECRET, GOSTORE_ADDRESS: `127.0.0.1:${s3Port}` },
          stdio: "ignore",
        })
      : spawn(path.join(BIN, "fakes3.exe"), ["--listen", `127.0.0.1:${s3Port}`], { stdio: "ignore" }),
  );
  await waitFor(`http://127.0.0.1:${corePort}/healthz`);
  await waitFor(`http://127.0.0.1:${s3Port}/`);
  s3 = new S3Client({
    endpoint: `http://127.0.0.1:${s3Port}`,
    region: "us-east-1",
    forcePathStyle: true,
    credentials: { accessKeyId: S3_KEY, secretAccessKey: S3_SECRET },
  });
  await s3.send(new CreateBucketCommand({ Bucket: BUCKET }));
  cp = new Cryplus({ url: `http://127.0.0.1:${corePort}`, token: TOKEN });
  enc = new EncryptedS3(cp, { client: s3, PutObjectCommand, GetObjectCommand, Upload: Upload as any });
});

after(async () => {
  for (const p of procs) p.kill();
  await new Promise((r) => setTimeout(r, 200));
  try {
    rmSync(tmp, { recursive: true, force: true });
  } catch {}
});

const rawGet = async (key: string) =>
  collect((await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: key }))).Body as Readable);

describe("encrypted S3", () => {
  it("small object: S3 holds only ciphertext, round-trips exactly", async () => {
    const secret = Buffer.from("contrato confidencial: CPF 123.456.789-00 ".repeat(50));
    await enc.put("acme", BUCKET, "docs/a.txt", secret);
    const stored = await rawGet("docs/a.txt");
    assert.equal(stored.includes("CPF 123.456"), false, "plaintext visible in S3");
    assert.ok(stored.length > secret.length);
    const back = await collect(await enc.get("acme", BUCKET, "docs/a.txt"));
    assert.ok(back.equals(secret));
  });

  it("large object (multipart, ~12 MB) round-trips with matching hash", async () => {
    const big = randomBytes(12 * 1024 * 1024);
    await enc.put("acme", BUCKET, "big/blob.bin", Readable.from([big]));
    const stored = await rawGet("big/blob.bin");
    assert.ok(stored.length > big.length);
    const back = await collect(await enc.get("acme", BUCKET, "big/blob.bin"));
    assert.equal(sha(back), sha(big));
  });

  it("another tenant cannot read the object", async () => {
    await assert.rejects(enc.get("evil", BUCKET, "docs/a.txt").then(collect), /decryption_failed/);
  });

  it("object renamed/copied to another key stops decrypting (bucket/key are bound)", async () => {
    const stored = await rawGet("docs/a.txt");
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: "docs/stolen.txt", Body: stored }));
    await assert.rejects(enc.get("acme", BUCKET, "docs/stolen.txt").then(collect), /decryption_failed/);
  });

  it("tampered object in the bucket is detected", async () => {
    const stored = Buffer.from(await rawGet("docs/a.txt"));
    stored[stored.length - 20] = stored[stored.length - 20]! ^ 1;
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: "docs/a.txt", Body: stored }));
    await assert.rejects(async () => collect(await enc.get("acme", BUCKET, "docs/a.txt")));
  });

  it("truncated object in the bucket is detected", async () => {
    const secret = randomBytes(300_000);
    await enc.put("acme", BUCKET, "docs/t.bin", secret);
    const stored = await rawGet("docs/t.bin");
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: "docs/t.bin", Body: stored.subarray(0, 140_000) }));
    await assert.rejects(async () => collect(await enc.get("acme", BUCKET, "docs/t.bin")));
  });

  it("KEK rotation: old object still readable; header re-wrap keeps it readable", async () => {
    const data = randomBytes(200_000);
    await enc.put("acme", BUCKET, "rot/x.bin", data);
    await cp.rotateKeys();
    assert.ok((await collect(await enc.get("acme", BUCKET, "rot/x.bin"))).equals(data), "old object unreadable after rotation");
    const stored = await rawGet("rot/x.bin");
    const rewrapped = await collect(await cp.rewrapStream({ tenant: "acme", collection: BUCKET, field: "rot/x.bin" }, Readable.from([stored])));
    assert.notDeepEqual(rewrapped.subarray(0, 120), stored.subarray(0, 120), "header should change");
    assert.equal(rewrapped.length, stored.length);
    assert.ok(rewrapped.subarray(120).equals(stored.subarray(120)), "payload bytes must be untouched");
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: "rot/x.bin", Body: rewrapped }));
    assert.ok((await collect(await enc.get("acme", BUCKET, "rot/x.bin"))).equals(data));
  });
});
