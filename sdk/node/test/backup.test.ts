import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { after, before, describe, it } from "node:test";
import { Cryplus } from "../src/index.ts";
import { CORE_BIN, startCore, type Core } from "./harness.ts";

// Disaster-recovery drill: encrypt a "database dump", then decrypt it OFFLINE with only the key file and passphrase
// (no running service), including after key rotation, tampering and a wrong passphrase.
let dir: string, keyfile: string;
let core: Core;
let cp: Cryplus;
const PASS = "backup drill passphrase 123";
const ENV = { ...process.env, CRYPLUS_PASSPHRASE: PASS };
const T = ["--tenant", "backup:2026-11", "--collection", "backups", "--field", "operax-2026-11-19.dump"];
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

const run = (args: string[], env: NodeJS.ProcessEnv = ENV, input?: Buffer) =>
  spawnSync(CORE_BIN, ["file", ...args, "--keyfile", keyfile], { env, input, maxBuffer: 512 << 20, timeout: 120_000 });

let plain: Buffer, plainPath: string;

before(async () => {
  dir = mkdtempSync(path.join(tmpdir(), "cryplus-backup-"));
  keyfile = path.join(dir, "keys.json");
  // a leader creates the sealed key file, exactly as in production, then goes away
  core = await startCore(ENV, { args: ["--keyfile", keyfile] });
  cp = new Cryplus({ url: core.url, token: core.token });
  // ~30 MB "dump": PGDMP magic + SQL text with recognisable secrets + incompressible noise
  const sql = Buffer.from("INSERT INTO clientes VALUES ('Maria Silva','123.456.789-00','maria@example.com');\n".repeat(20_000));
  plain = Buffer.concat([Buffer.from("PGDMP\x01\x0e\x00"), sql, randomBytes(20 * 1024 * 1024)]);
  plainPath = path.join(dir, "operax.dump");
  writeFileSync(plainPath, plain);
});
after(async () => {
  cp.close();
  await core.stop().catch(() => {});
  rmSync(dir, { recursive: true, force: true });
});

describe("encrypted backups and offline disaster recovery", () => {
  let enc: string;

  it("encrypts a large dump; the file leaks nothing", () => {
    enc = path.join(dir, "operax.dump.cp");
    const r = run(["encrypt", ...T, plainPath, enc]);
    assert.equal(r.status, 0, r.stderr?.toString());
    const bytes = readFileSync(enc);
    assert.ok(bytes.length > plain.length && bytes.length < plain.length * 1.01, "overhead should be tiny");
    for (const needle of ["PGDMP", "123.456.789-00", "maria@example.com", "INSERT INTO"]) {
      assert.equal(bytes.includes(Buffer.from(needle)), false, `${needle} visible in the encrypted backup`);
    }
    assert.equal(existsSync(enc + ".partial"), false);
  });

  it("restores byte-for-byte OFFLINE with only the key file and passphrase", () => {
    const out = path.join(dir, "restored.dump");
    const r = run(["decrypt", ...T, enc, out]);
    assert.equal(r.status, 0, r.stderr?.toString());
    assert.equal(sha(readFileSync(out)), sha(plain));
  });

  it("works as a pipe (stdin/stdout), the way pg_dump | cryplus | upload would", () => {
    const e = run(["encrypt", ...T, "-", "-"], ENV, plain.subarray(0, 3_000_000));
    assert.equal(e.status, 0, e.stderr?.toString());
    const d = run(["decrypt", ...T, "-", "-"], ENV, e.stdout as Buffer);
    assert.equal(d.status, 0, d.stderr?.toString());
    assert.ok((d.stdout as Buffer).equals(plain.subarray(0, 3_000_000)));
  });

  it("a backup made THROUGH THE SERVICE restores offline (and vice versa)", async () => {
    const { Readable } = await import("node:stream");
    const ctx = { tenant: "backup:2026-11", collection: "backups", field: "operax-2026-11-19.dump" };
    const chunks: Buffer[] = [];
    for await (const c of await cp.encryptStream(ctx, Readable.from([plain.subarray(0, 5_000_000)]))) chunks.push(c as Buffer);
    const viaService = path.join(dir, "via-service.cp");
    writeFileSync(viaService, Buffer.concat(chunks));
    const out = path.join(dir, "via-service.out");
    const r = run(["decrypt", ...T, viaService, out]);
    assert.equal(r.status, 0, r.stderr?.toString());
    assert.ok(readFileSync(out).equals(plain.subarray(0, 5_000_000)));
    // offline-encrypted file decrypts through the service
    const dec: Buffer[] = [];
    for await (const c of await cp.decryptStream(ctx, Readable.from([readFileSync(enc)]))) dec.push(c as Buffer);
    assert.equal(sha(Buffer.concat(dec)), sha(plain));
  });

  it("old backups still restore after the KEK is rotated", async () => {
    await cp.rotateKeys();
    const out = path.join(dir, "after-rotation.dump");
    const r = run(["decrypt", ...T, enc, out]);
    assert.equal(r.status, 0, r.stderr?.toString());
    assert.equal(sha(readFileSync(out)), sha(plain));
  });

  it("a corrupted backup fails loudly and leaves NO file that could be mistaken for a restore", () => {
    const bytes = readFileSync(enc);
    for (const [name, mutate] of [
      ["flipped byte in the middle", (b: Buffer) => ((b[b.length >> 1] = b[b.length >> 1]! ^ 1), b)],
      ["flipped byte in the last chunk", (b: Buffer) => ((b[b.length - 5] = b[b.length - 5]! ^ 1), b)],
      ["truncated at a chunk boundary", (b: Buffer) => b.subarray(0, 120 + 3 * (65536 + 16))],
      ["truncated mid-chunk", (b: Buffer) => b.subarray(0, b.length - 1000)],
      ["garbage appended", (b: Buffer) => Buffer.concat([b, Buffer.from("tail")])],
    ] as const) {
      const bad = path.join(dir, "bad.cp");
      writeFileSync(bad, mutate(Buffer.from(bytes)));
      const out = path.join(dir, "bad.out");
      const r = run(["decrypt", ...T, bad, out]);
      assert.notEqual(r.status, 0, `${name}: decrypt must fail`);
      assert.equal(existsSync(out), false, `${name}: a final output file exists`);
      assert.equal(existsSync(out + ".partial"), false, `${name}: partial file left behind`);
    }
  });

  it("refuses the wrong tenant, the wrong object name, and the wrong passphrase", () => {
    const out = path.join(dir, "x.out");
    assert.notEqual(run(["decrypt", "--tenant", "backup:other", "--collection", "backups", "--field", "operax-2026-11-19.dump", enc, out]).status, 0);
    assert.notEqual(run(["decrypt", "--tenant", "backup:2026-11", "--collection", "backups", "--field", "renamed.dump", enc, out]).status, 0);
    const wrong = run(["decrypt", ...T, enc, out], { ...process.env, CRYPLUS_PASSPHRASE: "this is definitely not it" });
    assert.notEqual(wrong.status, 0);
    assert.match(String(wrong.stderr), /passphrase|unseal/i);
    assert.equal(existsSync(out), false);
  });

  it("the passphrase can come from a file (Docker/Kubernetes secrets) instead of the environment", () => {
    const pf = path.join(dir, "passphrase.txt");
    writeFileSync(pf, PASS + "\n"); // trailing newline, as secret files usually have
    const env = { ...process.env, CRYPLUS_PASSPHRASE: "", CRYPLUS_PASSPHRASE_FILE: pf };
    const out = path.join(dir, "from-secret.out");
    const r = run(["decrypt", ...T, enc, out], env);
    assert.equal(r.status, 0, r.stderr?.toString());
    assert.equal(sha(readFileSync(out)), sha(plain));
    const missing = run(["decrypt", ...T, enc, path.join(dir, "n.out")], { ...env, CRYPLUS_PASSPHRASE_FILE: path.join(dir, "missing.txt") });
    assert.notEqual(missing.status, 0);
  });

  it("offline commands never create a key file (a typo must not mint new keys)", () => {
    const missing = path.join(dir, "does-not-exist.json");
    const r = spawnSync(CORE_BIN, ["file", "encrypt", ...T, "--keyfile", missing, plainPath, path.join(dir, "o.cp")], { env: ENV });
    assert.notEqual(r.status, 0);
    assert.equal(existsSync(missing), false);
  });
});
