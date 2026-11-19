import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { after, before, describe, it } from "node:test";
import { Cryplus, CryplusError } from "../src/index.ts";
import { startCore, type Core } from "./harness.ts";

let core: Core;
let c: Cryplus;
const ctx = { tenant: "acme", collection: "User", field: "cpf" };

before(async () => {
  core = await startCore();
  c = new Cryplus({ url: core.url, token: core.token });
});
after(() => core.stop());

const collect = async (r: Readable) => {
  const out: Buffer[] = [];
  for await (const ch of r) out.push(ch as Buffer);
  return Buffer.concat(out);
};

describe("client", () => {
  it("round-trips strings and unicode", async () => {
    for (const s of ["", "123.456.789-00", "ação ✓ 日本語", "x".repeat(100_000)]) {
      const ct = await c.encrypt(ctx, s);
      assert.match(ct, /^cp1\./);
      assert.equal(await c.decrypt(ctx, ct), s);
    }
  });

  it("round-trips raw bytes", async () => {
    const bytes = Uint8Array.from([0, 255, 1, 254, 0]);
    const ct = await c.encrypt(ctx, bytes);
    assert.deepEqual(Buffer.from(await c.decryptBytes(ctx, ct)), Buffer.from(bytes));
  });

  it("auto-batches a burst and keeps results ordered", async () => {
    const count = () => readFileSync(core.auditPath, "utf8").split("\n").filter(Boolean).length;
    const before = count();
    const vals = Array.from({ length: 300 }, (_, i) => "v" + i);
    const cts = await Promise.all(vals.map((v) => c.encrypt(ctx, v)));
    const back = await Promise.all(cts.map((ct) => c.decrypt(ctx, ct)));
    assert.deepEqual(back, vals);
    assert.equal(new Set(cts).size, 300);
    // every operation is audited individually even though they were batched
    assert.equal(count() - before, 600);
  });

  it("one failing item does not poison its batch", async () => {
    const good = await c.encrypt(ctx, "ok");
    const [a, b] = await Promise.allSettled([c.decrypt(ctx, good), c.decrypt(ctx, "cp1.garbage")]);
    assert.equal(a.status, "fulfilled");
    assert.equal(b.status, "rejected");
    assert.equal((b as PromiseRejectedResult).reason.code, "malformed_ciphertext");
  });

  it("refuses to decrypt under another tenant or field with a generic error", async () => {
    const ct = await c.encrypt(ctx, "secret");
    await assert.rejects(c.decrypt({ ...ctx, tenant: "evil" }, ct), (e: CryplusError) => e.code === "decryption_failed");
    await assert.rejects(c.decrypt({ ...ctx, field: "phone" }, ct), (e: CryplusError) => e.code === "decryption_failed");
  });

  it("requires a tenant", async () => {
    await assert.rejects(c.encrypt({ tenant: "" }, "x"), (e: CryplusError) => e.code === "tenant_required");
  });

  it("rejects a bad token", async () => {
    const bad = new Cryplus({ url: core.url, token: "wrong-token-0123456789" });
    await assert.rejects(bad.encrypt(ctx, "x"), (e: CryplusError) => e.code === "unauthorized");
  });

  it("blind index is deterministic, scoped, and rotation-stable", async () => {
    const a = await c.blindIndex(ctx, "111");
    assert.equal(a, await c.blindIndex(ctx, "111"));
    assert.notEqual(a, await c.blindIndex(ctx, "222"));
    assert.notEqual(a, await c.blindIndex({ ...ctx, tenant: "other" }, "111"));
    await c.rotateKeys();
    assert.equal(a, await c.blindIndex(ctx, "111"));
  });

  it("rotate + rewrap moves old ciphertext to the new KEK, data intact", async () => {
    const old = await c.encrypt(ctx, "keep me");
    const v = await c.rotateKeys();
    const k = await c.keys();
    assert.equal(k.current, v);
    const r = await c.rewrap(ctx, old);
    assert.equal(r.changed, true);
    assert.equal(await c.decrypt(ctx, r.ciphertext), "keep me");
    assert.equal((await c.rewrap(ctx, r.ciphertext)).changed, false);
  });
});

describe("streaming", () => {
  const big = Buffer.alloc(500_000);
  for (let i = 0; i < big.length; i++) big[i] = (i * 31) & 0xff;

  it("encrypts and decrypts large streams without exposing plaintext", async () => {
    const enc = await collect(await c.encryptStream(ctx, Readable.from([big])));
    assert.equal(enc.includes(big.subarray(1000, 1064)), false);
    const dec = await collect(await c.decryptStream(ctx, Readable.from([enc])));
    assert.ok(dec.equals(big));
  });

  it("rejects the wrong tenant before releasing any plaintext", async () => {
    const enc = await collect(await c.encryptStream(ctx, Readable.from([big])));
    await assert.rejects(
      c.decryptStream({ ...ctx, tenant: "evil" }, Readable.from([enc])),
      (e: CryplusError) => e.code === "decryption_failed",
    );
  });

  it("surfaces tampering as a stream error, not a clean short read", async () => {
    const enc = await collect(await c.encryptStream(ctx, Readable.from([big])));
    const bad = Buffer.from(enc);
    bad[bad.length - 10] = bad[bad.length - 10]! ^ 1;
    // fail-closed: the error may surface when the response starts or mid-body
    await assert.rejects(async () => collect(await c.decryptStream(ctx, Readable.from([bad]))));
  });

  it("surfaces truncation as a stream error", async () => {
    const enc = await collect(await c.encryptStream(ctx, Readable.from([big])));
    await assert.rejects(async () => collect(await c.decryptStream(ctx, Readable.from([enc.subarray(0, 70_000)]))));
  });
});
