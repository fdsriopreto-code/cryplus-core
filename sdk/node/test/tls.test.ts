import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { after, before, describe, it } from "node:test";
import { Cryplus, CryplusError } from "../src/index.ts";
import { CORE_BIN, startCore, type Core } from "./harness.ts";

let core: Core;
let dir: string;
let tokApp: string, tokOps: string, tokBackup: string;
const pem = (f: string) => readFileSync(path.join(dir, f));

const cli = (...args: string[]) => {
  const r = spawnSync(CORE_BIN, args, { encoding: "utf8" });
  assert.equal(r.status, 0, `cryplus-core ${args.join(" ")} failed: ${r.stderr}`);
  return r.stdout.trim();
};

const client = (token: string, opts: Partial<ConstructorParameters<typeof Cryplus>[0]> = {}) =>
  new Cryplus({
    url: core.url,
    token,
    tls: { ca: pem("ca.pem"), cert: pem("client.pem"), key: pem("client-key.pem") },
    timeoutMs: 5000,
    ...opts,
  });

const ctx = { tenant: "acme-1", collection: "User", field: "cpf" };
const collect = async (r: Readable) => {
  const out: Buffer[] = [];
  for await (const c of r) out.push(c as Buffer);
  return Buffer.concat(out);
};

before(async () => {
  dir = mkdtempSync(path.join(tmpdir(), "cryplus-tls-"));
  cli("tls", "dev-certs", "--out", dir, "--client-name", "operax-api");
  const tokens = path.join(dir, "tokens.json");
  tokApp = cli("token", "new", "--name", "operax-api", "--roles", "crypt", "--tenants", "acme-*,__platform__", "--file", tokens);
  tokBackup = cli("token", "new", "--name", "backup-job", "--roles", "crypt", "--tenants", "backup:*", "--file", tokens);
  tokOps = cli("token", "new", "--name", "ops", "--roles", "admin", "--tenants", "*", "--file", tokens);
  core = await startCore(
    {},
    {
      scheme: "https",
      waitTcp: true,
      args: [
        "--tls-cert", path.join(dir, "server.pem"),
        "--tls-key", path.join(dir, "server-key.pem"),
        "--client-ca", path.join(dir, "ca.pem"),
        "--tokens-file", tokens,
        "--reload-interval", "100ms",
      ],
    },
  );
});
after(async () => {
  await core.stop();
  rmSync(dir, { recursive: true, force: true });
});

describe("TLS 1.3 + mTLS + per-service tokens (real core)", () => {
  it("works end to end over mutual TLS", async () => {
    const c = client(tokApp);
    const ct = await c.encrypt(ctx, "123.456.789-00");
    assert.equal(await c.decrypt(ctx, ct), "123.456.789-00");
    const enc = await collect(await c.encryptStream(ctx, Readable.from([Buffer.alloc(300_000, 7)])));
    assert.ok((await collect(await c.decryptStream(ctx, Readable.from([enc])))).equals(Buffer.alloc(300_000, 7)));
    c.close();
  });

  it("refuses a client with no certificate", async () => {
    const c = client(tokApp, { tls: { ca: pem("ca.pem") } });
    await assert.rejects(c.encrypt(ctx, "x"), (e: CryplusError) => e.code.startsWith("unreachable"));
    c.close();
  });

  it("refuses a client certificate from a different CA", async () => {
    const other = mkdtempSync(path.join(tmpdir(), "cryplus-tls-other-"));
    cli("tls", "dev-certs", "--out", other, "--client-name", "attacker");
    const c = client(tokApp, { tls: { ca: pem("ca.pem"), cert: readFileSync(path.join(other, "client.pem")), key: readFileSync(path.join(other, "client-key.pem")) } });
    await assert.rejects(c.encrypt(ctx, "x"), (e: CryplusError) => e.code.startsWith("unreachable"));
    c.close();
    rmSync(other, { recursive: true, force: true });
  });

  it("refuses to talk to a server whose certificate it does not trust (no skip-verify switch)", async () => {
    const other = mkdtempSync(path.join(tmpdir(), "cryplus-tls-other-"));
    cli("tls", "dev-certs", "--out", other);
    const c = client(tokApp, { tls: { ca: readFileSync(path.join(other, "ca.pem")), cert: pem("client.pem"), key: pem("client-key.pem") } });
    await assert.rejects(c.encrypt(ctx, "x"), (e: CryplusError) => e.code.startsWith("unreachable"));
    c.close();
    rmSync(other, { recursive: true, force: true });
  });

  it("a valid certificate is not enough: the bearer token is still required", async () => {
    const c = client("not-a-real-token-0123456789abcdef");
    await assert.rejects(c.encrypt(ctx, "x"), (e: CryplusError) => e.code === "unauthorized");
    c.close();
  });

  it("reads TLS material from CRYPLUS_* environment variables", async () => {
    const saved = { ...process.env };
    process.env.CRYPLUS_CA = path.join(dir, "ca.pem");
    process.env.CRYPLUS_CLIENT_CERT = path.join(dir, "client.pem");
    process.env.CRYPLUS_CLIENT_KEY = path.join(dir, "client-key.pem");
    try {
      const c = new Cryplus({ url: core.url, token: tokApp });
      assert.match(await c.encrypt(ctx, "env"), /^cp1\./);
      c.close();
    } finally {
      for (const k of ["CRYPLUS_CA", "CRYPLUS_CLIENT_CERT", "CRYPLUS_CLIENT_KEY"]) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
    }
  });

  it("rejects TLS options on a plain http:// URL instead of silently ignoring them", () => {
    assert.throws(() => new Cryplus({ url: "http://127.0.0.1:1", token: "x".repeat(20), tls: { ca: pem("ca.pem") } }), /not https/);
  });

  it("tenant allowlist: a service only reaches its own tenants", async () => {
    const app = client(tokApp);
    assert.match(await app.encrypt({ tenant: "acme-42" }, "ok"), /^cp1\./);
    assert.match(await app.encrypt({ tenant: "__platform__" }, "ok"), /^cp1\./);
    await assert.rejects(app.encrypt({ tenant: "other-co" }, "x"), (e: CryplusError) => e.code === "tenant_forbidden");
    // the backup service cannot read the app's data even though it holds a valid token
    const ct = await app.encrypt({ tenant: "acme-42" }, "secret");
    const bk = client(tokBackup);
    await assert.rejects(bk.decrypt({ tenant: "acme-42" }, ct), (e: CryplusError) => e.code === "tenant_forbidden");
    // inside a batch only the forbidden item fails
    const [a, b] = await Promise.allSettled([bk.encrypt({ tenant: "backup:2026-11" }, "ok"), bk.encrypt({ tenant: "acme-42" }, "no")]);
    assert.equal(a.status, "fulfilled");
    assert.equal(b.status, "rejected");
    // streams are covered too
    await assert.rejects(bk.encryptStream({ tenant: "acme-42" }, Readable.from([Buffer.from("x")])), (e: CryplusError) => e.code === "tenant_forbidden");
    app.close();
    bk.close();
  });

  it("roles: crypt services cannot rotate keys; the admin service cannot read data", async () => {
    const app = client(tokApp);
    await assert.rejects(app.rotateKeys(), (e: CryplusError) => e.code === "role_forbidden");
    await assert.rejects(app.keys(), (e: CryplusError) => e.code === "role_forbidden");
    const ops = client(tokOps);
    const before = (await ops.keys()).current;
    assert.equal(await ops.rotateKeys(), before + 1);
    await assert.rejects(ops.encrypt({ tenant: "acme-1" }, "x"), (e: CryplusError) => e.code === "role_forbidden");
    // data written before the rotation still decrypts for the app
    const ct = await app.encrypt({ tenant: "acme-1" }, "after");
    assert.equal(await app.decrypt({ tenant: "acme-1" }, ct), "after");
    app.close();
    ops.close();
  });

  it("revoking a service in the tokens file takes effect without restarting the core", async () => {
    const tokens = path.join(dir, "tokens.json");
    const bk = client(tokBackup);
    assert.match(await bk.encrypt({ tenant: "backup:1" }, "x"), /^cp1\./);
    const tf = JSON.parse(readFileSync(tokens, "utf8"));
    tf.services = tf.services.filter((s: any) => s.name !== "backup-job");
    writeFileSync(tokens, JSON.stringify(tf));
    const deadline = Date.now() + 5000;
    let revoked = false;
    while (Date.now() < deadline && !revoked) {
      await new Promise((r) => setTimeout(r, 150));
      revoked = await bk.encrypt({ tenant: "backup:1" }, "x").then(() => false, (e: CryplusError) => e.code === "unauthorized");
    }
    assert.ok(revoked, "revoked token kept working");
    // and the other services were unaffected
    const app = client(tokApp);
    assert.match(await app.encrypt({ tenant: "acme-1" }, "still works"), /^cp1\./);
    app.close();
    bk.close();
  });
});
