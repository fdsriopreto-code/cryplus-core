// Compatibility suite: Prisma 5.22 + plain JavaScript/CommonJS (the Operax stack).
// Needs the isolated Postgres from ../prisma-demo (`node pg.ts`). Uses its own schema ("p5").
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const { mkdtempSync, rmSync, readFileSync } = require("node:fs");
const { createServer } = require("node:net");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { after, before, describe, it } = require("node:test");
const { PrismaClient } = require("@prisma/client");
const { Cryplus, migrateModel, revertModel, parseSchema, withCryplus, withTenant } = require("cryplus");

const DB = "postgresql://cryplus:cryplus@127.0.0.1:54329/cryplus_demo?schema=p5";
const BIN = path.resolve(__dirname, "../../bin/cryplus-core.exe");
const SCHEMA_PATH = path.join(__dirname, "prisma/schema.prisma");
const TOKEN = "p5-token-0123456789abcdef";
const schema = parseSchema(readFileSync(SCHEMA_PATH, "utf8"));

let child, tmp, cp, raw, db;

const freePort = () =>
  new Promise((res) => {
    const s = createServer().listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });

before(async () => {
  tmp = mkdtempSync(path.join(tmpdir(), "cryplus-p5-"));
  const port = await freePort();
  child = spawn(BIN, ["--listen", `127.0.0.1:${port}`, "--keyfile", path.join(tmp, "k.json"), "--audit-log", ""], {
    env: { ...process.env, CRYPLUS_TOKEN: TOKEN, CRYPLUS_PASSPHRASE: "p5 passphrase for the key file" },
    stdio: ["ignore", "ignore", "inherit"],
  });
  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(url + "/healthz")).ok) break;
    } catch {}
    await new Promise((r) => setTimeout(r, 50));
  }
  cp = new Cryplus({ url, token: TOKEN });

  // plain, non-destructive `db push` into the dedicated "p5" schema
  execFileSync(process.execPath, [path.join(__dirname, "node_modules/prisma/build/index.js"), "db", "push", "--skip-generate"], {
    cwd: __dirname,
    env: { ...process.env, DATABASE_URL: DB },
    stdio: "pipe",
  });

  raw = new PrismaClient({ datasources: { db: { url: DB } } });
  await raw.mensagem.deleteMany({});
  await raw.conversa.deleteMany({});
  await raw.configuracao.deleteMany({});
  await raw.funcionario.deleteMany({});
  await raw.tenant.deleteMany({});

  // Operax-style wiring: platform tenant for the Tenant model, ambient tenant for the rest.
  db = withCryplus(new PrismaClient({ datasources: { db: { url: DB } } }), {
    cryplus: cp,
    schemaPath: SCHEMA_PATH,
    tenant: ({ model }) => (model === "Tenant" ? "__platform__" : undefined),
  });
});

after(async () => {
  await raw?.$disconnect();
  await db?.$disconnect();
  child?.kill();
  await new Promise((r) => setTimeout(r, 200));
  try {
    rmSync(tmp, { recursive: true, force: true });
  } catch {}
});

const dumpAll = async () => {
  const parts = [];
  for (const t of ["Tenant", "Funcionario", "Configuracao", "Mensagem"]) {
    const rows = await raw.$queryRawUnsafe(`SELECT x::text AS t FROM p5."${t}" x`);
    parts.push(...rows.map((r) => r.t));
  }
  return parts.join("\n");
};

describe("Prisma 5.22 + CommonJS", () => {
  let tenantA, tenantB;

  it("loads through require() and the extension installs on Prisma 5.22", () => {
    assert.equal(typeof withCryplus, "function");
    assert.equal(require("@prisma/client/package.json").version, "5.22.0");
  });

  it("platform model: tokens encrypted with no ambient tenant (signup / login / webhooks)", async () => {
    // no withTenant() here on purpose: the Tenant model resolves to __platform__
    const t = await db.tenant.create({ data: { nome: "Empresa A", mpOauthAccessToken: "APP_USR-secret-access", mpOauthRefreshToken: "TG-secret-refresh" } });
    tenantA = t.id;
    assert.equal(t.mpOauthAccessToken, "APP_USR-secret-access");
    const row = await raw.tenant.findUniqueOrThrow({ where: { id: tenantA } });
    assert.match(row.mpOauthAccessToken, /^cp1\./);
    assert.match(row.mpOauthRefreshToken, /^cp1\./);
    tenantB = (await db.tenant.create({ data: { nome: "Empresa B" } })).id;
  });

  it("generic key/value table: only valorSecreto is encrypted, valor stays queryable", async () => {
    await withTenant(tenantA, async () => {
      await db.configuracao.create({ data: { tenantId: tenantA, chave: "empresa_pix_chave", valorSecreto: "123.456.789-00" } });
      await db.configuracao.create({ data: { tenantId: tenantA, chave: "whatsapp_numero:1", valor: "5511999990000" } });
      const pix = await db.configuracao.findUnique({ where: { tenantId_chave: { tenantId: tenantA, chave: "empresa_pix_chave" } } });
      assert.equal(pix.valorSecreto, "123.456.789-00");
    });
    const rows = await raw.configuracao.findMany({ orderBy: { chave: "asc" } });
    assert.match(rows.find((r) => r.chave === "empresa_pix_chave").valorSecreto, /^cp1\./);
    assert.equal(rows.find((r) => r.chave === "whatsapp_numero:1").valor, "5511999990000", "non-sensitive column untouched (raw-SQL phone lookups keep working)");
  });

  it("CPF: encrypted, searchable by equality, and @@unique works on the blind index", async () => {
    await withTenant(tenantA, async () => {
      const f = await db.funcionario.create({ data: { tenantId: tenantA, nome: "Joao", cpf: "111.222.333-44", rg: "12.345.678-9" } });
      assert.equal(f.cpf, "111.222.333-44");
      assert.equal((await db.funcionario.findFirst({ where: { tenantId: tenantA, cpf: "11122233344" } }))?.id, f.id);
      // duplicate CPF in the same tenant, written differently, must still violate uniqueness
      await assert.rejects(
        db.funcionario.create({ data: { tenantId: tenantA, nome: "Dup", cpf: "11122233344" } }),
        (e) => e.code === "P2002",
      );
    });
    // the same CPF in ANOTHER tenant is allowed (index is tenant-scoped)
    await withTenant(tenantB, async () => {
      await db.funcionario.create({ data: { tenantId: tenantB, nome: "Outro", cpf: "111.222.333-44" } });
    });
  });

  it("message table without tenantId: tenant comes from context", async () => {
    await withTenant(tenantA, async () => {
      const conv = await db.conversa.create({ data: { tenantId: tenantA } });
      const link = "https://pay.example/c/abc123";
      await db.mensagem.create({ data: { conversaId: conv.id, direcao: "saida", conteudo: "Segue o link " + link, linkHash: "h-abc123" } });
      const m = await db.mensagem.findFirst({ where: { conversaId: conv.id, linkHash: "h-abc123" } });
      assert.equal(m.conteudo, "Segue o link " + link);
    });
  });

  it("attacker's view: the database dump holds no plaintext secret", async () => {
    const all = await dumpAll();
    for (const secret of ["APP_USR-secret-access", "TG-secret-refresh", "123.456.789-00", "11122233344", "111.222.333-44", "12.345.678-9", "pay.example"]) {
      assert.equal(all.includes(secret), false, `plaintext leaked: ${secret}`);
    }
    assert.match(all, /cp1\./);
  });

  it("tenant isolation and fail-closed without a tenant", async () => {
    const f = await raw.funcionario.findFirstOrThrow({ where: { tenantId: tenantA } });
    await withTenant(tenantB, async () => {
      await assert.rejects(db.funcionario.findUnique({ where: { id: f.id } }), /decryption_failed/);
    });
    await assert.rejects(db.funcionario.findUnique({ where: { id: f.id } }), /no tenant/);
  });

  it("interactive $transaction(async tx) works, and the signup flow works with a pre-generated tenant id", async () => {
    const { randomUUID } = require("node:crypto");
    const newTenantId = randomUUID();
    await db.$transaction(async (tx) => {
      await tx.tenant.create({ data: { id: newTenantId, nome: "Nova", mpOauthAccessToken: "tok-nova" } });
      await withTenant(newTenantId, async () => {
        await tx.funcionario.create({ data: { tenantId: newTenantId, nome: "Dono", cpf: "999.888.777-66" } });
      });
    });
    const row = await raw.tenant.findUniqueOrThrow({ where: { id: newTenantId } });
    assert.match(row.mpOauthAccessToken, /^cp1\./);
    await withTenant(newTenantId, async () => {
      assert.equal((await db.funcionario.findFirst({ where: { tenantId: newTenantId, cpf: "99988877766" } }))?.nome, "Dono");
    });
  });

  it("interactive $transaction rolls back cleanly on error", async () => {
    const before = await raw.tenant.count();
    await assert.rejects(
      db.$transaction(async (tx) => {
        await tx.tenant.create({ data: { nome: "Vai falhar", mpOauthAccessToken: "x" } });
        throw new Error("boom");
      }),
      /boom/,
    );
    assert.equal(await raw.tenant.count(), before);
  });

  it("batch $transaction([...]) and createManyAndReturn (Prisma 5.14+)", async () => {
    await withTenant(tenantA, async () => {
      await db.$transaction([
        db.funcionario.create({ data: { tenantId: tenantA, nome: "Lote1", cpf: "100" } }),
        db.funcionario.create({ data: { tenantId: tenantA, nome: "Lote2", cpf: "200" } }),
      ]);
      const many = await db.funcionario.createManyAndReturn({
        data: [{ tenantId: tenantA, nome: "M1", cpf: "300" }, { tenantId: tenantA, nome: "M2", cpf: "400" }],
      });
      assert.deepEqual(many.map((m) => m.cpf).sort(), ["300", "400"]);
      assert.equal(await db.funcionario.count({ where: { tenantId: tenantA, cpf: { in: ["100", "200", "300", "400"] } } }), 4);
    });
    const raws = await raw.funcionario.findMany({ where: { nome: { in: ["Lote1", "M1"] } } });
    assert.ok(raws.every((r) => r.cpf.startsWith("cp1.")));
  });

  it("nested relation write from Tenant (platform) into Funcionario needs a tenant: fails closed, never mis-scopes", async () => {
    // Funcionario inside a Tenant write resolves to the ambient tenant. Without one it must refuse.
    await assert.rejects(
      db.tenant.create({ data: { nome: "Nested", funcionarios: { create: [{ nome: "F", cpf: "555" }] } } }),
      /no tenant for Funcionario/,
    );
  });

  it("unsupported queries throw instead of silently returning wrong results", async () => {
    await withTenant(tenantA, async () => {
      await assert.rejects(db.funcionario.findMany({ where: { cpf: { contains: "111" } } }), /not supported/);
      await assert.rejects(db.funcionario.findMany({ where: { rg: "x" } }), /searchable/);
      await assert.rejects(db.funcionario.findMany({ orderBy: { cpf: "asc" } }), /cannot order/);
    });
  });

  it("raw SQL bypasses the extension and sees ciphertext (documented limitation)", async () => {
    await withTenant(tenantA, async () => {
      const rows = await db.$queryRawUnsafe(`SELECT cpf FROM p5."Funcionario" WHERE "tenantId" = '${tenantA}' LIMIT 1`);
      assert.match(rows[0].cpf, /^cp1\./);
    });
  });

  it("migrates legacy plaintext, then survives KEK rotation + rewrap", async () => {
    await raw.funcionario.deleteMany({ where: { tenantId: tenantB } });
    await raw.tenant.update({ where: { id: tenantB }, data: { mpOauthAccessToken: "legacy-plaintext-token" } });
    for (let i = 0; i < 120; i++) {
      await raw.funcionario.create({ data: { tenantId: tenantB, nome: "L" + i, cpf: String(70000000000 + i), rg: "rg" + i } });
    }
    const s1 = await migrateModel(raw, cp, schema, { model: "Funcionario", tenantOf: (r) => r.tenantId, batchSize: 50 });
    assert.equal(s1.failures.length, 0);
    assert.ok(s1.encrypted >= 240, `encrypted=${s1.encrypted}`);
    const s1t = await migrateModel(raw, cp, schema, { model: "Tenant", tenantOf: () => "__platform__" });
    assert.equal(s1t.failures.length, 0);
    assert.ok(s1t.encrypted >= 1);

    await withTenant(tenantB, async () => {
      assert.equal((await db.funcionario.findFirst({ where: { tenantId: tenantB, cpf: "70000000007" } }))?.nome, "L7");
    });
    assert.equal((await db.tenant.findUnique({ where: { id: tenantB } })).mpOauthAccessToken, "legacy-plaintext-token");

    await cp.rotateKeys();
    const s2 = await migrateModel(raw, cp, schema, { model: "Funcionario", tenantOf: (r) => r.tenantId });
    assert.ok(s2.rewrapped >= 240);
    assert.equal(s2.failures.length, 0);
    await withTenant(tenantB, async () => {
      assert.equal((await db.funcionario.findFirst({ where: { tenantId: tenantB, cpf: "70000000007" } }))?.rg, "rg7");
    });
    const s3 = await migrateModel(raw, cp, schema, { model: "Funcionario", tenantOf: (r) => r.tenantId });
    assert.equal(s3.rewrapped + s3.encrypted, 0, "migration must be idempotent");
  });

  it("ROLLBACK: revertModel puts plaintext back, is safe to re-run, and the data can be encrypted again", async () => {
    await withTenant(tenantB, async () => {
      assert.equal((await db.funcionario.findFirst({ where: { tenantId: tenantB, cpf: "70000000011" } }))?.rg, "rg11");
    });
    const dry = await revertModel(raw, cp, schema, { model: "Funcionario", tenantOf: (r) => r.tenantId, dryRun: true });
    assert.ok(dry.decrypted >= 240 && dry.failures.length === 0);
    assert.match((await raw.funcionario.findFirstOrThrow({ where: { tenantId: tenantB } })).cpf, /^cp1\./, "dry run must not write");

    const s = await revertModel(raw, cp, schema, { model: "Funcionario", tenantOf: (r) => r.tenantId, batchSize: 70 });
    assert.equal(s.failures.length, 0);
    const back = await raw.funcionario.findFirstOrThrow({ where: { tenantId: tenantB, nome: "L11" } });
    assert.equal(back.cpf, "70000000011");
    assert.equal(back.rg, "rg11");
    assert.ok(back.cpfIdx, "blind index must be left in place");
    assert.equal((await revertModel(raw, cp, schema, { model: "Funcionario", tenantOf: (r) => r.tenantId })).decrypted, 0, "second run is a no-op");

    // and forward again
    const again = await migrateModel(raw, cp, schema, { model: "Funcionario", tenantOf: (r) => r.tenantId });
    assert.equal(again.failures.length, 0);
    assert.match((await raw.funcionario.findFirstOrThrow({ where: { tenantId: tenantB, nome: "L11" } })).cpf, /^cp1\./);
  });
});
