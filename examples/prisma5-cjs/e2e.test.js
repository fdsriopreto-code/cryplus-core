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

// CRYPLUS_MODE=memory runs this whole suite against the in-process test client (no key service).
const MEMORY = process.env.CRYPLUS_MODE === "memory";

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
  const port = MEMORY ? 0 : await freePort();
  if (!MEMORY) child = spawn(BIN, ["--listen", `127.0.0.1:${port}`, "--keyfile", path.join(tmp, "k.json"), "--audit-log", ""], {
    env: { ...process.env, CRYPLUS_TOKEN: TOKEN, CRYPLUS_PASSPHRASE: "p5 passphrase for the key file" },
    stdio: ["ignore", "ignore", "inherit"],
  });
  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; !MEMORY && i < 100; i++) {
    try {
      if ((await fetch(url + "/healthz")).ok) break;
    } catch {}
    await new Promise((r) => setTimeout(r, 50));
  }
  cp = MEMORY ? Cryplus.inMemory() : new Cryplus({ url, token: TOKEN });

  // plain, non-destructive `db push` into the dedicated "p5" schema
  execFileSync(process.execPath, [path.join(__dirname, "node_modules/prisma/build/index.js"), "db", "push", "--skip-generate"], {
    cwd: __dirname,
    env: { ...process.env, DATABASE_URL: DB },
    stdio: "pipe",
  });

  raw = new PrismaClient({ datasources: { db: { url: DB } } });
  await raw.orcamento.deleteMany({});
  await raw.cliente.deleteMany({});
  await raw.webhook.deleteMany({});
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
  for (const t of ["Tenant", "Funcionario", "Configuracao", "Mensagem", "clientes", "orcamentos", "webhooks"]) {
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

  it("raw SQL on an encrypted column is refused (it would silently see ciphertext); a reviewed query shows it really is ciphertext", async () => {
    await withTenant(tenantA, async () => {
      await assert.rejects(db.$queryRawUnsafe(`SELECT cpf FROM p5."Funcionario" WHERE "tenantId" = '${tenantA}' LIMIT 1`), /raw SQL touches encrypted data/);
      const rows = await db.$queryRawUnsafe(`SELECT cpf /* cryplus:handled */ FROM p5."Funcionario" WHERE "tenantId" = '${tenantA}' LIMIT 1`);
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

  // ----------------------------------------------------------------------------------------------------------
  // P1-7: Prisma coverage the Operax team asked to see proven on 5.22 without a driver adapter
  // ----------------------------------------------------------------------------------------------------------
  describe("Prisma write/read coverage", () => {
    let T;
    it("setup", async () => {
      T = (await db.tenant.create({ data: { nome: "Cobertura" } })).id;
    });
    const mk = (extra = {}) => ({ tenantId: T, nome: "c", cpfCnpj: "111.222.333-44", telefone: "(11) 91234-5678", email: "Ana@Example.com", documentos: ["a.pdf", "b.pdf"], prefs: { tema: "escuro" }, ...extra });

    it("create: String[], Json, suffix, global and equality indexes; the dump has no plaintext", async () => {
      await withTenant(T, async () => {
        const c = await db.cliente.create({ data: mk() });
        assert.deepEqual(c.documentos, ["a.pdf", "b.pdf"]);
        assert.deepEqual(c.prefs, { tema: "escuro" });
        assert.equal(c.cpfCnpj, "111.222.333-44");
        assert.equal("cpfCnpjIdx" in c || "telefoneSfx4" in c || "emailGIdx" in c, false);
      });
      const dump = (await raw.$queryRawUnsafe(`SELECT x::text AS t FROM p5.clientes x`)).map((r) => r.t).join("\n");
      for (const secret of ["111.222.333-44", "91234", "ana@example.com", "a.pdf", "escuro"]) assert.equal(dump.toLowerCase().includes(secret.toLowerCase()), false, secret);
    });

    it("findUnique by the COMPOUND key the app already uses (tenantId_cpfCnpj) is rewritten to the blind index", async () => {
      await withTenant(T, async () => {
        const c = await db.cliente.findUnique({ where: { tenantId_cpfCnpj: { tenantId: T, cpfCnpj: "11122233344" } } });
        assert.equal(c?.nome, "c");
        assert.equal(await db.cliente.findUnique({ where: { tenantId_cpfCnpj: { tenantId: T, cpfCnpj: "99999999999" } } }), null);
      });
    });

    it("upsert (create path, then update path through the compound key)", async () => {
      await withTenant(T, async () => {
        const where = { tenantId_cpfCnpj: { tenantId: T, cpfCnpj: "555.666.777-88" } };
        const created = await db.cliente.upsert({ where, create: mk({ cpfCnpj: "555.666.777-88", nome: "novo" }), update: { nome: "x" } });
        assert.equal(created.nome, "novo");
        const updated = await db.cliente.upsert({ where, create: mk({ cpfCnpj: "555.666.777-88" }), update: { nome: "atualizado", telefone: "(21) 99999-0000" } });
        assert.equal(updated.nome, "atualizado");
        assert.equal(updated.telefone, "(21) 99999-0000");
        assert.equal(await db.cliente.count({ where: { cpfCnpj: "55566677788" } }), 1);
      });
    });

    it("createMany, updateMany and deleteMany by blind-indexed filter", async () => {
      await withTenant(T, async () => {
        await db.cliente.createMany({ data: [mk({ cpfCnpj: "1", nome: "m1" }), mk({ cpfCnpj: "2", nome: "m2", documentos: ["z"] })] });
        const n = await db.cliente.updateMany({ where: { cpfCnpj: { in: ["1", "2"] } }, data: { telefone: "11 4000-1111", documentos: { set: ["novo.pdf"] } } });
        assert.equal(n.count, 2);
        const rows = await db.cliente.findMany({ where: { cpfCnpj: { in: ["1", "2"] } }, orderBy: { nome: "asc" } });
        assert.deepEqual(rows.map((r) => r.telefone), ["11 4000-1111", "11 4000-1111"]);
        assert.deepEqual(rows[0].documentos, ["novo.pdf"]);
        assert.equal((await db.cliente.deleteMany({ where: { cpfCnpj: "1" } })).count, 1);
      });
    });

    it("nested writes: create children, update through the parent, and read the parent's encrypted fields from the child (include/select)", async () => {
      await withTenant(T, async () => {
        const c = await db.cliente.create({
          data: mk({ cpfCnpj: "321", orcamentos: { create: [{ tenantId: T, numero: 1, observacao: "obs um" }, { tenantId: T, numero: 2, observacao: "obs dois" }] } }),
          include: { orcamentos: { orderBy: { numero: "asc" } } },
        });
        assert.deepEqual(c.orcamentos.map((o) => o.observacao), ["obs um", "obs dois"]);

        await db.cliente.update({
          where: { id: c.id },
          data: { telefone: "11 90000-0000", orcamentos: { update: { where: { id: c.orcamentos[0].id }, data: { observacao: "alterada" } }, create: { tenantId: T, numero: 3, observacao: "obs tres" } } },
        });
        // an Orcamento read with its Cliente included: the Cliente's encrypted fields come back decrypted
        const o = await db.orcamento.findFirst({ where: { numero: 1 }, include: { cliente: true } });
        assert.equal(o.observacao, "alterada");
        assert.equal(o.cliente.cpfCnpj, "321");
        assert.equal(o.cliente.telefone, "11 90000-0000");
        assert.deepEqual(o.cliente.documentos, ["a.pdf", "b.pdf"]);
        const s = await db.orcamento.findFirst({ where: { numero: 3 }, select: { observacao: true, cliente: { select: { telefone: true, nome: true } } } });
        assert.deepEqual(s, { observacao: "obs tres", cliente: { telefone: "11 90000-0000", nome: "c" } });
        // filtering the child through the parent's blind-indexed field
        assert.equal((await db.orcamento.findMany({ where: { cliente: { cpfCnpj: "321" } } })).length, 3);
      });
    });

    it("a select that omits the index columns works; select of the encrypted column decrypts", async () => {
      await withTenant(T, async () => {
        const r = await db.cliente.findFirst({ where: { cpfCnpj: "321" }, select: { nome: true, cpfCnpj: true } });
        assert.deepEqual(r, { nome: "c", cpfCnpj: "321" });
      });
    });

    it("suffix search (last 4 / last 8 digits) and global e-mail lookup before any tenant is known", async () => {
      await withTenant(T, async () => {
        assert.ok((await db.cliente.findMany({ where: { telefone: { endsWith: "0000" } } })).length >= 1);
        await assert.rejects(db.cliente.findMany({ where: { telefone: { endsWith: "000" } } }), /indexed lengths/);
      });
      // login-style lookup: NO tenant context, ask only for ids (nothing encrypted is read back)
      const hit = await db.cliente.findFirst({ where: { email: " ANA@example.com" }, select: { id: true, tenantId: true } });
      assert.equal(hit.tenantId, T);
      // and asking for the decrypted e-mail without a tenant fails closed
      await assert.rejects(db.cliente.findFirst({ where: { email: "ana@example.com" } }), /no tenant for Cliente/);
    });

    it("aggregate / groupBy / distinct / orderBy on encrypted fields throw; harmless ones work", async () => {
      await withTenant(T, async () => {
        await assert.rejects(db.cliente.groupBy({ by: ["telefone"], _count: true }), /cannot groupBy/);
        await assert.rejects(db.cliente.aggregate({ _min: { telefone: true } }), /cannot aggregate/);
        await assert.rejects(db.cliente.findMany({ distinct: ["cpfCnpj"] }), /distinct/);
        await assert.rejects(db.cliente.findMany({ orderBy: { telefone: "asc" } }), /cannot order/);
        assert.ok((await db.cliente.count({ where: { tenantId: T } })) > 0);
        assert.ok((await db.cliente.groupBy({ by: ["tenantId"], _count: { _all: true } })).length >= 1);
      });
    });

    it("interactive transaction with nested writes and a rollback", async () => {
      const before = await raw.cliente.count();
      await assert.rejects(
        withTenant(T, () =>
          db.$transaction(async (tx) => {
            await tx.cliente.create({ data: mk({ cpfCnpj: "tx1" }) });
            await tx.cliente.update({ where: { tenantId_cpfCnpj: { tenantId: T, cpfCnpj: "tx1" } }, data: { nome: "tx" } });
            throw new Error("boom");
          }),
        ),
        /boom/,
      );
      assert.equal(await raw.cliente.count(), before);
    });
  });

  // ----------------------------------------------------------------------------------------------------------
  // P0-1: raw SQL guard and helpers
  // ----------------------------------------------------------------------------------------------------------
  describe("raw SQL guard and helpers", () => {
    let T;
    it("setup", async () => {
      T = (await db.tenant.create({ data: { nome: "Raw" } })).id;
      await withTenant(T, async () => {
        await db.webhook.create({ data: { tenantId: T, url: "https://hook", secret: "whsec_raw_1" } });
        await db.funcionario.create({ data: { tenantId: T, nome: "F", cpf: "123.456.789-00" } });
      });
    });

    it("refuses raw SQL that touches an encrypted column, in all four forms, using the REAL database names", async () => {
      await assert.rejects(db.$queryRaw`SELECT secret_value FROM p5.webhooks`, /raw SQL touches encrypted data.*Webhook/s);
      await assert.rejects(db.$queryRawUnsafe(`SELECT * FROM p5.webhooks`), /selects every column/);
      await assert.rejects(db.$executeRaw`UPDATE p5.webhooks SET secret_value = 'x'`, /Webhook/);
      await assert.rejects(db.$executeRawUnsafe(`INSERT INTO p5.webhooks VALUES ('i','t','u','s')`), /inserts without a column list/);
      // value parameters do not hide it
      const id = "x";
      await assert.rejects(db.$queryRaw`SELECT url FROM p5.webhooks WHERE secret_value = ${id}`, /Webhook/);
      // and nothing was written
      assert.equal(await raw.webhook.count({ where: { secret: "x" } }), 0);
    });

    it("does not get in the way of unrelated or reviewed SQL", async () => {
      assert.equal(Number((await db.$queryRaw`SELECT count(*)::int AS n FROM p5.webhooks`)[0].n) >= 1, true);
      assert.equal((await db.$queryRawUnsafe(`SELECT 1 AS one`))[0].one, 1);
      assert.equal((await db.$queryRaw`SELECT url FROM p5.webhooks LIMIT 1`).length, 1);
      // the BASE client is never affected (that is the point of using it for migrations)
      assert.ok((await raw.$queryRawUnsafe(`SELECT secret_value FROM p5.webhooks LIMIT 1`)).length === 1);
    });

    it("$cryplus.decryptRows: a reviewed raw SELECT comes back decrypted (aliases supported)", async () => {
      await withTenant(T, async () => {
        const rows = await db.$queryRawUnsafe(`SELECT id, url, secret_value /* cryplus:handled */ AS whsec FROM p5.webhooks WHERE tenant_id = '${T}'`);
        assert.match(rows[0].whsec, /^cp1\./, "raw rows really are ciphertext");
        await db.$cryplus.decryptRows("Webhook", rows, { columns: { whsec: "secret" } });
        assert.equal(rows[0].whsec, "whsec_raw_1");
      });
    });

    it("$cryplus.index / encryptValue / indexColumns: raw WHERE and raw INSERT interoperate with the model API", async () => {
      await withTenant(T, async () => {
        const idx = await db.$cryplus.index("Funcionario", "cpf", "12345678900");
        const hit = await db.$queryRawUnsafe(`SELECT id, nome FROM p5."Funcionario" WHERE "tenantId" = '${T}' AND "cpfIdx" = '${idx}'`);
        assert.equal(hit.length, 1);
        assert.equal(hit[0].nome, "F");

        const ct = await db.$cryplus.encryptValue("Funcionario", "cpf", "987.654.321-00");
        const cols = await db.$cryplus.indexColumns("Funcionario", "cpf", "987.654.321-00");
        await db.$executeRawUnsafe(
          `INSERT INTO p5."Funcionario" (id, "tenantId", nome, cpf, "cpfIdx") /* cryplus:handled */ VALUES ('raw-1', '${T}', 'Inserido por SQL', '${ct}', '${cols.cpfIdx}')`,
        );
        const viaApi = await db.funcionario.findFirst({ where: { tenantId: T, cpf: "98765432100" } });
        assert.equal(viaApi?.nome, "Inserido por SQL");
        assert.equal(viaApi?.cpf, "987.654.321-00");
      });
    });

    it("$cryplus.searchDecrypted: substring search over a bounded candidate set", async () => {
      await withTenant(T, async () => {
        const conv = await db.conversa.create({ data: { tenantId: T } });
        await db.mensagem.createMany({
          data: Array.from({ length: 40 }, (_, i) => ({ conversaId: conv.id, direcao: "saida", conteudo: i % 10 === 3 ? `pague em https://pay.example/c/${i}` : `olÃ¡ ${i}` })),
        });
        const hits = await db.$cryplus.searchDecrypted(db.mensagem, "Mensagem", { where: { conversaId: conv.id }, predicate: (m) => m.conteudo.includes("https://pay.example/c/"), pageSize: 15 });
        assert.equal(hits.length, 4);
        await assert.rejects(db.$cryplus.searchDecrypted(db.mensagem, "Mensagem", { where: {}, predicate: () => true }), /non-empty `where`/);
      });
    });
  });

  // ----------------------------------------------------------------------------------------------------------
  // P1-9: migration, rotation and rollback on a live table, for every kind of encrypted column
  // ----------------------------------------------------------------------------------------------------------
  describe("migration, rotation and rollback (all kinds)", () => {
    const { rotateModel } = require("cryplus");
    let T;
    const N = 150;
    const legacy = (tenantId, n, base = 0) =>
      Array.from({ length: n }, (_, i) => ({
        tenantId,
        nome: "L" + (base + i),
        cpfCnpj: String(10_000_000_000 + base + i),
        telefone: `(11) 9${String(1000_0000 + base + i).padStart(8, "0")}`,
        email: `user${base + i}@legacy.com`,
        documentos: [`doc${base + i}.pdf`],
        prefs: { n: base + i, tema: "claro" },
      }));
    const tenantOf = (r) => r.tenantId;

    it("setup: legacy rows written without Cryplus", async () => {
      T = (await db.tenant.create({ data: { nome: "Migracao" } })).id;
      await raw.cliente.createMany({ data: legacy(T, N) });
      assert.equal(await raw.cliente.count({ where: { tenantId: T } }), N);
    });

    it("dry run counts, writes nothing", async () => {
      const dry = await migrateModel(raw, cp, schema, { model: "Cliente", tenantOf, dryRun: true });
      assert.ok(dry.scanned >= N);
      assert.ok(dry.encrypted >= 5 * N, `encrypted=${dry.encrypted}`);
      const one = await raw.cliente.findFirstOrThrow({ where: { tenantId: T } });
      assert.equal(one.cpfCnpj.startsWith("cp1."), false);
    });

    it("migrates every kind with a read-back verification, in throttled batches", async () => {
      const t0 = Date.now();
      const s = await migrateModel(raw, cp, schema, { model: "Cliente", tenantOf, batchSize: 40, throttleMs: 20, verify: true });
      assert.equal(s.failures.length, 0, JSON.stringify(s.failures.slice(0, 3)));
      assert.ok(s.encrypted >= 5 * N);
      assert.ok(s.verified >= 5 * N, `verified=${s.verified}`);
      assert.ok(Date.now() - t0 >= 60, "throttle between batches was applied");
      const one = await raw.cliente.findFirstOrThrow({ where: { tenantId: T, nome: "L7" } });
      assert.match(one.cpfCnpj, /^cp1\./);
      assert.match(one.telefone, /^cp1\./);
      assert.match(one.documentos[0], /^cp1\./);
      assert.match(one.prefs, /^cp1\./);
      assert.match(one.telefoneSfx8, /^bi1\./);
      assert.match(one.emailGIdx, /^bi1\./);
      assert.match(one.cpfCnpjIdx, /^bi1\./);
    });

    it("everything is searchable and readable through the extension afterwards", async () => {
      await withTenant(T, async () => {
        const c = await db.cliente.findFirst({ where: { cpfCnpj: "10000000007" } });
        assert.equal(c.nome, "L7");
        assert.deepEqual(c.documentos, ["doc7.pdf"]);
        assert.deepEqual(c.prefs, { n: 7, tema: "claro" });
        assert.equal(c.email, "user7@legacy.com");
        assert.equal((await db.cliente.findMany({ where: { telefone: { endsWith: "10000007" } } })).map((x) => x.nome)[0], "L7");
        assert.equal((await db.cliente.findMany({ where: { telefone: { endsWith: "0007" } } })).length >= 1, true);
      });
      const hit = await db.cliente.findFirst({ where: { email: "USER7@legacy.com" }, select: { tenantId: true } });
      assert.equal(hit.tenantId, T, "global e-mail lookup works with no tenant context");
    });

    it("is idempotent", async () => {
      const again = await migrateModel(raw, cp, schema, { model: "Cliente", tenantOf });
      assert.equal(again.encrypted + again.rewrapped + again.indexed, 0);
    });

    it("failures are listed per row; maxFailures stops early; startAfter/lastId resumes", async () => {
      const T2 = (await db.tenant.create({ data: { nome: "Resume" } })).id;
      await raw.cliente.createMany({ data: legacy(T2, 60, 5000) });
      const bad = (await raw.cliente.findMany({ where: { tenantId: T2 }, orderBy: { id: "asc" }, take: 5 }))[2];
      const flaky = (r) => {
        if (r.id === bad.id) throw new Error("tenant lookup failed for this row");
        return r.tenantId;
      };
      const first = await migrateModel(raw, cp, schema, { model: "Cliente", tenantOf: flaky, batchSize: 20, maxFailures: 1 });
      assert.equal(first.aborted, true);
      assert.deepEqual(first.failures.map((f) => [f.id, f.field]), [[bad.id, "*"]]);
      assert.ok(first.lastId, "lastId lets the caller resume");
      assert.ok(first.scanned < (await raw.cliente.count()), "stopped before the end of the table");

      const rest = await migrateModel(raw, cp, schema, { model: "Cliente", tenantOf, batchSize: 20, startAfter: first.lastId });
      assert.equal(rest.failures.length, 0);
      // the one skipped row is picked up by a plain re-run, and nothing else changes
      const final = await migrateModel(raw, cp, schema, { model: "Cliente", tenantOf });
      assert.ok(final.encrypted >= 5, "the previously failed row was migrated");
      const stillPlain = await raw.cliente.count({ where: { tenantId: T2, cpfCnpj: { not: { startsWith: "cp1." } } } });
      assert.equal(stillPlain, 0);
    });

    it("index-only mode fills missing index columns on already-encrypted rows and changes nothing else", async () => {
      const victims = await raw.cliente.findMany({ where: { tenantId: T }, orderBy: { id: "asc" }, take: 10, select: { id: true, cpfCnpj: true } });
      await raw.cliente.updateMany({ where: { id: { in: victims.map((v) => v.id) } }, data: { telefoneSfx4: null, telefoneSfx8: null, emailGIdx: null } });
      const s = await migrateModel(raw, cp, schema, { model: "Cliente", tenantOf, mode: "index-only" });
      assert.equal(s.failures.length, 0);
      assert.equal(s.encrypted, 0);
      assert.equal(s.rewrapped, 0);
      assert.equal(s.indexed, 20, "telefone + email for each of the 10 rows");
      const back = await raw.cliente.findUniqueOrThrow({ where: { id: victims[0].id } });
      assert.match(back.telefoneSfx4, /^bi1\./);
      assert.equal(back.cpfCnpj, victims[0].cpfCnpj, "ciphertext untouched");
    });

    it("rotateModel re-wraps strings, array elements and Json, resumably, and everything still reads", async () => {
      await cp.rotateKeys();
      const s = await rotateModel(raw, cp, schema, { model: "Cliente", tenantOf, batchSize: 50, verify: true });
      assert.equal(s.failures.length, 0, JSON.stringify(s.failures.slice(0, 2)));
      assert.ok(s.rewrapped >= 5 * N, `rewrapped=${s.rewrapped}`);
      assert.equal(s.encrypted, 0);
      assert.equal((await rotateModel(raw, cp, schema, { model: "Cliente", tenantOf })).rewrapped, 0);
      await withTenant(T, async () => {
        const c = await db.cliente.findFirst({ where: { cpfCnpj: "10000000042" } });
        assert.deepEqual([c.nome, c.documentos, c.prefs], ["L42", ["doc42.pdf"], { n: 42, tema: "claro" }]);
      });
    });

    it("rollback restores plaintext for every kind, and re-encrypting works again", async () => {
      const r = await revertModel(raw, cp, schema, { model: "Cliente", tenantOf, batchSize: 70 });
      assert.equal(r.failures.length, 0);
      const back = await raw.cliente.findFirstOrThrow({ where: { tenantId: T, nome: "L9" } });
      assert.equal(back.cpfCnpj, "10000000009");
      assert.deepEqual(back.documentos, ["doc9.pdf"]);
      assert.deepEqual(back.prefs, { n: 9, tema: "claro" });
      assert.equal(back.email, "user9@legacy.com");
      assert.ok(back.cpfCnpjIdx, "index columns stay");
      assert.equal((await revertModel(raw, cp, schema, { model: "Cliente", tenantOf })).decrypted, 0);
      const fwd = await migrateModel(raw, cp, schema, { model: "Cliente", tenantOf, verify: true });
      assert.equal(fwd.failures.length, 0);
      assert.match((await raw.cliente.findFirstOrThrow({ where: { tenantId: T, nome: "L9" } })).prefs, /^cp1\./);
    });
  });
});
