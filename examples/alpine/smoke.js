// Runs INSIDE node:20-alpine (musl), against the packed SDK tarball, a linux cryplus-core and a postgres:16-alpine container.
// Exercises what the Operax Dockerfile would run: require() from CommonJS, Prisma 5.22 + the extension, the key cache's local crypto, the scanner.
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { readFileSync } = require("node:fs");
const { PrismaClient } = require("@prisma/client");
const { Cryplus, migrateModel, rotateModel, parseSchema, withCryplus, withTenant } = require("cryplus");

const URL = "http://127.0.0.1:7788";
const TOKEN = process.env.CRYPLUS_TOKEN;
const DB = process.env.DATABASE_URL;
const schema = parseSchema(readFileSync("/work/app/prisma/schema.prisma", "utf8"));
let passed = 0;
const t = async (name, fn) => {
  try {
    await fn();
    passed++;
    console.log("  ok  ", name);
  } catch (e) {
    console.log("  FAIL", name, "\n      ", e && e.stack ? e.stack.split("\n").slice(0, 4).join("\n       ") : e);
    process.exitCode = 1;
  }
};

(async () => {
  const musl = !process.report.getReport().header.glibcVersionRuntime;
  console.log(`node ${process.version}, ${process.platform}/${process.arch}, ${musl ? "musl" : "glibc"}, prisma ${require("@prisma/client/package.json").version}`);
  assert.ok(musl, "this smoke test is meant to run on musl (alpine)");
  assert.match(process.version, /^v20\./, "Operax runs node 20");

  const svc = new Cryplus({ url: URL, token: TOKEN });
  const local = new Cryplus({ url: URL, token: TOKEN, keyCache: true });
  const ctx = { tenant: "acme", collection: "User", field: "cpf" };

  await t("service round trip and the in-memory client, from plain CommonJS", async () => {
    assert.equal(await svc.decrypt(ctx, await svc.encrypt(ctx, "123.456.789-00")), "123.456.789-00");
    const m = Cryplus.inMemory();
    assert.equal(await m.decrypt(ctx, await m.encrypt(ctx, "x")), "x");
  });

  await t("key cache: local crypto (node:crypto XChaCha20 via HChaCha20 / AES-GCM) interoperates with the Go core on musl", async () => {
    for (const s of ["", "ação ✓ 日本語", "x".repeat(10000)]) {
      assert.equal(await svc.decrypt(ctx, await local.encrypt(ctx, s)), s);
      assert.equal(await local.decrypt(ctx, await svc.encrypt(ctx, s)), s);
    }
    assert.equal(await local.blindIndex(ctx, "12345678900"), await svc.blindIndex(ctx, "12345678900"));
    assert.ok(local.stats().cache.hits > 0);
  });

  const db = withCryplus(new PrismaClient({ datasources: { db: { url: DB } } }), {
    cryplus: svc,
    schemaPath: "/work/app/prisma/schema.prisma",
    tenant: ({ model }) => (model === "Tenant" ? "__platform__" : undefined),
    tenantFrom: { Mensagem: { via: "conversaId", model: "Conversa" } },
    rowBinding: "on",
  });
  const base = new PrismaClient({ datasources: { db: { url: DB } } });
  let tenantId;

  await t("Prisma 5.22 on musl: platform tenant, searchable/global/suffix/array/json fields, filters, unique keys", async () => {
    tenantId = (await db.tenant.create({ data: { nome: "Alpine Ltda", mpOauthAccessToken: "APP_USR-secret" } })).id;
    await withTenant(tenantId, async () => {
      const c = await db.cliente.create({ data: { tenantId, nome: "Ana", cpfCnpj: "123.456.789-00", telefone: "(11) 91234-5678", email: "Ana@Example.com", documentos: ["a", "b"], prefs: { x: 1 } } });
      assert.equal(c.cpfCnpj, "123.456.789-00");
      assert.equal((await db.cliente.findFirst({ where: { cpfCnpj: "123.456.789-00" } })).nome, "Ana");
      assert.equal((await db.cliente.findUnique({ where: { tenantId_cpfCnpj: { tenantId, cpfCnpj: "123.456.789-00" } } })).nome, "Ana");
      assert.equal((await db.cliente.findFirst({ where: { telefone: { endsWith: "5678" } } })).nome, "Ana");
      assert.equal(await db.cliente.count({ where: { tenantId, NOT: { cpfCnpj: "123.456.789-00" } } }), 0);
      assert.equal(await db.cliente.count({ where: { tenantId, cpfCnpj: undefined } }), 1);
      assert.deepEqual((await db.cliente.findUnique({ where: { id: c.id }, select: { documentos: true, prefs: true } })), { documentos: ["a", "b"], prefs: { x: 1 } });
      const row = await base.cliente.findUniqueOrThrow({ where: { id: c.id } });
      assert.match(row.cpfCnpj, /^cp1\./);
      assert.match(row.telefone, /^cp1\./);
    });
  });

  await t("row binding on musl: a swap of two rows' values is detected", async () => {
    await withTenant(tenantId, async () => {
      const a = await db.webhook.create({ data: { tenantId, url: "a", secret: "secret-a" } });
      const b = await db.webhook.create({ data: { tenantId, url: "b", secret: "secret-b" } });
      const ra = await base.webhook.findUniqueOrThrow({ where: { id: a.id } });
      const rb = await base.webhook.findUniqueOrThrow({ where: { id: b.id } });
      await base.webhook.update({ where: { id: a.id }, data: { secret: rb.secret } });
      await assert.rejects(db.webhook.findUniqueOrThrow({ where: { id: a.id } }), /decryption_failed/);
      await base.webhook.update({ where: { id: a.id }, data: { secret: ra.secret } });
      assert.equal((await db.webhook.findUniqueOrThrow({ where: { id: a.id } })).secret, "secret-a");
    });
  });

  await t("tenantFrom: Mensagem has no tenant column and no ambient tenant is needed", async () => {
    const conv = await base.conversa.create({ data: { tenantId } });
    const m = await db.mensagem.create({ data: { conversaId: conv.id, direcao: "in", conteudo: "olá" } });
    assert.equal((await db.mensagem.findUniqueOrThrow({ where: { id: m.id } })).conteudo, "olá");
  });

  await t("raw SQL guard and helpers, interactive and batch $transaction", async () => {
    await assert.rejects(db.$queryRawUnsafe("SELECT secret_value FROM webhooks"), /raw SQL touches encrypted data/);
    await db.$transaction(async (tx) => {
      await withTenant(tenantId, () => tx.webhook.create({ data: { tenantId, url: "tx", secret: "in-tx" } }));
    });
    await withTenant(tenantId, async () => {
      const [a, b] = await db.$transaction([db.webhook.findMany({ where: { url: "tx" } }), db.webhook.count()]);
      assert.equal(a[0].secret, "in-tx");
      assert.ok(b >= 3);
    });
  });

  await t("migrateModel + rotateModel(bindRows) with sampled verification, concurrency and progress", async () => {
    await base.webhook.createMany({ data: Array.from({ length: 40 }, (_, i) => ({ tenantId, url: "legacy", secret: "plain-" + i })) });
    const s = await migrateModel(base, svc, schema, { model: "Webhook", tenantOf: (r) => r.tenantId, concurrency: 4, verify: { sample: 0.5 }, bindRows: true });
    assert.deepEqual(s.failures, []);
    assert.ok(s.encrypted >= 40 && s.total >= 40 && s.rowsPerSec > 0);
    const r = await rotateModel(base, svc, schema, { model: "Webhook", tenantOf: (x) => x.tenantId, bindRows: true });
    assert.deepEqual(r.failures, []);
    await withTenant(tenantId, async () => assert.equal((await db.webhook.findMany({ where: { url: "legacy" } })).length, 40));
  });

  await t("cryplus-scan runs from node_modules/.bin on alpine and finds a raw query", async () => {
    require("node:fs").writeFileSync("/work/app/bad.js", "prisma.$queryRaw`SELECT secret_value FROM webhooks`;\n");
    let out = "";
    try {
      execFileSync("/work/app/node_modules/.bin/cryplus-scan", ["--schema", "/work/app/prisma/schema.prisma", "--src", "/work/app/bad.js"], { encoding: "utf8" });
    } catch (e) {
      out = e.stdout;
      assert.equal(e.status, 1);
    }
    assert.match(out, /bad\.js:1:\d+\s+error/);
  });

  await base.$disconnect();
  await db.$disconnect();
  console.log(process.exitCode ? `\nFAILED (${passed} passed)` : `\nALL ${passed} PASSED on node ${process.version} / musl`);
})();
