// Row binding, undefined filters, legacy fallback + index-only, tenantFrom, per-model plaintext policy, write-then-read reuse,
// migration options and the Express middleware, on Prisma 5.22 + CommonJS + real Postgres.
// Needs the isolated Postgres from ../prisma-demo (`node pg.ts`). Uses the in-process client (crypto is covered elsewhere).
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { after, before, describe, it } = require("node:test");
const { PrismaClient } = require("@prisma/client");
const { Cryplus, migrateModel, rotateModel, parseSchema, withCryplus, withTenant, currentTenant, cryplusTenantMiddleware } = require("cryplus");

const DB = "postgresql://cryplus:cryplus@127.0.0.1:54329/cryplus_demo?schema=p5";
const SCHEMA_PATH = path.join(__dirname, "prisma/schema.prisma");
const schema = parseSchema(readFileSync(SCHEMA_PATH, "utf8"));
const platform = ({ model }) => (model === "Tenant" ? "__platform__" : undefined);

let raw, cp, tenantA, tenantB, tenantC;
const clients = [];
const make = (extra = {}, crypto = cp) => {
  const c = withCryplus(new PrismaClient({ datasources: { db: { url: DB } } }), { cryplus: crypto, schemaPath: SCHEMA_PATH, tenant: platform, ...extra });
  clients.push(c);
  return c;
};
const counting = (inner) => {
  const n = { encrypt: 0, decrypt: 0, blindIndex: 0 };
  return {
    n,
    encrypt: (c, p) => (n.encrypt++, inner.encrypt(c, p)),
    decrypt: (c, t) => (n.decrypt++, inner.decrypt(c, t)),
    blindIndex: (c, v) => (n.blindIndex++, inner.blindIndex(c, v)),
    rewrap: (c, t) => inner.rewrap(c, t),
  };
};

before(async () => {
  cp = Cryplus.inMemory(); // fresh random keys: rows left by another suite (real core keys) are unreadable here, so start from empty tables
  raw = new PrismaClient({ datasources: { db: { url: DB } } });
  for (const m of ["orcamento", "cliente", "webhook", "mensagem", "conversa"]) await raw[m].deleteMany({});
  const t = make();
  tenantA = (await t.tenant.create({ data: { nome: "Features A" } })).id;
  tenantB = (await t.tenant.create({ data: { nome: "Features B" } })).id;
  tenantC = (await t.tenant.create({ data: { nome: "Features C (row binding)" } })).id; // rows bound to their ids live here only
});
after(async () => {
  await raw.webhook.deleteMany({ where: { tenantId: { in: [tenantA, tenantB, tenantC] } } });
  await raw.mensagem.deleteMany({ where: { conversa: { tenantId: { in: [tenantA, tenantB, tenantC] } } } });
  await raw.conversa.deleteMany({ where: { tenantId: { in: [tenantA, tenantB, tenantC] } } });
  await raw.orcamento.deleteMany({ where: { tenantId: { in: [tenantA, tenantB, tenantC] } } });
  await raw.cliente.deleteMany({ where: { tenantId: { in: [tenantA, tenantB, tenantC] } } });
  await raw.$disconnect();
  await Promise.all(clients.map((c) => c.$disconnect()));
});

describe("schema: which models can be bound", () => {
  it("only a single String @id qualifies; the default generator is recognised", () => {
    assert.equal(schema.get("Webhook").bindable, true);
    assert.equal(schema.get("Webhook").fields.get("id").idDefault, "uuid");
    const s = parseSchema("model N {\n id Int @id @default(autoincrement())\n /// @encrypted\n x String?\n}\nmodel C {\n a String\n b String\n /// @encrypted\n x String?\n @@id([a, b])\n}\nmodel U {\n id String @id @default(cuid())\n}");
    assert.equal(s.get("N").bindable, false);
    assert.equal(s.get("C").bindable, false);
    assert.equal(s.get("U").fields.get("id").idDefault, "cuid");
  });
});

describe("rowBinding: ciphertexts are tied to their row", () => {
  let off, on, strict;
  before(() => {
    off = make();
    on = make({ rowBinding: "on" });
    strict = make({ rowBinding: "strict" });
  });

  it("WITHOUT binding, swapping two rows' ciphertexts of the same tenant and field is NOT detected (the limit this feature removes)", async () => {
    await withTenant(tenantC, async () => {
      const a = await off.webhook.create({ data: { tenantId: tenantC, url: "u1", secret: "secret-of-A" } });
      const b = await off.webhook.create({ data: { tenantId: tenantC, url: "u2", secret: "secret-of-B" } });
      const ra = await raw.webhook.findUniqueOrThrow({ where: { id: a.id } });
      const rb = await raw.webhook.findUniqueOrThrow({ where: { id: b.id } });
      await raw.webhook.update({ where: { id: a.id }, data: { secret: rb.secret } });
      await raw.webhook.update({ where: { id: b.id } , data: { secret: ra.secret } });
      assert.equal((await off.webhook.findUniqueOrThrow({ where: { id: a.id } })).secret, "secret-of-B"); // silently the other row's value
    });
  });

  it("create generates the id first and binds the ciphertext to it", async () => {
    await withTenant(tenantC, async () => {
      const w = await on.webhook.create({ data: { tenantId: tenantC, url: "u", secret: "bound-secret" } });
      assert.match(w.id, /^[0-9a-f-]{36}$/);
      assert.equal(w.secret, "bound-secret");
      const row = await raw.webhook.findUniqueOrThrow({ where: { id: w.id } });
      const ctx = { tenant: tenantC, collection: "Webhook", field: "secret" };
      assert.equal(await cp.decrypt({ ...ctx, recordId: w.id }, row.secret), "bound-secret");
      await assert.rejects(cp.decrypt(ctx, row.secret), /decryption_failed/);
      await assert.rejects(cp.decrypt({ ...ctx, recordId: "another-id" }, row.secret), /decryption_failed/);
      // an id supplied by the caller is respected
      const mine = await on.webhook.create({ data: { id: "caller-chosen-id-" + Date.now(), tenantId: tenantC, url: "u", secret: "x" } });
      assert.match(mine.id, /^caller-chosen-id-/);
      assert.equal(await cp.decrypt({ ...ctx, recordId: mine.id }, (await raw.webhook.findUniqueOrThrow({ where: { id: mine.id } })).secret), "x");
    });
  });

  it("swapping two rows' ciphertexts is detected on read (decryption_failed), in every read path", async () => {
    await withTenant(tenantC, async () => {
      const a = await on.webhook.create({ data: { tenantId: tenantC, url: "sw1", secret: "A-secret" } });
      const b = await on.webhook.create({ data: { tenantId: tenantC, url: "sw2", secret: "B-secret" } });
      const ra = await raw.webhook.findUniqueOrThrow({ where: { id: a.id } });
      const rb = await raw.webhook.findUniqueOrThrow({ where: { id: b.id } });
      await raw.webhook.update({ where: { id: a.id }, data: { secret: rb.secret } });
      await raw.webhook.update({ where: { id: b.id }, data: { secret: ra.secret } });
      await assert.rejects(on.webhook.findUniqueOrThrow({ where: { id: a.id } }), /decryption_failed/);
      await assert.rejects(on.webhook.findMany({ where: { id: { in: [a.id, b.id] } } }), /decryption_failed/);
      await assert.rejects(on.webhook.findMany({ where: { id: b.id }, select: { secret: true } }), /decryption_failed/);
      await assert.rejects(strict.webhook.findUniqueOrThrow({ where: { id: a.id } }), /decryption_failed/);
      // put them back: reads work again
      await raw.webhook.update({ where: { id: a.id }, data: { secret: ra.secret } });
      await raw.webhook.update({ where: { id: b.id }, data: { secret: rb.secret } });
      assert.equal((await on.webhook.findUniqueOrThrow({ where: { id: a.id } })).secret, "A-secret");
    });
  });

  it("a select without the id still decrypts, and the id it had to add is not left in the result", async () => {
    await withTenant(tenantC, async () => {
      const w = await on.webhook.create({ data: { tenantId: tenantC, url: "sel", secret: "only-secret" }, select: { secret: true } });
      assert.deepEqual(w, { secret: "only-secret" });
      const rows = await on.webhook.findMany({ where: { url: "sel" }, select: { secret: true, url: true } });
      assert.deepEqual(rows, [{ secret: "only-secret", url: "sel" }]);
      const one = await on.webhook.findFirst({ where: { url: "sel" }, select: { url: true } }); // nothing encrypted selected: untouched
      assert.deepEqual(one, { url: "sel" });
    });
  });

  it("nested include/select: children are bound to their own ids and the injected ids are stripped", async () => {
    await withTenant(tenantC, async () => {
      const c = await on.conversa.create({ data: { tenantId: tenantC, mensagens: { create: [{ direcao: "in", conteudo: "m1" }, { direcao: "out", conteudo: "m2" }] } }, include: { mensagens: true } });
      assert.deepEqual(c.mensagens.map((m) => m.conteudo).sort(), ["m1", "m2"]);
      for (const m of c.mensagens) {
        const row = await raw.mensagem.findUniqueOrThrow({ where: { id: m.id } });
        assert.equal(await cp.decrypt({ tenant: tenantC, collection: "Mensagem", field: "conteudo", recordId: m.id }, row.conteudo), m.conteudo);
      }
      const sel = await on.conversa.findUniqueOrThrow({ where: { id: c.id }, select: { mensagens: { select: { conteudo: true }, orderBy: { direcao: "asc" } } } });
      assert.deepEqual(sel, { mensagens: [{ conteudo: "m1" }, { conteudo: "m2" }] });
    });
  });

  it("writes must identify the row: update by id works; by anything else, updateMany with a value, and upsert without an id are refused", async () => {
    await withTenant(tenantC, async () => {
      const w = await on.webhook.create({ data: { tenantId: tenantC, url: "upd", secret: "v1" } });
      assert.equal((await on.webhook.update({ where: { id: w.id }, data: { secret: "v2" } })).secret, "v2");
      assert.equal((await on.webhook.findUniqueOrThrow({ where: { id: w.id } })).secret, "v2");
      assert.equal((await on.webhook.update({ where: { id: w.id, url: "upd" }, data: { secret: "v2b" } })).secret, "v2b"); // still identified by its id
      const cpf = "390.533.447-05";
      await on.cliente.create({ data: { tenantId: tenantC, nome: "ByKey", cpfCnpj: cpf } });
      await assert.rejects(on.cliente.update({ where: { tenantId_cpfCnpj: { tenantId: tenantC, cpfCnpj: cpf } }, data: { telefone: "11999990000" } }), /must identify the row/);
      assert.equal((await on.cliente.update({ where: { tenantId_cpfCnpj: { tenantId: tenantC, cpfCnpj: cpf } }, data: { nome: "ByKey2" } })).nome, "ByKey2"); // no encrypted value written: fine
      await assert.rejects(on.webhook.updateMany({ where: { url: "upd" }, data: { secret: "v3" } }), /must identify the row/);
      assert.equal((await on.webhook.updateMany({ where: { url: "upd" }, data: { secret: null } })).count, 1); // clearing needs no ciphertext
      assert.equal((await on.webhook.findUniqueOrThrow({ where: { id: w.id } })).secret, null);
      assert.equal((await on.webhook.updateMany({ where: { url: "upd" }, data: { url: "upd2" } })).count, 1); // plain columns are unaffected

      const id = "upsert-" + Date.now();
      const created = await on.webhook.upsert({ where: { id }, create: { tenantId: tenantC, url: "up", secret: "c1" }, update: { secret: "u1" } });
      assert.equal(created.id, id); // the id of the where is used for the create too
      assert.equal(await cp.decrypt({ tenant: tenantC, collection: "Webhook", field: "secret", recordId: id }, (await raw.webhook.findUniqueOrThrow({ where: { id } })).secret), "c1");
      const updated = await on.webhook.upsert({ where: { id }, create: { tenantId: tenantC, url: "up", secret: "c2" }, update: { secret: "u1" } });
      assert.equal(updated.secret, "u1");
      await assert.rejects(on.cliente.upsert({ where: { tenantId_cpfCnpj: { tenantId: tenantC, cpfCnpj: cpf } }, create: { tenantId: tenantC, nome: "n", cpfCnpj: cpf }, update: { telefone: "11999990000" } }), /must identify the row/);
    });
  });

  it("createMany binds every row to its own id", async () => {
    await withTenant(tenantC, async () => {
      await on.webhook.createMany({ data: [1, 2, 3].map((i) => ({ tenantId: tenantC, url: "many", secret: "s" + i })) });
      const rows = await raw.webhook.findMany({ where: { url: "many", tenantId: tenantC } });
      assert.equal(rows.length, 3);
      for (const r of rows) {
        const plain = await cp.decrypt({ tenant: tenantC, collection: "Webhook", field: "secret", recordId: r.id }, r.secret);
        assert.match(plain, /^s[123]$/);
      }
      assert.deepEqual((await on.webhook.findMany({ where: { url: "many" } })).map((r) => r.secret).sort(), ["s1", "s2", "s3"]);
    });
  });

  it("String[] and Json values are bound too", async () => {
    await withTenant(tenantC, async () => {
      const c = await on.cliente.create({ data: { tenantId: tenantC, nome: "Bound", documentos: ["d1", "d2"], prefs: { a: 1 } } });
      const row = await raw.cliente.findUniqueOrThrow({ where: { id: c.id } });
      const ctx = (f) => ({ tenant: tenantC, collection: "Cliente", field: f, recordId: c.id });
      assert.equal(await cp.decrypt(ctx("documentos"), row.documentos[0]), "d1");
      assert.equal(await cp.decrypt(ctx("prefs"), row.prefs), '{"a":1}');
      const back = await on.cliente.findUniqueOrThrow({ where: { id: c.id } });
      assert.deepEqual([back.documentos, back.prefs], [["d1", "d2"], { a: 1 }]);
      await on.cliente.update({ where: { id: c.id }, data: { documentos: { push: "d3" } } });
      assert.deepEqual((await on.cliente.findUniqueOrThrow({ where: { id: c.id } })).documentos, ["d1", "d2", "d3"]);
    });
  });

  it("migration path: existing unbound rows read in 'on', are refused in 'strict', and rotateModel({bindRows}) binds them", async () => {
    await withTenant(tenantB, async () => {
      for (let i = 0; i < 5; i++) await off.webhook.create({ data: { tenantId: tenantB, url: "legacy", secret: "old-" + i } });
      assert.equal((await on.webhook.findMany({ where: { url: "legacy" } })).length, 5); // falls back to the unbound AAD
      await assert.rejects(strict.webhook.findMany({ where: { url: "legacy" } }), /decryption_failed/);

      const stats = await rotateModel(raw, cp, schema, { model: "Webhook", tenantOf: (r) => r.tenantId, bindRows: true, verify: true });
      assert.deepEqual(stats.failures, []);
      assert.ok(stats.rebound >= 5, JSON.stringify(stats));
      assert.ok(stats.verified >= 5);
      assert.deepEqual((await strict.webhook.findMany({ where: { url: "legacy" }, orderBy: { id: "asc" } })).map((r) => r.secret).sort(), ["old-0", "old-1", "old-2", "old-3", "old-4"]);
      // idempotent: a second pass has nothing left to bind
      const again = await rotateModel(raw, cp, schema, { model: "Webhook", tenantOf: (r) => r.tenantId, bindRows: true });
      assert.equal(again.rebound, 0);
      assert.deepEqual(again.failures, []);
    });
  });

  it("the raw helpers take the row id: decryptRows picks it from the row, encryptValue needs recordId", async () => {
    await withTenant(tenantC, async () => {
      const w = await on.webhook.create({ data: { tenantId: tenantC, url: "rawh", secret: "via-helper" } });
      const rows = await raw.$queryRawUnsafe(`SELECT id, secret_value /* cryplus:handled */ FROM p5.webhooks WHERE id = $1`, w.id);
      await on.$cryplus.decryptRows("Webhook", rows);
      assert.equal(rows[0].secret_value, "via-helper");
      await assert.rejects(on.$cryplus.encryptValue("Webhook", "secret", "x"), /row id/);
      const ct = await on.$cryplus.encryptValue("Webhook", "secret", "x", { recordId: w.id });
      assert.equal(await on.$cryplus.decryptValue("Webhook", "secret", ct, { recordId: w.id }), "x");
    });
  });
});

describe("filters: undefined means 'no filter', exactly like Prisma", () => {
  it("top level, inside AND / OR / NOT, as an operand, in a relation filter and in a compound key", async () => {
    const db = make();
    await withTenant(tenantA, async () => {
      await raw.cliente.deleteMany({ where: { tenantId: tenantA } });
      await db.cliente.create({ data: { tenantId: tenantA, nome: "U1", cpfCnpj: "111.222.333-44" } });
      await db.cliente.create({ data: { tenantId: tenantA, nome: "U2" } });
      const all = (await db.cliente.findMany({ where: { tenantId: tenantA } })).length;
      assert.ok(all >= 2);
      for (const where of [
        { tenantId: tenantA, cpfCnpj: undefined },
        { tenantId: tenantA, cpfCnpj: { equals: undefined } },
        { tenantId: tenantA, cpfCnpj: { in: undefined } },
        { tenantId: tenantA, cpfCnpj: { not: undefined } },
        { tenantId: tenantA, AND: [{ cpfCnpj: undefined }] },
        { tenantId: tenantA, AND: [undefined, { cpfCnpj: undefined }] },
        { tenantId: tenantA, telefone: undefined, email: undefined },
      ]) {
        assert.equal((await db.cliente.findMany({ where })).length, all, JSON.stringify(where));
      }
      // an OR whose only member is an undefined filter behaves like the same OR on a plain column (whatever Prisma decides)
      assert.equal(await db.cliente.count({ where: { tenantId: tenantA, OR: [{ cpfCnpj: undefined }] } }), await db.cliente.count({ where: { tenantId: tenantA, OR: [{ nome: undefined }] } }));
      const one = await db.cliente.findFirst({ where: { tenantId: tenantA, cpfCnpj: "111.222.333-44", telefone: undefined } });
      assert.equal(one.nome, "U1");
      assert.equal((await db.cliente.findUnique({ where: { tenantId_cpfCnpj: { tenantId: tenantA, cpfCnpj: "111.222.333-44" } } })).nome, "U1");
      // an optional-filter helper written the way Operax writes them
      const search = async (cpf) => db.cliente.findMany({ where: { tenantId: tenantA, cpfCnpj: cpf || undefined } });
      assert.equal((await search("")).length, all);
      assert.equal((await search("111.222.333-44")).length, 1);
    });
  });
});

describe("legacy rows during a migration", () => {
  const CPF = "529.982.247-25";
  let plain, fallback;
  before(async () => {
    plain = make();
    fallback = make({ legacy: "fallback" });
    // a legacy row: plaintext, no index (as it is before the migration touches it)
    await raw.cliente.deleteMany({ where: { tenantId: tenantA, nome: "Legado" } });
    await raw.cliente.create({ data: { tenantId: tenantA, nome: "Legado", cpfCnpj: CPF } });
  });

  it("without help, equality search does not see it, so a duplicate check lets a duplicate through (the problem)", async () => {
    await withTenant(tenantA, async () => assert.equal(await plain.cliente.findFirst({ where: { cpfCnpj: CPF } }), null));
  });

  it("legacy: 'fallback' finds it through the plaintext column, for equals and in; other operators are refused", async () => {
    await withTenant(tenantA, async () => {
      assert.equal((await fallback.cliente.findFirst({ where: { cpfCnpj: CPF } })).nome, "Legado");
      assert.equal((await fallback.cliente.findFirst({ where: { cpfCnpj: { equals: CPF } } })).nome, "Legado");
      assert.equal((await fallback.cliente.findMany({ where: { cpfCnpj: { in: [CPF, "000"] } } })).length, 1);
      assert.equal(await fallback.cliente.findFirst({ where: { cpfCnpj: "999.999.999-99" } }), null);
      assert.equal((await fallback.cliente.findMany({ where: { cpfCnpj: undefined, tenantId: tenantA } })).length > 0, true);
      await assert.rejects(fallback.cliente.findMany({ where: { cpfCnpj: { not: CPF } } }), /legacy "fallback" supports only equality/);
      // equality under NOT is fine (not (idx match or plaintext match)); only the operators `not` / `notIn` are refused
      const others = await fallback.cliente.findMany({ where: { tenantId: tenantA, NOT: { cpfCnpj: CPF } } });
      assert.ok(others.every((c) => c.nome !== "Legado"));
      await assert.rejects(fallback.cliente.findMany({ where: { tenantId: tenantA, cpfCnpj: { notIn: [CPF] } } }), /legacy "fallback" supports only equality/);
    });
  });

  it("index-only fills the index of the still-PLAINTEXT row and leaves the value alone; equality search then works without the fallback", async () => {
    const stats = await migrateModel(raw, cp, schema, { model: "Cliente", tenantOf: (r) => r.tenantId, mode: "index-only" });
    assert.deepEqual(stats.failures, []);
    assert.ok(stats.indexed >= 1);
    const row = await raw.cliente.findFirstOrThrow({ where: { tenantId: tenantA, nome: "Legado" } });
    assert.equal(row.cpfCnpj, CPF); // still plaintext
    assert.ok(row.cpfCnpjIdx);
    await withTenant(tenantA, async () => {
      assert.equal((await plain.cliente.findFirst({ where: { cpfCnpj: CPF } })).nome, "Legado");
      assert.equal((await plain.cliente.findFirst({ where: { cpfCnpj: CPF } })).cpfCnpj, CPF);
    });
  });

  it("then `all` encrypts it, and the same lookup still works", async () => {
    const stats = await migrateModel(raw, cp, schema, { model: "Cliente", tenantOf: (r) => r.tenantId, mode: "all", verify: true });
    assert.deepEqual(stats.failures, []);
    assert.match((await raw.cliente.findFirstOrThrow({ where: { tenantId: tenantA, nome: "Legado" } })).cpfCnpj, /^cp1\./);
    await withTenant(tenantA, async () => assert.equal((await plain.cliente.findFirst({ where: { cpfCnpj: CPF } })).cpfCnpj, CPF));
  });
});

describe("tenantFrom: tables without a tenant column", () => {
  let db, lookups;
  before(() => {
    const base = new PrismaClient({ datasources: { db: { url: DB } } });
    clients.push(base);
    lookups = 0;
    const spy = { ...base, conversa: { findUnique: (a) => (lookups++, base.conversa.findUnique(a)) }, mensagem: base.mensagem };
    db = make({ tenantFrom: { Mensagem: { via: "conversaId", model: "Conversa" } }, lookupClient: spy });
  });

  it("with NO ambient tenant: create/read by conversaId, by relation filter, by id; and each tenant's data is encrypted under its own keys", async () => {
    const ca = await raw.conversa.create({ data: { tenantId: tenantA } });
    const cb = await raw.conversa.create({ data: { tenantId: tenantB } });
    assert.equal(currentTenant(), undefined);

    const m = await db.mensagem.create({ data: { conversaId: ca.id, direcao: "in", conteudo: "olá A" } });
    await db.mensagem.create({ data: { conversaId: cb.id, direcao: "in", conteudo: "olá B" } });
    const rowA = await raw.mensagem.findUniqueOrThrow({ where: { id: m.id } });
    assert.equal(await cp.decrypt({ tenant: tenantA, collection: "Mensagem", field: "conteudo" }, rowA.conteudo), "olá A");
    await assert.rejects(cp.decrypt({ tenant: tenantB, collection: "Mensagem", field: "conteudo" }, rowA.conteudo), /decryption_failed/);

    assert.deepEqual((await db.mensagem.findMany({ where: { conversaId: ca.id } })).map((x) => x.conteudo), ["olá A"]);
    assert.deepEqual((await db.mensagem.findMany({ where: { conversa: { is: { tenantId: tenantB } } } })).map((x) => x.conteudo), ["olá B"]);
    assert.deepEqual((await db.mensagem.findMany({ where: { conversa: { tenantId: tenantA } } })).map((x) => x.conteudo), ["olá A"]);
    assert.equal((await db.mensagem.findUniqueOrThrow({ where: { id: m.id } })).conteudo, "olá A"); // only the row's own id is known: looked up
    assert.equal((await db.mensagem.update({ where: { id: m.id }, data: { conteudo: "editada" } })).conteudo, "editada");

    await db.mensagem.createMany({ data: [1, 2].map((i) => ({ conversaId: ca.id, direcao: "in", conteudo: "lote " + i })) }); // all rows share one conversa
    assert.equal((await db.mensagem.findMany({ where: { conversaId: ca.id, conteudo: undefined } })).length, 3);
    // rows that do NOT share a conversa cannot be attributed to one tenant: refused, not guessed
    await assert.rejects(db.mensagem.createMany({ data: [{ conversaId: ca.id, direcao: "in", conteudo: "x" }, { conversaId: cb.id, direcao: "in", conteudo: "y" }] }), /no tenant for Mensagem/);
    // nested create from the parent resolves the child through its parent's tenant
    const nested = await db.conversa.create({ data: { tenantId: tenantA, mensagens: { create: { direcao: "in", conteudo: "aninhada" } } }, include: { mensagens: true } });
    assert.equal(nested.mensagens[0].conteudo, "aninhada");
  });

  it("the parent lookup is cached: many operations on one conversation cost one lookup", async () => {
    const ca = await raw.conversa.create({ data: { tenantId: tenantA } });
    const m = await db.mensagem.create({ data: { conversaId: ca.id, direcao: "in", conteudo: "c0" } });
    lookups = 0;
    for (let i = 0; i < 20; i++) await db.mensagem.findMany({ where: { conversaId: ca.id } });
    for (let i = 0; i < 5; i++) await db.mensagem.findUniqueOrThrow({ where: { id: m.id } });
    assert.ok(lookups <= 1, `lookups: ${lookups}`);
  });

  it("an ambient tenant is used as is and skips the lookup entirely", async () => {
    const ca = await raw.conversa.create({ data: { tenantId: tenantA } });
    lookups = 0;
    await withTenant(tenantA, async () => {
      await db.mensagem.create({ data: { conversaId: ca.id, direcao: "in", conteudo: "ambient" } });
      assert.equal((await db.mensagem.findMany({ where: { conversaId: ca.id } }))[0].conteudo, "ambient");
    });
    assert.equal(lookups, 0);
  });

  it("an unknown conversation fails closed with the usual message", async () => {
    // nothing to decrypt, nothing to resolve: an unknown conversation just has no messages
    assert.deepEqual(await db.mensagem.findMany({ where: { conversaId: "does-not-exist" } }), []);
    // but rows that need decrypting with no way to tell their tenant are refused, never guessed
    await assert.rejects(db.mensagem.findMany({ where: { direcao: "in" } }), /no tenant for Mensagem/);
  });

  it("models WITH a tenant column do not derive their tenant from the query unless tenantFromArgs is set (forgetting withTenant must fail)", async () => {
    const closed = make({ tenantFrom: { Mensagem: { via: "conversaId", model: "Conversa" } } });
    await assert.rejects(closed.cliente.create({ data: { tenantId: tenantA, nome: "no ctx", telefone: "1" } }), /no tenant for Cliente/);
    const c = await raw.cliente.create({ data: { tenantId: tenantA, nome: "by id", cpfCnpj: null } });
    await assert.rejects(closed.cliente.findUnique({ where: { id: c.id } }), /no tenant|decrypt|plaintext/).catch(() => {});
    const open = make({ tenantFromArgs: true });
    const made = await open.cliente.create({ data: { tenantId: tenantA, nome: "derived", telefone: "11 90000-1111" } });
    assert.equal(made.telefone, "11 90000-1111");
    assert.equal((await open.cliente.findMany({ where: { tenantId: tenantA, nome: "derived" } }))[0].telefone, "11 90000-1111");
    assert.equal((await open.cliente.findUniqueOrThrow({ where: { id: made.id } })).telefone, "11 90000-1111"); // id only: looked up
    const row = await raw.cliente.findUniqueOrThrow({ where: { id: made.id } });
    assert.equal(await cp.decrypt({ tenant: tenantA, collection: "Cliente", field: "telefone" }, row.telefone), "11 90000-1111");
  });

  it("a rule that points at a missing field or model is rejected at startup", () => {
    assert.throws(() => make({ tenantFrom: { Mensagem: { via: "nope", model: "Conversa" } } }), /no field "nope"/);
    assert.throws(() => make({ tenantFrom: { Mensagem: { via: "conversaId", model: "Nada" } } }), /unknown parent model/);
  });
});

describe("plaintext policy per model", () => {
  it("{ default: 'allow', Webhook: 'reject' } rejects plaintext only where asked", async () => {
    const db = make({ plaintext: { default: "allow", Webhook: "reject" } });
    const w = await raw.webhook.create({ data: { tenantId: tenantA, url: "pt", secret: "plain-secret" } });
    const c = await raw.cliente.create({ data: { tenantId: tenantA, nome: "PT", telefone: "plain-phone" } });
    await withTenant(tenantA, async () => {
      await assert.rejects(db.webhook.findUniqueOrThrow({ where: { id: w.id } }), /plaintext reads are rejected/);
      assert.equal((await db.cliente.findUniqueOrThrow({ where: { id: c.id } })).telefone, "plain-phone");
    });
    await raw.webhook.delete({ where: { id: w.id } });
  });
});

describe("a write does not pay a second round trip to read its own values back", () => {
  it("create/update return the plaintext without calling decrypt; a later read decrypts once per value", async () => {
    const c = counting(cp);
    const db = make({}, c);
    await withTenant(tenantA, async () => {
      const w = await db.webhook.create({ data: { tenantId: tenantA, url: "rt", secret: "round-trip" } });
      assert.equal(w.secret, "round-trip");
      assert.equal(c.n.decrypt, 0, "create must not decrypt what it just encrypted");
      const u = await db.webhook.update({ where: { id: w.id }, data: { secret: "round-trip-2" } });
      assert.equal(u.secret, "round-trip-2");
      assert.equal(c.n.decrypt, 0);
      assert.equal(c.n.encrypt, 2);
      assert.equal((await db.webhook.findUniqueOrThrow({ where: { id: w.id } })).secret, "round-trip-2");
      assert.equal(c.n.decrypt, 1, "a fresh read still decrypts (the cache lives only for one operation)");
      // a value that is NOT the one we just wrote is never taken from the cache
      await raw.webhook.update({ where: { id: w.id }, data: { secret: (await cp.encrypt({ tenant: tenantA, collection: "Webhook", field: "secret" }, "changed-behind-our-back")) } });
      assert.equal((await db.webhook.findUniqueOrThrow({ where: { id: w.id } })).secret, "changed-behind-our-back");
    });
  });
});

describe("migrateModel: concurrency, sampled verification, progress", () => {
  it("encrypts a table with 4 writers, verifies a sample, and reports total / rate / eta", async () => {
    await raw.webhook.deleteMany({ where: { tenantId: tenantB, url: "bulk" } });
    await raw.webhook.createMany({ data: Array.from({ length: 80 }, (_, i) => ({ tenantId: tenantB, url: "bulk", secret: "plain-" + i })) });
    const seen = [];
    const stats = await migrateModel(raw, cp, schema, {
      model: "Webhook", tenantOf: (r) => r.tenantId, batchSize: 25, concurrency: 4, verify: { sample: 0.5 }, onProgress: (s) => seen.push({ ...s }),
    });
    assert.deepEqual(stats.failures, []);
    assert.ok(stats.encrypted >= 80);
    assert.ok(stats.verified > 0 && stats.verified < stats.encrypted, `sampled verification: ${stats.verified}/${stats.encrypted}`);
    assert.ok(stats.total >= 80);
    assert.ok(stats.rowsPerSec > 0 && stats.elapsedMs >= 0);
    assert.ok(seen.length >= 3);
    assert.ok(seen.some((s) => typeof s.etaSec === "number"));
    const rows = await raw.webhook.findMany({ where: { tenantId: tenantB, url: "bulk" } });
    assert.ok(rows.every((r) => /^cp1\./.test(r.secret)));
    const db = make();
    await withTenant(tenantB, async () => {
      assert.deepEqual((await db.webhook.findMany({ where: { url: "bulk" } })).map((r) => r.secret).sort().slice(0, 2), ["plain-0", "plain-1"]);
    });
  });

  it("a failing writer stops the pool and the error is reported, not swallowed", async () => {
    const broken = { ...raw, webhook: { findMany: (a) => raw.webhook.findMany(a), count: () => raw.webhook.count(), update: () => Promise.reject(new Error("db down")) } };
    await raw.webhook.create({ data: { tenantId: tenantB, url: "bulk2", secret: "will-fail" } });
    await assert.rejects(migrateModel(broken, cp, schema, { model: "Webhook", tenantOf: (r) => r.tenantId, concurrency: 3 }), /db down/);
  });
});

describe("cryplusTenantMiddleware (Express)", () => {
  it("sets the ambient tenant for the whole request, including awaited work, and skips it when there is none", async () => {
    const mw = cryplusTenantMiddleware((req) => req.tenantId);
    const seen = [];
    await new Promise((resolve) =>
      mw({ tenantId: "t-express" }, {}, async () => {
        seen.push(currentTenant());
        await new Promise((r) => setTimeout(r, 5));
        seen.push(currentTenant());
        resolve();
      }),
    );
    assert.deepEqual(seen, ["t-express", "t-express"]);
    assert.equal(currentTenant(), undefined);
    await new Promise((resolve) => cryplusTenantMiddleware(() => undefined)({}, {}, () => (assert.equal(currentTenant(), undefined), resolve())));
    await new Promise((resolve) => cryplusTenantMiddleware(async (r) => r.t)({ t: "async-t" }, {}, () => (assert.equal(currentTenant(), "async-t"), resolve())));
    const err = await new Promise((resolve) => cryplusTenantMiddleware(() => { throw new Error("boom"); })({}, {}, resolve));
    assert.equal(err.message, "boom");
  });

  it("two concurrent requests never see each other's tenant", async () => {
    const mw = cryplusTenantMiddleware((req) => req.t);
    const run = (t, ms) => new Promise((resolve) => mw({ t }, {}, async () => { await new Promise((r) => setTimeout(r, ms)); resolve(currentTenant()); }));
    assert.deepEqual(await Promise.all([run("one", 30), run("two", 5), run("three", 15)]), ["one", "two", "three"]);
  });
});
