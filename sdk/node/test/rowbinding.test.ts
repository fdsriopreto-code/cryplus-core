import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Cryplus, newId, parseSchema, cryplusTenantMiddleware, currentTenant } from "../src/index.ts";
import { Transformer, plaintextPolicy } from "../src/prisma.ts";
import { createTenantDeriver } from "../src/tenantfrom.ts";

const schema = parseSchema(`
model Webhook {
  id String @id @default(uuid())
  tenantId String
  url String
  /// @encrypted
  secret String?
}
model Cliente {
  id String @id @default(cuid())
  tenantId String
  /// @encrypted(searchable, digits)
  cpf String?
  cpfIdx String?
  /// @encrypted
  tags String[]
  /// @encrypted
  prefs Json?
}
model Legacy {
  id Int @id @default(autoincrement())
  /// @encrypted
  secret String?
}
model Conversa {
  id String @id
  tenantId String
  mensagens Mensagem[]
}
model Mensagem {
  id String @id @default(uuid())
  conversaId String
  conversa Conversa @relation(fields: [conversaId], references: [id])
  /// @encrypted
  texto String?
}
`);

const make = (opts: Partial<ConstructorParameters<typeof Transformer>[3]> = {}, tenant = "t1") =>
  new Transformer(Cryplus.inMemory() as any, schema, async () => tenant, { plaintext: "allow", hideIndexFields: true, ...opts });

describe("ids", () => {
  it("newId looks like what the schema default would generate", () => {
    assert.match(newId("uuid"), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.match(newId("cuid"), /^c[0-9a-z]{24}$/);
    assert.match(newId("ulid"), /^[0-9A-HJKMNP-TV-Z]{26}$/);
    assert.match(newId("nanoid"), /^[\w-]{21}$/);
    assert.equal(new Set(Array.from({ length: 500 }, () => newId("cuid"))).size, 500);
  });
  it("which models can be bound", () => {
    assert.deepEqual(["Webhook", "Cliente", "Legacy", "Conversa"].map((m) => schema.get(m)!.bindable), [true, true, false, true]);
    assert.equal(schema.get("Cliente")!.fields.get("id")!.idDefault, "cuid");
    assert.equal(schema.get("Legacy")!.fields.get("id")!.idDefault, "autoincrement");
    assert.equal(schema.get("Conversa")!.fields.get("id")!.idDefault, undefined);
  });
});

describe("Transformer with rowBinding", () => {
  it("create: the id is generated first, kept in the data, and is what the ciphertext is bound to", async () => {
    const x = make({ rowBinding: "on" });
    const m = schema.get("Webhook")!;
    const out = await x.data(m, { tenantId: "t1", url: "u", secret: "s3" });
    assert.match(out.id, /^[0-9a-f-]{36}$/);
    const c = x.c as Cryplus;
    assert.equal(await c.decrypt({ tenant: "t1", collection: "Webhook", field: "secret", recordId: out.id }, out.secret), "s3");
    await assert.rejects(c.decrypt({ tenant: "t1", collection: "Webhook", field: "secret" }, out.secret), /decryption_failed/);
    // a supplied id is respected, and two creates get different ids
    assert.equal((await x.data(m, { id: "mine", tenantId: "t1", url: "u", secret: "x" })).id, "mine");
    assert.notEqual((await x.data(m, { url: "u", secret: "x", tenantId: "t1" })).id, out.id);
  });

  it("String[] and Json are bound; array create gives every row its own id", async () => {
    const x = make({ rowBinding: "on" });
    const m = schema.get("Cliente")!;
    const rows = (await x.data(m, [{ tenantId: "t1", tags: ["a", "b"], prefs: { k: 1 } }, { tenantId: "t1", tags: ["c"] }])) as any[];
    assert.notEqual(rows[0].id, rows[1].id);
    const c = x.c as Cryplus;
    assert.equal(await c.decrypt({ tenant: "t1", collection: "Cliente", field: "tags", recordId: rows[0].id }, rows[0].tags[1]), "b");
    assert.equal(await c.decrypt({ tenant: "t1", collection: "Cliente", field: "prefs", recordId: rows[0].id }, rows[0].prefs), '{"k":1}');
  });

  it("update/upsert/updateMany: an encrypted value needs the row id; null and plain columns do not", async () => {
    const x = make({ rowBinding: "on" });
    const m = schema.get("Webhook")!;
    await assert.rejects(x.data(m, { secret: "v" }, { kind: "update" }), /must identify the row/);
    assert.deepEqual(await x.data(m, { secret: null, url: "z" }, { kind: "update" }), { secret: null, url: "z" });
    assert.deepEqual(await x.data(m, { url: "z" }, { kind: "update" }), { url: "z" });
    const ok = await x.data(m, { secret: "v" }, { kind: "update", rid: "row-1" });
    assert.equal(await (x.c as Cryplus).decrypt({ tenant: "t1", collection: "Webhook", field: "secret", recordId: "row-1" }, ok.secret), "v");
    // upsert's create takes the id of its where
    const created = await x.data(m, { tenantId: "t1", url: "u", secret: "v" }, { kind: "create", id: "from-where" });
    assert.equal(created.id, "from-where");
  });

  it("a model that cannot be bound (Int id) is left alone", async () => {
    const x = make({ rowBinding: "strict" });
    const m = schema.get("Legacy")!;
    const out = await x.data(m, { secret: "plain->enc" });
    assert.equal("id" in out, false);
    assert.equal(await x.c.decrypt({ tenant: "t1", collection: "Legacy", field: "secret" }, out.secret), "plain->enc");
    assert.equal(await x.decryptValue(m, m.encrypted.get("secret")!, out.secret), "plain->enc");
  });

  it("reads: bound opens with the id; legacy opens in 'on' and is refused in 'strict'; a swapped value is refused in both", async () => {
    const off = make();
    const on = make({ rowBinding: "on" });
    const strict = make({ rowBinding: "strict" });
    // same in-memory keys for all three
    const shared = Cryplus.inMemory();
    const mk = (o: any) => new Transformer(shared as any, schema, async () => "t1", { plaintext: "allow", hideIndexFields: true, ...o });
    const [o, n, s] = [mk({}), mk({ rowBinding: "on" }), mk({ rowBinding: "strict" })];
    void off; void on; void strict;
    const m = schema.get("Webhook")!;
    const f = m.encrypted.get("secret")!;
    const legacy = (await o.data(m, { tenantId: "t1", url: "u", secret: "old" })).secret as string; // written without binding
    const bound = await n.data(m, { id: "A", tenantId: "t1", url: "u", secret: "new" });
    assert.equal(await mk({ rowBinding: "on" }).decryptValue(m, f, legacy, "A"), "old");
    await assert.rejects(s.decryptValue(m, f, legacy, "A"), /decryption_failed/);
    assert.equal(await s.decryptValue(m, f, bound.secret, "A"), "new");
    await assert.rejects(mk({ rowBinding: "on" }).decryptValue(m, f, bound.secret, "B"), /decryption_failed/, "swapped into another row");
    await assert.rejects(s.decryptValue(m, f, bound.secret, "B"), /decryption_failed/);
    await assert.rejects(s.decryptValue(m, f, bound.secret, undefined), /id is not available/);
  });

  it("injectIds adds the id to a select that lacks it (nested too) and applyStrip removes exactly that", () => {
    const x = make({ rowBinding: "on" });
    const m = schema.get("Conversa")!;
    const args: any = { select: { tenantId: true, mensagens: { select: { texto: true } } } };
    const strip = x.injectIds(m, args)!;
    assert.deepEqual(args.select.mensagens.select, { texto: true, id: true });
    assert.equal(args.select.id, undefined, "Conversa has no encrypted field selected: no id needed there");
    const row: any = { tenantId: "t1", mensagens: [{ texto: "a", id: "m1" }, { texto: "b", id: "m2" }] };
    x.applyStrip(m, row, strip);
    assert.deepEqual(row, { tenantId: "t1", mensagens: [{ texto: "a" }, { texto: "b" }] });
    // an id the caller asked for stays
    const keep: any = { select: { texto: true, id: true } };
    assert.equal(x.injectIds(schema.get("Mensagem")!, keep), undefined);
    // nothing to do when binding is off
    assert.equal(make().injectIds(schema.get("Mensagem")!, { select: { texto: true } }), undefined);
  });

  it("values this operation encrypted are read back without a decrypt call", async () => {
    let decrypts = 0;
    const inner = Cryplus.inMemory();
    const counting = { encrypt: inner.encrypt.bind(inner), decrypt: (c: any, t: string) => (decrypts++, inner.decrypt(c, t)), blindIndex: inner.blindIndex.bind(inner) };
    const x = new Transformer(counting as any, schema, async () => "t1", { plaintext: "allow", hideIndexFields: true });
    const m = schema.get("Cliente")!;
    const data = await x.data(m, { tenantId: "t1", cpf: "123", tags: ["a"], prefs: { z: 1 } });
    const back = await x.result(m, { ...data });
    assert.deepEqual([back.cpf, back.tags, back.prefs], ["123", ["a"], { z: 1 }]);
    assert.equal(decrypts, 0);
    // a different Transformer (another operation) does not share the cache
    const y = new Transformer(counting as any, schema, async () => "t1", { plaintext: "allow", hideIndexFields: true });
    await y.result(m, { ...data });
    assert.equal(decrypts, 3);
  });
});

describe("filters", () => {
  const m = schema.get("Cliente")!;
  it("undefined is dropped everywhere, and an empty filter object stays empty", async () => {
    const x = make();
    assert.deepEqual(await x.where(m, { tenantId: "t1", cpf: undefined }), { tenantId: "t1" });
    assert.deepEqual(await x.where(m, { AND: [undefined, { cpf: undefined }], NOT: undefined }), { AND: [{}] });
    assert.deepEqual(await x.where(m, { cpf: { equals: undefined, in: undefined, not: undefined } }), { cpfIdx: {} });
    assert.deepEqual(await x.where(m, { cpf: { in: ["1"], notIn: undefined } }).then((r) => Object.keys(r.cpfIdx)), ["in"]);
  });

  it("legacy fallback: equality becomes OR(index, plaintext) and survives the post-rewrite check; other operators are refused", async () => {
    const x = make({ legacy: "fallback" });
    const w = await x.where(m, { tenantId: "t1", cpf: "123" });
    assert.equal(w.AND.length, 1);
    assert.equal(Object.keys(w.AND[0].OR[0])[0], "cpfIdx");
    assert.deepEqual(w.AND[0].OR[1], { cpf: "123" });
    x.assertRewritten(m, w); // the plaintext leg is ours, so it is allowed
    x.assertRewritten(m, await x.where(m, { OR: [{ cpf: { in: ["1", "2"] } }, { NOT: { cpf: "3" } }] }));
    await assert.rejects(x.where(m, { cpf: { not: "1" } }), /legacy "fallback" supports only equality/);
    await assert.rejects(x.where(m, { cpf: { notIn: ["1"] } }), /legacy "fallback" supports only equality/);
    // an AND the caller wrote is kept next to the generated one
    const both = await x.where(m, { AND: [{ tenantId: "t1" }], cpf: "9" });
    assert.equal(both.AND.length, 2);
    // a user-written plaintext condition that did NOT come from the rewriter is still refused by the check
    assert.throws(() => x.assertRewritten(m, { OR: [{ cpfIdx: "x" }, { cpf: "123" }] }), /not rewritten/);
  });

  it("_count filters and nested relation orderBy are rewritten / checked", async () => {
    const x = make();
    const c = schema.get("Conversa")!;
    const sel = await x.selection(c, { _count: { select: { mensagens: { where: { texto: null } } } } });
    assert.deepEqual(sel._count.select.mensagens.where, { texto: null });
    await assert.rejects(x.selection(c, { _count: { select: { mensagens: { where: { texto: "x" } } } } }), /cannot filter on encrypted field Mensagem.texto/);
    assert.doesNotThrow(() => x.checkOrder(schema.get("Mensagem")!, { conversa: { id: "asc" } }));
    assert.throws(() => x.checkOrder(c, { mensagens: { texto: "asc" } }), /cannot order by encrypted field Mensagem.texto/);
  });
});

describe("plaintext policy", () => {
  it("per model, with a default", () => {
    assert.equal(plaintextPolicy(undefined, "A"), "allow");
    assert.equal(plaintextPolicy("reject", "A"), "reject");
    assert.equal(plaintextPolicy({ default: "allow", B: "reject" }, "A"), "allow");
    assert.equal(plaintextPolicy({ default: "allow", B: "reject" }, "B"), "reject");
    assert.equal(plaintextPolicy({ B: "reject" } as any, "A"), "allow");
    assert.equal(plaintextPolicy({ default: "reject", B: "allow" }, "A"), "reject");
  });
});

describe("tenantFrom resolution (no database: a fake lookup client)", () => {
  const rows: Record<string, any> = { c1: { tenantId: "tA" }, c2: { tenantId: "tB" } };
  let lookups = 0;
  const client = { conversa: { findUnique: async ({ where }: any) => (lookups++, rows[where.id] ?? null) } };
  const derive = createTenantDeriver(schema, { tenantFrom: { Mensagem: { via: "conversaId", model: "Conversa" } }, client: () => client });

  it("from the foreign key, a relation filter, a connect, a nested create and the cache", async () => {
    assert.equal(await derive("Mensagem", "Mensagem", { data: { conversaId: "c1", texto: "x" } }), "tA");
    assert.equal(await derive("Mensagem", "Mensagem", { where: { conversaId: "c2" } }), "tB");
    assert.equal(await derive("Mensagem", "Mensagem", { where: { conversa: { is: { tenantId: "direct" } } } }), "direct");
    assert.equal(await derive("Mensagem", "Mensagem", { where: { conversa: { tenantId: "direct2" } } }), "direct2");
    assert.equal(await derive("Mensagem", "Mensagem", { data: { texto: "x", conversa: { connect: { id: "c1" } } } }), "tA");
    assert.equal(await derive("Mensagem", "Mensagem", { data: [{ conversaId: "c1" }, { conversaId: "c1" }] }), "tA", "createMany, one conversa");
    assert.equal(await derive("Mensagem", "Mensagem", { data: [{ conversaId: "c1" }, { conversaId: "c2" }] }), undefined, "createMany, mixed: never guessed");
    assert.equal(await derive("Mensagem", "Mensagem", { where: { conversaId: "nope" } }), undefined);
    assert.equal(await derive("Mensagem", "Mensagem", { where: { texto: null } }), undefined);
    assert.equal(await derive("Mensagem", "Conversa", { data: { tenantId: "tZ", mensagens: { create: {} } } }), "tZ", "nested under the parent");
    const before = lookups;
    for (let i = 0; i < 10; i++) await derive("Mensagem", "Mensagem", { where: { conversaId: "c1" } });
    assert.equal(lookups, before, "cached");
  });

  it("models with a tenant column are NOT derived unless fromArgs is set", async () => {
    assert.equal(await derive("Webhook", "Webhook", { data: { tenantId: "tX" } }), undefined);
    const open = createTenantDeriver(schema, { fromArgs: true, client: () => client });
    assert.equal(await open("Webhook", "Webhook", { data: { tenantId: "tX" } }), "tX");
    assert.equal(await open("Webhook", "Webhook", { where: { AND: [{ tenantId: "tY" }] } }), "tY");
    assert.equal(await open("Webhook", "Webhook", { data: [{ tenantId: "tX" }, { tenantId: "tZ" }] }), undefined);
  });

  it("bad rules are rejected at construction", () => {
    assert.throws(() => createTenantDeriver(schema, { tenantFrom: { Mensagem: { via: "x", model: "Conversa" } } }), /no field "x"/);
    assert.throws(() => createTenantDeriver(schema, { tenantFrom: { Nope: { via: "x", model: "Conversa" } } }), /unknown model/);
  });

  it("the cache is bounded", async () => {
    const many: Record<string, any> = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`k${i}`, { tenantId: "t" + i }]));
    let n = 0;
    const d = createTenantDeriver(schema, { tenantFrom: { Mensagem: { via: "conversaId", model: "Conversa" } }, cacheSize: 5, client: () => ({ conversa: { findUnique: async ({ where }: any) => (n++, many[where.id]) } }) });
    for (let i = 0; i < 20; i++) await d("Mensagem", "Mensagem", { where: { conversaId: `k${i}` } });
    assert.equal(n, 20);
    await d("Mensagem", "Mensagem", { where: { conversaId: "k0" } }); // evicted: looked up again
    assert.equal(n, 21);
    await d("Mensagem", "Mensagem", { where: { conversaId: "k19" } }); // still cached
    assert.equal(n, 21);
  });
});

describe("cryplusTenantMiddleware", () => {
  it("sets the tenant for the request, async getters work, nothing leaks out", async () => {
    const seen: (string | undefined)[] = [];
    await new Promise<void>((done) =>
      cryplusTenantMiddleware<any>(async (r) => r.t)({ t: "T" }, {}, async () => {
        seen.push(currentTenant());
        await new Promise((r) => setTimeout(r, 5));
        seen.push(currentTenant());
        done();
      }),
    );
    assert.deepEqual(seen, ["T", "T"]);
    assert.equal(currentTenant(), undefined);
    await new Promise<void>((done) => cryplusTenantMiddleware<any>(() => undefined)({}, {}, () => (assert.equal(currentTenant(), undefined), done())));
    const err = await new Promise<any>((done) => cryplusTenantMiddleware<any>(() => { throw new Error("boom"); })({}, {}, done));
    assert.equal(err.message, "boom");
  });
});
