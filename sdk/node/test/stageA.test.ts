import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { after, before, describe, it } from "node:test";
import {
  analyzeSql,
  applyNormalizers,
  brPhoneCanonical,
  checkSchema,
  ciphertextLength,
  Cryplus,
  createCryplus,
  cryplusExtension,
  fold,
  INDEX_TEXT_LENGTH,
  parseSchema,
  SchemaError,
  withTenant,
} from "../src/index.ts";
import { startCore, type Core } from "./harness.ts";

const collect = async (r: Readable) => {
  const out: Buffer[] = [];
  for await (const c of r) out.push(c as Buffer);
  return Buffer.concat(out);
};

describe("ciphertext length formula", () => {
  let core: Core;
  let aesCore: Core;
  before(async () => {
    core = await startCore();
    aesCore = await startCore({}, { args: ["--alg", "aes256gcm"] });
  });
  after(async () => {
    await core.stop();
    await aesCore.stop();
  });

  it("matches the REAL service byte for byte (xchacha20 and aes256gcm), and the blind index length", async () => {
    for (const [c, alg] of [[core, "xchacha20"], [aesCore, "aes256gcm"]] as const) {
      const cp = new Cryplus({ url: c.url, token: c.token });
      for (const s of ["", "1", "123.456.789-00", "ação ✓ 日本語", "x".repeat(1000)]) {
        const ct = await cp.encrypt({ tenant: "t" }, s);
        assert.equal(ct.length, ciphertextLength(Buffer.byteLength(s), alg), `${alg}: ${JSON.stringify(s.slice(0, 10))}`);
      }
      assert.equal((await cp.blindIndex({ tenant: "t", collection: "c", field: "f" }, "v")).length, INDEX_TEXT_LENGTH);
      cp.close();
    }
  });

  it("a 14-character CPF needs 183 characters, so VarChar(14) can never hold it", () => {
    assert.equal(ciphertextLength(14), 183);
  });
});

describe("schema preflight", () => {
  const SCHEMA = `
model Funcionario {
  id    String  @id
  cpf   String? @db.VarChar(14) /// @encrypted
  rg    String? @map("rg_num") @db.VarChar(20) /// @encrypted(max(12))
  ok    String? @db.VarChar(300) /// @encrypted(max(14))
  nome  String  @db.VarChar(100)
  @@map("funcionarios")
}
model Cliente {
  id        String  @id
  cpfCnpj   String? @map("cpf_cnpj") /// @encrypted(searchable)
  cpfCnpjIdx String? @map("cpf_cnpj_idx") @db.VarChar(30)
  @@map("clientes")
}
`;
  it("refuses @encrypted on short VarChar and prints the exact ALTER TABLE with the real database names", () => {
    const { problems } = checkSchema(SCHEMA);
    const byField = Object.fromEntries(problems.map((p) => [`${p.model}.${p.field}`, p]));
    assert.match(byField["Funcionario.cpf"]!.fix!, /ALTER TABLE "funcionarios" ALTER COLUMN "cpf" TYPE text;/);
    assert.match(byField["Funcionario.rg"]!.fix!, /ALTER TABLE "funcionarios" ALTER COLUMN "rg_num" TYPE text;/);
    assert.match(byField["Funcionario.cpf"]!.message, /needs 2\d\d/);
    // a VarChar big enough for the declared max is fine
    assert.equal(byField["Funcionario.ok"], undefined);
    // the blind-index column has its own minimum
    assert.match(byField["Cliente.cpfCnpjIdx"]!.fix!, /ALTER TABLE "clientes" ALTER COLUMN "cpf_cnpj_idx" TYPE text;/);
    assert.equal(problems.length, 3);
  });

  it("parseSchema throws one SchemaError listing every problem", () => {
    assert.throws(
      () => parseSchema(SCHEMA),
      (e: any) => e instanceof SchemaError && e.problems.length === 3 && /run first: ALTER TABLE/.test(e.message),
    );
  });

  it("explains unsupported types with a workaround", () => {
    const { problems } = checkSchema("model P {\n id String @id\n nasc DateTime? @db.Date /// @encrypted\n n Int /// @encrypted\n}");
    assert.match(problems[0]!.message, /DateTime column cannot hold ciphertext.*String column/);
    assert.match(problems[1]!.message, /does not support type Int/);
  });

  it("records @map / @@map names", () => {
    const { schema } = checkSchema(SCHEMA.replace("@db.VarChar(14)", "").replace("@db.VarChar(20)", "").replace("@db.VarChar(30)", ""));
    assert.equal(schema.get("Funcionario")!.dbTable, "funcionarios");
    assert.equal(schema.get("Funcionario")!.encrypted.get("rg")!.dbName, "rg_num");
    assert.equal(schema.get("Cliente")!.encrypted.get("cpfCnpj")!.dbName, "cpf_cnpj");
  });
});

describe("normalizers", () => {
  it("br-phone-canonical makes the usual spellings of one number equal", () => {
    const same = ["(11) 91234-5678", "11912345678", "+55 11 91234-5678", "5511912345678", "11 1234-5678", "(11) 1234-5678", "551112345678"];
    for (const s of same) assert.equal(brPhoneCanonical(s), "1112345678", s);
    assert.equal(brPhoneCanonical("0800 123 456"), "0800123456");
    assert.equal(brPhoneCanonical("12345"), "12345");
    assert.equal(brPhoneCanonical("(11) 81234-5678"), "11812345678", "an 11-digit number whose subscriber part does not start with 9 is left alone");
  });
  it("fold lowercases and strips accents", () => {
    assert.equal(fold("João Çaña ÀÉÍÓÚ ü"), "joao cana aeiou u");
  });
  it("email-lower and trim", () => {
    assert.equal(applyNormalizers("  Ana.Silva+X@Example.COM ", ["email-lower"]), "ana.silva+x@example.com");
  });
});

const SEARCH_SCHEMA = `
model Contato {
  id        String  @id
  tenantId  String
  telefone  String? /// @encrypted(searchable, suffix(4), suffix(8), br-phone-canonical)
  telefoneIdx  String?
  telefoneSfx4 String?
  telefoneSfx8 String?
  email     String? /// @encrypted(global, email-lower)
  emailGIdx String?
  docs      String[] /// @encrypted
  config    Json?    /// @encrypted
}
`;

describe("search options and extra types (in-memory client, mocked query)", () => {
  const cp = Cryplus.inMemory();
  const ext = cryplusExtension({ cryplus: cp, schemaText: SEARCH_SCHEMA }).query.$allModels.$allOperations as any;
  const seen: any[] = [];
  const call = (operation: string, args: any, result: any = null) =>
    ext({ model: "Contato", operation, args, query: async (a: any) => (seen.push(a), typeof result === "function" ? result(a) : result) });
  const last = () => seen[seen.length - 1];

  it("writes equality, suffix and global indexes; suffix is null when the value is too short", async () => {
    await withTenant("acme", () => call("create", { data: { tenantId: "acme", telefone: "(11) 91234-5678", email: " Ana@X.com " } }));
    const d = last().data;
    assert.match(d.telefone, /^cp1\./);
    for (const k of ["telefoneIdx", "telefoneSfx4", "telefoneSfx8", "emailGIdx"]) assert.match(d[k], /^bi1\./, k);
    await withTenant("acme", () => call("create", { data: { tenantId: "acme", telefone: "123" } }));
    assert.equal(last().data.telefoneSfx4, null);
    assert.equal(last().data.telefoneSfx8, null);
    assert.match(last().data.telefoneIdx, /^bi1\./);
  });

  it("endsWith uses the suffix index and spelling does not matter", async () => {
    await withTenant("acme", async () => {
      await call("create", { data: { tenantId: "acme", telefone: "(11) 91234-5678" } });
      const stored = last().data;
      await call("findMany", { where: { telefone: { endsWith: "-5678" } } });
      assert.equal(last().where.telefoneSfx4, stored.telefoneSfx4);
      await call("findMany", { where: { telefone: { endsWith: "1234-5678" } } });
      assert.equal(last().where.telefoneSfx8, stored.telefoneSfx8);
      // equality goes through the canonical form as well
      await call("findFirst", { where: { telefone: "+55 11 1234-5678" } });
      assert.equal(last().where.telefoneIdx, stored.telefoneIdx);
      // other operators are refused, never answered wrongly
      await assert.rejects(call("findMany", { where: { telefone: { endsWith: "678" } } }), /exactly one of the indexed lengths \[4, 8\]/);
      await assert.rejects(call("findMany", { where: { telefone: { endsWith: "345678" } } }), /exactly one of the indexed lengths/);
      await assert.rejects(call("findMany", { where: { telefone: { contains: "1234" } } }), /not supported/);
    });
  });

  it("suffix indexes are per tenant", async () => {
    let a = "", b = "";
    await withTenant("acme", async () => { await call("create", { data: { tenantId: "x", telefone: "11912345678" } }); a = last().data.telefoneSfx8; });
    await withTenant("other", async () => { await call("create", { data: { tenantId: "x", telefone: "11912345678" } }); b = last().data.telefoneSfx8; });
    assert.notEqual(a, b);
  });

  it("global index: same value, same index in every tenant (and the equality index still differs)", async () => {
    let ga = "", gb = "", ea = "", eb = "";
    await withTenant("acme", async () => { await call("create", { data: { tenantId: "x", telefone: "1", email: "ana@x.com" } }); ga = last().data.emailGIdx; ea = last().data.telefoneIdx; });
    await withTenant("other", async () => { await call("create", { data: { tenantId: "x", telefone: "1", email: "ANA@x.com" } }); gb = last().data.emailGIdx; eb = last().data.telefoneIdx; });
    assert.equal(ga, gb);
    assert.notEqual(ea, eb);
  });

  it("a global-only field is searchable WITHOUT any tenant context (lookup before the tenant is known)", async () => {
    // no withTenant here on purpose
    await call("findFirst", { where: { email: "Ana@X.com" }, select: { id: true, tenantId: true } });
    const w = last().where;
    assert.equal(w.email, undefined);
    assert.match(w.emailGIdx, /^bi1\./);
    // ...but reading the decrypted email itself still needs the tenant and fails closed without it
    const ct = await cp.encrypt({ tenant: "acme", collection: "Contato", field: "email" }, "ana@x.com");
    await assert.rejects(call("findFirst", { where: { email: "ana@x.com" } }, { id: "1", email: ct }), /no tenant/);
  });

  it("String[] and Json round-trip and are stored encrypted", async () => {
    await withTenant("acme", async () => {
      await call("create", { data: { tenantId: "acme", docs: ["https://a/1.pdf", "https://a/2.pdf"], config: { tema: "escuro", n: [1, 2] } } });
      const d = last().data;
      assert.ok(d.docs.every((x: string) => /^cp1\./.test(x)));
      assert.match(d.config, /^cp1\./);
      assert.equal(JSON.stringify(d).includes("a/1.pdf"), false);
      const rows = await call("findMany", {}, [{ id: "1", docs: d.docs, config: d.config }]);
      assert.deepEqual(rows[0].docs, ["https://a/1.pdf", "https://a/2.pdf"]);
      assert.deepEqual(rows[0].config, { tema: "escuro", n: [1, 2] });

      await call("update", { where: { id: "1" }, data: { docs: { push: "https://a/3.pdf" } } });
      assert.match(last().data.docs.push[0], /^cp1\./);
      await call("update", { where: { id: "1" }, data: { docs: { set: ["x"] } } });
      assert.match(last().data.docs.set[0], /^cp1\./);
      await call("update", { where: { id: "1" }, data: { config: null } });
      assert.equal(last().data.config, null);

      await assert.rejects(call("findMany", { where: { docs: { has: "x" } } }), /cannot filter/);
      await call("findMany", { where: { docs: { isEmpty: true } } });
      assert.deepEqual(last().where.docs, { isEmpty: true });
      await assert.rejects(call("create", { data: { tenantId: "acme", docs: [1] } }), /arrays of strings/);
    });
  });

  it("aggregate / groupBy / distinct on encrypted fields throw", async () => {
    await withTenant("acme", async () => {
      await assert.rejects(call("aggregate", { _min: { telefone: true } }), /cannot aggregate/);
      await assert.rejects(call("groupBy", { by: ["telefone"], _count: true }), /cannot groupBy/);
      await assert.rejects(call("findMany", { distinct: ["telefone"] }), /distinct/);
      await call("aggregate", { _count: { _all: true } }, { _count: { _all: 3 } }); // harmless aggregates still work
    });
  });
});

describe("in-memory client", () => {
  const ctx = { tenant: "acme", collection: "User", field: "cpf" };

  it("same API: round trip, tenant isolation, context binding, tampering, blind index", async () => {
    const m = Cryplus.inMemory();
    const ct = await m.encrypt(ctx, "123.456.789-00");
    assert.match(ct, /^cp1\./);
    assert.equal(await m.decrypt(ctx, ct), "123.456.789-00");
    for (const bad of [{ ...ctx, tenant: "evil" }, { ...ctx, field: "rg" }, { ...ctx, recordId: "9" }]) {
      await assert.rejects(m.decrypt(bad, ct), (e: any) => e.code === "decryption_failed");
    }
    const raw = Buffer.from(ct.slice(4), "base64url");
    raw[raw.length - 3] = raw[raw.length - 3]! ^ 1;
    await assert.rejects(m.decrypt(ctx, "cp1." + raw.toString("base64url")), (e: any) => e.code === "decryption_failed");
    await assert.rejects(m.decrypt(ctx, "cp1.garbage"), (e: any) => e.code === "malformed_ciphertext");
    await assert.rejects(m.encrypt({ tenant: "" }, "x"), (e: any) => e.code === "tenant_required");
    const a = await m.blindIndex(ctx, "1");
    assert.equal(a, await m.blindIndex(ctx, "1"));
    assert.notEqual(a, await m.blindIndex({ ...ctx, tenant: "o" }, "1"));
  });

  it("same ciphertext LENGTH as the real service, so column-size bugs show up in tests", async () => {
    const m = Cryplus.inMemory();
    for (const s of ["", "123.456.789-00", "ação ✓ 日本語", "x".repeat(500)]) {
      assert.equal((await m.encrypt(ctx, s)).length, ciphertextLength(Buffer.byteLength(s)));
    }
    assert.equal((await m.blindIndex(ctx, "v")).length, INDEX_TEXT_LENGTH);
  });

  it("rotation and rewrap keep data readable", async () => {
    const m = Cryplus.inMemory();
    const ct = await m.encrypt(ctx, "keep");
    assert.equal(await m.rotateKeys(), 2);
    assert.equal(await m.decrypt(ctx, ct), "keep");
    const r = await m.rewrap(ctx, ct);
    assert.equal(r.changed, true);
    assert.equal(await m.decrypt(ctx, r.ciphertext), "keep");
    assert.equal((await m.rewrap(ctx, r.ciphertext)).changed, false);
    assert.equal((await m.keys()).current, 2);
  });

  it("is repeatable: same seed gives the same blind indexes; deterministic mode gives the same ciphertext", async () => {
    const a = Cryplus.inMemory({ seed: "s" }), b = Cryplus.inMemory({ seed: "s" });
    assert.equal(await a.blindIndex(ctx, "x"), await b.blindIndex(ctx, "x"));
    const d1 = Cryplus.inMemory({ seed: "s", deterministic: true }), d2 = Cryplus.inMemory({ seed: "s", deterministic: true });
    assert.equal(await d1.encrypt(ctx, "x"), await d2.encrypt(ctx, "x"));
    assert.equal(await d2.decrypt(ctx, await d1.encrypt(ctx, "x")), "x");
    const r1 = Cryplus.inMemory(), r2 = Cryplus.inMemory();
    assert.notEqual(await r1.encrypt(ctx, "x"), await r1.encrypt(ctx, "x"), "default mode must stay randomized");
    assert.equal(await r2.decrypt(ctx, await r1.encrypt(ctx, "y")), "y", "same default seed: two instances interoperate");
  });

  it("streams: round trip, tamper, truncation, wrong tenant", async () => {
    const m = Cryplus.inMemory();
    const data = Buffer.alloc(300_000, 7);
    for (const n of [0, 1, 65535, 65536, 65537, 300_000]) {
      const src = data.subarray(0, n);
      const enc = await collect(await m.encryptStream(ctx, Readable.from([src])));
      assert.ok((await collect(await m.decryptStream(ctx, Readable.from([enc])))).equals(src), `size ${n}`);
    }
    const enc = await collect(await m.encryptStream(ctx, Readable.from([data])));
    const bad = Buffer.from(enc);
    bad[bad.length - 20] = bad[bad.length - 20]! ^ 1;
    await assert.rejects(async () => collect(await m.decryptStream(ctx, Readable.from([bad]))));
    await assert.rejects(async () => collect(await m.decryptStream(ctx, Readable.from([enc.subarray(0, 70_000)]))));
    await assert.rejects(async () => collect(await m.decryptStream({ ...ctx, tenant: "evil" }, Readable.from([enc]))));
  });

  it("refuses to run in production, and createCryplus honours CRYPLUS_MODE=memory", () => {
    const saved = { ...process.env };
    try {
      process.env.NODE_ENV = "production";
      assert.throws(() => Cryplus.inMemory(), /tests only/);
      process.env.CRYPLUS_MODE = "memory";
      assert.throws(() => createCryplus(), /tests only/);
      process.env.NODE_ENV = "test";
      const c = createCryplus();
      assert.equal(c.constructor.name, "InMemoryCryplus");
      delete process.env.CRYPLUS_MODE;
      assert.throws(() => createCryplus({ token: undefined }), /token required/);
    } finally {
      process.env.NODE_ENV = saved.NODE_ENV;
      if (saved.CRYPLUS_MODE === undefined) delete process.env.CRYPLUS_MODE;
      else process.env.CRYPLUS_MODE = saved.CRYPLUS_MODE;
    }
  });
});

describe("raw-SQL helpers and analyzer", () => {
  const SCHEMA = `
model Webhook {
  id      String @id
  tenantId String @map("tenant_id")
  secret  String? /// @encrypted
  url     String
  @@map("webhooks")
}
model Funcionario {
  id    String @id
  cpf   String? @map("cpf_num") /// @encrypted(searchable, digits)
  cpfIdx String? @map("cpf_idx")
  @@map("funcionarios")
}
model Mensagem {
  id String @id
  conversaId String
  conteudo String? /// @encrypted
}
`;
  const cp = Cryplus.inMemory();
  const prismaLike = cryplusExtension({ cryplus: cp, schemaText: SCHEMA });
  const h = (prismaLike.client as any).$cryplus;

  it("rows(): decrypts encrypted columns of a raw SELECT, including aliases, in batch", async () => {
    await withTenant("acme", async () => {
      const stored = await h.encryptValue("Webhook", "secret", "whsec_123");
      const rows = [{ id: "1", url: "u", secret: stored }, { id: "2", url: "v", whsec: await h.encryptValue("Webhook", "secret", "whsec_456") }, { id: "3", secret: null }];
      await h.decryptRows("Webhook", rows, { columns: { whsec: "secret" } });
      assert.equal(rows[0]!.secret, "whsec_123");
      assert.equal((rows[1] as any).whsec, "whsec_456");
      assert.equal(rows[2]!.secret, null);
      assert.equal(rows[0]!.url, "u");
    });
    // wrong tenant fails closed
    await withTenant("evil", async () => {
      const stored = await h.encryptValue("Webhook", "secret", "x");
      await withTenant("acme", async () => {
        await assert.rejects(h.decryptRows("Webhook", [{ secret: stored }]), /decryption_failed/);
      });
    });
  });

  it("index()/indexColumns()/encryptValue() give values usable in raw WHERE / INSERT, matching what the extension writes", async () => {
    await withTenant("acme", async () => {
      const idx = await h.index("Funcionario", "cpf", "123.456.789-00");
      const viaExt: any[] = [];
      const ext = prismaLike.query.$allModels.$allOperations as any;
      await ext({ model: "Funcionario", operation: "create", args: { data: { cpf: "12345678900" } }, query: async (a: any) => (viaExt.push(a), null) });
      assert.equal(idx, viaExt[0].data.cpfIdx);
      assert.deepEqual(Object.keys(await h.indexColumns("Funcionario", "cpf", "1")), ["cpfIdx"]);
      assert.equal(await h.index("Funcionario", "cpf_num", "123.456.789-00"), idx, "lookup by database column name works too");
      assert.equal(await h.index("Funcionario", "cpf", "1", { tenant: "other" }) === idx, false);
      await assert.rejects(h.index("Webhook", "url", "x"), /not an @encrypted field/);
      await assert.rejects(h.index("Webhook", "secret", "x"), /not @encrypted\(searchable\)/);
    });
  });

  it("searchDecrypted: filters in memory across pages, refuses an unbounded scan", async () => {
    const rowsAll = Array.from({ length: 1234 }, (_, i) => ({ id: String(i).padStart(5, "0"), conteudo: i % 100 === 7 ? `pague o link https://pay/${i}` : `msg ${i}` }));
    let calls = 0;
    const delegate = {
      async findMany(a: any) {
        calls++;
        const start = a.cursor ? rowsAll.findIndex((r) => r.id === a.cursor.id) + 1 : 0;
        return rowsAll.filter((r) => r.id.startsWith("")).slice(start, start + a.take);
      },
    };
    const hits = await h.searchDecrypted(delegate, "Mensagem", { where: { conversaId: "c1" }, predicate: (r: any) => r.conteudo.includes("https://pay/"), limit: 100, pageSize: 200 });
    assert.equal(hits.length, 13);
    assert.ok(calls >= 6, `paged (${calls} calls)`);
    await assert.rejects(h.searchDecrypted(delegate, "Mensagem", { where: {}, predicate: () => true }), /non-empty `where`/);
    await assert.rejects(h.searchDecrypted(delegate, "Mensagem", { where: { conversaId: "c1" }, predicate: () => false, maxScan: 500, pageSize: 200 }), /scanned \d+ rows without finishing/);
    const few = await h.searchDecrypted(delegate, "Mensagem", { where: { conversaId: "c1" }, predicate: () => true, limit: 3 });
    assert.equal(few.length, 3);
  });

  it("analyzer: finds encrypted columns by their DATABASE names, @@map tables, star selects and column-less inserts", () => {
    const sch = parseSchema(SCHEMA);
    const f = (sql: string) => analyzeSql(sch, sql).map((x) => `${x.model}:${x.columns.join("|")}`);
    assert.deepEqual(f(`SELECT id, secret FROM webhooks WHERE tenant_id = $1`), ["Webhook:secret"]);
    assert.deepEqual(f(`select w.* from public."webhooks" w`), ["Webhook:*"]);
    assert.deepEqual(f(`SELECT * FROM funcionarios`), ["Funcionario:*"]);
    assert.deepEqual(f(`UPDATE "funcionarios" SET "cpf_num" = $1 WHERE id = $2`), ["Funcionario:cpf_num"]);
    assert.deepEqual(f(`INSERT INTO webhooks VALUES ($1,$2,$3,$4)`), ["Webhook:*"]);
    assert.deepEqual(f(`INSERT INTO webhooks (id, tenant_id, url) VALUES ($1,$2,$3)`), []);
    assert.deepEqual(f(`SELECT count(*) FROM webhooks WHERE tenant_id = $1`), []);
    assert.deepEqual(f(`SELECT id FROM funcionarios WHERE cpf_idx = $1`), [], "using the index column is the sanctioned way");
    assert.deepEqual(f(`SELECT conteudo FROM mensagens`), [], "a table name that is not in the schema is not guessed (Mensagem has no @@map)");
    assert.deepEqual(f(`SELECT conteudo FROM "Mensagem"`), ["Mensagem:conteudo"]);
    assert.deepEqual(f(`SELECT secret /* cryplus:handled */ FROM webhooks`), []);
    assert.deepEqual(f(`-- secret\nSELECT id FROM webhooks`), [], "comments are ignored");
    assert.deepEqual(f(`SELECT secrets_count FROM webhooks`), [], "word boundaries");
  });
});
