import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { Cryplus, cryplusExtension, currentTenant, parseSchema, withTenant } from "../src/index.ts";
import { startCore, type Core } from "./harness.ts";

const SCHEMA = `
datasource db { provider = "postgresql" }
generator client { provider = "prisma-client-js" }

enum Role {
  ADMIN
  USER
}

model User {
  id      String  @id @default(uuid())
  name    String
  email   String  @unique
  cpf     String? /// @encrypted(searchable, digits)
  cpfIdx  String? @unique
  /// @encrypted
  notes   String?
  phone   String? /// @encrypted(searchable)
  phoneIdx String?
  role    Role    @default(USER)
  cards   Card[]
  profile Profile?

  @@index([name])
}

model Card {
  id      String @id
  number  String /// @encrypted
  label   String
  user    User   @relation(fields: [userId], references: [id])
  userId  String
}

model Profile {
  id     String @id
  bio    String? /// @encrypted
  user   User   @relation(fields: [userId], references: [id])
  userId String @unique
}
`;

describe("schema parser", () => {
  const s = parseSchema(SCHEMA);
  it("finds models, ids, relations and ignores enums/datasource", () => {
    assert.deepEqual([...s.keys()].sort(), ["Card", "Profile", "User"]);
    assert.equal(s.get("User")!.idField, "id");
    assert.equal(s.get("User")!.fields.get("cards")!.relation, "Card");
    assert.equal(s.get("Card")!.fields.get("user")!.relation, "User");
  });
  it("reads trailing and leading /// directives with options", () => {
    const u = s.get("User")!;
    assert.deepEqual([...u.encrypted.keys()].sort(), ["cpf", "notes", "phone"]);
    assert.equal(u.encrypted.get("cpf")!.searchable, true);
    assert.deepEqual(u.encrypted.get("cpf")!.normalize, ["digits"]);
    assert.equal(u.encrypted.get("cpf")!.indexField, "cpfIdx");
    assert.equal(u.encrypted.get("notes")!.searchable, false);
    assert.ok(u.indexFields.has("cpfIdx") && u.indexFields.has("phoneIdx"));
  });
  it("rejects misconfiguration loudly", () => {
    assert.throws(() => parseSchema("model A {\n id Int @id\n n Int /// @encrypted\n}"), /not a plain String/);
    assert.throws(() => parseSchema("model A {\n id Int @id\n n String /// @encrypted(searchable)\n}"), /nIdx/);
    assert.throws(() => parseSchema("model A {\n id Int @id\n n String /// @encrypted(bogus)\n}"), /unknown @encrypted option/);
    assert.throws(() => parseSchema("model A {\n id Int @id\n n String /// @encrypted(lowercase)\n}"), /only apply to searchable/);
  });
});

describe("prisma extension (real core, mocked query)", () => {
  let core: Core;
  let cp: Cryplus;
  let hook: (a: any) => Promise<any>;
  const calls: { model: string; operation: string; args: any }[] = [];
  let reply: any = null;

  before(async () => {
    core = await startCore();
    cp = new Cryplus({ url: core.url, token: core.token });
    const ext = cryplusExtension({ cryplus: cp, schemaText: SCHEMA });
    hook = ext.query.$allModels.$allOperations as any;
  });
  after(() => core.stop());

  const run = (model: string, operation: string, args: any, result: any = null) =>
    hook({
      model,
      operation,
      args,
      query: async (a: any) => {
        calls.push({ model, operation, args: a });
        return typeof result === "function" ? result(a) : result;
      },
    });
  const last = () => calls[calls.length - 1]!.args;

  it("fails closed without a tenant", async () => {
    await assert.rejects(run("User", "create", { data: { name: "a", cpf: "1" } }), /no tenant/);
  });

  it("withTenant works with lazy thenables (Prisma promises run only when awaited)", async () => {
    let ranInTenant: string | undefined;
    const lazy = () => ({
      then(res: (v: any) => void, rej: (e: unknown) => void) {
        // like a PrismaPromise: executes at .then(), not at creation
        Promise.resolve().then(() => currentTenant()).then((t) => { ranInTenant = t; res("done"); }, rej);
      },
    });
    assert.equal(await withTenant("lazy-org", () => lazy() as any), "done");
    assert.equal(ranInTenant, "lazy-org");
    // and the scope does not leak out afterwards
    assert.equal(currentTenant(), undefined);
  });

  it("resolves the tenant per model: platform model + tenant-scoped nested model in one write", async () => {
    const ext = cryplusExtension({
      cryplus: cp,
      schemaText: SCHEMA,
      tenant: ({ model }) => (model === "Profile" ? "__platform__" : undefined),
    }).query.$allModels.$allOperations as any;
    const seen: any[] = [];
    const call = (model: string, operation: string, args: any, result: any = null) =>
      ext({ model, operation, args, query: async (a: any) => (seen.push(a), result) });
    await withTenant("acme", () =>
      call("User", "create", { data: { name: "n", notes: "secret", profile: { create: { id: "p", bio: "platform-scoped" } } } }),
    );
    const d = seen[0].data;
    // notes is under "acme", the nested Profile.bio under "__platform__": each decrypts only under its own tenant
    assert.equal(await cp.decrypt({ tenant: "acme", collection: "User", field: "notes" }, d.notes), "secret");
    assert.equal(await cp.decrypt({ tenant: "__platform__", collection: "Profile", field: "bio" }, d.profile.create.bio), "platform-scoped");
    await assert.rejects(cp.decrypt({ tenant: "acme", collection: "Profile", field: "bio" }, d.profile.create.bio), /decryption_failed/);
  });

  it("passes through models and calls that touch nothing encrypted... but still needs tenant only when needed", async () => {
    const r = await run("User", "findMany", { where: { name: "x" } }, [{ id: "1", name: "x", cpf: null }]);
    assert.equal(r[0].name, "x");
  });

  it("encrypts on create, stores a blind index, leaves other fields alone", async () => {
    await withTenant("acme", () => run("User", "create", { data: { name: "Ana", email: "a@x.io", cpf: "123.456.789-00", notes: "vip" } }));
    const d = last().data;
    assert.match(d.cpf, /^cp1\./);
    assert.match(d.notes, /^cp1\./);
    assert.match(d.cpfIdx, /^bi1\./);
    assert.equal(d.name, "Ana");
    assert.equal(d.phone, undefined);
    assert.equal(JSON.stringify(d).includes("123.456.789-00"), false);
  });

  it("normalizes before indexing so formatting does not matter", async () => {
    await withTenant("acme", async () => {
      await run("User", "create", { data: { name: "a", cpf: "123.456.789-00" } });
      const i1 = last().data.cpfIdx;
      await run("User", "create", { data: { name: "b", cpf: " 12345678900 " } });
      assert.equal(last().data.cpfIdx, i1);
    });
  });

  it("blind index differs per tenant", async () => {
    let a = "", b = "";
    await withTenant("acme", async () => { await run("User", "create", { data: { name: "a", cpf: "111" } }); a = last().data.cpfIdx; });
    await withTenant("other", async () => { await run("User", "create", { data: { name: "a", cpf: "111" } }); b = last().data.cpfIdx; });
    assert.notEqual(a, b);
  });

  it("rewrites where on a searchable field to the blind index", async () => {
    await withTenant("acme", async () => {
      await run("User", "findFirst", { where: { cpf: "123.456.789-00" } });
      const w = last().where;
      assert.equal(w.cpf, undefined);
      assert.match(w.cpfIdx, /^bi1\./);

      await run("User", "findMany", { where: { OR: [{ cpf: { equals: "111" } }, { cpf: { in: ["222", "333"] } }], name: "x" } });
      const o = last().where;
      assert.equal(o.name, "x");
      assert.match(o.OR[0].cpfIdx.equals, /^bi1\./);
      assert.equal(o.OR[1].cpfIdx.in.length, 2);

      await run("User", "findUnique", { where: { cpf: "123.456.789-00" } });
      assert.match(last().where.cpfIdx, /^bi1\./);
    });
  });

  it("refuses operations that would silently be wrong", async () => {
    await withTenant("acme", async () => {
      await assert.rejects(run("User", "findMany", { where: { notes: "x" } }), /searchable/);
      await assert.rejects(run("User", "findMany", { where: { cpf: { contains: "12" } } }), /not supported/);
      await assert.rejects(run("User", "findMany", { orderBy: { cpf: "asc" } }), /cannot order/);
      await assert.rejects(run("User", "findMany", { distinct: ["cpf"] }), /distinct/);
      await assert.rejects(run("User", "groupBy", { by: ["cpf"] }), /groupBy/);
      await assert.rejects(run("User", "create", { data: { name: "x", cpfIdx: "forged" } }), /managed automatically/);
      await assert.rejects(run("User", "create", { data: { name: "x", cpf: 12345 } }), /only accepts string/);
      await assert.rejects(run("User", "create", { data: { name: "x", cpf: "cp1.AAAA" } }), /already looks like ciphertext/);
    });
  });

  it("handles { set: } and null on update", async () => {
    await withTenant("acme", async () => {
      await run("User", "update", { where: { id: "1" }, data: { cpf: { set: "999" } } });
      assert.match(last().data.cpf.set, /^cp1\./);
      assert.match(last().data.cpfIdx, /^bi1\./);
      await run("User", "update", { where: { id: "1" }, data: { cpf: null } });
      assert.equal(last().data.cpf, null);
      assert.equal(last().data.cpfIdx, null);
    });
  });

  it("handles createMany and upsert", async () => {
    await withTenant("acme", async () => {
      await run("User", "createMany", { data: [{ name: "a", cpf: "1" }, { name: "b", cpf: "2" }] });
      assert.ok(last().data.every((d: any) => /^cp1\./.test(d.cpf)));
      await run("User", "upsert", { where: { email: "e" }, create: { name: "n", notes: "c" }, update: { notes: "u" } });
      assert.match(last().create.notes, /^cp1\./);
      assert.match(last().update.notes, /^cp1\./);
    });
  });

  it("encrypts nested relation writes", async () => {
    await withTenant("acme", async () => {
      await run("User", "create", {
        data: {
          name: "n",
          cards: { create: [{ id: "c1", label: "L", number: "4111111111111111" }], createMany: { data: [{ id: "c2", label: "M", number: "5500" }] } },
          profile: { create: { id: "p1", bio: "hello" } },
        },
      });
      const d = last().data;
      assert.match(d.cards.create[0].number, /^cp1\./);
      assert.equal(d.cards.create[0].label, "L");
      assert.match(d.cards.createMany.data[0].number, /^cp1\./);
      assert.match(d.profile.create.bio, /^cp1\./);

      await run("User", "update", {
        where: { id: "1" },
        data: { cards: { update: { where: { id: "c1" }, data: { number: "new" } } }, profile: { update: { bio: "bye" } } },
      });
      assert.match(last().data.cards.update.data.number, /^cp1\./);
      assert.match(last().data.profile.update.bio, /^cp1\./);
    });
  });

  it("rewrites filters through relations and inside include", async () => {
    await withTenant("acme", async () => {
      await run("Card", "findMany", { where: { user: { cpf: "123" } } });
      assert.match(last().where.user.cpfIdx, /^bi1\./);
      await run("Card", "findMany", { where: { user: { is: { cpf: "123" } } } });
      assert.match(last().where.user.is.cpfIdx, /^bi1\./);
      await run("User", "findMany", { include: { cards: { where: { number: "x" } } } }).catch((e) => assert.match(e.message, /searchable/));
    });
  });

  it("decrypts results, including nested relations, and hides index columns", async () => {
    let rows: any;
    await withTenant("acme", async () => {
      await run("User", "create", {
        data: { name: "Ana", cpf: "123", notes: "n", cards: { create: [{ id: "c1", label: "L", number: "4111" }] } },
      });
      const stored = last().data;
      rows = [
        {
          id: "1", name: "Ana", cpf: stored.cpf, cpfIdx: stored.cpfIdx, notes: stored.notes, phone: null,
          cards: [{ id: "c1", label: "L", number: stored.cards.create[0].number, user: undefined }],
        },
      ];
      const out = await run("User", "findMany", { include: { cards: true } }, rows);
      assert.equal(out[0].cpf, "123");
      assert.equal(out[0].notes, "n");
      assert.equal(out[0].cards[0].number, "4111");
      assert.equal("cpfIdx" in out[0], false);
      assert.equal(out[0].phone, null);
    });
  });

  it("will not decrypt under the wrong tenant", async () => {
    let ct = "";
    await withTenant("acme", async () => {
      await run("User", "create", { data: { name: "x", notes: "secret" } });
      ct = last().data.notes;
    });
    await withTenant("evil", async () => {
      await assert.rejects(run("User", "findFirst", {}, { id: "1", notes: ct }), /decryption_failed/);
    });
  });

  it("will not decrypt a value moved to another field", async () => {
    let ct = "";
    await withTenant("acme", async () => {
      await run("User", "create", { data: { name: "x", notes: "secret" } });
      ct = last().data.notes;
      // attacker with DB write access copies the notes ciphertext into phone
      await assert.rejects(run("User", "findFirst", {}, { id: "1", phone: ct }), /decryption_failed/);
    });
  });

  it("plaintext policy: allow (default) vs reject", async () => {
    await withTenant("acme", async () => {
      const out = await run("User", "findFirst", {}, { id: "1", notes: "legacy plaintext" });
      assert.equal(out.notes, "legacy plaintext");
    });
    const strict = cryplusExtension({ cryplus: cp, schemaText: SCHEMA, plaintext: "reject" }).query.$allModels.$allOperations as any;
    await withTenant("acme", async () => {
      await assert.rejects(
        strict({ model: "User", operation: "findFirst", args: {}, query: async () => ({ id: "1", notes: "legacy plaintext" }) }),
        /plaintext/,
      );
    });
  });

  it("count/aggregate results are not touched", async () => {
    const r = await withTenant("acme", () => run("User", "count", { where: { cpf: "1" } }, 7));
    assert.equal(r, 7);
  });
});
