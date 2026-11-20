// Generated equivalence test: every filter shape that can be written against an encrypted `searchable` field must select
// exactly the rows the SAME filter selects on a plaintext twin column (the oracle).
// {equals, in, not, notIn, null, undefined} x {top level, NOT, NOT[], AND, AND[NOT], OR, NOT[OR], NOT[AND], relation some/none/every/NOT}.
// Needs the isolated Postgres from ../prisma-demo (`node pg.ts`).
const assert = require("node:assert/strict");
const path = require("node:path");
const { after, before, describe, it } = require("node:test");
const { PrismaClient } = require("@prisma/client");
const { Cryplus, withCryplus, withTenant } = require("cryplus");

const DB = "postgresql://cryplus:cryplus@127.0.0.1:54329/cryplus_demo?schema=p5";
const SCHEMA_PATH = path.join(__dirname, "prisma/schema.prisma");
const T = "oracle-tenant";
let db, raw;

// plaintext values of the oracle rows (null and "" included on purpose)
const ROWS = { a: "X", b: "Y", c: null, d: "X", e: "", f: "Z" };
const PARENTS = { p1: ["a", "b"], p2: ["c", "d"], p3: ["e"], p4: [], p5: ["a", "f", "c"] };

// leaf conditions: [label, builder(field) -> value for that field]
const LEAVES = [
  ["value", () => "X"],
  ["equals", () => ({ equals: "X" })],
  ["equals-null", () => ({ equals: null })],
  ["null", () => null],
  ["in", () => ({ in: ["X", "Y"] })],
  ["in-one", () => ({ in: ["X"] })],
  ["in-empty", () => ({ in: [] })],
  ["not", () => ({ not: "X" })],
  ["not-null", () => ({ not: null })],
  ["notIn", () => ({ notIn: ["X"] })],
  ["notIn-two", () => ({ notIn: ["X", "Y"] })],
  ["notIn-empty", () => ({ notIn: [] })],
  ["absent-value", () => "NOPE"],
  ["not-absent", () => ({ not: "NOPE" })],
  ["empty-string", () => ""],
  ["not-empty-string", () => ({ not: "" })],
  ["undefined", () => undefined],
  ["equals-undefined", () => ({ equals: undefined })],
  ["in-undefined", () => ({ in: undefined })],
  ["and-ops", () => ({ not: "X", in: ["Y", "Z"] })],
];

// positions: wrap a leaf filter object (already keyed by the field) into a where clause
const POSITIONS = [
  ["top", (f) => f],
  ["NOT", (f) => ({ NOT: f })],
  ["NOT[]", (f) => ({ NOT: [f] })],
  ["AND", (f) => ({ AND: f })],
  ["AND[]", (f) => ({ AND: [f] })],
  ["AND[NOT]", (f) => ({ AND: [{ NOT: f }] })],
  ["OR", (f) => ({ OR: [f, { id: "no-such-id" }] })],
  ["OR[NOT]", (f) => ({ OR: [{ NOT: f }, { id: "no-such-id" }] })],
  ["NOT[OR]", (f) => ({ NOT: { OR: [f, { id: "no-such-id" }] } })],
  ["NOT[AND]", (f) => ({ NOT: { AND: [f, { tenantId: T }] } })],
  ["NOT[NOT]", (f) => ({ NOT: { NOT: f } })],
  ["undefined-sibling", (f) => ({ ...f, grpX: undefined, AND: [undefined, f] })],
];

const ids = (rows) => rows.map((r) => r.id).sort().join(",");

before(async () => {
  raw = new PrismaClient({ datasources: { db: { url: DB } } });
  db = withCryplus(new PrismaClient({ datasources: { db: { url: DB } } }), { cryplus: Cryplus.inMemory(), schemaPath: SCHEMA_PATH });
  await raw.oraculo.deleteMany({ where: { tenantId: T } });
  await raw.oraculoPai.deleteMany({ where: { tenantId: T } });
  await withTenant(T, async () => {
    for (const [p, kids] of Object.entries(PARENTS)) {
      await db.oraculoPai.create({ data: { id: p, tenantId: T } });
      for (const k of kids) await db.oraculo.create({ data: { id: `${p}-${k}`, tenantId: T, paiId: p, plain: ROWS[k], enc: ROWS[k] } });
    }
    // rows that belong to no parent
    for (const k of Object.keys(ROWS)) await db.oraculo.create({ data: { id: `solo-${k}`, tenantId: T, plain: ROWS[k], enc: ROWS[k] } });
  });
});
after(async () => {
  await raw?.oraculo.deleteMany({ where: { tenantId: T } });
  await raw?.oraculoPai.deleteMany({ where: { tenantId: T } });
  await raw?.$disconnect();
  await db?.$disconnect();
});

describe("encrypted filters select the same rows as the plaintext column", () => {
  it("the fixture really stores ciphertext and keeps the plaintext twin", async () => {
    const r = await raw.oraculo.findUniqueOrThrow({ where: { id: "solo-a" } });
    assert.match(r.enc, /^cp1\./);
    assert.equal(r.plain, "X");
    assert.ok(r.encIdx);
    assert.equal((await raw.oraculo.findUniqueOrThrow({ where: { id: "solo-c" } })).encIdx, null);
  });

  for (const [pname, wrap] of POSITIONS) {
    it(`Oraculo.findMany, position ${pname}: all ${LEAVES.length} leaf filters`, async () => {
      let compared = 0;
      await withTenant(T, async () => {
        for (const [lname, leaf] of LEAVES) {
          // `top` with an object like { AND: ... } built from a bare field filter
          const mk = (field) => wrap({ [field]: leaf() });
          const want = ids(await db.oraculo.findMany({ where: { tenantId: T, ...mk("plain") } }));
          const got = ids(await db.oraculo.findMany({ where: { tenantId: T, ...mk("enc") } }));
          assert.equal(got, want, `position ${pname}, filter ${lname}`);
          compared++;
        }
      });
      assert.equal(compared, LEAVES.length);
    });

    it(`Oraculo.count / findFirst, position ${pname}`, async () => {
      await withTenant(T, async () => {
        for (const [lname, leaf] of LEAVES) {
          const mk = (field) => ({ tenantId: T, ...wrap({ [field]: leaf() }) });
          assert.equal(await db.oraculo.count({ where: mk("enc") }), await db.oraculo.count({ where: mk("plain") }), `count, ${pname}, ${lname}`);
        }
      });
    });
  }

  for (const rel of ["some", "none", "every"]) {
    for (const [pname, wrap] of POSITIONS) {
      it(`relation ${rel}, position ${pname} inside it, and ${rel} wrapped in NOT`, async () => {
        await withTenant(T, async () => {
          for (const [lname, leaf] of LEAVES) {
            const q = (field, negate) => {
              const where = { tenantId: T, filhos: { [rel]: wrap({ [field]: leaf() }) } };
              return negate ? { tenantId: T, NOT: where } : where;
            };
            for (const negate of [false, true]) {
              const want = ids(await db.oraculoPai.findMany({ where: q("plain", negate) }));
              const got = ids(await db.oraculoPai.findMany({ where: q("enc", negate) }));
              assert.equal(got, want, `${rel}${negate ? " (negated)" : ""}, ${pname}, ${lname}`);
            }
          }
        });
      });
    }
  }

  it("child-side relation filter: rows whose parent has a matching child", async () => {
    await withTenant(T, async () => {
      for (const [lname, leaf] of LEAVES) {
        const q = (field) => ({ tenantId: T, pai: { is: { filhos: { some: { [field]: leaf() } } } } });
        assert.equal(ids(await db.oraculo.findMany({ where: q("enc") })), ids(await db.oraculo.findMany({ where: q("plain") })), lname);
      }
    });
  });

  it("include with a nested filter and _count with a filter agree with the oracle", async () => {
    await withTenant(T, async () => {
      for (const [lname, leaf] of LEAVES) {
        const inc = (field) => ({ filhos: { where: { [field]: leaf() }, orderBy: { id: "asc" } }, _count: { select: { filhos: { where: { [field]: leaf() } } } } });
        const a = await db.oraculoPai.findMany({ where: { tenantId: T }, include: inc("enc"), orderBy: { id: "asc" } });
        const b = await db.oraculoPai.findMany({ where: { tenantId: T }, include: inc("plain"), orderBy: { id: "asc" } });
        assert.deepEqual(a.map((p) => [p.id, p.filhos.map((k) => k.id), p._count.filhos]), b.map((p) => [p.id, p.filhos.map((k) => k.id), p._count.filhos]), lname);
      }
    });
  });

  it("updateMany / deleteMany with a negated encrypted filter touch exactly the oracle's rows", async () => {
    await withTenant(T, async () => {
      for (const [lname, leaf] of LEAVES) {
        const where = (field) => ({ tenantId: T, paiId: "p5", NOT: { [field]: leaf() } });
        const want = await db.oraculo.count({ where: where("plain") });
        const hit = await db.oraculo.updateMany({ where: where("enc"), data: { paiId: "p5" } }); // no-op write: counts matches
        assert.equal(hit.count, want, lname);
      }
    });
  });

  it("FAILS CLOSED: a filter on an encrypted column that was not rewritten never reaches the database", async () => {
    const { Transformer } = require("../../sdk/node/dist/cjs/prisma.js");
    const { parseSchema } = require("cryplus");
    const schema = parseSchema(require("node:fs").readFileSync(SCHEMA_PATH, "utf8"));
    const x = new Transformer(Cryplus.inMemory(), schema, async () => T, { plaintext: "allow", hideIndexFields: true });
    const m = schema.get("Oraculo");
    assert.throws(() => x.assertRewritten(m, { enc: "X" }), /not rewritten/);
    assert.throws(() => x.assertRewritten(m, { NOT: { enc: { in: ["X"] } } }), /not rewritten/);
    assert.throws(() => x.assertRewritten(m, { AND: [{ NOT: [{ enc: { notIn: ["X"] } }] }] }), /not rewritten/);
    assert.throws(() => x.assertRewritten(schema.get("OraculoPai"), { filhos: { some: { NOT: { enc: "X" } } } }), /not rewritten/);
    x.assertRewritten(m, { encIdx: "bi1.x", enc: null, NOT: { enc: null } }); // legitimate leftovers pass
    // and every shape the rewriter produces passes the check (that is what the loop above exercises through db.*)
    for (const [, wrap] of POSITIONS) for (const [, leaf] of LEAVES) x.assertRewritten(m, await x.where(m, wrap({ enc: leaf() })));
  });

  it("unsupported operators on an encrypted field throw, they are never passed through", async () => {
    await withTenant(T, async () => {
      for (const op of [{ contains: "X" }, { startsWith: "X" }, { gt: "A" }, { lte: "Z" }, { mode: "insensitive" }, { search: "X" }]) {
        await assert.rejects(db.oraculo.findMany({ where: { tenantId: T, enc: op } }), /not supported|cannot/, JSON.stringify(op));
        await assert.rejects(db.oraculo.findMany({ where: { tenantId: T, NOT: { enc: op } } }), /not supported|cannot/, "NOT " + JSON.stringify(op));
      }
      await assert.rejects(db.oraculo.findMany({ where: { tenantId: T }, orderBy: { enc: "asc" } }), /cannot order/);
      await assert.rejects(db.oraculoPai.findMany({ where: { tenantId: T }, orderBy: { filhos: { _count: "asc" } }, include: { filhos: { orderBy: { enc: "asc" } } } }), /cannot order/);
      await assert.rejects(db.oraculo.findMany({ where: { tenantId: T }, orderBy: { pai: { id: "asc" } }, distinct: ["enc"] }), /distinct/);
    });
  });
});
