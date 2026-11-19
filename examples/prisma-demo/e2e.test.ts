// End-to-end: real cryplus-core + real Prisma Client + real Postgres.
// Run `node pg.ts` (or npm run pg) in another terminal first, then `npm run e2e`.
import assert from "node:assert/strict";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { PrismaPg } from "@prisma/adapter-pg";
import { Cryplus, migrateModel, parseSchema, withCryplus, withTenant } from "cryplus";
import { readFileSync } from "node:fs";
import { PrismaClient } from "./generated/client.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const DB = process.env.DATABASE_URL ?? "postgresql://cryplus:cryplus@127.0.0.1:54329/cryplus_demo";
const BIN = path.resolve(here, "../../bin/cryplus-core.exe");
const SCHEMA_PATH = path.join(here, "prisma/schema.prisma");
const TOKEN = "e2e-token-0123456789abcdef";

let child: ChildProcess;
let tmp: string;
let cp: Cryplus;
let raw: PrismaClient; // no extension: sees exactly what an attacker with DB access sees
let db: PrismaClient; // with cryplus extension
const schema = parseSchema(readFileSync(SCHEMA_PATH, "utf8"));

async function freePort() {
  return new Promise<number>((res) => {
    const s = createServer().listen(0, "127.0.0.1", () => {
      const p = (s.address() as any).port;
      s.close(() => res(p));
    });
  });
}

before(async () => {
  tmp = mkdtempSync(path.join(tmpdir(), "cryplus-e2e-"));
  const port = await freePort();
  child = spawn(BIN, ["--listen", `127.0.0.1:${port}`, "--keyfile", path.join(tmp, "k.json"), "--audit-log", path.join(tmp, "audit.jsonl")], {
    env: { ...process.env, CRYPLUS_TOKEN: TOKEN, CRYPLUS_PASSPHRASE: "e2e passphrase for the key file" },
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

  // Create/update tables in the isolated, dedicated test database. Plain
  // `db push` only: nothing destructive, no force-reset.
  execFileSync(process.execPath, [path.join(here, "node_modules/prisma/build/index.js"), "db", "push"], {
    cwd: here,
    env: { ...process.env, DATABASE_URL: DB },
    stdio: "pipe",
  });

  raw = new PrismaClient({ adapter: new PrismaPg({ connectionString: DB }) });
  // start every run from empty tables (children first)
  await raw.card.deleteMany({});
  await raw.user.deleteMany({});
  await raw.organization.deleteMany({});
  db = withCryplus(new PrismaClient({ adapter: new PrismaPg({ connectionString: DB }) }), { cryplus: cp, schemaPath: SCHEMA_PATH });
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

const CPF = "123.456.789-00";
const CARD = "4111 1111 1111 1111";

describe("Prisma + Postgres end to end", () => {
  let orgA: string, orgB: string, userId: string;

  it("encrypts on write, decrypts on read, nested relations included", async () => {
    orgA = (await raw.organization.create({ data: { name: "A" } })).id;
    orgB = (await raw.organization.create({ data: { name: "B" } })).id;

    const u = await withTenant(orgA, () =>
      db.user.create({
        data: {
          name: "Ana",
          email: "ana@x.io",
          cpf: CPF,
          notes: "cliente VIP",
          organizationId: orgA,
          cards: { create: [{ label: "visa", number: CARD }] },
        },
        include: { cards: true },
      }),
    );
    userId = u.id;
    assert.equal(u.cpf, CPF);
    assert.equal(u.notes, "cliente VIP");
    assert.equal(u.cards[0]!.number, CARD);
    assert.equal("cpfIdx" in u, false, "index column must be hidden");
  });

  it("the database only ever holds ciphertext (attacker's view)", async () => {
    // Everything an attacker with a SQL dump would see, across ALL columns:
    const dump = await raw.$queryRawUnsafe<{ t: string }[]>(
      `SELECT t::text AS t FROM "User" t UNION ALL SELECT c::text FROM "Card" c`,
    );
    const all = dump.map((r) => r.t).join("\n");
    for (const secret of [CPF, "12345678900", "cliente VIP", CARD, "4111"]) {
      assert.equal(all.includes(secret), false, `plaintext leaked: ${secret}`);
    }
    assert.match(all, /cp1\./);
    assert.match(all, /bi1\./); // the blind index is there, and it is not the CPF
    const row = await raw.user.findUniqueOrThrow({ where: { id: userId } });
    assert.match(row.cpf!, /^cp1\./);
    assert.match(row.notes!, /^cp1\./);
  });

  it("searches by blind index regardless of CPF formatting", async () => {
    await withTenant(orgA, async () => {
      for (const variant of [CPF, "12345678900", " 123.456.789-00 "]) {
        const f = await db.user.findFirst({ where: { cpf: variant } });
        assert.equal(f?.id, userId, `variant ${JSON.stringify(variant)}`);
      }
      assert.equal((await db.user.findUnique({ where: { cpf: CPF } as any }))?.id, userId);
      assert.equal((await db.user.findMany({ where: { cpf: { in: [CPF, "000"] } } })).length, 1);
      assert.equal(await db.user.count({ where: { cpf: "99999999999" } }), 0);
      assert.equal(await db.user.count({ where: { NOT: { cpf: "99999999999" } } }), 1);
      // through a relation
      const card = await db.card.findFirst({ where: { user: { cpf: CPF } } });
      assert.equal(card?.number, CARD);
    });
  });

  it("refuses unsafe queries instead of returning wrong data", async () => {
    await withTenant(orgA, async () => {
      await assert.rejects(db.user.findMany({ where: { cpf: { contains: "123" } } }), /not supported/);
      await assert.rejects(db.user.findMany({ where: { notes: "x" } }), /searchable/);
      await assert.rejects(db.user.findMany({ orderBy: { cpf: "asc" } }), /cannot order/);
    });
  });

  it("update re-encrypts and re-indexes", async () => {
    await withTenant(orgA, async () => {
      await db.user.update({ where: { id: userId }, data: { cpf: { set: "987.654.321-00" } } });
      assert.equal(await db.user.count({ where: { cpf: CPF } }), 0, "old CPF must stop matching");
      assert.equal((await db.user.findFirst({ where: { cpf: "98765432100" } }))?.cpf, "987.654.321-00");
      await db.user.update({ where: { id: userId }, data: { cpf: CPF } });
    });
  });

  it("tenant isolation: another tenant cannot read these rows", async () => {
    await withTenant(orgB, async () => {
      await assert.rejects(db.user.findUnique({ where: { id: userId } }), /decryption_failed/);
      // and its blind index differs, so it cannot even *search* for the CPF
      assert.equal(await db.user.count({ where: { cpf: CPF } }), 0);
    });
  });

  it("no tenant, no access", async () => {
    await assert.rejects(db.user.findUnique({ where: { id: userId } }), /no tenant/);
  });

  it("tampering with a ciphertext in the database is detected", async () => {
    const row = await raw.user.findUniqueOrThrow({ where: { id: userId } });
    const orig = row.notes!;
    const flipped = orig.slice(0, -2) + (orig.endsWith("A") ? "BB" : "AA");
    await raw.user.update({ where: { id: userId }, data: { notes: flipped } });
    await withTenant(orgA, async () => {
      await assert.rejects(db.user.findUnique({ where: { id: userId } }), /decryption_failed/);
    });
    await raw.user.update({ where: { id: userId }, data: { notes: orig } });
    await withTenant(orgA, async () => assert.equal((await db.user.findUnique({ where: { id: userId } }))?.notes, "cliente VIP"));
  });

  it("works inside interactive transactions", async () => {
    await withTenant(orgA, async () => {
      const id = await db.$transaction(async (tx) => {
        const u = await tx.user.create({ data: { name: "Tx", email: "tx@x.io", cpf: "111.111.111-11", organizationId: orgA } });
        const back = await tx.user.findUniqueOrThrow({ where: { id: u.id } });
        assert.equal(back.cpf, "111.111.111-11");
        return u.id;
      });
      await db.user.delete({ where: { id } });
    });
  });

  it("concurrent tenants never see each other's context (AsyncLocalStorage)", async () => {
    const ids = await Promise.all(
      Array.from({ length: 20 }, (_, i) => {
        const org = i % 2 ? orgA : orgB;
        return withTenant(org, async () => {
          const u = await db.user.create({ data: { name: "c" + i, email: `c${i}@x.io`, cpf: `${i}00`.padStart(11, "0"), organizationId: org } });
          return { id: u.id, org };
        });
      }),
    );
    // each row must decrypt under ITS tenant and fail under the other
    const results = await Promise.all(
      ids.map(async ({ id, org }) => {
        const ok = await withTenant(org, () => db.user.findUnique({ where: { id } }));
        const other = org === orgA ? orgB : orgA;
        const bad = await withTenant(other, () => db.user.findUnique({ where: { id } })).then(
          () => "leaked",
          () => "refused",
        );
        return ok?.id === id && bad === "refused";
      }),
    );
    assert.ok(results.every(Boolean), "a tenant context leaked across concurrent requests");
    await raw.user.deleteMany({ where: { name: { startsWith: "c" }, email: { startsWith: "c" } } });
  });

  it("migrates legacy plaintext, then survives KEK rotation", async () => {
    // legacy rows written WITHOUT cryplus (plain text in the encrypted columns)
    await raw.card.deleteMany({});
    await raw.user.deleteMany({});
    const legacy = Array.from({ length: 450 }, (_, i) => ({
      name: "L" + i,
      email: `l${i}@x.io`,
      cpf: String(10_000_000_000 + i),
      notes: "note " + i,
      organizationId: i % 2 ? orgA : orgB,
    }));
    await raw.user.createMany({ data: legacy });
    const orgOf = (r: any) => r.organizationId as string;

    const dry = await migrateModel(raw, cp, schema, { model: "User", tenantOf: orgOf, dryRun: true });
    assert.equal(dry.scanned, 450);
    assert.equal(dry.encrypted, 900); // cpf + notes
    assert.equal((await raw.user.findFirstOrThrow()).cpf!.startsWith("cp1."), false, "dry run must not write");

    const s1 = await migrateModel(raw, cp, schema, { model: "User", tenantOf: orgOf, batchSize: 100 });
    assert.deepEqual({ ...s1, failures: s1.failures.length }, { scanned: 450, encrypted: 900, rewrapped: 0, indexed: 0, failures: 0 });

    // app reads it through the extension; search works on migrated data
    await withTenant(orgA, async () => {
      const f = await db.user.findFirst({ where: { cpf: String(10_000_000_001) } });
      assert.equal(f?.name, "L1");
      assert.equal(f?.notes, "note 1");
    });

    // idempotent
    const s2 = await migrateModel(raw, cp, schema, { model: "User", tenantOf: orgOf });
    assert.equal(s2.encrypted + s2.rewrapped + s2.indexed, 0);

    // rotate the KEK: old data still readable, migration moves it
    const v = await cp.rotateKeys();
    await withTenant(orgB, async () => assert.equal((await db.user.findFirst({ where: { cpf: "10000000000" } }))?.name, "L0"));
    const s3 = await migrateModel(raw, cp, schema, { model: "User", tenantOf: orgOf });
    assert.equal(s3.rewrapped, 900);
    assert.equal(s3.failures.length, 0);
    const sample = await raw.user.findFirstOrThrow();
    const info = await fetch(cp.url + "/v1/keys", { headers: { Authorization: `Bearer ${TOKEN}` } }).then((r) => r.json());
    assert.equal(info.current, v);
    await withTenant(sample.organizationId, async () => assert.ok(await db.user.findFirst({ where: { id: sample.id } })));
    const s4 = await migrateModel(raw, cp, schema, { model: "User", tenantOf: orgOf });
    assert.equal(s4.rewrapped, 0);
  });

  it("throughput: 500 creates + 500-row read", async () => {
    await raw.card.deleteMany({});
    await raw.user.deleteMany({});
    const t0 = performance.now();
    await withTenant(orgA, async () => {
      await db.user.createMany({
        data: Array.from({ length: 500 }, (_, i) => ({ name: "p" + i, email: `p${i}@x.io`, cpf: String(20_000_000_000 + i), notes: "n" + i, organizationId: orgA })),
      });
    });
    const t1 = performance.now();
    const rows = await withTenant(orgA, () => db.user.findMany({ where: { name: { startsWith: "p" } } }));
    const t2 = performance.now();
    assert.equal(rows.length, 500);
    assert.ok(rows.every((r) => /^\d{11}$/.test(r.cpf!)));
    console.log(`    createMany(500 rows x 2 encrypted fields + 2 indexes): ${(t1 - t0).toFixed(0)} ms; findMany(500 rows, 1000 decrypts): ${(t2 - t1).toFixed(0)} ms`);
  });
});
