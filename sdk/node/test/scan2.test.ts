import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseSchema, scanSource, analyzeSql, type ScanFinding } from "../src/index.ts";

const schema = parseSchema(`
model Webhook {
  id String @id
  tenantId String @map("tenant_id")
  url String
  createdAt DateTime
  /// @encrypted
  secret String?
  @@map("webhooks")
}
model Tenant {
  id String @id
  nome String
  telefone String?
  /// @encrypted
  mpToken String? @map("mp_token")
  @@map("tenants")
}
model Funcionario {
  id String @id
  nome String
  celular String?
  /// @encrypted(searchable, digits)
  cpf String?
  cpfIdx String? @map("cpf_idx")
  /// @encrypted(suffix(4))
  fone String?
  foneSfx4 String? @map("fone_sfx4")
  @@map("funcionarios")
}
model Mensagem {
  id String @id
  conversaId String
  /// @encrypted
  conteudo String?
  conversa Conversa @relation(fields: [conversaId], references: [id])
}
model Conversa {
  id String @id
  titulo String
  mensagens Mensagem[]
}
`);
const scan = (src: string): ScanFinding[] => scanSource(schema, src, "x.js");
const msgs = (fs: ScanFinding[]) => fs.map((f) => `${f.severity}:${f.call}:${f.message}`);

describe("scanner: `*` is only a select-list star (false positive from the Operax rankings queries)", () => {
  const sqlFor = (body: string) => analyzeSql(schema, body);

  it("arithmetic is not a star", () => {
    assert.deepEqual(sqlFor("SELECT COUNT(CASE WHEN w.id IS NOT NULL THEN 1 END) * 100.0 / NULLIF(COUNT(*), 0) AS pct FROM webhooks w WHERE w.tenant_id = $1"), []);
    assert.deepEqual(sqlFor("SELECT SUM(CASE WHEN x THEN 1 ELSE 0 END) * 100.0 AS p, AVG(a) * 2 FROM webhooks"), []);
    assert.deepEqual(sqlFor("SELECT (COUNT(*) FILTER (WHERE a)) * 100.0 / COUNT(*) FROM webhooks"), []);
    assert.deepEqual(sqlFor("SELECT a * b FROM webhooks"), []);
    assert.deepEqual(sqlFor("SELECT\n  COUNT(DISTINCT id) * 100.0\nFROM webhooks"), []);
  });

  it("real select-list stars are still caught", () => {
    for (const q of [
      "SELECT * FROM webhooks",
      "select * from webhooks where tenant_id = $1",
      "SELECT w.* FROM webhooks w",
      "SELECT id, w.* FROM webhooks w",
      "SELECT DISTINCT * FROM webhooks",
      "SELECT\n  *\nFROM webhooks",
      "WITH x AS (SELECT * FROM webhooks) SELECT 1 FROM x",
      "DELETE FROM webhooks WHERE a = 1 RETURNING *",
    ]) {
      assert.equal(sqlFor(q).length, 1, q);
    }
    assert.equal(sqlFor("SELECT COUNT(*) FROM webhooks").length, 0);
  });
});

describe("scanner: // cryplus-columns declares what helper-built SQL touches", () => {
  const helper = (annotation: string, call = "await prisma.$queryRawUnsafe(`SELECT ${CANON('f.celular')} FROM funcionarios f`);") => `${annotation}\n${call}\n`;

  it("without it, helper-built SQL is only 'cannot analyze'", () => {
    assert.deepEqual(scan(helper("")).map((f) => f.severity), ["dynamic"]);
  });

  it("with plain columns the call is CHECKED and clean: the note is gone", () => {
    assert.deepEqual(scan(helper("// cryplus-columns: funcionarios.celular, tenants.telefone")), []);
    assert.deepEqual(scan(helper("/* cryplus-columns: funcionarios.nome */")), []);
    assert.deepEqual(scan(helper("// cryplus-columns: funcionarios.celular\n// (reviewed)")), []);
  });

  it("an encrypted column in the declaration is an error, by database or field name", () => {
    assert.match(msgs(scan(helper("// cryplus-columns: funcionarios.cpf")))[0]!, /^error:\$queryRawUnsafe:.*declared column cpf is encrypted/);
    assert.match(msgs(scan(helper("// cryplus-columns: tenants.mp_token, funcionarios.celular")))[0]!, /declared column mp_token is encrypted/);
    assert.match(msgs(scan(helper("// cryplus-columns: tenants.mpToken")))[0]!, /declared column mp_token is encrypted/);
    assert.match(msgs(scan(helper("// cryplus-columns: webhooks.*")))[0]!, /every column, which includes encrypted/);
    assert.deepEqual(scan(helper("// cryplus-columns: conversas.*")).length, 1, "unknown table");
  });

  it("typos are errors, not silence", () => {
    assert.match(msgs(scan(helper("// cryplus-columns: funcionarios.celulr")))[0]!, /has no column "celulr"/);
    assert.match(msgs(scan(helper("// cryplus-columns: funcionario")))[0]!, /is not table.column/);
    assert.match(msgs(scan(helper("// cryplus-columns: nada.x")))[0]!, /unknown table "nada"/);
  });

  it("applies to the call right below it (up to three lines), not to a distant one", () => {
    const far = "// cryplus-columns: funcionarios.celular\nconst a = 1;\nconst b = 2;\nconst c = 3;\nconst d = 4;\nawait prisma.$queryRawUnsafe(`SELECT ${CANON('f.celular')} FROM funcionarios f`);\n";
    assert.deepEqual(scan(far).map((f) => f.severity), ["dynamic"]);
    const near = "// cryplus-columns: funcionarios.celular\nconst sql = build();\nawait prisma.$queryRawUnsafe(sql);\n";
    assert.deepEqual(scan(near), []);
  });

  it("literal text of the same call is still analyzed", () => {
    const f = scan(helper("// cryplus-columns: funcionarios.celular", "await prisma.$queryRawUnsafe(`SELECT ${CANON('f.celular')}, cpf FROM funcionarios f`);"));
    assert.ok(f.some((x) => x.severity === "error" && /cpf/.test(x.message)));
  });
});

describe("scanner: Prisma calls that the extension would refuse", () => {
  it("unsupported operators on encrypted fields", () => {
    const f = scan("await prisma.funcionario.findMany({ where: { cpf: { contains: '123' } } });");
    assert.equal(f.length, 1);
    assert.match(f[0]!.message, /unsupported filter on encrypted field cpf: contains/);
    assert.match(msgs(scan("prisma.webhook.findFirst({ where: { tenantId, secret: { startsWith: 'a' } } })"))[0]!, /startsWith/);
    assert.equal(scan("prisma.funcionario.count({ where: { AND: [{ nome: 'a' }, { NOT: { cpf: { gte: '1' } } }] } })").length, 1, "inside AND / NOT");
    assert.equal(scan("prisma.funcionario.findMany({ where: { cpf: { endsWith: '1234' } } })").length, 1, "endsWith without suffix index");
    assert.equal(scan("prisma.funcionario.findMany({ where: { fone: { endsWith: '1234' } } })").length, 0, "endsWith WITH suffix index is supported");
  });

  it("equality on an encrypted field that is not searchable", () => {
    assert.match(msgs(scan("prisma.webhook.findFirst({ where: { secret: token } })"))[0]!, /not @encrypted\(searchable\)/);
    assert.match(msgs(scan("prisma.webhook.findMany({ where: { secret: { in: [a, b] } } })"))[0]!, /not @encrypted\(searchable\)/);
    assert.match(msgs(scan("prisma.webhook.findMany({ where: { secret: { equals: 'x' } } })"))[0]!, /not @encrypted\(searchable\)/);
  });

  it("orderBy / groupBy / distinct / aggregates", () => {
    assert.match(msgs(scan("prisma.funcionario.findMany({ orderBy: { cpf: 'asc' } })"))[0]!, /cannot order by encrypted field cpf/);
    assert.match(msgs(scan("prisma.funcionario.findMany({ orderBy: [{ nome: 'asc' }, { cpf: 'desc' }] })"))[0]!, /order by/);
    assert.match(msgs(scan("prisma.funcionario.groupBy({ by: ['cpf'], _count: true })"))[0]!, /group by/);
    assert.match(msgs(scan("prisma.funcionario.groupBy({ by: [\"nome\", \"cpf\"] })"))[0]!, /group by/);
    assert.match(msgs(scan("prisma.funcionario.findMany({ distinct: ['cpf'] })"))[0]!, /distinct on/);
    assert.match(msgs(scan("prisma.funcionario.aggregate({ _max: { cpf: true } })"))[0]!, /aggregate \(_max\)/);
  });

  it("fields of related models are seen through include / relation filters", () => {
    assert.match(msgs(scan("prisma.conversa.findMany({ where: { mensagens: { some: { conteudo: { contains: 'oi' } } } } })"))[0]!, /contains/);
    assert.match(msgs(scan("prisma.conversa.findMany({ include: { mensagens: { orderBy: { conteudo: 'asc' } } } })"))[0]!, /order by encrypted field conteudo/);
  });

  it("what is supported or unrelated is NOT flagged", () => {
    for (const ok of [
      "prisma.funcionario.findMany({ where: { cpf: valor } })",
      "prisma.funcionario.findFirst({ where: { cpf: { in: [a, b] } } })",
      "prisma.funcionario.findFirst({ where: { cpf: { not: null } } })",
      "prisma.funcionario.findFirst({ where: { cpf: null, nome: { contains: 'a' } } })",
      "prisma.funcionario.findMany({ where: { nome: { contains: 'a' } }, orderBy: { nome: 'asc' } })",
      "prisma.webhook.findMany({ where: { secret: null } })",
      "prisma.webhook.findMany({ where: { url: { startsWith: 'https' } }, orderBy: { createdAt: 'desc' } })",
      "prisma.webhook.create({ data: { secret: 'x', tenantId } })",
      "prisma.webhook.update({ where: { id }, data: { secret: nextSecret } })",
      "prisma.webhook.groupBy({ by: ['tenantId'], _count: true })",
      "prisma.conversa.findMany({ orderBy: { titulo: 'asc' } })",
      "other.funcionario.cpf.contains('x')",
    ]) {
      assert.deepEqual(msgs(scan(ok)), [], ok);
    }
  });

  it("reports the line, and cryplus-ignore-next-line silences it", () => {
    const f = scan("const a = 1;\nawait prisma.funcionario.findMany({\n  where: { cpf: { contains: 'x' } },\n});");
    assert.equal(f.length, 1);
    assert.equal(f[0]!.line, 2);
    assert.deepEqual(scan("// cryplus-ignore-next-line: reviewed, only used in tests\nawait prisma.funcionario.findMany({ where: { cpf: { contains: 'x' } } });"), []);
  });

  it("a tx.<model> or this.prisma.<model> delegate is read the same way", () => {
    assert.equal(scan("await tx.funcionario.findMany({ orderBy: { cpf: 'asc' } });").length, 1);
    assert.equal(scan("await this.prisma.funcionario.findMany({ orderBy: { cpf: 'asc' } });").length, 1);
  });
});
