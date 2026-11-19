import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { parseSchema, scanPaths, scanSource, type ScanFinding } from "../src/index.ts";

const SCHEMA = `
model Webhook {
  id String @id
  tenantId String @map("tenant_id")
  url String
  /// @encrypted
  secret String?
  @@map("webhooks")
}
model Tenant {
  id String @id
  /// @encrypted
  mpOauthAccessToken String? @map("mp_oauth_access_token")
  @@map("tenants")
}
model Funcionario {
  id String @id
  tenantId String @map("tenant_id")
  /// @encrypted(searchable, digits)
  cpf String?
  cpfIdx String? @map("cpf_idx")
  @@map("funcionarios")
}
model Cliente {
  id String @id
  /// @encrypted(searchable)
  cpfCnpj String? @map("cpf_cnpj")
  cpfCnpjIdx String? @map("cpf_cnpj_idx")
  @@map("clientes")
}
model ApiKey {
  id String @id
  key String
  @@map("api_keys")
}
`;
const schema = parseSchema(SCHEMA);
const scan = (src: string): ScanFinding[] => scanSource(schema, src, "x.js");
const sev = (fs: ScanFinding[]) => fs.map((f) => f.severity + ":" + f.call);

describe("scanner: what it must catch", () => {
  it("tagged $queryRaw / $executeRaw that mention an encrypted column, by DATABASE name", () => {
    const f = scan("await prisma.$queryRaw`SELECT id, url, secret FROM webhooks WHERE tenant_id = ${tenantId} AND ativo = true`;");
    assert.deepEqual(sev(f), ["error:$queryRaw"]);
    assert.match(f[0]!.message, /Webhook \(webhooks\).*secret/);
    assert.equal(f[0]!.line, 1);
    assert.deepEqual(sev(scan("await prisma.$executeRaw`INSERT INTO webhooks (id, tenant_id, url, secret) VALUES (${a}, ${b}, ${c}, ${d})`;")), ["error:$executeRaw"]);
    // the real column is mp_oauth_access_token, not the Prisma field name
    assert.deepEqual(sev(scan("prisma.$queryRaw`SELECT mp_oauth_access_token FROM tenants WHERE id = ${id}`")), ["error:$queryRaw"]);
    assert.deepEqual(sev(scan("prisma.$queryRaw`SELECT mpOauthAccessToken FROM tenants WHERE id = ${id}`")), [], "the Prisma field name is not a column");
  });

  it("Unsafe string, template, concatenation and Prisma.sql forms", () => {
    assert.deepEqual(sev(scan(`prisma.$queryRawUnsafe('SELECT cpf FROM funcionarios WHERE id = $1', id)`)), ["error:$queryRawUnsafe"]);
    assert.deepEqual(sev(scan(`prisma.$queryRawUnsafe("SELECT cpf " + "FROM funcionarios")`)), ["error:$queryRawUnsafe"]);
    assert.deepEqual(sev(scan("prisma.$queryRaw(Prisma.sql`SELECT cpf FROM funcionarios WHERE tenant_id = ${t}`)")), ["error:$queryRaw"]);
    assert.deepEqual(sev(scan("prisma.$queryRawUnsafe(`SELECT cpf FROM funcionarios WHERE id = $1`, id)")), ["error:$queryRawUnsafe"]);
  });

  it("resolves a constant declared in the same file", () => {
    const f = scan("const q = `SELECT cpf FROM funcionarios WHERE id = $1`;\nawait prisma.$queryRawUnsafe(q, id);");
    assert.deepEqual(sev(f), ["error:$queryRawUnsafe"]);
    assert.equal(f[0]!.line, 2);
    assert.deepEqual(sev(scan("const A = 'SELECT cpf ';\nconst B = A + 'FROM funcionarios';\nprisma.$queryRawUnsafe(B)")), ["error:$queryRawUnsafe"]);
  });

  it("SELECT * / RETURNING * / INSERT without a column list on an encrypted table", () => {
    assert.deepEqual(sev(scan("prisma.$queryRaw`SELECT * FROM webhooks`")), ["error:$queryRaw"]);
    assert.deepEqual(sev(scan("prisma.$queryRaw`SELECT w.* FROM webhooks w`")), ["error:$queryRaw"]);
    assert.deepEqual(sev(scan("prisma.$queryRaw`INSERT INTO webhooks VALUES (${a},${b},${c},${d})`")), ["error:$queryRaw"]);
    assert.deepEqual(sev(scan("prisma.$queryRaw`UPDATE webhooks SET url = ${u} WHERE id = ${i} RETURNING *`")), ["error:$queryRaw"]);
  });

  it("destructured helper, nested templates inside ${}, and the call form with a tagged template", () => {
    assert.deepEqual(sev(scan("const { $queryRaw } = prisma;\nawait $queryRaw`SELECT cpf FROM funcionarios`;")), ["error:$queryRaw"]);
    assert.deepEqual(sev(scan("prisma.$queryRaw`SELECT ${`a${b}`} FROM funcionarios WHERE cpf = ${x} /* ${'}'} */`")), ["error:$queryRaw"]);
  });
});

describe("scanner: what it must not flag", () => {
  it("unencrypted tables, count(*), the index column, handled marker, comments", () => {
    assert.deepEqual(scan("prisma.$queryRaw`SELECT * FROM api_keys WHERE key = ${apiKey}`"), []);
    assert.deepEqual(scan("prisma.$queryRaw`SELECT count(*) FROM webhooks WHERE tenant_id = ${t}`"), []);
    assert.deepEqual(scan("prisma.$queryRaw`SELECT id FROM funcionarios WHERE tenant_id = ${t} AND cpf_idx = ${i}`"), []);
    assert.deepEqual(scan("prisma.$queryRaw`SELECT secret /* cryplus:handled */ FROM webhooks`"), []);
    assert.deepEqual(scan("// prisma.$queryRaw`SELECT secret FROM webhooks`\nconst s = \"prisma.$queryRaw`SELECT secret FROM webhooks`\";"), []);
    assert.deepEqual(scan("const x = prisma.$queryRaw; // just a reference"), []);
  });

  it("// cryplus-ignore-next-line silences exactly the next line; cryplus-ignore-file the whole file", () => {
    assert.deepEqual(scan("// cryplus-ignore-next-line: reviewed, only counts rows\nawait prisma.$queryRaw`SELECT cpf FROM funcionarios`;"), []);
    const two = scan("// cryplus-ignore-next-line: ok\nawait prisma.$queryRaw`SELECT cpf FROM funcionarios`;\nawait prisma.$queryRaw`SELECT cpf FROM funcionarios`;");
    assert.equal(two.length, 1);
    assert.equal(two[0]!.line, 3);
    assert.deepEqual(scan("/* cryplus-ignore-file */\nprisma.$queryRaw`SELECT cpf FROM funcionarios`"), []);
  });
});

describe("scanner: SQL it cannot analyze is reported, never skipped silently", () => {
  it("concatenation with a runtime value, interpolated Unsafe templates, helper calls", () => {
    const a = scan(`prisma.$queryRawUnsafe('SELECT id FROM clientes WHERE tenant_id = $1 AND (' + conds.join(' OR ') + ')', t)`);
    assert.deepEqual(sev(a), ["dynamic:$queryRawUnsafe"]);
    assert.match(a[0]!.message, /cannot analyze.*conds\.join/);
    assert.deepEqual(sev(scan("prisma.$queryRawUnsafe(`SELECT ${cols} FROM clientes`)")), ["dynamic:$queryRawUnsafe"]);
    assert.deepEqual(sev(scan("prisma.$queryRawUnsafe(buildQuery(filters))")), ["dynamic:$queryRawUnsafe"]);
    assert.deepEqual(sev(scan("function run(sql) { return prisma.$queryRawUnsafe(sql); }")), ["dynamic:$queryRawUnsafe"]);
    // Prisma.raw injected into a tagged query is dynamic too
    assert.deepEqual(sev(scan("prisma.$queryRaw`SELECT id FROM clientes ${Prisma.raw(orderBy)}`")), ["dynamic:$queryRaw"]);
  });

  it("static pieces are still analyzed, so a dynamic query can ALSO be an error", () => {
    const f = scan(`prisma.$queryRawUnsafe('SELECT cpf_cnpj FROM clientes WHERE ' + where, ...params)`);
    assert.deepEqual(sev(f).sort(), ["dynamic:$queryRawUnsafe", "error:$queryRawUnsafe"]);
  });

  it("a safe tagged template with only bound parameters is NOT dynamic", () => {
    assert.deepEqual(scan("prisma.$queryRaw`SELECT id FROM clientes WHERE tenant_id = ${t} AND id = ${id}`"), []);
  });

  it("direct pg driver use is flagged as not analyzed", () => {
    assert.deepEqual(sev(scan("const { Pool } = require('pg');\nconst pool = new Pool();")), ["info:pg"]);
  });
});

describe("scanner CLI", () => {
  let dir: string;
  const cli = fileURLToPath(new URL("../src/scan-cli.ts", import.meta.url));
  const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
  const put = (rel: string, content: string) => {
    const p = path.join(dir, rel);
    mkdirSync(path.dirname(p), { recursive: true });
    writeFileSync(p, content);
  };

  before(() => {
    dir = mkdtempSync(path.join(tmpdir(), "cryplus-scan-"));
    put("prisma/schema.prisma", SCHEMA);
    put("src/webhookService.js", "module.exports = async (prisma, t) => prisma.$queryRaw`SELECT url, secret FROM webhooks WHERE tenant_id = ${t}`;\n");
    put("src/dashboard.js", "module.exports = (prisma) => prisma.$queryRaw`SELECT count(*) FROM webhooks`;\n");
    put("src/dyn.js", "module.exports = (prisma, q) => prisma.$queryRawUnsafe(q);\n");
    put("node_modules/lib/x.js", "prisma.$queryRaw`SELECT secret FROM webhooks`\n");
    put("src/types.d.ts", "declare const a: string;\n");
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("exits 1 and prints file:line:column for each finding, skipping node_modules", () => {
    const r = run("--schema", path.join(dir, "prisma/schema.prisma"), "--src", dir);
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stdout, /webhookService\.js:1:\d+\s+error\s+\$queryRaw\s+Webhook \(webhooks\)/);
    assert.match(r.stdout, /dyn\.js:1:\d+\s+dynamic/);
    assert.doesNotMatch(r.stdout, /node_modules/);
    assert.doesNotMatch(r.stdout, /dashboard\.js/);
    assert.match(r.stdout, /1 error\(s\), 1 unanalyzable/);
  });

  it("json format is machine readable", () => {
    const r = run("--schema", path.join(dir, "prisma/schema.prisma"), "--src", dir, "--format", "json");
    const j = JSON.parse(r.stdout);
    assert.equal(j.findings.filter((f: any) => f.severity === "error").length, 1);
    assert.ok(j.files >= 3);
  });

  it("--allow-dynamic fails only on confirmed errors; a clean tree exits 0", () => {
    const clean = mkdtempSync(path.join(tmpdir(), "cryplus-scan-clean-"));
    mkdirSync(path.join(clean, "src"));
    writeFileSync(path.join(clean, "src/a.js"), "prisma.$queryRaw`SELECT count(*) FROM webhooks`\nprisma.$queryRawUnsafe(q)\n");
    const strict = run("--schema", path.join(dir, "prisma/schema.prisma"), "--src", clean);
    assert.equal(strict.status, 1, "unanalyzable SQL fails by default");
    const lax = run("--schema", path.join(dir, "prisma/schema.prisma"), "--src", clean, "--allow-dynamic");
    assert.equal(lax.status, 0);
    writeFileSync(path.join(clean, "src/a.js"), "prisma.$queryRaw`SELECT count(*) FROM webhooks`\n");
    assert.equal(run("--schema", path.join(dir, "prisma/schema.prisma"), "--src", clean).status, 0);
    rmSync(clean, { recursive: true, force: true });
  });

  it("exits 2 on usage errors and on an invalid schema (printing the ALTER TABLE to run)", () => {
    assert.equal(run().status, 2);
    assert.equal(run("--schema", "nope.prisma", "--src", dir).status === 0, false);
    const bad = path.join(dir, "bad.prisma");
    writeFileSync(bad, "model A {\n id String @id\n cpf String @db.VarChar(14) /// @encrypted\n @@map(\"a_tbl\")\n}\n");
    const r = run("--schema", bad, "--src", dir);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /ALTER TABLE "a_tbl" ALTER COLUMN "cpf" TYPE text;/);
  });
});

describe("scanner on a whole tree", () => {
  it("scanPaths walks directories and counts files", () => {
    const d = mkdtempSync(path.join(tmpdir(), "cryplus-scan-tree-"));
    mkdirSync(path.join(d, "a/b"), { recursive: true });
    writeFileSync(path.join(d, "a/b/x.ts"), "prisma.$queryRaw`SELECT secret FROM webhooks`");
    writeFileSync(path.join(d, "a/y.js"), "const ok = 1;");
    writeFileSync(path.join(d, "a/notes.md"), "prisma.$queryRaw`SELECT secret FROM webhooks`");
    const r = scanPaths(schema, [d]);
    assert.equal(r.files, 2);
    assert.equal(r.findings.length, 1);
    rmSync(d, { recursive: true, force: true });
  });
});
