// Informational benchmark (not part of the test run): write latency with and without Cryplus, and migrateModel throughput.
// Needs the isolated Postgres from ../prisma-demo (`node pg.ts`). Uses a real cryplus-core on loopback.
//   node bench.js
const { spawn } = require("node:child_process");
const { mkdtempSync, rmSync } = require("node:fs");
const { createServer } = require("node:net");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { PrismaClient } = require("@prisma/client");
const { Cryplus, migrateModel, parseSchema, withCryplus, withTenant } = require("cryplus");

const DB = "postgresql://cryplus:cryplus@127.0.0.1:54329/cryplus_demo?schema=p5";
const BIN = path.resolve(__dirname, "../../bin/cryplus-core.exe");
const SCHEMA_PATH = path.join(__dirname, "prisma/schema.prisma");
const schema = parseSchema(require("node:fs").readFileSync(SCHEMA_PATH, "utf8"));
const TOKEN = "bench-token-0123456789abcdef";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pct = (a, p) => [...a].sort((x, y) => x - y)[Math.min(a.length - 1, Math.floor(a.length * p))];
const stat = (a) => `p50 ${pct(a, 0.5).toFixed(2)} ms   p95 ${pct(a, 0.95).toFixed(2)} ms`;
const time = async (n, fn) => {
  const out = [];
  for (let i = 0; i < n; i++) {
    const t = performance.now();
    await fn(i);
    out.push(performance.now() - t);
  }
  return out;
};
const freePort = () => new Promise((res) => { const s = createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });

(async () => {
  const tmp = mkdtempSync(path.join(tmpdir(), "cryplus-bench-"));
  const port = await freePort();
  const child = spawn(BIN, ["--listen", `127.0.0.1:${port}`, "--keyfile", path.join(tmp, "k.json"), "--audit-log", "", "--allow-key-export"], {
    env: { ...process.env, CRYPLUS_TOKEN: TOKEN, CRYPLUS_PASSPHRASE: "bench passphrase for the key file" },
    stdio: ["ignore", "ignore", "inherit"],
  });
  for (let i = 0; i < 100; i++) { try { if ((await fetch(`http://127.0.0.1:${port}/healthz`)).ok) break; } catch {} await sleep(50); }
  const cp = new Cryplus({ url: `http://127.0.0.1:${port}`, token: TOKEN });
  const raw = new PrismaClient({ datasources: { db: { url: DB } } });
  const ext = withCryplus(new PrismaClient({ datasources: { db: { url: DB } } }), { cryplus: cp, schemaPath: SCHEMA_PATH });
  const T = "bench-tenant";
  await raw.webhook.deleteMany({ where: { tenantId: T } });
  const N = 300;

  console.log(`--- write latency, ${N} sequential creates of Webhook(url, secret @encrypted), local Postgres, real cryplus-core ---`);
  await time(30, (i) => raw.webhook.create({ data: { tenantId: T, url: "w" + i, secret: "s" + i } })); // warm up
  const plain = await time(N, (i) => raw.webhook.create({ data: { tenantId: T, url: "p" + i, secret: "secret-value-" + i } }));
  console.log("plain (no Cryplus)                       ", stat(plain));
  await withTenant(T, async () => {
    await time(30, (i) => ext.webhook.create({ data: { tenantId: T, url: "w" + i, secret: "s" + i } }));
    const enc = await time(N, (i) => ext.webhook.create({ data: { tenantId: T, url: "e" + i, secret: "secret-value-" + i } }));
    console.log("encrypted, write only (1 encrypt call)    ", stat(enc));
    const find = await time(N, (i) => ext.webhook.findFirst({ where: { url: "e" + i } }));
    console.log("encrypted, findFirst (1 decrypt call)     ", stat(find));
    const plainFind = await time(N, (i) => raw.webhook.findFirst({ where: { url: "p" + i } }));
    console.log("plain findFirst                           ", stat(plainFind));
  });
  const cached = withCryplus(new PrismaClient({ datasources: { db: { url: DB } } }), { cryplus: new Cryplus({ url: `http://127.0.0.1:${port}`, token: TOKEN, keyCache: true }), schemaPath: SCHEMA_PATH });
  await withTenant(T, async () => {
    await time(30, (i) => cached.webhook.create({ data: { tenantId: T, url: "w" + i, secret: "s" + i } }));
    console.log("encrypted, key cache ON, write            ", stat(await time(N, (i) => cached.webhook.create({ data: { tenantId: T, url: "c" + i, secret: "secret-value-" + i } }))));
  });
  await raw.webhook.deleteMany({ where: { tenantId: T } });

  console.log(`\n--- migrateModel throughput: 2000 plaintext rows, verify on, real core + local Postgres ---`);
  for (const [label, o] of [["concurrency 1, verify all   ", { concurrency: 1, verify: true }], ["concurrency 8, verify all   ", { concurrency: 8, verify: true }], ["concurrency 8, verify 5 %   ", { concurrency: 8, verify: { sample: 0.05 } }], ["concurrency 16, verify 5 %  ", { concurrency: 16, verify: { sample: 0.05 } }]]) {
    await raw.webhook.deleteMany({ where: { tenantId: T } });
    await raw.webhook.createMany({ data: Array.from({ length: 2000 }, (_, i) => ({ tenantId: T, url: "m" + i, secret: "plain-secret-" + i })) });
    const t0 = performance.now();
    const s = await migrateModel(raw, cp, schema, { model: "Webhook", tenantOf: (r) => r.tenantId, batchSize: 200, ...o });
    const sec = (performance.now() - t0) / 1000;
    console.log(label, `${(2000 / sec).toFixed(0)} rows/s  (${sec.toFixed(1)} s)  encrypted ${s.encrypted}, verified ${s.verified}, failures ${s.failures.length}`);
  }
  await raw.webhook.deleteMany({ where: { tenantId: T } });
  await raw.$disconnect(); await ext.$disconnect(); await cached.$disconnect();
  child.kill();
  await sleep(200);
  try { rmSync(tmp, { recursive: true, force: true }); } catch {}
})();
