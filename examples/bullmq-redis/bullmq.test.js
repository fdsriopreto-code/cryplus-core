// Job sealing against a REAL BullMQ and a REAL Redis (docker run redis:7-alpine), with a real cryplus-core.
// Needs Docker. Skipped (not failed) when Docker is not available.
const assert = require("node:assert/strict");
const { spawn, spawnSync } = require("node:child_process");
const { mkdtempSync, rmSync } = require("node:fs");
const { createServer } = require("node:net");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { after, before, describe, it } = require("node:test");
const IORedis = require("ioredis");
const { Queue, Worker, QueueEvents } = require("bullmq");
const { Cryplus, encryptedQueue, encryptedWorker, sealJobData, currentTenant } = require("cryplus");

const BIN = path.resolve(__dirname, "../../bin/cryplus-core.exe");
const TOKEN = "bullmq-token-0123456789abcdef";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((res) => { const s = createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const docker = (...a) => spawnSync("docker", a, { encoding: "utf8" });
const dockerOk = docker("version", "--format", "{{.Server.Version}}").status === 0;

const SECRET_NAME = "Maria da Silva Sauro";
const SECRET_CPF = "123.456.789-00";
let redisPort, container, core, tmp, cp, conn, bare;
const toClose = [];

// everything Redis holds, as text, for a plaintext search
async function dumpRedis() {
  let out = "";
  const keys = await bare.keys("*");
  for (const k of keys) {
    const t = await bare.type(k);
    if (t === "hash") out += k + JSON.stringify(await bare.hgetall(k));
    else if (t === "string") out += k + (await bare.get(k));
    else if (t === "list") out += k + JSON.stringify(await bare.lrange(k, 0, -1));
    else if (t === "zset") out += k + JSON.stringify(await bare.zrange(k, 0, -1, "WITHSCORES"));
    else if (t === "set") out += k + JSON.stringify(await bare.smembers(k));
    else if (t === "stream") out += k + JSON.stringify(await bare.xrange(k, "-", "+"));
  }
  return out;
}

before(async () => {
  if (!dockerOk) return;
  redisPort = await freePort();
  const r = docker("run", "-d", "--rm", "-p", `127.0.0.1:${redisPort}:6379`, "redis:7-alpine");
  assert.equal(r.status, 0, r.stderr);
  container = r.stdout.trim();
  tmp = mkdtempSync(path.join(tmpdir(), "cryplus-bq-"));
  const port = await freePort();
  core = spawn(BIN, ["--listen", `127.0.0.1:${port}`, "--keyfile", path.join(tmp, "k.json"), "--audit-log", ""], {
    env: { ...process.env, CRYPLUS_TOKEN: TOKEN, CRYPLUS_PASSPHRASE: "bullmq test passphrase, long enough" },
    stdio: ["ignore", "ignore", "inherit"],
  });
  for (let i = 0; i < 100; i++) { try { if ((await fetch(`http://127.0.0.1:${port}/healthz`)).ok) break; } catch {} await sleep(50); }
  cp = new Cryplus({ url: `http://127.0.0.1:${port}`, token: TOKEN });
  bare = new IORedis(redisPort, "127.0.0.1", { maxRetriesPerRequest: null });
  for (let i = 0; i < 100; i++) { try { if ((await bare.ping()) === "PONG") break; } catch {} await sleep(100); }
  conn = { host: "127.0.0.1", port: redisPort };
});

after(async () => {
  for (const c of toClose.reverse()) { try { await c.close(); } catch {} }
  try { await bare?.quit(); } catch {}
  core?.kill();
  if (container) docker("rm", "-f", container);
  await sleep(200);
  if (tmp) try { rmSync(tmp, { recursive: true, force: true }); } catch {}
});

const opts = { skip: dockerOk ? false : "Docker is not available" };

describe("sealed jobs on real BullMQ + real Redis", opts, () => {
  it("the payload in Redis holds no plaintext, anywhere (hashes, lists, sorted sets, streams)", async () => {
    const raw = new Queue("pdf", { connection: conn });
    toClose.push(raw);
    const q = encryptedQueue(raw, cp);
    const job = await q.add("render", { tenantId: "acme", orcamento: { cliente: SECRET_NAME, cpf: SECRET_CPF, itens: [1, 2, 3] } });
    const h = await bare.hgetall(`bull:pdf:${job.id}`);
    const stored = JSON.parse(h.data);
    assert.equal(stored.__cryplus, 1);
    assert.equal(stored.tenantId, "acme"); // routing information stays readable on purpose
    assert.match(stored.sealed, /^cp1\./);
    const everything = await dumpRedis();
    assert.ok(everything.includes("bull:pdf"), "sanity: the dump covers the queue");
    for (const s of [SECRET_NAME, "Sauro", "123.456", "789-00"]) assert.equal(everything.includes(s), false, `plaintext "${s}" found in Redis`);
  });

  it("a worker receives the plaintext, runs inside the job's tenant, and the result is delivered", async () => {
    const q = encryptedQueue(new Queue("work", { connection: conn }), cp);
    toClose.push(q);
    const seen = [];
    const w = new Worker("work", encryptedWorker(cp, async (job) => {
      seen.push({ cliente: job.data.orcamento.cliente, tenant: currentTenant(), name: job.name });
      return { ok: true, total: job.data.orcamento.itens.length };
    }), { connection: conn });
    toClose.push(w);
    const events = new QueueEvents("work", { connection: conn });
    toClose.push(events);
    await events.waitUntilReady();
    const job = await q.add("render", { tenantId: "acme", orcamento: { cliente: SECRET_NAME, itens: [1, 2] } });
    const result = await job.waitUntilFinished(events, 10_000);
    assert.deepEqual(result, { ok: true, total: 2 });
    assert.deepEqual(seen, [{ cliente: SECRET_NAME, tenant: "acme", name: "render" }]);
    assert.equal((await dumpRedis()).includes("Sauro"), false);
  });

  it("retries: the failed attempt leaves the job sealed in Redis and the next attempt sees the plaintext again", async () => {
    const q = encryptedQueue(new Queue("retry", { connection: conn }), cp);
    toClose.push(q);
    let attempts = 0;
    const midRun = [];
    const w = new Worker("retry", encryptedWorker(cp, async (job) => {
      attempts++;
      if (attempts === 1) {
        midRun.push(await dumpRedis()); // while the processor runs, Redis still has only the sealed form
        throw new Error("transient failure (no secrets in this message)");
      }
      return job.data.orcamento.cliente === SECRET_NAME ? "ok" : "wrong";
    }), { connection: conn });
    toClose.push(w);
    const events = new QueueEvents("retry", { connection: conn });
    toClose.push(events);
    await events.waitUntilReady();
    const job = await q.add("render", { tenantId: "acme", orcamento: { cliente: SECRET_NAME } }, { attempts: 3, backoff: { type: "fixed", delay: 50 } });
    assert.equal(await job.waitUntilFinished(events, 10_000), "ok");
    assert.equal(attempts, 2);
    assert.equal(midRun[0].includes("Sauro"), false);
    assert.equal((await dumpRedis()).includes("Sauro"), false, "nothing leaked after completion either");
  });

  it("addBulk, delayed jobs and priorities all go through sealing", async () => {
    const q = encryptedQueue(new Queue("bulk", { connection: conn }), cp);
    toClose.push(q);
    const got = [];
    const w = new Worker("bulk", encryptedWorker(cp, async (job) => { got.push(job.data.n); }), { connection: conn, concurrency: 5 });
    toClose.push(w);
    const events = new QueueEvents("bulk", { connection: conn });
    toClose.push(events);
    await events.waitUntilReady();
    const jobs = await q.addBulk(Array.from({ length: 30 }, (_, n) => ({ name: "x", data: { tenantId: n % 2 ? "a" : "b", n, nome: SECRET_NAME } })));
    assert.equal(jobs.length, 30);
    const delayed = await q.add("x", { tenantId: "a", n: 100, nome: SECRET_NAME }, { delay: 300, priority: 1 });
    await delayed.waitUntilFinished(events, 10_000);
    await Promise.all(jobs.map((j) => j.waitUntilFinished(events, 10_000)));
    assert.deepEqual([...got].sort((a, b) => a - b), [...Array.from({ length: 30 }, (_, n) => n), 100]);
    assert.equal((await dumpRedis()).includes("Sauro"), false);
  });

  it("a sealed payload replayed into another queue (or under another job name) is never processed", async () => {
    const q = encryptedQueue(new Queue("alpha", { connection: conn }), cp);
    toClose.push(q);
    const job = await q.add("render", { tenantId: "acme", secret: SECRET_NAME });
    const sealed = JSON.parse((await bare.hgetall(`bull:alpha:${job.id}`)).data);
    const plainQueue = new Queue("beta", { connection: conn }); // an attacker (or a bug) copies the stored payload into another queue
    toClose.push(plainQueue);
    const events = new QueueEvents("beta", { connection: conn });
    toClose.push(events);
    await events.waitUntilReady();
    let processed = 0;
    const w = new Worker("beta", encryptedWorker(cp, async () => { processed++; }), { connection: conn });
    toClose.push(w);
    const replay = await plainQueue.add("render", sealed);
    await assert.rejects(replay.waitUntilFinished(events, 10_000), /decryption_failed|cryplus/);
    const renamed = await plainQueue.add("other-name", sealMove(sealed));
    await assert.rejects(renamed.waitUntilFinished(events, 10_000));
    assert.equal(processed, 0);
    function sealMove(s) { return s; }
  });

  it("allowPlain:false refuses a job that was enqueued without sealing, allowPlain:true (default) still runs it during a rollout", async () => {
    const plain = new Queue("rollout", { connection: conn });
    toClose.push(plain);
    const events = new QueueEvents("rollout", { connection: conn });
    toClose.push(events);
    await events.waitUntilReady();
    const strict = new Worker("rollout", encryptedWorker(cp, async () => "ran", { allowPlain: false }), { connection: conn });
    toClose.push(strict);
    const j = await plain.add("render", { tenantId: "acme", nome: "not sealed" });
    await assert.rejects(j.waitUntilFinished(events, 10_000), /not sealed/);
    await strict.close();
    const lenient = new Worker("rollout", encryptedWorker(cp, async (job) => `ran:${currentTenant()}`), { connection: conn });
    toClose.push(lenient);
    const k = await plain.add("render", { tenantId: "acme", nome: "not sealed" });
    assert.equal(await k.waitUntilFinished(events, 10_000), "ran:acme");
  });

  it("what sealing does NOT cover (documented): return values and failure reasons are stored in clear", async () => {
    const q = encryptedQueue(new Queue("leaky", { connection: conn }), cp);
    toClose.push(q);
    const events = new QueueEvents("leaky", { connection: conn });
    toClose.push(events);
    await events.waitUntilReady();
    const w = new Worker("leaky", encryptedWorker(cp, async (job) => { throw new Error(`could not render for ${job.data.nome}`); }), { connection: conn });
    toClose.push(w);
    const job = await q.add("render", { tenantId: "acme", nome: SECRET_NAME });
    await assert.rejects(job.waitUntilFinished(events, 10_000));
    const dump = await dumpRedis();
    assert.equal(dump.includes("Sauro"), true, "the processor put the name in its own error message: that text is NOT sealed (docs/OPERAX.md says so)");
  });

  it("the job id, name and tenant id are the clear text that remains (and nothing else of the data)", async () => {
    const raw = new Queue("clear", { connection: conn });
    toClose.push(raw);
    const q = encryptedQueue(raw, cp);
    const job = await q.add("render-pdf", { tenantId: "acme", a: 1 }, { jobId: "chosen-id-1" });
    const h = await bare.hgetall(`bull:clear:${job.id}`);
    assert.equal(h.name, "render-pdf");
    assert.deepEqual(Object.keys(JSON.parse(h.data)).sort(), ["__cryplus", "sealed", "tenantId"]);
  });

  it("no tenant: the enqueue fails closed (nothing reaches Redis)", async () => {
    const raw = new Queue("notenant", { connection: conn });
    toClose.push(raw);
    const q = encryptedQueue(raw, cp);
    await assert.rejects(q.add("x", { nome: SECRET_NAME }), /no tenant for this job/);
    assert.equal(await raw.count(), 0);
  });

  it("sealJobData is what the proxy uses (the same payload shape)", async () => {
    const s = await sealJobData(cp, "q", "n", { tenantId: "acme", x: 1 });
    assert.deepEqual(Object.keys(s).sort(), ["__cryplus", "sealed", "tenantId"]);
  });
});
