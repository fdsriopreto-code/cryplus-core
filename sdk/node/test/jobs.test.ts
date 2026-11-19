import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cacheKey, Cryplus, currentTenant, encryptedQueue, encryptedWorker, isSealedJob, openJobData, sealJobData, withTenant } from "../src/index.ts";

// A stand-in for BullMQ that records exactly what would be written to Redis, and replays it to a processor.
// (BullMQ itself needs a Redis server, which is not available here: see docs.)
class FakeQueue {
  name: string;
  redis: { name: string; data: any; opts?: any }[] = [];
  other = "untouched";
  constructor(name: string) {
    this.name = name;
  }
  async add(name: string, data: any, opts?: any) {
    this.redis.push({ name, data: structuredClone(data), opts });
    return { id: String(this.redis.length) };
  }
  async addBulk(jobs: { name: string; data: any; opts?: any }[]) {
    for (const j of jobs) await this.add(j.name, j.data, j.opts);
    return jobs.map((_, i) => ({ id: String(i) }));
  }
  getName() {
    return this.name;
  }
}
const asJob = (q: FakeQueue, i = 0) => ({ name: q.redis[i]!.name, queueName: q.name, data: structuredClone(q.redis[i]!.data) });

describe("sealed jobs", () => {
  const cp = Cryplus.inMemory();

  it("Redis holds no plaintext field, only the tenant id, and the worker sees the data and the tenant", async () => {
    const q = encryptedQueue(new FakeQueue("pdf-generation"), cp);
    const orcamento = { cliente: { nome: "Maria Silva", cpf: "123.456.789-00" }, endereco: "Rua das Flores 10" };
    await q.add("render", { tenantId: "acme", orcamento }, { attempts: 3, delay: 1000 });

    const stored = (q as unknown as FakeQueue).redis[0]!;
    assert.deepEqual(Object.keys(stored.data).sort(), ["__cryplus", "sealed", "tenantId"]);
    assert.equal(stored.data.tenantId, "acme");
    const blob = JSON.stringify(stored);
    for (const s of ["Maria Silva", "123.456.789-00", "Rua das Flores", "cliente", "endereco"]) assert.equal(blob.includes(s), false, `${s} visible in Redis`);
    assert.deepEqual(stored.opts, { attempts: 3, delay: 1000 }, "job options pass through untouched");

    let seen: any, tenant: string | undefined;
    const run = encryptedWorker(cp, async (job: any) => {
      seen = job.data;
      tenant = currentTenant();
      return "ok";
    });
    assert.equal(await run(asJob(q as unknown as FakeQueue)), "ok");
    assert.deepEqual(seen, { tenantId: "acme", orcamento });
    assert.equal(tenant, "acme", "the processor runs inside withTenant automatically");
    assert.equal(currentTenant(), undefined, "and the tenant does not leak out of it");
  });

  it("other queue methods and properties pass through; addBulk seals every job", async () => {
    const fq = new FakeQueue("email-delivery");
    const q = encryptedQueue(fq, cp);
    assert.equal(q.other, "untouched");
    assert.equal(q.getName(), "email-delivery");
    await q.addBulk([
      { name: "invite", data: { tenantId: "t1", email: "a@x.com", token: "tok-1" } },
      { name: "invite", data: { tenantId: "t2", email: "b@x.com", token: "tok-2" } },
    ]);
    assert.equal(fq.redis.length, 2);
    assert.ok(fq.redis.every((j) => isSealedJob(j.data)));
    assert.equal(JSON.stringify(fq.redis).includes("tok-1"), false);
    assert.deepEqual(fq.redis.map((j) => j.data.tenantId), ["t1", "t2"]);
  });

  it("uses the ambient tenant when the data has none, and fails closed when there is none at all", async () => {
    const fq = new FakeQueue("geocodificacao");
    const q = encryptedQueue(fq, cp);
    await withTenant("amb", () => q.add("geocode", { obraId: 1, endereco: "Av. Brasil 100" }));
    assert.equal(fq.redis[0]!.data.tenantId, "amb");
    await assert.rejects(q.add("geocode", { obraId: 2 }), /no tenant for this job/);
    assert.equal(fq.redis.length, 1, "nothing was enqueued");
  });

  it("a sealed payload is bound to its queue, job name and tenant (replay and swap are refused)", async () => {
    const a = new FakeQueue("webhook-delivery");
    await encryptedQueue(a, cp).add("deliver", { tenantId: "acme", secret: "whsec_1" });
    const fresh = () => asJob(a); // the worker opens job.data in place, so every attempt gets its own copy
    const run = encryptedWorker(cp, async () => "processed");
    assert.equal(await run(fresh()), "processed");
    await assert.rejects(run({ ...fresh(), queueName: "email-delivery" }), (e: any) => e.code === "decryption_failed");
    await assert.rejects(run({ ...fresh(), name: "other" }), (e: any) => e.code === "decryption_failed");
    await assert.rejects(run({ ...fresh(), data: { ...fresh().data, tenantId: "evil" } }), (e: any) => e.code === "decryption_failed");
    const tampered = fresh();
    tampered.data.sealed = tampered.data.sealed.slice(0, -4) + "AAAA";
    await assert.rejects(run(tampered), (e: any) => e.code === "decryption_failed");
  });

  it("jobs enqueued before rollout (plain data) still run, inside their tenant, unless allowPlain is false", async () => {
    let tenant: string | undefined;
    const plain = { name: "render", queueName: "q", data: { tenantId: "old-co", x: 1 } };
    const lenient = encryptedWorker(cp, async () => (tenant = currentTenant()));
    await lenient(plain);
    assert.equal(tenant, "old-co");
    const strict = encryptedWorker(cp, async () => "no", { allowPlain: false });
    await assert.rejects(strict(plain), /not sealed/);
  });

  it("works with a processor that throws (the tenant scope is still cleaned up)", async () => {
    const fq = new FakeQueue("q");
    await encryptedQueue(fq, cp).add("j", { tenantId: "acme" });
    await assert.rejects(encryptedWorker(cp, async () => { throw new Error("boom"); })(asJob(fq)), /boom/);
    assert.equal(currentTenant(), undefined);
  });

  it("sealJobData / openJobData round trip and custom tenant field", async () => {
    const s = await sealJobData(cp, "q", "n", { empresa: "e1", v: 1 }, { tenantField: "empresa" });
    assert.equal(s.tenantId, "e1");
    assert.deepEqual(await openJobData(cp, "q", "n", s), { empresa: "e1", v: 1 });
  });

  it("cacheKey never contains the secret and is stable", () => {
    const k = cacheKey("apikey", "sk_live_abcdef");
    assert.equal(k, cacheKey("apikey", "sk_live_abcdef"));
    assert.equal(k.includes("sk_live"), false);
    assert.match(k, /^apikey:[0-9a-f]{64}$/);
    assert.notEqual(k, cacheKey("apikey", "sk_live_abcdeg"));
  });
});
