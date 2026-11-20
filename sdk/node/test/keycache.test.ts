import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { Cryplus, CryplusError, cryplusExtension, prometheusSink, Stats, withTenant } from "../src/index.ts";
import { hchacha20, parseEnvelope } from "../src/localcrypto.ts";
import { CORE_BIN, startCore, type Core } from "./harness.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const cli = (...args: string[]) => {
  const r = spawnSync(CORE_BIN, args, { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim();
};

let dir: string;
let tokens: string;
let keyfile: string;
let tokApp: string, tokCryptOnly: string, tokNarrow: string, tokOps: string;
const env = { CRYPLUS_PASSPHRASE: "keycache test passphrase, long enough" };
const ctx = { tenant: "acme", collection: "User", field: "cpf" };

const open = (extra: string[] = [], port?: number, e: Record<string, string> = env) =>
  startCore(e, { port, args: ["--keyfile", keyfile, "--tokens-file", tokens, "--allow-key-export", "--reload-interval", "100ms", ...extra] });
const client = (c: Core | number, token: string, o: ConstructorParameters<typeof Cryplus>[0] = {}) =>
  new Cryplus({ url: typeof c === "number" ? `http://127.0.0.1:${c}` : c.url, token, timeoutMs: 2000, ...o });

before(() => {
  dir = mkdtempSync(path.join(tmpdir(), "cryplus-kc-"));
  tokens = path.join(dir, "tokens.json");
  keyfile = path.join(dir, "keys.json");
  tokApp = cli("token", "new", "--name", "app", "--roles", "crypt,keys", "--tenants", "*", "--file", tokens);
  tokCryptOnly = cli("token", "new", "--name", "plain", "--roles", "crypt", "--tenants", "*", "--file", tokens);
  tokNarrow = cli("token", "new", "--name", "narrow", "--roles", "crypt,keys", "--tenants", "acme,beta", "--file", tokens);
  tokOps = cli("token", "new", "--name", "ops", "--roles", "admin", "--tenants", "*", "--file", tokens);
});
after(() => rmSync(dir, { recursive: true, force: true }));

describe("HChaCha20 (the primitive behind the local XChaCha20-Poly1305)", () => {
  it("matches the published test vector", () => {
    const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
    const nonce = Buffer.from("000000090000004a0000000031415927", "hex");
    assert.equal(hchacha20(key, nonce).toString("hex"), "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
  });
});

describe("local crypto interoperates with the Go service, byte for byte", () => {
  for (const [alg, localAlg] of [["xchacha20", "aes256gcm"], ["xchacha20", "xchacha20"], ["aes256gcm", "aes256gcm"], ["aes256gcm", "xchacha20"]] as const) {
    it(`service --alg ${alg}, local ${localAlg}: both directions, blind index, isolation, tamper`, async () => {
      const core = await open(["--alg", alg]);
      const svc = client(core, tokCryptOnly);
      const local = client(core, tokApp, { keyCache: true, localAlg });
      try {
        for (const s of ["", "123.456.789-00", "ação ✓ 日本語", "x".repeat(5000)]) {
          // written locally, read by the service
          const a = await local.encrypt(ctx, s);
          assert.equal(await svc.decrypt(ctx, a), s, `local->service ${JSON.stringify(s.slice(0, 8))}`);
          // written by the service, read locally
          const b = await svc.encrypt(ctx, s);
          assert.equal(await local.decrypt(ctx, b), s, `service->local ${JSON.stringify(s.slice(0, 8))}`);
        }
        assert.equal(await local.blindIndex(ctx, "12345678900"), await svc.blindIndex(ctx, "12345678900"), "blind indexes must be identical");
        // context binding and tenant isolation hold locally exactly as in the service
        const ct = await local.encrypt(ctx, "secret");
        for (const bad of [{ ...ctx, tenant: "beta" }, { ...ctx, field: "rg" }, { ...ctx, collection: "Other" }, { ...ctx, recordId: "7" }]) {
          await assert.rejects(local.decrypt(bad, ct), (e: CryplusError) => e.code === "decryption_failed");
          await assert.rejects(svc.decrypt(bad, ct), (e: CryplusError) => e.code === "decryption_failed");
        }
        const raw = Buffer.from(ct.slice(4), "base64url");
        for (const at of [2, 9, 40, raw.length - 1]) {
          const m = Buffer.from(raw);
          m[at] = m[at]! ^ 1;
          await assert.rejects(local.decrypt(ctx, "cp1." + m.toString("base64url")), (e: CryplusError) => ["decryption_failed", "malformed_ciphertext"].includes(e.code), `flip ${at}`);
        }
        await assert.rejects(local.decrypt(ctx, "cp1.garbage"), (e: CryplusError) => e.code === "malformed_ciphertext");
        await assert.rejects(local.encrypt({ tenant: "" }, "x"), (e: CryplusError) => e.code === "tenant_required");
      } finally {
        svc.close();
        local.close();
        await core.stop();
      }
    });
  }
});

describe("key cache behaviour (real core)", () => {
  let core: Core;
  before(async () => {
    core = await open();
  });
  after(() => core.stop());

  it("warm cache means ZERO round trips: 1 key fetch serves hundreds of operations, and the service audits the fetch, not each operation", async () => {
    const c = client(core, tokApp, { keyCache: true });
    const auditLines = () => readFileSync(core.auditPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const before = auditLines().length;
    const cts = await Promise.all(Array.from({ length: 300 }, (_, i) => c.encrypt({ ...ctx, tenant: "warm" }, "v" + i)));
    const back = await Promise.all(cts.map((ct) => c.decrypt({ ...ctx, tenant: "warm" }, ct)));
    assert.equal(back[299], "v299");
    const fresh = auditLines().slice(before).filter((l) => l.tenant === "warm");
    assert.deepEqual([...new Set(fresh.map((l) => l.op))], ["key_export"], "only key fetches reach the service");
    assert.equal(fresh.length, 1, "one fetch for the tenant, however many operations");
    assert.equal(fresh[0].service, "app");
    const st = c.stats();
    assert.ok(st.cache!.hits >= 599, `hits=${st.cache!.hits}`);
    assert.equal(st.counters['requests_total{mode="local",op="encrypt",result="ok"}'], 300);
    c.close();
  });

  it("is much faster than a round trip per call (informational timing)", async () => {
    const c = client(core, tokApp, { keyCache: true });
    const svc = client(core, tokCryptOnly);
    const c0 = { ...ctx, tenant: "perf" };
    await c.encrypt(c0, "warm up");
    const N = 5000;
    let t = performance.now();
    for (let i = 0; i < N; i++) await c.decrypt(c0, await c.encrypt(c0, "valor " + i));
    const local = performance.now() - t;
    t = performance.now();
    for (let i = 0; i < 300; i++) await svc.decrypt(c0, await svc.encrypt(c0, "valor " + i));
    const remote = ((performance.now() - t) / 300) * N;
    console.log(`    local: ${((local / N) * 1000).toFixed(0)} µs per encrypt+decrypt; service: ${((remote / N) * 1000).toFixed(0)} µs (sequential calls)`);
    assert.ok(local < remote, "local mode must beat a network round trip per call");
    c.close();
    svc.close();
  });

  it("the keys role is separate: a crypt-only token, or a tenant outside the allowlist, gets no key", async () => {
    const plain = client(core, tokCryptOnly, { keyCache: true });
    await assert.rejects(plain.encrypt(ctx, "x"), (e: CryplusError) => e.code === "role_forbidden");
    const narrow = client(core, tokNarrow, { keyCache: true });
    assert.match(await narrow.encrypt({ ...ctx, tenant: "beta" }, "ok"), /^cp1\./);
    await assert.rejects(narrow.encrypt({ ...ctx, tenant: "gamma" }, "x"), (e: CryplusError) => e.code === "tenant_forbidden");
    await assert.rejects(narrow.blindIndex({ ...ctx, tenant: "gamma" }, "x"), (e: CryplusError) => e.code === "tenant_forbidden");
    plain.close();
    narrow.close();
  });

  it("rotation: new data uses the new version after the cache expires; old data still opens (fetching its version)", async () => {
    const c = client(core, tokApp, { keyCache: { ttlMs: 250 } });
    const ops = client(core, tokOps);
    const t = { ...ctx, tenant: "rot" };
    const old = await c.encrypt(t, "before");
    assert.equal(parseEnvelope(old).version, 1);
    const v = await ops.rotateKeys();
    assert.ok(v >= 2);
    await sleep(300);
    const fresh = await c.encrypt(t, "after");
    assert.equal(parseEnvelope(fresh).version, v);
    assert.equal(await c.decrypt(t, old), "before");
    assert.equal(await c.decrypt(t, fresh), "after");
    c.close();
    ops.close();
  });

  it("max entries evicts the oldest keys", async () => {
    const c = client(core, tokApp, { keyCache: { maxEntries: 3 } });
    for (const tn of ["e1", "e2", "e3", "e4", "e5"]) await c.encrypt({ ...ctx, tenant: tn }, "x");
    assert.ok(c.stats().cache!.entries <= 3);
    c.close();
  });
});

describe("export is opt-in on the server", () => {
  it("without --allow-key-export the SDK says so clearly (and does not pretend the service is down)", async () => {
    const core = await startCore({}, { args: [] });
    try {
      const c = new Cryplus({ url: core.url, token: core.token, keyCache: true, timeoutMs: 2000 });
      await assert.rejects(c.encrypt(ctx, "x"), (e: CryplusError) => e.code === "key_export_disabled");
      c.close();
    } finally {
      await core.stop();
    }
  });
});

describe("availability: the key service goes away (real core, real process kill)", () => {
  it("warm cache keeps serving, cold tenants fail closed, expired keys fail closed after the stale window, and it recovers", async () => {
    let core = await open();
    const port = core.port;
    const c = client(port, tokApp, { keyCache: { ttlMs: 400, staleMs: 1200 }, circuitBreaker: { failureThreshold: 3, resetMs: 300 } });
    const A = { ...ctx, tenant: "tenant-a" }, B = { ...ctx, tenant: "tenant-b" };
    const ctA = await c.encrypt(A, "written while up");
    assert.equal(await c.blindIndex(A, "111") .then(() => "ok"), "ok");

    await core.stop(); // the service is gone

    // 1. inside the TTL: fully served from cache
    assert.equal(await c.decrypt(A, ctA), "written while up");
    assert.match(await c.encrypt(A, "written while down"), /^cp1\./);
    // 2. a tenant never seen before has no key: fail closed with a clear error
    await assert.rejects(c.encrypt(B, "x"), (e: CryplusError) => e.code === "key_service_unavailable");
    // 3. past the TTL but inside the stale window: still served (the service cannot be reached)
    await sleep(500);
    assert.equal(await c.decrypt(A, ctA), "written while up");
    assert.ok(c.stats().cache!.staleServed >= 1);
    // 4. the readiness probe tells the truth: degraded, not ok-as-usual and not dead
    const rd = await c.ready();
    assert.equal(rd.mode, "degraded");
    assert.equal(rd.ok, true);
    // 5. past ttl + stale: fail closed
    await sleep(1300);
    await assert.rejects(c.decrypt(A, ctA), (e: CryplusError) => e.code === "key_service_unavailable");
    await assert.rejects(c.encrypt(A, "x"), (e: CryplusError) => e.code === "key_service_unavailable");
    // 6. the breaker opened, so failures are now instant instead of waiting for a connect timeout
    const t0 = performance.now();
    await assert.rejects(c.encrypt(A, "x"), (e: CryplusError) => e.code === "key_service_unavailable");
    assert.ok(performance.now() - t0 < 100, "open circuit must fail fast");
    assert.equal((await c.ready()).breaker, "open");
    assert.equal((await c.ready()).mode, "down");

    // 7. the service comes back at the same address with the same key file: the client recovers by itself
    core = await open([], port);
    await sleep(350); // let the breaker's reset window pass
    assert.equal(await c.decrypt(A, ctA), "written while up", "data written before the outage still opens");
    assert.equal((await c.ready()).mode, "service");
    assert.equal(c.stats().breaker, "closed");
    c.close();
    await core.stop();
  });

  it("circuit breaker on the plain service path: opens after N failures, fails fast, half-opens and recovers", async () => {
    let core = await open();
    const port = core.port;
    const c = client(port, tokCryptOnly, { circuitBreaker: { failureThreshold: 3, resetMs: 300 }, timeoutMs: 800 });
    assert.match(await c.encrypt(ctx, "up"), /^cp1\./);
    await core.stop();
    for (let i = 0; i < 3; i++) await assert.rejects(c.encrypt(ctx, "x"), (e: CryplusError) => e.code.startsWith("unreachable"));
    const t0 = performance.now();
    await assert.rejects(c.encrypt(ctx, "x"), (e: CryplusError) => e.code === "circuit_open");
    assert.ok(performance.now() - t0 < 50);
    assert.equal(c.stats().counters['breaker_transitions_total{to="open"}'], 1);

    core = await open([], port);
    await sleep(350);
    assert.match(await c.encrypt(ctx, "back"), /^cp1\./);
    assert.equal(c.stats().breaker, "closed");
    // an ANSWER, even an error answer, keeps the breaker closed
    for (let i = 0; i < 5; i++) await assert.rejects(c.decrypt({ ...ctx, tenant: "evil" }, "cp1.garbage"), (e: CryplusError) => e.code === "malformed_ciphertext");
    assert.equal(c.stats().breaker, "closed");
    c.close();
    await core.stop();
  });

  it("the breaker can be disabled", async () => {
    const c = new Cryplus({ url: "http://127.0.0.1:1", token: "x".repeat(20), circuitBreaker: false, timeoutMs: 300 });
    for (let i = 0; i < 8; i++) await assert.rejects(c.encrypt(ctx, "x"), (e: CryplusError) => e.code.startsWith("unreachable"));
    assert.equal(c.stats().breaker, undefined);
    c.close();
  });
});

describe("metrics", () => {
  it("prometheusSink feeds prom-client-shaped Counter/Histogram objects with prefixed names", async () => {
    const made: Record<string, { type: string; labelNames: string[]; calls: any[] }> = {};
    const prom = {
      Counter: class { constructor(o: any) { made[o.name] = { type: "counter", labelNames: o.labelNames, calls: [] }; (this as any).n = o.name; } inc(l: any, v: number) { made[(this as any).n]!.calls.push([l, v]); } },
      Histogram: class { constructor(o: any) { made[o.name] = { type: "histogram", labelNames: o.labelNames, calls: [] }; (this as any).n = o.name; } observe(l: any, v: number) { made[(this as any).n]!.calls.push([l, v]); } },
    };
    const m = Cryplus.inMemory();
    const sink = prometheusSink(prom);
    sink.inc("requests_total", { op: "encrypt", mode: "local", result: "ok" });
    sink.inc("requests_total", { op: "encrypt", mode: "local", result: "ok" }, 2);
    sink.observe("request_seconds", 0.002, { op: "encrypt", mode: "local" });
    assert.deepEqual(made["cryplus_requests_total"]!.labelNames, ["op", "mode", "result"]);
    assert.equal(made["cryplus_requests_total"]!.calls.length, 2);
    assert.equal(made["cryplus_request_seconds"]!.type, "histogram");
    void m;
  });

  it("a real client reports requests, errors and cache events to the sink", async () => {
    const core = await open();
    const seen = new Stats();
    const c = client(core, tokApp, { keyCache: true, metrics: seen });
    await c.encrypt(ctx, "x");
    await c.encrypt(ctx, "y");
    await assert.rejects(c.decrypt(ctx, "cp1.garbage"));
    assert.equal(seen.get("requests_total", { op: "encrypt", mode: "local", result: "ok" }), 2);
    assert.equal(seen.get("errors_total", { code: "malformed_ciphertext" }), 1);
    assert.ok(seen.get("key_cache_total", { event: "hit" }) >= 1);
    assert.equal(seen.get("key_cache_total", { event: "miss" }) >= 1, true);
    assert.equal(c.stats().timings['request_seconds{mode="local",op="encrypt"}']!.count, 2);
    c.close();
    await core.stop();
  });

  it("the Prisma extension counts 'no tenant' and decryption failures by cause", async () => {
    const SCHEMA = "model U {\n id String @id\n tenantId String\n cpf String? /// @encrypted\n}";
    const sink = new Stats();
    const mem = Cryplus.inMemory();
    const hook = cryplusExtension({ cryplus: mem, schemaText: SCHEMA, metrics: sink }).query.$allModels.$allOperations as any;
    const run = (args: any, result: any = null) => hook({ model: "U", operation: "findFirst", args, query: async () => result });
    await assert.rejects(run({}, { id: "1", cpf: await mem.encrypt({ tenant: "a", collection: "U", field: "cpf" }, "1") }), /no tenant/);
    await withTenant("evil", () => assert.rejects(run({}, { id: "1", cpf: "cp1.zzz" })));
    await withTenant("a", () => assert.rejects(run({ where: { cpf: { contains: "1" } } }), /cannot|not supported/));
    assert.equal(sink.get("prisma_errors_total", { code: "no_tenant", model: "U", operation: "findFirst" }), 1);
    assert.equal(sink.get("prisma_errors_total", { code: "unsupported_query", model: "U", operation: "findFirst" }), 1);
  });
});

describe("mixed read/write load with the key cache (real core)", () => {
  it("8 workers x 5 tenants, local and service paths side by side, a key rotation AND a service restart in the middle: nothing lost, nothing wrong", async () => {
    let core = await open();
    const port = core.port;
    const app = client(port, tokApp, { keyCache: { ttlMs: 400, staleMs: 6000 }, circuitBreaker: false });
    const svc = client(port, tokCryptOnly, { circuitBreaker: false });
    const ops = client(port, tokOps);
    let stopped = false;
    try {
    const tenants = ["mx-0", "mx-1", "mx-2", "mx-3", "mx-4"];
    const c = (tenant: string, recordId?: string) => ({ tenant, collection: "Mensagem", field: "conteudo", ...(recordId ? { recordId } : {}) });
    let firstVersion = 0;
    for (const t of tenants) firstVersion = parseEnvelope(await app.encrypt(c(t), "warm")).version; // every tenant is warm before anything goes wrong

    type Rec = { tenant: string; id: string; plain: string; ct: string; by: "local" | "service" };
    const records: Rec[] = [];
    const errors: string[] = []; // wrong results, and ANY error on the local path
    const serviceErrors: string[] = []; // errors on the service path: only legitimate when the service was going away
    let outage = false;
    // After a rotation the service starts writing with the NEW version at once, while this process only learns it after the ttl.
    // Reading such a value needs a key this process has never fetched ("cold", and rightly fail-closed if the service is slow),
    // so service-side writes pause until the local cache has been warmed with the new version.
    let serviceWrites = true;
    const counts = { writes: 0, reads: 0, indexes: 0, serviceOps: 0 };
    const rnd = (n: number) => Math.floor(Math.random() * n);

    const worker = async (w: number) => {
      let i = 0;
      while (!stopped) {
        i++;
        await sleep(1); // pace the workers: this is a mixed load, not a flood
        const tenant = tenants[rnd(tenants.length)]!;
        const r = Math.random();
        let path: "local" | "service" = "local";
        let what = "";
        try {
          if (r < 0.45 || records.length < 20) {
            what = "encrypt";
            const id = `w${w}-${i}`;
            const plain = `msg ${id} ${"x".repeat(rnd(200))} ação`;
            const useService = !outage && serviceWrites && Math.random() < 0.3;
            path = useService ? "service" : "local";
            const ct = await (useService ? svc : app).encrypt(c(tenant, id), plain);
            if (useService) counts.serviceOps++;
            records.push({ tenant, id, plain, ct, by: useService ? "service" : "local" });
            counts.writes++;
          } else if (r < 0.9) {
            what = "decrypt";
            const rec = records[rnd(records.length)]!;
            const useService = !outage && Math.random() < 0.3;
            path = useService ? "service" : "local";
            const got = await (useService ? svc : app).decrypt(c(rec.tenant, rec.id), rec.ct);
            if (useService) counts.serviceOps++;
            if (got !== rec.plain) errors.push(`wrong plaintext for ${rec.id} (written ${rec.by}, read ${useService ? "service" : "local"})`);
            counts.reads++;
          } else {
            what = "blindIndex";
            const v = String(rnd(1000));
            const local = await app.blindIndex(c(tenant), v);
            if (!outage) {
              path = "service";
              const remote = await svc.blindIndex(c(tenant), v);
              if (local !== remote) errors.push("blind index differs between local and service");
              counts.serviceOps++;
            }
            counts.indexes++;
          }
        } catch (e) {
          (path === "local" ? errors : serviceErrors).push(`${path} ${what} t+${Date.now() - t0}ms outage=${outage}: ${(e as Error).message}`);
        }
      }
    };

    const t0 = Date.now();
    const workers = Array.from({ length: 8 }, (_, w) => worker(w));
    await sleep(600);
    serviceWrites = false;
    const version = await ops.rotateKeys(); // new data will use the new version once the cache refreshes
    await sleep(500); // > ttl: the cache now refreshes its view of the current version
    for (const t of tenants) assert.equal(parseEnvelope(await app.encrypt(c(t), "warm v2")).version, version);
    serviceWrites = true;
    await sleep(300);
    outage = true; // workers stop using the service path (the local path must keep working)...
    await sleep(150); // ...let the service calls already in flight finish
    await core.stop(); // the service disappears under load
    await sleep(900);
    core = await open([], port); // and comes back at the same address with the same key file
    await sleep(500);
    outage = false;
    await sleep(500);
    stopped = true;
    await Promise.all(workers);

    assert.deepEqual([...new Set(errors)].slice(0, 5), [], `errors during the run: ${errors.length}`);
    // a service call may fail only because the service was being stopped (in flight at that instant), never for another reason
    assert.deepEqual(serviceErrors.filter((e) => !/unreachable|ECONNRESET|ECONNREFUSED|socket hang up/.test(e)), []);
    assert.ok(serviceErrors.length < 40, `service-path errors: ${serviceErrors.length}`);
    assert.ok(counts.writes > 300 && counts.reads > 300, JSON.stringify(counts));
    // everything ever written (locally or by the service, before, during and after the outage) opens, on both paths
    let versions = new Set<number>();
    for (const rec of records) versions.add(parseEnvelope(rec.ct).version);
    const sample = (n: number) => Array.from({ length: Math.min(n, records.length) }, () => records[rnd(records.length)]!);
    const byService = records.filter((r) => r.by === "service").slice(0, 100);
    for (const rec of [...sample(400), ...byService]) assert.equal(await svc.decrypt(c(rec.tenant, rec.id), rec.ct), rec.plain, `${rec.id} via service`);
    for (const rec of sample(300)) assert.equal(await app.decrypt(c(rec.tenant, rec.id), rec.ct), rec.plain, `${rec.id} via local`);
    assert.ok(versions.has(firstVersion) && versions.has(version), `both key versions were used: ${[...versions]}`);
    const st = app.stats().cache!;
    // lookups answered without waiting for the service: fresh hits plus stale keys served; only real misses cost a round trip
    const lookups = st.hits + st.misses + st.staleServed;
    assert.ok(st.misses / lookups < 0.15, `cache misses ${(st.misses / lookups).toFixed(3)} of lookups (${JSON.stringify(st)})`);
    assert.ok(st.staleServed >= 1, "the outage was ridden out on stale keys");
    assert.equal(st.fetchErrors > 0, true);
    console.log(`    mixed load: ${JSON.stringify(counts)}, records ${records.length}, versions ${[...versions]}, cache ${JSON.stringify(st)}`);
    } finally {
      // always release everything, so a failed assertion cannot leave a core process or open sockets behind
      stopped = true;
      app.close();
      svc.close();
      ops.close();
      await core.stop();
    }
  });
});
