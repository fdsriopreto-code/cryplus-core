import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { Cryplus, CryplusError } from "../src/index.ts";
import { CORE_BIN, startCore, type Core } from "./harness.ts";

// Two real cryplus-core processes share ONE passphrase-sealed key file: a leader and a follower.
let shared: string, keyfile: string;
let leader: Core, follower: Core;
const env = { CRYPLUS_PASSPHRASE: "ha test passphrase, long enough" };
const ctx = { tenant: "acme", collection: "User", field: "cpf" };
const only = (c: Core) => new Cryplus({ url: c.url, token: c.token, timeoutMs: 3000 });

before(async () => {
  shared = mkdtempSync(path.join(tmpdir(), "cryplus-ha-"));
  keyfile = path.join(shared, "keys.json");
  const common = ["--keyfile", keyfile, "--reload-interval", "100ms"];
  leader = await startCore(env, { args: common });
  follower = await startCore(env, { args: [...common, "--follower"] });
});
after(async () => {
  await leader.stop().catch(() => {});
  await follower.stop().catch(() => {});
  rmSync(shared, { recursive: true, force: true });
});

describe("high availability: leader + follower on a shared key file", () => {
  it("data encrypted through the leader decrypts through the follower, and vice versa", async () => {
    const ct = await only(leader).encrypt(ctx, "via leader");
    assert.equal(await only(follower).decrypt(ctx, ct), "via leader");
    const ct2 = await only(follower).encrypt(ctx, "via follower");
    assert.equal(await only(leader).decrypt(ctx, ct2), "via follower");
    // blind indexes must be identical on both instances, or search would break behind a load balancer
    assert.equal(await only(leader).blindIndex(ctx, "111"), await only(follower).blindIndex(ctx, "111"));
  });

  it("a follower refuses to rotate; the SDK finds the leader when several URLs are configured", async () => {
    await assert.rejects(only(follower).rotateKeys(), (e: CryplusError) => e.code === "read_only_instance");
    // follower listed FIRST on purpose: the client must skip it and rotate on the leader
    const both = new Cryplus({ url: [follower.url, leader.url], token: leader.token, timeoutMs: 3000 });
    const before = (await only(leader).keys()).current;
    assert.equal(await both.rotateKeys(), before + 1);
    both.close();
  });

  it("the follower adopts the new KEK version without a restart", async () => {
    const ct = await only(leader).encrypt(ctx, "after rotation"); // wrapped under the NEW version
    assert.equal(await only(follower).decrypt(ctx, ct), "after rotation");
    const deadline = Date.now() + 3000;
    let cur = 0;
    const lcur = (await only(leader).keys()).current;
    while (Date.now() < deadline && cur !== lcur) {
      cur = (await only(follower).keys()).current;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.equal(cur, lcur, "follower never moved to the leader's current version");
  });

  it("client failover: a dead instance in the list is skipped", async () => {
    const c = new Cryplus({ url: ["http://127.0.0.1:1", follower.url], token: follower.token, timeoutMs: 3000 });
    const ct = await c.encrypt(ctx, "failover");
    assert.equal(await c.decrypt(ctx, ct), "failover");
    c.close();
  });

  it("the service keeps working when the leader dies, and data stays readable by a restarted leader", async () => {
    const both = new Cryplus({ url: [leader.url, follower.url], token: leader.token, timeoutMs: 3000 });
    const before = await both.encrypt(ctx, "written before the crash");
    await leader.stop();
    // reads and writes continue on the follower
    assert.equal(await both.decrypt(ctx, before), "written before the crash");
    const during = await both.encrypt(ctx, "written during the outage");
    assert.equal(await both.decrypt(ctx, during), "written during the outage");
    // rotation is unavailable until a leader is back, and says so clearly
    await assert.rejects(both.rotateKeys(), (e: CryplusError) => e.code === "read_only_instance" || e.code.startsWith("unreachable"));
    // a new leader on the same key file reads what the follower wrote
    leader = await startCore(env, { args: ["--keyfile", keyfile, "--reload-interval", "100ms"] });
    assert.equal(await only(leader).decrypt(ctx, during), "written during the outage");
    both.close();
  });

  it("a follower refuses to start without an existing key file (it must never mint keys)", () => {
    const r = spawnSync(CORE_BIN, ["--listen", "127.0.0.1:0", "--follower", "--keyfile", path.join(shared, "nope.json"), "--audit-log", ""], {
      env: { ...process.env, ...env, CRYPLUS_TOKEN: "x".repeat(24) },
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /start the leader first/);
  });
});
