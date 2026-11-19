import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
// npm and .cmd shims need a shell on Windows; `node` must NOT go through one (quoting of -e code).
const sh = (cmd: string, args: string[], cwd: string, shell = false) => spawnSync(cmd, args, { cwd, encoding: "utf8", shell: shell && process.platform === "win32" });

// Packaging as the Operax Dockerfile would consume it: a vendored tarball, `npm install --omit=dev`, plain CommonJS, node:20-alpine.
describe("packaged SDK (tarball -> clean project)", () => {
  let work: string, tgz: string, app: string;

  before(() => {
    work = mkdtempSync(path.join(tmpdir(), "cryplus-pack-"));
    const build = sh(npm, ["run", "build"], root, true);
    assert.equal(build.status, 0, build.stderr);
    const pack = sh(npm, ["pack", "--pack-destination", work, "--silent"], root, true);
    assert.equal(pack.status, 0, pack.stderr);
    tgz = path.join(work, pack.stdout.trim().split(/\r?\n/).pop()!);
    app = path.join(work, "app");
    sh("node", ["-e", "require('fs').mkdirSync(process.argv[1])", app], work);
    writeFileSync(path.join(app, "package.json"), JSON.stringify({ name: "consumer", version: "1.0.0", private: true }));
    const install = sh(npm, ["install", tgz, "--omit=dev", "--no-audit", "--no-fund", "--offline"], app, true);
    assert.equal(install.status, 0, "installs with no network: " + install.stderr);
  });
  after(() => rmSync(work, { recursive: true, force: true }));

  it("has NO runtime dependencies and NO native add-ons (so it builds anywhere, including musl/Alpine)", () => {
    const pj = JSON.parse(readFileSync(path.join(app, "node_modules/cryplus/package.json"), "utf8"));
    assert.equal(pj.dependencies, undefined);
    assert.equal(pj.optionalDependencies, undefined);
    assert.equal(pj.scripts?.install, undefined);
    assert.equal(pj.scripts?.postinstall, undefined);
    assert.equal(pj.gypfile, undefined);
    const all: string[] = [];
    const walk = (d: string) => readdirSync(d).forEach((e) => (statSync(path.join(d, e)).isDirectory() ? walk(path.join(d, e)) : all.push(e)));
    walk(path.join(app, "node_modules/cryplus"));
    assert.deepEqual(all.filter((f) => /\.(node|so|dll|dylib)$|binding\.gyp$/.test(f)), []);
    assert.equal(readdirSync(path.join(app, "node_modules")).filter((d) => d !== ".package-lock.json" && d !== ".bin").join(","), "cryplus", "nothing else was installed");
  });

  it("ships only dist, and stays small", () => {
    const files: string[] = [];
    const walk = (d: string, rel = "") =>
      readdirSync(d).forEach((e) => {
        const p = path.join(d, e);
        statSync(p).isDirectory() ? walk(p, rel + e + "/") : files.push(rel + e);
      });
    walk(path.join(app, "node_modules/cryplus"));
    assert.ok(files.every((f) => f === "package.json" || f === "README.md" || f === "LICENSE" || f.startsWith("dist/")), files.filter((f) => !f.startsWith("dist/")).join(", "));
    assert.equal(files.some((f) => /test|\.ts$/.test(f) && !f.endsWith(".d.ts")), false);
    assert.ok(statSync(tgz).size < 300_000, `tarball is ${statSync(tgz).size} bytes`);
  });

  it("require() works from plain CommonJS (no flags), and import works from ESM", () => {
    const cjs = sh("node", ["-e", "const c=require('cryplus'); const m=c.Cryplus.inMemory(); m.encrypt({tenant:'t'},'x').then(ct=>m.decrypt({tenant:'t'},ct)).then(v=>{ if(v!=='x') process.exit(3); console.log(typeof c.withCryplus, typeof c.encryptedQueue, typeof c.rotateModel, typeof c.scanPaths) })"], app);
    assert.equal(cjs.status, 0, cjs.stderr);
    assert.equal(cjs.stdout.trim(), "function function function function");
    const esm = sh("node", ["--input-type=module", "-e", "import { Cryplus, parseSchema } from 'cryplus'; console.log(typeof Cryplus.inMemory, parseSchema('model A {\\n id String @id\\n}').size)"], app);
    assert.equal(esm.status, 0, esm.stderr);
    assert.equal(esm.stdout.trim(), "function 1");
  });

  it("the cryplus-scan binary is installed and runs", () => {
    const bin = path.join(app, "node_modules/.bin", process.platform === "win32" ? "cryplus-scan.cmd" : "cryplus-scan");
    assert.ok(existsSync(bin), "bin link missing");
    const help = sh(bin, ["--help"], app, true);
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /find raw SQL that touches @encrypted columns/);
    writeFileSync(path.join(app, "schema.prisma"), "model W {\n id String @id\n /// @encrypted\n secret String?\n @@map(\"webhooks\")\n}\n");
    writeFileSync(path.join(app, "bad.js"), "prisma.$queryRaw`SELECT secret FROM webhooks`;\n");
    const r = sh(bin, ["--schema", "schema.prisma", "--src", "bad.js"], app, true);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /bad\.js:1:\d+\s+error/);
  });
});
