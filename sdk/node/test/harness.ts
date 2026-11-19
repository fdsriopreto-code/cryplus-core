import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const CORE_BIN = path.resolve(here, "../../../bin/cryplus-core.exe");
export const TOKEN = "test-token-0123456789abcdef";

async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as any).port;
      s.close(() => res(p));
    });
    s.on("error", rej);
  });
}

export interface Core {
  url: string;
  token: string;
  dir: string;
  auditPath: string;
  stop(): Promise<void>;
}

/** Spawn a real cryplus-core on a free port with a throwaway key file. */
export async function startCore(extraEnv: Record<string, string> = {}): Promise<Core> {
  const dir = mkdtempSync(path.join(tmpdir(), "cryplus-test-"));
  const port = await freePort();
  const auditPath = path.join(dir, "audit.jsonl");
  const child: ChildProcess = spawn(
    CORE_BIN,
    ["--listen", `127.0.0.1:${port}`, "--keyfile", path.join(dir, "keys.json"), "--audit-log", auditPath],
    { env: { ...process.env, CRYPLUS_TOKEN: TOKEN, ...extraEnv }, stdio: ["ignore", "ignore", "pipe"] },
  );
  let stderr = "";
  child.stderr!.on("data", (d) => (stderr += d));
  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      if ((await fetch(url + "/healthz")).ok) break;
    } catch {}
    if (child.exitCode !== null) throw new Error("core exited early: " + stderr);
    if (Date.now() > deadline) throw new Error("core did not start: " + stderr);
    await new Promise((r) => setTimeout(r, 50));
  }
  return {
    url,
    token: TOKEN,
    dir,
    auditPath,
    async stop() {
      child.kill();
      await new Promise((r) => child.once("exit", r));
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {}
    },
  };
}
