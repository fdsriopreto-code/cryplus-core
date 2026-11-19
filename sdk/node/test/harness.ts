import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const CORE_BIN = path.resolve(here, "../../../bin/cryplus-core.exe");
export { here as TEST_DIR };
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
  port: number;
  url: string;
  token: string;
  dir: string;
  auditPath: string;
  stop(): Promise<void>;
}

/** Spawn a real cryplus-core on a free port with a throwaway key file. */
export interface CoreOptions {
  /** Extra command-line args (e.g. --tls-cert ...). */
  args?: string[];
  scheme?: "http" | "https";
  /** Use a bare TCP connect for readiness (needed when mTLS rejects an anonymous health probe). */
  waitTcp?: boolean;
  /** Listen on this port instead of a free one (to restart a core at the same address). */
  port?: number;
}

export async function startCore(extraEnv: Record<string, string> = {}, o: CoreOptions = {}): Promise<Core> {
  const dir = mkdtempSync(path.join(tmpdir(), "cryplus-test-"));
  const port = o.port ?? (await freePort());
  const auditPath = path.join(dir, "audit.jsonl");
  const child: ChildProcess = spawn(
    CORE_BIN,
    ["--listen", `127.0.0.1:${port}`, "--keyfile", path.join(dir, "keys.json"), "--audit-log", auditPath, ...(o.args ?? [])],
    { env: { ...process.env, CRYPLUS_TOKEN: TOKEN, ...extraEnv }, stdio: ["ignore", "ignore", "pipe"] },
  );
  let stderr = "";
  child.stderr!.on("data", (d) => (stderr += d));
  const url = `${o.scheme ?? "http"}://127.0.0.1:${port}`;
  const deadline = Date.now() + 10_000;
  const tcpUp = () =>
    new Promise<boolean>((res) => {
      const s = connect(port, "127.0.0.1", () => (s.destroy(), res(true)));
      s.on("error", () => res(false));
    });
  for (;;) {
    try {
      if (o.waitTcp ? await tcpUp() : (await fetch(url + "/healthz")).ok) break;
    } catch {}
    if (child.exitCode !== null) throw new Error("core exited early: " + stderr);
    if (Date.now() > deadline) throw new Error("core did not start: " + stderr);
    await new Promise((r) => setTimeout(r, 50));
  }
  return {
    port,
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
