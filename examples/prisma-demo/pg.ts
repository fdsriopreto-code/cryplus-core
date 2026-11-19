// Starts an ISOLATED Postgres for the demo/e2e tests.
// Data dir: d:\cryplus\.pgdata (never touches other Postgres installs), port 54329.
import EmbeddedPostgres from "embedded-postgres";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = path.resolve(here, "../../.pgdata");
const fresh = !existsSync(path.join(dir, "PG_VERSION"));

const pg = new EmbeddedPostgres({
  databaseDir: dir,
  user: "cryplus",
  password: "cryplus",
  port: 54329,
  persistent: true,
});

if (fresh) await pg.initialise();
await pg.start();
if (fresh) await pg.createDatabase("cryplus_demo");
console.log("POSTGRES_READY postgresql://cryplus:cryplus@127.0.0.1:54329/cryplus_demo");

const stop = async () => {
  await pg.stop();
  process.exit(0);
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
setInterval(() => {}, 1 << 30);
