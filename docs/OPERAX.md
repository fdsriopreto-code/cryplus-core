# Integrating Cryplus into Operax

Based on two read-only surveys of the `metal-flow-back-end` repository (Express 4, plain JavaScript/CommonJS, Prisma 5.22 without a
driver adapter, one `PrismaClient`, BullMQ + Redis, S3-compatible storage, `node:20-alpine`) and on the improvement requests the Operax
team wrote from them. **This repository has never seen the Operax code.** What is verified here is the same stack in a faithful test
project (`examples/prisma5-cjs`: 40 compatibility tests in two modes (real `cryplus-core` and the in-memory
test client), a 94-test oracle/feature suite, real BullMQ+Redis and Alpine/musl runs). Anything that depends on Operax itself is marked **VERIFY**.

> **Correction.** An earlier version of this guide said "the column type does not change". That is wrong for `VarChar(n)` columns:
> a 14-character CPF becomes a 183-character ciphertext. See [Column types and sizes](#column-types-and-sizes).

## Order of work

| Wave | What | Status |
|---|---|---|
| **0** | Hash one-time secrets; restrict the public bucket; encrypt database backups; run `cryplus-scan` | Independent of the extension |
| **1** | Secrets nobody searches: OAuth/payment tokens, webhook secrets, PIX key (new column), notes | Ready |
| **2** | CPF/CNPJ/documento with equality search; message bodies after the two code changes below | Ready; needs the unique-key and `VarChar` changes |
| **3** | Phone numbers and e-mail: suffix and global indexes now exist | Features built and tested; the Operax-side change (8 tables at once, the BR phone rule, lookups before the tenant) is still yours to confirm |

## Step 0: find every raw query (do this first)

Raw SQL bypasses the Prisma extension: a SELECT returns ciphertext and an INSERT/UPDATE stores plaintext, both silently.
There are three layers of protection, in the order you will use them:

**1. The scanner** (CI-friendly, no database needed). It reads `schema.prisma`, resolves the real column and table names (`@map`, `@@map`),
and finds raw calls whose SQL mentions an encrypted column, selects every column of an encrypted table, or inserts without a column list.
SQL built at runtime is reported as "cannot analyze", never skipped.

```bash
npx cryplus-scan --schema prisma/schema.prisma --src src
# src/controllers/webhooks.controller.js:57:10  error    $queryRaw  Webhook (webhooks): mentions encrypted column(s) secret
# src/services/x.js:12:3  dynamic  $queryRawUnsafe  cannot analyze: SQL comes from `buildQuery(filters)`. Review by hand, then add ...
# exit status 1; 0 = clean; 2 = usage or schema error. --format json, --allow-dynamic
```

It understands tagged templates (including nested `${}`), `Unsafe` calls, string concatenation, `Prisma.sql`, and same-file constants.
Silence a reviewed call with `// cryplus-ignore-next-line: <reason>` on the line before it, or `/* cryplus:handled */` inside the SQL.
SQL assembled by helper functions (`CANON('f.celular')` in `tenant.controller.js`) cannot be read, but you can **declare** what it touches on the line(s) before the call
(up to three lines above), and then it is checked instead of ignored:

```js
// cryplus-columns: funcionarios.celular, tenants.telefone
const rows = await prisma.$queryRawUnsafe(buildPhoneQuery(CANON('f.celular')), tenantId);
```

An encrypted column in the list is an error, so is a typo or an unknown table; `table.*` means every column. Plain columns clear the "cannot analyze" note for that call.

The scanner also reads **Prisma calls** (`prisma.mensagem.findMany({...})`, `tx.x`, `this.prisma.x`) and reports what the extension would refuse at runtime, so it shows up in CI instead of in production:
`contains/startsWith/gt/gte/lt/lte/search` on an encrypted field, equality on an encrypted field that is not `searchable`, and `orderBy` / `groupBy by` / `distinct` / `_min _max _sum _avg` on one.
It follows relations two levels deep, so `conversa.findMany({ where: { mensagens: { some: { conteudo: { contains } } } } })` is found. It is a token-level reader, not a type checker: a same-named
field on another model can produce a false positive (silence it with `cryplus-ignore-next-line`), and a query built in a variable is not seen.

A `*` is reported only as a select-list star (after `SELECT`, `DISTINCT` or a comma, followed by a comma or `FROM`); `COUNT(...) * 100.0` is not one.

It does **not** analyze SQL sent through a direct `pg` client (it lists those files as `info`). Run it on the Operax repo and treat
"zero errors, every dynamic query reviewed" as the exit criterion for each wave.

**2. The runtime guard** (on by default). The extension refuses raw SQL that mentions an encrypted column, in all four forms
(`$queryRaw`, `$queryRawUnsafe`, `$executeRaw`, `$executeRawUnsafe`), verified on Prisma 5.22 and 7.10. `rawGuard: "warn" | "off"` to relax it.
The base (non-extended) client is never affected, which is what migrations should use.

**3. The helpers** for the places raw SQL cannot be avoided (`prisma.$cryplus`):

```js
// reviewed SELECT: decrypt the rows (batched, tenant-aware, aliases supported)
const rows = await prisma.$queryRawUnsafe(`SELECT id, secret /* cryplus:handled */ AS whsec FROM webhooks WHERE tenant_id = $1`, tenantId);
await prisma.$cryplus.decryptRows('Webhook', rows, { columns: { whsec: 'secret' } });

// raw WHERE on a blind index, and raw INSERT/UPDATE with the same values the extension would write
const idx  = await prisma.$cryplus.index('Funcionario', 'cpf', '123.456.789-00');         // use in: WHERE cpf_idx = $1
const ct   = await prisma.$cryplus.encryptValue('Funcionario', 'cpf', '123.456.789-00');   // the stored ciphertext
const cols = await prisma.$cryplus.indexColumns('Funcionario', 'cpf', '123.456.789-00');   // every companion index column to write with it
```

For substring search over encrypted text (a bounded candidate set, decrypted and filtered in memory):

```js
const hits = await prisma.$cryplus.searchDecrypted(prisma.mensagem, 'Mensagem', {
  where: { conversaId },                         // required, non-empty: narrows the candidate set
  predicate: (m) => m.conteudo.toLowerCase().includes(termo),
  limit: 50, maxScan: 5000,                      // refuses to scan more than maxScan rows
});
```

## Wave 0 (no extension involved)

**1. Hash tokens instead of encrypting them.** `ApiKey.key` and other random bearer secrets that are shown **once** (invite tokens): store `sha256(token)`
and look up by the hash, like a password. Tokens that Operax re-sends and re-displays (`tokenAprovacao`, `tokenAcompanhamento`, `portalConviteToken`) need
encryption plus an index instead, because the plaintext must be recoverable.

```js
const crypto = require('node:crypto');
const sha256 = (t) => crypto.createHash('sha256').update(t).digest('hex');
// create: const raw = crypto.randomBytes(32).toString('hex'); store sha256(raw); show raw to the user ONCE
// lookup: WHERE key_hash = ${sha256(presented)}
```

**Caches**: never use a plaintext secret as a cache or Map key (Redis keys show up in `MONITOR`, `SCAN` and dumps). `cacheKey('apikey', key)`
returns `apikey:<sha256>`. For low-entropy values (CPF, phone) use `$cryplus.index(...)`, which is keyed per tenant.

**2. The bucket has public read on the whole `operax/` prefix** (`documentos`, `funcionarios`, `whatsapp` included). Product decision: **VERIFY**.

**3. Encrypt the `pg_dump` backups** (plaintext for up to 12 months of retention): pipe `pg_dump`'s stdout through the service before the upload.

```js
const dump = spawn('pg_dump', ['--format=custom', ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
const ctx = { tenant: `backup:${yyyyMm}`, collection: 'backups', field: objectKey };   // bound to the object name
const encrypted = await cryplus.encryptStream(ctx, dump.stdout);
await new Upload({ client: s3, params: { Bucket, Key: objectKey, Body: encrypted } }).done();
// check pg_dump's exit code: a failed dump must fail the job, not upload a truncated file
```

Use a service token limited to `--tenants 'backup:*'`. Restore with `cryplus-core file decrypt` (works with no service running; DEPLOY.md §5).
**Not tested here:** `pg_dump` itself (a synthetic dump goes through the same stream path) and your Easypanel runtime. Do a full restore drill in staging.

## Column types and sizes

A ciphertext is much longer than its plaintext. The exact length of the stored text is

```
raw  = 8 + 72 + nonce + plaintext_bytes + 16        nonce = 24 (xchacha20, default) or 12 (aes256gcm)
text = 4 + ceil(raw * 4 / 3)                        ("cp1." prefix + unpadded base64url)
```

so `text = 4 + ceil(4 * (120 + n) / 3)` for xchacha20 (n = UTF-8 bytes). Verified byte for byte against the real service. A 14-character ASCII CPF is
**183** characters; a blind-index value is always **47**. Helpers: `ciphertextLength(n, alg)` and `INDEX_TEXT_LENGTH`.

The schema parser enforces this. It refuses `@encrypted` on `@db.VarChar(n)` / `@db.Char(n)` too short for the value and prints the migration with the
**real** names (`@map`/`@@map`); index columns are checked too:

```
Funcionario.cpf: column is @db.VarChar(14) but an encrypted value of up to 14 characters needs 239 ...
    run first: ALTER TABLE "funcionarios" ALTER COLUMN "cpf" TYPE text;
```

A `VarChar` that is big enough is accepted when you state the plaintext maximum: `/// @encrypted(max(14))` on a `VarChar(300)`. Otherwise change the column to `text`
(additive and cheap in PostgreSQL: `varchar(n)` to `text` does not rewrite the table). In the Operax schema this affects at least `Funcionario.cpf/rg`,
`Tenant/Cliente/Prestador.cpfCnpj` and `Fornecedor.documento`. Wave 1 secrets (`Text`/plain `String`) need nothing.

## Supported column types

| Prisma type | Support |
|---|---|
| `String` | yes (all options) |
| `String[]` | yes: each element is encrypted; `{ set }` and `{ push }` work; only `isEmpty` can filter it |
| `Json` | yes: stored as an encrypted JSON string; reads give the original value back; cannot be filtered |
| `DateTime` (`@db.Date`) | **no**: a date column cannot hold ciphertext. Add a `String` column (`nascimentoEnc String? /// @encrypted`), store the ISO date there, migrate, and drop the old one |
| `Int`, `Decimal`, `Boolean`... | no (the parser says so, with this hint) |

## Searching encrypted fields

| Need | Option | Notes |
|---|---|---|
| Equality (`=`, `in`, `not`) | `@encrypted(searchable)` + `<field>Idx` | per tenant; the same value in two tenants gives different indexes |
| Equality across tenants (lookup **before** the tenant is known: login, phone to tenant) | `@encrypted(global)` + `<field>GIdx` | separate key domain; **makes cross-tenant equality visible**. A global-only field is searched with no tenant context; reading its decrypted value still needs one |
| Last N characters (`endsWith`) | `@encrypted(suffix(4), suffix(8))` + `<field>Sfx4/8` | per tenant only; the filter value must have exactly an indexed length after normalization. 4 digits have little entropy: it leaks more (frequency groups of 10^4) |
| Substring / ILIKE | none | use `$cryplus.searchDecrypted` on a bounded set. An n-gram index is **not** implemented |
| Ordering, distinct, groupBy, `_min/_max/_sum/_avg` | none | **throws** instead of returning wrong results; `count` works |

### How filters on encrypted fields behave

- **Equality only**, on `searchable` (per tenant) or `global` fields: `value`, `equals`, `in`, `not`, `notIn`, `null`, `not: null`, `endsWith` (with `suffix(n)`).
  Everything else (`contains`, `startsWith`, `gt`, `mode`, `search`...) **throws**, also under `NOT`, `AND`, `OR`, in relation filters and in `_count`.
- They work at any depth: `NOT`, `NOT: [...]`, `AND`, `OR`, relation `some/every/none/is/isNot`, `include { where }`, `_count { where }`. **Semantics are exactly those of a plaintext column**,
  including SQL's treatment of `NULL` (Prisma's `NOT` and `not` do not return rows whose column is `NULL`). That is not an assumption: `examples/prisma5-cjs/oracle.test.js` runs
  {equals, in, not, notIn, null, undefined, ...} x {top level, NOT, NOT[], AND, AND[NOT], OR, OR[NOT], NOT[OR], NOT[AND], NOT[NOT]} x {plain on a twin column, encrypted} and relation
  `some/none/every` (also negated), and requires identical row sets (66 tests, real Postgres). Add your own filter shapes to its `LEAVES` / `POSITIONS` lists.
- **Fail closed.** After rewriting, every filter is walked once more; a condition on an encrypted column that was not rewritten is refused (`filter on an encrypted field was not
  rewritten`) instead of being sent. `orderBy` is checked through relations too.
- **`undefined` means "no filter"**, exactly as in Prisma (top level, inside `AND/OR/NOT`, as an operand, in `where` of a relation, in compound keys).
- If a query returns rows you do not expect, first check that it goes through the **extended** client: a second `PrismaClient`, or the base client, bypasses the extension (it then compares
  plaintext with ciphertext and matches nothing, or everything under a negation). Keep a single exported, extended client.

Normalizers (applied to the stored value and to every filter value): `trim` (always), `lowercase`, `digits`, `fold` (lowercase + strip accents, the effect
of `translate(lower(x), 'áàãâéêíóôõúüç', 'aaaaeeiooouuc')`), `email-lower`, `br-phone-canonical`.
`br-phone-canonical` as specified from the survey: digits only; drop a leading `55` when the number has 12 or 13 digits; for an 11-digit mobile number drop the
extra `9` after the DDD (so `(11) 91234-5678`, `11912345678`, `+55 11 91234-5678` and the old `(11) 1234-5678` are equal). **VERIFY** this against the SQL it replaces
(`tenant.controller.js:330-334`) with real numbers before relying on it.

Compound unique keys keep working: after moving uniqueness to the index (`@@unique([tenantId, cpfIdx])`) code that calls
`findUnique({ where: { tenantId_cpf: { tenantId, cpf } } })`, `upsert` or `update` with that key is rewritten automatically (tested).

### A searchable field on a table that already has data (safe order)

While a table is half-migrated, a plaintext row has an **empty index column**, so an equality lookup does not see it and a "CPF already registered" check lets a duplicate through. Order:

1. Add the index column (additive migration) and deploy code with the `/// @encrypted(searchable)` comment.
2. **`migrateModel({ mode: 'index-only' })`**: fills the index of every row, **including rows that are still plaintext** (it computes the index from the plaintext and leaves the value alone).
3. Deploy the equality code. From here a lookup finds old and new rows.
4. `migrateModel({ mode: 'all' })` encrypts the values (the index is already there).

If code that depends on equality must go out *before* step 2 finishes, use `legacy: 'fallback'` for the window: `{ f: X }` becomes `OR [{ fIdx: idx(X) }, { f: X }]` (equals / in only; `not`/`notIn`
throw in this mode, equality under `NOT` is fine). Turn it off once the backfill is done: it costs an extra OR and exists only for the window.

## Tests with encryption ON, no network

```js
const { createCryplus } = require('cryplus');
const cryplus = createCryplus();        // CRYPLUS_MODE=memory -> in-process test client; otherwise the real one
// or explicitly: Cryplus.inMemory({ seed: 'tests', deterministic: true })
```

Same API, no key service, no mTLS. Keys derive from a seed, so runs are repeatable; `deterministic: true` also makes ciphertext repeatable (snapshots). It uses the **same ciphertext
length** as production (so column-size bugs show up) but a different format byte, so it can never be confused with real data, and it **refuses to start with
`NODE_ENV=production`**. The whole `examples/prisma5-cjs` suite passes in this mode (`CRYPLUS_MODE=memory`). Running Operax's own PGlite suite is yours to do: **VERIFY**.

## Jobs (BullMQ / Redis)

BullMQ stores `job.data` in clear text. Seal it:

```js
const { encryptedQueue, encryptedWorker } = require('cryplus');
const queue = encryptedQueue(new Queue('pdf-generation', { connection }), cryplus);     // add / addBulk seal the data
await queue.add('render', { tenantId, orcamento });     // Redis holds { __cryplus: 1, tenantId, sealed: "cp1..." }
new Worker('pdf-generation', encryptedWorker(cryplus, async (job) => { /* job.data is plain again, tenant is set */ }), { connection });
```

The payload is bound to the queue and job name (replay into another queue or job type is refused) and the worker runs inside `withTenant(job tenant)`, so Prisma works with no extra code.
Still in clear in Redis: job name, options, the **tenant id**. Not covered: `returnvalue`, `failedReason`, stack traces and logs (do not put secrets in them), `job.updateData`, repeatable-job keys you build from data.
Passing only an id and letting the worker read the row is better than sealing. Tested against a **real BullMQ 5 and a real Redis 7** (`examples/bullmq-redis`, needs Docker, 10 tests): the whole Redis keyspace (hashes, lists, sorted sets, streams) is searched for the
plaintext after enqueue, during a failing attempt and after completion; retries with backoff, `addBulk`, delayed and prioritised jobs, replay into another queue, `allowPlain`, and no-tenant fail-closed.
The same test shows the limit: a **return value** or an **error message** that contains the data is stored in clear. The hand-over to your own queue code in staging is still yours to **VERIFY**. `allowPlain` (default true) lets jobs enqueued before the rollout still run.

## Availability and latency

Default mode: every operation goes to the key service (concurrent operations share the connection pool; there is no multi-operation batch endpoint, so a 200-row list is 200 small requests issued together).
**A write no longer pays a second round trip**: the values `create`/`update`/`upsert` just encrypted are remembered for that one operation, so the row Prisma returns is read back
**without calling `decrypt`** (a later `find` still decrypts; nothing is cached across operations). Measured on one machine (Windows, local Postgres 17 on loopback, real `cryplus-core`, 300 sequential creates of a
row with one encrypted field; `examples/prisma5-cjs/bench.js`, run it on yours): plain 1.8 ms p50, encrypted **3.4 ms** p50 (p95 17 ms), encrypted with the key cache **2.3 ms**; `findFirst` 1.3 ms plain, 2.7 ms encrypted.
Your own measurement was +4 to 9 ms per write: that includes the decrypt round trip that is now gone, but the service-over-the-network case (not loopback) will be slower than these numbers.
Opt-in **key cache** mode:

```js
const cryplus = new Cryplus({ keyCache: { ttlMs: 300_000, staleMs: 60_000 } });   // needs the 'keys' role and --allow-key-export on the core
```

AES runs in-process; keys are fetched once per tenant. Measured on one machine, sequential calls: about 1.1 ms per encrypt+decrypt locally against about 4.1 ms through the service.
Interoperates byte for byte with the service (both directions, both ciphers), verified against the real binary. Behaviour when the service goes away (tested by killing the real process):

| Situation | Result |
|---|---|
| Key cached and fresh | served locally, no round trip |
| Key expired but within `ttlMs + staleMs` and the service is unreachable | served from the stale key (`staleServed` counter) |
| Tenant never seen (cold) | **fails closed**: `key_service_unavailable` |
| Past `ttlMs + staleMs` | fails closed |
| Service back | recovers by itself (circuit breaker half-opens) |

While the service is down, an expired-but-still-usable key is **not re-fetched on every operation**: after a failed refresh the cache keeps serving the stale key and retries after `retryMs` (default 1000).
(Found by a mixed-load test: without this, every operation during an outage tried to reach the dead service: 907 failed fetches in 1.5 s instead of 50.)
Mixed load, real core (`test/keycache.test.ts`): 8 workers, 5 tenants, local and service paths side by side, a **key rotation and a service restart in the middle**: 1879 writes, 1858 reads, 411 blind indexes,
0 errors; everything written (before, during and after the outage, by either path) opens by both paths; cache hit ratio above 0.9.

**The trade-off:** the tenant key now lives in this process's memory, individual operations are no longer audited by the service (only key fetches are), and a revoked service keeps working
until its cached keys expire (`ttlMs`). Rotation reaches this process after `ttlMs`. Keep `ttlMs` short and give the token a narrow `tenants` allowlist.

Always on: a **circuit breaker** (5 consecutive unreachable failures, 10 s; `circuitBreaker: false` to disable), `cryplus.ready()` for a readiness probe (`service` / `degraded` / `down`),
`cryplus.stats()`, and metrics: `new Cryplus({ metrics: prometheusSink(require('prom-client')) })` exposes `cryplus_requests_total{op,mode,result}`, `cryplus_request_seconds`,
`cryplus_errors_total{code}`, `cryplus_key_cache_total{event}`, `cryplus_breaker_transitions_total{to}`; and `withCryplus(base, { ..., metrics })` adds
`cryplus_prisma_errors_total{code=no_tenant|decryption_failed|raw_blocked|unsupported_query|...}`. Operax's own breaker in `circuit-breaker.js` can wrap `cryplus.*` calls too; the SDK one is independent.

## Running the key service

See [DEPLOY.md](DEPLOY.md): one leader and at least one follower on the same host/private network sharing a volume for the sealed key file; services `operax-api` (`crypt`, all tenants,
plus `keys` if you use the key cache), `backup-job` (`crypt`, `backup:*`) and `ops` (`admin`); TLS 1.3 with mTLS. The SDK takes the list of URLs and fails over.

### Packaging for a Docker build on `node:20-alpine`

The SDK has **no runtime dependencies and no native add-ons**, so musl/Alpine is not an issue (checked by a test that packs the tarball, installs it into a clean project
offline with `--omit=dev`, and loads it from CJS and ESM). It is not on npm; vendor the tarball:

```bash
cd sdk/node && npm run build && npm pack          # -> cryplus-0.3.0.tgz   (commit it next to the backend, e.g. vendor/cryplus-0.3.0.tgz)
```

```dockerfile
# in the backend's multi-stage Dockerfile
COPY vendor/cryplus-0.3.0.tgz ./vendor/
COPY package.json package-lock.json ./
RUN npm ci --omit=dev          # package.json: "cryplus": "file:vendor/cryplus-0.3.0.tgz"
```

(`npm i ./vendor/cryplus-0.3.0.tgz` writes that line.) Publishing to a private registry or npm is equally fine; the name `cryplus` is unclaimed on npm and publishing is your decision.
Run on an actual image: `examples/alpine/run.ps1` packs the tarball, installs it with `--omit=dev` into **`node:20-alpine` (Node 20.20, musl)** next to Prisma 5.22.0, cross-compiles a linux `cryplus-core`, starts
`postgres:16-alpine`, and runs 8 checks (service and key-cache local crypto interoperating on musl, the extension with searchable/global/suffix/array/json fields, row binding, `tenantFrom`, raw guard, transactions,
`migrateModel`/`rotateModel`, `cryplus-scan`): all pass. **Prisma itself needs `openssl` in an Alpine image** (`apk add openssl`); that is Prisma's requirement, not Cryplus's. Your own Dockerfile and base image remain yours to **VERIFY**.

**A second Prisma client.** If any code creates another `new PrismaClient()` instead of using the extended singleton, it reads and writes raw ciphertext without any error. Operax has one in `src/config/prisma.js`;
`operax-agente` has its own Prisma and database (a separate integration with the same service). Run `cryplus-scan` and `grep -rn "new PrismaClient"` to be sure.

## Wiring Prisma (CommonJS)

`src/config/prisma.js`, keeping your singleton and the `$on('error')` on the **base** client (`$on` is not available after `$extends`):

```js
const path = require('node:path');
const { PrismaClient } = require('@prisma/client');
const { Cryplus, withCryplus } = require('cryplus');

const base = global._prisma ?? new PrismaClient({ log: [{ emit: 'event', level: 'error' }] });
if (process.env.NODE_ENV !== 'production') global._prisma = base;
base.$on('error', (e) => console.error('prisma', e));

let prisma = base;
if (process.env.CRYPLUS_URL) {
  const cryplus = new Cryplus({ /* url, token and TLS files from CRYPLUS_URL, CRYPLUS_TOKEN, CRYPLUS_CA, CRYPLUS_CLIENT_CERT, CRYPLUS_CLIENT_KEY */ });
  prisma = withCryplus(base, {
    cryplus,
    schemaPath: path.join(__dirname, '../../prisma/schema.prisma'),   // VERIFY: the schema must exist in the runtime image
    tenant: ({ model }) => (model === 'Tenant' ? '__platform__' : undefined),   // undefined = ambient tenant
  });
}
module.exports = prisma;
```

Options worth knowing (all optional, all in `withCryplus(base, {...})`):

| Option | What it does |
|---|---|
| `tenant: ({ model }) => ...` | Tenant for a model before the ambient one (e.g. `Tenant` -> `__platform__`) |
| `tenantFrom: { Mensagem: { via: 'conversaId', model: 'Conversa' } }` | Tables with no tenant column: the tenant is that of the parent row (see below) |
| `tenantFromArgs: true` | Also derive the tenant of models that have a `tenantId` column from `data/where/create` (**off by default**, see below) |
| `plaintext: { default: 'allow', Mensagem: 'reject' }` | Reject plaintext reads per model for a staged rollout (or `'reject'` / `'allow'` for all) |
| `rowBinding: 'on'` or `'strict'` | Bind each ciphertext to its row id (see [Row binding](#row-binding)) |
| `legacy: 'fallback'` | Equality also matches rows that are still plaintext, during a migration |
| `rawGuard`, `metrics`, `hideIndexFields` | as before |

`module.exports` must be the extended client everywhere. **Never turn Cryplus off once any column has been encrypted**: the app would read ciphertext
(to remove it, run `revertModel` for every model first).

## Tenant context

Wrap the authenticated request once, in `auth.middleware.js`, right after `req.tenantId = usuario.tenantId`:

```js
const { withTenant } = require('cryplus');
return withTenant(req.tenantId, () => next());
```

or, as Express middleware (async getter allowed; returning nothing leaves the request without a tenant, e.g. login and webhooks):

```js
const { cryplusTenantMiddleware } = require('cryplus');
app.use(authenticate);
app.use(cryplusTenantMiddleware((req) => req.tenantId));
```

(or point the `tenant` option at your own `AsyncLocalStorage` store in `contexto.js`). Outside a request you must set it yourself, otherwise the call **fails closed** with `no tenant for <Model>`:

| Place | What to do |
|---|---|
| WhatsApp/payment webhooks | After you resolve the tenant: `withTenant(id, () => ...)` |
| Public pages by token | Same, using the tenant of the record found by the token |
| Schedulers that sweep all tenants | `for (const t of tenants) await withTenant(t.id, () => work(t))` |
| BullMQ workers | `encryptedWorker` does it |
| Signup (`Tenant`, `Usuario`, `Funcionario` in one `$transaction`) | Generate the tenant id first (`randomUUID()`), create the `Tenant` (platform scope), then create children inside `withTenant(newId, ...)`. Tested. |
| Login (looks up `Usuario` by e-mail before the tenant is known) | `@encrypted(global)` on the e-mail if you must encrypt it; otherwise leave it |

A tenant mismatch never leaks: decrypting under the wrong tenant is refused.

**Tables without a tenant column** (Operax: `Mensagem`, owned through `Conversa`) are declared once instead of with a hand-written resolver:

```js
withCryplus(base, { cryplus, schemaPath, tenantFrom: { Mensagem: { via: 'conversaId', model: 'Conversa' } } });
```

Without an ambient tenant the tenant is found from, in order: `data/create/where.conversaId`; `where: { conversa: { is: { tenantId } } }` (or `{ conversa: { tenantId } }`); a `conversa: { connect: { id } }`;
a nested create under the parent; and finally `where: { id }` alone (the row is looked up). `createMany` works when every row has the same `conversaId` and is refused (`no tenant for Mensagem`) when
they differ. Lookups go through the base client, are cached (a row never changes tenant; 10 000 entries) and are skipped entirely when an ambient tenant exists. A lookup made inside an
interactive `$transaction` runs outside it, so it cannot see a parent created in the same transaction: set `withTenant` there (signup does).

**Why `tenantId` columns are not derived from the query by default.** The ambient tenant is the authorisation context: a handler that forgot `withTenant` must **fail**, not decrypt whatever tenant
its `where` names. `tenantFromArgs: true` opts in for models that have a `tenantId` column (data/create/where, or a lookup for `where: { id }`); models in `tenantFrom` always derive.

## Row binding

By default a ciphertext is bound to its **tenant, collection and field**. Someone who can write to the database can still swap the stored values of two rows of the same tenant and field; reading either row then
returns the other row's data **without any error** (measured on Operax's copy; cross-tenant swaps are already detected). `rowBinding` puts the row's primary key into what is authenticated, so that swap fails with
`decryption_failed` on read.

```js
withCryplus(base, { cryplus, schemaPath, rowBinding: 'on' });   // 1. new writes are bound; old (unbound) values still read
// 2. bind what exists, per model, with the base client:
await rotateModel(base, cryplus, schema, { model: 'Webhook', tenantOf: (r) => r.tenantId, bindRows: true, verify: { sample: 0.05 }, concurrency: 4 });
// 3. then refuse unbound values:  rowBinding: 'strict'
```

What it changes, deliberately:

- Applies to models with a single `String` `@id`. `Int`/autoincrement and composite keys cannot be bound (the id does not exist before the INSERT): those models keep working unbound.
- The extension **generates the id before encrypting** (`uuid()`, `cuid()`, `ulid()`, `nanoid()` defaults; `cuid` values are cuid-shaped, not byte-identical to Prisma's generator) or uses the id you supply.
- `update`, `upsert` and nested updates that write an **encrypted value** must identify the row by `where: { id }` (an `id` in the `where` is enough, other filters may be added). `update` by `tenantId_cpf`,
  `updateMany` with an encrypted value, and `upsert` by a compound key are **refused** with a message naming the fix, because each row needs its own ciphertext. Writing `null` or plain columns is unaffected.
- A `select` without the id still works: the id is added to the query and removed from the result (also in nested selects). Raw helpers: `decryptRows` reads the id column from the rows (select it),
  `encryptValue` / `decryptValue` take `{ recordId }`.
- Turning it **off** again after rows were bound makes those rows unreadable (they would be opened without their id). Rollback is `revertModel` (which opens both kinds), not flipping the option.
- `rotateModel` after a key rotation re-wraps bound values correctly with or without `bindRows`.
- A value written before binding was enabled still reads in `'on'` (it is tried without the id when the bound attempt fails: one extra call per legacy value). In that window a swap of two **legacy** values is
  still possible; `'strict'` closes it.

## Wave 1: schema and migration

```prisma
model Tenant {
  /// @encrypted
  mpOauthAccessToken  String?
  /// @encrypted
  mpOauthRefreshToken String?
  /// @encrypted
  pagbankAccessToken  String?
  /// @encrypted
  pagbankRefreshToken String?
}
model UserPaymentIntegration { /// @encrypted
                               accessToken String?
                               /// @encrypted
                               refreshToken String? }
model Webhook      { /// @encrypted
                     secret String? }
model ClienteNota  { /// @encrypted
                     texto String }
model Configuracao {
  valor        String?          // unchanged: phones are compared in raw SQL
  /// @encrypted
  valorSecreto String?          // NEW: move empresa_pix_chave here
}
```

`Configuracao.valor` mixes phones (compared with `regexp_replace` in raw SQL), PIX keys and plain settings: do not encrypt it as a whole.
Add `valorSecreto` (additive migration) and change the one reader/writer (`atendimento.service.js`, key `empresa_pix_chave`).

**VERIFY before marking each field**: run `cryplus-scan`, and `grep` the backend for the field name (a `contains`, `orderBy`, `distinct`, `groupBy`, raw SQL or an API response that exposes it changes the answer;
the extension throws on unsupported filters, and the guard on raw SQL).
`Mensagem.conteudo` waits for two code changes: replace the dedupe `contains` (`centralIa.controller.js:369`) with a `linkHash` column (sha256 of the link, compared by equality), and move the Central search
(`central.controller.js:1112`) to Prisma plus `$cryplus.searchDecrypted` on the conversation.

### Migration, key rotation, rollback

Always with the **base** client, in **staging first**, after a database backup:

```js
const { migrateModel, rotateModel, revertModel, parseSchema } = require('cryplus');
const schema = parseSchema(require('node:fs').readFileSync('prisma/schema.prisma', 'utf8'));
const p = { model: 'Tenant', tenantOf: () => '__platform__' };

await migrateModel(base, cryplus, schema, { ...p, dryRun: true });                       // counts, writes nothing
const s = await migrateModel(base, cryplus, schema, { ...p, batchSize: 200, throttleMs: 50, verify: true });
// s: { scanned, encrypted, rewrapped, rebound, indexed, verified, failures: [{ id, field, error }], lastId, aborted, total, rowsPerSec, etaSec }
```

- **Idempotent and resumable**: `lastId` from a run goes into `startAfter`; `maxFailures` stops early. Every failure is listed per row and field.
- **Live system**: `throttleMs` sleeps between batches; `batchSize` bounds each read. Run it while users work and watch the database.
- **`verify: true`** reads every changed row back and checks each field decrypts to what was meant to be stored, through a fresh state (it never trusts what the same run just encrypted). `verify: { sample: 0.05 }` checks about 5 %.
- **Speed**: `concurrency: 4` writes four rows at a time (default 1; mind the Prisma connection pool). `onProgress` receives `scanned`, `total`, `rowsPerSec` and `etaSec`; the final stats carry `elapsedMs`. Writes are one `UPDATE` per row (a bulk
  `UPDATE ... FROM (VALUES ...)` is **not** implemented): measure with your data and tune `concurrency` and `batchSize`.
- **Modes**: `all` (encrypt plaintext, re-wrap, backfill indexes), `index-only` (fill missing index columns, for encrypted **and** still-plaintext rows), `rewrap-only`. `bindRows: true` also binds values to their rows.
- **Key rotation without downtime**: `await cryplus.rotateKeys()`, then `rotateModel(base, cryplus, schema, { model, tenantOf, ... })` per model. Old ciphertext keeps working throughout.
- **Rollback**: `revertModel` writes plaintext back (all kinds; index columns stay), idempotent. Put secrets back in clear text only deliberately.
- **Adding an index column to a big table**: (1) add the nullable column (additive migration, no lock beyond the DDL); (2) deploy code that writes it; (3) backfill with `migrateModel(..., { mode: 'index-only', throttleMs })`;
  (4) only then create the unique index `CONCURRENTLY` (in raw SQL outside Prisma migrate, if you need a unique constraint) and switch the app's `findUnique` keys (the extension rewrites the old compound names).

Deploy the new code with the extension and the `/// @encrypted` comments **before or together with** the migration: plaintext rows keep reading (`plaintext: 'allow'`, default) and writes are encrypted from then on;
afterwards set `plaintext: 'reject'` so a stray plaintext value cannot hide.

## Wave 2: CPF/CNPJ

```prisma
cpf    String? @db.Text /// @encrypted(searchable, digits)     // VarChar(14) must become text first
cpfIdx String?                                                   // blind index (new column)
@@unique([tenantId, cpfIdx])                                     // replaces @@unique([tenantId, cpf])
```

- **The old unique constraint silently stops working** if left on the encrypted column (each ciphertext differs). Move it to the index (tested, including a duplicate in another format being rejected).
- Screens that search CPF/CNPJ/e-mail with `contains` become exact-match searches: a product change, **VERIFY** with the team.
- Candidates: `Funcionario.cpf`, `Fornecedor.documento`, `Cliente.cpfCnpj`, `Prestador.cpfCnpj`, `Tenant.cpfCnpj`. Rewrite their raw SQL (`clientes.controller.js:39`, `tenant.controller.js`) first; `cryplus-scan` lists them.

## Wave 3: phones and e-mail

The pieces now exist (`br-phone-canonical`, `suffix(4/8)`, `global`, compound-key rewriting, `searchDecrypted`), but the coordination does not: a phone lives in about eight tables that must be encrypted together
(`Cliente`, `Contato.telefoneNormalizado`, `LocalCliente`, `Obra`, `Orcamento`, `FeedEntry`, `CrmLinkRastreavel`, `IaConversa`), the incoming-WhatsApp lookups (`tenant.controller.js` 263/334/347/357,
`whatsappCadastro.service.js:63`) normalize inside SQL and must move to `$cryplus.index(..., { global: true })`, and the trade-offs above apply (global index = cross-tenant equality is visible; 4-digit suffix = weak).
Decide field by field. Do not encrypt `Usuario.email` unless you accept the global index for it.

## Not covered by Cryplus (decide separately)

- Raw SQL through a direct `pg` client (the scanner lists the files).
- Media files (public bucket, video range requests, ffmpeg/sharp). Only documents could be added later, via an authenticated download route.
- `operax-agente` (own database and Prisma): a second integration, same service.
- A fully compromised backend can still ask the service to decrypt what it may read; the allowlist and the audit log limit and reveal that (and with the key cache, only key fetches are audited).
- Per-tenant crypto-shredding (LGPD deletion): **designed, not implemented**: see [DESIGN-crypto-shredding.md](DESIGN-crypto-shredding.md).

## Rollout checklist

1. Wave 0: scanner clean, backups encrypted, restore drill. 2. Key service up (leader + follower, TLS, tokens), health checked, key file backed up **and** a restore of the key file tested.
3. Staging: extension on, `cryplus-scan` clean, migration dry run, migration with `verify`, `npm run test:integracao` (also with `CRYPLUS_MODE=memory`), verify screens and API responses that expose encrypted fields.
4. Production: backup, deploy, migrate model by model with `throttleMs`, watch `cryplus_prisma_errors_total` and the audit log for `decryption_failed` / `no_tenant`, then `plaintext: 'reject'`.
5. Keep `revertModel` ready, and keep the old plaintext backups until you are sure.
