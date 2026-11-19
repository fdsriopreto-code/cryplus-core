# Integrating Cryplus into Operax

Based on two read-only surveys of the `metal-flow-back-end` repository (Express 4, plain JavaScript/CommonJS, Prisma 5.22 without a
driver adapter, one `PrismaClient`, BullMQ + Redis, S3-compatible storage, `node:20-alpine`) and on the improvement requests the Operax
team wrote from them. **This repository has never seen the Operax code.** What is verified here is the same stack in a faithful test
project (`examples/prisma5-cjs`, 40 tests against real Postgres, in two modes: against a real `cryplus-core` and against the in-memory
test client). Anything that depends on Operax itself is marked **VERIFY**.

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

Normalizers (applied to the stored value and to every filter value): `trim` (always), `lowercase`, `digits`, `fold` (lowercase + strip accents, the effect
of `translate(lower(x), 'áàãâéêíóôõúüç', 'aaaaeeiooouuc')`), `email-lower`, `br-phone-canonical`.
`br-phone-canonical` as specified from the survey: digits only; drop a leading `55` when the number has 12 or 13 digits; for an 11-digit mobile number drop the
extra `9` after the DDD (so `(11) 91234-5678`, `11912345678`, `+55 11 91234-5678` and the old `(11) 1234-5678` are equal). **VERIFY** this against the SQL it replaces
(`tenant.controller.js:330-334`) with real numbers before relying on it.

Compound unique keys keep working: after moving uniqueness to the index (`@@unique([tenantId, cpfIdx])`) code that calls
`findUnique({ where: { tenantId_cpf: { tenantId, cpf } } })`, `upsert` or `update` with that key is rewritten automatically (tested).

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
Passing only an id and letting the worker read the row is better than sealing. Tested with a stand-in for BullMQ that records exactly what would be written to Redis;
**not tested against a real Redis/BullMQ** (none available here): **VERIFY** in staging. `allowPlain` (default true) lets jobs enqueued before the rollout still run.

## Availability and latency

Default mode: every operation goes to the key service, batched per event-loop tick (a 200-row list is one round trip per Prisma call). Opt-in **key cache** mode:

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
Not run on an actual Alpine image here (no Docker): **VERIFY** the first build.

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

`module.exports` must be the extended client everywhere. **Never turn Cryplus off once any column has been encrypted**: the app would read ciphertext
(to remove it, run `revertModel` for every model first).

## Tenant context

Wrap the authenticated request once, in `auth.middleware.js`, right after `req.tenantId = usuario.tenantId`:

```js
const { withTenant } = require('cryplus');
return withTenant(req.tenantId, () => next());
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
// s: { scanned, encrypted, rewrapped, indexed, verified, failures: [{ id, field, error }], lastId, aborted }
```

- **Idempotent and resumable**: `lastId` from a run goes into `startAfter`; `maxFailures` stops early. Every failure is listed per row and field.
- **Live system**: `throttleMs` sleeps between batches; `batchSize` bounds each read. Run it while users work and watch the database.
- **`verify: true`** reads every changed row back and checks each field decrypts to what was meant to be stored.
- **Modes**: `all` (encrypt plaintext, re-wrap, backfill indexes), `index-only` (columns that are already encrypted but whose index columns are new or empty), `rewrap-only`.
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
