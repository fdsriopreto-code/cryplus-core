# Integrating Cryplus into Operax

Based on a read-only survey of the `metal-flow-back-end` repository (Express 4, plain JavaScript/CommonJS, Prisma 5.22 without
a driver adapter, one `PrismaClient`, `AsyncLocalStorage` already used in `src/config/contexto.js`, Easypanel, GoStorage).
**This repository has never seen the Operax code.** What is verified here is the same stack in a faithful test project
(`examples/prisma5-cjs`, 15 tests against real Postgres). Anything that depends on Operax itself is marked **VERIFY**.

## Order of work

| Wave | What | Cryplus needed | Risk |
|---|---|---|---|
| **0** | Hash API keys and one-time tokens; restrict the public bucket; encrypt database backups | Backups only | Low |
| **1** | Secrets nobody searches: OAuth/payment tokens, webhook secrets, PIX key, notes and message bodies | Yes | Low |
| **2** | CPF/CNPJ/documento with equality search | Yes | Medium |
| **3** | Phone numbers and e-mail (partial search, lookups before the tenant is known) | **Features not built yet** | High; do last |

Do not start wave 3 with the current code (see the end).

## Wave 0 (no extension involved)

**1. Hash tokens instead of encrypting them.** `ApiKey.key`, `Orcamento.tokenAprovacao/tokenAcompanhamento`,
`Convite*.token`, `Cliente.portalConviteToken` are random bearer secrets looked up by equality. Store `sha256(token)` and look up by the hash,
exactly like a password. This keeps the unique index and the equality lookup and needs no key service:

```js
const crypto = require('node:crypto');
const sha256 = (t) => crypto.createHash('sha256').update(t).digest('hex');
// create: const raw = crypto.randomBytes(32).toString('hex'); store sha256(raw); show raw to the user ONCE
// lookup: WHERE key_hash = ${sha256(presented)}
```

Existing rows: add a `keyHash` column, backfill with `sha256(key)`, switch the lookup, then null the plaintext `key`.
Only valid for high-entropy random tokens (never for CPF, phone, e-mail).

**2. The bucket has public read on the whole `operax/` prefix.** Keys look like `operax/<categoria>/<tenantId>/<timestamp>-<nome>`.
Restrict public read to the categories that really must be public; `documentos`, `funcionarios` and `whatsapp` should not be.
Whether this is intended is a product decision: **VERIFY**.

**3. Encrypt the `pg_dump` backups** (they are plaintext for up to 12 months of retention).
In `backupBanco.service.js`, pipe `pg_dump`'s stdout through the service before the upload:

```js
const { spawn } = require('node:child_process');
const dump = spawn('pg_dump', ['--format=custom', ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
const ctx = { tenant: `backup:${yyyyMm}`, collection: 'backups', field: objectKey };   // bound to the object name
const encrypted = await cryplus.encryptStream(ctx, dump.stdout);                       // Readable
await new Upload({ client: s3, params: { Bucket, Key: objectKey, Body: encrypted } }).done();
// and check dump's exit code: a failed pg_dump must fail the job, not upload a truncated file
```

Use a service token limited to `--tenants 'backup:*'`. Restore with `cryplus-core file decrypt` (works with no service running; see DEPLOY.md §5).
Old plaintext dumps remain in the bucket until they rotate out; decide whether to delete or re-encrypt them.
**Not tested here:** `pg_dump` itself (the test uses a synthetic dump through the same stream path) and your Easypanel runtime. Do a full
restore drill in staging.

## Running the key service

See [DEPLOY.md](DEPLOY.md). For Operax: one leader and at least one follower as services on the same Easypanel host/private network sharing a
volume for the sealed key file; services `operax-api` (`crypt`, all tenants), `backup-job` (`crypt`, `backup:*`) and `ops` (`admin`);
TLS 1.3 with mTLS. The Node SDK takes the list of URLs and fails over.

Distribution of the SDK: it is not on npm yet. The name `cryplus` is currently unclaimed on the registry; publishing is your decision.
Until then: `cd sdk/node && npm run build && npm pack`, and `npm i ./cryplus-0.1.0.tgz` in the backend. The package ships ESM and CommonJS builds;
`require('cryplus')` works from plain JS on Node 20 without any flag.

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

`module.exports` must be the extended client everywhere (every file already `require`s this one). **Never turn Cryplus off once any column has been
encrypted**: the app would read ciphertext. (To remove it, run `revertModel` for every model first.)

## Tenant context

Wrap the authenticated request once, in `auth.middleware.js`, right after `req.tenantId = usuario.tenantId`:

```js
const { withTenant } = require('cryplus');
// ...
return withTenant(req.tenantId, () => next());
```

(or point the `tenant` option at your own `AsyncLocalStorage` store in `contexto.js`). Everything the request does afterwards uses that tenant.
Outside a request you must set it yourself, otherwise the call **fails closed** with `no tenant for <Model>`:

| Place | What to do |
|---|---|
| WhatsApp/payment webhooks | After you resolve the tenant (`metadata.tenantId`, the cobrança, the token): `withTenant(id, () => ...)` |
| Public pages by token | Same, using the tenant of the record found by the token |
| Schedulers that sweep all tenants (`backupBanco`, `renovacaoAssinatura`, `retrospectiva`...) | `for (const t of tenants) await withTenant(t.id, () => work(t))` |
| BullMQ workers | Put `tenantId` in the payload and wrap the processor in `withTenant` |
| Signup (creates `Tenant`, `Usuario`, `Funcionario` in one `$transaction`) | Generate the tenant id first (`randomUUID()`), create the `Tenant` (platform scope, no context needed), then create children inside `withTenant(newId, ...)`. Tested. |
| Login (looks up `Usuario` by e-mail before the tenant is known) | Keep `Usuario.email` unencrypted (wave 3 topic) |

A tenant mismatch never leaks: decrypting under the wrong tenant is refused.

**BullMQ/Redis carries secrets and personal data in clear text** (webhook `secret`, obra addresses, the whole budget in PDF jobs, invite e-mails
and tokens). Pass ids only and let the worker read from the database (where the extension decrypts), and check the Redis password, network exposure
and `removeOnComplete` retention. This is a leak the extension cannot cover.

## Wave 1: schema and migration

Marking a column is a comment in `schema.prisma`; the column type does not change (`String`/`String?` only: `DateTime` and `String[]` are not supported).

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
model UserPaymentIntegration {
  /// @encrypted
  accessToken  String?
  /// @encrypted
  refreshToken String?
}
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

`Configuracao.valor` mixes phones (compared with `regexp_replace` in raw SQL), PIX keys and plain settings, so it must not be encrypted as a whole.
Add `valorSecreto` (additive migration), change the one reader/writer (`atendimento.service.js`, key `empresa_pix_chave`) and migrate that key's value.

**VERIFY before marking each field**: `grep` the backend for the field name. A `contains`, `orderBy`, `distinct`, `groupBy`, raw SQL or an API response
that exposes it changes the answer (the extension throws on unsupported filters instead of returning wrong data, but raw SQL silently sees ciphertext).
The survey found no such use for the fields above. `Mensagem.conteudo` is **not** in wave 1: it is read by raw SQL (`central.controller.js:1112`,
`LIKE '%termo%'`) and by a `contains` used to deduplicate payment links (`centralIa.controller.js:369`). Replace the dedupe with a `linkHash`
column (sha256 of the link, compared by equality) and move the Central search to Prisma plus an in-memory filter over the conversation, then encrypt it.

Migration (run in **staging first**, after a database backup):

```js
const { PrismaClient } = require('@prisma/client');            // the BASE client, not the extended one
const { Cryplus, migrateModel, revertModel, parseSchema } = require('cryplus');
const schema = parseSchema(require('node:fs').readFileSync('prisma/schema.prisma', 'utf8'));
const base = new PrismaClient(), cryplus = new Cryplus();

const plan = [
  { model: 'Tenant',                 tenantOf: () => '__platform__' },
  { model: 'UserPaymentIntegration', tenantOf: (r) => r.tenantId },
  { model: 'Webhook',                tenantOf: (r) => r.tenantId },
  { model: 'ClienteNota',            tenantOf: (r) => r.tenantId },
];
for (const p of plan) {
  console.log(p.model, 'dry run', await migrateModel(base, cryplus, schema, { ...p, dryRun: true }));
  // review, then:
  console.log(p.model, await migrateModel(base, cryplus, schema, p));   // idempotent and resumable; failures are listed, never silent
}
// ROLLBACK per model (writes plaintext back into the table; take a backup first): revertModel(base, cryplus, schema, p)
```

Order: deploy the new code with the extension and the `/// @encrypted` comments **before or together with** the migration. Reads of still-plaintext rows keep
working (`plaintext: 'allow'`, the default) and writes are encrypted from then on; after migrating, set `plaintext: 'reject'` so a stray plaintext value cannot hide.

## Wave 2: CPF/CNPJ

```prisma
/// @encrypted(searchable, digits)
cpf    String?
cpfIdx String?                     // blind index (new column)
@@unique([tenantId, cpfIdx])       // replaces @@unique([tenantId, cpf])
```

- **The old unique constraint silently stops working** if left on the encrypted column: each ciphertext is different, so duplicates never collide.
  Move the uniqueness to `cpfIdx` (tested, including a duplicate written in a different format being rejected).
- `Tenant.cpfCnpj @unique` (global): `Tenant` runs under the platform scope, so its index is global as well.
- Screens that search CPF/CNPJ/e-mail with `contains` become exact-match searches (`equals`/`in`). That is a product change: **VERIFY** with the team.
- Candidates from the survey: `Funcionario.cpf`, `Fornecedor.documento`, `Cliente.cpfCnpj`, `Prestador.cpfCnpj`, `Tenant.cpfCnpj`.
  Their raw SQL usage (`clientes.controller.js:39`, `tenant.controller.js`) must be rewritten before encrypting them: raw SQL reads ciphertext.

## Wave 3: why it is not ready

Phones and e-mail are used for **partial search** (last 4/8 digits, `contains`) and for **lookups before the tenant is known**
(`tenant.controller.js` 263/334/347/357, `whatsappCadastro.service.js:63`, login by e-mail). The blind index today is equality-only and per tenant.
It needs a platform-scoped index and a suffix index (neither exists yet), and a phone lives in about eight tables that must change together.
Do not encrypt phones or `Usuario.email` before that work.

## Not covered by Cryplus (decide separately)

- Raw SQL (about 150 calls in 42 files) bypasses the extension. Anything reading an encrypted column by raw SQL gets ciphertext.
- Media files (public bucket, video range requests, ffmpeg/sharp): not in scope. Only documents could be added later, via an authenticated download route.
- `operax-agente` has its own database and Prisma (`Conversation.content`, `AgentMemory.fato`, `Lead.*`): a second integration, same service.
- A fully compromised backend can still ask the service to decrypt what it may read; the allowlist and the audit log limit and reveal that.

## Rollout checklist

1. Wave 0 items; restore drill from an encrypted backup. 2. Key service up (leader + follower, TLS, tokens), health checked, key file backed up **and** a restore of the key file tested.
3. Staging: extension on, migration dry run, migration, run the integration suite (`npm run test:integracao`), verify screens and API responses that expose encrypted fields.
4. Production: backup, deploy, migrate model by model, watch the audit log for `decryption_failed`/`no tenant` errors, then `plaintext: 'reject'`.
5. Keep `revertModel` ready, and keep the old plaintext backups until you are sure.
