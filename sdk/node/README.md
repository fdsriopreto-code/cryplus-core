# cryplus (Node SDK)

Client for [`cryplus-core`](https://github.com/fdsriopreto-code/cryplus-core): field-level, per-record envelope encryption, a Prisma extension, a raw-SQL scanner and guard,
BullMQ job sealing, migration helpers and an in-memory client for tests. Zero runtime dependencies, no native add-ons, ESM and CommonJS.

> Pre-1.0 and not externally audited. Read the repository README ("Limitations") before protecting anything you cannot afford to lose.

```js
const { Cryplus, withCryplus, withTenant } = require('cryplus');          // or: import { ... } from 'cryplus'

const cryplus = new Cryplus();      // CRYPLUS_URL (comma-separated for failover), CRYPLUS_TOKEN, CRYPLUS_CA / CRYPLUS_CLIENT_CERT / CRYPLUS_CLIENT_KEY
const ct = await cryplus.encrypt({ tenant: 'acme', collection: 'User', field: 'cpf' }, '123.456.789-00');
```

| Piece | What it is |
|---|---|
| `new Cryplus(opts)` | client: `encrypt`, `decrypt`, `blindIndex`, `rewrap`, streams, `rotateKeys`, `ready()`, `stats()`; options `keyCache`, `circuitBreaker`, `metrics`, `tls`, multiple URLs |
| `Cryplus.inMemory(opts)` / `createCryplus()` | in-process client for tests (`CRYPLUS_MODE=memory`); refuses `NODE_ENV=production` |
| `withCryplus(prisma, { cryplus, schemaPath, tenant, rawGuard, plaintext, metrics })` | Prisma extension driven by `/// @encrypted(...)` comments; adds `prisma.$cryplus` helpers |
| `withTenant(id, fn)` / `cryplusTenantMiddleware(req => req.tenantId)` | ambient tenant (AsyncLocalStorage); awaits `fn` inside the scope / Express middleware |
| `npx cryplus-scan --schema prisma/schema.prisma --src src` | finds raw SQL touching encrypted columns |
| `encryptedQueue(queue, cryplus)` / `encryptedWorker(cryplus, processor)` | keep job data out of Redis in clear text |
| `migrateModel` / `rotateModel` / `revertModel` | encrypt existing data, rotate keys, bind rows, roll back; resumable, throttled, concurrent, sampled verification, ETA |
| `EncryptedS3` | client-side encrypted S3 objects |
| `parseSchema`, `ciphertextLength` | schema reader and exact ciphertext sizing |

Prisma extension options: `tenantFrom` (tables without a tenant column), `tenantFromArgs`, `plaintext` (per model), `rowBinding` (`on`/`strict`), `legacy: 'fallback'`, `rawGuard`, `metrics`.
Filters on encrypted fields behave like plaintext ones (verified by a generated oracle test), `undefined` means "no filter", and anything not rewritten is refused.

Directive syntax: `/// @encrypted`, `@encrypted(searchable, digits)`, `@encrypted(global)`, `@encrypted(suffix(4), suffix(8), br-phone-canonical)`, `@encrypted(max(14))`.
Supported column types: `String`, `String[]`, `Json`. Full guide for a real integration: `docs/OPERAX.md` in the repository.
