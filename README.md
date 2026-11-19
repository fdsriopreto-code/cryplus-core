# Cryplus

Field-level, per-record **envelope encryption** for the data your SaaS keeps in Postgres and S3,
usable from any language through a small local sidecar.

> **Status: pre-1.0, not externally audited.** The cryptography uses only standard, well-reviewed
> primitives (XChaCha20-Poly1305 / AES-256-GCM, HKDF-SHA256, HMAC-SHA256, Argon2id) from Go's
> standard library and `golang.org/x/crypto`. Cryplus invents **no** cipher. The design and code
> still need independent review before you trust it with production secrets. See
> [Limitations](#limitations-read-this).

## What problem it solves

Most breaches don't break AES. They steal a database dump, a backup, or open an S3 bucket.
With Cryplus the sensitive columns and objects are ciphertext **at rest**, each record under its
own key, so that dump is useless without the key service.

```
App (any language) ──SDK──▶ cryplus-core (Go sidecar) ◀──▶ key backend (file / passphrase / Vault / KMS)
        │                         │
        ▼                         └─ audit log (who used which key, never the data)
Postgres / S3   ← only ciphertext ever lands here
```

- **A fresh data key (DEK) for every value.** The DEK is wrapped by a per-tenant key derived from a
  versioned master key (KEK). Rotating the KEK re-wraps tiny DEKs; the data is not re-encrypted.
- **Context-bound.** Ciphertext is bound to `tenant / collection / field`, so copying a value into
  another tenant, table or column stops it decrypting. S3 objects are bound to `bucket/key`.
- **Searchable without decrypting.** Equality search over encrypted columns through keyed blind
  indexes (HMAC), scoped per tenant and field.
- **Streams.** Large files/S3 objects use a chunked AEAD (STREAM); truncation, reordering and
  tampering are detected and never delivered as a clean short read.
- **Keys never touch disk in the clear** when sealed by a passphrase (Argon2id), Vault transit or AWS KMS.

## Layout

| Path | What |
|---|---|
| [`core/`](core) | `cryplus-core`: Go library + sidecar binary (envelope, streams, keyring, HTTP API, audit) |
| [`sdk/node/`](sdk/node) | Node/TypeScript SDK **+ Prisma extension**, migration helper, encrypted-S3 helper |
| [`sdk/python/`](sdk/python) | Python SDK (stdlib only) |
| [`examples/prisma-demo/`](examples/prisma-demo) | End-to-end tests: real Prisma + real Postgres |
| [`examples/s3-demo/`](examples/s3-demo) | End-to-end tests: AWS SDK v3 (incl. multipart) + S3-compatible server |
| [`tools/fakes3/`](tools/fakes3) | Tiny S3 emulator used by the tests (not AWS) |

Go users can skip the sidecar and import `github.com/fdsriopreto-code/cryplus-core/envelope` directly.

## Quick start (Prisma)

1. Run the sidecar next to your app:

   ```bash
   export CRYPLUS_TOKEN="$(openssl rand -hex 24)"     # min 16 chars
   export CRYPLUS_PASSPHRASE="a long passphrase"      # seals the key file at rest
   cryplus-core --keyfile ./cryplus-keys.json         # listens on 127.0.0.1:7788
   ```

2. Mark columns in `schema.prisma` with a triple-slash comment:

   ```prisma
   model User {
     id      String  @id @default(uuid())
     email   String  @unique
     /// @encrypted(searchable, digits)
     cpf     String?
     cpfIdx  String? @unique        // blind-index column, required for `searchable`
     /// @encrypted
     notes   String?
   }
   ```

3. Wrap your client once:

   ```ts
   import { Cryplus, withCryplus, withTenant } from "cryplus";

   const cryplus = new Cryplus();   // CRYPLUS_URL / CRYPLUS_TOKEN
   const prisma = withCryplus(new PrismaClient(/* adapter */), {
     cryplus,
     schemaPath: "prisma/schema.prisma",
   });

   // after authenticating the request, in middleware:
   await withTenant(user.organizationId, async () => {
     await prisma.user.create({ data: { email, cpf: "123.456.789-00", notes: "vip" } });
     await prisma.user.findFirst({ where: { cpf: "12345678900" } });   // via blind index
   });
   ```

Your code reads and writes plain values; Postgres only ever stores `cp1.…` ciphertext.

### What the extension handles

`create`, `createMany(AndReturn)`, `update`, `updateMany(AndReturn)`, `upsert`, nested relation writes
(`create`, `createMany`, `connectOrCreate`, `update`, `updateMany`, `upsert`), `where` rewriting
(`equals`, `in`, `not`, `notIn`, `AND/OR/NOT`, through relations and inside `include`), decryption of
results including nested relations, interactive transactions. It **refuses** (throws) anything that
would silently be wrong: `contains/startsWith/gt/...`, `orderBy`, `distinct`, `groupBy` on encrypted
fields, and non-searchable filters.

### Migrating an existing table / rotating keys

```ts
import { migrateModel, parseSchema } from "cryplus";
// pass the BASE client (without the extension). Idempotent and resumable.
await migrateModel(basePrisma, cryplus, parseSchema(schemaText), {
  model: "User",
  tenantOf: (row) => row.organizationId,
});
await cryplus.rotateKeys();           // new KEK version; old data stays readable
await migrateModel(/* same call */);  // re-wraps every ciphertext to the new version
```

## S3

```ts
const s3 = new EncryptedS3(cryplus, { client, PutObjectCommand, GetObjectCommand, Upload });
await s3.put(tenantId, "bucket", "docs/contract.pdf", fileStream);   // encrypted before leaving the process
const plain = await s3.get(tenantId, "bucket", "docs/contract.pdf"); // Readable; errors on tamper/truncation
```

Verified against the AWS SDK v3 (including lib-storage multipart) on two S3-compatible servers: the
bundled emulator and [gostore-s3](https://github.com/fdsriopreto-code/gostore-s3)
(`S3_SERVER=gostore node --test examples/s3-demo/s3.test.ts`). It has **not** been run against AWS S3 itself.
Cryplus encrypts on the client, so it composes with any server-side encryption the storage already has.

## Other languages

Any language can call the HTTP API (see [`core/server`](core/server/server.go)): `POST /v1/encrypt`,
`/v1/decrypt`, `/v1/blind-index`, `/v1/rewrap`, `/v1/batch`, `/v1/stream/*`, `GET /v1/keys`,
`POST /v1/keys/rotate`. The Python SDK is a ~150-line example of a thin client.

## Running the tests

```powershell
./scripts/test-all.ps1     # Go + Node + Python; add -E2E to also run Prisma/Postgres and S3 suites
```

## Limitations (read this)

- **Not audited.** Get an external review before protecting anything you cannot afford to lose.
- **Compromised app ⇒ compromised data.** The app (and anything holding `CRYPLUS_TOKEN`) can ask the
  sidecar to decrypt what its tenants may read. Cryplus protects data **at rest and in dumps**, it
  does not stop a fully compromised application server. Tenant scoping and the audit log limit and
  reveal the blast radius.
- **No row binding.** Ciphertext is bound to tenant/model/field, not to the row id. Someone with
  write access to your database can swap two rows' values for the same field within one tenant and
  the swap will decrypt. (Cross-tenant, cross-field and cross-table moves *are* detected.)
- **Blind indexes leak equality and frequency** of values (that is how search works). Don't mark
  low-entropy fields (booleans, small enums) as `searchable`. Only equality search exists.
- **Prisma raw SQL (`$queryRaw`/`$executeRaw`) bypasses the extension**, as does anything that talks
  to the database without the extended client.
- **Key backends:** the local file and passphrase sealing are tested. **AWS KMS is only tested
  against a mock**; **Vault is tested against a simulated transit API** and has an integration test
  (`CRYPLUS_TEST_VAULT_ADDR`) that has not yet been run against a real Vault. Validate both in your
  environment before relying on them.
- With Vault/KMS the *sealed master key is held in the sidecar's memory* (that is what keeps
  per-record encryption fast and cheap); it is not a per-record HSM call.
- **Windows:** key-file mode `0600` is not enforced by the OS there. Use the passphrase/Vault/KMS
  sealing and an ACL-restricted directory.
- The sidecar speaks plain HTTP on loopback and refuses other addresses unless `--allow-remote`.
  There is no built-in TLS/mTLS yet; put a TLS terminator in front if you must go off-host.
- No rate limiting. A transparent Postgres wire-protocol proxy is **not** implemented (see below).
- Tested with Prisma 7.10.1, Node 24, Go 1.27, PostgreSQL 18.

## Roadmap

1. External security review.
2. Row-id binding (`recordId`) for client-generated ids.
3. TLS/mTLS between app and sidecar; per-service tokens.
4. Plugins for other ORMs (Drizzle, TypeORM, SQLAlchemy, GORM).
5. Transparent Postgres proxy (large; column rewriting breaks `WHERE/ORDER BY/LIKE`, so it needs a
   query-aware design). Deliberately **not** attempted until 1–3 are done.

## License

Apache-2.0. See [LICENSE](LICENSE).
