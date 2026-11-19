# Design: per-tenant crypto-shredding (NOT implemented)

Goal: when a tenant asks for deletion (LGPD), destroy a key so that **all of that tenant's data becomes unrecoverable**, including copies in backups
and in replicas that were never touched, without having to find and delete every copy.

This is a design for review. **Nothing below exists in the code yet.**

## Why it does not work today

A tenant's KEK is *derived*: `HKDF(master[version], "cryplus/kek/v1\0" + tenant)`. Anyone holding the master key can re-derive it, so there is no
per-tenant key to destroy. Deleting a tenant's rows removes live data but leaves ciphertext in every backup, and the master key still opens it.

## Proposal

1. **A per-tenant random salt, stored in the key file.** New derivation for enrolled tenants:
   `KEK = HKDF(master[version], salt = tenant_salt, info = "cryplus/kek/v2\0" + tenant)`.
   `tenant_salt` is 32 random bytes held next to the master keys (sealed the same way).
   Destroying the salt makes the KEK underivable even for someone who still has every master key. The master key alone no longer suffices.
2. **Format flag.** Today the envelope header has `[0] format = 1`. Enrolled tenants write `format = 2`, whose wrapped DEK is bound to the salted KEK. Format 1 stays readable.
   (A flag in the KEK version field was rejected: it would collide with version numbers.)
3. **Enrollment** of an existing tenant is a migration: unwrap each DEK with the legacy KEK and wrap it with the salted one (`rewrap` already exists; it would take a target
   format). Until then the tenant is *not* shreddable, and the API says so.
4. **API** (admin role, audited, two-step):
   - `POST /v1/tenants/{tenant}/enroll` creates the salt (idempotent).
   - `POST /v1/tenants/{tenant}/shred` with `{ "confirm": "<tenant>", "reason": "..." }` records a tombstone, deletes the salt from the key file atomically, and refuses all further
     key operations for that tenant (`tenant_shredded`). It returns the time and the number of key versions affected.
   - `GET /v1/tenants/{tenant}` returns `enrolled | shredded | legacy`.
   Blind indexes are keyed per tenant from the index master; shredding must also stop serving them (and the global index, which is a separate domain, is *not* shredded).
5. **Followers and the key cache.** A shred must propagate: followers pick it up through the existing key-file reload (the salt disappears and the tombstone appears);
   SDKs with a key cache keep working until `ttlMs` expires, so the guarantee is "unrecoverable once every cache has expired".

## Guarantees and caveats (to state to the data subject honestly)

- **Unrecoverable only if every copy of the key material is gone.** That includes **backups of the key file** (the sealed key file is backed up separately by design): a backup taken before the shred
  still contains the salt. The shredding procedure must therefore include destroying or rotating those key-file backups, or the "deletion" is reversible by whoever holds one.
  This is the main operational caveat and the reason the design keeps the key file in one place.
- Data that was **decrypted and copied elsewhere** (exports, caches, logs, search indexes in clear text) is outside the guarantee.
- **Plaintext in `Configuracao.valor`-style columns, names, addresses and anything not marked `@encrypted`** is unaffected: crypto-shredding only covers encrypted columns. A tenant deletion must still delete those.
- The blind indexes of a shredded tenant should be deleted from the database too (they reveal equality); shredding the key makes them useless for new lookups but they remain as opaque tokens.
- Not a substitute for deleting rows. It is what makes the leftovers (backups, replicas, old dumps) harmless.

## Open questions

- Salt per tenant **per key version**, or one salt for the tenant? (One salt is simpler; per-version allows partial shredding of old data, which nobody has asked for.)
- Where tombstones live so a restored old key file cannot resurrect a tenant (a signed tombstone list outside the key file?).
- Whether enrollment should become mandatory for new tenants (probably yes: new tenants enrolled at creation, so only old tenants need the migration).
- Legal: what proof of deletion the Operax data-deletion page should give (the shred record, with timestamp and key versions, is the evidence).

## What it costs

Roughly: a new envelope format version and its tests (including interop with the SDK's local mode), a key-file schema extension with the same history-protection rules as today,
three endpoints, followers' reload rules, a tenant-enrollment migration, and an operator runbook for the backup caveat. It should be reviewed before it is built.
