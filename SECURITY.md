# Security policy

## Status

Pre-1.0 and **not externally audited**. The primitives are standard (XChaCha20-Poly1305, AES-256-GCM, HKDF-SHA256, HMAC-SHA256,
Argon2id, TLS 1.3) and come from Go's standard library and `golang.org/x/crypto`; Cryplus does not implement any cipher. The way they are
composed (envelope format, context binding, STREAM chunking, key-file reload rules) has not been reviewed by a third party.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting ("Security" tab, "Report a vulnerability") on this repository. Do not open a public issue
for a vulnerability. Include the version/commit, what you could do, and a minimal reproduction.

## What Cryplus is meant to protect

- Data at rest and in dumps/backups: a stolen database, backup or bucket listing yields ciphertext, with a separate key per record.
- Cross-tenant, cross-field and cross-object moves: ciphertext is bound to its tenant/collection/field (S3 objects to bucket and key).
- Tampering, truncation and reordering of stored values and streams are detected.
- Key hygiene: sealed key file, versioned keys, rotation without re-encrypting data, per-service credentials, TLS 1.3/mTLS, audit trail.

## What it does not protect (by design)

- A compromised application server or any holder of a service token can request decryption of what that service may read.
- Row swaps within one tenant and field are not detected (no row-id binding yet).
- Blind indexes reveal equality and frequency of values.
- Raw SQL and any path that bypasses the SDK sees ciphertext; availability depends on the key service.
- Loss of the key file or its passphrase is unrecoverable.

See the README "Limitations" and docs/DEPLOY.md for operating guidance.
