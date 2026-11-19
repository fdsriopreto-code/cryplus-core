# Deploying cryplus-core

Everything here was exercised by the test suites in this repository, **except** the Dockerfile and the
compose file at the end, which have not been built in this environment (marked below).

## Topologies

| | When | Notes |
|---|---|---|
| **A. Loopback sidecar** | One app instance, same host | `cryplus-core` on `127.0.0.1`, plain HTTP, one shared token. Simplest. |
| **B. Shared service, 1 leader + N followers** | Several app replicas (e.g. Operax on Easypanel) | HTTPS (TLS 1.3), optional mTLS, one token per service, all instances share one sealed key file. |

In B, **exactly one instance is the leader** (it may create and rotate keys). Followers start with
`--follower`: they never create or rotate keys, they follow the leader's key file, and they keep serving
if the leader is down. The SDK takes several URLs and fails over between them.

## 1. Generate credentials (once)

```bash
# service tokens: only SHA-256 hashes go into the file; the token itself is printed once
cryplus-core token new --name operax-api --roles crypt --tenants '*'        --file tokens.json
cryplus-core token new --name backup-job --roles crypt --tenants 'backup:*' --file tokens.json
cryplus-core token new --name ops        --roles admin --tenants '*'        --file tokens.json
```

- `crypt` = encrypt/decrypt/blind index/rewrap/streams. `admin` = key status and rotation. Keep them on separate services.
- `--tenants` is a mandatory allowlist (`'*'`, exact ids, or `prefix*`). A service can only touch its tenants;
  attempts are refused and audited. Use a narrow allowlist for jobs (e.g. backups).
- Edit `tokens.json` to revoke a service. A running core reloads it within `--reload-interval` (default 5 s).
  If the new file is invalid, the previous valid set stays in force and an error is logged.

TLS: use your own PKI in production. For development and tests: `cryplus-core tls dev-certs --out ./certs`.

## 2. Run

```bash
export CRYPLUS_PASSPHRASE='<long random passphrase, from your secret manager>'   # seals the key file at rest (Argon2id)

# leader
cryplus-core --listen 0.0.0.0:7788 --allow-remote \
  --keyfile /data/keys/cryplus-keys.json \
  --tokens-file /data/tokens.json \
  --tls-cert /data/tls/server.pem --tls-key /data/tls/server-key.pem --client-ca /data/tls/ca.pem

# follower(s): same command plus --follower, and the same key file (shared volume)
```

Rules the binary enforces:
- A non-loopback address needs `--allow-remote` **and** TLS. Plain HTTP is loopback only.
- TLS is 1.3 only. `--client-ca` turns on mutual TLS (a valid client certificate is required **and** the bearer token).
- The server certificate is re-read when the files change, so renewal needs no restart (a broken replacement keeps the last good certificate).
- A follower refuses to start if the key file does not exist (it must never mint keys by accident).

Client side (Node): `new Cryplus({ url: ["https://core-1:7788","https://core-2:7788"], token, tls: { ca, cert, key } })`,
or the environment: `CRYPLUS_URL` (comma-separated), `CRYPLUS_TOKEN`, `CRYPLUS_CA`, `CRYPLUS_CLIENT_CERT`, `CRYPLUS_CLIENT_KEY`.
There is deliberately no "skip certificate verification" option.

### Key export (opt-in, off by default)

`--allow-key-export` lets services holding the **`keys`** role fetch tenant keys (`POST /v1/keys/tenant`, `/v1/keys/index`) so the Node SDK can encrypt locally with a short-lived cache
(`new Cryplus({ keyCache: { ttlMs, staleMs } })`): zero round trips when warm, and it keeps serving while the service is briefly down. Read the trade-off before enabling it:
the tenant key then lives in the client's memory, individual operations stop being audited per call (only key fetches are: `key_export`, `index_key_export`), a revoked service keeps
working until its cached keys expire, and rotation reaches a client after its `ttlMs`. The `keys` role obeys the same tenant allowlist as everything else; give it only to services that need it, with the narrowest list.
Every fetch is audited with the calling service, and refused attempts too.

## 3. The key file is the crown jewel

- Losing the key file **or** the passphrase means the data is permanently unrecoverable. There is no backdoor.
- Back up the key file **separately from the database and from the data backups**, and store the passphrase in a different system.
  The key file is sealed (useless without the passphrase), so it may be stored offsite.
- Rotation only ever **adds** versions: old versions must stay in the file as long as any data (or backup) still uses them.
- Do the restore drill below before you rely on it.

Shared-volume caveats (important): all instances must see the same file through a filesystem that supports atomic rename and
exclusive file creation (a local volume shared by containers on the same host is fine). Network filesystems (NFS/SMB) can delay
mtime visibility or weaken lock semantics; they were **not** tested. For multi-host setups prefer one leader plus followers
that receive the key file by a deploy step, and rotate only through the leader.

## 4. Rotation runbook

1. Take a backup of the key file.
2. Rotate through the leader (`admin` service): `await cryplus.rotateKeys()` (or `POST /v1/keys/rotate`). The SDK finds the leader among its URLs.
3. Followers pick up the new version within `--reload-interval`; they also reload on demand if they meet a ciphertext from a newer version.
4. Move existing data to the new version: `migrateModel(...)` for tables, `rewrapStream` for stored files. Both are idempotent and resumable.
5. Keep the old versions in the key file. They are needed for old backups.

A rejected key-file change (a version changed or disappeared, the current version went backwards, the index key changed) is **not applied**:
the instance logs `key file NOT reloaded` and keeps the keys it already trusts.

## 5. Disaster recovery: restore a backup with no running service

```bash
export CRYPLUS_PASSPHRASE='<passphrase>'
cryplus-core file decrypt --keyfile ./cryplus-keys.json \
  --tenant backup:2026-11 --collection backups --field operax-2026-11-19.dump  operax.dump.cp  operax.dump
```

Offline commands open the key file read-only and never create keys. The output is written to `*.partial` and renamed only after every chunk
verified, so a corrupt or truncated backup leaves no file that looks like a restore. The tenant/collection/field must match what was used to encrypt.

## 6. Operating it

- **Audit log** (`--audit-log`, JSON lines): time, operation, service, tenant, collection, field, KEK version, ok/code, remote. Never plaintext, ciphertext or keys.
  Alert on bursts of `decryption_failed`, `tenant_forbidden`, `role_forbidden` and `unauthorized`.
- **Audit volume**: `--audit-level denied` logs only failures and administrative events (rotation, key export); `--audit-sample N` keeps 1 in N successful data operations (failures and administrative
  events are never sampled); `--audit-max-mb M --audit-keep K` rolls the file over at M MiB and keeps K old files, so retention is bounded by about M * (K+1) MiB. Sampling and `denied` reduce what an investigation can see: choose deliberately.
- **Health**: `GET /healthz` (no auth). Run at least two instances behind the SDK's URL list. In the application use `cryplus.ready()` (`service` / `degraded` / `down`) for readiness and `cryplus.stats()` or `prometheusSink(prom-client)` for metrics.
- **Availability**: if every instance is down the app cannot read encrypted fields. Plan for that.
- No rate limiting is built in; put the service on a private network.

## 7. Container files (NOT built or run in this environment)

```dockerfile
# core/Dockerfile: build from the repository root: docker build -f core/Dockerfile -t cryplus-core .
FROM golang:1.27 AS build
WORKDIR /src
COPY core/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cryplus-core ./cmd/cryplus-core

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cryplus-core /cryplus-core
USER nonroot
ENTRYPOINT ["/cryplus-core"]
```

```yaml
# docker-compose sketch: one leader, one follower, one shared volume for the sealed key file
services:
  cryplus-leader:
    image: cryplus-core
    command: ["--listen=0.0.0.0:7788","--allow-remote","--keyfile=/keys/cryplus-keys.json","--tokens-file=/secrets/tokens.json",
              "--tls-cert=/secrets/server.pem","--tls-key=/secrets/server-key.pem","--client-ca=/secrets/ca.pem","--audit-log=-"]
    environment: { CRYPLUS_PASSPHRASE_FILE: /run/secrets/cryplus_passphrase }   # or CRYPLUS_PASSPHRASE
    secrets: [cryplus_passphrase]
    volumes: ["cryplus-keys:/keys", "./secrets:/secrets:ro"]
  cryplus-follower:
    image: cryplus-core
    command: ["--follower","--listen=0.0.0.0:7788","--allow-remote","--keyfile=/keys/cryplus-keys.json","--tokens-file=/secrets/tokens.json",
              "--tls-cert=/secrets/server.pem","--tls-key=/secrets/server-key.pem","--client-ca=/secrets/ca.pem","--audit-log=-"]
    environment: { CRYPLUS_PASSPHRASE_FILE: /run/secrets/cryplus_passphrase }
    secrets: [cryplus_passphrase]
    volumes: ["cryplus-keys:/keys", "./secrets:/secrets:ro"]
    depends_on: [cryplus-leader]
volumes: { cryplus-keys: {} }
secrets: { cryplus_passphrase: { file: ./secrets/passphrase.txt } }
```

The passphrase (and the single shared token) can be given as `CRYPLUS_PASSPHRASE` / `CRYPLUS_TOKEN`, or as a file path in
`CRYPLUS_PASSPHRASE_FILE` / `CRYPLUS_TOKEN_FILE` (Docker/Kubernetes secrets), which keeps the value out of `docker inspect`.
