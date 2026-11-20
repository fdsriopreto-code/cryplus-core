#!/bin/sh
# Runs inside node:20-alpine. /work holds: cryplus.tgz, cryplus-core (linux/amd64, static), schema.prisma, smoke.js
set -e
apk add --no-cache openssl >/dev/null  # Prisma engines need openssl on alpine (the Operax image must have it too)
cd /work
rm -rf app && mkdir -p app/prisma && cd app
cp /work/schema.prisma prisma/schema.prisma
npm init -y >/dev/null
# the SDK from the vendored tarball, offline-style install of dev=false, exactly as a Dockerfile would
npm install /work/cryplus.tgz --omit=dev --no-audit --no-fund 2>&1 | tail -2
npm install @prisma/client@5.22.0 prisma@5.22.0 --no-audit --no-fund 2>&1 | tail -2
export DATABASE_URL="postgresql://cryplus:cryplus@pg:5432/cryplus?schema=alp"
npx prisma generate 2>&1 | grep -i -E "generated|error" || true
npx prisma db push --skip-generate 2>&1 | tail -2
export CRYPLUS_PASSPHRASE="alpine test passphrase, long enough"
export CRYPLUS_TOKEN="alpine-token-0123456789abcdef"
/work/cryplus-core --listen 127.0.0.1:7788 --keyfile /tmp/keys.json --audit-log "" --allow-key-export >/tmp/core.log 2>&1 &
i=0; until wget -q -O- http://127.0.0.1:7788/healthz >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 50 ] && { cat /tmp/core.log; exit 1; }; sleep 0.2; done
cp /work/smoke.js /work/app/smoke.js
node /work/app/smoke.js
