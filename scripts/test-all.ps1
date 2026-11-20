param([switch]$E2E)
# Runs every suite. -E2E also runs the Prisma/Postgres and S3 suites
# (needs `node pg.ts` running in examples/prisma-demo for the Postgres one).
$ErrorActionPreference = "Continue"  # native tools write progress to stderr; we gate on exit codes
$root = Split-Path -Parent $PSScriptRoot

Write-Host "== Go core ==" -ForegroundColor Cyan
Push-Location "$root\core"
go vet ./...; if ($LASTEXITCODE) { exit 1 }
go test ./...; if ($LASTEXITCODE) { exit 1 }
New-Item -ItemType Directory -Force "$root\bin" | Out-Null
go build -o "$root\bin\cryplus-core.exe" ./cmd/cryplus-core; if ($LASTEXITCODE) { exit 1 }
Pop-Location

Write-Host "== Node SDK ==" -ForegroundColor Cyan
Push-Location "$root\sdk\node"
npx tsc --noEmit; if ($LASTEXITCODE) { exit 1 }
node --test --test-concurrency=1 test/client.test.ts test/prisma.test.ts test/stageA.test.ts test/scan.test.ts test/scan2.test.ts test/rowbinding.test.ts test/jobs.test.ts test/keycache.test.ts test/tls.test.ts test/ha.test.ts test/backup.test.ts test/pack.test.ts; if ($LASTEXITCODE) { exit 1 }
npm run build | Out-Null
Pop-Location

Write-Host "== Python SDK ==" -ForegroundColor Cyan
Push-Location "$root\sdk\python"
python -I -m unittest discover -s tests; if ($LASTEXITCODE) { exit 1 }
Pop-Location

if ($E2E) {
  Write-Host "== E2E: S3 ==" -ForegroundColor Cyan
  Push-Location "$root\tools\fakes3"; go build -o "$root\bin\fakes3.exe" .; Pop-Location
  Push-Location "$root\examples\s3-demo"; node --test --test-concurrency=1 s3.test.ts; if ($LASTEXITCODE) { exit 1 }; Pop-Location
  Write-Host "== E2E: Prisma 5.22 + CommonJS ==" -ForegroundColor Cyan
  Push-Location "$root\examples\prisma5-cjs"; node --test --test-concurrency=1 e2e.test.js; if ($LASTEXITCODE) { exit 1 }; Pop-Location
  Write-Host "== E2E: Prisma 5.22: filter oracle, row binding, tenantFrom, legacy rows, migration options ==" -ForegroundColor Cyan
  Push-Location "$root\examples\prisma5-cjs"; node --test --test-concurrency=1 oracle.test.js features.test.js; if ($LASTEXITCODE) { exit 1 }; Pop-Location
  Write-Host "== E2E: Prisma 5.22 + CommonJS, in-memory client (no key service) ==" -ForegroundColor Cyan
  Push-Location "$root\examples\prisma5-cjs"; $env:CRYPLUS_MODE = "memory"; node --test --test-concurrency=1 e2e.test.js; $mem = $LASTEXITCODE; Remove-Item Env:CRYPLUS_MODE; if ($mem) { exit 1 }; Pop-Location
  Write-Host "== E2E: Prisma 7 + Postgres ==" -ForegroundColor Cyan
  Push-Location "$root\examples\prisma-demo"; npx tsx --test --test-concurrency=1 e2e.test.ts; if ($LASTEXITCODE) { exit 1 }; Pop-Location
}
Write-Host "ALL GREEN" -ForegroundColor Green

