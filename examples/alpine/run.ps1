# Packs the SDK, cross-compiles a linux core, and runs smoke.js inside node:20-alpine against a postgres:16-alpine container.
# Needs Docker. Leaves nothing running: the Postgres container and the network are removed at the end.
$ErrorActionPreference = "Continue"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$work = "$root\.alpine"
New-Item -ItemType Directory -Force $work | Out-Null
Remove-Item "$work\*" -Force -ErrorAction SilentlyContinue

Push-Location "$root\core"
$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -trimpath -ldflags="-s -w" -o "$work\cryplus-core" ./cmd/cryplus-core
$rc = $LASTEXITCODE
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
Pop-Location
if ($rc) { Write-Host "core build failed"; exit 1 }

Push-Location "$root\sdk\node"
npm run build | Out-Null
$tgz = (npm pack --pack-destination $work --silent | Select-Object -Last 1).Trim()
Pop-Location
Move-Item "$work\$tgz" "$work\cryplus.tgz" -Force

Copy-Item "$root\examples\prisma5-cjs\prisma\schema.prisma" "$work\schema.prisma"
Copy-Item "$PSScriptRoot\smoke.js" "$work\smoke.js"
(Get-Content "$PSScriptRoot\inside.sh" -Raw).Replace("`r`n", "`n") | Set-Content -NoNewline -Encoding ascii "$work\inside.sh"

$net = "cryplus-alpine-test"
docker network create $net | Out-Null
docker rm -f cryplus-alpine-pg 2>$null | Out-Null
docker run -d --rm --name cryplus-alpine-pg --network $net --network-alias pg -e POSTGRES_USER=cryplus -e POSTGRES_PASSWORD=cryplus -e POSTGRES_DB=cryplus postgres:16-alpine | Out-Null
for ($i = 0; $i -lt 60; $i++) {
  docker exec cryplus-alpine-pg pg_isready -U cryplus -d cryplus 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) { break }
  Start-Sleep -Milliseconds 500
}
Start-Sleep -Seconds 2   # pg_isready is true slightly before the init scripts finish

docker run --rm --network $net -v "${work}:/work" node:20-alpine sh /work/inside.sh
$code = $LASTEXITCODE

docker rm -f cryplus-alpine-pg 2>$null | Out-Null
docker network rm $net 2>$null | Out-Null
exit $code
