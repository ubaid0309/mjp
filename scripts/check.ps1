# Runs the SecureMatrix health check: database, storage, admin, knowledge base, Semgrep, OpenAI, worker API.
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
. "$PSScriptRoot\common.ps1"

$mode = "docker"
$modeFile = Join-Path $Root ".securematrix-mode"
if (Test-Path $modeFile) { $mode = (Get-Content $modeFile -Raw).Trim() }

if ($mode -eq "docker") {
    $running = docker compose ps --status running -q worker 2>$null
    if ($running) { docker compose exec worker python -m securematrix_worker doctor --api http://localhost:8787 }
    else { docker compose run --rm worker python -m securematrix_worker doctor }
} else {
    Push-Location (Join-Path $Root "worker")
    .\.venv\Scripts\python.exe -m securematrix_worker doctor --api http://localhost:8787
    Pop-Location
}
