# Starts SecureMatrix (worker + web app) and opens the browser. Used by start.bat and at the end of setup.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
. "$PSScriptRoot\common.ps1"

if (-not (Test-Path (Join-Path $Root "worker\.env")) -or -not (Test-Path (Join-Path $Root "web\node_modules"))) {
    Fail "SecureMatrix is not set up yet. Run setup.bat first."
}
$mode = "docker"
$modeFile = Join-Path $Root ".securematrix-mode"
if (Test-Path $modeFile) { $mode = (Get-Content $modeFile -Raw).Trim() }

Step "Starting the scan worker ($mode)"
if ($mode -eq "docker") {
    Start-DockerIfNeeded
    docker compose up -d worker
    if ($LASTEXITCODE -ne 0) { Fail "Could not start the worker container. Try: docker compose up --build worker" }
} else {
    $workerDir = Join-Path $Root "worker"
    Start-Process -FilePath "cmd.exe" -WorkingDirectory $workerDir `
        -ArgumentList "/k", "title SecureMatrix worker && .venv\Scripts\python.exe -m securematrix_worker run"
}
if (Wait-ForUrl "http://localhost:8787/health" 90) { Ok "Worker API is up at http://localhost:8787" }
else { Warn "The worker did not answer yet. Check it with: docker compose logs worker" }

Step "Starting the web app"
$webDir = Join-Path $Root "web"
Start-Process -FilePath "cmd.exe" -WorkingDirectory $webDir -ArgumentList "/k", "title SecureMatrix web && npm run dev"
if (Wait-ForUrl "http://localhost:5173" 60) {
    Ok "Web app is up"
    Start-Process "http://localhost:5173"
} else {
    Warn "The web app did not start within a minute; check the 'SecureMatrix web' window."
}
Write-Host ""
Write-Host "  SecureMatrix is running at http://localhost:5173" -ForegroundColor Green
Write-Host "  Keep the 'SecureMatrix web' window open. Use stop.bat to shut everything down."
