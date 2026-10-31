# Stops SecureMatrix: the worker (container or Python process) and the web dev server.
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
. "$PSScriptRoot\common.ps1"

$mode = "docker"
$modeFile = Join-Path $Root ".securematrix-mode"
if (Test-Path $modeFile) { $mode = (Get-Content $modeFile -Raw).Trim() }

if ($mode -eq "docker" -and (Test-Command "docker")) {
    docker compose stop worker *> $null
    Ok "Worker container stopped"
} elseif (Stop-PortListener 8787) {
    Ok "Worker stopped"
}
if (Stop-PortListener 5173) { Ok "Web app stopped" } else { Ok "Web app was not running" }
