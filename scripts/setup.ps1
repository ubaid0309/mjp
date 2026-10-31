# SecureMatrix one-time setup for Windows.
# Run it by double-clicking setup.bat in the project folder. Safe to run again: existing values are offered as defaults.
#
#   setup.bat            Docker mode (recommended): the worker runs in Docker Desktop
#   setup.bat -Native    No Docker: the worker runs in a local Python virtual environment
param([switch]$Native)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
. "$PSScriptRoot\common.ps1"

Write-Host ""
Write-Host "  SecureMatrix setup" -ForegroundColor Cyan
Write-Host "  This takes about 5-10 minutes the first time (mostly downloads)." -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
Step "1/6  Checking prerequisites"
# ---------------------------------------------------------------------------
if (-not (Test-Command "node")) {
    Warn "Node.js is not installed."
    if ((Test-Command "winget") -and (Confirm-Choice "Install Node.js LTS with winget now?")) {
        winget install -e --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
        Update-SessionPath
    }
    if (-not (Test-Command "node")) { Fail "Install Node.js 20 LTS from https://nodejs.org, then run setup again." }
}
$nodeMajor = [int]((node --version).TrimStart("v").Split(".")[0])
if ($nodeMajor -lt 18) { Fail "Node.js $(node --version) is too old. Install Node.js 20 LTS from https://nodejs.org." }
Ok "Node.js $(node --version)"

if (-not $Native) {
    if (-not (Test-Command "docker")) {
        Warn "Docker Desktop is not installed."
        Write-Host "     Either install Docker Desktop (needs a restart), or run 'setup.bat -Native' to use Python instead."
        if ((Test-Command "winget") -and (Confirm-Choice "Install Docker Desktop with winget now?")) {
            winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements
            Fail "Docker Desktop installed. Restart Windows, open Docker Desktop once, then run setup.bat again."
        }
        Fail "Docker is required for the default setup. Alternative: setup.bat -Native"
    }
    Start-DockerIfNeeded
    Ok "Docker is running"
} else {
    $script:Python = Find-Python
    if (-not $script:Python) {
        Warn "Python 3.10+ is not installed."
        if ((Test-Command "winget") -and (Confirm-Choice "Install Python 3.12 with winget now?")) {
            winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
            Update-SessionPath
            $script:Python = Find-Python
        }
        if (-not $script:Python) { Fail "Install Python 3.12 from https://www.python.org (tick 'Add to PATH'), then run setup again." }
    }
    Ok "Python: $($script:Python -join ' ')"
}

# ---------------------------------------------------------------------------
Step "2/6  Supabase and OpenAI settings"
# ---------------------------------------------------------------------------
$workerEnvPath = Join-Path $Root "worker\.env"
$webEnvPath = Join-Path $Root "web\.env.local"
$old = Read-EnvFile $workerEnvPath
$oldWeb = Read-EnvFile $webEnvPath

Write-Host "  Open your project on https://supabase.com/dashboard, then:" -ForegroundColor DarkGray
Write-Host "    Project Settings > API (or 'API Keys'): Project URL, anon/publishable key, service_role/secret key" -ForegroundColor DarkGray
Write-Host "    Connect (top bar) > Session pooler: the connection string; replace [YOUR-PASSWORD] with your DB password" -ForegroundColor DarkGray
Write-Host ""

do {
    $supabaseUrl = (Ask "Supabase Project URL" $old["SUPABASE_URL"]).TrimEnd("/")
    $validUrl = $supabaseUrl -match '^https?://[^\s/]+$'
    if (-not $validUrl) { Warn "That should look like https://abcdefgh.supabase.co" }
} until ($validUrl)
$anonKey = Ask "Supabase anon / publishable key" $oldWeb["VITE_SUPABASE_ANON_KEY"]
$serviceKey = Ask "Supabase service_role / secret key" $old["SUPABASE_SERVICE_ROLE_KEY"] -Secret
$databaseUrl = Ask "Database connection string (Session pooler; Enter to skip if you ran the SQL yourself)" $old["DATABASE_URL"] -Secret -Optional
$openaiKey = Ask "OpenAI API key (Enter to skip; AI search/explanations stay off)" $old["OPENAI_API_KEY"] -Secret -Optional

foreach ($v in @($supabaseUrl, $anonKey, $serviceKey, $databaseUrl, $openaiKey)) {
    if ($v -and $v.Contains("'")) { Fail "Values cannot contain a single quote ('). Please check what you pasted." }
}
if ($databaseUrl -and $databaseUrl -match '\[YOUR-PASSWORD\]') { Fail "Replace [YOUR-PASSWORD] in the connection string with your database password." }

Write-Host "  Checking the Supabase keys..." -ForegroundColor DarkGray
try {
    Invoke-RestMethod -Uri "$supabaseUrl/auth/v1/settings" -Headers @{ apikey = $anonKey } -TimeoutSec 20 | Out-Null
    Ok "Supabase project reachable, anon key accepted"
} catch {
    Fail "Supabase rejected the URL or anon key ($($_.Exception.Message)). Copy them again from Project Settings > API."
}

Write-Host ""
Write-Host "  Administrator account for the app (created already confirmed, no email needed)" -ForegroundColor DarkGray
$adminEmail = Ask "Admin email" $(if ($old["SM_ADMIN_EMAIL_HINT"]) { $old["SM_ADMIN_EMAIL_HINT"] } else { "admin@securematrix.local" })
$adminName = Ask "Admin full name" "Project Admin"
do {
    $adminPassword = Ask "Admin password (min 8 characters)" "" -Secret
    if ($adminPassword.Length -lt 8) { Warn "Use at least 8 characters." }
} until ($adminPassword.Length -ge 8)

# ---------------------------------------------------------------------------
Step "3/6  Writing configuration files"
# ---------------------------------------------------------------------------
$workerEnv = [ordered]@{
    SUPABASE_URL              = $supabaseUrl
    SUPABASE_SERVICE_ROLE_KEY = $serviceKey
    DATABASE_URL              = $databaseUrl
    OPENAI_API_KEY            = $openaiKey
    OPENAI_CHAT_MODEL         = $(if ($old["OPENAI_CHAT_MODEL"]) { $old["OPENAI_CHAT_MODEL"] } else { "gpt-4o-mini" })
    SM_CORS_ORIGINS           = "http://localhost:5173,http://127.0.0.1:5173"
    SM_ADMIN_EMAIL_HINT       = $adminEmail
}
if ($Native) {
    $workerEnv["SEMGREP_BIN"] = Join-Path $Root "worker\.venv-semgrep\Scripts\semgrep.exe"
    $workerEnv["SM_WORK_DIR"] = Join-Path $env:TEMP "securematrix"
}
Write-EnvFile $workerEnvPath $workerEnv
Write-EnvFile $webEnvPath ([ordered]@{
    VITE_SUPABASE_URL      = $supabaseUrl
    VITE_SUPABASE_ANON_KEY = $anonKey
    VITE_WORKER_API_URL    = "http://localhost:8787"
})
Ok "worker\.env and web\.env.local written (they are git-ignored)"
Set-Content -Path (Join-Path $Root ".securematrix-mode") -Value $(if ($Native) { "native" } else { "docker" }) -Encoding ASCII

# ---------------------------------------------------------------------------
Step "4/6  Building the scan worker"
# ---------------------------------------------------------------------------
if (-not $Native) {
    docker compose build worker
    if ($LASTEXITCODE -ne 0) { Fail "Docker build failed. Check your internet connection and that Docker Desktop is running." }
    Ok "Worker image built (includes Semgrep)"
} else {
    Push-Location (Join-Path $Root "worker")
    if (-not (Test-Path ".venv")) { Invoke-Python $script:Python @("-m", "venv", ".venv") }
    .\.venv\Scripts\python.exe -m pip install --quiet --upgrade pip
    .\.venv\Scripts\python.exe -m pip install --quiet -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Pop-Location; Fail "pip install failed." }
    if (-not (Test-Path ".venv-semgrep")) { Invoke-Python $script:Python @("-m", "venv", ".venv-semgrep") }
    .\.venv-semgrep\Scripts\python.exe -m pip install --quiet semgrep==1.183.0
    if ($LASTEXITCODE -ne 0) { Pop-Location; Fail "Installing Semgrep failed. Native Windows support in Semgrep is limited; Docker mode is recommended." }
    Pop-Location
    Ok "Python environments ready"
}

# ---------------------------------------------------------------------------
Step "5/6  Database, admin account and knowledge base"
# ---------------------------------------------------------------------------
$env:SM_ADMIN_EMAIL = $adminEmail
$env:SM_ADMIN_PASSWORD = $adminPassword
$env:SM_ADMIN_NAME = $adminName
try {
    if (-not $Native) {
        docker compose run --rm -e SM_ADMIN_EMAIL -e SM_ADMIN_PASSWORD -e SM_ADMIN_NAME worker python -m securematrix_worker bootstrap
    } else {
        Push-Location (Join-Path $Root "worker")
        .\.venv\Scripts\python.exe -m securematrix_worker bootstrap
        Pop-Location
    }
    $bootstrapExit = $LASTEXITCODE
} finally {
    Remove-Item Env:SM_ADMIN_PASSWORD -ErrorAction SilentlyContinue
}
if ($bootstrapExit -eq 2) { Fail "Setup stopped (see the error above). Fix it and run setup.bat again; finished steps are skipped." }
if ($bootstrapExit -ne 0) { Warn "Some checks failed or are only warnings (see above). The app may still work; run check.bat later." }

# ---------------------------------------------------------------------------
Step "6/6  Installing the web app"
# ---------------------------------------------------------------------------
Push-Location (Join-Path $Root "web")
npm ci --no-audit --no-fund
$npmExit = $LASTEXITCODE
Pop-Location
if ($npmExit -ne 0) { Fail "npm install failed. Check your internet connection and run setup again." }
Ok "Web app dependencies installed"

Write-Host ""
Write-Host "  Setup complete." -ForegroundColor Green
Write-Host "  Sign in with: $adminEmail" -ForegroundColor Green
Write-Host "  Demo project to upload: demo\bytemart-vulnerable.zip"
Write-Host ""
& "$PSScriptRoot\start.ps1"
