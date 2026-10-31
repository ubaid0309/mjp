# Shared helpers for the SecureMatrix Windows scripts (Windows PowerShell 5.1 compatible).

# Windows PowerShell 5.1 may default to TLS 1.0; Supabase and npm need TLS 1.2+.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Step([string]$text) { Write-Host ""; Write-Host "== $text" -ForegroundColor Cyan }
function Ok([string]$text) { Write-Host "  [ OK ] $text" -ForegroundColor Green }
function Warn([string]$text) { Write-Host "  [WARN] $text" -ForegroundColor Yellow }
function Fail([string]$text) {
    Write-Host ""
    Write-Host "  [FAIL] $text" -ForegroundColor Red
    exit 1
}

function Test-Command([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function Update-SessionPath {
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
}

function Confirm-Choice([string]$question) {
    $answer = Read-Host "  $question [Y/n]"
    return ($answer -eq "" -or $answer -match '^(y|yes)$')
}

function Ask([string]$label, [string]$default, [switch]$Secret, [switch]$Optional) {
    while ($true) {
        $shown = ""
        if ($default) {
            if ($Secret) { $shown = " [keep existing]" } else { $shown = " [$default]" }
        }
        if ($Secret) {
            $secure = Read-Host "  $label$shown" -AsSecureString
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try { $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        } else {
            $value = Read-Host "  $label$shown"
        }
        $value = $value.Trim()
        if (-not $value) { $value = $default }
        if ($value -or $Optional) { return $value }
        Write-Host "  This value is required." -ForegroundColor Yellow
    }
}

function Read-EnvFile([string]$path) {
    $values = @{}
    if (Test-Path $path) {
        foreach ($line in Get-Content $path) {
            if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
                $values[$Matches[1]] = $Matches[2].Trim().Trim("'").Trim('"')
            }
        }
    }
    return $values
}

# Writes KEY='value' lines as UTF-8 without BOM (Docker and python-dotenv both read single-quoted values literally).
function Write-EnvFile([string]$path, $values) {
    $lines = @("# Written by SecureMatrix setup. Do not commit this file.")
    foreach ($key in $values.Keys) {
        $lines += "$key='$($values[$key])'"
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($path, (($lines -join "`n") + "`n"), $utf8)
}

function Find-Python {
    $ErrorActionPreference = "Continue"
    foreach ($candidate in @(@("py", "-3"), @("python"))) {
        if (Test-Command $candidate[0]) {
            try {
                $extra = @($candidate | Select-Object -Skip 1)
                $version = & $candidate[0] @extra -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
                if ($version -and [version]$version -ge [version]"3.10") { return $candidate }
            } catch { }
        }
    }
    return $null
}

# Runs the Python found by Find-Python, e.g. Invoke-Python $py @("-m", "venv", ".venv")
function Invoke-Python($python, [string[]]$arguments) {
    $extra = @($python | Select-Object -Skip 1)
    & $python[0] @extra @arguments
}

function Start-DockerIfNeeded {
    # Native commands writing to stderr must not abort the script here.
    $ErrorActionPreference = "Continue"
    docker info *> $null
    if ($LASTEXITCODE -eq 0) { return }
    $desktop = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
    if (Test-Path $desktop) {
        Write-Host "  Starting Docker Desktop (this can take a minute)..." -ForegroundColor DarkGray
        Start-Process $desktop | Out-Null
        for ($i = 0; $i -lt 60; $i++) {
            Start-Sleep -Seconds 3
            docker info *> $null
            if ($LASTEXITCODE -eq 0) { return }
        }
    }
    Fail "Docker Desktop is installed but not running. Open Docker Desktop, wait until it says 'Engine running', then run this again."
}

function Stop-PortListener([int]$port) {
    $ErrorActionPreference = "Continue"
    $owners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($procId in $owners) {
        if ($procId -gt 0) { & taskkill /PID $procId /T /F *> $null }
    }
    return [bool]$owners
}

function Wait-ForUrl([string]$url, [int]$seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        try {
            Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 | Out-Null
            return $true
        } catch { Start-Sleep -Seconds 1 }
    }
    return $false
}
