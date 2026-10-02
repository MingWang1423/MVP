<#
============================================================================
 start_all.ps1 - one-click start (PROJECT_PLAN.md §5.10 P9, Day13 task 6)
----------------------------------------------------------------------------
 What it does:
   1) docker compose up -d        -> postgres / neo4j / chroma / api / frontend
   2) wait until all services report (healthy)
   3) python -m scripts.init_db && python -m scripts.seed_sources
   4) optionally start the collector scheduler in background (host venv)
   5) optionally start Streamlit locally when the frontend container is skipped
   6) print access URLs (API docs / frontend / neo4j browser)

 Usage:
   powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
   powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1 -SkipScheduler
   powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1 -LocalStreamlit

 PIDs of background jobs are written to .run\*.pid (see stop_all.ps1).
============================================================================
#>
param(
    [switch]$SkipScheduler,
    [switch]$SkipStreamlit,
    [switch]$LocalStreamlit,
    [int]$TimeoutSeconds = 420
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$RunDir = Join-Path $Root '.run'
if (-not (Test-Path $RunDir)) { New-Item -ItemType Directory -Path $RunDir | Out-Null }

$Python = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) { $Python = 'python' }

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host ("=== " + $Message) -ForegroundColor Cyan
}

function Wait-ComposeHealthy([int]$Timeout) {
    $deadline = (Get-Date).AddSeconds($Timeout)
    while ((Get-Date) -lt $deadline) {
        $rows = docker compose ps --format "{{.Service}}|{{.Status}}" 2>$null
        $status = @{}
        foreach ($row in $rows) {
            $parts = $row -split '\|'
            if ($parts.Count -eq 2) { $status[$parts[0]] = $parts[1] }
        }
        $expected = @('postgres', 'neo4j', 'chroma', 'api', 'frontend')
        $notReady = @()
        foreach ($name in $expected) {
            if (-not $status.ContainsKey($name) -or $status[$name] -notmatch 'healthy') { $notReady += $name }
        }
        if ($notReady.Count -eq 0) { return $true }
        Write-Host ("  waiting: " + ($notReady -join ', '))
        Start-Sleep -Seconds 8
    }
    return $false
}

Write-Step "1/6 docker compose up -d"
docker compose up -d --build

Write-Step "2/6 wait for healthy (timeout ${TimeoutSeconds}s)"
if (Wait-ComposeHealthy -Timeout $TimeoutSeconds) {
    Write-Host "  all 5 services are healthy" -ForegroundColor Green
} else {
    Write-Warning "not all services became healthy in time; run 'docker compose ps' to inspect"
}
docker compose ps

Write-Step "3/6 init db + seed sources"
& $Python -m scripts.init_db
& $Python -m scripts.seed_sources

if (-not $SkipScheduler) {
    Write-Step "4/6 start collector scheduler (background)"
    $sched = Start-Process -FilePath $Python `
        -ArgumentList '-m', 'scripts.run_scheduler', '--source', 'all' `
        -WorkingDirectory $Root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $RunDir 'scheduler.log') `
        -RedirectStandardError (Join-Path $RunDir 'scheduler.err')
    $sched.Id | Out-File (Join-Path $RunDir 'scheduler.pid')
    Write-Host ("  scheduler pid=" + $sched.Id + " (log: .run\scheduler.log)") -ForegroundColor Green
} else {
    Write-Step "4/6 scheduler skipped (-SkipScheduler)"
}

if ($LocalStreamlit -and -not $SkipStreamlit) {
    Write-Step "5/6 start Streamlit locally on 8501 (host venv)"
    $st = Start-Process -FilePath $Python `
        -ArgumentList '-m', 'streamlit', 'run', 'frontend/app.py', '--server.port', '8501', '--server.address', '0.0.0.0', '--server.headless', 'true' `
        -WorkingDirectory $Root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $RunDir 'streamlit.log') `
        -RedirectStandardError (Join-Path $RunDir 'streamlit.err')
    $st.Id | Out-File (Join-Path $RunDir 'streamlit.pid')
    Write-Host ("  streamlit pid=" + $st.Id) -ForegroundColor Green
} else {
    Write-Step "5/6 Streamlit runs in the 'frontend' container (use -LocalStreamlit for host mode)"
}

Write-Step "6/6 access URLs"
Write-Host "  API docs    : http://localhost:8000/docs"
Write-Host "  API health  : http://localhost:8000/healthz"
Write-Host "  Frontend    : http://localhost:8501"
Write-Host "  Neo4j       : http://localhost:7474"
Write-Host "  Stop all    : powershell -ExecutionPolicy Bypass -File scripts\stop_all.ps1"
