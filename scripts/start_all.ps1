<#
============================================================================
 start_all.ps1 - one-click start (PROJECT_PLAN.md §5.10 P9, Day13 task 6)
----------------------------------------------------------------------------
 What it does:
   1) docker compose up -d        -> postgres / neo4j / chroma / api / scheduler / frontend-react
   2) wait until all services report (healthy)
   3) python -m scripts.init_db && python -m scripts.seed_sources
   4) optionally start the collector scheduler in background (host venv; compose 已自带 scheduler 服务)
   5) print access URLs (API docs / React frontend / neo4j browser)

 Usage:
   powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
   powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1 -SkipScheduler

 PIDs of background jobs are written to .run\*.pid (see stop_all.ps1).
============================================================================
#>
param(
    [switch]$SkipScheduler,
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
        # 有 healthcheck 的服务必须 (healthy)；scheduler 无 healthcheck（无端口），Up 即算就绪
        $expected = @('postgres', 'neo4j', 'chroma', 'api', 'frontend-react')
        $running = @('scheduler')
        $notReady = @()
        foreach ($name in $expected) {
            if (-not $status.ContainsKey($name) -or $status[$name] -notmatch 'healthy') { $notReady += $name }
        }
        foreach ($name in $running) {
            if (-not $status.ContainsKey($name) -or $status[$name] -notmatch 'Up') { $notReady += $name }
        }
        if ($notReady.Count -eq 0) { return $true }
        Write-Host ("  waiting: " + ($notReady -join ', '))
        Start-Sleep -Seconds 8
    }
    return $false
}

Write-Step "1/5 docker compose up -d"
docker compose up -d --build

Write-Step "2/5 wait for healthy (timeout ${TimeoutSeconds}s)"
if (Wait-ComposeHealthy -Timeout $TimeoutSeconds) {
    Write-Host "  all 6 services are healthy (scheduler 无 healthcheck，按 running 计)" -ForegroundColor Green
} else {
    Write-Warning "not all services became healthy in time; run 'docker compose ps' to inspect"
}
docker compose ps

Write-Step "3/5 init db + seed sources"
& $Python -m scripts.init_db
& $Python -m scripts.seed_sources

if (-not $SkipScheduler) {
    Write-Step "4/5 start collector scheduler (background)"
    $sched = Start-Process -FilePath $Python `
        -ArgumentList '-m', 'scripts.run_scheduler', '--source', 'all' `
        -WorkingDirectory $Root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $RunDir 'scheduler.log') `
        -RedirectStandardError (Join-Path $RunDir 'scheduler.err')
    $sched.Id | Out-File (Join-Path $RunDir 'scheduler.pid')
    Write-Host ("  scheduler pid=" + $sched.Id + " (log: .run\scheduler.log)") -ForegroundColor Green
} else {
    Write-Step "4/5 scheduler skipped (-SkipScheduler)"
}

Write-Step "5/5 access URLs"
Write-Host "  API docs     : http://localhost:8000/docs"
Write-Host "  API health   : http://localhost:8000/healthz"
Write-Host "  React front  : http://localhost:3000"
Write-Host "  Scheduler    : docker compose logs -f scheduler"
Write-Host "  Neo4j        : http://localhost:7474"
Write-Host "  Stop all     : powershell -ExecutionPolicy Bypass -File scripts\stop_all.ps1"
