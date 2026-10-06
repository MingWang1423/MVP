<#
============================================================================
 stop_all.ps1 - one-click stop (PROJECT_PLAN.md §5.10 P9, Day13 task 6)
----------------------------------------------------------------------------
 What it does:
   1) stop background jobs started by start_all.ps1 (.run\*.pid: scheduler)
   2) docker compose down (middleware + api + frontend-react)
   3) optional: -RemoveVolumes also drops named volumes (pg/neo4j/chroma data)

 Usage:
   powershell -ExecutionPolicy Bypass -File scripts\stop_all.ps1
   powershell -ExecutionPolicy Bypass -File scripts\stop_all.ps1 -RemoveVolumes
============================================================================
#>
param(
    [switch]$RemoveVolumes
)

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$RunDir = Join-Path $Root '.run'

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host ("=== " + $Message) -ForegroundColor Cyan
}

Write-Step "1/2 stop background host jobs"
if (Test-Path $RunDir) {
    foreach ($name in @('scheduler')) {
        $pidFile = Join-Path $RunDir ($name + '.pid')
        if (-not (Test-Path $pidFile)) { continue }
        $processId = Get-Content $pidFile | Select-Object -First 1
        if ($processId) {
            $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($proc) {
                Stop-Process -Id $processId -Force
                Write-Host ("  stopped " + $name + " pid=" + $processId) -ForegroundColor Green
            } else {
                Write-Host ("  " + $name + " pid=" + $processId + " already gone")
            }
        }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "  no .run directory (nothing to stop)"
}

Write-Step "2/2 docker compose down"
if ($RemoveVolumes) {
    docker compose down --volumes --remove-orphans
} else {
    docker compose down --remove-orphans
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
