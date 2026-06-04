<#
.SYNOPSIS
    Functional smoke-test harness for WSTT_v3.0.ps1.
.DESCRIPTION
    Loads ONLY the function/constant definitions from WSTT_v3.0.ps1 (the
    trailing "#region Script Entry Point" block that auto-launches the
    interactive menu is stripped out) and then executes the read-only
    Test-* diagnostic functions, capturing output length and any exceptions.

    This lets us validate that the diagnostic code paths run end-to-end
    without driving the interactive menu or requiring the script to elevate.
#>

[CmdletBinding()]
param(
    [string]$ScriptPath = (Join-Path $PSScriptRoot 'WSTT_v3.0.ps1')
)

$ErrorActionPreference = 'Continue'

Write-Host "=== WSTT Functional Smoke Test ===" -ForegroundColor Cyan
Write-Host "Script under test: $ScriptPath"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ("Running as Administrator: {0}" -f $isAdmin)
Write-Host ("OS locale: {0}" -f (Get-Culture).Name)
Write-Host ""

# --- Load definitions only (strip the auto-run entry point) ---
$raw = Get-Content -Path $ScriptPath -Raw
$marker = '#region Script Entry Point'
$idx = $raw.IndexOf($marker)
if ($idx -lt 0) {
    throw "Could not find entry-point marker '$marker' — aborting to avoid launching the interactive menu."
}
$definitions = $raw.Substring(0, $idx)

# The script body has a #Requires -RunAsAdministrator directive at the top.
# #Requires is a parser directive; it is ignored by Invoke-Expression, so we
# can load the definitions without elevation for read-only testing.
try {
    Invoke-Expression $definitions
    Write-Host "[OK] Definitions loaded ($([math]::Round($definitions.Length/1KB,1)) KB of script body)." -ForegroundColor Green
}
catch {
    Write-Host "[FAIL] Could not load definitions: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
Write-Host ""

# --- Read-only diagnostic functions to exercise ---
$targets = @(
    'Test-ServerBaseline'
    'Test-NetworkConfiguration'
    'Test-MemoryUsage'          # edited: section 12 leak analysis cleanup
    'Test-CPUUsage'
    'Test-DiskPerformance'
    'Test-ServicesHealth'
    'Test-EventLogHealth'
    'Test-DNSHealth'
    'Test-SecurityAuthentication'
    'Test-WindowsUpdateStatus'
    'Test-TLSConfiguration'
    'Test-CrossCategoryHealth'
)

$results = [System.Collections.Generic.List[object]]::new()

foreach ($fn in $targets) {
    $cmd = Get-Command $fn -ErrorAction SilentlyContinue
    if (-not $cmd) {
        $results.Add([pscustomobject]@{ Function = $fn; Status = 'MISSING'; Lines = 0; Error = 'Not defined' })
        continue
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $output = & $fn *>&1 | Out-String
        $sw.Stop()
        $lineCount = ($output -split "`n").Count
        $results.Add([pscustomobject]@{
            Function = $fn
            Status   = 'OK'
            Lines    = $lineCount
            Seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            Error    = ''
        })
        Write-Host ("[OK]   {0,-30} {1,4} lines  {2,5}s" -f $fn, $lineCount, [math]::Round($sw.Elapsed.TotalSeconds,1)) -ForegroundColor Green
    }
    catch {
        $sw.Stop()
        $results.Add([pscustomobject]@{
            Function = $fn
            Status   = 'ERROR'
            Lines    = 0
            Seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            Error    = $_.Exception.Message
        })
        Write-Host ("[FAIL] {0,-30} {1}" -f $fn, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$results | Format-Table Function, Status, Lines, Seconds, Error -AutoSize

$failed = @($results | Where-Object { $_.Status -in @('ERROR', 'MISSING') })
Write-Host ("Total: {0}  Passed: {1}  Failed: {2}" -f $results.Count, ($results.Count - $failed.Count), $failed.Count) -ForegroundColor Cyan

# --- Targeted check for the edited Show-WSFCPortSummaryTable -Peers path ---
Write-Host ""
Write-Host "=== Edited-path check: Show-WSFCPortSummaryTable -Peers ===" -ForegroundColor Cyan
$spt = Get-Command Show-WSFCPortSummaryTable -ErrorAction SilentlyContinue
if ($spt) {
    if ($spt.Parameters.ContainsKey('Peers')) {
        Write-Host "[OK] -Peers parameter is present on Show-WSFCPortSummaryTable." -ForegroundColor Green
    }
    else {
        Write-Host "[FAIL] -Peers parameter missing from Show-WSFCPortSummaryTable." -ForegroundColor Red
    }
}
else {
    Write-Host "[WARN] Show-WSFCPortSummaryTable not defined." -ForegroundColor Yellow
}

if ($failed.Count -gt 0) { exit 1 } else { exit 0 }
