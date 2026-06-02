#Requires -Version 5.1
<#
.SYNOPSIS
    One-off generator that splits WSTT_v4.0.ps1 into the WSTT/ PowerShell module.

.DESCRIPTION
    Reads the monolithic v4.0 script, partitions it by `#region ... #endregion`
    boundaries, and emits one source file per region under WSTT/Source/.
    The "Script Entry Point" region is dropped (lives in the shim instead).

    Idempotent: WSTT/Source is wiped and rebuilt every run.

.NOTES
    Run from this folder:  pwsh -NoProfile -File .\tools\Split-Module.ps1
#>

[CmdletBinding()]
param(
    [string]$ScriptPath  = (Join-Path $PSScriptRoot '..\WSTT_v4.0.ps1'),
    [string]$ModuleRoot  = (Join-Path $PSScriptRoot '..\WSTT')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptPath = (Resolve-Path $ScriptPath).Path
$srcDir     = Join-Path $ModuleRoot 'Source'

if (Test-Path $srcDir) { Remove-Item $srcDir -Recurse -Force }
New-Item -ItemType Directory -Path $srcDir -Force | Out-Null

$lines = Get-Content $ScriptPath
$total = $lines.Count

# --- 1. Find TOP-LEVEL region boundaries (ignore nested regions) ------------
$regions = New-Object System.Collections.Generic.List[object]
$current = $null
$depth   = 0
for ($i = 0; $i -lt $total; $i++) {
    $line = $lines[$i]
    if ($line -match '^\s*#region\s+(.+?)\s*$') {
        if ($depth -eq 0) {
            $current = [pscustomobject]@{ Name = $Matches[1].Trim(); Start = $i; End = -1 }
        }
        $depth++
    }
    elseif ($line -match '^\s*#endregion') {
        if ($depth -le 0) { throw "Stray #endregion at line $($i+1)." }
        $depth--
        if ($depth -eq 0 -and $current) {
            $current.End = $i
            $regions.Add($current) | Out-Null
            $current = $null
        }
    }
}
if ($depth -ne 0) { throw "Unclosed region at end of file (depth=$depth)." }

Write-Host "Found $($regions.Count) regions." -ForegroundColor Cyan

# --- 2. Write each region (except entry point) to Source/ -------------------
$index = 0
foreach ($r in $regions) {
    if ($r.Name -match '^Script Entry Point') {
        Write-Host "  - skipping '$($r.Name)' (handled by shim)" -ForegroundColor DarkGray
        continue
    }
    $index++
    $safe = ($r.Name -replace '[^\w\-]+', '_').Trim('_')
    $fileName = ('{0:D2}-{1}.ps1' -f $index, $safe)
    $body = $lines[($r.Start)..($r.End)] -join "`r`n"
    $header = @"
# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: $($r.Name)
# Source lines: $($r.Start + 1) - $($r.End + 1)
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================

"@
    Set-Content -Path (Join-Path $srcDir $fileName) -Value ($header + $body) -Encoding UTF8
    Write-Host ("  + {0,-50} ({1} lines)" -f $fileName, ($r.End - $r.Start + 1))
}

Write-Host ""
Write-Host "Module source written to: $srcDir" -ForegroundColor Green
Write-Host "Files: $((Get-ChildItem $srcDir -Filter *.ps1).Count)" -ForegroundColor Green
