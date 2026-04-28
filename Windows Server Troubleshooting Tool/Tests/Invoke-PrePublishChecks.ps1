#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-publish quality gate for WSTT_v3.0.ps1.
.DESCRIPTION
    Run this before pushing changes to GitHub. Performs:
      1. PSScriptAnalyzer lint (Error severity must be 0)
      2. Pester 5 unit tests
      3. Authenticode signature inspection (informational)

    Exit code 0 = ready to publish, 1 = blocked.
.EXAMPLE
    .\Tests\Invoke-PrePublishChecks.ps1
.EXAMPLE
    .\Tests\Invoke-PrePublishChecks.ps1 -InstallMissing
#>
[CmdletBinding()]
param(
    [switch]$InstallMissing
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Root       = Split-Path -Parent $PSScriptRoot
$script:Script     = Join-Path $script:Root 'WSTT_v3.0.ps1'
$script:TestFile   = Join-Path $PSScriptRoot 'WSTT.Tests.ps1'
$script:Failed     = $false

function Write-Step([string]$msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "[ OK ] $msg" -ForegroundColor Green }
function Write-Bad([string]$msg)  { Write-Host "[FAIL] $msg" -ForegroundColor Red; $script:Failed = $true }

function Ensure-Module {
    param([string]$Name, [version]$MinVersion)
    $found = Get-Module -ListAvailable $Name | Where-Object { $_.Version -ge $MinVersion } | Select-Object -First 1
    if ($found) { return $true }
    if ($InstallMissing) {
        Write-Host "Installing $Name >= $MinVersion ..." -ForegroundColor Yellow
        Install-Module $Name -MinimumVersion $MinVersion -Scope CurrentUser -Force -SkipPublisherCheck
        return $true
    }
    Write-Bad "$Name >= $MinVersion not installed. Re-run with -InstallMissing or run: Install-Module $Name -Scope CurrentUser -Force"
    return $false
}

# ── 0. Prerequisites ─────────────────────────────────────────────────────────
Write-Step 'Checking prerequisites'
$pesterOk = Ensure-Module -Name Pester             -MinVersion '5.0.0'
$pssaOk   = Ensure-Module -Name PSScriptAnalyzer   -MinVersion '1.20.0'
if (-not $pesterOk) { exit 1 }

# ── 1. PSScriptAnalyzer ──────────────────────────────────────────────────────
if ($pssaOk) {
    Write-Step 'PSScriptAnalyzer (Error severity)'
    $errors = Invoke-ScriptAnalyzer -Path $script:Script -Severity Error -ErrorAction SilentlyContinue
    if ($errors) {
        $errors | Format-Table RuleName, Line, Message -AutoSize | Out-String | Write-Host
        Write-Bad "$($errors.Count) Error-level findings"
    } else {
        Write-Ok 'No Error-level findings'
    }
}

# ── 2. Pester tests ──────────────────────────────────────────────────────────
Write-Step 'Pester 5 tests'
Import-Module Pester -MinimumVersion 5.0 -Force
$cfg = New-PesterConfiguration
$cfg.Run.Path        = $script:TestFile
$cfg.Output.Verbosity = 'Detailed'
$cfg.Run.PassThru    = $true
$result = Invoke-Pester -Configuration $cfg
if ($result.FailedCount -gt 0) { Write-Bad "$($result.FailedCount) test(s) failed" }
else                            { Write-Ok "$($result.PassedCount) test(s) passed" }

# ── 3. Signature (informational) ─────────────────────────────────────────────
Write-Step 'Authenticode signature (informational)'
$sig = Get-AuthenticodeSignature -FilePath $script:Script
Write-Host "Status: $($sig.Status)" -ForegroundColor Gray
if ($sig.SignerCertificate) { Write-Host "Signer: $($sig.SignerCertificate.Subject)" -ForegroundColor Gray }

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Step 'Summary'
if ($script:Failed) {
    Write-Bad 'Pre-publish checks FAILED — do NOT push.'
    exit 1
}
Write-Ok 'Pre-publish checks PASSED — safe to publish.'
exit 0
