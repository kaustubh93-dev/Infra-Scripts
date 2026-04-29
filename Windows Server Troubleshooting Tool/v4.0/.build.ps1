<#
.SYNOPSIS
    Invoke-Build pipeline for the WSTT v4.0 module.

.DESCRIPTION
    Tasks:
      Clean    — wipe ./out
      Split    — regenerate WSTT/Source from WSTT_v4.0.ps1
      Analyze  — PSScriptAnalyzer over WSTT/ and WSTT.ps1 (fail on Error severity)
      Test     — Pester 5 over Tests/ (NUnit XML to ./out/test-results.xml)
      Package  — copy WSTT/, WSTT.ps1, README to ./out/WSTT-<version>/
      .        — default task: Clean, Analyze, Test, Package

.EXAMPLE
    Invoke-Build              # default: full pipeline
    Invoke-Build Test         # tests only
    Invoke-Build Split        # rebuild module sources from monolith

.NOTES
    Requires modules: InvokeBuild, PSScriptAnalyzer, Pester (>=5.0).
#>

[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$OutputDir     = (Join-Path $BuildRoot 'out')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # suppress Copy-Item / Compress-Archive progress noise

$ModuleName    = 'WSTT'
$ModuleRoot    = Join-Path $BuildRoot 'WSTT'
$ManifestPath  = Join-Path $ModuleRoot 'WSTT.psd1'
$ShimPath      = Join-Path $BuildRoot 'WSTT.ps1'
$TestsPath     = Join-Path $BuildRoot 'Tests'
$SplitTool     = Join-Path $BuildRoot 'tools\Split-Module.ps1'

# --- Tasks -------------------------------------------------------------------

task Clean {
    if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

task Split {
    if (-not (Test-Path $SplitTool)) { throw "Generator not found: $SplitTool" }
    # The split tool only works if the original WSTT_v4.0.ps1 monolith is present
    # (kept around for one-off re-generation). After modularisation the canonical
    # source lives in WSTT/Source — edit those files directly.
    $monolith = Join-Path $BuildRoot 'WSTT_v4.0.ps1'
    if (-not (Test-Path $monolith)) {
        Write-Build Yellow "Skipping Split: monolith $monolith no longer exists (module is canonical)."
        return
    }
    & $SplitTool
}

task Analyze {
    if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
        Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -SkipPublisherCheck
    }
    Import-Module PSScriptAnalyzer -Force
    $exclude = @(
        'PSAvoidUsingWriteHost',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns',
        'PSAvoidUsingInvokeExpression',
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingEmptyCatchBlock',
        'PSReviewUnusedParameter',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSAvoidGlobalVars',
        'PSPossibleIncorrectComparisonWithNull',
        'PSAvoidUsingPositionalParameters'
    )
    $targets = @($ModuleRoot, $ShimPath)
    $results = foreach ($t in $targets) {
        Invoke-ScriptAnalyzer -Path $t -Recurse -ExcludeRule $exclude -Severity Error,Warning
    }
    $errors = @($results | Where-Object Severity -eq 'Error')
    $warns  = @($results | Where-Object Severity -eq 'Warning')
    Write-Build Cyan "PSSA: Errors=$($errors.Count) Warnings=$($warns.Count)"
    if ($errors.Count -gt 0) {
        $errors | Format-Table ScriptName,Line,RuleName,Message -AutoSize | Out-String | Write-Build Red
        throw "PSScriptAnalyzer reported $($errors.Count) Error-level finding(s)."
    }
}

task Test {
    if (-not (Get-Module -ListAvailable Pester | Where-Object { $_.Version.Major -ge 5 })) {
        Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force -SkipPublisherCheck
    }
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

    # Run Pester in a child pwsh process so the WSTT module + temp file handles
    # loaded during tests do not leak into the main build session and stall
    # downstream tasks (Package).
    $resultPath = Join-Path $OutputDir 'test-results.xml'
    $pesterScript = @"
`$ProgressPreference = 'SilentlyContinue'
Import-Module Pester -MinimumVersion 5.0 -Force
`$cfg = New-PesterConfiguration
`$cfg.Run.Path                = '$TestsPath'
`$cfg.Run.PassThru            = `$true
`$cfg.Output.Verbosity        = 'Normal'
`$cfg.TestResult.Enabled      = `$true
`$cfg.TestResult.OutputFormat = 'NUnitXml'
`$cfg.TestResult.OutputPath   = '$resultPath'
`$r = Invoke-Pester -Configuration `$cfg
Write-Host "Pester: Passed=`$(`$r.PassedCount) Failed=`$(`$r.FailedCount) Skipped=`$(`$r.SkippedCount)"
exit `$r.FailedCount
"@
    $tmpScript = Join-Path $OutputDir '_run-pester.ps1'
    Set-Content -LiteralPath $tmpScript -Value $pesterScript -Encoding UTF8
    $exe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
    & $exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $tmpScript
    $code = $LASTEXITCODE
    Remove-Item -LiteralPath $tmpScript -Force -ErrorAction SilentlyContinue
    if ($code -gt 0) { throw "Pester reported $code failed test(s)." }
}

task Package {
    # Pester may have reset progress preferences during Test; re-suppress here
    # so file copy / zip don't render multi-GB phantom progress.
    $ProgressPreference = 'SilentlyContinue'
    # Parse manifest as a hashtable rather than via Test-ModuleManifest, which
    # re-imports the module (already loaded by Test) and can hang the session.
    $manifestData = Import-PowerShellDataFile -Path $ManifestPath
    $version      = $manifestData.ModuleVersion
    $stage    = Join-Path $OutputDir ("$ModuleName-$version")
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null

    # Pure .NET file copy + zip — no PowerShell progress streams, no external processes
    $stageModule = Join-Path $stage $ModuleName
    New-Item -ItemType Directory -Path $stageModule -Force | Out-Null
    $rootLen = $ModuleRoot.Length
    Get-ChildItem -LiteralPath $ModuleRoot -Recurse -Force | ForEach-Object {
        $rel = $_.FullName.Substring($rootLen).TrimStart('\','/')
        $dest = Join-Path $stageModule $rel
        if ($_.PSIsContainer) {
            if (-not (Test-Path -LiteralPath $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
        } else {
            $destDir = Split-Path -Parent $dest
            if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
            [System.IO.File]::Copy($_.FullName, $dest, $true)
        }
    }

    [System.IO.File]::Copy($ShimPath, (Join-Path $stage 'WSTT.ps1'), $true)
    $readme = Join-Path $BuildRoot '..\README.md'
    if (Test-Path $readme) { [System.IO.File]::Copy($readme, (Join-Path $stage 'README.md'), $true) }

    $zipPath = Join-Path $OutputDir ("$ModuleName-$version.zip")
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zipPath)
    Write-Build Green "Packaged: $zipPath"
}

task Docs {
    # Generates / refreshes platyPS markdown help under docs/help and compiles
    # the external MAML cab under WSTT/en-US so `Get-Help` works after install.
    if (-not (Get-Module -ListAvailable platyPS)) {
        Install-Module platyPS -Scope CurrentUser -Force -SkipPublisherCheck
    }
    Import-Module platyPS -Force
    Import-Module $ManifestPath -Force -DisableNameChecking

    $docsRoot   = Join-Path $BuildRoot 'docs\help'
    $maml       = Join-Path $ModuleRoot 'en-US'
    if (-not (Test-Path $docsRoot)) { New-Item -ItemType Directory -Path $docsRoot -Force | Out-Null }
    if (-not (Test-Path $maml))     { New-Item -ItemType Directory -Path $maml     -Force | Out-Null }

    $modulePage = Join-Path $docsRoot 'WSTT.md'
    if (Test-Path $modulePage) {
        Update-MarkdownHelpModule -Path $docsRoot -RefreshModulePage -AlphabeticParamsOrder | Out-Null
    } else {
        New-MarkdownHelp -Module $ModuleName -OutputFolder $docsRoot -WithModulePage `
            -ModulePagePath $modulePage -AlphabeticParamsOrder -Force | Out-Null
    }
    New-ExternalHelp -Path $docsRoot -OutputPath $maml -Force | Out-Null

    $cnt = (Get-ChildItem $docsRoot -Filter *.md).Count
    Write-Build Green "Docs: refreshed $cnt markdown pages, compiled MAML to $maml"
}

task Sign {
    # Optional Authenticode signing pass.
    # Requires a code-signing certificate in the user's Cert:\CurrentUser\My store
    # (or pass -CertPath to a PFX). Set $env:WSTT_SIGN_CERT_THUMB to the cert
    # thumbprint, or the task picks the first valid CodeSigning cert.
    $thumb = $env:WSTT_SIGN_CERT_THUMB
    $cert  = if ($thumb) {
        Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
            Where-Object Thumbprint -eq $thumb | Select-Object -First 1
    } else {
        Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
    }
    if (-not $cert) {
        Write-Build Yellow 'Sign: skipped — no CodeSigning certificate in CurrentUser\My (set $env:WSTT_SIGN_CERT_THUMB).'
        return
    }
    $tsa = 'http://timestamp.digicert.com'
    $files = @()
    $files += Get-ChildItem -LiteralPath $ModuleRoot -Recurse -Include *.ps1,*.psm1,*.psd1
    $files += Get-Item -LiteralPath $ShimPath
    $signed = 0
    foreach ($f in $files) {
        $r = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert `
                -TimestampServer $tsa -HashAlgorithm SHA256 -ErrorAction Stop
        if ($r.Status -ne 'Valid') {
            throw "Signing failed for $($f.FullName): $($r.Status) / $($r.StatusMessage)"
        }
        $signed++
    }
    Write-Build Green "Signed $signed file(s) with cert $($cert.Thumbprint) (SHA256, timestamped)."
}

# Default task: full pipeline (Docs + Sign are opt-in via explicit invocation)
task . Clean, Analyze, Test, Package
