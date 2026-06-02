#Requires -Modules InvokeBuild
<#
.SYNOPSIS
    ArcMonitor build pipeline — lint, test, help, package.
.DESCRIPTION
    Run tasks with: Invoke-Build <TaskName>
    Run all:        Invoke-Build
.EXAMPLE
    Invoke-Build Analyze    # Run PSScriptAnalyzer
    Invoke-Build Test       # Run Pester tests
    Invoke-Build            # Run full pipeline (Clean → Analyze → Test → Package)
#>

$ProjectRoot = $BuildRoot
$ModuleName  = 'ArcMonitor'
$OutputDir   = Join-Path $ProjectRoot 'output'

# ── Clean ────────────────────────────────────────────────────────────────────────
task Clean {
    if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
    Write-Build Green "  Cleaned output directory"
}

# ── Analyze (PSScriptAnalyzer) ───────────────────────────────────────────────────
task Analyze {
    Import-Module PSScriptAnalyzer -Force

    $excludeRules = @(
        'PSAvoidUsingWriteHost'
        'PSAvoidUsingConvertToSecureStringWithPlainText'
        'PSUseSingularNouns'
        'PSUseUsingScopeModifierInNewRunspaces'
        'PSUseOutputTypeCorrectly'
    )

    $results = Invoke-ScriptAnalyzer -Path $ProjectRoot -Recurse `
                 -ExcludeRule $excludeRules -Severity Error, Warning

    $errors = @($results | Where-Object Severity -eq 'Error')
    $warnings = @($results | Where-Object Severity -eq 'Warning')

    Write-Build Cyan "  PSScriptAnalyzer: $($errors.Count) errors, $($warnings.Count) warnings"

    if ($errors.Count -gt 0) {
        $errors | ForEach-Object { Write-Build Red "    ERROR: $($_.ScriptName):$($_.Line) $($_.Message)" }
        throw "PSScriptAnalyzer found $($errors.Count) error(s)"
    }

    if ($warnings.Count -gt 0) {
        $warnings | ForEach-Object { Write-Build Yellow "    WARN: $($_.ScriptName):$($_.Line) $($_.RuleName)" }
    }
}

# ── Test (Pester 5) ─────────────────────────────────────────────────────────────
task Test {
    if (-not (Get-Module Pester -ListAvailable | Where-Object { $_.Version.Major -ge 5 })) {
        throw "Pester 5+ required: Install-Module Pester -Force -SkipPublisherCheck"
    }
    Import-Module Pester -MinimumVersion 5.0 -Force

    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = Join-Path $ProjectRoot 'Tests'
    $pesterConfig.Output.Verbosity = 'Detailed'
    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputPath = Join-Path $ProjectRoot 'Tests' 'TestResults.xml'
    $pesterConfig.TestResult.OutputFormat = 'NUnitXml'

    $testResult = Invoke-Pester -Configuration $pesterConfig

    Write-Build Cyan "  Pester: $($testResult.PassedCount) passed, $($testResult.FailedCount) failed"

    if ($testResult.FailedCount -gt 0) {
        throw "Pester: $($testResult.FailedCount) test(s) failed"
    }
}

# ── Package (copy to output) ────────────────────────────────────────────────────
task Package {
    $moduleOut = Join-Path $OutputDir $ModuleName
    New-Item -ItemType Directory -Path $moduleOut -Force | Out-Null

    $filesToCopy = @(
        '*.ps1', '*.psd1', '*.psm1', 'README.md'
    )
    foreach ($pattern in $filesToCopy) {
        Get-ChildItem -Path $ProjectRoot -Filter $pattern -File |
            Copy-Item -Destination $moduleOut -Force
    }

    # Copy subdirectories
    @('Config', 'docs', 'images') | ForEach-Object {
        $src = Join-Path $ProjectRoot $_
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $moduleOut -Recurse -Force
        }
    }

    Write-Build Green "  Packaged to: $moduleOut"

    # Show package contents
    $fileCount = (Get-ChildItem $moduleOut -Recurse -File).Count
    $sizeMB = [Math]::Round((Get-ChildItem $moduleOut -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 2)
    Write-Build Cyan "  Files: $fileCount | Size: $sizeMB MB"
}

# ── Default (full pipeline) ─────────────────────────────────────────────────────
task . Clean, Analyze, Test, Package
