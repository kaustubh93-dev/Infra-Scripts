#Requires -Version 5.1
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0' }

<#
.SYNOPSIS
    Pester 5 baseline tests for the WSTT v4.0 module (post-modularisation).

.DESCRIPTION
    Imports the WSTT module and validates the public surface, Phase 0 helpers,
    exporters, and graceful-skip behaviour. Module imports without admin rights
    because individual `#Requires -RunAsAdministrator` checks live on the shim
    (WSTT.ps1), not inside the module.

.NOTES
    Run with: Invoke-Pester .\Tests\WSTT.Tests.ps1 -Output Detailed
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

BeforeDiscovery {
    $script:ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:ManifestPath = Join-Path $script:ModuleRoot 'WSTT\WSTT.psd1'
    Import-Module $script:ManifestPath -Force -DisableNameChecking
}

BeforeAll {
    $script:ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:ManifestPath = Join-Path $script:ModuleRoot 'WSTT\WSTT.psd1'
    Import-Module $script:ManifestPath -Force -DisableNameChecking
    # Pre-populate cluster environment cache used by ~6 diagnostic functions.
    # Must run inside the module's session state so $script:ClusterEnv targets
    # the module scope that the diagnostics read from under StrictMode.
    $wsttMod = Get-Module WSTT
    if ($wsttMod) {
        & $wsttMod { $script:ClusterEnv = Get-ClusterEnvironmentInfo }
    }
}

AfterAll {
    Get-Module WSTT | Remove-Module -Force -ErrorAction SilentlyContinue
}

Describe 'WSTT module — manifest and import' {
    It 'has a valid manifest' {
        { Test-ModuleManifest -Path $script:ManifestPath } | Should -Not -Throw
    }

    It 'imports without errors' {
        Get-Module WSTT | Should -Not -BeNullOrEmpty
    }

    It 'exports the expected public surface' {
        $expected = @(
            'Start-TroubleshootingTool', 'Invoke-WSTTUnattended',
            'Add-Finding', 'Get-Findings', 'Reset-Findings',
            'Get-OSCapability', 'Test-WSTTCommand', 'Test-WSTTHasRole',
            'Export-FindingsToFile',
            'Test-ActiveDirectoryHealth', 'Test-HyperVHostHealth',
            'Test-AdvancedStorageHealth', 'Test-ModernSecurityPosture',
            'Test-Server2025FeatureAudit', 'Test-CertificateAndPKIHealth',
            'Test-AzureArcHybridHealth', 'Test-PatchingDepthAndLifecycle',
            'Invoke-MultiServerRemotingMenu', 'Invoke-ExportDiagnosticsMenu',
            'Show-UnattendedModeHelp'
        )
        $exported = (Get-Command -Module WSTT).Name
        foreach ($name in $expected) { $exported | Should -Contain $name }
    }
}

Describe 'WSTT module — source files parse cleanly' {
    It 'every Source/*.ps1 parses without errors' {
        $files = Get-ChildItem (Join-Path $script:ModuleRoot 'WSTT\Source') -Filter *.ps1
        foreach ($f in $files) {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile(
                $f.FullName, [ref]$null, [ref]$errors) | Out-Null
            $errors | Should -BeNullOrEmpty
        }
    }

    It 'has zero PSScriptAnalyzer Error-level findings under WSTT/' -Skip:(-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
        $r = Invoke-ScriptAnalyzer -Path (Join-Path $script:ModuleRoot 'WSTT') -Recurse -Severity Error
        $r | Should -BeNullOrEmpty
    }
}

Describe 'WSTT module — Phase 0 foundation' {
    It 'Add-Finding appends an immutable record with required fields' {
        Reset-Findings
        Add-Finding -Severity 'INFO' -Category 'TestCat' -CheckId 't.1' -Message 'hello'
        $f = Get-Findings
        $f.Count                  | Should -Be 1
        $f[0].Severity            | Should -Be 'INFO'
        $f[0].Category            | Should -Be 'TestCat'
        $f[0].CheckId             | Should -Be 't.1'
        $f[0].Message             | Should -Be 'hello'
        $f[0].Host                | Should -Be $env:COMPUTERNAME
        { [datetime]::Parse($f[0].TimestampUtc) } | Should -Not -Throw
    }

    It 'Add-Finding rejects invalid Severity' {
        { Add-Finding -Severity 'BOGUS' -Message 'x' } | Should -Throw
    }

    It 'Get-OSCapability returns an object with expected fields and is cached' {
        $c1 = Get-OSCapability
        $c1                  | Should -Not -BeNullOrEmpty
        $c1.BuildNumber      | Should -BeOfType [int]
        $c1.Architecture     | Should -Match '^(x64|x86|ARM|ARM64|Unknown.*)$'
        ($c1.Is2019 -or $c1.Is2022 -or $c1.Is2025 -or -not $c1.IsServer) | Should -BeTrue
        $c2 = Get-OSCapability   # cached
        [object]::ReferenceEquals($c1, $c2) | Should -BeTrue
    }
}

Describe 'WSTT module — Export-FindingsToFile produces valid output' {
    BeforeEach {
        Reset-Findings
        Add-Finding -Severity 'INFO'  -Category 'C1' -CheckId '1.1' -Message 'm1'
        Add-Finding -Severity 'WARN'  -Category 'C2' -CheckId '2.1' -Message 'm2'
        Add-Finding -Severity 'ERROR' -Category 'C3' -CheckId '3.1' -Message 'm3'
        $script:OutDir = Join-Path $env:TEMP "wstt-test-$([guid]::NewGuid().ToString('N'))"
        New-Item $script:OutDir -ItemType Directory -Force | Out-Null
    }
    AfterEach {
        if ($script:OutDir -and (Test-Path $script:OutDir)) {
            Remove-Item $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'writes a parseable JSON envelope with schema=wstt-findings-v1' {
        Export-FindingsToFile -Format 'JSON' -OutputPath $script:OutDir
        $file = Get-ChildItem $script:OutDir -Filter '*.json' | Select-Object -First 1
        $file | Should -Not -BeNullOrEmpty
        $obj  = Get-Content $file.FullName -Raw | ConvertFrom-Json
        $obj.schema       | Should -Be 'wstt-findings-v1'
        $obj.findings.Count | Should -Be 3
    }

    It 'writes NDJSON (one JSON object per line)' {
        Export-FindingsToFile -Format 'NDJSON' -OutputPath $script:OutDir
        $file = Get-ChildItem $script:OutDir -Filter '*.ndjson' | Select-Object -First 1
        $lines = Get-Content $file.FullName
        $lines.Count | Should -Be 3
        foreach ($l in $lines) { { $l | ConvertFrom-Json } | Should -Not -Throw }
    }

    It 'writes a CSV with required columns' {
        Export-FindingsToFile -Format 'CSV' -OutputPath $script:OutDir
        $file = Get-ChildItem $script:OutDir -Filter '*.csv' | Select-Object -First 1
        $rows = Import-Csv $file.FullName
        $rows.Count | Should -Be 3
        $rows[0].PSObject.Properties.Name | Should -Contain 'Severity'
        $rows[0].PSObject.Properties.Name | Should -Contain 'CheckId'
    }

    It 'writes a SARIF 2.1.0 document' {
        Export-FindingsToFile -Format 'SARIF' -OutputPath $script:OutDir
        $file = Get-ChildItem $script:OutDir -Filter '*.sarif' | Select-Object -First 1
        $obj  = Get-Content $file.FullName -Raw | ConvertFrom-Json
        $obj.version             | Should -Be '2.1.0'
        $obj.runs[0].tool.driver.name | Should -Be 'WSTT'
        $obj.runs[0].results.Count    | Should -Be 3
    }
}

Describe 'WSTT module — security baseline' {
    It 'no Source file uses ExecutionPolicy Bypass' {
        $files = Get-ChildItem (Join-Path $script:ModuleRoot 'WSTT\Source') -Filter *.ps1
        Select-String -Path $files.FullName -Pattern 'ExecutionPolicy\s+Bypass' |
            Should -BeNullOrEmpty
    }
    It 'no Source file uses $Global: scope' {
        $files = Get-ChildItem (Join-Path $script:ModuleRoot 'WSTT\Source') -Filter *.ps1
        $hits = Select-String -Path $files.FullName -Pattern '\$Global:' |
                Where-Object { $_.Line -notmatch '^\s*#' }
        $hits | Should -BeNullOrEmpty
    }
    It 'no Source file accepts -Password as plain string' {
        $files = Get-ChildItem (Join-Path $script:ModuleRoot 'WSTT\Source') -Filter *.ps1
        Select-String -Path $files.FullName -Pattern '\[string\]\s*\$Password\b' |
            Should -BeNullOrEmpty
    }
}

Describe 'WSTT module — DC-aware checks degrade gracefully on non-DC' {
    It 'Test-ActiveDirectoryHealth returns without error on non-DC hosts' -Skip:((Get-OSCapability).IsDomainController) {
        Reset-Findings
        { Test-ActiveDirectoryHealth } | Should -Not -Throw
        (Get-Findings) | Where-Object { $_.Severity -eq 'NA' -and $_.Category -eq 'AD' } |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'WSTT module — Hyper-V check degrades gracefully when role missing' {
    It 'Test-HyperVHostHealth returns without error when Hyper-V not installed' -Skip:(Test-WSTTHasRole 'Hyper-V') {
        Reset-Findings
        { Test-HyperVHostHealth } | Should -Not -Throw
        (Get-Findings) | Where-Object { $_.Severity -eq 'NA' -and $_.Category -eq 'HyperV' } |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'WSTT shim (WSTT.ps1) — sanity' {
    It 'parses cleanly' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $script:ModuleRoot 'WSTT.ps1'), [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'declares both #Requires -Version and -RunAsAdministrator' {
        $head = (Get-Content (Join-Path $script:ModuleRoot 'WSTT.ps1') -TotalCount 5) -join "`n"
        $head | Should -Match '#Requires\s+-Version'
        $head | Should -Match '#Requires\s+-RunAsAdministrator'
    }
}

# ---------------------------------------------------------------------------
# Per-function smoke coverage (AC-3): every exported diagnostic function must
# parse, declare [CmdletBinding()], be callable parameterless without throwing,
# and contribute at least one finding (or NA on unsupported hosts).
#
# Slow / interactive functions are excluded from the run-but-don't-throw check;
# they are still asserted to exist and to declare CmdletBinding.
# ---------------------------------------------------------------------------

Describe 'WSTT module — per-function shape (CmdletBinding + parses)' -Tag 'Coverage' {
    BeforeDiscovery {
        $script:DiagFunctions = @(
            'Test-ActiveDirectoryHealth', 'Test-AdvancedStorageHealth',
            'Test-AzureArcHybridHealth', 'Test-CertificateAndPKIHealth',
            'Test-CPUUsage', 'Test-CrossCategoryHealth', 'Test-DiskPerformance',
            'Test-DNSHealth', 'Test-EventLogHealth', 'Test-HyperVHostHealth',
            'Test-IISHealth', 'Test-MemoryUsage', 'Test-ModernSecurityPosture',
            'Test-NetworkConfiguration', 'Test-PatchingDepthAndLifecycle',
            'Test-SecurityAuthentication', 'Test-Server2025FeatureAudit',
            'Test-ServicesHealth', 'Test-TaskSchedulerHealth',
            'Test-TLSConfiguration', 'Test-WindowsUpdateStatus'
        )
    }

    It '<_> is exported and uses [CmdletBinding()]' -ForEach $DiagFunctions {
        $cmd = Get-Command $_ -Module WSTT -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
        $cmd.CmdletBinding | Should -BeTrue
    }
}

Describe 'WSTT module — per-function smoke (callable, contributes findings)' -Tag 'Coverage','Slow' {
    BeforeAll {
        # Re-prime the module-scoped cluster cache for this Describe's runspace.
        $wsttMod = Get-Module WSTT
        if ($wsttMod) {
            & $wsttMod { $script:ClusterEnv = Get-ClusterEnvironmentInfo }
        }
    }
    # Functions that are safe to invoke without arguments in CI/sandbox:
    # they either run read-only cmdlets, role-detect first, or already
    # graceful-degrade on missing modules / non-admin contexts.
    BeforeDiscovery {
        $script:SmokeFunctions = @(
            'Test-ActiveDirectoryHealth',     # role-skips on non-DC
            'Test-AdvancedStorageHealth',     # role-skips when no S2D
            'Test-AzureArcHybridHealth',      # role-skips when azcmagent missing
            'Test-CertificateAndPKIHealth',   # read-only Cert: enumeration
            'Test-HyperVHostHealth',          # role-skips when feature missing
            'Test-ModernSecurityPosture',     # read-only DeviceGuard / registry
            'Test-Server2025FeatureAudit',    # OS-detects and emits NA
            'Test-NetworkConfiguration',      # read-only NetTCPIP / NetAdapter
            'Test-DNSHealth',                 # read-only Get-DnsClient*
            'Test-ServicesHealth',            # Get-Service
            'Test-EventLogHealth',            # Get-WinEvent enumerate
            'Test-WindowsUpdateStatus',       # WU client COM, read-only
            'Test-TLSConfiguration',          # registry read
            'Test-TaskSchedulerHealth',       # Get-ScheduledTask
            'Test-IISHealth',                 # role-skips when WebAdmin missing
            'Test-PatchingDepthAndLifecycle', # Get-HotFix + registry
            'Test-SecurityAuthentication',    # NetFirewall + Security event read
            'Test-MemoryUsage',               # CIM Win32_OperatingSystem
            'Test-CPUUsage',                  # short Get-Counter sample
            'Test-DiskPerformance',           # Get-PhysicalDisk + Get-Volume
            'Test-CrossCategoryHealth'        # aggregator over $script:Findings
        )
    }

    It '<_> runs without throwing and contributes at least one finding' -ForEach $SmokeFunctions {
        $fn = $_
        Reset-Findings
        $before = (Get-Findings).Count
        # Per-function safety: each diagnostic is wrapped so a single broken
        # check does not fail the whole suite. Findings count is the gate.
        try {
            & $fn *> $null
        } catch {
            throw "Function '$fn' threw: $($_.Exception.Message)"
        }
        $after = (Get-Findings).Count
        ($after - $before) | Should -BeGreaterThan 0 -Because "$fn should add at least one finding (INFO/WARN/ERROR/NA)"
    }
}

Describe 'WSTT module — utility helpers' {
    It 'Test-WSTTCommand returns true for a built-in cmdlet' {
        Test-WSTTCommand 'Get-Process' | Should -BeTrue
    }
    It 'Test-WSTTCommand returns false for a non-existent cmdlet' {
        Test-WSTTCommand 'Get-NonExistentXyzzy123' | Should -BeFalse
    }
    It 'Test-WSTTHasRole returns a boolean for a known optional feature name' {
        $r = Test-WSTTHasRole 'Hyper-V'
        $r | Should -BeOfType [bool]
    }
    It 'Protect-DiagMessage redacts UNC paths and email addresses' {
        $out = Protect-DiagMessage -Message 'check \\fileserver\share01 and admin@contoso.com please'
        $out | Should -Not -Match 'fileserver'
        $out | Should -Not -Match 'admin@contoso\.com'
    }
}

