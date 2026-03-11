#Requires -Version 5.1
<#
.SYNOPSIS
    Pester 5 tests for ArcMonitor framework.
.DESCRIPTION
    Unit tests covering input validation, config loading, defaults,
    and security-related checks.
.NOTES
    Run with: Invoke-Pester .\Tests\ArcMonitor.Tests.ps1 -Output Detailed
    Requires Pester 5.x: Install-Module Pester -Force -SkipPublisherCheck -Scope CurrentUser
#>

# Force Pester 5+ (Windows ships with 3.4.0 which has incompatible syntax)
if (-not (Get-Module Pester -ListAvailable | Where-Object { $_.Version.Major -ge 5 })) {
    Write-Error "Pester 5+ required. Run: Install-Module Pester -Force -SkipPublisherCheck -Scope CurrentUser"
    return
}
Import-Module Pester -MinimumVersion 5.0 -Force

# ── Helper: resolve paths relative to test file ─────────────────────────────
$script:ProjectRoot = Split-Path -Parent $PSScriptRoot

# ── Helper: load Test-ValidServerName without running the full script ────────
# Extract just the function from Start-ArcMonitor.ps1
$script:StartScript = Join-Path $script:ProjectRoot "Start-ArcMonitor.ps1"
$script:FunctionBlock = $null
if (Test-Path $script:StartScript) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:StartScript, [ref]$null, [ref]$null)
    $funcDef = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'Test-ValidServerName' }, $true)
    if ($funcDef) {
        $script:FunctionBlock = $funcDef[0].Extent.Text
    }
}

# ── Tests ────────────────────────────────────────────────────────────────────

Describe "Test-ValidServerName" {
    BeforeAll {
        if ($script:FunctionBlock) {
            Invoke-Expression $script:FunctionBlock
        } else {
            throw "Could not extract Test-ValidServerName from Start-ArcMonitor.ps1"
        }
    }

    It "Accepts valid hostname" {
        Test-ValidServerName "srv-app-01" | Should -Be $true
    }

    It "Accepts FQDN" {
        Test-ValidServerName "srv-app-01.corp.local" | Should -Be $true
    }

    It "Accepts valid IPv4 address" {
        Test-ValidServerName "10.0.0.11" | Should -Be $true
    }

    It "Rejects empty string" {
        Test-ValidServerName "" | Should -Be $false
    }

    It "Rejects null" {
        Test-ValidServerName $null | Should -Be $false
    }

    It "Rejects string with spaces" {
        Test-ValidServerName "srv app 01" | Should -Be $false
    }

    It "Rejects string with special characters" {
        Test-ValidServerName "srv;drop table" | Should -Be $false
    }

    It "Rejects string with semicolons" {
        Test-ValidServerName "srv01;srv02" | Should -Be $false
    }

    It "Rejects invalid IP (out of range)" {
        Test-ValidServerName "256.0.0.1" | Should -Be $false
    }
}

Describe "Config defaults.json" {
    BeforeAll {
        $script:configPath = Join-Path $script:ProjectRoot "Config\defaults.json"
        $script:defaults = Get-Content $script:configPath -Raw | ConvertFrom-Json
    }

    It "Loads without errors" {
        $script:defaults | Should -Not -BeNullOrEmpty
    }

    It "Has network settings" {
        $script:defaults.network.winrmPort | Should -Be 5985
        $script:defaults.network.winrmHttpsPort | Should -Be 5986
        $script:defaults.network.tcpConnectTimeoutMs | Should -BeGreaterThan 0
    }

    It "Has prerequisite thresholds" {
        $script:defaults.prerequisites.minDiskSpaceGB | Should -Be 2
        $script:defaults.prerequisites.minDotNetRelease | Should -Be 394802
        $script:defaults.prerequisites.minPSMajorVersion | Should -Be 5
    }

    It "Has Azure endpoints" {
        @($script:defaults.azureEndpoints).Count | Should -BeGreaterOrEqual 7
        $script:defaults.azureEndpoints[0].host | Should -Not -BeNullOrEmpty
        $script:defaults.azureEndpoints[0].port | Should -Be 443
    }

    It "Has agent download URLs pointing to Microsoft domains" {
        $script:defaults.agentUrls.windowsAgent | Should -Match 'azure\.com|microsoft\.com|aka\.ms'
        $script:defaults.agentUrls.linuxAgent | Should -Match 'azure\.com|microsoft\.com|aka\.ms'
    }
}

Describe "ArcMonitor-Config Security" {
    BeforeAll {
        $script:configContent = Get-Content (Join-Path $script:ProjectRoot "ArcMonitor-Config.ps1") -Raw
    }

    It "Does not contain plaintext secrets (only placeholders allowed)" {
        $script:configContent | Should -Not -Match 'Secret\s*=\s*"[a-zA-Z0-9+/=]{20,}"'
    }

    It "Does not use Global scope for config export" {
        $script:configContent | Should -Not -Match '\$Global:'
    }

    It "Includes security warning about plaintext secrets" {
        $script:configContent | Should -Match 'Key Vault|Export-Clixml|DPAPI'
    }
}

Describe "Script Security Baseline" {
    It "Start-ArcMonitor does not use ExecutionPolicy Bypass" {
        $content = Get-Content (Join-Path $script:ProjectRoot "Start-ArcMonitor.ps1") -Raw
        $content | Should -Not -Match '-ExecutionPolicy.*Bypass'
    }

    It "ArcMonitor-Onboard does not use ExecutionPolicy Bypass" {
        $content = Get-Content (Join-Path $script:ProjectRoot "ArcMonitor-Onboard.ps1") -Raw
        $content | Should -Not -Match '-ExecutionPolicy.*Bypass'
    }

    It "PreReqCheck does not recommend TrustedHosts wildcard" {
        $content = Get-Content (Join-Path $script:ProjectRoot "ArcMonitor-PreReqCheck.ps1") -Raw
        $content | Should -Not -Match "TrustedHosts -Value '\*'"
    }

    It "Scripts use Set-StrictMode" {
        $startContent = Get-Content (Join-Path $script:ProjectRoot "Start-ArcMonitor.ps1") -Raw
        $startContent | Should -Match 'Set-StrictMode'

        $onboardContent = Get-Content (Join-Path $script:ProjectRoot "ArcMonitor-Onboard.ps1") -Raw
        $onboardContent | Should -Match 'Set-StrictMode'

        $prereqContent = Get-Content (Join-Path $script:ProjectRoot "ArcMonitor-PreReqCheck.ps1") -Raw
        $prereqContent | Should -Match 'Set-StrictMode'
    }
}
