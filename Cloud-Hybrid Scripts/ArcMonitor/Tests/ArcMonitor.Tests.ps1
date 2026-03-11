#Requires -Modules Pester
<#
.SYNOPSIS
    Pester tests for ArcMonitor framework.
.DESCRIPTION
    Unit tests covering input validation, config loading, defaults,
    and security-related checks.
#>

BeforeAll {
    $scriptRoot = Split-Path -Parent $PSScriptRoot
    . "$scriptRoot\Start-ArcMonitor.ps1" -Mode $null 2>$null
}

Describe "Test-ValidServerName" {
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
        $configPath = Join-Path (Split-Path -Parent $PSScriptRoot) "Config\defaults.json"
        $defaults = Get-Content $configPath -Raw | ConvertFrom-Json
    }

    It "Loads without errors" {
        $defaults | Should -Not -BeNullOrEmpty
    }

    It "Has network settings" {
        $defaults.network.winrmPort | Should -Be 5985
        $defaults.network.winrmHttpsPort | Should -Be 5986
        $defaults.network.tcpConnectTimeoutMs | Should -BeGreaterThan 0
    }

    It "Has prerequisite thresholds" {
        $defaults.prerequisites.minDiskSpaceGB | Should -Be 2
        $defaults.prerequisites.minDotNetRelease | Should -Be 394802
        $defaults.prerequisites.minPSMajorVersion | Should -Be 5
    }

    It "Has Azure endpoints" {
        $defaults.azureEndpoints.Count | Should -BeGreaterOrEqual 7
        $defaults.azureEndpoints[0].host | Should -Not -BeNullOrEmpty
        $defaults.azureEndpoints[0].port | Should -Be 443
    }

    It "Has agent download URLs pointing to Microsoft domains" {
        $defaults.agentUrls.windowsAgent | Should -Match 'azure\.com|microsoft\.com|aka\.ms'
        $defaults.agentUrls.linuxAgent | Should -Match 'azure\.com|microsoft\.com|aka\.ms'
    }
}

Describe "ArcMonitor-Config Security" {
    BeforeAll {
        $configContent = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) "ArcMonitor-Config.ps1") -Raw
    }

    It "Does not contain plaintext secrets (only placeholders allowed)" {
        # Ensure the config file only has placeholder values, not real secrets
        $configContent | Should -Not -Match 'Secret\s*=\s*"[a-zA-Z0-9+/=]{20,}"'
    }

    It "Does not use Global scope for config export" {
        $configContent | Should -Not -Match '\$Global:'
    }

    It "Includes security warning about plaintext secrets" {
        $configContent | Should -Match 'Key Vault|Export-Clixml|DPAPI'
    }
}

Describe "Script Security Baseline" {
    It "Start-ArcMonitor does not use ExecutionPolicy Bypass" {
        $content = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) "Start-ArcMonitor.ps1") -Raw
        $content | Should -Not -Match '-ExecutionPolicy.*Bypass'
    }

    It "ArcMonitor-Onboard does not use ExecutionPolicy Bypass" {
        $content = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) "ArcMonitor-Onboard.ps1") -Raw
        $content | Should -Not -Match '-ExecutionPolicy.*Bypass'
    }

    It "PreReqCheck does not recommend TrustedHosts wildcard" {
        $content = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) "ArcMonitor-PreReqCheck.ps1") -Raw
        $content | Should -Not -Match "TrustedHosts -Value '\*'"
    }

    It "Scripts use Set-StrictMode" {
        $startContent = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) "Start-ArcMonitor.ps1") -Raw
        $startContent | Should -Match 'Set-StrictMode'

        $onboardContent = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) "ArcMonitor-Onboard.ps1") -Raw
        $onboardContent | Should -Match 'Set-StrictMode'

        $prereqContent = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) "ArcMonitor-PreReqCheck.ps1") -Raw
        $prereqContent | Should -Match 'Set-StrictMode'
    }
}
