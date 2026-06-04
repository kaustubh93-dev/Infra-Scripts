#Requires -Version 5.1
<#
.SYNOPSIS
    Pester 5 tests for WSTT_v3.0.ps1 (Windows Server Troubleshooting Tool).
.DESCRIPTION
    Pre-publish quality gate. Each Describe is self-contained and dot-sources
    Tests/_WSTT-TestHelpers.ps1 in its BeforeAll to work around Pester 5's
    isolated Run-phase scopes.
.NOTES
    Run with:
        Import-Module Pester -MinimumVersion 5.0 -Force
        Invoke-Pester .\Tests\WSTT.Tests.ps1 -Output Detailed
#>

BeforeDiscovery {
    $sp = Join-Path (Split-Path -Parent $PSScriptRoot) 'WSTT_v3.0.ps1'
    if (-not (Test-Path $sp)) { throw "WSTT_v3.0.ps1 not found at $sp" }
}

Describe 'WSTT_v3.0.ps1 — Static / AST checks' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        $script:ScriptContent = Get-Content -Path $script:ScriptPath -Raw
        $parseErrors = $null; $tokens = $null
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath, [ref]$tokens, [ref]$parseErrors
        )
        $script:ParseErrors = $parseErrors
        $script:Functions = $script:Ast.FindAll(
            { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true
        )
    }

    It 'Parses without errors' {
        $script:ParseErrors | Should -BeNullOrEmpty
    }

    It 'Declares #Requires -RunAsAdministrator' {
        $script:ScriptContent | Should -Match '#Requires\s+-RunAsAdministrator'
    }

    It 'Has a param() block at top level' {
        $script:Ast.ParamBlock | Should -Not -BeNullOrEmpty
    }

    It 'Defines the documented entry-point function' {
        ($script:Functions.Name) | Should -Contain 'Start-TroubleshootingTool'
    }

    It 'Defines Invoke-TSSCommand (TSS launcher)' {
        ($script:Functions.Name) | Should -Contain 'Invoke-TSSCommand'
    }
}

Describe 'Security baseline' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        $script:ScriptContent = Get-Content -Path $script:ScriptPath -Raw
    }

    It 'Does not use -ExecutionPolicy Bypass' {
        $script:ScriptContent | Should -Not -Match '-ExecutionPolicy\s+Bypass'
    }

    It 'Does not assign to $Global: scope' {
        $script:ScriptContent | Should -Not -Match '\$Global:\w+\s*='
    }

    It 'Does not contain plaintext password assignments' {
        $script:ScriptContent | Should -Not -Match '\$(password|pwd|secret|apikey|token)\s*=\s*["''][^"'']{3,}["'']'
    }

    It 'Does not call Invoke-Expression on user input' {
        $script:ScriptContent | Should -Not -Match 'Invoke-Expression\s+\$'
    }

    It 'Uses array-form ArgumentList in TSS launcher (regression: NewSession parser bug)' {
        $script:ScriptContent | Should -Match '\$tssArgList\s*=\s*@\('
        $script:ScriptContent | Should -Not -Match '\$tssArgString\s*=\s*"-NoProfile'
    }
}

Describe 'Test-PathValid — input validation' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        function Write-DiagError   { param($msg) }
        function Write-DiagWarning { param($msg) }
        function Write-Success     { param($msg) }
        . ([scriptblock]::Create((Import-WSTTFunction -Name 'Test-PathValid')))
    }

    It 'Rejects empty path' {
        Test-PathValid -Path '' | Should -Be $false
    }

    It 'Rejects null path' {
        Test-PathValid -Path $null | Should -Be $false
    }

    It 'Rejects path traversal (..)' {
        Test-PathValid -Path 'C:\Logs\..\Windows' | Should -Be $false
    }

    It 'Rejects shell metacharacter (semicolon)' {
        Test-PathValid -Path 'C:\Logs;rm' | Should -Be $false
    }

    It 'Rejects shell metacharacter (subexpression)' {
        Test-PathValid -Path 'C:\Logs$(whoami)' | Should -Be $false
    }

    It 'Rejects shell metacharacter (backtick)' {
        Test-PathValid -Path 'C:\Logs`echo`' | Should -Be $false
    }

    It 'Rejects UNC paths' {
        Test-PathValid -Path '\\evil\share' | Should -Be $false
    }

    It 'Accepts an existing local path' {
        Test-PathValid -Path $env:TEMP | Should -Be $true
    }

    It 'Creates a new directory when -CreateIfNotExist is used' {
        $tmp = Join-Path $env:TEMP ("WSTT_Test_" + [guid]::NewGuid().ToString('N'))
        try {
            Test-PathValid -Path $tmp -CreateIfNotExist | Should -Be $true
            Test-Path $tmp | Should -Be $true
        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Get-ValidatedChoice — input validation' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        function Write-DiagWarning { param($msg) }
        . ([scriptblock]::Create((Import-WSTTFunction -Name 'Get-ValidatedChoice')))
    }

    It 'Returns the choice when valid input is supplied' {
        Mock Read-Host { 'Y' }
        Get-ValidatedChoice -Prompt 'Continue?' -ValidChoices @('Y','N') | Should -Be 'Y'
    }

    It 'Re-prompts on invalid input then returns valid choice' {
        $script:callCount = 0
        Mock Read-Host {
            $script:callCount++
            if ($script:callCount -lt 3) { 'BAD' } else { 'N' }
        }
        Get-ValidatedChoice -Prompt 'Continue?' -ValidChoices @('Y','N') | Should -Be 'N'
        $script:callCount | Should -Be 3
    }

    It 'Returns empty string when -AllowEmpty and blank input' {
        Mock Read-Host { '' }
        Get-ValidatedChoice -Prompt 'Optional?' -ValidChoices @('Y','N') -AllowEmpty | Should -Be ''
    }
}

Describe 'Invoke-TSSCommand — command-injection guard' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        function Write-DiagError   { param($msg) }
        function Write-DiagWarning { param($msg) }
        function Write-Success     { param($msg) }
        function Write-Info        { param($msg) }
        function Get-ValidatedChoice { param($Prompt, $ValidChoices) 'N' }
        $script:TSSPath = 'C:\NonExistentTSSPath_For_Test'
        . ([scriptblock]::Create((Import-WSTTFunction -Name 'Invoke-TSSCommand')))
    }

    It 'Rejects semicolon injection' {
        { Invoke-TSSCommand -Command '-Xperf Memory; rm -rf C:\' } | Should -Throw
    }

    It 'Rejects pipe injection' {
        { Invoke-TSSCommand -Command '-Xperf Memory | evil.exe' } | Should -Throw
    }

    It 'Rejects backtick injection' {
        { Invoke-TSSCommand -Command '-Xperf Memory `echo pwn`' } | Should -Throw
    }

    It 'Rejects subexpression injection' {
        { Invoke-TSSCommand -Command '-Xperf Memory $(whoami)' } | Should -Throw
    }

    It 'Accepts well-formed TSS arguments at parameter binding' {
        { Invoke-TSSCommand -Command "-Xperf Memory -XperfMaxFileMB 4096 -LogFolderPath 'C:\MS_data'" } |
            Should -Not -Throw
    }
}

Describe 'Test-PathOnCSV — cluster safety helper' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        . ([scriptblock]::Create((Import-WSTTFunction -Name 'Test-PathOnCSV')))
    }

    It 'Returns $false when no CSV paths are configured' {
        Test-PathOnCSV -Path 'C:\Logs' -CSVPaths @() | Should -Be $false
    }

    It 'Returns $true when path is rooted under a CSV mountpoint' {
        Test-PathOnCSV -Path 'C:\ClusterStorage\Volume1\Logs' `
                       -CSVPaths @('C:\ClusterStorage\Volume1') | Should -Be $true
    }

    It 'Is case-insensitive' {
        Test-PathOnCSV -Path 'c:\clusterstorage\volume1\logs' `
                       -CSVPaths @('C:\ClusterStorage\Volume1') | Should -Be $true
    }
}

Describe 'WSFC Cluster Port Compliance — port matrix constant' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        $script:ScriptContent = Get-Content -Path $script:ScriptPath -Raw
    }

    It 'Defines $script:WSFC_REQUIRED_PORTS' {
        $script:ScriptContent | Should -Match '\$script:WSFC_REQUIRED_PORTS\s*='
    }

    It 'Defines $script:HOSTNAME_REGEX' {
        $script:ScriptContent | Should -Match '\$script:HOSTNAME_REGEX\s*='
    }

    It 'Includes TCP/UDP 3343 (cluster heartbeat)' {
        $script:ScriptContent | Should -Match "Port\s*=\s*3343"
    }

    It 'Includes ICMP entry (Add Node Wizard)' {
        $script:ScriptContent | Should -Match "Protocol\s*=\s*'ICMP'"
    }

    It 'Includes WinRM 5985 (cloud witness)' {
        $script:ScriptContent | Should -Match "Port\s*=\s*5985"
    }

    It 'Does NOT include dynamic RPC range 49152-65535 (out of scope by design)' {
        $script:ScriptContent | Should -Not -Match 'Port\s*=\s*49152'
    }
}

Describe 'WSFC Cluster Port Compliance — function definitions' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        $tokens = $null; $errors = $null
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath, [ref]$tokens, [ref]$errors
        )
        $script:Functions = $script:Ast.FindAll(
            { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true
        )
    }

    It 'Defines Test-WSFCPortReachability' {
        ($script:Functions.Name) | Should -Contain 'Test-WSFCPortReachability'
    }

    It 'Defines Get-WSFCFirewallRuleStatus' {
        ($script:Functions.Name) | Should -Contain 'Get-WSFCFirewallRuleStatus'
    }

    It 'Defines Test-WSFCClusterPortCompliance (orchestrator)' {
        ($script:Functions.Name) | Should -Contain 'Test-WSFCClusterPortCompliance'
    }

    It 'Defines Show-WSFCPortSummaryTable' {
        ($script:Functions.Name) | Should -Contain 'Show-WSFCPortSummaryTable'
    }

    It 'Defines Export-WSFCPortReportToCsv' {
        ($script:Functions.Name) | Should -Contain 'Export-WSFCPortReportToCsv'
    }

    It 'Defines Export-WSFCPortReportToHtml' {
        ($script:Functions.Name) | Should -Contain 'Export-WSFCPortReportToHtml'
    }

    It 'Test-WSFCClusterPortCompliance has [CmdletBinding()]' {
        $func = $script:Functions | Where-Object { $_.Name -eq 'Test-WSFCClusterPortCompliance' } | Select-Object -First 1
        $func.Body.ParamBlock.Attributes.TypeName.Name | Should -Contain 'CmdletBinding'
    }
}

Describe 'WSFC menu wiring' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        $script:ScriptContent = Get-Content -Path $script:ScriptPath -Raw
    }

    It 'Show-MainMenu lists option 22' {
        $script:ScriptContent | Should -Match '22\.\s+WSFC Cluster Port Compliance'
    }

    It 'Get-ValidatedChoice accepts "22"' {
        $script:ScriptContent | Should -Match 'Select an option \(0-23\)'
    }

    It 'Dispatcher has a "22" case that calls Test-WSFCClusterPortCompliance' {
        $script:ScriptContent | Should -Match '"22"\s*\{[^}]*Test-WSFCClusterPortCompliance'
    }
}

Describe 'Recent Server Changes (24h) feature' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        $script:ScriptContent = Get-Content -Path $script:ScriptPath -Raw
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath, [ref]$tokens, [ref]$errors)
        $script:RcFunctions = $ast.FindAll(
            { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    }

    It 'Defines Get-RecentServerChange' {
        ($script:RcFunctions.Name) | Should -Contain 'Get-RecentServerChange'
    }

    It 'Defines the Get-RegistryKeyLastWriteTime helper' {
        ($script:RcFunctions.Name) | Should -Contain 'Get-RegistryKeyLastWriteTime'
    }

    It 'Get-RecentServerChange has [CmdletBinding()] and an -Hours parameter' {
        $func = $script:RcFunctions | Where-Object { $_.Name -eq 'Get-RecentServerChange' } | Select-Object -First 1
        $func.Body.ParamBlock.Attributes.TypeName.Name | Should -Contain 'CmdletBinding'
        ($func.Body.ParamBlock.Parameters.Name.VariablePath.UserPath) | Should -Contain 'Hours'
    }

    It 'Show-MainMenu lists option 23' {
        $script:ScriptContent | Should -Match '23\.\s+Recent Server Changes'
    }

    It 'Dispatcher has a "23" case that calls Get-RecentServerChange' {
        $script:ScriptContent | Should -Match '"23"\s*\{[\s\S]*?Get-RecentServerChange'
    }

    It 'P/Invoke type registration is idempotent' {
        $script:ScriptContent | Should -Match "Wstt\.Native\.RegInfo' -as \[type\]"
    }

    It 'HTML report includes the Recent Server Changes section' {
        $script:ScriptContent | Should -Match 'Recent Server Changes \(24h\)"; Cmd = \{ Get-RecentServerChange'
    }
}

Describe 'WSFC Get-WSFCFirewallRuleStatus — module-missing fallback' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        function Write-DiagError   { param($msg) }
        function Write-DiagWarning { param($msg) }
        function Write-Success     { param($msg) }
        function Write-Info        { param($msg) }
        . ([scriptblock]::Create((Import-WSTTFunction -Name 'Get-WSFCFirewallRuleStatus')))
    }

    It 'Returns Unknown with explanatory ErrorMessage when NetSecurity is missing' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-NetFirewallRule' }
        $r = Get-WSFCFirewallRuleStatus -PortDefinition @{ Service='Test'; Protocol='TCP'; Port=445 }
        $r.InboundAllow  | Should -Be 'Unknown'
        $r.OutboundAllow | Should -Be 'Unknown'
        $r.ErrorMessage  | Should -Match 'NetSecurity'
    }
}

Describe 'WSFC Test-WSFCPortReachability — protocol dispatch' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
        function Write-DiagError   { param($msg) }
        function Write-DiagWarning { param($msg) }
        function Write-Success     { param($msg) }
        function Write-Info        { param($msg) }
        . ([scriptblock]::Create((Import-WSTTFunction -Name 'Test-WSFCPortReachability')))
    }

    It 'Returns a PSCustomObject with TargetNode/Protocol/Port/Status' {
        $r = Test-WSFCPortReachability -TargetNode 'unreachable.invalid' `
            -PortDefinition @{ Service='Test'; Protocol='TCP'; Port=1 } -TimeoutMs 250
        $r | Should -Not -BeNullOrEmpty
        $r.TargetNode | Should -Be 'unreachable.invalid'
        $r.Protocol   | Should -Be 'TCP'
        $r.Port       | Should -Be 1
        $r.Status     | Should -BeIn @('Pass','Fail','Inconclusive')
    }

    It 'UDP probe returns Inconclusive (connectionless)' {
        $r = Test-WSFCPortReachability -TargetNode '127.0.0.1' `
            -PortDefinition @{ Service='Test'; Protocol='UDP'; Port=137 } -TimeoutMs 250
        $r.Status | Should -Be 'Inconclusive'
    }

    It 'Unknown protocol returns Fail with explanatory message' {
        $r = Test-WSFCPortReachability -TargetNode '127.0.0.1' `
            -PortDefinition @{ Service='Test'; Protocol='XYZ'; Port=1 } -TimeoutMs 250
        $r.Status       | Should -Be 'Fail'
        $r.ErrorMessage | Should -Match 'Unknown protocol'
    }
}

Describe 'PSScriptAnalyzer lint gate' {

    BeforeAll {
        . (Join-Path $PSScriptRoot '_WSTT-TestHelpers.ps1')
    }

    It 'Has 0 Error-level findings' -Skip:(-not [bool](Get-Module -ListAvailable PSScriptAnalyzer)) {
        $findings = Invoke-ScriptAnalyzer -Path $script:ScriptPath -Severity Error -ErrorAction SilentlyContinue
        if ($findings) {
            $findings | Format-Table RuleName, Line, Message -AutoSize | Out-String | Write-Host
        }
        ($findings | Measure-Object).Count | Should -Be 0
    }
}
