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
