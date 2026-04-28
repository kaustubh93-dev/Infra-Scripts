# Test helpers for WSTT.Tests.ps1
# Dot-sourced inside each Describe's BeforeAll so functions/paths are
# available in Pester 5's isolated Run-phase scopes.

$script:ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'WSTT_v3.0.ps1'

function Import-WSTTFunction {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Path = $script:ScriptPath
    )
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors
    )
    $func = $ast.FindAll(
        { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq $Name },
        $true
    ) | Select-Object -First 1
    if (-not $func) { throw "Function '$Name' not found in WSTT script" }
    return $func.Extent.Text
}
