#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    WSTT v4.0 entry-point shim.

.DESCRIPTION
    Thin launcher for the WSTT module. All diagnostic logic lives in .\WSTT\
    (see WSTT.psd1 / WSTT.psm1 / Source\*.ps1). This shim only:
      1. Imports the module from the script's folder.
      2. Routes invocation to interactive (Start-TroubleshootingTool) or
         unattended (Invoke-WSTTUnattended) mode based on parameters.

.PARAMETER EnableLogging
    Enables transcript logging of the interactive session.

.PARAMETER Unattended
    Runs in unattended/scheduled mode (no prompts). Requires -Categories.

.PARAMETER Categories
    Categories of checks to run when -Unattended is used.

.PARAMETER Format
    Output format(s) for unattended runs.

.PARAMETER OutputPath
    Folder where unattended results are written.

.PARAMETER ComputerName
    Optional list of remote servers to fan out to.

.PARAMETER CredentialPath
    Path to a clixml credential file (Export-Clixml output) used for remoting.

.PARAMETER ThrottleLimit
    Max parallel PSSessions for multi-server runs.

.EXAMPLE
    .\WSTT.ps1
    Launches the interactive menu.

.EXAMPLE
    .\WSTT.ps1 -Unattended -Categories ModernSecurity,Server2025 -Format JSON -OutputPath C:\WSTTReports
    Runs ModernSecurity and Server2025 audits unattended and writes JSON.
#>

[CmdletBinding(DefaultParameterSetName='Interactive')]
param(
    [Parameter(ParameterSetName='Interactive')]
    [switch]$EnableLogging,

    [Parameter(ParameterSetName='Unattended', Mandatory)]
    [switch]$Unattended,

    [Parameter(ParameterSetName='Unattended')]
    [ValidateSet('Network','Memory','CPU','Disk','Services','EventLog','DNS','Security',
                 'WindowsUpdate','TLS','IIS','TaskScheduler','Baseline',
                 'AD','HyperV','AdvStorage','ModernSecurity','Server2025','PKI','Arc','Patching','All')]
    [string[]]$Categories = @('All'),

    [Parameter(ParameterSetName='Unattended')]
    [ValidateSet('JSON','NDJSON','CSV','SARIF','HTML','Both','All')]
    [string]$Format = 'JSON',

    [Parameter(ParameterSetName='Unattended')]
    [string]$OutputPath,

    [Parameter(ParameterSetName='Unattended')]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName='Unattended')]
    [string]$CredentialPath,

    [Parameter(ParameterSetName='Unattended')]
    [int]$ThrottleLimit = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'WSTT\WSTT.psd1'
if (-not (Test-Path $modulePath)) {
    throw "WSTT module not found at '$modulePath'. Run tools\Split-Module.ps1 first."
}
Import-Module $modulePath -Force -DisableNameChecking

if ($Unattended) {
    Invoke-WSTTUnattended `
        -Categories     $Categories `
        -Format         $Format `
        -OutputPath     $OutputPath `
        -ComputerName   $ComputerName `
        -CredentialPath $CredentialPath `
        -ThrottleLimit  $ThrottleLimit
}
elseif ($EnableLogging) {
    Start-TroubleshootingTool -EnableLogging
}
else {
    Start-TroubleshootingTool
}
