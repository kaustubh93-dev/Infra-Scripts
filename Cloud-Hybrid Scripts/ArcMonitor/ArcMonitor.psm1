#Requires -Version 5.1
<#
.SYNOPSIS
    ArcMonitor — Root module loader
.DESCRIPTION
    Dot-sources all component scripts to assemble the ArcMonitor module.
    Import via: Import-Module .\ArcMonitor.psd1
#>

$ModuleRoot = $PSScriptRoot

# Load components in dependency order
. "$ModuleRoot\ArcMonitor-TUI.ps1"
. "$ModuleRoot\ArcMonitor-Config.ps1"
. "$ModuleRoot\ArcMonitor-PreReqCheck.ps1"
. "$ModuleRoot\ArcMonitor-Onboard.ps1"
