# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Event Query Helper
# Source lines: 480 - 518
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Event Query Helper
function Get-RecentEvents {
    <#
    .SYNOPSIS
        Shared helper to query recent Windows Event Log entries
    .PARAMETER LogName
        Event log name (e.g. System, Application, Security)
    .PARAMETER EventIds
        Array of Event IDs to search for
    .PARAMETER HoursBack
        Number of hours to look back (default: 24)
    .PARAMETER DaysBack
        Number of days to look back (overrides HoursBack if specified)
    .PARAMETER MaxEvents
        Maximum events to return (default: 50)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][int[]]$EventIds,
        [int]$HoursBack = 0,
        [int]$DaysBack = 0,
        [int]$MaxEvents = 50
    )
    
    $startTime = if ($DaysBack -gt 0) { (Get-Date).AddDays(-$DaysBack) } elseif ($HoursBack -gt 0) { (Get-Date).AddHours(-$HoursBack) } else { (Get-Date).AddHours(-24) }
    
    try {
        @(Get-WinEvent -FilterHashtable @{
                LogName   = $LogName
                Id        = $EventIds
                StartTime = $startTime
            } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
    }
    catch {
        @()
    }
}
#endregion
