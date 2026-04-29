# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Event Message Helper
# Source lines: 453 - 478
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Event Message Helper
function Get-EventSnippet {
    <#
    .SYNOPSIS
        Safely extracts a message snippet from an event log entry
    .PARAMETER Event
        The event log entry
    .PARAMETER MaxLength
        Maximum number of characters to return (default: 100)
    #>
    param(
        [Parameter(Mandatory = $true)]$Event,
        [int]$MaxLength = 100
    )
    
    $msg = $Event.Message
    if ([string]::IsNullOrEmpty($msg)) {
        return "(No message available)"
    }
    $msg = $msg -replace '[\r\n]+', ' '
    if ($msg.Length -gt $MaxLength) {
        return $msg.Substring(0, $MaxLength)
    }
    return $msg
}
#endregion
