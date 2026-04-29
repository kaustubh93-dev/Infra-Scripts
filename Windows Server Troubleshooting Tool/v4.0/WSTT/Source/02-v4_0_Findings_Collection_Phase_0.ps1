# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 Findings Collection (Phase 0)
# Source lines: 196 - 257
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 Findings Collection (Phase 0)
# Central in-memory store for structured diagnostic findings. Used by Add-Finding
# and surfaced via Option 31 (Export Diagnostics) and unattended mode.
$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:RunMetadata = [pscustomobject]@{
    Schema       = 'wstt-findings-v1'
    Tool         = 'WSTT'
    Version      = '4.0'
    Host         = $env:COMPUTERNAME
    User         = $env:USERNAME
    StartedUtc   = (Get-Date).ToUniversalTime().ToString('o')
    PSVersion    = $PSVersionTable.PSVersion.ToString()
}

function Add-Finding {
    <#
    .SYNOPSIS
        Adds a structured finding to the in-memory collection.
    .DESCRIPTION
        Phase 0 helper. Called automatically by Write-Success/DiagWarning/DiagError
        so existing checks contribute to JSON/CSV/SARIF output without rewriting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('INFO','WARN','ERROR','FATAL','NA')]
        [string]$Severity,
        [string]$Category = 'General',
        [string]$CheckId  = '',
        [Parameter(Mandatory)][string]$Message,
        [object]$Data
    )
    if ($null -eq $script:Findings) { return }
    $f = [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Severity     = $Severity
        Category     = $Category
        CheckId      = $CheckId
        Message      = $Message
        Data         = $Data
        Host         = $env:COMPUTERNAME
    }
    [void]$script:Findings.Add($f)
}

function Reset-Findings {
    <#
    .SYNOPSIS
        Clear the in-memory findings collection (e.g., between unattended runs).
    #>
    [CmdletBinding()] param()
    $script:Findings.Clear()
}

function Get-Findings {
    <#
    .SYNOPSIS
        Returns a snapshot copy of current findings.
    #>
    [CmdletBinding()] param()
    return ,@($script:Findings)
}
#endregion
