# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 — Option 28: Hybrid / Azure Arc
# Source lines: 8694 - 8745
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 — Option 28: Hybrid / Azure Arc
function Test-AzureArcHybridHealth {
    <#
    .SYNOPSIS
        Arc agent health, AMA, outbound endpoints, extension state.
    #>
    [CmdletBinding()] param()
    Write-Header 'HYBRID / AZURE ARC (Option 28)'

    $himds = Get-Service himds -EA SilentlyContinue
    if (-not $himds) {
        Write-Info 'Azure Arc agent (himds) not installed — host is not Arc-enabled.'
        Add-Finding -Severity 'NA' -Category 'Arc' -CheckId '28.1' -Message 'Arc agent not installed.'
        return
    }
    Write-Section 'Arc agent service'
    if ($himds.Status -eq 'Running') { Write-Success 'himds service running.' -Category 'Arc' -CheckId '28.1' }
    else { Write-DiagError "himds service status: $($himds.Status)" -Category 'Arc' -CheckId '28.1' }

    Write-Section 'azcmagent show'
    if (Test-WSTTCommand 'azcmagent') {
        try {
            $info = & azcmagent show 2>&1 | Out-String
            Write-Host $info
            if ($info -match 'Agent Status\s*:\s*Connected') {
                Write-Success 'Arc agent: Connected.' -Category 'Arc' -CheckId '28.1'
            } else {
                Write-DiagWarning 'Arc agent NOT in Connected state.' -Category 'Arc' -CheckId '28.1'
            }
        } catch { Write-DiagWarning "azcmagent failed: $($_.Exception.Message)" -Category 'Arc' -CheckId '28.1' }
    } else { Write-DiagWarning 'azcmagent CLI not in PATH.' -Category 'Arc' -CheckId '28.1' }

    Write-Section 'Azure Monitor Agent (AMA)'
    $ama = Get-Service AzureMonitorAgent -EA SilentlyContinue
    if ($ama) {
        if ($ama.Status -eq 'Running') { Write-Success 'AzureMonitorAgent running.' -Category 'Arc' -CheckId '28.3' }
        else { Write-DiagWarning "AMA status: $($ama.Status)" -Category 'Arc' -CheckId '28.3' }
    } else { Write-Info 'Azure Monitor Agent not installed.' }

    Write-Section 'Outbound endpoint reachability (TCP 443)'
    $endpoints = @(
        'management.azure.com',
        'guestnotificationservice.azure.com',
        'login.microsoftonline.com'
    )
    foreach ($ep in $endpoints) {
        $ok = Test-NetConnection -ComputerName $ep -Port 443 -InformationLevel Quiet -EA SilentlyContinue
        if ($ok) { Write-Success "$ep:443 reachable." -Category 'Arc' -CheckId '28.6' }
        else { Write-DiagError "$ep:443 NOT reachable (Arc may fail)." -Category 'Arc' -CheckId '28.6' }
    }
}
#endregion
