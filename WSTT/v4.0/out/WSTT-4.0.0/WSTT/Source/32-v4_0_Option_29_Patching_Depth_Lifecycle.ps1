# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 — Option 29: Patching Depth & Lifecycle
# Source lines: 8747 - 8819
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 — Option 29: Patching Depth & Lifecycle
function Test-PatchingDepthAndLifecycle {
    <#
    .SYNOPSIS
        Hotpatch state, latest LCU age, pending-reboot root cause, failed updates, OS lifecycle.
    #>
    [CmdletBinding()] param()
    Write-Header 'PATCHING DEPTH & LIFECYCLE (Option 29)'
    $cap = Get-OSCapability

    Write-Section 'Latest cumulative update'
    try {
        $hf = Get-HotFix -EA SilentlyContinue | Where-Object { $_.Description -match 'Update|Security' } |
              Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hf -and $hf.InstalledOn) {
            $age = (New-TimeSpan -Start $hf.InstalledOn -End (Get-Date)).Days
            if ($age -gt 60) { Write-DiagError "Last update $($hf.HotFixID) is $age days old (>60d)." -Category 'Patching' -CheckId '29.2' }
            elseif ($age -gt 35) { Write-DiagWarning "Last update $($hf.HotFixID) is $age days old." -Category 'Patching' -CheckId '29.2' }
            else { Write-Success "Last update $($hf.HotFixID), $age days ago." -Category 'Patching' -CheckId '29.2' }
        } else { Write-DiagWarning 'No hotfixes detected.' -Category 'Patching' -CheckId '29.2' }
    } catch {}

    Write-Section 'Pending reboot signals'
    $pending = @{}
    $pending.CBS  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $pending.WU   = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $pending.PFRO = $false
    try {
        $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA SilentlyContinue).PendingFileRenameOperations
        $pending.PFRO = [bool]$pfro
    } catch {}
    $any = $pending.GetEnumerator() | Where-Object { $_.Value }
    if ($any) {
        Write-DiagWarning "Pending reboot signals: $($any.Key -join ', ')" -Category 'Patching' -CheckId '29.4'
    } else { Write-Success 'No pending reboot signals.' -Category 'Patching' -CheckId '29.4' }

    Write-Section 'Failed updates (last 30d)'
    try {
        $fails = Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-WindowsUpdateClient';Level=2,3;StartTime=(Get-Date).AddDays(-30)} -EA SilentlyContinue
        if ($fails) { Write-DiagError "WindowsUpdateClient failures (30d): $($fails.Count)" -Category 'Patching' -CheckId '29.5' }
        else { Write-Success 'No WindowsUpdateClient failures in last 30 days.' -Category 'Patching' -CheckId '29.5' }
    } catch {}

    Write-Section 'OS lifecycle'
    $lifecycle = @{
        '2019' = [datetime]'2029-01-09'
        '2022' = [datetime]'2031-10-14'
        '2025' = [datetime]'2034-10-10'
    }
    $key = if ($cap.Is2019) { '2019' } elseif ($cap.Is2022) { '2022' } elseif ($cap.Is2025) { '2025' } else { $null }
    if ($key) {
        $end = $lifecycle[$key]
        $months = [int](($end - (Get-Date)).TotalDays / 30)
        if ($months -lt 12) { Write-DiagWarning "Server $key extended-support ends $($end.ToString('yyyy-MM-dd')) (in $months months)." -Category 'Patching' -CheckId '29.6' }
        else { Write-Success "Server $key supported until $($end.ToString('yyyy-MM-dd')) ($months months)." -Category 'Patching' -CheckId '29.6' }
    } else { Write-Info 'Lifecycle table has no entry for this build.' }

    Write-Section '.NET Framework version'
    try {
        $rel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -EA SilentlyContinue).Release
        Write-Info ".NET Framework Release key: $rel"
    } catch {}

    Write-Section 'WSUS source'
    try {
        $wu = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name UseWUServer -EA SilentlyContinue).UseWUServer
        if ($wu -eq 1) {
            $svr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name WUServer -EA SilentlyContinue).WUServer
            Write-Info "WSUS source: $svr"
        } else { Write-Info 'Microsoft Update (no WSUS).' }
    } catch {}
}
#endregion
