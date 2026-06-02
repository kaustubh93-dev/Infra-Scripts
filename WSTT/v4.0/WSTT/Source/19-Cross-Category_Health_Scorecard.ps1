# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Cross-Category Health Scorecard
# Source lines: 5581 - 5788
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Cross-Category Health Scorecard
function Test-CrossCategoryHealth {
    <#
    .SYNOPSIS
        Consolidated health scorecard surfacing highest-frequency cross-cutting issues
    .DESCRIPTION
        Quick summary of the most common production issues across all categories:
        cluster/AG instability, storage errors, DNS failures, RDP connectivity
    #>
    [CmdletBinding()]
    param()

    Write-Header "Cross-Category Health Scorecard"
    $issues = 0

    # 1. Cluster / AG Instability (heartbeat loss + network discards)
    Write-Info "1. Cluster / AG Stability:"
    try {
        $clusterEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1135, 1672
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($clusterEvts) {
            $issues++
            Write-DiagError "   ISSUE: $($clusterEvts.Count) cluster heartbeat/quarantine events in 7 days"
        }
        else {
            Write-Success "   OK - No cluster instability events"
        }
    }
    catch {
        Write-Info "   Skipped (Failover Clustering not installed)"
    }

    # 2. Storage 129/153 Errors
    Write-Info "2. Storage Health:"
    try {
        $storEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 129, 153
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($storEvts) {
            $issues++
            Write-DiagError "   ISSUE: $($storEvts.Count) storage adapter errors (129/153) in 7 days"
        }
        else {
            Write-Success "   OK - No storage path errors"
        }
    }
    catch { Write-Info "   Could not check" }

    # 3. DNS Bad Key / Cluster DNS
    Write-Info "3. DNS Health:"
    try {
        $dnsFailures = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 8018, 8019
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($dnsFailures) {
            $issues++
            Write-DiagWarning "   ISSUE: DNS dynamic update failures detected"
        }
        else {
            Write-Success "   OK - No DNS update failures"
        }
    }
    catch { Write-Info "   Could not check" }

    # 4. RDP Connectivity & MachineKeys
    Write-Info "4. RDP Connectivity:"
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync('127.0.0.1', 3389)
        $completed = $connectTask.Wait(2000)  # 2-second timeout
        if ($completed -and $tcpClient.Connected) {
            Write-Success "   OK - RDP port 3389 is listening"
        }
        else {
            $issues++
            Write-DiagError "   ISSUE: RDP port 3389 is NOT listening"
        }
        $tcpClient.Close()
        $tcpClient.Dispose()
    }
    catch {
        Write-Info "   Could not test RDP port"
        if ($tcpClient) { $tcpClient.Dispose() }
    }

    try {
        $mkPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
        if (Test-Path $mkPath) {
            $acl = Get-Acl $mkPath -ErrorAction Stop
            $hasSystem = $acl.Access | Where-Object { $_.IdentityReference -like '*SYSTEM*' }
            if (-not $hasSystem) {
                $issues++
                Write-DiagError "   ISSUE: MachineKeys missing SYSTEM permissions (RDP/TLS may break)"
            }
        }
    }
    catch { }

    # 5. Account Lockouts
    Write-Info "5. Account Lockouts:"
    try {
        $lockouts = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4740
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($lockouts) {
            $issues++
            Write-DiagWarning "   ISSUE: $($lockouts.Count) account lockout(s) in last 24h"
        }
        else {
            Write-Success "   OK - No account lockouts"
        }
    }
    catch { Write-Info "   Could not check (audit policy may be needed)" }

    # 6. Pending Reboot
    Write-Info "6. Pending Reboot:"
    $rebootNeeded = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") -or
    (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
    if ($rebootNeeded) {
        $issues++
        Write-DiagWarning "   ISSUE: Pending reboot detected"
    }
    else {
        Write-Success "   OK - No pending reboot"
    }

    # 7. Schannel / TLS Errors
    Write-Info "7. TLS/Schannel Health:"
    try {
        $schannelEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 36870, 36871
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 3 -ErrorAction SilentlyContinue

        if ($schannelEvts) {
            $issues++
            Write-DiagWarning "   ISSUE: Schannel TLS errors detected ($($schannelEvts.Count) in 7 days)"
        }
        else {
            Write-Success "   OK - No Schannel errors"
        }
    }
    catch { Write-Info "   Could not check" }

    # 8. Quorum Health (v3.0)
    if ($script:ClusterEnv.IsClusterNode) {
        Write-Info "8. Cluster Quorum Health:"
        try {
            $quorumType = $script:ClusterEnv.QuorumType
            $quorumRes = $script:ClusterEnv.QuorumResource
            Write-Info "   Quorum Type: $quorumType | Witness: $quorumRes"
            
            $downNodes = $script:ClusterEnv.ClusterNodes | Where-Object { $_.State -ne 'Up' }
            if ($downNodes) {
                $issues++
                Write-DiagError "   ISSUE: $(@($downNodes).Count) cluster node(s) not in 'Up' state:"
                foreach ($dn in $downNodes) {
                    Write-DiagWarning "     $($dn.Name): $($dn.State)"
                }
            }
            else {
                Write-Success "   OK - All $(@($script:ClusterEnv.ClusterNodes).Count) cluster nodes are Up"
            }
        }
        catch {
            Write-Info "   Could not check quorum"
        }

        # 9. SQL AG Sync Health (v3.0)
        if ($script:ClusterEnv.IsAGInstalled -and $script:ClusterEnv.AGDetails.Count -gt 0) {
            Write-Info "9. SQL AG Synchronization:"
            foreach ($ag in $script:ClusterEnv.AGDetails) {
                if ($ag.sync_health -eq 'HEALTHY') {
                    Write-Success "   AG '$($ag.ag_name)': $($ag.local_role) - $($ag.sync_health)"
                }
                else {
                    $issues++
                    Write-DiagError "   ISSUE: AG '$($ag.ag_name)': $($ag.local_role) - $($ag.sync_health)"
                }
            }
        }
    }

    # Summary
    Write-Host ""
    if ($issues -eq 0) {
        Write-Success "SCORECARD: All clear - no cross-category issues detected!"
    }
    else {
        Write-DiagWarning "SCORECARD: $issues issue area(s) need attention (see details above)"
    }
    Write-Info "Run individual diagnostics (options 1-9) for deeper analysis."
}
#endregion
