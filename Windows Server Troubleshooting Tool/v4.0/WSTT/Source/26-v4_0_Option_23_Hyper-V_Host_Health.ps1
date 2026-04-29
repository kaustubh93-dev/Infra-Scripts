# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 — Option 23: Hyper-V Host Health
# Source lines: 8226 - 8315
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 — Option 23: Hyper-V Host Health
function Test-HyperVHostHealth {
    <#
    .SYNOPSIS
        Hyper-V host audit (VMs, integration services, dynamic memory, checkpoints, replica, vSwitch, GPU-P).
    #>
    [CmdletBinding()] param()
    Write-Header 'HYPER-V HOST HEALTH (Option 23)'
    if (-not (Test-WSTTHasRole 'Hyper-V')) {
        Write-Info 'Hyper-V role not installed — skipping.'
        Add-Finding -Severity 'NA' -Category 'HyperV' -CheckId '23.1' -Message 'Hyper-V not installed.'
        return
    }
    if (-not (Test-WSTTCommand 'Get-VM')) {
        Write-DiagWarning 'Hyper-V PowerShell module unavailable.' -Category 'HyperV' -CheckId '23.1'
        return
    }
    Write-Success 'Hyper-V role detected.' -Category 'HyperV' -CheckId '23.1'

    Write-Section 'VM Inventory'
    try {
        $vms = Get-VM -EA SilentlyContinue
        $byState = $vms | Group-Object State | Select-Object Name,Count
        $byState | Format-Table -AutoSize | Out-Host
        $crit = $vms | Where-Object { $_.State -eq 'Critical' }
        if ($crit) { Write-DiagError "VMs in Critical state: $($crit.Name -join ', ')" -Category 'HyperV' -CheckId '23.2' }
        else { Write-Success "Total VMs: $($vms.Count); none in Critical state." -Category 'HyperV' -CheckId '23.2' }
    } catch { Write-DiagWarning "Get-VM failed: $($_.Exception.Message)" -Category 'HyperV' -CheckId '23.2' }

    Write-Section 'Integration Services version'
    try {
        $stale = Get-VM | Where-Object { $_.IntegrationServicesVersion -and $_.IntegrationServicesVersion -lt (Get-OSCapability).Version }
        if ($stale) { Write-DiagWarning "VMs with stale integration services: $(($stale.Name) -join ', ')" -Category 'HyperV' -CheckId '23.3' }
        else { Write-Success 'Integration services aligned with host.' -Category 'HyperV' -CheckId '23.3' }
    } catch {}

    Write-Section 'Dynamic Memory pressure'
    try {
        Get-VM | Where-Object { $_.DynamicMemoryEnabled } | ForEach-Object {
            $assigned = $_.MemoryAssigned; $demand = $_.MemoryDemand
            if ($assigned -gt 0) {
                $pct = [math]::Round(($demand / $assigned) * 100, 1)
                if ($pct -ge 80) { Write-DiagWarning ("VM {0}: memory demand {1}% of assigned." -f $_.Name, $pct) -Category 'HyperV' -CheckId '23.4' }
            }
        }
    } catch {}

    Write-Section 'Checkpoint sprawl'
    try {
        $old = Get-VM | Get-VMSnapshot -EA SilentlyContinue | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-7) }
        if ($old) {
            Write-DiagWarning "Snapshots older than 7d: $($old.Count) (potential perf/disk impact)." -Category 'HyperV' -CheckId '23.5'
            $old | Select-Object VMName,Name,CreationTime | Format-Table -AutoSize | Out-Host
        } else { Write-Success 'No snapshots older than 7 days.' -Category 'HyperV' -CheckId '23.5' }
    } catch {}

    Write-Section 'Hyper-V Replica'
    if (Test-WSTTCommand 'Get-VMReplication') {
        try {
            $bad = Get-VMReplication -EA SilentlyContinue | Where-Object { $_.Health -ne 'Normal' }
            if ($bad) { Write-DiagError "Replication unhealthy on: $(($bad.Name) -join ', ')" -Category 'HyperV' -CheckId '23.6' }
            else { Write-Success 'Replication health: Normal (or no replicas).' -Category 'HyperV' -CheckId '23.6' }
        } catch {}
    }

    Write-Section 'vSwitch health'
    try {
        Get-VMSwitch | Format-Table Name,SwitchType,NetAdapterInterfaceDescription -AutoSize | Out-Host
        Write-Success 'vSwitches enumerated.' -Category 'HyperV' -CheckId '23.7'
    } catch {}

    Write-Section 'GPU partitioning (Server 2025)'
    if ((Get-OSCapability).Is2025 -and (Test-WSTTCommand 'Get-VMHostPartitionableGpu')) {
        try {
            $gpus = Get-VMHostPartitionableGpu -EA SilentlyContinue
            if ($gpus) { Write-Success "Partitionable GPUs: $($gpus.Count)" -Category 'HyperV' -CheckId '23.10' }
            else { Write-Info 'No partitionable GPUs detected.' }
        } catch {}
    } else { Write-Info 'GPU-P check requires Server 2025 + GPU-P-capable adapter.' }

    Write-Section 'Hyper-V VMMS event log (last 24h)'
    try {
        $evt = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-VMMS-Admin';Level=1,2,3;StartTime=(Get-Date).AddDays(-1)} -EA SilentlyContinue
        if ($evt) {
            Write-DiagWarning "VMMS admin log: $($evt.Count) Critical/Error/Warning entries (24h)." -Category 'HyperV' -CheckId '23.11'
            $evt | Select-Object -First 5 TimeCreated,Id,LevelDisplayName,Message | Format-List | Out-Host
        } else { Write-Success 'No VMMS admin events in last 24h.' -Category 'HyperV' -CheckId '23.11' }
    } catch {}
}
#endregion
