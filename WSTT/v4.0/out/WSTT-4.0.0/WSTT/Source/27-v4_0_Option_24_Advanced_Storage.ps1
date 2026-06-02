# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 — Option 24: Advanced Storage
# Source lines: 8317 - 8394
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 — Option 24: Advanced Storage
function Test-AdvancedStorageHealth {
    <#
    .SYNOPSIS
        S2D / Storage Replica / Dedup / ReFS / Storage QoS / NVMe firmware checks.
    #>
    [CmdletBinding()] param()
    Write-Header 'ADVANCED STORAGE (Option 24)'

    Write-Section 'S2D / Storage Pool'
    if (Test-WSTTCommand 'Get-StoragePool') {
        try {
            $pools = Get-StoragePool -EA SilentlyContinue | Where-Object { $_.IsPrimordial -eq $false }
            foreach ($p in $pools) {
                if ($p.HealthStatus -ne 'Healthy') {
                    Write-DiagError "Pool '$($p.FriendlyName)' health=$($p.HealthStatus); op=$($p.OperationalStatus)" -Category 'Storage' -CheckId '24.1'
                } else {
                    Write-Success "Pool '$($p.FriendlyName)' healthy." -Category 'Storage' -CheckId '24.1'
                }
            }
            if (-not $pools) { Write-Info 'No non-primordial storage pools (S2D not configured).' }
        } catch {}
    }

    Write-Section 'Storage Replica'
    if (Test-WSTTCommand 'Get-SRPartnership') {
        try {
            $sr = Get-SRPartnership -EA SilentlyContinue
            if ($sr) { $sr | Format-Table -AutoSize | Out-Host; Write-Success 'Storage Replica partnerships enumerated.' -Category 'Storage' -CheckId '24.3' }
            else { Write-Info 'No Storage Replica partnerships.' }
        } catch {}
    }

    Write-Section 'Data Deduplication'
    if (Test-WSTTCommand 'Get-DedupStatus') {
        try {
            $dd = Get-DedupStatus -EA SilentlyContinue
            if ($dd) {
                foreach ($v in $dd) {
                    $age = (New-TimeSpan -Start $v.LastOptimizationTime -End (Get-Date)).Days
                    if ($age -gt 7) { Write-DiagWarning "Dedup $($v.Volume) last optimized $age days ago." -Category 'Storage' -CheckId '24.4' }
                    else { Write-Success "Dedup $($v.Volume): savings $([math]::Round($v.SavingsRate,1))% (last opt $age d)." -Category 'Storage' -CheckId '24.4' }
                }
            } else { Write-Info 'Deduplication not enabled on any volume.' }
        } catch {}
    }

    Write-Section 'ReFS file integrity'
    if (Test-WSTTCommand 'Get-FileIntegrity') {
        try {
            $refs = Get-Volume | Where-Object FileSystem -eq 'ReFS'
            if ($refs) {
                Write-Success "ReFS volumes: $(($refs.DriveLetter -join ',') )" -Category 'Storage' -CheckId '24.5'
            } else { Write-Info 'No ReFS volumes.' }
        } catch {}
    }

    Write-Section 'Storage QoS policies'
    if (Test-WSTTCommand 'Get-StorageQosPolicy') {
        try {
            $q = Get-StorageQosPolicy -EA SilentlyContinue
            if ($q) { $q | Format-Table Name,PolicyType,MinimumIops,MaximumIops -AutoSize | Out-Host
                     Write-Success "$($q.Count) QoS policies." -Category 'Storage' -CheckId '24.6' }
            else { Write-Info 'No Storage QoS policies.' }
        } catch {}
    }

    Write-Section 'NVMe / Physical disk firmware'
    try {
        Get-PhysicalDisk -EA SilentlyContinue |
            Select-Object FriendlyName,MediaType,HealthStatus,FirmwareVersion,Size |
            Format-Table -AutoSize | Out-Host
        $bad = Get-PhysicalDisk -EA SilentlyContinue | Where-Object { $_.HealthStatus -ne 'Healthy' }
        if ($bad) { Write-DiagError "Unhealthy physical disks: $(($bad.FriendlyName) -join ', ')" -Category 'Storage' -CheckId '24.10' }
        else { Write-Success 'All physical disks healthy.' -Category 'Storage' -CheckId '24.10' }
    } catch {}
}
#endregion
