# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Disk/Storage Diagnostics
# Source lines: 3368 - 4126
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Disk/Storage Diagnostics
function Test-DiskPerformance {
    <#
    .SYNOPSIS
        Analyzes disk performance
    .DESCRIPTION
        Checks physical disks, logical disk space, latency, cluster size, IOPS, throughput,
        media type, SMART health, VSS snapshots, Storage Spaces, fragmentation, pagefile
        placement, filter drivers, MPIO, ReFS/NTFS, disk busy time, and storage tiering
    .EXAMPLE
        Test-DiskPerformance
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "Disk Performance Analysis"
    
    # Cache volumes once for reuse throughout this function
    $cachedVolumes = $null
    try {
        $cachedVolumes = Get-Volume -ErrorAction Stop | Where-Object { $null -ne $_.DriveLetter }
    }
    catch {
        Write-DiagError "Failed to retrieve volume information: $($_.Exception.Message)"
    }
    
    # Disk information
    try {
        $disks = Get-PhysicalDisk -ErrorAction Stop
        Write-Info "Physical Disks:"
        foreach ($disk in $disks) {
            Write-Info "  $($disk.FriendlyName) - Size: $([math]::Round($disk.Size / 1GB, 2)) GB - Health: $($disk.HealthStatus)"
        }
    }
    catch {
        Write-DiagError "Failed to retrieve physical disk information: $($_.Exception.Message)"
    }
    
    # Logical disk space
    Write-Section "Logical Disk Space"
    if ($cachedVolumes) {
        foreach ($vol in $cachedVolumes) {
            if ($vol.Size -le 0) { continue }
            $usedSpace = $vol.Size - $vol.SizeRemaining
            $usedPercent = [math]::Round(($usedSpace / $vol.Size) * 100, 2)
            $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
            
            Write-Info "  Drive $($vol.DriveLetter): - $($usedPercent)% used - $($freeGB) GB free"
            if ($usedPercent -gt $DISK_CRITICAL_THRESHOLD) {
                Write-DiagError "    CRITICAL: Less than 10% free space!"
            }
            elseif ($usedPercent -gt $DISK_WARNING_THRESHOLD) {
                Write-DiagWarning "    WARNING: Less than 20% free space"
            }
        }
    }
    else {
        Write-DiagWarning "  No volume information available"
    }
    
    # Disk latency check
    Write-Section "Disk Latency (avg over last few seconds)"
    try {
        $diskReadLatency = Get-Counter '\PhysicalDisk(*)\Avg. Disk sec/Read' -ErrorAction Stop
        
        if ($diskReadLatency) {
            foreach ($sample in $diskReadLatency.CounterSamples) {
                if ($sample.InstanceName -ne "_total") {
                    $latencyMs = [math]::Round($sample.CookedValue * 1000, 2)
                    Write-Info "  Read Latency - $($sample.InstanceName): $($latencyMs) ms"
                    
                    if ($latencyMs -gt $DISK_LATENCY_CRITICAL_MS) {
                        Write-DiagError "    CRITICAL: Serious I/O bottleneck (>$($DISK_LATENCY_CRITICAL_MS)ms)"
                    }
                    elseif ($latencyMs -gt $DISK_LATENCY_WARNING_MS) {
                        Write-DiagWarning "    WARNING: Slow, needs attention ($($DISK_LATENCY_WARNING_MS)-$($DISK_LATENCY_CRITICAL_MS)ms)"
                    }
                    elseif ($latencyMs -gt $DISK_LATENCY_ACCEPTABLE_MS) {
                        Write-Info "    INFO: Acceptable ($($DISK_LATENCY_ACCEPTABLE_MS)-$($DISK_LATENCY_WARNING_MS)ms)"
                    }
                    else {
                        Write-Success "    GOOD: Very good (<$($DISK_LATENCY_ACCEPTABLE_MS)ms)"
                    }
                }
            }
        }
    }
    catch {
        Write-DiagWarning "Could not retrieve disk latency metrics: $($_.Exception.Message)"
    }
    
    # Check cluster size for volumes (reuses cached $cachedVolumes)
    Write-Section "Cluster Size (should be 64KB for databases)"
    if ($cachedVolumes) {
        foreach ($vol in $cachedVolumes) {
            $drive = $vol.DriveLetter + ":"
            try {
                $clusterSize = (Get-CimInstance -Query "SELECT BlockSize FROM Win32_Volume WHERE DriveLetter='$drive'" -ErrorAction Stop).BlockSize
                if ($clusterSize) {
                    $clusterSizeKB = $clusterSize / 1KB
                    Write-Info "  Drive $($vol.DriveLetter): - Cluster Size: $($clusterSizeKB) KB"
                    if ($clusterSizeKB -ne 64) {
                        Write-DiagWarning "    Recommended cluster size for SQL/Database servers is 64KB"
                    }
                }
            }
            catch {
                Write-DiagWarning "  Could not retrieve cluster size for drive $($vol.DriveLetter)"
            }
        }
    }

    # Storage Disconnect Events (129, 153)
    Write-Section "Storage Error Events (last 7 days)"
    try {
        $storageEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 129, 153
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 20 -ErrorAction SilentlyContinue

        if ($storageEvents) {
            $grouped = $storageEvents | Group-Object Id
            foreach ($g in $grouped) {
                Write-DiagError "  Event $($g.Name): $($g.Count) occurrence(s) in last 7 days"
                $g.Group | Select-Object -First 2 | ForEach-Object {
                    Write-DiagWarning "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $_ -MaxLength 80)"
                }
            }
        }
        else {
            Write-Success "  No storage error events (129/153) found"
        }
    }
    catch {
        Write-Info "  Could not query storage events"
    }

    # Disk Queue Length
    Write-Section "Disk Queue Length"
    try {
        $queueLength = Get-Counter '\PhysicalDisk(*)\Current Disk Queue Length' -ErrorAction Stop
        foreach ($sample in $queueLength.CounterSamples) {
            if ($sample.InstanceName -ne "_total" -and $sample.CookedValue -gt 0) {
                Write-Info "  $($sample.InstanceName): Queue Length = $([math]::Round($sample.CookedValue, 1))"
                if ($sample.CookedValue -gt $DISK_QUEUE_WARNING_THRESHOLD) {
                    Write-DiagWarning "    WARNING: Queue length >$($DISK_QUEUE_WARNING_THRESHOLD) - I/O bottleneck on this disk"
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk queue length"
    }

    # Write Latency (supplement to existing read latency)
    Write-Section "Disk Write Latency"
    try {
        $writeLatency = Get-Counter '\PhysicalDisk(*)\Avg. Disk sec/Write' -ErrorAction Stop
        foreach ($sample in $writeLatency.CounterSamples) {
            if ($sample.InstanceName -ne "_total") {
                $latencyMs = [math]::Round($sample.CookedValue * 1000, 2)
                Write-Info "  Write Latency - $($sample.InstanceName): $latencyMs ms"
                if ($latencyMs -gt $DISK_LATENCY_CRITICAL_MS) {
                    Write-DiagError "    CRITICAL: Write latency >$($DISK_LATENCY_CRITICAL_MS)ms"
                }
                elseif ($latencyMs -gt $DISK_LATENCY_WARNING_MS) {
                    Write-DiagWarning "    WARNING: Write latency elevated"
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check write latency"
    }

    # NTFS Metadata / Corruption Errors
    Write-Section "NTFS Errors (last 30 days)"
    try {
        $ntfsEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 55
            StartTime = (Get-Date).AddDays(-30)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($ntfsEvents) {
            Write-DiagError "  Found $($ntfsEvents.Count) NTFS corruption event(s)!"
            $ntfsEvents | Select-Object -First 3 | ForEach-Object {
                Write-DiagWarning "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $_ -MaxLength 100)"
            }
            Write-Info "  Run: chkdsk /R on affected volume"
        }
        else {
            Write-Success "  No NTFS errors detected"
        }
    }
    catch {
        Write-Info "  Could not query NTFS events"
    }

    # VM Pause-Critical Risk (>95% full) — reuses cached $cachedVolumes
    Write-Section "VM Pause-Critical Risk Check"
    if ($cachedVolumes) {
        foreach ($vol in ($cachedVolumes | Where-Object { $_.Size -gt 0 })) {
            $usedPercent = [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 1)
            if ($usedPercent -gt 95) {
                Write-DiagError "  Drive $($vol.DriveLetter): $usedPercent% full - VM MAY PAUSE if disk fills completely!"
            }
        }
    }

    #region v3.0 Disk Checks

    # 1. Disk IOPS (Read + Write)
    Write-Section "Disk IOPS"
    try {
        $readIOPS = Get-Counter '\PhysicalDisk(*)\Disk Reads/sec' -ErrorAction Stop
        $writeIOPS = Get-Counter '\PhysicalDisk(*)\Disk Writes/sec' -ErrorAction Stop
        foreach ($sample in $readIOPS.CounterSamples) {
            if ($sample.InstanceName -ne "_total" -and ($sample.CookedValue -gt 0)) {
                $wSample = $writeIOPS.CounterSamples | Where-Object { $_.InstanceName -eq $sample.InstanceName }
                $rIOPS = [math]::Round($sample.CookedValue, 0)
                $wIOPS = if ($wSample) { [math]::Round($wSample.CookedValue, 0) } else { 0 }
                $totalIOPS = $rIOPS + $wIOPS
                Write-Info "  $($sample.InstanceName): Read=$rIOPS Write=$wIOPS Total=$totalIOPS IOPS"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk IOPS"
    }

    # 2. Disk Throughput (MB/sec)
    Write-Section "Disk Throughput"
    try {
        $readTP = Get-Counter '\PhysicalDisk(*)\Disk Read Bytes/sec' -ErrorAction Stop
        $writeTP = Get-Counter '\PhysicalDisk(*)\Disk Write Bytes/sec' -ErrorAction Stop
        foreach ($sample in $readTP.CounterSamples) {
            if ($sample.InstanceName -ne "_total" -and ($sample.CookedValue -gt 0 -or ($writeTP.CounterSamples | Where-Object { $_.InstanceName -eq $sample.InstanceName }).CookedValue -gt 0)) {
                $wSample = $writeTP.CounterSamples | Where-Object { $_.InstanceName -eq $sample.InstanceName }
                $rMBs = [math]::Round($sample.CookedValue / 1MB, 2)
                $wMBs = if ($wSample) { [math]::Round($wSample.CookedValue / 1MB, 2) } else { 0 }
                Write-Info "  $($sample.InstanceName): Read=${rMBs} MB/s Write=${wMBs} MB/s"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk throughput"
    }

    # 3. Storage Media Type (SSD vs HDD)
    Write-Section "Storage Media Type"
    try {
        $physDisks = Get-PhysicalDisk -ErrorAction Stop
        foreach ($pd in $physDisks) {
            $mediaType = if ($pd.MediaType) { $pd.MediaType } else { "Unknown" }
            $busType = if ($pd.BusType) { $pd.BusType } else { "Unknown" }
            $sizeGB = [math]::Round($pd.Size / 1GB, 1)
            Write-Info "  $($pd.FriendlyName): $mediaType ($busType) - ${sizeGB}GB"
            if ($mediaType -eq "HDD") {
                Write-DiagWarning "    HDD detected — expect higher latency than SSD; critical for SQL/database workloads"
            }
            if ($mediaType -eq "Unspecified" -and $busType -like "*iSCSI*") {
                Write-Info "    iSCSI LUN — media type depends on SAN backend"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not determine storage media types"
    }

    # 4. SMART / Predictive Failure Detection
    Write-Section "Disk Health & Predictive Failure"
    try {
        $physDisks = Get-PhysicalDisk -ErrorAction Stop
        foreach ($pd in $physDisks) {
            $health = $pd.HealthStatus
            $opStatus = $pd.OperationalStatus
            if ($health -ne "Healthy" -or $opStatus -ne "OK") {
                Write-DiagError "  $($pd.FriendlyName): Health=$health OpStatus=$opStatus"
                if ($health -like "*Predict*" -or $health -like "*Warning*") {
                    Write-DiagError "    PREDICTIVE FAILURE — replace this disk immediately!"
                }
            }
            else {
                Write-Success "  $($pd.FriendlyName): Health=$health OpStatus=$opStatus"
            }
        }
        # Also check via WMI for SMART status
        $smartDisks = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue
        if ($smartDisks) {
            foreach ($sd in $smartDisks) {
                if ($sd.PredictFailure) {
                    Write-DiagError "  SMART Predictive Failure on InstanceName: $($sd.InstanceName)"
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk health: $($_.Exception.Message)"
    }

    # 5. Volume Shadow Copy (VSS) Snapshot Space
    Write-Section "VSS Shadow Copy Usage"
    try {
        $shadows = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
        if ($shadows) {
            $shadowsByVolume = $shadows | Group-Object VolumeName
            foreach ($group in $shadowsByVolume) {
                $count = $group.Count
                $totalSizeMB = [math]::Round(($group.Group | Measure-Object -Property MaxSize -Sum).Sum / 1MB, 0)
                $oldestDate = ($group.Group | Sort-Object InstallDate | Select-Object -First 1).InstallDate
                Write-Info "  Volume $($group.Name): $count snapshot(s)"
                if ($count -gt 10) {
                    Write-DiagWarning "    $count VSS snapshots — orphaned snapshots consuming hidden disk space"
                    Write-Info "    Clean up: vssadmin delete shadows /for=$($group.Name) /oldest"
                }
            }
            Write-Info "  Total VSS snapshots: $($shadows.Count)"
        }
        else {
            Write-Info "  No VSS shadow copies found"
        }
    }
    catch {
        Write-DiagWarning "  Could not check VSS snapshots"
    }

    # Check VSS writers health
    try {
        $vssWriters = vssadmin list writers 2>&1
        $failedWriters = $vssWriters | Select-String 'State:.*Failed|State:.*Not responding|State:.*Waiting for completion' -ErrorAction SilentlyContinue
        if ($failedWriters) {
            Write-DiagWarning "  VSS Writer issues detected:"
            foreach ($fw in $failedWriters) {
                Write-DiagWarning "    $($fw.Line.Trim())"
            }
        }
        else {
            Write-Success "  All VSS writers are stable"
        }
    }
    catch { }

    # 6. Storage Spaces / Pool Health
    Write-Section "Storage Spaces & Pool Health"
    try {
        $pools = Get-StoragePool -ErrorAction SilentlyContinue | Where-Object { $_.IsPrimordial -eq $false }
        if ($pools) {
            foreach ($pool in $pools) {
                $health = $pool.HealthStatus
                $opStatus = $pool.OperationalStatus
                $sizeGB = [math]::Round($pool.Size / 1GB, 1)
                $allocGB = [math]::Round($pool.AllocatedSize / 1GB, 1)
                Write-Info "  Pool '$($pool.FriendlyName)': $allocGB/$sizeGB GB allocated"
                if ($health -ne "Healthy") {
                    Write-DiagError "    Pool Health: $health ($opStatus)"
                    # Check for degraded virtual disks
                    $vDisks = Get-VirtualDisk -StoragePool $pool -ErrorAction SilentlyContinue
                    foreach ($vd in $vDisks) {
                        if ($vd.HealthStatus -ne "Healthy" -or $vd.OperationalStatus -ne "OK") {
                            Write-DiagError "    VDisk '$($vd.FriendlyName)': $($vd.HealthStatus) / $($vd.OperationalStatus)"
                            if ($vd.OperationalStatus -like "*Degraded*") {
                                Write-DiagError "      DEGRADED — rebuild in progress or missing disk!"
                            }
                        }
                    }
                }
                else {
                    Write-Success "    Pool Health: Healthy"
                }
            }
        }
        else {
            Write-Info "  No Storage Spaces pools configured"
        }
    }
    catch {
        Write-Info "  Storage Spaces not available or not configured"
    }

    # 7. Disk Fragmentation Level
    Write-Section "Disk Fragmentation"
    if ($cachedVolumes) {
        foreach ($vol in ($cachedVolumes | Where-Object { $_.DriveLetter -and $_.Size -gt 0 })) {
            try {
                $defragInfo = Optimize-Volume -DriveLetter $vol.DriveLetter -Analyze -Verbose 4>&1 -ErrorAction Stop
                $fragLine = $defragInfo | Select-String 'fragmented|Current' -ErrorAction SilentlyContinue
                if ($fragLine) {
                    Write-Info "  Drive $($vol.DriveLetter): $($fragLine.Line.Trim())"
                }
                else {
                    Write-Info "  Drive $($vol.DriveLetter): Analysis completed (check verbose output for details)"
                }
            }
            catch {
                # Optimize-Volume may fail on system volumes or SSDs (TRIM instead)
                Write-Info "  Drive $($vol.DriveLetter): Cannot analyze (SSD uses TRIM, or volume is in use)"
            }
        }
    }

    # 8. Pagefile Disk Placement
    Write-Section "Pagefile Disk Placement"
    try {
        $pageFiles = Get-CimInstance Win32_PageFileUsage -ErrorAction Stop
        if ($pageFiles) {
            foreach ($pf in $pageFiles) {
                $pfDrive = $pf.Name.Substring(0, 2)
                Write-Info "  Page file: $($pf.Name) ($($pf.AllocatedBaseSize) MB)"
                # Check if pagefile is on the OS drive
                $osDrive = $env:SystemDrive
                if ($pfDrive -eq $osDrive) {
                    Write-DiagWarning "    Page file is on the OS drive ($osDrive) — may cause I/O contention"
                    Write-Info "    For high-performance servers, place page file on a separate disk"
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check pagefile placement"
    }

    # 9. Temp/TempDB Disk Check
    Write-Section "TEMP & SQL TempDB Location"
    try {
        $tempPath = $env:TEMP
        $tempDrive = $tempPath.Substring(0, 2)
        $osDrive = $env:SystemDrive
        Write-Info "  Windows TEMP: $tempPath (Drive: $tempDrive)"
        if ($tempDrive -eq $osDrive) {
            Write-Info "    TEMP is on OS drive — normal for most servers"
        }

        # Check SQL TempDB if SQL is running
        if ($script:ClusterEnv.IsAGInstalled -or (Get-Service -Name "MSSQLSERVER" -ErrorAction SilentlyContinue)) {
            try {
                $conn = New-Object System.Data.SqlClient.SqlConnection "Server=.;Integrated Security=True;Connection Timeout=5"
                $conn.Open()
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = "SELECT physical_name FROM sys.master_files WHERE database_id = DB_ID('tempdb')"
                $reader = $cmd.ExecuteReader()
                while ($reader.Read()) {
                    $tempDbPath = $reader["physical_name"]
                    $tempDbDrive = $tempDbPath.Substring(0, 2)
                    Write-Info "  SQL TempDB: $tempDbPath"
                    if ($tempDbDrive -eq $osDrive) {
                        Write-DiagWarning "    TempDB on OS drive ($osDrive) — move to a dedicated fast disk for production"
                    }
                }
                $reader.Close()
                $conn.Close()
            }
            catch {
                Write-Info "  Could not query SQL TempDB location"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check TEMP locations"
    }

    # 10. Filter Driver Stack (fltmc)
    Write-Section "File System Filter Drivers"
    try {
        $fltmcOutput = fltmc 2>&1
        $filterLines = $fltmcOutput | Select-String '^\s*\d+' -ErrorAction SilentlyContinue
        if ($filterLines) {
            $filterCount = $filterLines.Count
            Write-Info "  Active filter drivers: $filterCount"
            foreach ($fl in $filterLines | Select-Object -First 15) {
                $line = $fl.Line.Trim()
                # Flag known high-impact AV filters
                if ($line -match 'WdFilter|csagent|SentinelMonitor|SymEFA|savonaccess|CbFilter|epfw|tmPreFilter') {
                    Write-DiagWarning "    $line  [AV/Security filter — impacts I/O latency]"
                }
                else {
                    Write-Info "    $line"
                }
            }
            if ($filterCount -gt 15) {
                Write-Info "    ... and $($filterCount - 15) more"
            }
            if ($filterCount -gt 10) {
                Write-DiagWarning "  $filterCount filter drivers is HIGH — each adds latency to every I/O operation"
            }
        }
        else {
            Write-Info "  No filter drivers detected (or fltmc not available)"
        }
    }
    catch {
        Write-DiagWarning "  Could not enumerate filter drivers"
    }

    # Check filter instances
    try {
        $fltmcInst = fltmc instances 2>&1
        $instanceCount = ($fltmcInst | Select-String '^\s*\S+' | Where-Object { $_.Line -notmatch 'Filter|Instance|---' }).Count
        if ($instanceCount -gt 0) {
            Write-Info "  Filter instances attached to volumes: $instanceCount"
        }
    }
    catch { }

    # 11. Disk Timeout & Retry Settings
    Write-Section "Disk Timeout Configuration"
    try {
        $diskTimeout = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Disk' -Name 'TimeOutValue' -ErrorAction SilentlyContinue
        $timeoutValue = if ($diskTimeout -and $diskTimeout.TimeOutValue) { $diskTimeout.TimeOutValue } else { 60 }
        Write-Info "  Disk I/O Timeout: $timeoutValue seconds"
        if ($timeoutValue -eq 60) {
            Write-Info "    Default value (60s) — appropriate for most configurations"
        }
        elseif ($timeoutValue -lt 30) {
            Write-DiagWarning "    LOW timeout (${timeoutValue}s) — may cause premature I/O failures on slow SAN paths"
        }
        elseif ($timeoutValue -gt 120) {
            Write-DiagWarning "    HIGH timeout (${timeoutValue}s) — I/O hangs will take very long to surface as errors"
        }

        # Check SAN-specific timeout for iSCSI
        $iscsiTimeout = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}\0000' -Name 'LinkDownTime' -ErrorAction SilentlyContinue
        if ($iscsiTimeout -and $iscsiTimeout.LinkDownTime) {
            Write-Info "  iSCSI Link Down Time: $($iscsiTimeout.LinkDownTime) seconds"
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk timeout settings"
    }

    # 12. MPIO (Multipath I/O) Status
    Write-Section "MPIO (Multipath I/O)"
    try {
        $mpioFeature = Get-WindowsFeature -Name Multipath-IO -ErrorAction SilentlyContinue
        if ($mpioFeature -and $mpioFeature.Installed) {
            Write-Success "  MPIO feature is installed"
            try {
                $mpioDevices = Get-MSDSMSupportedHW -ErrorAction SilentlyContinue
                if ($mpioDevices) {
                    Write-Info "  Supported MPIO hardware entries: $(@($mpioDevices).Count)"
                }
            }
            catch { }

            # Check MPIO paths
            try {
                $mpioDisks = mpclaim -s -d 2>&1
                $pathLines = $mpioDisks | Select-String 'MPIO Disk' -ErrorAction SilentlyContinue
                if ($pathLines) {
                    Write-Info "  MPIO disks detected: $($pathLines.Count)"
                    # Look for degraded paths
                    $degradedPaths = $mpioDisks | Select-String 'Failed|Standby' -ErrorAction SilentlyContinue
                    if ($degradedPaths) {
                        Write-DiagWarning "  DEGRADED MPIO paths detected:"
                        foreach ($dp in $degradedPaths | Select-Object -First 5) {
                            Write-DiagWarning "    $($dp.Line.Trim())"
                        }
                    }
                    else {
                        Write-Success "  All MPIO paths are active"
                    }
                }
            }
            catch {
                Write-Info "  Could not query MPIO disk paths (mpclaim not available)"
            }
        }
        else {
            Write-Info "  MPIO feature not installed (not needed for local storage)"
        }
    }
    catch {
        Write-Info "  Could not check MPIO status (Get-WindowsFeature may not be available)"
    }

    # 13. ReFS vs NTFS Detection
    Write-Section "File System Type per Volume"
    if ($cachedVolumes) {
        foreach ($vol in ($cachedVolumes | Where-Object { $_.DriveLetter -and $_.Size -gt 0 })) {
            $fsType = $vol.FileSystemType
            $sizeGB = [math]::Round($vol.Size / 1GB, 1)
            Write-Info "  Drive $($vol.DriveLetter): $fsType (${sizeGB}GB)"
            if ($fsType -eq "ReFS") {
                Write-Info "    ReFS: Integrity streams, auto-repair. Optimal for Hyper-V, Veeam, Storage Spaces Direct"
                Write-Info "    Note: ReFS does not support file-level compression or encryption"
            }
        }
    }

    # 14. Disk Busy Time %
    Write-Section "Disk Busy Time"
    try {
        $diskTime = Get-Counter '\PhysicalDisk(*)\% Disk Time' -ErrorAction Stop
        foreach ($sample in $diskTime.CounterSamples) {
            if ($sample.InstanceName -ne "_total") {
                $busyPercent = [math]::Round($sample.CookedValue, 1)
                # % Disk Time can exceed 100% on multi-spindle arrays; cap display
                $displayPercent = [math]::Min($busyPercent, 100)
                if ($busyPercent -gt 80) {
                    Write-DiagWarning "  $($sample.InstanceName): $displayPercent% busy — disk is the bottleneck"
                }
                elseif ($busyPercent -gt 50) {
                    Write-Info "  $($sample.InstanceName): $displayPercent% busy (moderate load)"
                }
                elseif ($busyPercent -gt 0) {
                    Write-Info "  $($sample.InstanceName): $displayPercent% busy"
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk busy time"
    }

    # 15. Storage Tiering Status (Storage Spaces Direct / Tiered Volumes)
    Write-Section "Storage Tiering"
    try {
        $tiers = Get-StorageTier -ErrorAction SilentlyContinue
        if ($tiers) {
            Write-Info "  Storage tiers configured:"
            foreach ($tier in $tiers) {
                $tierSizeGB = [math]::Round($tier.Size / 1GB, 1)
                $mediaType = $tier.MediaType
                Write-Info "    $($tier.FriendlyName): $mediaType - ${tierSizeGB}GB"
            }

            # Check tier optimization schedule
            try {
                $tierTask = Get-ScheduledTask -TaskName "Storage Tiers Optimization" -ErrorAction SilentlyContinue
                if ($tierTask) {
                    Write-Info "  Tiering optimization task: $($tierTask.State)"
                    if ($tierTask.State -ne 'Ready' -and $tierTask.State -ne 'Running') {
                        Write-DiagWarning "    Tiering task is $($tierTask.State) — hot data may not be promoted to SSD tier"
                    }
                }
            }
            catch { }
        }
        else {
            Write-Info "  No storage tiers configured (standard non-tiered storage)"
        }
    }
    catch {
        Write-Info "  Storage tiering not available"
    }

    #endregion v3.0 Disk Checks
}

function Start-DiskLogCollection {
    <#
    .SYNOPSIS
        Starts disk/storage issue log collection
    .DESCRIPTION
        Provides options for StorPort trace and performance monitoring
    #>
    Write-Header "Disk/Storage Issue Log Collection"
    
    Write-Info "Disk/Storage Log Collection Options:"
    Write-Host "1. StorPort trace (10-15 minutes)" -ForegroundColor Yellow
    Write-Host "2. StorPort + Performance Monitor (comprehensive)" -ForegroundColor Yellow
    Write-Host "3. Manual StorPort trace commands" -ForegroundColor Yellow
    Write-Host "4. Long-term Performance Monitor only" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-4)" -ValidChoices @("1", "2", "3", "4")
    
    switch ($choice) {
        "1" {
            Invoke-WithTSSCheck `
                -TSSCommand "-StartNowait -PerfMon General -PerfIntervalSec 1 -SHA_Storport" `
                -ManualAlternativeAction { Show-StorPortCommands } `
                -Description "Starting StorPort trace for 10-15 minutes... Trace started. Let it run for 10-15 minutes, then stop with: TSS.ps1 -Stop"
        }
        "2" {
            Invoke-WithTSSCheck `
                -TSSCommand "-StartNowait -PerfMon General -PerfIntervalSec 1 -SHA_Storport -noSDP" `
                -ManualAlternativeAction { Show-StorPortCommands } `
                -Description "Starting comprehensive StorPort + Perfmon trace... Run for 10-15 minutes, then stop with: TSS.ps1 -Stop"
        }
        "3" {
            Show-StorPortCommands
        }
        "4" {
            Show-PerfmonCommand "Disk"
        }
    }
    
    Write-Info "`nDisk Performance Best Practices:"
    Write-Info "  1. Ensure disks have 64KB cluster size (especially for SQL)"
    Write-Info "  2. Use PVSCSI instead of LSI SAS (for VMs)"
    Write-Info "  3. Ensure antivirus exclusions are in place"
    Write-Info "  4. Perform regular database purging and maintenance"
    Write-Info "  5. Place database files and transaction logs on separate disks"
    Write-Info "  6. Consider using SSDs for better I/O performance"
    Write-Info "`nLatency Guidelines:"
    Write-Info "  * <$($DISK_LATENCY_ACCEPTABLE_MS)ms: Very good"
    Write-Info "  * $($DISK_LATENCY_ACCEPTABLE_MS)-$($DISK_LATENCY_WARNING_MS)ms: Okay"
    Write-Info "  * $($DISK_LATENCY_WARNING_MS)-$($DISK_LATENCY_CRITICAL_MS)ms: Slow, needs attention"
    Write-Info "  * >$($DISK_LATENCY_CRITICAL_MS)ms: Serious I/O bottleneck"
}

function Show-StorPortCommands {
    <#
    .SYNOPSIS
        Displays manual StorPort trace commands
    #>
    Write-Info "`nManual StorPort Trace Commands:"
    Write-Host @"

START STORPORT TRACE:
logman create trace "storport" -ow -o c:\perflogs\storport.etl -p "Microsoft-Windows-StorPort" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

STOP STORPORT TRACE:
logman stop "storport" -ets

ALSO RUN PERFMON (see option 4 for perfmon commands)

FILTER DRIVER CHECK:
fltmc
fltmc instances

"@ -ForegroundColor Cyan
}

function Show-PerfmonCommand {
    <#
    .SYNOPSIS
        Displays performance monitor collection commands
    .PARAMETER Scenario
        The monitoring scenario (Memory, CPU, Disk, Assessment)
    #>
    param([string]$Scenario)
    
    Write-Info "`nLong-term Performance Monitor Collection:"
    Write-Host @"

For $($Scenario) monitoring, collect perfmon for 2-4 hours:

CREATE PERFMON:
Logman.exe create counter PerfLog-$($env:COMPUTERNAME) -o "$($script:DefaultLogPath)\$($env:COMPUTERNAME)_PerfLog-short.blg" -f bincirc -v mmddhhmm -max 500 -c "\LogicalDisk(*)\*" "\Memory\*" "\Cache\*" "\Network Interface(*)\*" "\Paging File(*)\*" "\PhysicalDisk(*)\*" "\Processor(*)\*" "\Processor Information(*)\*" "\Process(*)\*" "\Redirector\*" "\Server\*" "\System\*" "\Server Work Queues(*)\*" "\Terminal Services\*" -si 00:00:05

START COLLECTION:
logman start PerfLog-$($env:COMPUTERNAME)

STOP COLLECTION:
logman stop PerfLog-$($env:COMPUTERNAME)

INTERVAL GUIDANCE:
  * 24 hours: -si 00:01:16 (1 min 16 sec)
  * 4 hours: -si 00:00:14 (14 seconds)
  * 2 hours: -si 00:00:07 (7 seconds)

You can also use -b MM/DD/YYYY HH:MM:SS AM/PM for begin time
and -e MM/DD/YYYY HH:MM:SS AM/PM for end time

"@ -ForegroundColor Cyan
}
#endregion
