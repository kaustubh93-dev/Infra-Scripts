# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Memory Diagnostics
# Source lines: 1977 - 2613
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Memory Diagnostics
function Test-MemoryUsage {
    <#
    .SYNOPSIS
        Analyzes system memory usage
    .DESCRIPTION
        Checks total memory, usage percentage, top consumers, committed bytes,
        NonPaged/Paged pool, page file, compression, handles/threads, standby cache,
        RAM hardware, resource exhaustion events, WS trimming, and leak detection
    .EXAMPLE
        Test-MemoryUsage
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "Memory Usage Analysis"
    
    try {
        # Get system memory info
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        # TotalVisibleMemorySize and FreePhysicalMemory are in KB;
        # dividing by 1MB (1,048,576) converts KB to GB
        $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeMemGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedMemGB = $totalMemGB - $freeMemGB
        $memUsagePercent = [math]::Round(($usedMemGB / $totalMemGB) * 100, 2)
        
        Write-Info "Total Memory: $($totalMemGB) GB"
        Write-Info "Used Memory: $($usedMemGB) GB"
        Write-Info "Free Memory: $($freeMemGB) GB"
        Write-Info "Memory Usage: $($memUsagePercent)%"
        
        if ($memUsagePercent -gt $MEMORY_CRITICAL_THRESHOLD) {
            Write-DiagError "CRITICAL: Memory usage above $($MEMORY_CRITICAL_THRESHOLD)%!"
        }
        elseif ($memUsagePercent -gt $MEMORY_WARNING_THRESHOLD) {
            Write-DiagWarning "WARNING: Memory usage above $($MEMORY_WARNING_THRESHOLD)%"
        }
        else {
            Write-Success "Memory usage is within normal range"
        }
    }
    catch {
        Write-DiagError "Failed to retrieve memory information: $($_.Exception.Message)"
        return
    }
    
    # Top memory consuming processes
    Write-Section "Top 10 Memory Consuming Processes"
    # Fetch fresh process data and cache for potential reuse by CPU diagnostics
    $script:LastProcessAnalysis = Get-ProcessAnalysis
    $script:LastProcessAnalysisTime = Get-Date
    $processAnalysis = $script:LastProcessAnalysis
    
    if ($processAnalysis) {
        $processAnalysis.ByMemory | Format-Table Name, 
        @{Label = "Memory(MB)"; Expression = { [math]::Round($_.WS / 1MB, 2) } },
        @{Label = "CPU(s)"; Expression = { [math]::Round($_.CPU, 2) } },
        Id -AutoSize
    }
    
    Write-Section "Committed Memory"
    try {
        $perfCounter = Get-Counter '\Memory\% Committed Bytes In Use' -ErrorAction Stop
        if ($perfCounter) {
            $committedPercent = [math]::Round($perfCounter.CounterSamples.CookedValue, 2)
            Write-Info "`nCommitted Bytes In Use: $($committedPercent)%"
            if ($committedPercent -gt $MEMORY_CRITICAL_THRESHOLD) {
                Write-DiagError "CRITICAL: Committed bytes above $($MEMORY_CRITICAL_THRESHOLD)%!"
            }
        }
    }
    catch {
        Write-DiagWarning "Could not retrieve committed bytes information: $($_.Exception.Message)"
    }

    # NonPagedPool Usage
    Write-Section "Kernel Memory Pools"
    Write-Info "NonPaged Pool:"
    try {
        $npPool = Get-Counter '\Memory\Pool Nonpaged Bytes' -ErrorAction Stop
        $npMB = [math]::Round($npPool.CounterSamples.CookedValue / 1MB, 2)
        Write-Info "  NonPaged Pool: $npMB MB"
        if ($npMB -gt $NONPAGED_POOL_CRITICAL_MB) {
            Write-DiagError "  CRITICAL: NonPaged Pool >$($NONPAGED_POOL_CRITICAL_MB)MB - possible ETW buffer or driver leak"
        }
        elseif ($npMB -gt $NONPAGED_POOL_WARNING_MB) {
            Write-DiagWarning "  WARNING: NonPaged Pool elevated (>$($NONPAGED_POOL_WARNING_MB)MB)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check NonPaged Pool"
    }

    # Modified Page List (file cache pressure)
    Write-Section "File Cache & Paging"
    Write-Info "Modified Page List:"
    try {
        $modPages = Get-Counter '\Memory\Modified Page List Bytes' -ErrorAction Stop
        $modGB = [math]::Round($modPages.CounterSamples.CookedValue / 1GB, 2)
        Write-Info "  Modified Page List: $modGB GB"
        if ($modGB -gt $MODIFIED_PAGE_LIST_WARNING_GB) {
            Write-DiagWarning "  WARNING: Large modified page list ($modGB GB) - file cache consuming RAM"
            Write-Info "  Consider: Disable 'Large System Cache' or tune MaxCacheSizeInMB"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Modified Page List"
    }

    # Paging Spikes
    Write-Info "`nPaging Activity:"
    try {
        $pagesPerSec = Get-Counter '\Memory\Pages/sec' -ErrorAction Stop
        $pps = [math]::Round($pagesPerSec.CounterSamples.CookedValue, 0)
        Write-Info "  Pages/sec: $pps"
        if ($pps -gt $PAGING_CRITICAL_THRESHOLD) {
            Write-DiagError "  CRITICAL: High paging activity (>$($PAGING_CRITICAL_THRESHOLD) pages/sec) - severe memory pressure"
        }
        elseif ($pps -gt $PAGING_WARNING_THRESHOLD) {
            Write-DiagWarning "  WARNING: Elevated paging activity (>$($PAGING_WARNING_THRESHOLD) pages/sec)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check paging activity"
    }

    # Known Leaky Process Detection
    Write-Section "Known Memory-Intensive Processes"
    $leakSuspects = @("java", "BMCMainEngine", "MonitoringHost", "WinCollect", "sqlservr")
    try {
        foreach ($suspect in $leakSuspects) {
            $procs = Get-Process -Name $suspect -ErrorAction SilentlyContinue
            if ($procs) {
                foreach ($p in $procs) {
                    $wsMB = [math]::Round($p.WorkingSet64 / 1MB, 0)
                    if ($wsMB -gt 1024) {
                        Write-DiagWarning "  $($p.Name) (PID $($p.Id)): $wsMB MB - high memory consumer"
                    }
                    else {
                        Write-Info "  $($p.Name) (PID $($p.Id)): $wsMB MB"
                    }
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check known processes"
    }

    #region v3.0 Memory Checks

    # 1. Page File Configuration & Usage
    Write-Section "Page File Configuration & Usage"
    try {
        $pageFiles = Get-CimInstance Win32_PageFileUsage -ErrorAction Stop
        if ($pageFiles) {
            foreach ($pf in $pageFiles) {
                $usedMB = $pf.CurrentUsage
                $totalMB = $pf.AllocatedBaseSize
                $peakMB = $pf.PeakUsage
                $usedPercent = if ($totalMB -gt 0) { [math]::Round(($usedMB / $totalMB) * 100, 1) } else { 0 }
                Write-Info "  $($pf.Name):"
                Write-Info "    Size: $totalMB MB | Used: $usedMB MB ($usedPercent%) | Peak: $peakMB MB"
                if ($usedPercent -gt $PAGEFILE_USAGE_CRITICAL_PERCENT) {
                    Write-DiagError "    CRITICAL: Page file is >$($PAGEFILE_USAGE_CRITICAL_PERCENT)% full!"
                }
                elseif ($usedPercent -gt $PAGEFILE_USAGE_WARNING_PERCENT) {
                    Write-DiagWarning "    WARNING: Page file usage above $($PAGEFILE_USAGE_WARNING_PERCENT)%"
                }
            }
        }
        else {
            Write-DiagWarning "  No page files found (system may crash under memory pressure!)"
        }

        # Check page file settings (system managed vs fixed)
        $pfSettings = Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue
        if ($pfSettings) {
            foreach ($pfs in $pfSettings) {
                if ($pfs.InitialSize -eq 0 -and $pfs.MaximumSize -eq 0) {
                    Write-Success "    $($pfs.Name): System managed (recommended)"
                }
                else {
                    Write-Info "    $($pfs.Name): Fixed size (Initial: $($pfs.InitialSize) MB, Max: $($pfs.MaximumSize) MB)"
                    if ($pfs.MaximumSize -lt 4096) {
                        Write-DiagWarning "    Page file max is under 4 GB - may be insufficient for memory dumps"
                    }
                }
            }
        }
        else {
            # Win32_PageFileSetting is empty when page file is system-managed (most common config)
            Write-Success "  Page file is system-managed (Win32_PageFileSetting empty — normal behavior)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check page file configuration: $($_.Exception.Message)"
    }

    # 2. Available MBytes (more accurate than free memory)
    Write-Section "Available Memory (includes reclaimable cache)"
    try {
        $availMB = Get-Counter '\Memory\Available MBytes' -ErrorAction Stop
        $availVal = [math]::Round($availMB.CounterSamples.CookedValue, 0)
        Write-Info "  Available MBytes: $availVal MB ($([math]::Round($availVal / 1024, 2)) GB)"
        if ($availVal -lt $AVAILABLE_MB_CRITICAL) {
            Write-DiagError "  CRITICAL: Available memory below $($AVAILABLE_MB_CRITICAL) MB!"
        }
        elseif ($availVal -lt $AVAILABLE_MB_WARNING) {
            Write-DiagWarning "  WARNING: Available memory below $($AVAILABLE_MB_WARNING) MB"
        }
        else {
            Write-Success "  Available memory is adequate"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Available MBytes"
    }

    # 3. Memory Compression Ratio
    Write-Section "Memory Compression"
    try {
        $compressProc = Get-Process -Name "Memory Compression" -ErrorAction SilentlyContinue
        if ($compressProc) {
            $compressWS = [math]::Round($compressProc.WorkingSet64 / 1MB, 0)
            Write-Info "  Memory Compression process WS: $compressWS MB"
            try {
                $compressedBytes = Get-Counter '\Memory\Compression Store Size' -ErrorAction Stop
                $compressedMB = [math]::Round($compressedBytes.CounterSamples.CookedValue / 1MB, 0)
                if ($compressWS -gt 0 -and $compressedMB -gt 0) {
                    $ratio = [math]::Round($compressedMB / $compressWS, 2)
                    Write-Info "  Compressed Store: $compressedMB MB | Compression Ratio: ${ratio}:1"
                    if ($compressWS -gt 2048) {
                        Write-DiagWarning "  WARNING: Over 2 GB of compressed memory - system is under significant memory pressure"
                    }
                }
            }
            catch {
                Write-Info "  Compression Store counter not available (Windows 10/2016+)"
            }
        }
        else {
            Write-Info "  Memory Compression process not active"
        }
    }
    catch {
        Write-DiagWarning "  Could not check memory compression"
    }

    # 4. Handle & Thread Count per Process
    Write-Section "Handle & Thread Analysis"
    Write-Info "Top Processes by Handle Count:"
    try {
        $handleProcs = Get-Process -ErrorAction Stop |
            Sort-Object HandleCount -Descending |
            Select-Object -First 10
        foreach ($hp in $handleProcs) {
            $handles = $hp.HandleCount
            $threads = $hp.Threads.Count
            $indicator = ""
            if ($handles -gt $HANDLE_LEAK_WARNING) { $indicator = " [POTENTIAL HANDLE LEAK]" }
            Write-Info "  $($hp.Name) (PID $($hp.Id)): Handles=$handles Threads=$threads$indicator"
        }

        $totalHandles = (Get-Process -ErrorAction Stop | Measure-Object HandleCount -Sum).Sum
        Write-Info "  System Total Handles: $totalHandles"
    }
    catch {
        Write-DiagWarning "  Could not check handle counts"
    }

    Write-Info "`nTop Processes by Thread Count:"
    try {
        $threadProcs = Get-Process -ErrorAction Stop |
            Sort-Object { $_.Threads.Count } -Descending |
            Select-Object -First 5
        foreach ($tp in $threadProcs) {
            $threads = $tp.Threads.Count
            $indicator = ""
            if ($threads -gt $THREAD_LEAK_WARNING) { $indicator = " [HIGH THREAD COUNT]" }
            Write-Info "  $($tp.Name) (PID $($tp.Id)): Threads=$threads$indicator"
        }
    }
    catch {
        Write-DiagWarning "  Could not check thread counts"
    }

    # 5. Paged Pool Usage
    Write-Section "Paged Pool Usage"
    try {
        $pagedPool = Get-Counter '\Memory\Pool Paged Bytes' -ErrorAction Stop
        $ppMB = [math]::Round($pagedPool.CounterSamples.CookedValue / 1MB, 2)
        Write-Info "  Paged Pool: $ppMB MB"
        if ($ppMB -gt $PAGED_POOL_CRITICAL_MB) {
            Write-DiagError "  CRITICAL: Paged Pool >$($PAGED_POOL_CRITICAL_MB)MB - risk of SESSION_POOL_EMPTY bugcheck"
        }
        elseif ($ppMB -gt $PAGED_POOL_WARNING_MB) {
            Write-DiagWarning "  WARNING: Paged Pool elevated (>$($PAGED_POOL_WARNING_MB)MB)"
        }
        else {
            Write-Success "  Paged Pool is within normal range"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Paged Pool"
    }

    # 6. System Cache Working Set
    Write-Section "System Cache Working Set"
    try {
        $cacheBytes = Get-Counter '\Memory\Cache Bytes' -ErrorAction Stop
        $cacheMB = [math]::Round($cacheBytes.CounterSamples.CookedValue / 1MB, 0)
        $cacheGB = [math]::Round($cacheBytes.CounterSamples.CookedValue / 1GB, 2)
        Write-Info "  System Cache: $cacheMB MB ($cacheGB GB)"
        if ($cacheGB -gt 4) {
            Write-DiagWarning "  WARNING: Large system cache ($cacheGB GB) - may be starving user processes"
            Write-Info "  On file servers, consider tuning LargeSystemCache registry key"
        }
    }
    catch {
        Write-DiagWarning "  Could not check system cache"
    }

    # 7. Memory Leak Trend Detection (Private Bytes vs Working Set)
    Write-Section "Memory Leak Indicators (Private Bytes vs Working Set)"
    try {
        $topProcesses = Get-Process -ErrorAction Stop |
            Where-Object { $_.WorkingSet64 -gt 100MB } |
            Sort-Object WorkingSet64 -Descending |
            Select-Object -First 10
        foreach ($proc in $topProcesses) {
            $wsMB = [math]::Round($proc.WorkingSet64 / 1MB, 0)
            $privateMB = [math]::Round($proc.PrivateMemorySize64 / 1MB, 0)
            $virtualMB = [math]::Round($proc.VirtualMemorySize64 / 1MB, 0)
            $gap = $privateMB - $wsMB
            $indicator = ""
            if ($gap -gt 500) {
                $indicator = " [LEAK SUSPECT: private >> WS by ${gap}MB]"
            }
            Write-Info "  $($proc.Name) (PID $($proc.Id)): WS=${wsMB}MB Private=${privateMB}MB Virtual=${virtualMB}MB$indicator"
        }
    }
    catch {
        Write-DiagWarning "  Could not perform leak trend analysis"
    }

    # 8. Standby List Breakdown
    Write-Section "Standby Cache Breakdown"
    try {
        $standbyCore = Get-Counter '\Memory\Standby Cache Core Bytes' -ErrorAction Stop
        $standbyNormal = Get-Counter '\Memory\Standby Cache Normal Priority Bytes' -ErrorAction Stop
        $standbyReserve = Get-Counter '\Memory\Standby Cache Reserve Bytes' -ErrorAction Stop

        $coreMB = [math]::Round($standbyCore.CounterSamples.CookedValue / 1MB, 0)
        $normalMB = [math]::Round($standbyNormal.CounterSamples.CookedValue / 1MB, 0)
        $reserveMB = [math]::Round($standbyReserve.CounterSamples.CookedValue / 1MB, 0)
        $totalStandby = $coreMB + $normalMB + $reserveMB

        Write-Info "  Total Standby: $totalStandby MB ($([math]::Round($totalStandby / 1024, 2)) GB)"
        Write-Info "    Core (high priority): $coreMB MB"
        Write-Info "    Normal priority: $normalMB MB"
        Write-Info "    Reserve (low priority, easily reclaimable): $reserveMB MB"

        if ($totalStandby -gt 0) {
            $reclaimablePercent = [math]::Round(($reserveMB / $totalStandby) * 100, 1)
            Write-Info "  Easily reclaimable: $reclaimablePercent% of standby cache"
            if ($reclaimablePercent -lt 20 -and $totalStandby -gt 2048) {
                Write-DiagWarning "  Low reclaimable standby cache - high-priority file cache is consuming standby memory"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve standby cache breakdown (requires Windows 8/2012+)"
    }

    # 9. RAM Hardware Information
    Write-Section "RAM Hardware Information"
    try {
        $memModules = Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop
        if ($memModules) {
            $totalSlots = (Get-CimInstance Win32_PhysicalMemoryArray -ErrorAction SilentlyContinue).MemoryDevices
            $usedSlots = @($memModules).Count
            Write-Info "  DIMM Slots: $usedSlots used$(if ($totalSlots) { " of $totalSlots total" })"

            $speeds = @()
            $types = @()
            foreach ($mod in $memModules) {
                $sizeMB = [math]::Round($mod.Capacity / 1MB, 0)
                $sizeGB = [math]::Round($mod.Capacity / 1GB, 1)
                $speed = $mod.Speed
                $manufacturer = if ($mod.Manufacturer) { $mod.Manufacturer.Trim() } else { "Unknown" }
                $partNumber = if ($mod.PartNumber) { $mod.PartNumber.Trim() } else { "" }
                $memType = switch ($mod.SMBIOSMemoryType) {
                    20 { "DDR" }
                    21 { "DDR2" }
                    24 { "DDR3" }
                    26 { "DDR4" }
                    34 { "DDR5" }
                    default { "Type $($mod.SMBIOSMemoryType)" }
                }
                $speeds += $speed
                $types += $memType

                Write-Info "  Slot $($mod.DeviceLocator): ${sizeGB}GB $memType @ ${speed}MHz ($manufacturer $partNumber)"
            }

            # Check for mismatched speeds
            $uniqueSpeeds = $speeds | Where-Object { $_ -gt 0 } | Select-Object -Unique
            if (@($uniqueSpeeds).Count -gt 1) {
                Write-DiagError "  MISMATCHED RAM speeds detected: $($uniqueSpeeds -join ', ') MHz"
                Write-Info "  All DIMMs will run at the slowest speed ($($uniqueSpeeds | Sort-Object | Select-Object -First 1) MHz)"
            }

            # Check for mixed types
            $uniqueTypes = $types | Select-Object -Unique
            if (@($uniqueTypes).Count -gt 1) {
                Write-DiagError "  MIXED RAM types detected: $($uniqueTypes -join ', ')"
            }

            # Upgrade suggestion
            if ($totalSlots -and $usedSlots -lt $totalSlots) {
                $emptySlots = $totalSlots - $usedSlots
                Write-Info "  $emptySlots empty DIMM slot(s) available for expansion"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve RAM hardware info: $($_.Exception.Message)"
    }

    # 10. Resource Exhaustion Events (2004)
    Write-Section "Resource Exhaustion Events (last 7 days)"
    try {
        $resExhaustEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 2004
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($resExhaustEvents) {
            Write-DiagError "  FOUND $($resExhaustEvents.Count) resource exhaustion event(s)!"
            foreach ($evt in $resExhaustEvents | Select-Object -First 5) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $evt -MaxLength 120)"
            }
            Write-Info "  Event 2004 = virtual memory exhaustion - increase page file or add RAM"
        }
        else {
            Write-Success "  No resource exhaustion events (Event 2004)"
        }

        # Also check for Event 333 (an LDR for memory low condition in older OS)
        $lowMemEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 333, 2003
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($lowMemEvents) {
            Write-DiagWarning "  Also found $($lowMemEvents.Count) low-memory condition event(s) (333/2003)"
        }
    }
    catch {
        Write-Info "  Could not query resource exhaustion events"
    }

    # 11. Working Set Trimming Rate
    Write-Section "Working Set Trimming Activity"
    try {
        $trimCounter = Get-Counter '\Memory\Transition Pages RePurposed/sec' -ErrorAction Stop
        $trimRate = [math]::Round($trimCounter.CounterSamples.CookedValue, 0)
        Write-Info "  Transition Pages Repurposed/sec: $trimRate"
        if ($trimRate -gt $WS_TRIM_WARNING_THRESHOLD) {
            Write-DiagWarning "  WARNING: High WS trimming rate (>$WS_TRIM_WARNING_THRESHOLD/sec) - OS is aggressively reclaiming memory"
        }

        $cacheFaults = Get-Counter '\Memory\Cache Faults/sec' -ErrorAction Stop
        $cacheFaultRate = [math]::Round($cacheFaults.CounterSamples.CookedValue, 0)
        Write-Info "  Cache Faults/sec: $cacheFaultRate"
        if ($cacheFaultRate -gt 5000) {
            Write-DiagWarning "  WARNING: High cache fault rate - system cache is being evicted frequently"
        }
    }
    catch {
        Write-DiagWarning "  Could not check working set trimming"
    }

    # 12. Per-Process Private Bytes vs Working Set (top suspects)
    Write-Section "Detailed Leak Analysis (Private >> Working Set)"
    try {
        $leakCandidates = Get-Process -ErrorAction Stop |
            Where-Object { $_.PrivateMemorySize64 -gt 200MB } |
            ForEach-Object {
                $wsMB = [math]::Round($_.WorkingSet64 / 1MB, 0)
                $privateMB = [math]::Round($_.PrivateMemorySize64 / 1MB, 0)
                $gdiObjects = 0
                $userObjects = 0
                try {
                    $gdiObjects = $_.GDI_Objects
                    $userObjects = $_.USER_Objects
                }
                catch { }
                [PSCustomObject]@{
                    Name      = $_.Name
                    PID       = $_.Id
                    WS_MB     = $wsMB
                    Private_MB = $privateMB
                    Gap_MB    = $privateMB - $wsMB
                    Handles   = $_.HandleCount
                }
            } |
            Where-Object { $_.Gap_MB -gt 200 } |
            Sort-Object Gap_MB -Descending |
            Select-Object -First 5

        if ($leakCandidates) {
            Write-DiagWarning "  Processes where Private Bytes significantly exceeds Working Set:"
            foreach ($lc in $leakCandidates) {
                Write-DiagWarning "    $($lc.Name) (PID $($lc.PID)): WS=$($lc.WS_MB)MB Private=$($lc.Private_MB)MB Gap=$($lc.Gap_MB)MB Handles=$($lc.Handles)"
            }
            Write-Info "  A large Private-WS gap suggests the process has allocated memory that was paged out (possible leak)"
        }
        else {
            Write-Success "  No significant Private Bytes vs Working Set gaps detected"
        }
    }
    catch {
        Write-DiagWarning "  Could not perform detailed leak analysis"
    }

    #endregion v3.0 Memory Checks
}

function Start-MemoryLogCollection {
    <#
    .SYNOPSIS
        Starts memory issue log collection
    .DESCRIPTION
        Provides options for immediate, timed, and intermittent memory issue capture
    #>
    Write-Header "Memory Issue Log Collection"
    
    $tssAvailable = Test-TSSAvailable
    
    Write-Info "Select Memory Issue Scenario:"
    Write-Host "1. High Memory - Issue happening NOW (manual stop)" -ForegroundColor Yellow
    Write-Host "2. High Memory - Issue happening NOW (automatic stop after 5 min)" -ForegroundColor Yellow
    Write-Host "3. High Memory - Intermittent (wait for 90% memory usage)" -ForegroundColor Yellow
    Write-Host "4. Long-term Performance Monitor collection" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-4)" -ValidChoices @("1", "2", "3", "4")
    
    switch ($choice) {
        "1" {
            if ($tssAvailable) {
                Write-Info "Starting memory trace - You will need to manually stop with TSS.ps1 -Stop."
                Write-Info "Let trace run for 60 seconds to 3 minutes while memory is high."
                $logPath = Read-Host "Enter log folder path (e.g., D:\Data) or press Enter for default"
                if ([string]::IsNullOrWhiteSpace($logPath)) { $logPath = $script:DefaultLogPath }
                if (Test-PathValid -Path $logPath -CreateIfNotExist) {
                    if ($script:ClusterEnv.IsClusterNode -and (Test-PathOnCSV -Path $logPath -CSVPaths $script:ClusterEnv.CSVPaths)) {
                        Write-DiagWarning "WARNING: Path '$logPath' is on a Cluster Shared Volume!"
                        Write-DiagWarning "Writing large traces to CSV can cause I/O storms affecting all cluster nodes."
                        $csvConfirm = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                        if ($csvConfirm -ne "Y") { return }
                    }
                    $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
                    if ($confirm -eq "Y") {
                        Invoke-TSSCommand -Command "-Xperf Memory -XperfMaxFileMB 4096 -LogFolderPath '$logPath'"
                    }
                }
            }
            else {
                Write-DiagWarning "TSS is not available. Please install TSS (option 15) to use this trace."
                Show-PerfmonCommand "Memory"
            }
        }
        "2" {
            if ($tssAvailable) {
                $logPath = Read-Host "Enter log folder path (e.g., D:\Data) or press Enter for default"
                
                if ([string]::IsNullOrWhiteSpace($logPath)) {
                    $logPath = $script:DefaultLogPath
                }
                
                if (Test-PathValid -Path $logPath -CreateIfNotExist) {
                    if ($script:ClusterEnv.IsClusterNode -and (Test-PathOnCSV -Path $logPath -CSVPaths $script:ClusterEnv.CSVPaths)) {
                        Write-DiagWarning "WARNING: Path '$logPath' is on a Cluster Shared Volume!"
                        Write-DiagWarning "Writing large traces to CSV can cause I/O storms affecting all cluster nodes."
                        $csvConfirm = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                        if ($csvConfirm -ne "Y") { return }
                    }
                    $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
                    if ($confirm -eq "Y") {
                        Invoke-TSSCommand -Command "-Xperf Memory -XperfMaxFileMB 4096 -StopWaitTimeInSec 300 -LogFolderPath '$logPath'"
                    }
                }
            }
            else {
                Write-DiagWarning "TSS is not available. Please install TSS (option 15) to use this trace."
                Write-Info "Manual alternative: Use Performance Monitor to capture memory counters."
                Show-PerfmonCommand "Memory"
            }
        }
        "3" {
            if ($tssAvailable) {
                Write-Info "Trace will wait for 90% memory usage, then capture for 5 minutes"
                $logPath = Read-Host "Enter log folder path (e.g., D:\Data) or press Enter for default"
                
                if ([string]::IsNullOrWhiteSpace($logPath)) {
                    $logPath = $script:DefaultLogPath
                }
                
                if (Test-PathValid -Path $logPath -CreateIfNotExist) {
                    if ($script:ClusterEnv.IsClusterNode -and (Test-PathOnCSV -Path $logPath -CSVPaths $script:ClusterEnv.CSVPaths)) {
                        Write-DiagWarning "WARNING: Path '$logPath' is on a Cluster Shared Volume!"
                        Write-DiagWarning "Writing large traces to CSV can cause I/O storms affecting all cluster nodes."
                        $csvConfirm = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                        if ($csvConfirm -ne "Y") { return }
                    }
                    $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
                    if ($confirm -eq "Y") {
                        Invoke-TSSCommand -Command "-Xperf Memory -WaitEvent HighMemory:90 -StopWaitTimeInSec 300 -LogFolderPath '$logPath'"
                    }
                }
            }
            else {
                Write-DiagWarning "TSS is not available. Please install TSS (option 15) to use this trace."
                Write-Info "Manual alternative: Use Performance Monitor to capture memory counters."
                Show-PerfmonCommand "Memory"
            }
        }
        "4" {
            Show-PerfmonCommand "Memory"
        }
    }
}
#endregion
