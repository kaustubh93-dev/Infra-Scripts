# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: CPU Diagnostics
# Source lines: 2615 - 3366
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region CPU Diagnostics
function Test-CPUUsage {
    <#
    .SYNOPSIS
        Analyzes CPU usage
    .DESCRIPTION
        Checks current CPU usage, per-core hotspots, privileged vs user time,
        queue length, context switches, interrupts/DPCs, power throttling,
        process analysis, AV detection, Hyper-V overhead, NUMA, and CPU events
    .EXAMPLE
        Test-CPUUsage
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "CPU Usage Analysis"
    
    # Current CPU usage
    try {
        $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop
        if ($cpuUsage) {
            $cpuPercent = [math]::Round($cpuUsage.CounterSamples.CookedValue, 2)
            Write-Info "Current CPU Usage: $($cpuPercent)%"
            
            if ($cpuPercent -gt $CPU_CRITICAL_THRESHOLD) {
                Write-DiagError "CRITICAL: CPU usage above $($CPU_CRITICAL_THRESHOLD)%!"
            }
            elseif ($cpuPercent -gt $CPU_WARNING_THRESHOLD) {
                Write-DiagWarning "WARNING: CPU usage above $($CPU_WARNING_THRESHOLD)%"
            }
            else {
                Write-Success "CPU usage is within normal range"
            }
        }
    }
    catch {
        Write-DiagError "Failed to retrieve CPU usage: $($_.Exception.Message)"
    }
    
    # Processor information (handle multi-socket servers)
    try {
        $cpus = @(Get-CimInstance Win32_Processor -ErrorAction Stop)
        Write-Section "Processor Information"
        if ($cpus.Count -gt 1) {
            Write-Info "  Sockets: $($cpus.Count)"
        }
        foreach ($cpu in $cpus) {
            Write-Info "  Name: $($cpu.Name)"
            Write-Info "  Cores: $($cpu.NumberOfCores)"
            Write-Info "  Logical Processors: $($cpu.NumberOfLogicalProcessors)"
        }
        $totalCores = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
        $totalLP = ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        if ($cpus.Count -gt 1) {
            Write-Info "  Total Cores: $totalCores | Total Logical Processors: $totalLP"
        }
    }
    catch {
        Write-DiagError "Failed to retrieve processor information: $($_.Exception.Message)"
    }
    
    # Top CPU consuming processes
    Write-Section "Top 10 CPU Consuming Processes"
    # Reuse cached process data only if fresh (< 2 minutes old), otherwise fetch new
    $cacheAge = if ($script:LastProcessAnalysisTime) { ((Get-Date) - $script:LastProcessAnalysisTime).TotalMinutes } else { 999 }
    $processAnalysis = if ($script:LastProcessAnalysis -and $cacheAge -lt 2) { $script:LastProcessAnalysis } else { Get-ProcessAnalysis }
    
    if ($processAnalysis) {
        $processAnalysis.ByCPU | Format-Table Name, 
        @{Label = "CPU(s)"; Expression = { [math]::Round($_.CPU, 2) } },
        @{Label = "Memory(MB)"; Expression = { [math]::Round($_.WS / 1MB, 2) } },
        Id -AutoSize
    }
    
    # Check for WMI high CPU
    try {
        $wmiProcess = Get-Process -Name "WmiPrvSE" -ErrorAction SilentlyContinue
        if ($wmiProcess) {
            $wmiCPU = [math]::Round($wmiProcess.CPU, 2)
            Write-Info "`nWMI Provider Host (WmiPrvSE) CPU Usage: $($wmiCPU) seconds"
            if ($wmiCPU -gt $WMI_CPU_WARNING_SECONDS) {
                Write-DiagWarning "WMI Provider Host is consuming significant CPU time"
                Write-Info "Consider using WMI-specific trace: .\TSS.ps1 -UEX_WMIBase -WIN_Kernel -ETWflags 1 -WPR CPU -Perfmon UEX_WMIPrvSE -PerfIntervalSec 1 -noBasicLog"
            }
        }
    }
    catch {
        Write-DiagWarning "Could not check WMI process: $($_.Exception.Message)"
    }

    # Svchost.exe Breakdown (top consumers)
    Write-Section "Top svchost.exe Instances by CPU"
    try {
        $svchosts = Get-Process -Name "svchost" -ErrorAction SilentlyContinue | Sort-Object CPU -Descending | Select-Object -First 5
        foreach ($sh in $svchosts) {
            $cpuSec = [math]::Round($sh.CPU, 1)
            $memMB = [math]::Round($sh.WorkingSet64 / 1MB, 0)
            # Try to get hosted services
            try {
                $services = Get-CimInstance Win32_Service -Filter "ProcessId = $($sh.Id)" -ErrorAction SilentlyContinue
                $svcNames = ($services.Name | Select-Object -First 3) -join ', '
                Write-Info "  PID $($sh.Id): CPU=${cpuSec}s Mem=${memMB}MB - $svcNames"
            }
            catch {
                Write-Info "  PID $($sh.Id): CPU=${cpuSec}s Mem=${memMB}MB"
            }
        }
    }
    catch {
        Write-DiagWarning "Could not analyze svchost processes"
    }

    # Monitoring Agent Detection
    Write-Section "Monitoring Agent CPU Check"
    $monitoringAgents = @("MonitoringHost", "HealthService", "WinCollect", "MOMAgent")
    try {
        foreach ($agent in $monitoringAgents) {
            $procs = Get-Process -Name $agent -ErrorAction SilentlyContinue
            if ($procs) {
                foreach ($p in $procs) {
                    $cpuSec = [math]::Round($p.CPU, 1)
                    if ($cpuSec -gt $MONITORING_AGENT_CPU_WARNING) {
                        Write-DiagWarning "  $($p.Name) (PID $($p.Id)): CPU=${cpuSec}s - monitoring agent CPU storm"
                    }
                    else {
                        Write-Info "  $($p.Name) (PID $($p.Id)): CPU=${cpuSec}s"
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not check monitoring agents: $($_.Exception.Message)"
    }

    # Java.exe High CPU
    try {
        $javaProcs = Get-Process -Name "java" -ErrorAction SilentlyContinue
        if ($javaProcs) {
            Write-Section "Java Process CPU Check"
            foreach ($jp in $javaProcs) {
                $cpuSec = [math]::Round($jp.CPU, 1)
                $memMB = [math]::Round($jp.WorkingSet64 / 1MB, 0)
                if ($cpuSec -gt $JAVA_CPU_WARNING_SECONDS) {
                    Write-DiagWarning "  java.exe (PID $($jp.Id)): CPU=${cpuSec}s Mem=${memMB}MB - high CPU"
                }
                else {
                    Write-Info "  java.exe (PID $($jp.Id)): CPU=${cpuSec}s Mem=${memMB}MB"
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not check Java processes: $($_.Exception.Message)"
    }

    # Split I/O Check (storage fragmentation indicator)
    Write-Section "Split I/O Check"
    try {
        $splitIO = Get-Counter '\PhysicalDisk(_Total)\Split IO/sec' -ErrorAction Stop
        $splitRate = [math]::Round($splitIO.CounterSamples.CookedValue, 0)
        Write-Info "  Split IO/sec: $splitRate"
        if ($splitRate -gt $SPLIT_IO_WARNING_THRESHOLD) {
            Write-DiagWarning "  HIGH Split I/O ($splitRate/sec) - storage fragmentation may be causing extra CPU load"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Split I/O"
    }

    # SQL AG Replication Counters (v3.0 cluster-safe)
    if ($script:ClusterEnv.IsAGInstalled) {
        Write-Section "SQL AG Replication Health"
        try {
            $sendQueue = Get-Counter '\SQLServer:Database Replica(*)\Log Send Queue' -ErrorAction Stop
            foreach ($sample in $sendQueue.CounterSamples) {
                if ($sample.InstanceName -ne "_total" -and $sample.CookedValue -gt 0) {
                    $queueKB = [math]::Round($sample.CookedValue, 0)
                    Write-Info "  $($sample.InstanceName): Log Send Queue = $queueKB KB"
                    if ($queueKB -gt 10240) {
                        Write-DiagWarning "    WARNING: Log send queue >10MB - AG replication lag"
                    }
                }
            }
        }
        catch {
            Write-Info "  SQL AG counters not available (AG may not be configured or SQL not running)"
        }
        try {
            $redoQueue = Get-Counter '\SQLServer:Database Replica(*)\Redo Queue Size' -ErrorAction Stop
            foreach ($sample in $redoQueue.CounterSamples) {
                if ($sample.InstanceName -ne "_total" -and $sample.CookedValue -gt 0) {
                    $redoKB = [math]::Round($sample.CookedValue, 0)
                    Write-Info "  $($sample.InstanceName): Redo Queue = $redoKB KB"
                    if ($redoKB -gt 10240) {
                        Write-DiagWarning "    WARNING: Redo queue >10MB - secondary applying changes slowly"
                    }
                }
            }
        }
        catch { }
    }

    #region v3.0 CPU Checks

    # 1. Per-Core CPU Usage
    Write-Section "Per-Core CPU Usage"
    try {
        $perCore = Get-Counter '\Processor(*)\% Processor Time' -ErrorAction Stop
        $hotCores = @()
        foreach ($sample in $perCore.CounterSamples) {
            if ($sample.InstanceName -ne "_total") {
                $corePercent = [math]::Round($sample.CookedValue, 1)
                if ($corePercent -gt 95) {
                    $hotCores += "Core $($sample.InstanceName): $corePercent%"
                }
            }
        }
        $coreCount = ($perCore.CounterSamples | Where-Object { $_.InstanceName -ne "_total" }).Count
        if ($hotCores.Count -gt 0) {
            Write-DiagWarning "  HOT CORE(s) detected ($($hotCores.Count) of $coreCount at >95%):"
            foreach ($hc in $hotCores) {
                Write-DiagWarning "    $hc"
            }
            Write-Info "  Single-threaded bottleneck likely (SQL query, .NET app, or service pinned to one core)"
        }
        else {
            Write-Success "  No hot cores detected ($coreCount cores, all below 95%)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check per-core CPU usage"
    }

    # 2. Privileged vs User Time
    Write-Section "Privileged vs User Time"
    try {
        $privTime = Get-Counter '\Processor(_Total)\% Privileged Time' -ErrorAction Stop
        $userTime = Get-Counter '\Processor(_Total)\% User Time' -ErrorAction Stop
        $privPercent = [math]::Round($privTime.CounterSamples.CookedValue, 1)
        $userPercent = [math]::Round($userTime.CounterSamples.CookedValue, 1)
        Write-Info "  Kernel (Privileged): $privPercent%"
        Write-Info "  Application (User):  $userPercent%"
        if ($privPercent -gt 30) {
            Write-DiagWarning "  HIGH kernel time (>30%) — investigate storage drivers, NIC drivers, or antivirus filter drivers"
        }
        elseif ($privPercent -gt $userPercent -and $privPercent -gt 15) {
            Write-DiagWarning "  Kernel time exceeds User time — driver or OS subsystem issue likely"
        }
        else {
            Write-Success "  Normal kernel/user time ratio"
        }
    }
    catch {
        Write-DiagWarning "  Could not check privileged/user time split"
    }

    # 3. Processor Queue Length
    Write-Section "Processor Queue Length"
    try {
        $queueLen = Get-Counter '\System\Processor Queue Length' -ErrorAction Stop
        $queue = [math]::Round($queueLen.CounterSamples.CookedValue, 0)
        $logicalProcs = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        $threshold = if ($logicalProcs) { $logicalProcs * 2 } else { 4 }
        Write-Info "  Queue Length: $queue (threshold: $threshold for $logicalProcs logical processors)"
        if ($queue -gt $threshold) {
            Write-DiagError "  CRITICAL: Processor queue length $queue > ${threshold} — threads are waiting for CPU!"
            Write-Info "  This server needs more CPU capacity or workload reduction"
        }
        elseif ($queue -gt ($logicalProcs)) {
            Write-DiagWarning "  WARNING: Queue length elevated ($queue) — approaching CPU saturation"
        }
        else {
            Write-Success "  Processor queue length is healthy"
        }
    }
    catch {
        Write-DiagWarning "  Could not check processor queue length"
    }

    # 4. Context Switches/sec
    Write-Section "Context Switches"
    try {
        $ctxSwitches = Get-Counter '\System\Context Switches/sec' -ErrorAction Stop
        $ctxRate = [math]::Round($ctxSwitches.CounterSamples.CookedValue, 0)
        $perCoreRate = if ($logicalProcs -and $logicalProcs -gt 0) { [math]::Round($ctxRate / $logicalProcs, 0) } else { $ctxRate }
        Write-Info "  Context Switches/sec: $ctxRate (${perCoreRate}/core)"
        if ($perCoreRate -gt 15000) {
            Write-DiagWarning "  HIGH context switching (>15K/core) — thread contention, excessive threads, or hypervisor scheduling"
        }
        elseif ($perCoreRate -gt 8000) {
            Write-DiagWarning "  Elevated context switching (>8K/core) — monitor for lock contention"
        }
        else {
            Write-Success "  Context switch rate is normal"
        }
    }
    catch {
        Write-DiagWarning "  Could not check context switches"
    }

    # 5. Interrupt & DPC Time
    Write-Section "Interrupt & DPC Time"
    try {
        $intTime = Get-Counter '\Processor(_Total)\% Interrupt Time' -ErrorAction Stop
        $dpcTime = Get-Counter '\Processor(_Total)\% DPC Time' -ErrorAction Stop
        $intPercent = [math]::Round($intTime.CounterSamples.CookedValue, 2)
        $dpcPercent = [math]::Round($dpcTime.CounterSamples.CookedValue, 2)
        Write-Info "  Interrupt Time: $intPercent%"
        Write-Info "  DPC Time: $dpcPercent%"
        if ($intPercent -gt 15 -or $dpcPercent -gt 15) {
            Write-DiagError "  CRITICAL: High interrupt/DPC time — NIC driver, storage driver, or hardware issue"
            Write-Info "  On Hyper-V hosts, check vmswitch and storage subsystem"
        }
        elseif ($intPercent -gt 5 -or $dpcPercent -gt 5) {
            Write-DiagWarning "  Elevated interrupt/DPC time — investigate NIC RSS settings and storage drivers"
        }
        else {
            Write-Success "  Interrupt and DPC time are normal"
        }
    }
    catch {
        Write-DiagWarning "  Could not check interrupt/DPC time"
    }

    # 6. System Uptime & Last Boot
    Write-Section "System Uptime"
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $uptime = (Get-Date) - $os.LastBootUpTime
        Write-Info "  Last Boot: $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        Write-Info "  Uptime: $($uptime.Days) days, $($uptime.Hours) hours"
        if ($uptime.TotalDays -gt 180) {
            Write-DiagError "  Server running for $([math]::Round($uptime.TotalDays, 0)) days — kernel timer drift and memory fragmentation risk"
        }
        elseif ($uptime.TotalDays -gt 90) {
            Write-DiagWarning "  Server running for $([math]::Round($uptime.TotalDays, 0)) days — consider scheduling maintenance reboot"
        }
    }
    catch {
        Write-DiagWarning "  Could not check system uptime"
    }

    # 7. Power Throttling Detection
    Write-Section "CPU Power Throttling"
    try {
        $perfPercent = Get-Counter '\Processor Information(_Total)\% Processor Performance' -ErrorAction Stop
        $perfVal = [math]::Round($perfPercent.CounterSamples.CookedValue, 1)
        Write-Info "  Processor Performance: $perfVal%"
        if ($perfVal -lt 80) {
            Write-DiagError "  CPU THROTTLED to $perfVal% — check power plan, thermal throttling, or VM host overcommit"
            Write-Info "  Set power plan to High Performance: powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        }
        elseif ($perfVal -lt 95) {
            Write-DiagWarning "  CPU performance at $perfVal% (not running at full speed)"
        }
        else {
            Write-Success "  CPU running at full performance ($perfVal%)"
        }

        # Check processor frequency
        $freqCounter = Get-Counter '\Processor Information(_Total)\Processor Frequency' -ErrorAction SilentlyContinue
        if ($freqCounter) {
            $freqMHz = [math]::Round($freqCounter.CounterSamples.CookedValue, 0)
            Write-Info "  Current Frequency: $freqMHz MHz"
        }
    }
    catch {
        Write-Info "  Processor Performance counter not available (may require newer OS)"
    }

    # 8. Antivirus / Filter Driver CPU Detection
    Write-Section "Antivirus & Security Agent CPU"
    try {
        $avProcesses = @(
            @{ Name = "MsMpEng"; Label = "Windows Defender" },
            @{ Name = "CSFalconService"; Label = "CrowdStrike Falcon" },
            @{ Name = "CSFalconContainer"; Label = "CrowdStrike Container" },
            @{ Name = "SentinelAgent"; Label = "SentinelOne" },
            @{ Name = "SentinelServiceHost"; Label = "SentinelOne Host" },
            @{ Name = "ccSvcHst"; Label = "Symantec/Broadcom" },
            @{ Name = "savservice"; Label = "Sophos" },
            @{ Name = "WRSA"; Label = "Webroot" },
            @{ Name = "cb"; Label = "Carbon Black" },
            @{ Name = "CylanceSvc"; Label = "Cylance" },
            @{ Name = "TaniumClient"; Label = "Tanium" },
            @{ Name = "ds_agent"; Label = "Trend Micro Deep Security" }
        )
        $avFound = $false
        foreach ($av in $avProcesses) {
            $procs = Get-Process -Name $av.Name -ErrorAction SilentlyContinue
            if ($procs) {
                $avFound = $true
                foreach ($p in $procs) {
                    $cpuSec = [math]::Round($p.CPU, 1)
                    $memMB = [math]::Round($p.WorkingSet64 / 1MB, 0)
                    $indicator = ""
                    if ($cpuSec -gt 300) { $indicator = " [HIGH CPU - investigate exclusions]" }
                    Write-Info "  $($av.Label) ($($p.Name), PID $($p.Id)): CPU=${cpuSec}s Mem=${memMB}MB$indicator"
                }
            }
        }
        if (-not $avFound) {
            Write-Info "  No known AV/security agent processes detected"
        }

        # Check filter drivers that could impact CPU
        try {
            $fltmc = fltmc 2>&1
            $filterCount = ($fltmc | Select-String '^\d+' | Measure-Object).Count
            if ($filterCount -gt 0) {
                Write-Info "  File system filter drivers: $filterCount active"
                $highAltitude = $fltmc | Select-String '(WdFilter|csagent|SentinelMonitor|SymEFA|savonaccess|CbFilter)' -ErrorAction SilentlyContinue
                if ($highAltitude) {
                    Write-Info "  AV filter drivers detected in filter stack:"
                    foreach ($f in $highAltitude) {
                        Write-Info "    $($f.Line.Trim())"
                    }
                }
            }
        }
        catch { }
    }
    catch {
        Write-DiagWarning "  Could not check antivirus processes"
    }

    # 9. Hyper-V Hypervisor Overhead
    Write-Section "Hyper-V Hypervisor Overhead"
    try {
        $hvSvc = Get-Service -Name "vmms" -ErrorAction SilentlyContinue
        if ($null -ne $hvSvc -and $hvSvc.Status -eq "Running") {
            try {
                $hvRunTime = Get-Counter '\Hyper-V Hypervisor Logical Processor(_Total)\% Total Run Time' -ErrorAction Stop
                $hvPercent = [math]::Round($hvRunTime.CounterSamples.CookedValue, 1)
                Write-Info "  Hypervisor Total Run Time: $hvPercent%"

                $hvOverhead = Get-Counter '\Hyper-V Hypervisor Logical Processor(_Total)\% Hypervisor Run Time' -ErrorAction SilentlyContinue
                if ($hvOverhead) {
                    $ohPercent = [math]::Round($hvOverhead.CounterSamples.CookedValue, 2)
                    Write-Info "  Hypervisor Overhead: $ohPercent%"
                    if ($ohPercent -gt 5) {
                        Write-DiagWarning "  HIGH hypervisor overhead (>5%) — too many VMs or NUMA misconfiguration"
                    }
                }

                $hvGuest = Get-Counter '\Hyper-V Hypervisor Logical Processor(_Total)\% Guest Run Time' -ErrorAction SilentlyContinue
                if ($hvGuest) {
                    Write-Info "  Guest VM Run Time: $([math]::Round($hvGuest.CounterSamples.CookedValue, 1))%"
                }
            }
            catch {
                Write-Info "  Hyper-V counters not available (may not be a host)"
            }
        }
        else {
            Write-Info "  Hyper-V not running on this server"
        }
    }
    catch {
        Write-Info "  Could not check Hyper-V status"
    }

    # 10. Process CPU Time Trend (two-sample snapshot)
    Write-Section "Real-Time Process CPU (5-second sample)"
    try {
        Write-Info "  Sampling CPU usage over 5 seconds..."
        $snapshot1 = Get-Process -ErrorAction Stop | Where-Object { $_.Id -ne 0 } |
            Select-Object Id, Name, @{N='CPU1';E={$_.TotalProcessorTime.TotalMilliseconds}}
        Start-Sleep -Seconds 5
        $snapshot2 = Get-Process -ErrorAction Stop | Where-Object { $_.Id -ne 0 } |
            Select-Object Id, Name, @{N='CPU2';E={$_.TotalProcessorTime.TotalMilliseconds}}

        $delta = foreach ($p2 in $snapshot2) {
            $p1 = $snapshot1 | Where-Object { $_.Id -eq $p2.Id }
            if ($p1) {
                $cpuDelta = $p2.CPU2 - $p1.CPU1
                if ($cpuDelta -gt 0) {
                    # Approximate % of one core over 5 seconds (5000ms)
                    $cpuPctApprox = [math]::Round(($cpuDelta / 5000) * 100, 1)
                    [PSCustomObject]@{
                        Name   = $p2.Name
                        PID    = $p2.Id
                        DeltaMs = [math]::Round($cpuDelta, 0)
                        ApproxPct = $cpuPctApprox
                    }
                }
            }
        }
        $topDelta = $delta | Sort-Object DeltaMs -Descending | Select-Object -First 10
        if ($topDelta) {
            Write-Info "  Top 10 processes by CURRENT CPU usage (last 5s):"
            foreach ($td in $topDelta) {
                Write-Info "    $($td.Name) (PID $($td.PID)): ${($td.DeltaMs)}ms (~$($td.ApproxPct)% of 1 core)"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not perform real-time CPU sampling"
    }

    # 11. System Threads & Process Count
    Write-Section "System Thread & Process Count"
    try {
        $sysThreads = Get-Counter '\System\Threads' -ErrorAction Stop
        $sysProcesses = Get-Counter '\System\Processes' -ErrorAction Stop
        $threadCount = [math]::Round($sysThreads.CounterSamples.CookedValue, 0)
        $processCount = [math]::Round($sysProcesses.CounterSamples.CookedValue, 0)
        Write-Info "  Total Threads: $threadCount"
        Write-Info "  Total Processes: $processCount"
        if ($threadCount -gt 5000) {
            Write-DiagWarning "  HIGH thread count ($threadCount) — approaching kernel resource limits"
        }
        if ($processCount -gt 500) {
            Write-DiagWarning "  HIGH process count ($processCount) — investigate runaway services or scheduled tasks"
        }
    }
    catch {
        Write-DiagWarning "  Could not check system thread/process counts"
    }

    # 12. DPC Queue Rate
    Write-Section "DPC Queue Rate"
    try {
        $dpcQueued = Get-Counter '\Processor(_Total)\DPCs Queued/sec' -ErrorAction Stop
        $dpcRate = [math]::Round($dpcQueued.CounterSamples.CookedValue, 0)
        Write-Info "  DPCs Queued/sec: $dpcRate"
        $perCoreDPC = if ($logicalProcs -and $logicalProcs -gt 0) { [math]::Round($dpcRate / $logicalProcs, 0) } else { $dpcRate }
        Write-Info "  Per-core DPC rate: $perCoreDPC/sec"
        if ($perCoreDPC -gt 5000) {
            Write-DiagWarning "  HIGH DPC rate (>5K/core) — NIC or storage driver processing bottleneck"
        }
    }
    catch {
        Write-DiagWarning "  Could not check DPC queue rate"
    }

    # 13. NUMA Node Imbalance
    Write-Section "NUMA Node Analysis"
    try {
        $numaNodes = Get-Counter '\NUMA Node Memory(*)\Total MBytes' -ErrorAction Stop
        $nodeData = @()
        foreach ($sample in $numaNodes.CounterSamples) {
            if ($sample.InstanceName -ne "_total") {
                $nodeData += [PSCustomObject]@{
                    Node = $sample.InstanceName
                    TotalMB = [math]::Round($sample.CookedValue, 0)
                }
            }
        }
        if ($nodeData.Count -gt 1) {
            Write-Info "  NUMA Nodes detected: $($nodeData.Count)"
            foreach ($nd in $nodeData) {
                Write-Info "    Node $($nd.Node): $($nd.TotalMB) MB"
            }
            $maxMB = ($nodeData | Measure-Object TotalMB -Maximum).Maximum
            $minMB = ($nodeData | Measure-Object TotalMB -Minimum).Minimum
            if ($maxMB -gt 0) {
                $imbalance = [math]::Round((($maxMB - $minMB) / $maxMB) * 100, 1)
                if ($imbalance -gt 20) {
                    Write-DiagWarning "  NUMA imbalance: $imbalance% memory difference between nodes"
                    Write-Info "  Processes may be hitting remote NUMA memory, causing hidden CPU penalties"
                }
                else {
                    Write-Success "  NUMA memory balanced (${imbalance}% difference)"
                }
            }
        }
        elseif ($nodeData.Count -eq 1) {
            Write-Info "  Single NUMA node ($($nodeData[0].TotalMB) MB) — no imbalance possible"
        }
    }
    catch {
        Write-Info "  NUMA counters not available (single-socket system or counters disabled)"
    }

    # 14. CPU-Related Event Log Entries
    Write-Section "CPU-Related Events (last 7 days)"
    try {
        # WHEA hardware errors (CPU/memory correctable and uncorrectable)
        $wheaEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 19, 47, 17
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($wheaEvents) {
            Write-DiagError "  WHEA hardware errors detected ($($wheaEvents.Count) events):"
            $wheaEvents | Group-Object Id | ForEach-Object {
                $desc = switch ($_.Name) {
                    '17' { "WHEA: Machine check exception" }
                    '19' { "WHEA: Corrected hardware error" }
                    '47' { "WHEA: Fatal hardware error" }
                    default { "WHEA event" }
                }
                Write-DiagError "    Event $($_.Name) ($desc): $($_.Count) occurrence(s)"
            }
            Write-Info "  WHEA errors indicate CPU, memory, or PCIe hardware degradation"
        }
        else {
            Write-Success "  No WHEA hardware errors"
        }

        # Thermal throttling / processor speed change
        $thermalEvents = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'
            StartTime    = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($thermalEvents) {
            Write-DiagWarning "  Kernel-Processor-Power events: $($thermalEvents.Count)"
            $thermalEvents | Select-Object -First 3 | ForEach-Object {
                Write-Info "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] ID:$($_.Id) $(Get-EventSnippet -Event $_ -MaxLength 100)"
            }
        }
        else {
            Write-Success "  No processor power/thermal events"
        }
    }
    catch {
        Write-Info "  Could not query CPU-related events"
    }

    # 15. Process CPU Affinity Check
    Write-Section "Process CPU Affinity"
    try {
        $affinityIssues = @()
        # Calculate full affinity mask for this system
        $fullMask = [long](([math]::Pow(2, $logicalProcs)) - 1)

        $topProcs = Get-Process -ErrorAction Stop |
            Where-Object { $_.CPU -gt 10 -and $_.Id -ne 0 -and $_.Id -ne 4 } |
            Sort-Object CPU -Descending |
            Select-Object -First 20
        foreach ($proc in $topProcs) {
            try {
                $affinity = $proc.ProcessorAffinity.ToInt64()
                if ($affinity -ne $fullMask -and $affinity -gt 0) {
                    $setBits = [Convert]::ToString($affinity, 2).ToCharArray() | Where-Object { $_ -eq '1' }
                    $coreCount = $setBits.Count
                    $affinityIssues += "  $($proc.Name) (PID $($proc.Id)): Affinity=$coreCount of $logicalProcs cores (mask: 0x$($affinity.ToString('X')))"
                }
            }
            catch { }
        }
        if ($affinityIssues.Count -gt 0) {
            Write-DiagWarning "  Processes with restricted CPU affinity:"
            foreach ($ai in $affinityIssues) {
                Write-DiagWarning "  $ai"
            }
            Write-Info "  Restricted affinity limits available CPU and can cause bottlenecks"
        }
        else {
            Write-Success "  No processes with restricted CPU affinity (all using full core set)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check process affinity"
    }

    #endregion v3.0 CPU Checks
}

function Start-CPULogCollection {
    <#
    .SYNOPSIS
        Starts CPU issue log collection
    .DESCRIPTION
        Provides options for immediate, timed, intermittent, and WMI-specific CPU issue capture
    #>
    Write-Header "CPU Issue Log Collection"
    
    $tssAvailable = Test-TSSAvailable
    
    Write-Info "Select CPU Issue Scenario:"
    Write-Host "1. High CPU - Issue happening NOW (manual stop, 60s-3min recommended)" -ForegroundColor Yellow
    Write-Host "2. High CPU - Issue happening NOW (automatic stop after 5 min)" -ForegroundColor Yellow
    Write-Host "3. High CPU - Intermittent (wait for 90% CPU usage)" -ForegroundColor Yellow
    Write-Host "4. High CPU - WMI related" -ForegroundColor Yellow
    Write-Host "5. Long-term Performance Monitor collection" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-5)" -ValidChoices @("1", "2", "3", "4", "5")
    
    switch ($choice) {
        "1" {
            if ($tssAvailable) {
                Write-Info "Starting CPU trace - You can manually stop with TSS.ps1 -Stop."
                Write-Info "Run for 60 seconds to 3 minutes while CPU is high (>88%)."
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
                        Invoke-TSSCommand -Command "-Xperf CPU -XperfMaxFileMB 4096 -LogFolderPath '$logPath'"
                    }
                }
            }
            else {
                Write-DiagWarning "TSS is not available. Please install TSS (option 15) to use this trace."
                Show-PerfmonCommand "CPU"
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
                        Invoke-TSSCommand -Command "-Xperf CPU -XperfMaxFileMB 4096 -StopWaitTimeInSec 300 -LogFolderPath '$logPath'"
                    }
                }
            }
            else {
                Write-DiagWarning "TSS is not available. Please install TSS (option 15) to use this trace."
                Write-Info "Manual alternative: Use Performance Monitor to capture CPU counters."
                Show-PerfmonCommand "CPU"
            }
        }
        "3" {
            Invoke-WithTSSCheck `
                -TSSCommand "-Xperf CPU -WaitEvent HighCPU:90 -XperfMaxFileMB 4096 -StopWaitTimeInSec 300" `
                -Description "Trace will wait for 90% CPU usage, then capture for 5 minutes"
        }
        "4" {
            Invoke-WithTSSCheck `
                -TSSCommand "-UEX_WMIBase -WIN_Kernel -ETWflags 1 -WPR CPU -Perfmon UEX_WMIPrvSE -PerfIntervalSec 1 -noBasicLog" `
                -Description "Starting WMI-specific CPU trace (run for 2 minutes during high CPU)"
        }
        "5" {
            Show-PerfmonCommand "CPU"
        }
    }
}
#endregion
