# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Event Log Analysis
# Source lines: 4397 - 4635
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Event Log Analysis
function Test-EventLogHealth {
    <#
    .SYNOPSIS
        Analyzes Windows Event Logs for issues
    .DESCRIPTION
        Scans System and Application logs for recent errors, groups by EventID,
        and checks log capacity
    .EXAMPLE
        Test-EventLogHealth
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "Event Log Analysis"
    
    $logNames = @("System", "Application")
    
    foreach ($logName in $logNames) {
        Write-Section "$logName Log"
        
        # Check log size and capacity
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $usedMB = [math]::Round($log.FileSize / 1MB, 2)
            $maxMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
            $usedPercent = if ($log.MaximumSizeInBytes -gt 0) {
                [math]::Round(($log.FileSize / $log.MaximumSizeInBytes) * 100, 1)
            }
            else { 0 }
            
            Write-Info "  Log Size: $usedMB MB / $maxMB MB ($usedPercent% used)"
            
            if ($usedPercent -gt 90) {
                Write-DiagWarning "  WARNING: Log is nearly full! Consider increasing max size or archiving."
            }
        }
        catch {
            Write-DiagWarning "  Could not retrieve $logName log properties"
        }
        
        # Scan for Critical and Error events in last 24 hours
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                Level     = 1, 2  # Critical, Error
                StartTime = (Get-Date).AddHours(-24)
            } -MaxEvents 500 -ErrorAction SilentlyContinue
            
            if ($events) {
                Write-DiagWarning "  Found $($events.Count) Critical/Error events in last 24 hours"
                
                # Group by EventID and Source
                $grouped = $events | Group-Object Id, ProviderName | Sort-Object Count -Descending | Select-Object -First 10
                
                Write-Info "  Top Event IDs (by frequency):"
                foreach ($group in $grouped) {
                    $parts = $group.Name -split ', '
                    $eventId = $parts[0]
                    $source = if ($parts.Length -gt 1) { $parts[1] } else { "Unknown" }
                    Write-Info "    EventID $eventId ($source): $($group.Count) occurrence(s)"
                }
                
                # Show last 5 critical/error events
                Write-Section "Last 5 Events"
                $events | Select-Object -First 5 | ForEach-Object {
                    $levelText = switch ($_.Level) { 1 { "CRITICAL" } 2 { "ERROR" } default { "UNKNOWN" } }
                    $msgSnippet = $(Get-EventSnippet -Event $_ -MaxLength 120)
                    Write-Info "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] [$levelText] ID:$($_.Id) - $msgSnippet"
                }
            }
            else {
                Write-Success "  No Critical/Error events in last 24 hours"
            }
        }
        catch {
            Write-Info "  No matching events found or unable to query $logName log"
        }
    }

    # Cluster Events (1135, 1672)
    Write-Section "Cluster Heartbeat/Quarantine Events (last 7 days)"
    try {
        $clusterEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1135, 1672
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($clusterEvts) {
            Write-DiagError "  Found $($clusterEvts.Count) cluster event(s):"
            foreach ($g in ($clusterEvts | Group-Object Id)) {
                Write-DiagWarning "    Event $($g.Name): $($g.Count) occurrence(s)"
            }
        }
        else {
            Write-Success "  No cluster heartbeat/quarantine events"
        }
    }
    catch { Write-Info "  Failover Clustering may not be installed" }

    # FailoverClustering Operational Log (v3.0 cluster-safe)
    if ($script:ClusterEnv.IsClusterNode) {
        Write-Section "Failover Clustering Operational Log (last 24h)"
        try {
            $fcEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-FailoverClustering/Operational'
                Level     = 1, 2, 3
                StartTime = (Get-Date).AddHours(-24)
            } -MaxEvents 20 -ErrorAction SilentlyContinue

            if ($fcEvents) {
                Write-DiagWarning "  Found $($fcEvents.Count) FailoverClustering event(s):"
                $fcGrouped = $fcEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5
                foreach ($g in $fcGrouped) {
                    Write-DiagWarning "    Event $($g.Name): $($g.Count) occurrence(s)"
                }
                $fcEvents | Select-Object -First 3 | ForEach-Object {
                    Write-Info "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] ID:$($_.Id) $(Get-EventSnippet -Event $_ -MaxLength 100)"
                }
            }
            else {
                Write-Success "  No FailoverClustering errors/warnings in last 24 hours"
            }
        }
        catch {
            Write-Info "  FailoverClustering Operational log not available"
        }
    }

    # Storage Events (129, 153)
    Write-Section "Storage Adapter Events (129/153, last 7 days)"
    try {
        $storEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 129, 153
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($storEvts) {
            Write-DiagError "  Found $($storEvts.Count) storage error event(s):"
            foreach ($g in ($storEvts | Group-Object Id)) {
                Write-DiagWarning "    Event $($g.Name): $($g.Count) occurrence(s)"
            }
        }
        else {
            Write-Success "  No storage adapter errors"
        }
    }
    catch { }

    # DNS Update Failures (1196)
    Write-Section "DNS Update Failure Events"
    try {
        $dnsEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 8018, 8019
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($dnsEvts) {
            Write-DiagWarning "  Found $($dnsEvts.Count) DNS dynamic update failure(s)"
        }
        else {
            Write-Success "  No DNS update failures"
        }
    }
    catch { }

    # Known Critical Event Summary (from $script:KnownCriticalEventIDs)
    Write-Section "High-Priority Event Summary (last 24h)"
    foreach ($logName in $script:KnownCriticalEventIDs.Keys) {
        foreach ($evtDef in $script:KnownCriticalEventIDs[$logName]) {
            try {
                # Single query instead of two — get all matching events and count
                $found = @(Get-WinEvent -FilterHashtable @{
                        LogName   = $logName
                        Id        = $evtDef.Id
                        StartTime = (Get-Date).AddHours(-24)
                    } -ErrorAction SilentlyContinue)

                if ($found.Count -gt 0) {
                    Write-DiagWarning "  [$logName] Event $($evtDef.Id) ($($evtDef.Desc)): $($found.Count) occurrence(s)"
                }
            }
            catch { }
        }
    }
}

function Start-EventLogCollection {
    <#
    .SYNOPSIS
        Starts event log collection for analysis
    .DESCRIPTION
        Provides options for event log export and TSS collection
    #>
    Write-Header "Event Log Collection"
    
    Write-Info "Event Log Collection Options:"
    Write-Host "1. Export System, Application, Security logs (.evtx)" -ForegroundColor Yellow
    Write-Host "2. TSS Setup SDP (includes event logs)" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-2)" -ValidChoices @("1", "2")
    
    switch ($choice) {
        "1" {
            $exportPath = Read-Host "Enter export path or press Enter for default"
            if ([string]::IsNullOrWhiteSpace($exportPath)) {
                $exportPath = Join-Path $script:DefaultLogPath "EventLogs"
            }
            
            if (Test-PathValid -Path $exportPath -CreateIfNotExist) {
                try {
                    $logNames = @("System", "Application", "Security")
                    foreach ($log in $logNames) {
                        Write-Info "Exporting $log event log..."
                        $evtxPath = Join-Path $exportPath "$($log.ToLower()).evtx"
                        wevtutil epl $log $evtxPath
                    }
                    Write-Success "Event logs exported to: $exportPath"
                }
                catch {
                    Write-DiagError "Failed to export event logs: $($_.Exception.Message)"
                }
            }
        }
        "2" {
            Invoke-WithTSSCheck `
                -TSSCommand "-SDP Setup -AcceptEula" `
                -ManualAlternativeAction {
                Write-Info "Manual: wevtutil epl System system.evtx"
                Write-Info "        wevtutil epl Application application.evtx"
            } `
                -Description "Starting TSS Setup SDP collection (includes event logs)..."
        }
    }
}
#endregion
