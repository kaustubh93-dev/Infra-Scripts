# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Services Health Diagnostics
# Source lines: 4128 - 4395
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Services Health Diagnostics
function Test-ServicesHealth {
    <#
    .SYNOPSIS
        Analyzes Windows services health
    .DESCRIPTION
        Checks critical services, stopped automatic services, and recently failed services
    .EXAMPLE
        Test-ServicesHealth
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "Windows Services Health Check"
    
    # Check critical services
    Write-Info "Checking Critical Services..."
    try {
        foreach ($svcName in $script:CriticalServices) {
            try {
                $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($null -eq $svc) { continue }
                
                if ($svc.Status -eq "Running") {
                    Write-Success "  $($svc.DisplayName) ($($svc.Name)): Running"
                }
                elseif ($svc.Status -eq "Stopped" -and $svc.StartType -eq "Automatic") {
                    if ($svcName -eq "SQLSERVERAGENT" -and $script:ClusterEnv.IsAGInstalled -and $script:ClusterEnv.LocalReplicaRole -eq "SECONDARY") {
                        Write-Info "  $($svc.DisplayName) ($($svc.Name)): Stopped (expected on AG SECONDARY replica)"
                    }
                    else {
                        Write-DiagError "  $($svc.DisplayName) ($($svc.Name)): STOPPED (Auto-Start)"
                    }
                }
                elseif ($svc.Status -eq "Stopped") {
                    Write-Info "  $($svc.DisplayName) ($($svc.Name)): Stopped ($($svc.StartType))"
                }
                else {
                    Write-DiagWarning "  $($svc.DisplayName) ($($svc.Name)): $($svc.Status)"
                }
            }
            catch {
                # Service not installed on this server, skip
            }
        }
    }
    catch {
        Write-DiagError "Failed to check critical services: $($_.Exception.Message)"
    }
    
    # Stopped automatic services
    Write-Section "Stopped Automatic Services"
    try {
        $stoppedAuto = Get-Service -ErrorAction Stop | Where-Object {
            $_.StartType -eq "Automatic" -and $_.Status -ne "Running"
        }
        
        if ($stoppedAuto) {
            Write-DiagWarning "  Found $($stoppedAuto.Count) stopped automatic service(s):"
            foreach ($svc in $stoppedAuto) {
                Write-DiagWarning "    - $($svc.DisplayName) ($($svc.Name)): $($svc.Status)"
            }
        }
        else {
            Write-Success "  All automatic services are running"
        }
    }
    catch {
        Write-DiagError "Failed to enumerate services: $($_.Exception.Message)"
    }
    
    # Disabled services that are typically needed
    Write-Section "Disabled Services (may need attention)"
    try {
        $disabledSvcs = @(Get-Service -ErrorAction Stop | Where-Object {
            $_.StartType -eq "Disabled"
        })
        
        if ($disabledSvcs.Count -gt 0) {
            Write-Info "  Found $($disabledSvcs.Count) disabled service(s):"
            # Issue #1: enumerate ALL disabled services so the file-save path captures the
            # full list (previously truncated to 15 entries with "... and N more").
            foreach ($svc in $disabledSvcs) {
                Write-Info "    - $($svc.DisplayName) ($($svc.Name))"
            }
        }
        else {
            Write-Info "  No disabled services found"
        }
    }
    catch {
        Write-DiagError "Failed to check disabled services: $($_.Exception.Message)"
    }
    
    # Recently crashed services (Event 7034)
    Write-Section "Recently Crashed/Terminated Services (last 24 hours)"
    try {
        $crashEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 7034
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 10 -ErrorAction SilentlyContinue
        
        if ($crashEvents) {
            Write-DiagWarning "  Found $($crashEvents.Count) service crash event(s):"
            foreach ($evt in $crashEvents) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] $(Get-EventSnippet -Event $evt -MaxLength 120)"
            }
        }
        else {
            Write-Success "  No service crashes detected in the last 24 hours"
        }
    }
    catch {
        Write-Info "  Could not query service crash events"
    }

    # W32Time NTP Sync Status
    Write-Section "Time Service (NTP) Sync Status"
    try {
        $w32tmOutput = w32tm /query /status 2>&1
        if ($LASTEXITCODE -eq 0) {
            $sourceMatch = $w32tmOutput | Select-String 'Source:'
            $stratumMatch = $w32tmOutput | Select-String 'Stratum:'
            $lastSync = $w32tmOutput | Select-String 'Last Successful Sync Time:'
            if ($sourceMatch) { Write-Info "  $($sourceMatch.Line.Trim())" }
            if ($stratumMatch) { Write-Info "  $($stratumMatch.Line.Trim())" }
            if ($lastSync) {
                Write-Info "  $($lastSync.Line.Trim())"
            }
            else {
                Write-DiagWarning "  NTP has never synced successfully"
            }
        }
        else {
            Write-DiagWarning "  W32Time service may not be running"
        }
    }
    catch {
        Write-DiagWarning "  Could not check NTP status"
    }

    # Task Scheduler Health
    Write-Section "Task Scheduler Health"
    try {
        $schedEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-TaskScheduler/Operational'
            Level     = 1, 2
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($schedEvents) {
            Write-DiagWarning "  Found $($schedEvents.Count) Task Scheduler error(s) in last 24h:"
            foreach ($evt in $schedEvents) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] ID:$($evt.Id) $(Get-EventSnippet -Event $evt -MaxLength 80)"
            }
        }
        else {
            Write-Success "  No Task Scheduler errors in last 24 hours"
        }
    }
    catch {
        Write-Info "  Task Scheduler Operational log not accessible"
    }

    # EventLog Service Errors
    Write-Section "EventLog Service Errors"
    try {
        $evtLogErrors = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1108
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 3 -ErrorAction SilentlyContinue

        if ($evtLogErrors) {
            Write-DiagError "  EventLog service errors detected (Event 1108):"
            foreach ($evt in $evtLogErrors) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $evt -MaxLength 80)"
            }
        }
        else {
            Write-Success "  No EventLog service errors"
        }
    }
    catch { Write-Info "  Could not query EventLog errors" }

    # Netlogon / Domain Connectivity Events
    Write-Section "Netlogon Events"
    try {
        $netlogonEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 5719, 7023, 7024
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($netlogonEvents) {
            Write-DiagWarning "  Found Netlogon/Service failure events:"
            foreach ($evt in $netlogonEvents) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] EventID $($evt.Id): $(Get-EventSnippet -Event $evt -MaxLength 80)"
            }
        }
        else {
            Write-Success "  No Netlogon connectivity issues"
        }
    }
    catch { Write-Info "  Could not query Netlogon events" }

    # RDP Licensing Service
    Write-Section "RDP Licensing"
    try {
        $rdpLic = Get-Service -Name "TermServLicensing" -ErrorAction SilentlyContinue
        if ($null -ne $rdpLic) {
            Write-Info "  TermServLicensing: $($rdpLic.Status) ($($rdpLic.StartType))"
        }
        $rdpEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1128, 1129
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 3 -ErrorAction SilentlyContinue
        if ($rdpEvents) {
            Write-DiagWarning "  RDP licensing errors found in last 7 days"
        }
    }
    catch { }
}

function Start-ServicesLogCollection {
    <#
    .SYNOPSIS
        Starts services-related log collection
    .DESCRIPTION
        Provides options for service trace collection and manual diagnostics
    #>
    Write-Header "Services Log Collection"
    
    Write-Info "Services Log Collection Options:"
    Write-Host "1. Export all service status to file" -ForegroundColor Yellow
    Write-Host "2. TSS Performance SDP (includes services)" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-2)" -ValidChoices @("1", "2")
    
    switch ($choice) {
        "1" {
            $exportPath = Join-Path $script:DefaultLogPath "ServiceStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            try {
                if (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist) {
                    Get-Service | Sort-Object Status, Name |
                    Format-Table Name, DisplayName, Status, StartType -AutoSize |
                    Out-String -Width 200 |
                    Out-File -FilePath $exportPath -Encoding UTF8
                    Write-Success "Service status exported to: $exportPath"
                }
            }
            catch {
                Write-DiagError "Failed to export service status: $($_.Exception.Message)"
            }
        }
        "2" {
            Invoke-WithTSSCheck `
                -TSSCommand "-SDP Perf -AcceptEula" `
                -ManualAlternativeAction {
                Write-Info "Manual alternative: Run 'Get-Service | Export-Csv services.csv' to export service info"
            } `
                -Description "Starting TSS Performance SDP collection (includes service information)..."
        }
    }
}
#endregion
