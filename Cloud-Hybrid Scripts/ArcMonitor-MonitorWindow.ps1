#Requires -Version 5.1
<#
.SYNOPSIS
    Arc Monitor — Standalone TUI Dashboard (runs in its own window)
.DESCRIPTION
    This script is launched in a SEPARATE PowerShell window by Start-ArcOnboarding.
    It reads server status from a shared JSON state file and renders the TUI dashboard.
    The main onboarding window writes status updates; this window only reads and displays.
    Close with Ctrl+C or it exits automatically when all servers reach a final state.
.PARAMETER StateFile
    Path to the shared JSON state file written by the onboarding process.
.PARAMETER PollInterval
    Seconds between dashboard refreshes.
#>
param(
    [Parameter(Mandatory)]
    [string]$StateFile,

    [int]$PollInterval = 5,

    [int]$MaxPolls = 720
)

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$scriptRoot\ArcMonitor-TUI.ps1"

$Host.UI.RawUI.WindowTitle = "ARC ONBOARDING MONITOR"

$columns = @(
    @{ Header = "Server";    Key = "Name";     Width = 22 }
    @{ Header = "Platform";  Key = "Platform";  Width = 12 }
    @{ Header = "PreReq";    Key = "PreReq";    Width = 12 }
    @{ Header = "Install";   Key = "Install";   Width = 14 }
    @{ Header = "Arc Reg";   Key = "ArcReg";    Width = 12 }
    @{ Header = "Agent";     Key = "Agent";     Width = 14 }
)

$startTime = Get-Date
$pollCount = 0

while ($pollCount -lt $MaxPolls) {
    $pollCount++
    $elapsed = (Get-Date) - $startTime

    # Read state file
    if (-not (Test-Path $StateFile)) {
        Clear-Host
        Write-Host "`n  Waiting for onboarding to begin..." -ForegroundColor Yellow
        Write-Host "  State file: $StateFile" -ForegroundColor DarkGray
        Start-Sleep -Seconds 2
        continue
    }

    try {
        $rawJson = Get-Content $StateFile -Raw -ErrorAction Stop
        $state = $rawJson | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Start-Sleep -Seconds 1
        continue
    }

    if (-not $state.Servers -or $state.Servers.Count -eq 0) {
        Start-Sleep -Seconds 1
        continue
    }

    # Build node status array
    $nodeList  = [System.Collections.Generic.List[hashtable]]::new()
    $allEvents = [System.Collections.Generic.List[hashtable]]::new()
    $running = 0; $done = 0; $failed = 0

    foreach ($srv in $state.Servers) {
        $nodeHash = @{
            Name     = $srv.Name
            Platform = $srv.Platform
            PreReq   = $srv.PreReq
            Install  = $srv.Install
            ArcReg   = $srv.ArcReg
            Agent    = $srv.Agent
            HIMDS    = $srv.HIMDS
        }
        $nodeList.Add($nodeHash)

        # Collect events
        if ($srv.Events) {
            foreach ($evt in $srv.Events) {
                $allEvents.Add(@{
                    Node     = $evt.Node
                    Message  = $evt.Message
                    Severity = $evt.Severity
                })
            }
        }

        # Count status
        switch ($srv.Phase) {
            "Done"    { $done++ }
            "Failed"  { $failed++ }
            "Skipped" { $failed++ }
            default   { $running++ }
        }
    }

    # Build download progress if available
    $downloads = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($srv in $state.Servers) {
        if ($srv.Install -eq "Downloading" -or $srv.Install -eq "Succeeded" -or $srv.Install -eq "InProgress") {
            $pct = switch ($srv.Install) {
                "Downloading" { 50 }
                "InProgress"  { 75 }
                "Succeeded"   { 100 }
                default       { 0 }
            }
            $downloads.Add(@{
                Node    = $srv.Name.Substring(0, [Math]::Min(10, $srv.Name.Length))
                Percent = $pct
                SizeMB  = 0
                Status  = $srv.Install
            })
        }
    }

    $subtitle = if ($state.Message) { $state.Message } else { "Live - PreReq | Install | Connect | Verify" }

    $dashState = @{
        Title        = "ARC ONBOARDING MONITOR"
        Subtitle     = $subtitle
        Mode         = "OnPrem"
        NodeCount    = $state.Servers.Count
        Elapsed      = $elapsed
        CurrentPoll  = $pollCount
        MaxPoll      = $MaxPolls
        Nodes        = $nodeList
        Columns      = $columns
        Downloads    = $downloads
        Events       = $allEvents
        Running      = $running
        Succeeded    = $done
        Failed       = $failed
        NextRefreshSeconds = $PollInterval
    }

    Show-ArcDashboard -State $dashState

    # Exit if all servers reached a final state and onboarding flagged complete
    if ($state.Complete -eq $true) {
        Write-Host ""
        if ($failed -eq 0 -and $done -gt 0) {
            Write-Host "  === ALL SERVERS ONBOARDED SUCCESSFULLY ===" -ForegroundColor Green
        }
        elseif ($done -gt 0) {
            Write-Host "  === ONBOARDING COMPLETE: $done succeeded, $failed failed ===" -ForegroundColor Yellow
        }
        else {
            Write-Host "  === ONBOARDING FINISHED: $failed failed ===" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "  This window will close in 30 seconds, or press any key..." -ForegroundColor DarkGray
        [Console]::CursorVisible = $true
        $waitEnd = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $waitEnd) {
            if ([Console]::KeyAvailable) { break }
            Start-Sleep -Milliseconds 500
        }
        exit 0
    }

    Start-Sleep -Seconds $PollInterval
}

