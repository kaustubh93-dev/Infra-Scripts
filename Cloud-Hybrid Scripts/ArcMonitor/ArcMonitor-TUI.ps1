<#
.SYNOPSIS
    Arc Bootstrap Monitor — TUI Rendering Engine
.DESCRIPTION
    Provides the text-based dashboard UI with animated header, status tables,
    progress bars, event panels, and auto-refresh for Azure Arc onboarding monitoring.
.NOTES
    This module is consumed by all three monitor scripts (AzureLocal, VMware, OnPrem).
#>

#region ── ANSI / Color Helpers ──────────────────────────────────────────────────

function Write-ColorText {
    param(
        [string]$Text,
        [ConsoleColor]$Color = 'White',
        [switch]$NoNewline
    )
    $prev = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    if ($NoNewline) { Write-Host $Text -NoNewline }
    else { Write-Host $Text }
    $Host.UI.RawUI.ForegroundColor = $prev
}

function Get-StatusColor {
    param([string]$Status)
    switch ($Status) {
        'Succeeded'    { 'Green' }
        'Complete'     { 'Green' }
        'Connected'    { 'Green' }
        'Done'         { 'Green' }
        'Running'      { 'Green' }
        'InProgress'   { 'Yellow' }
        'Install'      { 'Yellow' }
        'Downloading'  { 'Yellow' }
        'Registering'  { 'Yellow' }
        'Pending'      { 'DarkYellow' }
        'NotStarted'   { 'Gray' }
        'Failed'       { 'Red' }
        'Error'        { 'Red' }
        'Disconnected' { 'Red' }
        'RebootPending'{ 'Cyan' }
        default        { 'White' }
    }
}

#endregion

#region ── Header ────────────────────────────────────────────────────────────────

$script:SpinnerFrames = @('—', '\', '|', '/')
$script:SpinnerIndex  = 0

function Show-AnimatedHeader {
    param(
        [string]$Title = "ARC BOOTSTRAP MONITOR",
        [string]$Subtitle = "",
        [int]$Width = 80
    )

    $script:SpinnerIndex = ($script:SpinnerIndex + 1) % $script:SpinnerFrames.Count
    $spinner = $script:SpinnerFrames[$script:SpinnerIndex]

    $headerText = " $Title $spinner "
    $pad = [Math]::Max(0, $Width - $headerText.Length - 4)
    $leftPad  = [Math]::Floor($pad / 2)
    $rightPad = [Math]::Ceiling($pad / 2)

    Write-Host ""
    Write-Host ("  ┌" + ("─" * ($Width - 4)) + "┐") -ForegroundColor DarkCyan
    Write-Host ("  │" + (" " * $leftPad) + $headerText + (" " * $rightPad) + "│") -ForegroundColor Cyan
    Write-Host ("  └" + ("─" * ($Width - 4)) + "┘") -ForegroundColor DarkCyan

    if ($Subtitle) {
        Write-Host "  $Subtitle" -ForegroundColor DarkGray
    }
    Write-Host ""
}

#endregion

#region ── Stats Bar ─────────────────────────────────────────────────────────────

function Show-StatsBar {
    param(
        [int]$NodeCount,
        [TimeSpan]$Elapsed,
        [int]$CurrentPoll,
        [int]$MaxPoll,
        [string]$Mode = "AzureLocal"  # AzureLocal | VMware | OnPrem
    )

    $elapsedStr = $Elapsed.ToString("hh\:mm\:ss")
    $modeLabel = switch ($Mode) {
        'AzureLocal' { 'Azure Local' }
        'VMware'     { 'VMware vSphere' }
        'OnPrem'     { 'On-Prem Servers' }
        default      { $Mode }
    }

    Write-Host "  Nodes: " -NoNewline -ForegroundColor White
    Write-Host "$NodeCount" -NoNewline -ForegroundColor Cyan
    Write-Host "  │  Elapsed: " -NoNewline -ForegroundColor White
    Write-Host "$elapsedStr" -NoNewline -ForegroundColor Yellow
    Write-Host "  │  Poll: " -NoNewline -ForegroundColor White
    Write-Host "$CurrentPoll/$MaxPoll" -NoNewline -ForegroundColor Cyan
    Write-Host "  │  Mode: " -NoNewline -ForegroundColor White
    Write-Host "$modeLabel" -ForegroundColor Magenta
    Write-Host ""
}

#endregion

#region ── Status Table ──────────────────────────────────────────────────────────

function Show-StatusTable {
    <#
    .SYNOPSIS
        Renders a formatted status table for node onboarding progress.
    .PARAMETER Nodes
        Array of hashtables: @{ Name; Bootstrap; Update; ArcReg; Agent; Download; ... }
    .PARAMETER Columns
        Array of column definitions: @{ Header; Key; Width }
    #>
    param(
        [array]$Nodes,
        [array]$Columns
    )

    if (-not $Columns) {
        $Columns = @(
            @{ Header = "Node";      Key = "Name";      Width = 20 }
            @{ Header = "Bootstrap"; Key = "Bootstrap";  Width = 14 }
            @{ Header = "Update";    Key = "Update";     Width = 12 }
            @{ Header = "Arc Reg";   Key = "ArcReg";     Width = 12 }
            @{ Header = "Agent";     Key = "Agent";      Width = 14 }
        )
    }

    # Header line
    $headerLine = "  │ "
    $separatorLine = "  │ "
    foreach ($col in $Columns) {
        $headerLine    += $col.Header.PadRight($col.Width) + "│ "
        $separatorLine += ("─" * $col.Width) + "│ "
    }

    $topBorder = "  ┌─" + (($Columns | ForEach-Object { "─" * $_.Width + "┬─" }) -join "") 
    $topBorder = $topBorder.TrimEnd("┬─") + "┐"

    Write-Host $separatorLine -ForegroundColor DarkGray
    Write-Host $headerLine -ForegroundColor White
    Write-Host $separatorLine -ForegroundColor DarkGray

    # Data rows
    foreach ($node in $Nodes) {
        Write-Host "  │ " -NoNewline -ForegroundColor DarkGray
        foreach ($col in $Columns) {
            $val = if ($node[$col.Key]) { $node[$col.Key] } else { "────" }
            $color = if ($col.Key -eq "Name") { 'White' } else { Get-StatusColor $val }
            $padded = $val.PadRight($col.Width)
            Write-Host $padded -NoNewline -ForegroundColor $color
            Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        }
        Write-Host ""
    }
    Write-Host $separatorLine -ForegroundColor DarkGray
    Write-Host ""
}

#endregion

#region ── Progress Bars ─────────────────────────────────────────────────────────

function Show-DownloadProgress {
    <#
    .SYNOPSIS
        Renders download progress bars for each node.
    .PARAMETER Downloads
        Array of hashtables: @{ Node; Percent; SizeMB; Status }
    #>
    param(
        [array]$Downloads,
        [int]$BarWidth = 30
    )

    Write-Host "  ┌─ " -NoNewline -ForegroundColor DarkYellow
    Write-Host "DOWNLOAD PROGRESS" -NoNewline -ForegroundColor Yellow
    Write-Host (" " + "─" * 50) -ForegroundColor DarkYellow
    Write-Host ""

    foreach ($dl in $Downloads) {
        $pct = [Math]::Min(100, [Math]::Max(0, $dl.Percent))
        $filled = [Math]::Floor($BarWidth * $pct / 100)
        $empty  = $BarWidth - $filled

        $bar = ("█" * $filled) + ("░" * $empty)
        $barColor = if ($pct -eq 100) { 'Green' } elseif ($pct -gt 50) { 'Yellow' } else { 'DarkYellow' }
        $statusColor = Get-StatusColor $dl.Status

        $label = "  $($dl.Node):".PadRight(10)
        Write-Host "$label[" -NoNewline -ForegroundColor White
        Write-Host $bar -NoNewline -ForegroundColor $barColor
        Write-Host "] " -NoNewline -ForegroundColor White
        Write-Host "$($pct.ToString().PadLeft(3))%" -NoNewline -ForegroundColor Cyan
        Write-Host " $($dl.SizeMB.ToString('N2')) MB" -NoNewline -ForegroundColor Gray
        Write-Host "  $($dl.Status)" -ForegroundColor $statusColor
    }
    Write-Host ""
}

#endregion

#region ── Events Panel ──────────────────────────────────────────────────────────

function Show-EventsPanel {
    <#
    .SYNOPSIS
        Renders the events/alerts panel.
    .PARAMETER Events
        Array of hashtables: @{ Node; Message; Severity }
        Severity: Info | Warning | Error | Critical
    #>
    param(
        [array]$Events
    )

    Write-Host "  ┌─ " -NoNewline -ForegroundColor DarkRed
    Write-Host "EVENTS" -NoNewline -ForegroundColor Red
    Write-Host (" " + "─" * 62) -ForegroundColor DarkRed
    Write-Host ""

    if ($Events.Count -eq 0) {
        Write-Host "    No events." -ForegroundColor DarkGray
    }
    else {
        foreach ($evt in $Events) {
            $icon = switch ($evt.Severity) {
                'Info'     { '○' }
                'Warning'  { '▲' }
                'Error'    { '✖' }
                'Critical' { '◆' }
                default    { '●' }
            }
            $color = switch ($evt.Severity) {
                'Info'     { 'Cyan' }
                'Warning'  { 'Yellow' }
                'Error'    { 'Red' }
                'Critical' { 'Magenta' }
                default    { 'White' }
            }
            Write-Host "    $icon $($evt.Node): " -NoNewline -ForegroundColor White
            Write-Host $evt.Message -ForegroundColor $color
        }
    }
    Write-Host ""
}

#endregion

#region ── Summary / Footer ──────────────────────────────────────────────────────

function Show-Summary {
    param(
        [int]$Running = 0,
        [int]$Succeeded = 0,
        [int]$Failed = 0
    )

    if ($Running -gt 0)   { Write-Host "  $Running Running" -ForegroundColor Green }
    if ($Succeeded -gt 0) { Write-Host "  $Succeeded Succeeded" -ForegroundColor Cyan }
    if ($Failed -gt 0)    { Write-Host "  $Failed Failed" -ForegroundColor Red }
    Write-Host ""
    Write-Host ("  " + "─" * 76) -ForegroundColor DarkGray
}

function Show-Footer {
    param(
        [int]$NextRefreshSeconds = 60
    )
    $now = Get-Date -Format "HH:mm:ss"
    Write-Host ""
    Write-Host "  Last refresh: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$now" -NoNewline -ForegroundColor White
    Write-Host "  │  Next: " -NoNewline -ForegroundColor DarkGray
    Write-Host "${NextRefreshSeconds}s" -NoNewline -ForegroundColor Yellow
    Write-Host "  │  Ctrl+C to exit" -ForegroundColor DarkGray
}

#endregion

#region ── Full Dashboard Render ─────────────────────────────────────────────────

function Render-ArcDashboard {
    <#
    .SYNOPSIS
        Renders the complete Arc Bootstrap Monitor dashboard.
    .PARAMETER State
        Hashtable with keys: Title, Subtitle, Mode, Nodes, Columns, Downloads, Events,
                             NodeCount, Elapsed, CurrentPoll, MaxPoll, Running, Succeeded, Failed
    #>
    param([hashtable]$State)

    Clear-Host

    Show-AnimatedHeader `
        -Title    ($State.Title    ?? "ARC BOOTSTRAP MONITOR") `
        -Subtitle ($State.Subtitle ?? "")

    Show-StatsBar `
        -NodeCount   $State.NodeCount `
        -Elapsed     $State.Elapsed `
        -CurrentPoll $State.CurrentPoll `
        -MaxPoll     $State.MaxPoll `
        -Mode        ($State.Mode ?? "AzureLocal")

    Show-StatusTable `
        -Nodes   $State.Nodes `
        -Columns $State.Columns

    if ($State.Downloads -and $State.Downloads.Count -gt 0) {
        Show-DownloadProgress -Downloads $State.Downloads
    }

    if ($State.Events) {
        Show-EventsPanel -Events $State.Events
    }

    Show-Summary `
        -Running   ($State.Running   ?? 0) `
        -Succeeded ($State.Succeeded ?? 0) `
        -Failed    ($State.Failed    ?? 0)

    Show-Footer -NextRefreshSeconds ($State.NextRefreshSeconds ?? 60)
}

#endregion

#region ── Logging ───────────────────────────────────────────────────────────────

function Write-ArcLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$LogPath = ".\ArcMonitor\Logs"
    )
    if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $LogPath "ArcMonitor_$(Get-Date -Format 'yyyyMMdd').log"
    "$ts [$Level] $Message" | Add-Content -Path $logFile
}

#endregion

Write-Host "✓ TUI Engine loaded." -ForegroundColor Green
