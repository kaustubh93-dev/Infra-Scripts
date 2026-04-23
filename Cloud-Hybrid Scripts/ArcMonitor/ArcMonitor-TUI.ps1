#Requires -Version 5.1
<#
.SYNOPSIS
    Arc Bootstrap Monitor - TUI Rendering Engine
.DESCRIPTION
    Renders the dashboard matching the ARC BOOTSTRAP MONITOR reference design.
    Uses Unicode box-drawing for borders, colored backgrounds for progress bars.
.NOTES
    Requires UTF-8 BOM encoding and a TrueType console font (Consolas, Lucida Console).
#>

# Force UTF-8 output for Unicode box-drawing characters
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

#region -- Render Helpers

function Write-PaddedHost {
    <#
    .SYNOPSIS
        Write-Host with right-padding to console width. Overwrites stale content from previous frame.
    #>
    param(
        [string]$Text = "",
        [string]$ForegroundColor = "White",
        [switch]$NoNewline
    )
    $width = [Math]::Max(1, [Console]::WindowWidth - 1)
    $padded = if ($Text.Length -ge $width) { $Text.Substring(0, $width) } else { $Text.PadRight($width) }
    if ($NoNewline) {
        Write-Host $padded -ForegroundColor $ForegroundColor -NoNewline
    } else {
        Write-Host $padded -ForegroundColor $ForegroundColor
    }
}

function Clear-RemainingLines {
    <#
    .SYNOPSIS
        Clears lines from current cursor position to bottom of last known render area.
    #>
    param([int]$MaxLines = 5)
    $blank = " " * ([Math]::Max(1, [Console]::WindowWidth - 1))
    for ($i = 0; $i -lt $MaxLines; $i++) {
        Write-Host $blank
    }
}

#endregion

#region -- Color Helpers

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
        'Fixing'       { 'Yellow' }
        'Rechecking'   { 'Yellow' }
        'Pending'      { 'DarkYellow' }
        'Waiting'      { 'DarkGray' }
        'NotStarted'   { 'Gray' }
        'Ignored'      { 'DarkYellow' }
        'Skipped'      { 'DarkGray' }
        'Failed'       { 'Red' }
        'Error'        { 'Red' }
        'Disconnected' { 'Red' }
        'RebootPending'{ 'Cyan' }
        default        { 'White' }
    }
}

#endregion

#region -- Animated Header

$script:SpinnerChars = @([char]0x2014, '\', '|', '/')   # em-dash, backslash, pipe, slash
$script:SpinIdx = 0

function Show-AnimatedHeader {
    param(
        [string]$Title = "ARC BOOTSTRAP MONITOR",
        [string]$Subtitle = "",
        [int]$Width = 78
    )

    $script:SpinIdx = ($script:SpinIdx + 1) % $script:SpinnerChars.Count
    $spin = $script:SpinnerChars[$script:SpinIdx]

    $text = " $Title $spin "
    $innerW = $Width - 2
    $pad = $innerW - $text.Length
    $lp = [Math]::Floor($pad / 2)
    $rp = [Math]::Ceiling($pad / 2)

    $topBot = ([string][char]0x2500) * $innerW          # horizontal line
    $tl = [char]0x250C; $tr = [char]0x2510    # top-left, top-right corners
    $bl = [char]0x2514; $br = [char]0x2518    # bottom-left, bottom-right corners
    $vl = [char]0x2502                         # vertical line

    Write-Host ""
    Write-Host "  $tl$topBot$tr" -ForegroundColor DarkCyan
    Write-Host "  $vl$(' ' * $lp)$text$(' ' * $rp)$vl" -ForegroundColor Cyan
    Write-Host "  $bl$topBot$br" -ForegroundColor DarkCyan

    if ($Subtitle) {
        Write-Host "  $Subtitle" -ForegroundColor DarkGray
    }
    Write-Host ""
}

#endregion

#region -- Stats Bar

function Show-StatsBar {
    param(
        [int]$NodeCount,
        [TimeSpan]$Elapsed,
        [int]$CurrentPoll,
        [int]$MaxPoll,
        [string]$Mode = "AzureLocal"
    )

    $el = $Elapsed.ToString("hh\:mm\:ss")
    $ml = switch ($Mode) {
        'AzureLocal' { 'Azure Local' }
        'VMware'     { 'VMware vSphere' }
        'OnPrem'     { 'On-Prem Servers' }
        default      { $Mode }
    }

    Write-Host "  Nodes: " -NoNewline -ForegroundColor White
    Write-Host "$NodeCount" -NoNewline -ForegroundColor Cyan
    Write-Host "  |  Elapsed: " -NoNewline -ForegroundColor White
    Write-Host "$el" -NoNewline -ForegroundColor Yellow
    Write-Host "  |  Poll: " -NoNewline -ForegroundColor White
    Write-Host "$CurrentPoll/$MaxPoll" -ForegroundColor Cyan
    Write-Host ""
}

#endregion

#region -- Status Table

function Show-StatusTable {
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

    $vl = [char]0x2502   # vertical line
    $hl = [string][char]0x2500   # horizontal line

    # Build separator
    $sep = "  "
    foreach ($col in $Columns) { $sep += "$($hl * ($col.Width + 2))" }

    # Header
    Write-Host $sep -ForegroundColor DarkGray
    $hdr = "  "
    foreach ($col in $Columns) {
        $hdr += " $($col.Header.PadRight($col.Width)) $vl"
    }
    Write-Host $hdr -ForegroundColor White
    Write-Host $sep -ForegroundColor DarkGray

    # Data rows
    foreach ($node in $Nodes) {
        $row = "  "
        foreach ($col in $Columns) {
            $val = if ($node[$col.Key]) { [string]$node[$col.Key] } else { "----" }
            $color = if ($col.Key -eq "Name") { 'White' } else { Get-StatusColor $val }
            # Can't mix colors in one Write-Host, so output cell by cell
            Write-Host " " -NoNewline
            Write-Host "$($val.PadRight($col.Width))" -NoNewline -ForegroundColor $color
            Write-Host " $vl" -NoNewline -ForegroundColor DarkGray
        }
        Write-Host ""
    }
    Write-Host $sep -ForegroundColor DarkGray
    Write-Host ""
}

#endregion

#region -- Download Progress Bars

function Show-DownloadProgress {
    param(
        [array]$Downloads,
        [int]$BarWidth = 25
    )

    # Section header with box border
    $hl = [string][char]0x2500
    $tl = [char]0x250C; $tr = [char]0x2510
    $bl = [char]0x2514; $br = [char]0x2518
    $vl = [char]0x2502

    $boxW = 72
    Write-Host "  $tl " -NoNewline -ForegroundColor DarkYellow
    Write-Host "DOWNLOAD PROGRESS" -NoNewline -ForegroundColor Yellow
    Write-Host " $($hl * ($boxW - 22))$tr" -ForegroundColor DarkYellow
    Write-Host "  $vl" -ForegroundColor DarkYellow

    foreach ($dl in $Downloads) {
        $pct = [Math]::Min(100, [Math]::Max(0, $dl.Percent))
        $filled = [Math]::Floor($BarWidth * $pct / 100)
        $empty  = $BarWidth - $filled

        $statusColor = Get-StatusColor $dl.Status
        $label = "  $vl  $($dl.Node):".PadRight(14)

        Write-Host "$label [" -NoNewline -ForegroundColor White

        # Green background filled portion (matching the screenshot's solid green bar)
        if ($filled -gt 0) {
            Write-Host (" " * $filled) -NoNewline -ForegroundColor Black -BackgroundColor Green
        }
        # Dark empty portion
        if ($empty -gt 0) {
            Write-Host (" " * $empty) -NoNewline -ForegroundColor DarkGray -BackgroundColor Black
        }

        Write-Host "] " -NoNewline -ForegroundColor White
        Write-Host "$($pct.ToString().PadLeft(3))%" -NoNewline -ForegroundColor Cyan
        Write-Host " $($dl.SizeMB.ToString('N2')) MB" -NoNewline -ForegroundColor Gray
        Write-Host "  $($dl.Status)" -ForegroundColor $statusColor
    }

    Write-Host "  $vl" -ForegroundColor DarkYellow
    Write-Host "  $bl$($hl * $boxW)$br" -ForegroundColor DarkYellow
    Write-Host ""
}

#endregion

#region -- Events Panel

function Show-EventsPanel {
    param(
        [array]$Events
    )

    $hl = [string][char]0x2500
    $tl = [char]0x250C; $tr = [char]0x2510
    $bl = [char]0x2514; $br = [char]0x2518
    $vl = [char]0x2502

    $boxW = 72
    Write-Host "  $tl " -NoNewline -ForegroundColor DarkRed
    Write-Host "EVENTS" -NoNewline -ForegroundColor Red
    Write-Host " $($hl * ($boxW - 11))$tr" -ForegroundColor DarkRed
    Write-Host "  $vl" -ForegroundColor DarkRed

    if ($Events.Count -eq 0) {
        Write-Host "  $vl  No events." -ForegroundColor DarkGray
    }
    else {
        foreach ($evt in $Events) {
            Write-Host "  $vl  " -NoNewline -ForegroundColor DarkRed
            Write-Host "$($evt.Node): " -NoNewline -ForegroundColor White
            $color = switch ($evt.Severity) {
                'Info'     { 'Cyan' }
                'Warning'  { 'Yellow' }
                'Error'    { 'Red' }
                'Critical' { 'Magenta' }
                default    { 'White' }
            }
            Write-Host $evt.Message -ForegroundColor $color
        }
    }

    Write-Host "  $vl" -ForegroundColor DarkRed
    Write-Host "  $bl$($hl * $boxW)$br" -ForegroundColor DarkRed
    Write-Host ""
}

#endregion

#region -- Summary and Footer

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
    Write-Host ("  " + (([string][char]0x2500) * 76)) -ForegroundColor DarkGray
}

function Show-Footer {
    param(
        [int]$NextRefreshSeconds = 60
    )
    $now = Get-Date -Format "HH:mm:ss"
    Write-Host ""
    Write-Host "  Last refresh: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$now" -NoNewline -ForegroundColor White
    Write-Host "  |  Next: " -NoNewline -ForegroundColor DarkGray
    Write-Host "${NextRefreshSeconds}s" -NoNewline -ForegroundColor Yellow
    Write-Host "  |  Ctrl+C to exit" -ForegroundColor DarkGray
}

#endregion

#region -- Full Dashboard Render

# Render buffer for flicker-free differential updates
$script:RenderFrame = 0

function Show-ArcDashboard {
    param([hashtable]$State)

    # First frame: clear screen. Subsequent frames: reset cursor to top-left (no flicker)
    if ($script:RenderFrame -eq 0) {
        Clear-Host
        [Console]::CursorVisible = $false
    } else {
        [Console]::SetCursorPosition(0, 0)
    }
    $script:RenderFrame++

    $titleVal    = if ($State.Title)    { $State.Title }    else { "ARC BOOTSTRAP MONITOR" }
    $subtitleVal = if ($State.Subtitle) { $State.Subtitle } else { "" }

    Show-AnimatedHeader -Title $titleVal -Subtitle $subtitleVal

    Show-StatsBar `
        -NodeCount   $State.NodeCount `
        -Elapsed     $State.Elapsed `
        -CurrentPoll $State.CurrentPoll `
        -MaxPoll     $State.MaxPoll `
        -Mode        $(if ($State.Mode) { $State.Mode } else { "AzureLocal" })

    Show-StatusTable -Nodes $State.Nodes -Columns $State.Columns

    if ($State.Downloads -and $State.Downloads.Count -gt 0) {
        Show-DownloadProgress -Downloads $State.Downloads
    }

    if ($State.Events) {
        Show-EventsPanel -Events $State.Events
    }

    $runVal  = if ($State.Running)   { $State.Running }   else { 0 }
    $sucVal  = if ($State.Succeeded) { $State.Succeeded } else { 0 }
    $failVal = if ($State.Failed)    { $State.Failed }    else { 0 }

    Show-Summary -Running $runVal -Succeeded $sucVal -Failed $failVal

    $refreshVal = if ($State.NextRefreshSeconds) { $State.NextRefreshSeconds } else { 60 }
    Show-Footer -NextRefreshSeconds $refreshVal

    # Clear any stale lines below the current render (e.g., if downloads section disappeared)
    Clear-RemainingLines -MaxLines 8
}

#endregion

#region -- Logging

function Write-ArcLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$LogPath = ".\ArcMonitor\Logs"
    )
    try {
        if (-not (Test-Path $LogPath)) {
            New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction Stop | Out-Null
        }
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logFile = Join-Path $LogPath "ArcMonitor_$(Get-Date -Format 'yyyyMMdd').log"
        "$ts [$Level] $Message" | Add-Content -Path $logFile -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Warning "ArcMonitor logging failed: $($_.Exception.Message)"
    }
}

#endregion

Write-Host "  TUI Engine loaded." -ForegroundColor Green