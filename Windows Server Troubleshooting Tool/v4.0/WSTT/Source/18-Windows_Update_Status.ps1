# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Windows Update Status
# Source lines: 5277 - 5579
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Windows Update Status
function Test-WindowsUpdateStatus {
    <#
    .SYNOPSIS
        Checks Windows Update status and history
    .DESCRIPTION
        Shows recent updates, pending reboot status, days since last update,
        and Windows Update service status
    .EXAMPLE
        Test-WindowsUpdateStatus
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "Windows Update Status"
    
    # Windows Update service status
    Write-Info "Windows Update Service Status:"
    try {
        $wuService = Get-Service -Name "wuauserv" -ErrorAction Stop
        $bitsService = Get-Service -Name "BITS" -ErrorAction Stop
        
        Write-Info "  Windows Update (wuauserv): $($wuService.Status) ($($wuService.StartType))"
        Write-Info "  BITS: $($bitsService.Status) ($($bitsService.StartType))"
    }
    catch {
        Write-DiagError "Failed to check Windows Update services: $($_.Exception.Message)"
    }
    
    # Last installed updates
    Write-Section "Last 10 Installed Updates"
    try {
        $updates = Get-HotFix -ErrorAction Stop |
            Where-Object { $null -ne $_.InstalledOn } |
            Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue |
            Select-Object -First 10
        # Also get updates with null dates (common on Server 2019)
        $nullDateUpdates = Get-HotFix -ErrorAction SilentlyContinue |
            Where-Object { $null -eq $_.InstalledOn } |
            Select-Object -First 5
        
        if ($updates) {
            foreach ($update in $updates) {
                $installedDate = if ($null -ne $update.InstalledOn) { 
                    $update.InstalledOn.ToString('yyyy-MM-dd') 
                }
                else { 
                    "Unknown date" 
                }
                Write-Info "  $($update.HotFixID) - $installedDate - $($update.Description)"
            }
            
            # Days since last update
            $lastUpdate = $updates | Where-Object { $null -ne $_.InstalledOn } | Select-Object -First 1
            if ($null -ne $lastUpdate -and $null -ne $lastUpdate.InstalledOn) {
                $daysSinceUpdate = [math]::Round(((Get-Date) - $lastUpdate.InstalledOn).TotalDays, 0)
                Write-Info "`n  Days since last update: $daysSinceUpdate"
                
                if ($daysSinceUpdate -gt 90) {
                    Write-DiagError "  CRITICAL: Server has not been updated in over 90 days!"
                }
                elseif ($daysSinceUpdate -gt 30) {
                    Write-DiagWarning "  WARNING: Server has not been updated in over 30 days"
                }
                else {
                    Write-Success "  Server is up to date (last updated $daysSinceUpdate days ago)"
                }
            }
        }
        else {
            Write-DiagWarning "  No hotfix information available (with known install dates)"
        }
        # Show updates with unknown dates (common Server 2019 bug)
        if ($nullDateUpdates -and @($nullDateUpdates).Count -gt 0) {
            Write-Info "  Updates with unknown install date (Server 2019 known issue):"
            foreach ($ndu in $nullDateUpdates) {
                Write-Info "    $($ndu.HotFixID) - (date unavailable) - $($ndu.Description)"
            }
        }
    }
    catch {
        Write-DiagError "Failed to retrieve update history: $($_.Exception.Message)"
    }
    
    # Pending reboot check
    Write-Section "Pending Reboot Check"
    try {
        $pendingReboot = $false
        $reasons = @()
        
        # Check Component Based Servicing
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $pendingReboot = $true
            $reasons += "Component Based Servicing"
        }
        
        # Check Windows Update
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $pendingReboot = $true
            $reasons += "Windows Update"
        }
        
        # Check PendingFileRenameOperations
        try {
            $pfro = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
            if ($null -ne $pfro) {
                $pendingReboot = $true
                $reasons += "Pending File Rename Operations"
            }
        }
        catch { }
        
        if ($pendingReboot) {
            Write-DiagWarning "  REBOOT PENDING!"
            Write-DiagWarning "  Reasons: $($reasons -join ', ')"
        }
        else {
            Write-Success "  No pending reboot detected"
        }
    }
    catch {
        Write-DiagWarning "  Could not determine pending reboot status: $($_.Exception.Message)"
    }
    
    # OS version info
    Write-Section "OS Version Information"
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        Write-Info "  OS: $($os.Caption)"
        Write-Info "  Version: $($os.Version)"
        Write-Info "  Build: $($os.BuildNumber)"
        Write-Info "  Last Boot: $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        
        $uptime = (Get-Date) - $os.LastBootUpTime
        Write-Info "  Uptime: $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
        
        if ($uptime.TotalDays -gt 90) {
            Write-DiagWarning "  WARNING: Server has been running for over 90 days without restart"
        }
    }
    catch {
        Write-DiagError "Failed to retrieve OS information: $($_.Exception.Message)"
    }

    # CBS Store Health
    Write-Section "CBS Store Health"
    try {
        $cbsLog = "$env:SystemRoot\Logs\CBS\CBS.log"
        if (Test-Path $cbsLog) {
            $cbsErrors = Get-Content $cbsLog -Tail 200 | Select-String -Pattern '\bERROR\b' -AllMatches
            if ($cbsErrors.Count -gt 10) {
                Write-DiagWarning "  CBS.log has $($cbsErrors.Count) ERROR entries in last 200 lines"
                Write-Info "  Run: DISM /Online /Cleanup-Image /CheckHealth"
            }
            else {
                Write-Success "  CBS store appears healthy"
            }
        }
    }
    catch {
        Write-Info "  Could not check CBS store"
    }

    # Pending.xml Check
    Write-Section "Pending.xml Check"
    try {
        $pendingXml = "$env:SystemRoot\WinSxS\pending.xml"
        if (Test-Path $pendingXml) {
            $fileSize = [math]::Round((Get-Item $pendingXml).Length / 1KB, 1)
            Write-DiagWarning "  pending.xml EXISTS ($fileSize KB) - this can block role installations and updates"
            Write-Info "  If stale, a reboot should clear it. If persistent, CBS repair may be needed."
        }
        else {
            Write-Success "  No pending.xml found (good)"
        }
    }
    catch { }

    # Legacy OS Detection
    Write-Section "OS Lifecycle Check"
    try {
        $build = [int]$os.BuildNumber
        if ($build -lt 14393) {
            Write-DiagError "  OS Build $build (Server 2012/2012 R2 or older) - End of extended support"
            Write-Info "  Strongly recommend in-place upgrade or migration to Server 2022/2025"
        }
        elseif ($build -lt 17763) {
            Write-DiagWarning "  OS Build $build (Server 2016) - Approaching end of mainstream support"
            Write-Info "  Plan upgrade to Server 2022 or 2025"
        }
        elseif ($build -lt 20348) {
            Write-Info "  OS Build $build (Server 2019) - Supported (extended support until Oct 2029)"
        }
        elseif ($build -lt 26100) {
            Write-Success "  OS Build $build (Server 2022) - Fully supported"
        }
        elseif ($build -ge 26100) {
            Write-Success "  OS Build $build (Server 2025) - Latest release"
        }
        else {
            Write-Info "  OS Build $build - version not recognized"
        }
    }
    catch { }

    # Failed Update Events
    Write-Section "Failed Update Events (last 7 days)"
    try {
        $updateFail = Get-WinEvent -FilterHashtable @{
            LogName   = 'Setup'
            Level     = 1, 2, 3
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($updateFail) {
            Write-DiagWarning "  Found $($updateFail.Count) failed setup/update event(s):"
            foreach ($evt in $updateFail) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $evt -MaxLength 100)"
            }
        }
        else {
            Write-Success "  No failed update events"
        }
    }
    catch {
        Write-Info "  Could not query Setup event log"
    }
}

function Start-WindowsUpdateLogCollection {
    <#
    .SYNOPSIS
        Starts Windows Update related log collection
    .DESCRIPTION
        Provides options for Windows Update trace and CBS log collection
    #>
    Write-Header "Windows Update Log Collection"
    
    Write-Info "Windows Update Log Collection Options:"
    Write-Host "1. Collect CBS and DISM logs" -ForegroundColor Yellow
    Write-Host "2. TSS DND_SetupReport collection" -ForegroundColor Yellow
    Write-Host "3. Generate WindowsUpdate.log (Windows 10/Server 2016+)" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-3)" -ValidChoices @("1", "2", "3")
    
    switch ($choice) {
        "1" {
            $exportPath = Join-Path $script:DefaultLogPath "WULogs_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            if (Test-PathValid -Path $exportPath -CreateIfNotExist) {
                try {
                    $cbsSource = Join-Path $env:SystemRoot "Logs\CBS\CBS.log"
                    $dismSource = Join-Path $env:SystemRoot "Logs\DISM\DISM.log"
                    
                    if (Test-Path $cbsSource) {
                        Copy-Item $cbsSource -Destination $exportPath -ErrorAction Stop
                        Write-Success "  Copied CBS.log"
                    }
                    else {
                        Write-DiagWarning "  CBS.log not found"
                    }
                    
                    if (Test-Path $dismSource) {
                        Copy-Item $dismSource -Destination $exportPath -ErrorAction Stop
                        Write-Success "  Copied DISM.log"
                    }
                    else {
                        Write-DiagWarning "  DISM.log not found"
                    }
                    
                    Write-Success "Logs collected to: $exportPath"
                }
                catch {
                    Write-DiagError "Failed to collect Windows Update logs: $($_.Exception.Message)"
                }
            }
        }
        "2" {
            Invoke-WithTSSCheck `
                -TSSCommand "-Collectlog DND_SetupReport -AcceptEula" `
                -ManualAlternativeAction {
                Write-Info "Manual: Check C:\Windows\Logs\CBS\CBS.log"
                Write-Info "        Check C:\Windows\Logs\DISM\DISM.log"
                Write-Info "        Run: DISM /online /Cleanup-image /CheckHealth"
            } `
                -Description "Starting TSS DND_SetupReport collection..."
        }
        "3" {
            try {
                $wuLogPath = Join-Path $script:DefaultLogPath "WindowsUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                if (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist) {
                    Write-Info "Generating WindowsUpdate.log (this may take a moment)..."
                    Get-WindowsUpdateLog -LogPath $wuLogPath -ErrorAction Stop
                    Write-Success "WindowsUpdate.log generated: $wuLogPath"
                }
            }
            catch {
                Write-DiagError "Failed to generate WindowsUpdate.log: $($_.Exception.Message)"
                Write-Info "This feature requires Windows 10/Server 2016 or later"
            }
        }
    }
}
#endregion
