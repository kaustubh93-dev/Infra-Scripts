# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Additional Scenarios
# Source lines: 5790 - 5983
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Additional Scenarios
function Show-AdditionalScenarios {
    <#
    .SYNOPSIS
        Displays additional troubleshooting scenarios menu
    .DESCRIPTION
        Provides options for reboot, crash, SQL, cluster, patching, and other scenarios
    #>
    Write-Header "Additional Troubleshooting Scenarios"
    
    Write-Host "1. Unexpected Reboot" -ForegroundColor Yellow
    Write-Host "2. Boot Time Issues / Slow Logon" -ForegroundColor Yellow
    Write-Host "3. Server Crash / BugCheck / Hang" -ForegroundColor Yellow
    Write-Host "4. Application Crash" -ForegroundColor Yellow
    Write-Host "5. SQL Related Issues" -ForegroundColor Yellow
    Write-Host "6. Cluster Related Issues" -ForegroundColor Yellow
    Write-Host "7. OS Patch Issues" -ForegroundColor Yellow
    Write-Host "8. Server Assessment" -ForegroundColor Yellow
    Write-Host "9. Export Event Logs" -ForegroundColor Yellow
    Write-Host "0. Return to Main Menu" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (0-9)" -ValidChoices @("0", "1", "2", "3", "4", "5", "6", "7", "8", "9")
    
    $tssAvailable = Test-TSSAvailable
    
    switch ($choice) {
        "1" {
            Write-Info "Unexpected Reboot Log Collection:"
            if ($tssAvailable) {
                Write-Info "Collect memory dump and run:"
                Write-Host "TSS.ps1 -SDP Perf -AcceptEula" -ForegroundColor Cyan
                Write-Host "TSS.ps1 -SDP Setup -AcceptEula" -ForegroundColor Cyan
                Write-Host "TSS.ps1 -Collectlog DND_Setup" -ForegroundColor Cyan
            }
            else {
                Write-DiagWarning "TSS is not available. Install TSS from the main menu (option 15)."
            }
            Write-Info "Ensure to collect Memory.dmp from C:\Windows\ and minidump files from C:\Windows\Minidump\"
        }
        "2" {
            Write-Info "Slow Boot/Slow Logon (<30 minutes):"
            if ($tssAvailable) {
                Write-Host "TSS.ps1 -Start -Scenario ADS_SBSL" -ForegroundColor Cyan
                Write-Info "This will prompt for reboot. After reboot, stop with: TSS.ps1 -Stop"
                $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
                if ($confirm -eq "Y") {
                    Invoke-TSSCommand -Command "-Start -Scenario ADS_SBSL"
                }
            }
            else {
                Write-DiagWarning "TSS is not available. Install TSS from the main menu (option 15)."
            }
            Write-Info "`nFor boot-time issues:"
            Write-Host "TSS.ps1 -StartAutoLogger -Procmon -WPR General -Netsh" -ForegroundColor Cyan
            Write-Info "Restart (not shutdown), then stop after boot: TSS.ps1 -Stop"
        }
        "3" {
            Write-Info "Server Crash/BugCheck/Hang:"
            Write-Info "1. Configure Complete Memory Dump:"
            Write-Info "   Control Panel > System > Advanced > Startup and Recovery"
            Write-Info "   Set 'Complete memory dump' under Writing Debugging Information"
            Write-Info "2. Restart and wait for crash to occur"
            Write-Info "3. Collect dump from C:\Windows\Memory.dmp"
            if ($tssAvailable) {
                Write-Info "4. After reboot, run: TSS.ps1 -SDP Perf -AcceptEula"
            }
        }
        "4" {
            Write-Info "Application Crash Log Collection:"
            Write-Info "1. Download ProcDump: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump"
            Write-Info "2. Set as default debugger: procdump -ma -i -accepteula c:\dumps"
            Write-Info "3. Reproduce crash (collect 2-3 dumps)"
            Write-Info "4. Uninstall: procdump.exe -u"
            if ($tssAvailable) {
                Write-Info "5. Also collect: TSS.ps1 -SDP Perf -AcceptEula"
            }
        }
        "5" {
            Write-Info "SQL Related Issues:"
            if ($tssAvailable) {
                Write-Host "TSS.ps1 -SDP SQLBase -noPSR -AcceptEula" -ForegroundColor Cyan
                Write-Info "For SQL on Failover Cluster:"
                Write-Host "TSS.ps1 -SDP Cluster,SQLBase -AcceptEula" -ForegroundColor Cyan
            }
            else {
                Write-DiagWarning "TSS is not available. Install TSS from the main menu (option 15)."
                Write-Info "Manual: Collect SQL Server error logs from the SQL Server log directory."
            }
        }
        "6" {
            Write-Info "Cluster Related Issues:"
            if ($tssAvailable) {
                Write-Host "TSS.ps1 -SDP Cluster -AcceptEula" -ForegroundColor Cyan
                Write-Info "Run on ALL cluster nodes"
                if ($script:ClusterEnv.IsClusterNode) {
                    $activeOwners = @()
                    try {
                        $activeOwners = Get-ClusterGroup -ErrorAction SilentlyContinue | Where-Object { $_.OwnerNode -eq $env:COMPUTERNAME -and $_.State -eq 'Online' }
                    }
                    catch { }
                    if ($activeOwners) {
                        Write-DiagWarning "This node owns $(@($activeOwners).Count) active cluster group(s). Consider running on a passive node first:"
                        $activeOwners | Select-Object -First 5 | ForEach-Object { Write-Info "    $($_.Name): $($_.State)" }
                    }
                }
            }
            else {
                Write-DiagWarning "TSS is not available. Install TSS from the main menu (option 15)."
            }
            Write-Info "`nCluster Logs:"
            $clusterLogDest = Join-Path $env:TEMP "clusterlog"
            Write-Host "Get-ClusterLog -TimeSpan 60 -UseLocalTime -Destination $clusterLogDest" -ForegroundColor Cyan
            Write-DiagWarning "Note: Avoid using Cluster Shared Volumes as the destination"
            Write-Info "`nFor Event 1135 (intermittent):"
            Write-Host "TSS.ps1 -Scenario SHA_MsCluster -WaitEvent Evt:1135:System -AcceptEula" -ForegroundColor Cyan
            Write-Info "Generate Cluster Validation Report from Failover Cluster Manager"
        }
        "7" {
            Write-Info "OS Patch Issues:"
            Write-Info "Basic Troubleshooting Steps:"
            Write-Info "1. Mount Windows ISO and run:"
            Write-Host "   DISM /online /Cleanup-image /RestoreHealth /Source:<ISO_Drive>:\source\sxs" -ForegroundColor Cyan
            Write-Info "2. Run SFC scan:"
            Write-Host "   sfc /scannow" -ForegroundColor Cyan
            Write-Info "3. Reset Windows Update components:"
            if ($script:ClusterEnv.IsClusterNode) {
                Write-DiagWarning "CLUSTER NODE DETECTED: If Cluster-Aware Updating (CAU) is active, do NOT manually stop Windows Update services."
                Write-Info "  Use Failover Cluster Manager > Cluster-Aware Updating instead."
            }
            Write-Host @"
   net stop wuauserv
   net stop bits
   net stop cryptsvc
   Rename %systemroot%\SoftwareDistribution folder
   net start wuauserv
   net start bits
   net start cryptsvc
"@ -ForegroundColor Cyan
            if ($tssAvailable) {
                Write-Info "4. Collect logs:"
                Write-Host "TSS.ps1 -Collectlog DND_SetupReport -AcceptEula" -ForegroundColor Cyan
            }
            Write-Info "5. Check logs: C:\Windows\Logs\CBS\CBS.log, C:\Windows\Logs\DISM\DISM.log, and Setup event log"
        }
        "8" {
            Write-Info "Server Assessment:"
            Write-Info "Collect 4-hour perfmon with 1-minute interval + validator script"
            if ($tssAvailable) {
                Write-Host "Get-psSDP.ps1 Perf -savePath D:\MS_DATA" -ForegroundColor Cyan
                Write-Host "TSS.ps1 -sdp ALL -LogFolderPath E:\MS_Data" -ForegroundColor Cyan
            }
            Show-PerfmonCommand "Assessment"
        }
        "9" {
            Write-Info "Export Event Logs:"
            $exportPath = Read-Host "Enter export path (e.g., D:\EventLogs) or press Enter for default"
            
            if ([string]::IsNullOrWhiteSpace($exportPath)) {
                $exportPath = Join-Path $script:DefaultLogPath "EventLogs"
            }
            
            if (Test-PathValid -Path $exportPath -CreateIfNotExist) {
                try {
                    $systemEvtx = Join-Path $exportPath "system.evtx"
                    $appEvtx = Join-Path $exportPath "application.evtx"
                    $secEvtx = Join-Path $exportPath "security.evtx"
                    
                    Write-Info "Exporting System event log..."
                    wevtutil epl System $systemEvtx
                    
                    Write-Info "Exporting Application event log..."
                    wevtutil epl Application $appEvtx
                    
                    Write-Info "Exporting Security event log..."
                    wevtutil epl Security $secEvtx
                    
                    Write-Success "Event logs exported to: $($exportPath)"
                }
                catch {
                    Write-DiagError "Failed to export event logs: $($_.Exception.Message)"
                }
            }
        }
        "0" {
            return
        }
    }
    
    if ($choice -ne "0") {
        Write-Host "`nPress any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}
#endregion
