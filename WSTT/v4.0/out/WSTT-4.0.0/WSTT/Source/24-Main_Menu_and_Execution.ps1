# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Main Menu and Execution
# Source lines: 7765 - 8105
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Main Menu and Execution
function Show-MainMenu {
    <#
    .SYNOPSIS
        Displays the main menu
    .DESCRIPTION
        Shows all available diagnostic and troubleshooting options
    #>
    Clear-Host
    Write-Host @"

                                                                
     WINDOWS SERVER TROUBLESHOOTING & LOG COLLECTION TOOL       
                         Version 4.0
                                                                

"@ -ForegroundColor Cyan

    Write-Host "
PRIMARY DIAGNOSTICS:" -ForegroundColor Yellow
    Write-Host "  1. Network Issues (Packet Loss, Slowness, RSS, MTU, Routing & 15+ checks)" -ForegroundColor White
    Write-Host "  2. Memory Issues (Usage, Leaks, Page File, Hardware & 19 checks)" -ForegroundColor White
    Write-Host "  3. CPU Issues (Per-Core, Queue, Interrupts, Throttling & 24 checks)" -ForegroundColor White
    Write-Host "  4. Disk/Storage Issues (IOPS, Latency, SMART, VSS, MPIO & 24 checks)" -ForegroundColor White
    Write-Host "  5. Windows Services Health" -ForegroundColor White
    Write-Host "  6. Event Log Analysis" -ForegroundColor White
    Write-Host "  7. DNS Health & Connectivity" -ForegroundColor White
    Write-Host "  8. Security & Authentication" -ForegroundColor White
    Write-Host "  9. Windows Update Status" -ForegroundColor White
    Write-Host " 10. Cross-Category Health Scorecard" -ForegroundColor Green
    
    Write-Host "
ADDITIONAL SCENARIOS:" -ForegroundColor Yellow
    Write-Host " 11. Additional Troubleshooting Scenarios" -ForegroundColor White
    Write-Host "     (Reboot, Crash, SQL, Cluster, Patching, etc.)" -ForegroundColor Gray
    
    Write-Host "
UTILITIES:" -ForegroundColor Yellow
    Write-Host " 12. Generate System Report" -ForegroundColor White
    Write-Host " 13. TLS Configuration Validation" -ForegroundColor White
    Write-Host " 14. Validator Script Information" -ForegroundColor White
    Write-Host " 15. Configure TSS Path" -ForegroundColor White
    Write-Host " 16. Check TSS Status" -ForegroundColor White
    Write-Host " 17. Check .NET Framework Versions" -ForegroundColor White
    Write-Host " 18. IIS Troubleshooting & Diagnostics" -ForegroundColor White
    Write-Host " 19. Task Scheduler Diagnostics" -ForegroundColor White
    Write-Host " 20. Server Baseline Validation" -ForegroundColor White
    Write-Host " 21. Generate HTML Diagnostic Report" -ForegroundColor Green

    Write-Host "
v4.0 ROLE-AWARE & MODERN AUDITS:" -ForegroundColor Yellow
    Write-Host " 22. Active Directory Health (DC role)" -ForegroundColor White
    Write-Host " 23. Hyper-V Host Health" -ForegroundColor White
    Write-Host " 24. Advanced Storage (S2D / Dedup / ReFS / SR / QoS)" -ForegroundColor White
    Write-Host " 25. Modern Security Posture (VBS/HVCI/CG/LSA-PPL/ASR/BitLocker/LAPS)" -ForegroundColor White
    Write-Host " 26. Server 2025 Feature Audit (Hotpatch/dMSA/SMB-QUIC/NetATC/GPU-P)" -ForegroundColor White
    Write-Host " 27. Certificates & PKI Health" -ForegroundColor White
    Write-Host " 28. Hybrid / Azure Arc Health" -ForegroundColor White
    Write-Host " 29. Patching Depth & Lifecycle" -ForegroundColor White

    Write-Host "
v4.0 OUTPUT & AUTOMATION:" -ForegroundColor Yellow
    Write-Host " 30. Multi-Server Remoting Mode" -ForegroundColor Cyan
    Write-Host " 31. Export Diagnostics (JSON / NDJSON / CSV / SARIF-lite)" -ForegroundColor Cyan
    Write-Host " 32. Unattended / Scheduled Mode Helper" -ForegroundColor Cyan

    Write-Host "
  0. Exit" -ForegroundColor Red

    Write-Host ("`n" + "=" * 65) -ForegroundColor Cyan
}

function Start-TroubleshootingTool {
    <#
    .SYNOPSIS
        Main entry point for the troubleshooting tool
    .DESCRIPTION
        Initializes the tool, checks prerequisites, and displays the main menu
    .PARAMETER EnableLogging
        If specified, enables transcript logging
    .EXAMPLE
        Start-TroubleshootingTool
        Start-TroubleshootingTool -EnableLogging
    #>
    param(
        [switch]$EnableLogging
    )
    
    # Check if running as admin
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-DiagError "This script requires Administrator privileges!"
        Write-Info "Please run PowerShell as Administrator and try again."
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Initialize diagnostic paths
    if (-not (Initialize-DiagnosticPaths)) {
        Write-DiagError "Failed to initialize diagnostic paths. Some features may not work correctly."
    }
    
    # Detect cluster and SQL AG environment once at startup
    Write-Info "Detecting cluster and SQL AG environment..."
    $script:ClusterEnv = Get-ClusterEnvironmentInfo
    if ($script:ClusterEnv.IsClusterNode) {
        Write-Success "Cluster node detected: $($script:ClusterEnv.ClusterName)"
        if ($script:ClusterEnv.IsAGInstalled -and $script:ClusterEnv.LocalReplicaRole) {
            Write-Info "  SQL AG Role: $($script:ClusterEnv.LocalReplicaRole)"
        }
    }
    else {
        Write-Info "Standalone server (no cluster detected)"
    }
    
    # Locale check — warn if non-English (some checks parse English command output)
    $osLocale = (Get-Culture).Name
    if ($osLocale -notlike "en-*") {
        Write-DiagWarning "Non-English locale detected ($osLocale). Some checks (w32tm, klist, netsh, secedit) parse English output and may report incomplete results."
    }
    
    # Start transcript logging if requested
    $transcriptPath = $null
    if ($EnableLogging) {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $transcriptPath = Join-Path $script:DefaultLogPath "TroubleshootingTool_$($timestamp).log"
        try {
            Start-Transcript -Path $transcriptPath -ErrorAction Stop
            Write-Success "Transcript logging enabled: $($transcriptPath)"
        }
        catch {
            Write-DiagWarning "Could not start transcript logging: $($_.Exception.Message)"
            $EnableLogging = $false
        }
    }
    
    try {
        do {
            Show-MainMenu
            $choice = Get-ValidatedChoice -Prompt "`nSelect an option (0-32)" -ValidChoices @("0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32")
            
            switch ($choice) {
                "1" {
                    Clear-Host
                    Test-NetworkConfiguration
                    Write-Host "`n"
                    $saveChoice = Get-ValidatedChoice -Prompt "Save network analysis to file? (Y/N)" -ValidChoices @("Y", "N")
                    if ($saveChoice -eq "Y") {
                        Export-DiagnosticSection -Title "Network_Analysis" -ScriptBlock { Test-NetworkConfiguration }
                    }
                    Write-Host "`n"
                    Start-NetworkLogCollection
                }
                "2" {
                    Clear-Host
                    Test-MemoryUsage
                    Write-Host "`n"
                    $saveChoice = Get-ValidatedChoice -Prompt "Save memory analysis to file? (Y/N)" -ValidChoices @("Y", "N")
                    if ($saveChoice -eq "Y") {
                        Export-DiagnosticSection -Title "Memory_Analysis" -ScriptBlock { Test-MemoryUsage }
                    }
                    Write-Host "`n"
                    Start-MemoryLogCollection
                }
                "3" {
                    Clear-Host
                    Test-CPUUsage
                    Write-Host "`n"
                    $saveChoice = Get-ValidatedChoice -Prompt "Save CPU analysis to file? (Y/N)" -ValidChoices @("Y", "N")
                    if ($saveChoice -eq "Y") {
                        Export-DiagnosticSection -Title "CPU_Analysis" -ScriptBlock { Test-CPUUsage }
                    }
                    Write-Host "`n"
                    Start-CPULogCollection
                }
                "4" {
                    Clear-Host
                    Test-DiskPerformance
                    Write-Host "`n"
                    $saveChoice = Get-ValidatedChoice -Prompt "Save disk analysis to file? (Y/N)" -ValidChoices @("Y", "N")
                    if ($saveChoice -eq "Y") {
                        Export-DiagnosticSection -Title "Disk_Analysis" -ScriptBlock { Test-DiskPerformance }
                    }
                    Write-Host "`n"
                    Start-DiskLogCollection
                }
                "5" {
                    Clear-Host
                    Test-ServicesHealth
                    Write-Host "`n"
                    $saveChoice = Get-ValidatedChoice -Prompt "Save services health to file? (Y/N)" -ValidChoices @("Y", "N")
                    if ($saveChoice -eq "Y") {
                        Export-DiagnosticSection -Title "Services_Health" -ScriptBlock { Test-ServicesHealth }
                    }
                    Write-Host "`n"
                    Start-ServicesLogCollection
                }
                "6" {
                    Clear-Host
                    Test-EventLogHealth
                    Write-Host "`n"
                    $saveChoice = Get-ValidatedChoice -Prompt "Save event log analysis to file? (Y/N)" -ValidChoices @("Y", "N")
                    if ($saveChoice -eq "Y") {
                        Export-DiagnosticSection -Title "EventLog_Analysis" -ScriptBlock { Test-EventLogHealth }
                    }
                    Write-Host "`n"
                    Start-EventLogCollection
                }
                "7" {
                    Clear-Host
                    Test-DNSHealth
                    Write-Host "`n"
                    $saveChoice = Get-ValidatedChoice -Prompt "Save DNS health to file? (Y/N)" -ValidChoices @("Y", "N")
                    if ($saveChoice -eq "Y") {
                        Export-DiagnosticSection -Title "DNS_Health" -ScriptBlock { Test-DNSHealth }
                    }
                    Write-Host "`n"
                    Start-DNSLogCollection
                }
                "8" {
                    Clear-Host
                    Test-SecurityAuthentication
                    Write-Host "`n"
                    $saveChoice = Get-ValidatedChoice -Prompt "Save security authentication to file? (Y/N)" -ValidChoices @("Y", "N")
                    if ($saveChoice -eq "Y") {
                        Export-DiagnosticSection -Title "Security_Authentication" -ScriptBlock { Test-SecurityAuthentication }
                    }
                    Write-Host "`n"
                    Start-SecurityLogCollection
                }
                "9" {
                    Clear-Host
                    Test-WindowsUpdateStatus
                    Write-Host "`n"
                    $saveChoice = Get-ValidatedChoice -Prompt "Save Windows Update status to file? (Y/N)" -ValidChoices @("Y", "N")
                    if ($saveChoice -eq "Y") {
                        Export-DiagnosticSection -Title "Windows_Update" -ScriptBlock { Test-WindowsUpdateStatus }
                    }
                    Write-Host "`n"
                    Start-WindowsUpdateLogCollection
                }
                "10" {
                    Clear-Host
                    Test-CrossCategoryHealth
                }
                "11" {
                    Clear-Host
                    Show-AdditionalScenarios
                }
                "12" {
                    Clear-Host
                    Export-SystemReport
                }
                "13" {
                    Clear-Host
                    Test-TLSConfiguration
                    Write-Host "`n"
                    $export = Get-ValidatedChoice -Prompt "Export TLS report? (Y/N)" -ValidChoices @("Y", "N")
                    if ($export -eq "Y") {
                        Export-TLSReport
                    }
                }
                "14" {
                    Clear-Host
                    Show-ValidatorInfo
                }
                "15" {
                    Clear-Host
                    Set-TSSPath
                }
                "16" {
                    Clear-Host
                    $null = Test-TSSAvailable
                }
                "17" {
                    Clear-Host
                    Get-DotNetFrameworkVersion
                }
                "18" {
                    Clear-Host
                    Test-IISHealth
                }
                "19" {
                    Clear-Host
                    Test-TaskSchedulerHealth
                }
                "20" {
                    Clear-Host
                    Test-ServerBaseline
                }
                "21" {
                    Clear-Host
                    Export-HTMLReport
                }
                "22" { Clear-Host; Test-ActiveDirectoryHealth;       Invoke-PostCheckExport -Title 'AD_Health' }
                "23" { Clear-Host; Test-HyperVHostHealth;            Invoke-PostCheckExport -Title 'HyperV_Health' }
                "24" { Clear-Host; Test-AdvancedStorageHealth;       Invoke-PostCheckExport -Title 'Advanced_Storage' }
                "25" { Clear-Host; Test-ModernSecurityPosture;       Invoke-PostCheckExport -Title 'Modern_Security' }
                "26" { Clear-Host; Test-Server2025FeatureAudit;      Invoke-PostCheckExport -Title 'Server2025_Audit' }
                "27" { Clear-Host; Test-CertificateAndPKIHealth;     Invoke-PostCheckExport -Title 'PKI_Health' }
                "28" { Clear-Host; Test-AzureArcHybridHealth;        Invoke-PostCheckExport -Title 'Arc_Hybrid' }
                "29" { Clear-Host; Test-PatchingDepthAndLifecycle;   Invoke-PostCheckExport -Title 'Patching_Lifecycle' }
                "30" { Clear-Host; Invoke-MultiServerRemotingMenu }
                "31" { Clear-Host; Invoke-ExportDiagnosticsMenu }
                "32" { Clear-Host; Show-UnattendedModeHelp }
                "0" {
                    Write-Host "`nExiting... Thank you for using the troubleshooting tool!" -ForegroundColor Cyan
                    break
                }
            }
            
            if ($choice -ne "0") {
                Write-Host "`n"
                Write-Host "Press any key to return to main menu..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            
        } while ($choice -ne "0")
    }
    catch {
        Write-DiagError "An unexpected error occurred: $($_.Exception.Message)"
        Write-Info "Stack Trace: $($_.ScriptStackTrace)"
    }
    finally {
        # Stop transcript logging if it was enabled
        if ($EnableLogging -and $transcriptPath) {
            try {
                Write-DiagWarning "NOTE: Transcript log may contain sensitive data (security policies, account names, event details)."
                Write-Info "  Review and redact before sharing: $transcriptPath"
                Stop-Transcript
                Write-Success "Transcript saved to: $($transcriptPath)"
            }
            catch {
                Write-DiagWarning "Could not stop transcript: $($_.Exception.Message)"
            }
        }
    }
}
#endregion
