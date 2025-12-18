#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Enhanced Windows Server In-Place Upgrade Script with comprehensive scanning and upgrade capabilities.

.DESCRIPTION
    This script provides automated scanning and in-place upgrade functionality for Windows Server environments.
    It supports three operation modes: ScanOnly, UpgradeOnly, and ScanAndUpgrade with extensive logging,
    parallel processing, and safety features including system restore points.

.PARAMETER ServerListPath
    Path to text file containing server names (one per line). Comments starting with # are ignored.

.PARAMETER SourceISOPath
    Path to Windows Server ISO file for upgrades. Required for UpgradeOnly and ScanAndUpgrade modes.

.PARAMETER Mode
    Operation mode: ScanOnly, UpgradeOnly, or ScanAndUpgrade (default).

.PARAMETER LogPath
    Directory for log files. Default: C:\ServerUpgrade\Logs

.PARAMETER OutputPath
    Directory for CSV reports. Default: C:\ServerUpgrade\Reports

.PARAMETER MaxConcurrentJobs
    Maximum number of parallel operations. Default: 5

.PARAMETER MinimumDiskSpaceGB
    Minimum free disk space required for upgrade. Default: 20 GB

.PARAMETER WhatIf
    Test mode - shows what would be done without making changes.

.EXAMPLE
    .\EnhancedServerUpgrade.ps1 -ServerListPath "C:\servers.txt" -Mode "ScanOnly"
    Scans all servers and generates eligibility report.

.EXAMPLE
    .\EnhancedServerUpgrade.ps1 -ServerListPath "C:\servers.txt" -SourceISOPath "\\share\WindowsServer2022.iso" -Mode "ScanAndUpgrade"
    Scans servers, then upgrades eligible ones.

.EXAMPLE
    .\EnhancedServerUpgrade.ps1 -ServerListPath "C:\servers.txt" -SourceISOPath "\\share\WindowsServer2022.iso" -WhatIf
    Test run without making actual changes.

.NOTES
    Version: 2.0
    Author: System Administrator
    Requires: PowerShell 5.1+, Administrator privileges
    Supports: Windows Server 2012 R2 and later
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to server list file")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ServerListPath,
    
    [Parameter(Mandatory = $false, HelpMessage = "Path to Windows Server ISO file")]
    [string]$SourceISOPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("ScanOnly", "UpgradeOnly", "ScanAndUpgrade")]
    [string]$Mode = "ScanAndUpgrade",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\ServerUpgrade\Logs",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\ServerUpgrade\Reports",
    
    [Parameter(Mandatory = $false)]
    [string]$TempPath = "C:\ServerUpgrade\Temp",
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 20)]
    [int]$MaxConcurrentJobs = 5,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(10, 100)]
    [int]$MinimumDiskSpaceGB = 20,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

#region Configuration
# =============================================================================
# SCRIPT CONFIGURATION
# =============================================================================

# Script metadata
$ScriptVersion = "2.0"
$ScriptStartTime = Get-Date
$ErrorActionPreference = "Stop"

# File paths
$LogFile = Join-Path $LogPath "ServerUpgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorLogFile = Join-Path $LogPath "ServerUpgrade_Errors_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$SuccessLogFile = Join-Path $LogPath "ServerUpgrade_Success_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ScanReportFile = Join-Path $OutputPath "ServerScanReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$UpgradeReportFile = Join-Path $OutputPath "ServerUpgradeReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# Setup argument templates
$StandardSetupArgs = @(
    "/auto", "upgrade",           # Automatic upgrade mode
    "/quiet",                     # Silent installation
    "/norestart",                 # Prevent automatic restart
    "/dynamicupdate", "disable",  # Disable dynamic updates
    "/showoobe", "none",          # Skip OOBE
    "/compat", "ignorewarning",   # Ignore compatibility warnings
    "/telemetry", "disable"       # Disable telemetry
)

# Windows Setup exit code meanings
$ExitCodeMeanings = @{
    0 = "Success - Setup completed successfully"
    3010 = "Success - Setup completed successfully, restart required"
    1 = "General failure - Check setup logs for details"
    2 = "Setup was cancelled by user or system"
    3 = "Fatal error - Setup could not continue"
    5 = "Access denied - Insufficient privileges"
    6 = "Invalid command line parameters"
    7 = "Setup media is corrupt or missing files"
    8 = "Not enough disk space to continue"
    9 = "Incompatible architecture (32-bit vs 64-bit)"
    10 = "Incompatible OS version"
    11 = "Hardware compatibility issues detected"
    16 = "Unsupported upgrade path"
    17 = "Driver compatibility issues"
    18 = "Windows activation issues"
    0xC1900101 = "Installation failure in SAFE_OS phase"
    0xC1900204 = "Migration failure - User profile or data migration failed"
    0xC1900208 = "Compatibility issues - Incompatible software detected"
    0xC1900210 = "No inheritance - Previous installation cannot be inherited"
    0xC190020E = "Insufficient disk space for installation"
    0x80070070 = "Insufficient disk space error"
    0x80070002 = "System cannot find the file specified"
    0x80070005 = "Access denied"
}

# Critical services to verify post-upgrade
$CriticalServices = @("BITS", "wuauserv", "CryptSvc", "TrustedInstaller")

#endregion

#region Utility Functions
# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Enhanced logging function with console output and file logging.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level,
        
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [string]$ServerName = "LOCAL"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] [$ServerName] $Message"
    
    # Console output with colors
    $Colors = @{
        INFO = "White"
        WARN = "Yellow"
        ERROR = "Red"
        SUCCESS = "Green"
    }
    Write-Host $LogEntry -ForegroundColor $Colors[$Level]
    
    # File logging
    try {
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
        
        if ($Level -eq "ERROR") {
            Add-Content -Path $ErrorLogFile -Value $LogEntry -ErrorAction SilentlyContinue
        }
        elseif ($Level -eq "SUCCESS") {
            Add-Content -Path $SuccessLogFile -Value $LogEntry -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
}

function Initialize-Environment {
    <#
    .SYNOPSIS
        Initialize directories and logging infrastructure.
    #>
    try {
        # Create required directories
        @($LogPath, $TempPath, $OutputPath) | ForEach-Object {
            if (!(Test-Path $_)) {
                New-Item -ItemType Directory -Path $_ -Force | Out-Null
            }
        }
        
        # Initialize log files
        $LogHeader = "# Enhanced Server Upgrade Script v$ScriptVersion - Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        @($LogFile, $ErrorLogFile, $SuccessLogFile) | ForEach-Object {
            $LogHeader | Out-File -FilePath $_ -Force
        }
        
        Write-Log "SUCCESS" "Environment initialized successfully"
        Write-Log "INFO" "Script Version: $ScriptVersion"
        Write-Log "INFO" "Execution Mode: $Mode"
        Write-Log "INFO" "Log Files: Main=$LogFile, Errors=$ErrorLogFile, Success=$SuccessLogFile"
        
        return $true
    }
    catch {
        Write-Error "Failed to initialize environment: $($_.Exception.Message)"
        return $false
    }
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validate all prerequisites before script execution.
    #>
    Write-Log "INFO" "Validating prerequisites..."
    $ValidationPassed = $true
    
    # Administrator check
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "ERROR" "Script must be run as Administrator"
        $ValidationPassed = $false
    }
    
    # OS version check
    try {
        $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
        Write-Log "INFO" "Current OS: $($OSInfo.Caption) Build $($OSInfo.BuildNumber)"
        
        if ([int]$OSInfo.BuildNumber -lt 9600) {
            Write-Log "WARN" "OS version may not support all operations (Build < 9600)"
        }
    }
    catch {
        Write-Log "ERROR" "Failed to verify OS version: $($_.Exception.Message)"
    }
    
    # Server list validation
    if (!(Test-Path $ServerListPath)) {
        Write-Log "ERROR" "Server list file not found: $ServerListPath"
        $ValidationPassed = $false
    }
    
    # ISO validation (if required)
    if ($Mode -ne "ScanOnly" -and $SourceISOPath) {
        if (!(Test-Path $SourceISOPath)) {
            Write-Log "ERROR" "Source ISO not found: $SourceISOPath"
            $ValidationPassed = $false
        }
        else {
            $ISOInfo = Get-Item $SourceISOPath
            if ($ISOInfo.Extension -ne ".iso") {
                Write-Log "ERROR" "File is not an ISO: $SourceISOPath"
                $ValidationPassed = $false
            }
            else {
                $ISOSizeGB = [math]::Round($ISOInfo.Length / 1GB, 2)
                Write-Log "SUCCESS" "ISO validated - Size: $ISOSizeGB GB"
            }
        }
    }
    
    # Disk space check
    try {
        $SystemDrive = $env:SystemDrive
        $DiskInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$SystemDrive'"
        $FreeSpaceGB = [math]::Round($DiskInfo.FreeSpace / 1GB, 2)
        
        if ($FreeSpaceGB -ge $MinimumDiskSpaceGB) {
            Write-Log "SUCCESS" "Sufficient disk space: $FreeSpaceGB GB free"
        }
        else {
            Write-Log "ERROR" "Insufficient disk space: $FreeSpaceGB GB (need $MinimumDiskSpaceGB GB)"
            $ValidationPassed = $false
        }
    }
    catch {
        Write-Log "ERROR" "Failed to check disk space: $($_.Exception.Message)"
        $ValidationPassed = $false
    }
    
    if ($ValidationPassed) {
        Write-Log "SUCCESS" "All prerequisites validated"
    }
    else {
        Write-Log "ERROR" "Prerequisites validation failed"
    }
    
    return $ValidationPassed
}

function Get-SetupExitCodeMeaning {
    <#
    .SYNOPSIS
        Get human-readable meaning of Windows Setup exit codes.
    #>
    param([int]$ExitCode)
    
    if ($ExitCodeMeanings.ContainsKey($ExitCode)) {
        return $ExitCodeMeanings[$ExitCode]
    }
    else {
        return "Unknown exit code - Check Microsoft documentation and setup logs"
    }
}

#endregion

#region Server Operations
# =============================================================================
# SERVER OPERATION FUNCTIONS
# =============================================================================

function Test-ServerConnectivity {
    <#
    .SYNOPSIS
        Test server connectivity including ping and WinRM.
    #>
    param([string]$ServerName)
    
    try {
        # Test basic connectivity
        $PingTest = Test-Connection -ComputerName $ServerName -Count 2 -Quiet -ErrorAction Stop
        if (-not $PingTest) {
            Write-Log "ERROR" "Ping test failed" $ServerName
            return $false
        }
        
        # Test WinRM
        $WinRMTest = Test-WSMan -ComputerName $ServerName -ErrorAction Stop
        if ($WinRMTest) {
            Write-Log "SUCCESS" "Connectivity verified (Ping + WinRM)" $ServerName
            return $true
        }
    }
    catch {
        Write-Log "ERROR" "Connectivity test failed: $($_.Exception.Message)" $ServerName
    }
    
    return $false
}

function Test-PendingReboot {
    <#
    .SYNOPSIS
        Check for pending reboot conditions on target server.
    #>
    param([string]$ServerName)
    
    try {
        $RebootInfo = Invoke-Command -ComputerName $ServerName -ScriptBlock {
            $PendingReboot = $false
            $RebootReasons = @()
            
            # Check Windows Update reboot flag
            if (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) {
                $PendingReboot = $true
                $RebootReasons += "Windows Update"
            }
            
            # Check CBS reboot flag
            if (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue) {
                $PendingReboot = $true
                $RebootReasons += "Component Based Servicing"
            }
            
            # Check pending file operations
            $PendingFileOps = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
            if ($PendingFileOps) {
                $PendingReboot = $true
                $RebootReasons += "Pending File Operations"
            }
            
            return @{
                PendingReboot = $PendingReboot
                Reasons = $RebootReasons -join ", "
            }
        } -ErrorAction Stop
        
        if ($RebootInfo.PendingReboot) {
            Write-Log "WARN" "Pending reboot detected: $($RebootInfo.Reasons)" $ServerName
        }
        
        return $RebootInfo
    }
    catch {
        Write-Log "ERROR" "Failed to check pending reboot: $($_.Exception.Message)" $ServerName
        return @{ PendingReboot = $null; Reasons = "Check failed" }
    }
}

function Initialize-SystemRestore {
    <#
    .SYNOPSIS
        Enable system restore and create pre-upgrade restore point.
    #>
    param([string]$ServerName)
    
    try {
        $RestoreResults = Invoke-Command -ComputerName $ServerName -ScriptBlock {
            $Results = @{
                SystemRestoreEnabled = $false
                RestorePointCreated = $false
                RestorePointName = ""
                Message = ""
            }
            
            try {
                $SystemDrive = $env:SystemDrive
                
                # Enable System Restore
                try {
                    Enable-ComputerRestore -Drive $SystemDrive -ErrorAction Stop
                    $Results.SystemRestoreEnabled = $true
                    $Results.Message += "System Restore enabled on $SystemDrive. "
                }
                catch {
                    # Check if already enabled
                    $VSSOutput = vssadmin list shadowstorage 2>&1
                    if ($VSSOutput -match $SystemDrive) {
                        $Results.SystemRestoreEnabled = $true
                        $Results.Message += "System Restore already enabled. "
                    }
                }
                
                # Create restore point
                if ($Results.SystemRestoreEnabled) {
                    $RestorePointName = "Pre-Windows-Upgrade-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                    try {
                        Checkpoint-Computer -Description $RestorePointName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
                        $Results.RestorePointCreated = $true
                        $Results.RestorePointName = $RestorePointName
                        $Results.Message += "Restore point '$RestorePointName' created."
                    }
                    catch {
                        $Results.Message += "Failed to create restore point: $($_.Exception.Message)."
                    }
                }
            }
            catch {
                $Results.Message = "System Restore initialization failed: $($_.Exception.Message)"
            }
            
            return $Results
        } -ErrorAction Stop
        
        if ($RestoreResults.RestorePointCreated) {
            Write-Log "SUCCESS" "Restore point created: $($RestoreResults.RestorePointName)" $ServerName
        }
        else {
            Write-Log "WARN" $RestoreResults.Message $ServerName
        }
        
        return $RestoreResults
    }
    catch {
        Write-Log "ERROR" "Failed to initialize system restore: $($_.Exception.Message)" $ServerName
        return @{ 
            SystemRestoreEnabled = $false
            RestorePointCreated = $false
            RestorePointName = ""
            Message = "Initialization failed"
        }
    }
}

function Get-ServerInformation {
    <#
    .SYNOPSIS
        Comprehensive server information gathering and upgrade eligibility assessment.
    #>
    param([string]$ServerName)
    
    # Initialize server info object
    $ServerInfo = [PSCustomObject]@{
        ServerName = $ServerName
        Online = $false
        OSName = "N/A"
        OSVersion = "N/A"
        BuildNumber = "N/A"
        ServicePack = "N/A"
        Architecture = "N/A"
        TotalMemoryGB = 0
        FreeSpaceGB = 0
        TotalSpaceGB = 0
        ProcessorCount = 0
        LastBootTime = "N/A"
        Domain = "N/A"
        IPAddress = "N/A"
        PendingReboot = "N/A"
        RebootReasons = "N/A"
        SystemRestoreEnabled = "N/A"
        UpgradeEligible = $false
        Notes = ""
        ScanDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    try {
        Write-Log "INFO" "Starting comprehensive server scan" $ServerName
        
        # Test connectivity
        if (!(Test-ServerConnectivity -ServerName $ServerName)) {
            $ServerInfo.Notes = "Server unreachable or WinRM not configured"
            return $ServerInfo
        }
        
        $ServerInfo.Online = $true
        
        # Get system information
        $SystemInfo = Invoke-Command -ComputerName $ServerName -ScriptBlock {
            $OS = Get-WmiObject -Class Win32_OperatingSystem
            $CS = Get-WmiObject -Class Win32_ComputerSystem
            $Processor = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
            $LogicalDisk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
            $Network = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object -First 1
            
            return @{
                OSName = $OS.Caption
                OSVersion = $OS.Version
                BuildNumber = $OS.BuildNumber
                ServicePack = if ($OS.ServicePackMajorVersion -gt 0) { "SP$($OS.ServicePackMajorVersion)" } else { "None" }
                Architecture = $OS.OSArchitecture
                TotalMemoryGB = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
                FreeSpaceGB = [math]::Round($LogicalDisk.FreeSpace / 1GB, 2)
                TotalSpaceGB = [math]::Round($LogicalDisk.Size / 1GB, 2)
                ProcessorCount = $CS.NumberOfProcessors
                LastBootTime = $OS.ConvertToDateTime($OS.LastBootUpTime).ToString("yyyy-MM-dd HH:mm:ss")
                Domain = $CS.Domain
                IPAddress = if ($Network) { $Network.IPAddress[0] } else { "N/A" }
            }
        } -ErrorAction Stop
        
        # Populate server information
        foreach ($Property in $SystemInfo.Keys) {
            if ($ServerInfo.PSObject.Properties.Name -contains $Property) {
                $ServerInfo.$Property = $SystemInfo[$Property]
            }
        }
        
        # Check pending reboot
        $PendingRebootInfo = Test-PendingReboot -ServerName $ServerName
        $ServerInfo.PendingReboot = if ($PendingRebootInfo.PendingReboot -ne $null) { $PendingRebootInfo.PendingReboot.ToString() } else { "Check Failed" }
        $ServerInfo.RebootReasons = $PendingRebootInfo.Reasons
        
        # Initialize system restore
        $RestoreInfo = Initialize-SystemRestore -ServerName $ServerName
        $ServerInfo.SystemRestoreEnabled = $RestoreInfo.SystemRestoreEnabled.ToString()
        
        # Assess upgrade eligibility
        $EligibilityIssues = @()
        
        if ($SystemInfo.FreeSpaceGB -lt $MinimumDiskSpaceGB) {
            $EligibilityIssues += "Insufficient disk space ($($SystemInfo.FreeSpaceGB) GB available, $MinimumDiskSpaceGB GB required)"
        }
        
        if ($SystemInfo.OSName -notlike "*Windows Server*") {
            $EligibilityIssues += "Non-Windows Server OS detected"
        }
        
        if ($PendingRebootInfo.PendingReboot -eq $true) {
            $EligibilityIssues += "Pending reboot: $($PendingRebootInfo.Reasons)"
        }
        
        if ($EligibilityIssues.Count -eq 0) {
            $ServerInfo.UpgradeEligible = $true
            $ServerInfo.Notes = "Eligible for upgrade"
        }
        else {
            $ServerInfo.Notes = $EligibilityIssues -join "; "
        }
        
        Write-Log "SUCCESS" "Server scan completed - Eligible: $($ServerInfo.UpgradeEligible)" $ServerName
        
    }
    catch {
        $ServerInfo.Notes = "Scan failed: $($_.Exception.Message)"
        Write-Log "ERROR" "Server scan failed: $($_.Exception.Message)" $ServerName
    }
    
    return $ServerInfo
}

function Invoke-ServerUpgrade {
    <#
    .SYNOPSIS
        Perform Windows Server in-place upgrade with comprehensive safety measures.
    #>
    param(
        [string]$ServerName,
        [string]$ISOPath
    )
    
    $UpgradeScriptBlock = {
        param($ISOPath, $ServerName)
        
        $Results = @{
            Success = $false
            Message = ""
            MountPoint = ""
            SetupExitCode = $null
            SetupExitCodeMeaning = ""
            PreUpgradeRestorePoint = ""
            RebootRequired = $false
            UpgradeStartTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            UpgradeEndTime = ""
            SetupLogPath = "C:\Windows\Temp\SetupLogs"
        }
        
        try {
            Write-Host "[$ServerName] Starting upgrade process..."
            
            # Pre-upgrade validations
            Write-Host "[$ServerName] Performing pre-upgrade validations..."
            
            # Check for pending reboot
            $PendingReboot = $false
            if (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) {
                $PendingReboot = $true
            }
            
            if ($PendingReboot) {
                throw "System has pending reboot required before upgrade"
            }
            
            # Create system restore point
            $RestorePointName = "Pre-Windows-Upgrade-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            try {
                Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction SilentlyContinue
                Checkpoint-Computer -Description $RestorePointName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
                $Results.PreUpgradeRestorePoint = $RestorePointName
                Write-Host "[$ServerName] Restore point created: $RestorePointName"
            }
            catch {
                Write-Host "[$ServerName] Warning: Could not create restore point"
            }
            
            # Mount ISO
            Write-Host "[$ServerName] Mounting ISO: $ISOPath"
            $MountResult = Mount-DiskImage -ImagePath $ISOPath -PassThru -ErrorAction Stop
            $DriveLetter = ($MountResult | Get-Volume).DriveLetter
            $SetupPath = "${DriveLetter}:\setup.exe"
            $Results.MountPoint = "${DriveLetter}:"
            
            # Verify setup.exe
            if (!(Test-Path $SetupPath)) {
                throw "Setup.exe not found at $SetupPath"
            }
            
            # Prepare setup arguments
            $SetupArgs = @(
                "/auto", "upgrade"
                "/quiet"
                "/norestart"
                "/dynamicupdate", "disable"
                "/showoobe", "none"
                "/compat", "ignorewarning"
                "/telemetry", "disable"
                "/copylogs", $Results.SetupLogPath
            )
            
            # Create logs directory
            if (!(Test-Path $Results.SetupLogPath)) {
                New-Item -ItemType Directory -Path $Results.SetupLogPath -Force | Out-Null
            }
            
            # Execute upgrade
            Write-Host "[$ServerName] Executing Windows Setup..."
            $UpgradeStartTime = Get-Date
            
            $ProcessInfo = Start-Process -FilePath $SetupPath -ArgumentList $SetupArgs -Wait -PassThru -NoNewWindow
            $Results.SetupExitCode = $ProcessInfo.ExitCode
            $Results.UpgradeEndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            
            # Interpret exit code
            switch ($ProcessInfo.ExitCode) {
                0 { 
                    $Results.SetupExitCodeMeaning = "Success - Setup completed successfully"
                    $Results.Success = $true
                }
                3010 { 
                    $Results.SetupExitCodeMeaning = "Success - Setup completed successfully, restart required"
                    $Results.Success = $true
                    $Results.RebootRequired = $true
                }
                default { 
                    $Results.SetupExitCodeMeaning = "Setup failed with exit code: $($ProcessInfo.ExitCode)"
                }
            }
            
            # Post-upgrade verification
            if ($Results.Success) {
                Write-Host "[$ServerName] Performing post-upgrade verification..."
                
                # Check system file integrity
                $SFCResult = & sfc /scannow
                
                # Verify critical services
                $ServiceIssues = @()
                @("BITS", "wuauserv", "CryptSvc", "TrustedInstaller") | ForEach-Object {
                    $Service = Get-Service -Name $_ -ErrorAction SilentlyContinue
                    if ($Service -and $Service.Status -eq "Stopped" -and $Service.StartType -ne "Disabled") {
                        try {
                            Start-Service -Name $_ -ErrorAction Stop
                        }
                        catch {
                            $ServiceIssues += $_
                        }
                    }
                }
                
                $UpgradeDuration = (Get-Date) - $UpgradeStartTime
                $Results.Message = "Upgrade completed successfully in $([math]::Round($UpgradeDuration.TotalMinutes, 2)) minutes"
                if ($Results.RebootRequired) {
                    $Results.Message += ". System restart required."
                }
            }
            else {
                $Results.Message = "Upgrade failed: $($Results.SetupExitCodeMeaning)"
            }
        }
        catch {
            $Results.Message = "Upgrade failed: $($_.Exception.Message)"
            $Results.UpgradeEndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        finally {
            # Cleanup - unmount ISO
            try {
                if ($Results.MountPoint) {
                    Dismount-DiskImage -ImagePath $ISOPath -ErrorAction SilentlyContinue
                    Write-Host "[$ServerName] ISO unmounted"
                }
            }
            catch {
                Write-Host "[$ServerName] Warning: Failed to unmount ISO"
            }
        }
        
        return $Results
    }
    
    try {
        Write-Log "INFO" "Starting server upgrade" $ServerName
        
        if ($WhatIf) {
            Write-Log "INFO" "WhatIf: Would perform upgrade on server" $ServerName
            return @{ 
                Success = $true
                Message = "WhatIf mode - no actual upgrade performed"
                SetupExitCode = 0
                RebootRequired = $false
            }
        }
        
        $Results = Invoke-Command -ComputerName $ServerName -ScriptBlock $UpgradeScriptBlock -ArgumentList $ISOPath, $ServerName -ErrorAction Stop
        
        if ($Results.Success) {
            Write-Log "SUCCESS" $Results.Message $ServerName
        }
        else {
            Write-Log "ERROR" $Results.Message $ServerName
            Write-Log "ERROR" "Exit Code: $($Results.SetupExitCode) - $($Results.SetupExitCodeMeaning)" $ServerName
        }
        
        return $Results
    }
    catch {
        Write-Log "ERROR" "Failed to execute upgrade: $($_.Exception.Message)" $ServerName
        return @{ 
            Success = $false
            Message = $_.Exception.Message
            SetupExitCode = -1
            RebootRequired = $false
        }
    }
}

#endregion

#region Main Execution
# =============================================================================
# MAIN EXECUTION LOGIC
# =============================================================================

function Start-ServerScan {
    <#
    .SYNOPSIS
        Execute server scanning phase with parallel processing.
    #>
    param([array]$Servers)
    
    Write-Log "INFO" "Starting server scan phase for $($Servers.Count) servers..."
    $ScanResults = @()
    $Jobs = @()
    $ProcessedCount = 0
    
    foreach ($Server in $Servers) {
        # Manage concurrent jobs
        while ($Jobs.Count -ge $MaxConcurrentJobs) {
            $CompletedJobs = $Jobs | Where-Object { $_.State -eq "Completed" }
            
            foreach ($Job in $CompletedJobs) {
                $Result = Receive-Job $Job
                $ScanResults += $Result
                Remove-Job $Job
                $Jobs = $Jobs | Where-Object { $_.Id -ne $Job.Id }
                $ProcessedCount++
                
                Write-Log "INFO" "Scan progress: $ProcessedCount/$($Servers.Count) completed"
            }
            
            if ($Jobs.Count -ge $MaxConcurrentJobs) {
                Start-Sleep -Seconds 2
            }
        }
        
        # Start scan job
        $Job = Start-Job -ScriptBlock ${function:Get-ServerInformation} -ArgumentList $Server
        $Jobs += $Job
        Write-Log "INFO" "Started scan job for: $Server"
    }
    
    # Wait for remaining jobs
    Write-Log "INFO" "Waiting for remaining scan jobs to complete..."
    while ($Jobs.Count -gt 0) {
        $CompletedJobs = $Jobs | Where-Object { $_.State -eq "Completed" }
        
        foreach ($Job in $CompletedJobs) {
            $Result = Receive-Job $Job
            $ScanResults += $Result
            Remove-Job $Job
            $Jobs = $Jobs | Where-Object { $_.Id -ne $Job.Id }
            $ProcessedCount++
        }
        
        if ($Jobs.Count -gt 0) {
            Start-Sleep -Seconds 2
        }
    }
    
    # Export results and generate summary
    try {
        $ScanResults | Export-Csv -Path $ScanReportFile -NoTypeInformation -Force
        Write-Log "SUCCESS" "Scan report exported to: $ScanReportFile"
        
        # Display summary
        $OnlineServers = $ScanResults | Where-Object { $_.Online -eq $true }
        $EligibleServers = $ScanResults | Where-Object { $_.UpgradeEligible -eq $true }
        $OfflineServers = $ScanResults | Where-Object { $_.Online -eq $false }
        
        Write-Log "INFO" "==================== SCAN SUMMARY ===================="
        Write-Log "INFO" "Total Servers: $($ScanResults.Count)"
        Write-Log "SUCCESS" "Online: $($OnlineServers.Count)"
        Write-Log "SUCCESS" "Upgrade Eligible: $($EligibleServers.Count)"
        Write-Log "ERROR" "Offline/Unreachable: $($OfflineServers.Count)"
        Write-Log "WARN" "Issues Detected: $(($OnlineServers | Where-Object { $_.UpgradeEligible -eq $false }).Count)"
    }
    catch {
        Write-Log "ERROR" "Failed to export scan results: $($_.Exception.Message)"
    }
    
    return $ScanResults
}

function Start-ServerUpgrades {
    <#
    .SYNOPSIS
        Execute server upgrade phase with parallel processing.
    #>
    param([array]$EligibleServers)
    
    Write-Log "INFO" "Starting upgrade phase for $($EligibleServers.Count) eligible servers..."
    $UpgradeResults = @()
    $Jobs = @()
    $ProcessedCount = 0
    
    foreach ($Server in $EligibleServers) {
        # Manage concurrent jobs
        while ($Jobs.Count -ge $MaxConcurrentJobs) {
            $CompletedJobs = $Jobs | Where-Object { $_.State -eq "Completed" }
            
            foreach ($Job in $CompletedJobs) {
                $Result = Receive-Job $Job
                $UpgradeResults += $Result
                Remove-Job $Job
                $Jobs = $Jobs | Where-Object { $_.Id -ne $Job.Id }
                $ProcessedCount++
                
                Write-Log "INFO" "Upgrade progress: $ProcessedCount/$($EligibleServers.Count) completed"
            }
            
            if ($Jobs.Count -ge $MaxConcurrentJobs) {
                Start-Sleep -Seconds 5
            }
        }
        
        # Start upgrade job
        $Job = Start-Job -ScriptBlock {
            param($ServerName, $ISOPath)
            
            # Copy ISO to server
            $RemoteISOPath = "C:\ServerUpgrade\$(Split-Path $ISOPath -Leaf)"
            try {
                $Session = New-PSSession -ComputerName $ServerName
                Copy-Item -Path $ISOPath -Destination $RemoteISOPath -ToSession $Session -Force
                Remove-PSSession $Session
                
                # Perform upgrade
                $Results = Invoke-ServerUpgrade -ServerName $ServerName -ISOPath $RemoteISOPath
                
                # Cleanup
                Invoke-Command -ComputerName $ServerName -ScriptBlock {
                    param($Path)
                    if (Test-Path $Path) { Remove-Item $Path -Force }
                } -ArgumentList $RemoteISOPath
                
                return $Results
            }
            catch {
                return @{
                    Success = $false
                    Message = "Failed to copy ISO or execute upgrade: $($_.Exception.Message)"
                    SetupExitCode = -1
                    RebootRequired = $false
                }
            }
        } -ArgumentList $Server, $SourceISOPath
        
        $Jobs += $Job
        Write-Log "INFO" "Started upgrade job for: $Server"
    }
    
    # Wait for remaining jobs
    Write-Log "INFO" "Waiting for remaining upgrade jobs to complete..."
    while ($Jobs.Count -gt 0) {
        $CompletedJobs = $Jobs | Where-Object { $_.State -eq "Completed" }
        
        foreach ($Job in $CompletedJobs) {
            $Result = Receive-Job $Job
            $UpgradeResults += $Result
            Remove-Job $Job
            $Jobs = $Jobs | Where-Object { $_.Id -ne $Job.Id }
            $ProcessedCount++
        }
        
        if ($Jobs.Count -gt 0) {
            Start-Sleep -Seconds 5
        }
    }
    
    # Export results and generate summary
    try {
        $UpgradeResults | Export-Csv -Path $UpgradeReportFile -NoTypeInformation -Force
        Write-Log "SUCCESS" "Upgrade report exported to: $UpgradeReportFile"
        
        # Display summary
        $SuccessfulUpgrades = $UpgradeResults | Where-Object { $_.Success -eq $true }
        $FailedUpgrades = $UpgradeResults | Where-Object { $_.Success -eq $false }
        $RebootRequired = $UpgradeResults | Where-Object { $_.RebootRequired -eq $true }
        
        Write-Log "INFO" "==================== UPGRADE SUMMARY ===================="
        Write-Log "INFO" "Total Processed: $($UpgradeResults.Count)"
        Write-Log "SUCCESS" "Successful: $($SuccessfulUpgrades.Count)"
        Write-Log "ERROR" "Failed: $($FailedUpgrades.Count)"
        Write-Log "WARN" "Restart Required: $($RebootRequired.Count)"
        
        if ($FailedUpgrades.Count -gt 0) {
            Write-Log "ERROR" "Failed servers: $($FailedUpgrades.ServerName -join ', ')"
        }
    }
    catch {
        Write-Log "ERROR" "Failed to export upgrade results: $($_.Exception.Message)"
    }
    
    return $UpgradeResults
}

function Start-MainExecution {
    <#
    .SYNOPSIS
        Main execution function orchestrating the entire operation.
    #>
    Write-Log "INFO" "==================== SCRIPT START ===================="
    Write-Log "INFO" "Enhanced Server Upgrade Script v$ScriptVersion"
    Write-Log "INFO" "Mode: $Mode | Max Jobs: $MaxConcurrentJobs | Min Space: $MinimumDiskSpaceGB GB"
    Write-Log "INFO" "WhatIf: $($WhatIf.IsPresent) | Server List: $ServerListPath"
    if ($SourceISOPath) { Write-Log "INFO" "ISO Path: $SourceISOPath" }
    
    # Initialize environment
    if (!(Initialize-Environment)) {
        Write-Log "ERROR" "Environment initialization failed. Exiting."
        exit 1
    }
    
    # Validate prerequisites
    if (!(Test-Prerequisites)) {
        Write-Log "ERROR" "Prerequisites validation failed. Exiting."
        exit 1
    }
    
    # Load server list
    try {
        $Servers = Get-Content $ServerListPath | Where-Object { $_.Trim() -ne "" -and !$_.StartsWith("#") }
        Write-Log "SUCCESS" "Loaded $($Servers.Count) servers from list"
    }
    catch {
        Write-Log "ERROR" "Failed to read server list: $($_.Exception.Message)"
        exit 1
    }
    
    $ScanResults = @()
    $UpgradeResults = @()
    
    # Execute based on mode
    switch ($Mode) {
        "ScanOnly" {
            $ScanResults = Start-ServerScan -Servers $Servers
        }
        "UpgradeOnly" {
            if (!$SourceISOPath) {
                Write-Log "ERROR" "ISO path required for upgrade operations"
                exit 1
            }
            $UpgradeResults = Start-ServerUpgrades -EligibleServers $Servers
        }
        "ScanAndUpgrade" {
            if (!$SourceISOPath) {
                Write-Log "ERROR" "ISO path required for scan and upgrade operations"
                exit 1
            }
            
            # Phase 1: Scan
            $ScanResults = Start-ServerScan -Servers $Servers
            
            # Phase 2: Upgrade eligible servers
            $EligibleServers = ($ScanResults | Where-Object { $_.UpgradeEligible -eq $true }).ServerName
            
            if ($EligibleServers.Count -eq 0) {
                Write-Log "WARN" "No eligible servers found for upgrade"
            }
            else {
                $UpgradeResults = Start-ServerUpgrades -EligibleServers $EligibleServers
            }
        }
    }
    
    # Generate final report
    $TotalDuration = (Get-Date) - $ScriptStartTime
    Write-Log "INFO" "==================== EXECUTION COMPLETE ===================="
    Write-Log "SUCCESS" "Total execution time: $([math]::Round($TotalDuration.TotalMinutes, 2)) minutes"
    
    if ($ScanResults.Count -gt 0) {
        Write-Log "INFO" "Scan Report: $ScanReportFile"
    }
    if ($UpgradeResults.Count -gt 0) {
        Write-Log "INFO" "Upgrade Report: $UpgradeReportFile"
    }
    
    Write-Log "INFO" "Log files: $LogPath"
    Write-Log "SUCCESS" "Script execution completed successfully"
    
    return @{
        ScanResults = $ScanResults
        UpgradeResults = $UpgradeResults
        Duration = $TotalDuration
    }
}

#endregion

#region Script Execution
# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

try {
    $Results = Start-MainExecution
    exit 0
}
catch {
    Write-Log "ERROR" "Critical script failure: $($_.Exception.Message)"
    Write-Log "ERROR" "Stack Trace: $($_.ScriptStackTrace)"
    exit 1
}

#endregion
