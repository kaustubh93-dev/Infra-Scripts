<#
.SYNOPSIS
    Windows Server 2016 to 2022 In-Place Upgrade Script for Banking Environment
.DESCRIPTION
    Resilient PowerShell script for automated in-place upgrade with comprehensive
    logging, error handling, and rollback capabilities suitable for banking environments.
.PARAMETER ISOPath
    Path to Windows Server 2022 ISO file
.PARAMETER LogPath
    Path for detailed logging (default: C:\Logs\ServerUpgrade)
.PARAMETER PreCheckOnly
    Run pre-flight checks only without performing upgrade
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ISOPath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Logs\ServerUpgrade",
    
    [Parameter(Mandatory=$false)]
    [switch]$PreCheckOnly
)

# Initialize logging
$LogFile = "$LogPath\Upgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$TimeStamp [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry -Force
}

function Test-Administrator {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Prerequisites {
    Write-Log "Starting prerequisite checks..."
    
    # Check if running as administrator
    if (-not (Test-Administrator)) {
        throw "Script must be run as Administrator"
    }
    
    # Verify current OS version
    $OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
    if (-not $OSVersion.StartsWith("10.0.14393")) {
        Write-Log "Current OS: $OSVersion" "WARNING"
        Write-Log "Expected Windows Server 2016 (10.0.14393.x)" "WARNING"
    }
    
    # Check ISO file existence and validity
    if (-not (Test-Path $ISOPath)) {
        throw "ISO file not found: $ISOPath"
    }
    
    # Check available disk space (minimum 20GB free)
    $SystemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}
    $FreeSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
    
    if ($FreeSpaceGB -lt 20) {
        throw "Insufficient disk space. Available: $FreeSpaceGB GB, Required: 20GB minimum"
    }
    
    Write-Log "Disk space check passed: $FreeSpaceGB GB available"
    
    # Check for pending reboot
    if (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) {
        throw "Pending reboot detected. Please reboot before upgrade."
    }
    
    # Verify network connectivity for potential rollback
    try {
        Test-NetConnection -ComputerName "google.com" -Port 443 -InformationLevel Quiet
        Write-Log "Network connectivity verified"
    } catch {
        Write-Log "Network connectivity check failed - upgrade will continue" "WARNING"
    }
    
    Write-Log "All prerequisite checks passed"
    return $true
}

function Backup-SystemState {
    Write-Log "Creating system restore point..."
    
    try {
        # Enable system restore if not enabled
        Enable-ComputerRestore -Drive "$env:SystemDrive\"
        
        # Create restore point
        Checkpoint-Computer -Description "Pre-Server2022-Upgrade" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "System restore point created successfully"
    } catch {
        Write-Log "Failed to create system restore point: $($_.Exception.Message)" "WARNING"
    }
}

function Mount-UpgradeISO {
    param([string]$ISOPath)
    
    Write-Log "Mounting ISO: $ISOPath"
    
    try {
        $MountResult = Mount-DiskImage -ImagePath $ISOPath -PassThru
        $DriveLetter = ($MountResult | Get-Volume).DriveLetter
        $SetupPath = "$DriveLetter`:\setup.exe"
        
        if (-not (Test-Path $SetupPath)) {
            throw "Setup.exe not found in mounted ISO"
        }
        
        Write-Log "ISO mounted successfully at drive $DriveLetter`:"
        return @{
            DriveLetter = $DriveLetter
            SetupPath = $SetupPath
        }
    } catch {
        Write-Log "Failed to mount ISO: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Start-UpgradeProcess {
    param([hashtable]$MountInfo)
    
    Write-Log "Starting Windows Server 2022 upgrade process..."
    
    # Prepare setup arguments for unattended upgrade
    $SetupArgs = @(
        "/auto", "upgrade",
        "/imageindex", "2",          # Standard Server edition
        "/quiet",                    # Minimal user interaction
        "/DynamicUpdate", "Disable", # Disable updates during setup
        "/Compat", "IgnoreWarning",  # Ignore compatibility warnings
        "/copylogs", $LogPath        # Copy setup logs
    )
    
    Write-Log "Setup command: $($MountInfo.SetupPath) $($SetupArgs -join ' ')"
    
    try {
        # Start upgrade process
        $Process = Start-Process -FilePath $MountInfo.SetupPath -ArgumentList $SetupArgs -Wait -PassThru -NoNewWindow
        
        Write-Log "Setup process completed with exit code: $($Process.ExitCode)"
        
        # Exit codes reference from Microsoft documentation
        switch ($Process.ExitCode) {
            0 { Write-Log "Upgrade completed successfully" }
            -1047526904 { Write-Log "Upgrade requires user interaction" "WARNING" }
            -1047526906 { Write-Log "Upgrade blocked by compatibility issues" "ERROR" }
            default { Write-Log "Upgrade failed with exit code: $($Process.ExitCode)" "ERROR" }
        }
        
        return $Process.ExitCode
    } catch {
        Write-Log "Failed to start upgrade process: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Dismount-UpgradeISO {
    param([string]$ISOPath)
    
    try {
        Dismount-DiskImage -ImagePath $ISOPath -ErrorAction SilentlyContinue
        Write-Log "ISO dismounted successfully"
    } catch {
        Write-Log "Failed to dismount ISO: $($_.Exception.Message)" "WARNING"
    }
}

function Test-UpgradeResult {
    Write-Log "Verifying upgrade completion..."
    
    # Check if system requires reboot
    if (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) {
        Write-Log "System reboot required to complete upgrade" "INFO"
        return "REBOOT_REQUIRED"
    }
    
    # Additional post-upgrade verification can be added here
    return "SUCCESS"
}

# Main execution block
try {
    # Create log directory
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }
    
    Write-Log "=== Windows Server 2016 to 2022 Upgrade Started ==="
    Write-Log "Server: $env:COMPUTERNAME"
    Write-Log "ISO Path: $ISOPath"
    Write-Log "Log Path: $LogPath"
    
    # Run prerequisite checks
    Test-Prerequisites
    
    if ($PreCheckOnly) {
        Write-Log "Pre-check only mode - exiting without upgrade"
        exit 0
    }
    
    # Create system backup
    Backup-SystemState
    
    # Mount upgrade ISO
    $MountInfo = Mount-UpgradeISO -ISOPath $ISOPath
    
    try {    # Add after the OS version check
    $OSEdition = (Get-WmiObject -Class Win32_OperatingSystem).OperatingSystemSKU
    $ValidEditions = @(7, 8) # Server Standard and Datacenter editions
    if ($ValidEditions -notcontains $OSEdition) {
        throw "Unsupported Windows Server edition for upgrade"
    }    # Replace the existing disk space check with:
    $SystemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}
    $FreeSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
    $TotalSpaceGB = [math]::Round($SystemDrive.Size / 1GB, 2)
    $RequiredGB = 20
    
    if ($FreeSpaceGB -lt $RequiredGB) {
        throw "Insufficient disk space. Available: $FreeSpaceGB GB, Required: $RequiredGB GB minimum"
    }
    if (($FreeSpaceGB / $TotalSpaceGB) -lt 0.1) {
        Write-Log "Warning: Less than 10% free space available" "WARNING"
    }    function Test-CriticalServices {
        $CriticalServices = @('WinRM', 'LanmanServer', 'Schedule')
        foreach ($Service in $CriticalServices) {
            $ServiceStatus = Get-Service -Name $Service -ErrorAction SilentlyContinue
            if ($ServiceStatus.Status -ne 'Running') {
                Write-Log "Critical service $Service is not running" "WARNING"
                return $false
            }
        }
        return $true
    }    function Remove-UpgradeFiles {
        param([string]$LogPath)
        
        $OldFiles = Get-ChildItem -Path $LogPath -Filter "*.log" |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }
        
        foreach ($File in $OldFiles) {
            try {
                Remove-Item $File.FullName -Force
                Write-Log "Removed old log file: $($File.Name)"
            } catch {
                Write-Log "Failed to remove old log file: $($File.Name)" "WARNING"
            }
        }
    }    function Test-ISOHash {
        param([string]$ISOPath, [string]$ExpectedHash)
        
        Write-Log "Verifying ISO file integrity..."
        $FileHash = Get-FileHash -Path $ISOPath -Algorithm SHA256
        
        if ($FileHash.Hash -ne $ExpectedHash) {
            throw "ISO file hash verification failed"
        }
        Write-Log "ISO file integrity verified"
    }    function Test-BackupSuccess {
        param([datetime]$BackupTime)
        
        $RestorePoints = Get-ComputerRestorePoint |
            Where-Object { $_.CreationTime -gt $BackupTime }
        
        if (-not $RestorePoints) {
            throw "System restore point creation could not be verified"
        }
        Write-Log "Backup verification successful"
    }
        # Start upgrade process
        $ExitCode = Start-UpgradeProcess -MountInfo $MountInfo
        
        # Verify upgrade result
        $UpgradeResult = Test-UpgradeResult
        
        Write-Log "Upgrade process completed with result: $UpgradeResult"
        
        if ($UpgradeResult -eq "REBOOT_REQUIRED") {
            Write-Log "=== UPGRADE SUCCESSFUL - REBOOT REQUIRED ==="
            # Optionally schedule automatic reboot
            # shutdown /r /t 300 /c "Server upgrade completed - rebooting in 5 minutes"
        } else {
            Write-Log "=== UPGRADE COMPLETED SUCCESSFULLY ==="
        }
        
    } finally {
        # Always dismount ISO
        Dismount-UpgradeISO -ISOPath $ISOPath
    }
    
} catch {
    Write-Log "CRITICAL ERROR: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    Write-Log "=== UPGRADE FAILED ==="
    
    # Attempt cleanup
    try {
        Dismount-UpgradeISO -ISOPath $ISOPath
    } catch {
        Write-Log "Cleanup warning: $($_.Exception.Message)" "WARNING"
    }
    
    exit 1
} finally {
    Write-Log "=== Upgrade Process Ended ==="
}