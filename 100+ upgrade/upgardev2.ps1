# Server In-Place Upgrade Script with Comprehensive Error Handling
# Version: 1.0
# Purpose: Copy ISO, mount, and perform in-place Windows Server upgrades

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceISOPath,
    
    [Parameter(Mandatory = $true)]
    [string]$ServerListPath,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\ServerUpgrade\Logs",
    
    [Parameter(Mandatory = $false)]
    [string]$TempPath = "C:\ServerUpgrade\Temp",
    
    [Parameter(Mandatory = $false)]
    [int]$MaxConcurrentJobs = 5,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Initialize script variables
$ErrorActionPreference = "Stop"
$ScriptStartTime = Get-Date
$LogFile = Join-Path $LogPath "ServerUpgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorLogFile = Join-Path $LogPath "ServerUpgrade_Errors_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$SuccessLogFile = Join-Path $LogPath "ServerUpgrade_Success_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create directories if they don't exist
function Initialize-Directories {
    try {
        if (!(Test-Path $LogPath)) {
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        }
        if (!(Test-Path $TempPath)) {
            New-Item -ItemType Directory -Path $TempPath -Force | Out-Null
        }
        Write-Log "INFO" "Directories initialized successfully"
    }
    catch {
        Write-Error "Failed to initialize directories: $($_.Exception.Message)"
        exit 1
    }
}

# Enhanced logging function
function Write-Log {
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
    
    # Write to console with color coding
    switch ($Level) {
        "INFO"    { Write-Host $LogEntry -ForegroundColor White }
        "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
    }
    
    # Write to main log file
    try {
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
        
        # Write to specific log files based on level
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

# Function to validate prerequisites
function Test-Prerequisites {
    Write-Log "INFO" "Validating prerequisites..."
    
    # Check if source ISO exists
    if (!(Test-Path $SourceISOPath)) {
        Write-Log "ERROR" "Source ISO not found: $SourceISOPath"
        return $false
    }
    
    # Check if server list exists
    if (!(Test-Path $ServerListPath)) {
        Write-Log "ERROR" "Server list file not found: $ServerListPath"
        return $false
    }
    
    # Validate ISO file
    $ISOInfo = Get-Item $SourceISOPath
    if ($ISOInfo.Extension -ne ".iso") {
        Write-Log "ERROR" "File is not an ISO: $SourceISOPath"
        return $false
    }
    
    Write-Log "SUCCESS" "Prerequisites validation completed"
    return $true
}

# Function to test server connectivity
function Test-ServerConnectivity {
    param([string]$ServerName)
    
    try {
        $TestConnection = Test-Connection -ComputerName $ServerName -Count 2 -Quiet -ErrorAction Stop
        if ($TestConnection) {
            # Test WinRM connectivity
            $TestWinRM = Test-WSMan -ComputerName $ServerName -ErrorAction Stop
            if ($TestWinRM) {
                Write-Log "SUCCESS" "Server connectivity verified" $ServerName
                return $true
            }
        }
    }
    catch {
        Write-Log "ERROR" "Server connectivity failed: $($_.Exception.Message)" $ServerName
    }
    return $false
}

# Function to copy ISO to remote server
function Copy-ISOToServer {
    param(
        [string]$ServerName,
        [string]$SourcePath,
        [string]$DestinationPath
    )
    
    try {
        Write-Log "INFO" "Starting ISO copy operation" $ServerName
        
        # Create remote destination directory
        $RemoteDestDir = Split-Path $DestinationPath -Parent
        Invoke-Command -ComputerName $ServerName -ScriptBlock {
            param($Path)
            if (!(Test-Path $Path)) {
                New-Item -ItemType Directory -Path $Path -Force | Out-Null
            }
        } -ArgumentList $RemoteDestDir -ErrorAction Stop
        
        # Copy ISO with progress
        $Session = New-PSSession -ComputerName $ServerName -ErrorAction Stop
        try {
            Copy-Item -Path $SourcePath -Destination $DestinationPath -ToSession $Session -Force -ErrorAction Stop
            Write-Log "SUCCESS" "ISO copied successfully to $DestinationPath" $ServerName
            return $true
        }
        finally {
            Remove-PSSession $Session -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "ERROR" "Failed to copy ISO: $($_.Exception.Message)" $ServerName
        return $false
    }
}

# Function to mount ISO and run setup
function Invoke-ServerUpgrade {
    param(
        [string]$ServerName,
        [string]$ISOPath
    )
    
    $ScriptBlock = {
        param($ISOPath, $ServerName)
        
        $Results = @{
            Success = $false
            Message = ""
            MountPoint = ""
            SetupExitCode = $null
        }
        
        try {
            # Mount the ISO
            Write-Host "[$ServerName] Mounting ISO: $ISOPath"
            $MountResult = Mount-DiskImage -ImagePath $ISOPath -PassThru -ErrorAction Stop
            $DriveLetter = ($MountResult | Get-Volume).DriveLetter
            $SetupPath = "${DriveLetter}:\setup.exe"
            $Results.MountPoint = "${DriveLetter}:"
            
            Write-Host "[$ServerName] ISO mounted at drive $DriveLetter"
            
            # Verify setup.exe exists
            if (!(Test-Path $SetupPath)) {
                throw "Setup.exe not found at $SetupPath"
            }
            
            # Check current OS version for compatibility
            $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
            Write-Host "[$ServerName] Current OS: $($OSInfo.Caption) Build $($OSInfo.BuildNumber)"
            
            # Run setup.exe with in-place upgrade parameters
            Write-Host "[$ServerName] Starting Windows Setup..."
            $SetupArgs = @(
                "/auto", "upgrade"
                "/quiet"
                "/norestart"
                "/dynamicupdate", "disable"
                "/showoobe", "none"
            )
            
            $ProcessInfo = Start-Process -FilePath $SetupPath -ArgumentList $SetupArgs -Wait -PassThru -NoNewWindow
            $Results.SetupExitCode = $ProcessInfo.ExitCode
            
            # Check setup exit code
            switch ($ProcessInfo.ExitCode) {
                0 {
                    $Results.Success = $true
                    $Results.Message = "Setup completed successfully"
                }
                3010 {
                    $Results.Success = $true
                    $Results.Message = "Setup completed successfully, restart required"
                }
                default {
                    $Results.Message = "Setup failed with exit code: $($ProcessInfo.ExitCode)"
                }
            }
        }
        catch {
            $Results.Message = "Upgrade failed: $($_.Exception.Message)"
        }
        finally {
            # Unmount ISO
            try {
                if ($Results.MountPoint) {
                    Dismount-DiskImage -ImagePath $ISOPath -ErrorAction SilentlyContinue
                    Write-Host "[$ServerName] ISO unmounted"
                }
            }
            catch {
                Write-Host "[$ServerName] Warning: Failed to unmount ISO: $($_.Exception.Message)"
            }
        }
        
        return $Results
    }
    
    try {
        Write-Log "INFO" "Starting upgrade process" $ServerName
        
        if ($WhatIf) {
            Write-Log "INFO" "WhatIf: Would run upgrade on server" $ServerName
            return @{ Success = $true; Message = "WhatIf mode - no actual upgrade performed" }
        }
        
        $Results = Invoke-Command -ComputerName $ServerName -ScriptBlock $ScriptBlock -ArgumentList $ISOPath, $ServerName -ErrorAction Stop
        
        if ($Results.Success) {
            Write-Log "SUCCESS" $Results.Message $ServerName
            if ($Results.SetupExitCode -eq 3010) {
                Write-Log "WARN" "Server requires restart to complete upgrade" $ServerName
            }
        }
        else {
            Write-Log "ERROR" $Results.Message $ServerName
        }
        
        return $Results
    }
    catch {
        Write-Log "ERROR" "Failed to execute upgrade: $($_.Exception.Message)" $ServerName
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

# Function to process a single server
function Process-Server {
    param([string]$ServerName)
    
    $ServerStartTime = Get-Date
    Write-Log "INFO" "Starting server processing" $ServerName
    
    try {
        # Test connectivity
        if (!(Test-ServerConnectivity -ServerName $ServerName)) {
            return @{ 
                ServerName = $ServerName
                Success = $false
                Message = "Server connectivity failed"
                Duration = (Get-Date) - $ServerStartTime
            }
        }
        
        # Define remote ISO path
        $RemoteISOPath = "C:\ServerUpgrade\$(Split-Path $SourceISOPath -Leaf)"
        
        # Copy ISO to server
        if (!(Copy-ISOToServer -ServerName $ServerName -SourcePath $SourceISOPath -DestinationPath $RemoteISOPath)) {
            return @{
                ServerName = $ServerName
                Success = $false
                Message = "Failed to copy ISO to server"
                Duration = (Get-Date) - $ServerStartTime
            }
        }
        
        # Perform upgrade
        $UpgradeResults = Invoke-ServerUpgrade -ServerName $ServerName -ISOPath $RemoteISOPath
        
        # Cleanup remote ISO
        try {
            Invoke-Command -ComputerName $ServerName -ScriptBlock {
                param($Path)
                if (Test-Path $Path) {
                    Remove-Item $Path -Force -ErrorAction SilentlyContinue
                }
            } -ArgumentList $RemoteISOPath -ErrorAction SilentlyContinue
            Write-Log "INFO" "Remote ISO cleanup completed" $ServerName
        }
        catch {
            Write-Log "WARN" "Failed to cleanup remote ISO: $($_.Exception.Message)" $ServerName
        }
        
        $Duration = (Get-Date) - $ServerStartTime
        Write-Log "INFO" "Server processing completed in $([math]::Round($Duration.TotalMinutes, 2)) minutes" $ServerName
        
        return @{
            ServerName = $ServerName
            Success = $UpgradeResults.Success
            Message = $UpgradeResults.Message
            Duration = $Duration
            SetupExitCode = $UpgradeResults.SetupExitCode
        }
    }
    catch {
        $Duration = (Get-Date) - $ServerStartTime
        Write-Log "ERROR" "Unexpected error processing server: $($_.Exception.Message)" $ServerName
        
        return @{
            ServerName = $ServerName
            Success = $false
            Message = "Unexpected error: $($_.Exception.Message)"
            Duration = $Duration
        }
    }
}

# Main execution function
function Start-ServerUpgrade {
    Write-Log "INFO" "Starting Server Upgrade Script"
    Write-Log "INFO" "Source ISO: $SourceISOPath"
    Write-Log "INFO" "Server List: $ServerListPath"
    Write-Log "INFO" "Log Path: $LogPath"
    Write-Log "INFO" "Max Concurrent Jobs: $MaxConcurrentJobs"
    
    if ($WhatIf) {
        Write-Log "INFO" "Running in WhatIf mode - no actual changes will be made"
    }
    
    # Initialize directories
    Initialize-Directories
    
    # Validate prerequisites
    if (!(Test-Prerequisites)) {
        Write-Log "ERROR" "Prerequisites validation failed. Exiting."
        exit 1
    }
    
    # Read server list
    try {
        $Servers = Get-Content $ServerListPath | Where-Object { $_.Trim() -ne "" -and !$_.StartsWith("#") }
        Write-Log "INFO" "Loaded $($Servers.Count) servers from list"
    }
    catch {
        Write-Log "ERROR" "Failed to read server list: $($_.Exception.Message)"
        exit 1
    }
    
    # Process servers with job throttling
    $AllResults = @()
    $Jobs = @()
    $ProcessedCount = 0
    
    foreach ($Server in $Servers) {
        # Wait if we've reached max concurrent jobs
        while ($Jobs.Count -ge $MaxConcurrentJobs) {
            $CompletedJobs = $Jobs | Where-Object { $_.State -eq "Completed" }
            
            foreach ($Job in $CompletedJobs) {
                $Result = Receive-Job $Job
                $AllResults += $Result
                Remove-Job $Job
                $Jobs = $Jobs | Where-Object { $_.Id -ne $Job.Id }
                $ProcessedCount++
                
                Write-Log "INFO" "Progress: $ProcessedCount of $($Servers.Count) servers processed"
            }
            
            if ($Jobs.Count -ge $MaxConcurrentJobs) {
                Start-Sleep -Seconds 5
            }
        }
        
        # Start new job for server
        $Job = Start-Job -ScriptBlock ${function:Process-Server} -ArgumentList $Server
        $Jobs += $Job
        Write-Log "INFO" "Started processing job for server: $Server"
    }
    
    # Wait for remaining jobs to complete
    Write-Log "INFO" "Waiting for remaining jobs to complete..."
    while ($Jobs.Count -gt 0) {
        $CompletedJobs = $Jobs | Where-Object { $_.State -eq "Completed" }
        
        foreach ($Job in $CompletedJobs) {
            $Result = Receive-Job $Job
            $AllResults += $Result
            Remove-Job $Job
            $Jobs = $Jobs | Where-Object { $_.Id -ne $Job.Id }
            $ProcessedCount++
            
            Write-Log "INFO" "Progress: $ProcessedCount of $($Servers.Count) servers processed"
        }
        
        if ($Jobs.Count -gt 0) {
            Start-Sleep -Seconds 5
        }
    }
    
    # Generate summary report
    $SuccessfulUpgrades = $AllResults | Where-Object { $_.Success -eq $true }
    $FailedUpgrades = $AllResults | Where-Object { $_.Success -eq $false }
    $TotalDuration = (Get-Date) - $ScriptStartTime
    
    Write-Log "INFO" "==================== UPGRADE SUMMARY ===================="
    Write-Log "INFO" "Total Servers: $($Servers.Count)"
    Write-Log "SUCCESS" "Successful Upgrades: $($SuccessfulUpgrades.Count)"
    Write-Log "ERROR" "Failed Upgrades: $($FailedUpgrades.Count)"
    Write-Log "INFO" "Total Duration: $([math]::Round($TotalDuration.TotalMinutes, 2)) minutes"
    Write-Log "INFO" "Average Duration per Server: $([math]::Round(($AllResults | Measure-Object -Property Duration -Average).Average.TotalMinutes, 2)) minutes"
    
    if ($FailedUpgrades.Count -gt 0) {
        Write-Log "WARN" "Failed Servers:"
        foreach ($Failed in $FailedUpgrades) {
            Write-Log "ERROR" "$($Failed.ServerName): $($Failed.Message)"
        }
    }
    
    # Export detailed results
    $ResultsPath = Join-Path $LogPath "UpgradeResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $AllResults | Export-Csv -Path $ResultsPath -NoTypeInformation
    Write-Log "INFO" "Detailed results exported to: $ResultsPath"
    
    Write-Log "INFO" "Script execution completed"
    
    return $AllResults
}

# Execute main function
try {
    $Results = Start-ServerUpgrade
    exit 0
}
catch {
    Write-Log "ERROR" "Script execution failed: $($_.Exception.Message)"
    exit 1
}