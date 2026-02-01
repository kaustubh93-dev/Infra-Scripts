#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive Windows Server Troubleshooting and Log Collection Script
.DESCRIPTION
    Interactive script to diagnose and collect logs for Network, Memory, CPU, and Disk issues
.PARAMETER EnableLogging
    Enables transcript logging of the entire session
.EXAMPLE
    .\WindowsServertroubleshootingtool_v1.ps1
    .\WindowsServertroubleshootingtool_v1.ps1 -EnableLogging
.NOTES
    Version: 2.1
    Last Updated: 2026-02-01
    Requires: Administrator privileges
    Enhanced with improved error handling, validation, and best practices
#>

param(
    [switch]$EnableLogging
)

# Requirements: PowerShell 5.1+ and the NetTCPIP module (Get-Net* cmdlets).
# This file was updated to avoid overriding core cmdlets like `Write-Error` and `Write-Warning`.
# If running on older PowerShell versions, some cmdlets may be unavailable.

#region Constants and Configuration
# Script Version
$script:ScriptVersion = "2.1"
$script:LastUpdated = "2026-02-01"

# Threshold Constants
$MEMORY_CRITICAL_THRESHOLD = 90
$MEMORY_WARNING_THRESHOLD = 80
$CPU_CRITICAL_THRESHOLD = 90
$CPU_WARNING_THRESHOLD = 80
$DISK_CRITICAL_THRESHOLD = 90
$DISK_WARNING_THRESHOLD = 80
$DISK_LATENCY_CRITICAL_MS = 50
$DISK_LATENCY_WARNING_MS = 20
$DISK_LATENCY_ACCEPTABLE_MS = 10
$PORT_EXHAUSTION_THRESHOLD = 0.8
$NETWORK_PACKET_ERROR_THRESHOLD = 100
$LOG_RETENTION_DAYS = 30

# Path Configuration
$script:TempBasePath = Join-Path $env:TEMP "ServerDiagnostics"
$script:DefaultLogPath = Join-Path $script:TempBasePath "Logs"

# TSS Path Configuration - Auto-detection
# Automatically detects TSS from common installation locations
$script:TSSPath = @(
    "C:\TSS",
    "C:\Tools\TSS",
    "$env:ProgramFiles\TSS",
    "$env:SystemDrive\TSS"
) | Where-Object { Test-Path $_ -ErrorAction SilentlyContinue } | Select-Object -First 1

if (-not $script:TSSPath) {
    $script:TSSPath = "C:\TSS"  # Fallback default
}

# Process Analysis Cache
$script:ProcessCacheTimeout = 30  # seconds
$script:ProcessCache = $null
$script:ProcessCacheTime = $null
#endregion

#region Output and Display Functions
function Write-ColorOutput {
    param(
        [System.ConsoleColor]$ForegroundColor
    )
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) { Write-Output $args }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Header {
    <#
    .SYNOPSIS
        Displays a formatted header
    .PARAMETER Text
        The header text to display
    #>
    param([string]$Text)
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Success {
    <#
    .SYNOPSIS
        Displays a success message
    .PARAMETER Text
        The success message to display
    #>
    param([string]$Text)
    Write-Host "[SUCCESS] $($Text)" -ForegroundColor Green
}

function Write-WarningMessage {
    <#
    .SYNOPSIS
        Displays a warning message with custom formatting
    .PARAMETER Text
        The warning message to display
    .OUTPUTS
        None
    #>
    param([string]$Text)
    Write-Host "[WARNING] $($Text)" -ForegroundColor Yellow
}

function Write-ErrorMessage {
    <#
    .SYNOPSIS
        Displays an error message with custom formatting
    .PARAMETER Text
        The error message to display
    .OUTPUTS
        None
    #>
    param([string]$Text)
    Write-Host "[ERROR] $($Text)" -ForegroundColor Red
}

function Write-Info {
    <#
    .SYNOPSIS
        Displays an informational message
    .PARAMETER Text
        The informational message to display
    #>
    param([string]$Text)
    Write-Host "[INFO] $($Text)" -ForegroundColor White
}
#endregion

#region Helper Functions
function Initialize-DiagnosticPaths {
    <#
    .SYNOPSIS
        Initializes diagnostic paths and ensures they exist
    .DESCRIPTION
        Creates necessary directories for logs and reports
    #>
    try {
        if (-not (Test-Path $script:TempBasePath)) {
            New-Item -Path $script:TempBasePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Info "Created diagnostic base path: $($script:TempBasePath)"
        }
        
        if (-not (Test-Path $script:DefaultLogPath)) {
            New-Item -Path $script:DefaultLogPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        
        return $true
    }
    catch {
        Write-ErrorMessage "Failed to initialize diagnostic paths: $($_.Exception.Message)"
        return $false
    }
}

function Test-PathValid {
    <#
    .SYNOPSIS
        Validates and optionally creates a path
    .PARAMETER Path
        The path to validate
    .PARAMETER CreateIfNotExist
        If specified, creates the path if it doesn't exist
    #>
    param(
        [string]$Path,
        [switch]$CreateIfNotExist
    )
    
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    
    # Validate path format
    if (-not (Test-Path $Path -IsValid)) {
        Write-ErrorMessage "Invalid path format: $($Path)"
        return $false
    }
    
    # Check if path exists
    if (-not (Test-Path $Path)) {
        if ($CreateIfNotExist) {
            try {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Success "Created directory: $($Path)"
                return $true
            }
            catch {
                Write-ErrorMessage "Cannot create directory: $($_.Exception.Message)"
                return $false
            }
        }
        else {
            Write-WarningMessage "Path does not exist: $($Path)"
            return $false
        }
    }
    
    return $true
}

function Get-ValidatedChoice {
    <#
    .SYNOPSIS
        Prompts user for input and validates against allowed values
    .PARAMETER Prompt
        The prompt message
    .PARAMETER ValidChoices
        Array of valid choices
    .PARAMETER AllowEmpty
        If specified, allows empty input
    #>
    param(
        [string]$Prompt,
        [string[]]$ValidChoices,
        [switch]$AllowEmpty
    )
    
    do {
        $choice = Read-Host $Prompt
        
        if ([string]::IsNullOrWhiteSpace($choice) -and $AllowEmpty) {
            return ""
        }
        
        if ($choice -in $ValidChoices) {
            return $choice
        }
        
        Write-WarningMessage "Invalid choice. Please enter one of: $($ValidChoices -join ', ')"
    } while ($true)
}

function Invoke-WithTSSCheck {
    <#
    .SYNOPSIS
        Executes a command with TSS availability check
    .PARAMETER TSSCommand
        The TSS command to execute (without .\TSS.ps1 prefix)
    .PARAMETER ManualAlternativeAction
        Script block to execute if TSS is not available
    .PARAMETER Description
        Description of the operation
    #>
    param(
        [string]$TSSCommand,
        [scriptblock]$ManualAlternativeAction,
        [string]$Description
    )
    
    if (Test-TSSAvailable) {
        Write-Info $Description
        $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
        
        if ($confirm -eq "Y") {
            Invoke-TSSCommand -Command $TSSCommand
        }
    }
    else {
        if ($ManualAlternativeAction) {
            & $ManualAlternativeAction
        }
    }
}

function Get-ProcessAnalysis {
    <#
    .SYNOPSIS
        Analyzes process resource usage with caching
    .DESCRIPTION
        Gets top processes by CPU and Memory usage in a single call
        Uses caching to avoid redundant WMI calls within the cache timeout period
    .PARAMETER TopCount
        Number of top processes to return (default: 10)
    .PARAMETER Force
        Force refresh of cached data
    .OUTPUTS
        Hashtable with ByCPU, ByMemory, and Total properties
    #>
    param(
        [int]$TopCount = 10,
        [switch]$Force
    )
    
    # Check if cache is valid
    $cacheValid = $false
    if (-not $Force -and $script:ProcessCache -and $script:ProcessCacheTime) {
        $cacheAge = (Get-Date) - $script:ProcessCacheTime
        if ($cacheAge.TotalSeconds -lt $script:ProcessCacheTimeout) {
            $cacheValid = $true
        }
    }
    
    # Return cached data if valid
    if ($cacheValid) {
        return $script:ProcessCache
    }
    
    # Retrieve fresh process data
    try {
        $processes = Get-Process -ErrorAction Stop
        
        $result = @{
            ByCPU    = $processes | Sort-Object CPU -Descending | Select-Object -First $TopCount
            ByMemory = $processes | Sort-Object WS -Descending | Select-Object -First $TopCount
            Total    = $processes.Count
        }
        
        # Update cache
        $script:ProcessCache = $result
        $script:ProcessCacheTime = Get-Date
        
        return $result
    }
    catch {
        Write-ErrorMessage "Failed to retrieve process information: $($_.Exception.Message)"
        return $null
    }
}

#endregion

#region TSS Functions
function Set-TSSPath {
    <#
    .SYNOPSIS
        Allows user to update the hardcoded TSS path
    .DESCRIPTION
        Prompts user for TSS installation path and validates it
    .OUTPUTS
        Boolean indicating if valid TSS path was set
    #>
    Write-Header "TSS Path Configuration"
    Write-Info "Current TSS Path: $($script:TSSPath)"
    Write-Info ""
    Write-Info "TSS (TroubleShootingScript) is required for automated log collection."
    Write-Info "Download TSS from:"
    Write-Info "  - https://aka.ms/getTSS"
    Write-Info "  - https://aka.ms/getTSSlite"
    Write-Info "  - https://cesdiagtools.blob.core.windows.net/windows/TSS.zip"
    Write-Info ""
    
    $userPath = Read-Host "Enter the full path to TSS folder (or press Enter to keep current path)"
    
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        Write-Info "Keeping current TSS path: $($script:TSSPath)"
        return (Test-TSSAvailable)
    }
    
    # Validate the path
    if (-not (Test-Path $userPath -PathType Container)) {
        Write-ErrorMessage "Invalid path: Directory does not exist"
        return $false
    }
    
    # Check if TSS.ps1 exists in the provided path
    $tssScript = Join-Path $userPath "TSS.ps1"
    if (-not (Test-Path $tssScript -PathType Leaf)) {
        Write-ErrorMessage "TSS.ps1 not found in the specified directory: $($userPath)"
        Write-Info "Please ensure TSS.ps1 exists in the folder you specified."
        return $false
    }
    
    $script:TSSPath = $userPath
    Write-Success "TSS path updated to: $($script:TSSPath)"
    return $true
}

function Test-TSSAvailable {
    <#
    .SYNOPSIS
        Checks if TSS is available at the configured path
    .DESCRIPTION
        Verifies TSS.ps1 exists at the configured path
    .OUTPUTS
        Boolean indicating TSS availability
    #>
    if ([string]::IsNullOrWhiteSpace($script:TSSPath)) {
        Write-WarningMessage "TSS path not configured"
        Write-Info "Please configure TSS path from the main menu (option 8)"
        Write-Info "Download TSS from:"
        Write-Info "  - https://aka.ms/getTSS"
        Write-Info "  - https://aka.ms/getTSSlite"
        Write-Info "  - https://cesdiagtools.blob.core.windows.net/windows/TSS.zip"
        return $false
    }
    
    if (-not (Test-Path $script:TSSPath -PathType Container)) {
        Write-WarningMessage "TSS directory not found at: $($script:TSSPath)"
        Write-Info "Please update TSS path from the main menu (option 8)"
        return $false
    }
    
    $tssScript = Join-Path $script:TSSPath "TSS.ps1"
    if (Test-Path $tssScript) {
        Write-Success "TSS found at: $($tssScript)"
        return $true
    }
    else {
        Write-WarningMessage "TSS.ps1 not found at: $($script:TSSPath)"
        Write-Info "Please verify TSS installation or update path from the main menu (option 8)"
        return $false
    }
}

function Invoke-TSSCommand {
    <#
    .SYNOPSIS
        Invokes a TSS command with proper path handling
    .PARAMETER Command
        The TSS command to execute (without the .\TSS.ps1 prefix)
    .EXAMPLE
        Invoke-TSSCommand "-SDP Net -AcceptEula"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )
    
    if ([string]::IsNullOrWhiteSpace($script:TSSPath)) {
        Write-ErrorMessage "TSS path not configured. Please configure from main menu (option 8)"
        return $false
    }
    
    if (-not (Test-Path $script:TSSPath -PathType Container)) {
        Write-ErrorMessage "TSS directory not found at: $($script:TSSPath)"
        return $false
    }
    
    $tssScript = Join-Path $script:TSSPath "TSS.ps1"
    if (-not (Test-Path $tssScript)) {
        Write-ErrorMessage "TSS.ps1 not found at: $($tssScript)"
        return $false
    }
    
    $currentLocation = Get-Location
    
    try {
        # Change to TSS directory
        Set-Location $script:TSSPath
        
        # Execute TSS command securely (avoid Invoke-Expression)
        Write-Info "Executing: $tssScript $Command"
        
        # Split command into arguments and execute directly
        if ($Command) {
            & $tssScript $Command.Split(" ")
        }
        else {
            & $tssScript
        }
        
        Write-Success "TSS command completed"
        return $true
    }
    catch {
        Write-ErrorMessage "Failed to execute TSS command: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Return to original location
        Set-Location $currentLocation
    }
}
#endregion

#region Network Diagnostics
function Test-NetworkConfiguration {
    <#
    .SYNOPSIS
        Performs comprehensive network configuration diagnostics
    .DESCRIPTION
        Checks RSS status, ephemeral port usage, VMQ settings, adapter properties,
        power plan, and network statistics
    .EXAMPLE
        Test-NetworkConfiguration
    .NOTES
        Requires administrator privileges
    #>
    Write-Header "Network Configuration Check"
    
    try {
        # Check RSS (Receive Side Scaling)
        Write-Info "Checking RSS (Receive Side Scaling) status..."
        $adapters = Get-NetAdapterRss -ErrorAction Stop
        
        foreach ($adapter in $adapters) {
            if ($adapter.Enabled -eq $true) {
                Write-Success "RSS is ENABLED on $($adapter.Name)"
            }
            else {
                Write-WarningMessage "RSS is DISABLED on $($adapter.Name)"
                Write-Info "To enable RSS: Set-NetAdapterRss -Name '$($adapter.Name)' -Enabled `$true"
            }
        }
    }
    catch {
        Write-ErrorMessage "Failed to check RSS status: $($_.Exception.Message)"
    }
     
    # Ephemeral Port Usage (Port Exhaustion)
    Write-Info "`nChecking TCP Ephemeral Ports:"
    try {
        $tcpSettings = Get-NetTCPSetting -ErrorAction Stop
        # Get the first profile with dynamic port settings
        $tcpParams = $tcpSettings | Where-Object { $_.DynamicPortRangeNumberOfPorts -gt 0 } | Select-Object -First 1
        
        $currentConnections = (Get-NetTCPConnection -ErrorAction Stop).Count
        
        # Use the dynamic port range from settings, or default Windows value
        $maxPorts = if ($tcpParams -and $tcpParams.DynamicPortRangeNumberOfPorts) {
            $tcpParams.DynamicPortRangeNumberOfPorts
        }
        else {
            49152  # Default Windows dynamic port range size
        }
        
        Write-Info "  Active TCP Connections: $($currentConnections)"
        Write-Info "  Max Dynamic Ports Available: $($maxPorts)"
        
        $portUsagePercent = ($currentConnections / $maxPorts) * 100
        Write-Info "  Port Usage: $([math]::Round($portUsagePercent, 2))%"
        
        if ($currentConnections -gt ($maxPorts * $PORT_EXHAUSTION_THRESHOLD)) {
            Write-ErrorMessage "  CRITICAL: Potential Port Exhaustion (Using >$($PORT_EXHAUSTION_THRESHOLD * 100)% of available ports)"
        }
        else {
            Write-Success "  Port usage is within acceptable range"
        }
    }
    catch {
        Write-ErrorMessage "Failed to check ephemeral ports: $($_.Exception.Message)"
    }

    # Check VMQ (Virtual Machine Queue) Status
    Write-Info "`nChecking VMQ Status (Relevant for Hyper-V Hosts):"
    try {
        $vmq = Get-NetAdapterVmq -ErrorAction SilentlyContinue
        if ($vmq) {
            foreach ($v in $vmq) {
                Write-Info "  $($v.Name): VMQ Enabled: $($v.Enabled)"
                if ($v.Enabled -eq $true) {
                    Write-WarningMessage "    Note: If this is a 1Gbps Broadcom adapter, consider disabling VMQ to prevent packet drops."
                }
            }
        }
        else {
            Write-Info "  No VMQ-capable adapters found or VMQ not available"
        }
    }
    catch {
        Write-WarningMessage "Could not retrieve VMQ information: $($_.Exception.Message)"
    }

    # Check Network Adapter Advanced Properties
    Write-Info "`nChecking Network Adapter Buffer Settings..."
    try {
        $netAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
        
        foreach ($adapter in $netAdapters) {
            Write-Info "`nAdapter: $($adapter.Name)"
            try {
                $advProps = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction Stop
                
                # Check Small Rx Buffers
                $smallRxBuffer = $advProps | Where-Object { $_.DisplayName -like "*Small*Rx*Buffer*" -or $_.RegistryKeyword -like "*SmallRxBuffers*" }
                if ($smallRxBuffer) {
                    $currentValue = $smallRxBuffer.DisplayValue
                    Write-Info "  Small Rx Buffers: $($currentValue)"
                    if ($currentValue -ne "8192") {
                        Write-WarningMessage "  Recommended value is 8192"
                    }
                }
                
                # Check Rx Ring Size
                $rxRingSize = $advProps | Where-Object { $_.DisplayName -like "*Rx Ring*" -or $_.RegistryKeyword -like "*RxRing*" }
                if ($rxRingSize) {
                    $currentValue = $rxRingSize.DisplayValue
                    Write-Info "  Rx Ring Size: $($currentValue)"
                    if ($currentValue -ne "4096") {
                        Write-WarningMessage "  Recommended value is 4096"
                    }
                }
            }
            catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
                Write-WarningMessage "  Network adapter $($adapter.Name) does not support advanced properties"
            }
            catch {
                Write-WarningMessage "  Unable to retrieve advanced properties for $($adapter.Name): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-ErrorMessage "Failed to enumerate network adapters: $($_.Exception.Message)"
    }
    
    # Check Power Plan
    Write-Info "`nChecking Power Plan..."
    try {
        $powerPlan = powercfg /getactivescheme
        if ($powerPlan -like "*High performance*") {
            Write-Success "Power Plan is set to High Performance"
        }
        else {
            Write-WarningMessage "Power Plan is NOT set to High Performance"
            Write-Info "Current: $($powerPlan)"
            Write-Info "To set High Performance: powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        }
    }
    catch {
        Write-ErrorMessage "Failed to check power plan: $($_.Exception.Message)"
    }
    
    # Network Statistics
    Write-Info "`nNetwork Interface Statistics:"
    try {
        Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
            try {
                $stats = Get-NetAdapterStatistics -Name $_.Name -ErrorAction Stop
                Write-Info "  $($_.Name):"
                Write-Info "    Received Packets: $($stats.ReceivedUnicastPackets)"
                Write-Info "    Sent Packets: $($stats.SentUnicastPackets)"
                Write-Info "    Received Errors: $($stats.ReceivedPacketErrors)"
                Write-Info "    Sent Errors: $($stats.OutboundPacketErrors)"
            }
            catch {
                Write-WarningMessage "  Could not retrieve statistics for $($_.Name)"
            }
        }
    }
    catch {
        Write-ErrorMessage "Failed to retrieve network statistics: $($_.Exception.Message)"
    }
}

function Start-NetworkLogCollection {
    <#
    .SYNOPSIS
        Starts network log collection based on issue type
    .DESCRIPTION
        Provides options for packet drop, network slowness, or manual trace collection
    #>
    Write-Header "Network Issue Log Collection"
    
    Write-Info "Select Network Issue Type:"
    Write-Host "1. Packet Drop / Network Bottleneck (happening NOW)" -ForegroundColor Yellow
    Write-Host "2. Network Slowness (general diagnostics)" -ForegroundColor Yellow
    Write-Host "3. Manual netsh trace" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "Enter choice (1-3)" -ValidChoices @("1", "2", "3")
    
    switch ($choice) {
        "1" {
            Invoke-WithTSSCheck `
                -TSSCommand "-Scenario NET_AfdTcpFull -NET_NDIS" `
                -ManualAlternativeAction { Show-NetworkTraceCommand } `
                -Description "Starting TSS Network trace for packet drops... You will be prompted to reproduce the issue. Press 'Y' when issue is reproduced."
        }
        "2" {
            Invoke-WithTSSCheck `
                -TSSCommand "-SDP Net -AcceptEula" `
                -ManualAlternativeAction { Show-NetworkTraceCommand } `
                -Description "Starting general network diagnostics..."
        }
        "3" {
            Show-NetworkTraceCommand
        }
    }
}

function Show-NetworkTraceCommand {
    <#
    .SYNOPSIS
        Displays manual network trace commands
    #>
    Write-Info "`nManual Network Trace Commands:"
    Write-Host @"
    
START TRACE:
netsh trace start scenario=netconnection globallevel=5 capture=yes report=no overwrite=yes persistent=yes maxsize=1024 tracefile=C:\temp\casedata\%computername%.etl

STOP TRACE:
netsh trace stop

"@ -ForegroundColor Cyan
}
#endregion

#region Memory Diagnostics
function Test-MemoryUsage {
    <#
    .SYNOPSIS
        Analyzes system memory usage
    .DESCRIPTION
        Checks total memory, usage percentage, top consumers, and committed bytes
    .EXAMPLE
        Test-MemoryUsage
    #>
    Write-Header "Memory Usage Analysis"
    
    try {
        # Get system memory info
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeMemGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedMemGB = $totalMemGB - $freeMemGB
        $memUsagePercent = [math]::Round(($usedMemGB / $totalMemGB) * 100, 2)
        
        Write-Info "Total Memory: $($totalMemGB) GB"
        Write-Info "Used Memory: $($usedMemGB) GB"
        Write-Info "Free Memory: $($freeMemGB) GB"
        Write-Info "Memory Usage: $($memUsagePercent)%"
        
        if ($memUsagePercent -gt $MEMORY_CRITICAL_THRESHOLD) {
            Write-ErrorMessage "CRITICAL: Memory usage above $($MEMORY_CRITICAL_THRESHOLD)%!"
        }
        elseif ($memUsagePercent -gt $MEMORY_WARNING_THRESHOLD) {
            Write-WarningMessage "WARNING: Memory usage above $($MEMORY_WARNING_THRESHOLD)%"
        }
        else {
            Write-Success "Memory usage is within normal range"
        }
    }
    catch {
        Write-ErrorMessage "Failed to retrieve memory information: $($_.Exception.Message)"
        return
    }
    
    # Top memory consuming processes
    Write-Info "`nTop 10 Memory Consuming Processes:"
    $processAnalysis = Get-ProcessAnalysis
    
    if ($processAnalysis) {
        $processAnalysis.ByMemory | Format-Table Name, 
        @{Label = "Memory(MB)"; Expression = { [math]::Round($_.WS / 1MB, 2) } },
        @{Label = "CPU(s)"; Expression = { [math]::Round($_.CPU, 2) } },
        Id -AutoSize
    }
    
    # Check committed bytes
    try {
        $perfCounter = Get-Counter '\Memory\% Committed Bytes In Use' -ErrorAction Stop
        if ($perfCounter) {
            $committedPercent = [math]::Round($perfCounter.CounterSamples.CookedValue, 2)
            Write-Info "`nCommitted Bytes In Use: $($committedPercent)%"
            if ($committedPercent -gt $MEMORY_CRITICAL_THRESHOLD) {
                Write-ErrorMessage "CRITICAL: Committed bytes above $($MEMORY_CRITICAL_THRESHOLD)%!"
            }
        }
    }
    catch {
        Write-WarningMessage "Could not retrieve committed bytes information: $($_.Exception.Message)"
    }
}

function Start-MemoryLogCollection {
    <#
    .SYNOPSIS
        Starts memory issue log collection
    .DESCRIPTION
        Provides options for immediate, timed, and intermittent memory issue capture
    #>
    Write-Header "Memory Issue Log Collection"
    
    Write-Info "Select Memory Issue Scenario:"
    Write-Host "1. High Memory - Issue happening NOW (manual stop)" -ForegroundColor Yellow
    Write-Host "2. High Memory - Issue happening NOW (automatic stop after 5 min)" -ForegroundColor Yellow
    Write-Host "3. High Memory - Intermittent (wait for 90% memory usage)" -ForegroundColor Yellow
    Write-Host "4. Long-term Performance Monitor collection" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-4)" -ValidChoices @("1", "2", "3", "4")
    
    switch ($choice) {
        "1" {
            Invoke-WithTSSCheck `
                -TSSCommand "-Xperf Memory" `
                -Description "Starting memory trace - You will need to manually stop with TSS.ps1 -Stop. Let trace run for 60 seconds to 3 minutes while memory is high"
        }
        "2" {
            if ($tssAvailable) {
                $logPath = Read-Host "Enter log folder path (e.g., D:\Data) or press Enter for default"
                
                if ([string]::IsNullOrWhiteSpace($logPath)) {
                    $logPath = $script:DefaultLogPath
                }
                
                if (Test-PathValid -Path $logPath -CreateIfNotExist) {
                    $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
                    if ($confirm -eq "Y") {
                        Invoke-TSSCommand -Command "-Xperf Memory -XperfMaxFileMB 4096 -StopWaitTimeInSec 300 -LogFolderPath $logPath"
                    }
                }
            }
        }
        "3" {
            if ($tssAvailable) {
                Write-Info "Trace will wait for 90% memory usage, then capture for 5 minutes"
                $logPath = Read-Host "Enter log folder path (e.g., D:\Data) or press Enter for default"
                
                if ([string]::IsNullOrWhiteSpace($logPath)) {
                    $logPath = $script:DefaultLogPath
                }
                
                if (Test-PathValid -Path $logPath -CreateIfNotExist) {
                    $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
                    if ($confirm -eq "Y") {
                        Invoke-TSSCommand -Command "-Xperf Memory -WaitEvent HighMemory:90 -StopWaitTimeInSec 300 -LogFolderPath $logPath"
                    }
                }
            }
        }
        "4" {
            Show-PerfmonCommand "Memory"
        }
    }
}
#endregion

#region CPU Diagnostics
function Test-CPUUsage {
    <#
    .SYNOPSIS
        Analyzes CPU usage
    .DESCRIPTION
        Checks current CPU usage, processor information, and top CPU consumers
    .EXAMPLE
        Test-CPUUsage
    #>
    Write-Header "CPU Usage Analysis"
    
    # Current CPU usage
    try {
        $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop
        if ($cpuUsage) {
            $cpuPercent = [math]::Round($cpuUsage.CounterSamples.CookedValue, 2)
            Write-Info "Current CPU Usage: $($cpuPercent)%"
            
            if ($cpuPercent -gt $CPU_CRITICAL_THRESHOLD) {
                Write-ErrorMessage "CRITICAL: CPU usage above $($CPU_CRITICAL_THRESHOLD)%!"
            }
            elseif ($cpuPercent -gt $CPU_WARNING_THRESHOLD) {
                Write-WarningMessage "WARNING: CPU usage above $($CPU_WARNING_THRESHOLD)%"
            }
            else {
                Write-Success "CPU usage is within normal range"
            }
        }
    }
    catch {
        Write-ErrorMessage "Failed to retrieve CPU usage: $($_.Exception.Message)"
    }
    
    # Processor information
    try {
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop
        Write-Info "`nProcessor Information:"
        Write-Info "  Name: $($cpu.Name)"
        Write-Info "  Cores: $($cpu.NumberOfCores)"
        Write-Info "  Logical Processors: $($cpu.NumberOfLogicalProcessors)"
    }
    catch {
        Write-ErrorMessage "Failed to retrieve processor information: $($_.Exception.Message)"
    }
    
    # Top CPU consuming processes
    Write-Info "`nTop 10 CPU Consuming Processes:"
    $processAnalysis = Get-ProcessAnalysis
    
    if ($processAnalysis) {
        $processAnalysis.ByCPU | Format-Table Name, 
        @{Label = "CPU(s)"; Expression = { [math]::Round($_.CPU, 2) } },
        @{Label = "Memory(MB)"; Expression = { [math]::Round($_.WS / 1MB, 2) } },
        Id -AutoSize
    }
    
    # Check for WMI high CPU
    try {
        $wmiProcess = Get-Process -Name "WmiPrvSE" -ErrorAction SilentlyContinue
        if ($wmiProcess) {
            $wmiCPU = [math]::Round($wmiProcess.CPU, 2)
            Write-Info "`nWMI Provider Host (WmiPrvSE) CPU Usage: $($wmiCPU) seconds"
            if ($wmiCPU -gt 100) {
                Write-WarningMessage "WMI Provider Host is consuming significant CPU time"
                Write-Info "Consider using WMI-specific trace: .\TSS.ps1 -UEX_WMIBase -WIN_Kernel -ETWflags 1 -WPR CPU -Perfmon UEX_WMIPrvSE -PerfIntervalSec 1 -noBasicLog"
            }
        }
    }
    catch {
        Write-WarningMessage "Could not check WMI process: $($_.Exception.Message)"
    }
}

function Start-CPULogCollection {
    <#
    .SYNOPSIS
        Starts CPU issue log collection
    .DESCRIPTION
        Provides options for immediate, timed, intermittent, and WMI-specific CPU issue capture
    #>
    Write-Header "CPU Issue Log Collection"
    
    Write-Info "Select CPU Issue Scenario:"
    Write-Host "1. High CPU - Issue happening NOW (manual stop, 60s-3min recommended)" -ForegroundColor Yellow
    Write-Host "2. High CPU - Issue happening NOW (automatic stop after 5 min)" -ForegroundColor Yellow
    Write-Host "3. High CPU - Intermittent (wait for 90% CPU usage)" -ForegroundColor Yellow
    Write-Host "4. High CPU - WMI related" -ForegroundColor Yellow
    Write-Host "5. Long-term Performance Monitor collection" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-5)" -ValidChoices @("1", "2", "3", "4", "5")
    
    switch ($choice) {
        "1" {
            Invoke-WithTSSCheck `
                -TSSCommand "-Xperf CPU" `
                -Description "Starting CPU trace - You can manually stop with TSS.ps1 -Stop. Run for 60 seconds to 3 minutes while CPU is high (>88%)"
        }
        "2" {
            if ($tssAvailable) {
                $logPath = Read-Host "Enter log folder path (e.g., D:\Data) or press Enter for default"
                
                if ([string]::IsNullOrWhiteSpace($logPath)) {
                    $logPath = $script:DefaultLogPath
                }
                
                if (Test-PathValid -Path $logPath -CreateIfNotExist) {
                    $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
                    if ($confirm -eq "Y") {
                        Invoke-TSSCommand -Command "-Xperf CPU -XperfMaxFileMB 4096 -StopWaitTimeInSec 300 -LogFolderPath $logPath"
                    }
                }
            }
        }
        "3" {
            Invoke-WithTSSCheck `
                -TSSCommand "-Xperf CPU -WaitEvent HighCPU:90 -XperfMaxFileMB 4096 -StopWaitTimeInSec 300" `
                -Description "Trace will wait for 90% CPU usage, then capture for 5 minutes"
        }
        "4" {
            Invoke-WithTSSCheck `
                -TSSCommand "-UEX_WMIBase -WIN_Kernel -ETWflags 1 -WPR CPU -Perfmon UEX_WMIPrvSE -PerfIntervalSec 1 -noBasicLog" `
                -Description "Starting WMI-specific CPU trace (run for 2 minutes during high CPU)"
        }
        "5" {
            Show-PerfmonCommand "CPU"
        }
    }
}
#endregion

#region Disk/Storage Diagnostics
function Test-DiskPerformance {
    <#
    .SYNOPSIS
        Analyzes disk performance
    .DESCRIPTION
        Checks physical disks, logical disk space, latency, and cluster size
    .EXAMPLE
        Test-DiskPerformance
    #>
    Write-Header "Disk Performance Analysis"
    
    # Disk information
    try {
        $disks = Get-PhysicalDisk -ErrorAction Stop
        Write-Info "Physical Disks:"
        foreach ($disk in $disks) {
            Write-Info "  $($disk.FriendlyName) - Size: $([math]::Round($disk.Size / 1GB, 2)) GB - Health: $($disk.HealthStatus)"
        }
    }
    catch {
        Write-ErrorMessage "Failed to retrieve physical disk information: $($_.Exception.Message)"
    }
    
    # Logical disk space
    Write-Info "`nLogical Disk Space:"
    try {
        $volumes = Get-Volume -ErrorAction Stop | Where-Object { $null -ne $_.DriveLetter }
        foreach ($vol in $volumes) {
            $usedSpace = $vol.Size - $vol.SizeRemaining
            $usedPercent = [math]::Round(($usedSpace / $vol.Size) * 100, 2)
            $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
            
            Write-Info "  Drive $($vol.DriveLetter): - $($usedPercent)% used - $($freeGB) GB free"
            if ($usedPercent -gt $DISK_CRITICAL_THRESHOLD) {
                Write-ErrorMessage "    CRITICAL: Less than 10% free space!"
            }
            elseif ($usedPercent -gt $DISK_WARNING_THRESHOLD) {
                Write-WarningMessage "    WARNING: Less than 20% free space"
            }
        }
    }
    catch {
        Write-ErrorMessage "Failed to retrieve volume information: $($_.Exception.Message)"
    }
    
    # Disk latency check
    Write-Info "`nChecking Disk Latency (avg over last few seconds)..."
    try {
        $diskReadLatency = Get-Counter '\PhysicalDisk(*)\Avg. Disk sec/Read' -ErrorAction Stop
        
        if ($diskReadLatency) {
            foreach ($sample in $diskReadLatency.CounterSamples) {
                if ($sample.InstanceName -ne "_total") {
                    $latencyMs = [math]::Round($sample.CookedValue * 1000, 2)
                    Write-Info "  Read Latency - $($sample.InstanceName): $($latencyMs) ms"
                    
                    if ($latencyMs -gt $DISK_LATENCY_CRITICAL_MS) {
                        Write-ErrorMessage "    CRITICAL: Serious I/O bottleneck (>$($DISK_LATENCY_CRITICAL_MS)ms)"
                    }
                    elseif ($latencyMs -gt $DISK_LATENCY_WARNING_MS) {
                        Write-WarningMessage "    WARNING: Slow, needs attention ($($DISK_LATENCY_WARNING_MS)-$($DISK_LATENCY_CRITICAL_MS)ms)"
                    }
                    elseif ($latencyMs -gt $DISK_LATENCY_ACCEPTABLE_MS) {
                        Write-Info "    INFO: Acceptable ($($DISK_LATENCY_ACCEPTABLE_MS)-$($DISK_LATENCY_WARNING_MS)ms)"
                    }
                    else {
                        Write-Success "    GOOD: Very good (<$($DISK_LATENCY_ACCEPTABLE_MS)ms)"
                    }
                }
            }
        }
    }
    catch {
        Write-WarningMessage "Could not retrieve disk latency metrics: $($_.Exception.Message)"
    }
    
    # Check cluster size for volumes
    Write-Info "`nChecking Cluster Size (should be 64KB for databases):"
    try {
        $volumes = Get-Volume -ErrorAction Stop | Where-Object { $null -ne $_.DriveLetter }
        foreach ($vol in $volumes) {
            $drive = $vol.DriveLetter + ":"
            try {
                $clusterSize = (Get-CimInstance -Query "SELECT BlockSize FROM Win32_Volume WHERE DriveLetter='$drive'" -ErrorAction Stop).BlockSize
                if ($clusterSize) {
                    $clusterSizeKB = $clusterSize / 1KB
                    Write-Info "  Drive $($vol.DriveLetter): - Cluster Size: $($clusterSizeKB) KB"
                    if ($clusterSizeKB -ne 64) {
                        Write-WarningMessage "    Recommended cluster size for SQL/Database servers is 64KB"
                    }
                }
            }
            catch {
                Write-WarningMessage "  Could not retrieve cluster size for drive $($vol.DriveLetter)"
            }
        }
    }
    catch {
        Write-ErrorMessage "Failed to check cluster sizes: $($_.Exception.Message)"
    }
}

function Start-DiskLogCollection {
    <#
    .SYNOPSIS
        Starts disk/storage issue log collection
    .DESCRIPTION
        Provides options for StorPort trace and performance monitoring
    #>
    Write-Header "Disk/Storage Issue Log Collection"
    
    Write-Info "Disk/Storage Log Collection Options:"
    Write-Host "1. StorPort trace (10-15 minutes)" -ForegroundColor Yellow
    Write-Host "2. StorPort + Performance Monitor (comprehensive)" -ForegroundColor Yellow
    Write-Host "3. Manual StorPort trace commands" -ForegroundColor Yellow
    Write-Host "4. Long-term Performance Monitor only" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-4)" -ValidChoices @("1", "2", "3", "4")
    
    switch ($choice) {
        "1" {
            Invoke-WithTSSCheck `
                -TSSCommand "-StartNowait -PerfMon General -PerfIntervalSec 1 -SHA_Storport" `
                -ManualAlternativeAction { Show-StorPortCommands } `
                -Description "Starting StorPort trace for 10-15 minutes... Trace started. Let it run for 10-15 minutes, then stop with: TSS.ps1 -Stop"
        }
        "2" {
            Invoke-WithTSSCheck `
                -TSSCommand "-StartNowait -PerfMon General -PerfIntervalSec 1 -SHA_Storport -noSDP" `
                -ManualAlternativeAction { Show-StorPortCommands } `
                -Description "Starting comprehensive StorPort + Perfmon trace... Run for 10-15 minutes, then stop with: TSS.ps1 -Stop"
        }
        "3" {
            Show-StorPortCommands
        }
        "4" {
            Show-PerfmonCommand "Disk"
        }
    }
    
    Write-Info "`nDisk Performance Best Practices:"
    Write-Info "  1. Ensure disks have 64KB cluster size (especially for SQL)"
    Write-Info "  2. Use PVSCSI instead of LSI SAS (for VMs)"
    Write-Info "  3. Ensure antivirus exclusions are in place"
    Write-Info "  4. Perform regular database purging and maintenance"
    Write-Info "  5. Place database files and transaction logs on separate disks"
    Write-Info "  6. Consider using SSDs for better I/O performance"
    Write-Info "`nLatency Guidelines:"
    Write-Info "  • <$($DISK_LATENCY_ACCEPTABLE_MS)ms: Very good"
    Write-Info "  • $($DISK_LATENCY_ACCEPTABLE_MS)-$($DISK_LATENCY_WARNING_MS)ms: Okay"
    Write-Info "  • $($DISK_LATENCY_WARNING_MS)-$($DISK_LATENCY_CRITICAL_MS)ms: Slow, needs attention"
    Write-Info "  • >$($DISK_LATENCY_CRITICAL_MS)ms: Serious I/O bottleneck"
}

function Show-StorPortCommands {
    <#
    .SYNOPSIS
        Displays manual StorPort trace commands
    #>
    Write-Info "`nManual StorPort Trace Commands:"
    Write-Host @"

START STORPORT TRACE:
logman create trace "storport" -ow -o c:\perflogs\storport.etl -p "Microsoft-Windows-StorPort" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

STOP STORPORT TRACE:
logman stop "storport" -ets

ALSO RUN PERFMON (see option 4 for perfmon commands)

FILTER DRIVER CHECK:
fltmc
fltmc instances

"@ -ForegroundColor Cyan
}

function Show-PerfmonCommand {
    <#
    .SYNOPSIS
        Displays performance monitor collection commands
    .PARAMETER Scenario
        The monitoring scenario (Memory, CPU, Disk, Assessment)
    #>
    param(
        [ValidateSet("Memory", "CPU", "Disk", "Assessment")]
        [string]$Scenario
    )
    Write-Info "`nLong-term Performance Monitor Collection:"
    Write-Host @"

For $($Scenario) monitoring, collect perfmon for 2-4 hours:

CREATE PERFMON:
Logman.exe create counter PerfLog-$($env:COMPUTERNAME) -o "$($script:DefaultLogPath)\$($env:COMPUTERNAME)_PerfLog-short.blg" -f bincirc -v mmddhhmm -max 500 -c "\LogicalDisk(*)\*" "\Memory\*" "\Cache\*" "\Network Interface(*)\*" "\Paging File(*)\*" "\PhysicalDisk(*)\*" "\Processor(*)\*" "\Processor Information(*)\*" "\Process(*)\*" "\Redirector\*" "\Server\*" "\System\*" "\Server Work Queues(*)\*" "\Terminal Services\*" -si 00:00:05

START COLLECTION:
logman start PerfLog-$($env:COMPUTERNAME)

STOP COLLECTION:
logman stop PerfLog-$($env:COMPUTERNAME)

INTERVAL GUIDANCE:
  • 24 hours: -si 00:01:16 (1 min 16 sec)
  • 4 hours: -si 00:00:14 (14 seconds)
  • 2 hours: -si 00:00:07 (7 seconds)

You can also use -b MM/DD/YYYY HH:MM:SS AM/PM for begin time
and -e MM/DD/YYYY HH:MM:SS AM/PM for end time

"@ -ForegroundColor Cyan
}
#endregion

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
    
    switch ($choice) {
        "1" {
            Write-Info "Unexpected Reboot Log Collection:"
            if ($tssAvailable) {
                Write-Info "Collect memory dump and run:"
                Write-Host "TSS.ps1 -SDP Perf -AcceptEula" -ForegroundColor Cyan
                Write-Host "TSS.ps1 -SDP Setup -AcceptEula" -ForegroundColor Cyan
                Write-Host "TSS.ps1 -Collectlog DND_Setup" -ForegroundColor Cyan
                Write-Info "Ensure to collect Memory.dmp from C:\Windows\ and minidump files from C:\Windows\Minidump\"
            }
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
        }
        "6" {
            Write-Info "Cluster Related Issues:"
            if ($tssAvailable) {
                Write-Host "TSS.ps1 -SDP Cluster -AcceptEula" -ForegroundColor Cyan
                Write-Info "Run on ALL cluster nodes"
            }
            Write-Info "`nCluster Logs:"
            Write-Host "Get-ClusterLog -TimeSpan 60 -UseLocalTime -Destination D:\clusterlog\" -ForegroundColor Cyan
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
            Write-Info "5. Check logs: C:\Windows\Logs\CBS.log, DISM.log, and Setup event log"
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
                # Check Security log access
                $securityLogAccess = $true
                try {
                    Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null
                }
                catch {
                    $securityLogAccess = $false
                    Write-WarningMessage "No access to Security event log - skipping Security log export"
                }
                
                # Export System log
                try {
                    Write-Info "Exporting System event log..."
                    wevtutil epl System (Join-Path $exportPath "system.evtx")
                    Write-Success "  System log exported successfully"
                }
                catch {
                    Write-ErrorMessage "  Failed to export System log: $($_.Exception.Message)"
                }
                
                # Export Application log
                try {
                    Write-Info "Exporting Application event log..."
                    wevtutil epl Application (Join-Path $exportPath "application.evtx")
                    Write-Success "  Application log exported successfully"
                }
                catch {
                    Write-ErrorMessage "  Failed to export Application log: $($_.Exception.Message)"
                }
                
                # Export Security log if accessible
                if ($securityLogAccess) {
                    try {
                        Write-Info "Exporting Security event log..."
                        wevtutil epl Security (Join-Path $exportPath "security.evtx")
                        Write-Success "  Security log exported successfully"
                    }
                    catch {
                        Write-ErrorMessage "  Failed to export Security log: $($_.Exception.Message)"
                    }
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

#region Report Functions
function Show-ValidatorInfo {
    <#
    .SYNOPSIS
        Displays validator script information
    .DESCRIPTION
        Provides information about the validator script and its output
    #>
    Write-Header "Validator Script Information"
    Write-Info "The validator script generates HTML output with:"
    Write-Info "  • Key server sizing and specifications"
    Write-Info "  • High-level health status"
    Write-Info "  • Configuration details"
    Write-Info "`nOutput location: C:\Windows\ServerScanner"
    Write-Info "`nRequired: Run on ALL servers (cluster nodes or standalone)"
    Write-Info "Zip the ServerScanner folder and share for analysis"
}

function Test-TLSConfiguration {
    <#
    .SYNOPSIS
        Validates TLS configuration on the server
    .DESCRIPTION
        Checks enabled TLS protocols, cipher suites, and security configurations
    .EXAMPLE
        Test-TLSConfiguration
    #>
    Write-Header "TLS Configuration Validation"
    
    # TLS Registry Paths
    $tlsProtocols = @{
        "TLS 1.0" = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
        "TLS 1.1" = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
        "TLS 1.2" = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
        "TLS 1.3" = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3"
    }
    
    Write-Info "Checking TLS Protocol Status..."
    Write-Info ""
    
    foreach ($protocol in $tlsProtocols.GetEnumerator()) {
        $protocolName = $protocol.Key
        $regPath = $protocol.Value
        
        Write-Info "--- $protocolName ---"
        
        # Check if protocol key exists
        if (Test-Path $regPath) {
            # Check Client settings
            $clientPath = Join-Path $regPath "Client"
            if (Test-Path $clientPath) {
                try {
                    $clientEnabled = Get-ItemProperty -Path $clientPath -Name "Enabled" -ErrorAction SilentlyContinue
                    $clientDisabledByDefault = Get-ItemProperty -Path $clientPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue
                    
                    if ($clientEnabled.Enabled -eq 1 -and $clientDisabledByDefault.DisabledByDefault -eq 0) {
                        Write-Success "  Client: ENABLED"
                    }
                    elseif ($clientEnabled.Enabled -eq 0 -or $clientDisabledByDefault.DisabledByDefault -eq 1) {
                        Write-WarningMessage "  Client: DISABLED"
                    }
                    else {
                        Write-Info "  Client: Not explicitly configured (using system default)"
                    }
                }
                catch {
                    Write-Info "  Client: Not explicitly configured (using system default)"
                }
            }
            else {
                Write-Info "  Client: Not explicitly configured (using system default)"
            }
            
            # Check Server settings
            $serverPath = Join-Path $regPath "Server"
            if (Test-Path $serverPath) {
                try {
                    $serverEnabled = Get-ItemProperty -Path $serverPath -Name "Enabled" -ErrorAction SilentlyContinue
                    $serverDisabledByDefault = Get-ItemProperty -Path $serverPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue
                    
                    if ($serverEnabled.Enabled -eq 1 -and $serverDisabledByDefault.DisabledByDefault -eq 0) {
                        Write-Success "  Server: ENABLED"
                    }
                    elseif ($serverEnabled.Enabled -eq 0 -or $serverDisabledByDefault.DisabledByDefault -eq 1) {
                        Write-WarningMessage "  Server: DISABLED"
                    }
                    else {
                        Write-Info "  Server: Not explicitly configured (using system default)"
                    }
                }
                catch {
                    Write-Info "  Server: Not explicitly configured (using system default)"
                }
            }
            else {
                Write-Info "  Server: Not explicitly configured (using system default)"
            }
        }
        else {
            Write-Info "  Protocol registry key does not exist (using system default)"
        }
        
        Write-Info ""
    }
    
    # Security Recommendations
    Write-Info "--- Security Recommendations ---"
    Write-WarningMessage "TLS 1.0 and TLS 1.1 are deprecated and should be disabled"
    Write-Success "TLS 1.2 should be enabled (minimum requirement)"
    Write-Success "TLS 1.3 should be enabled for best security (Windows Server 2022+)"
    Write-Info ""
    
    # Check .NET Framework TLS support
    Write-Info "--- .NET Framework TLS Support ---"
    try {
        $netFx4Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path) {
            $schUseStrongCrypto = Get-ItemProperty -Path $netFx4Path -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
            $systemDefaultTls = Get-ItemProperty -Path $netFx4Path -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue
            
            if ($schUseStrongCrypto.SchUseStrongCrypto -eq 1) {
                Write-Success ".NET 4.x (32-bit): Strong Crypto ENABLED"
            }
            else {
                Write-WarningMessage ".NET 4.x (32-bit): Strong Crypto NOT enabled"
            }
            
            if ($systemDefaultTls.SystemDefaultTlsVersions -eq 1) {
                Write-Success ".NET 4.x (32-bit): System Default TLS ENABLED"
            }
            else {
                Write-WarningMessage ".NET 4.x (32-bit): System Default TLS NOT enabled"
            }
        }
        
        $netFx4Path64 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path64) {
            $schUseStrongCrypto64 = Get-ItemProperty -Path $netFx4Path64 -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
            $systemDefaultTls64 = Get-ItemProperty -Path $netFx4Path64 -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue
            
            if ($schUseStrongCrypto64.SchUseStrongCrypto -eq 1) {
                Write-Success ".NET 4.x (64-bit): Strong Crypto ENABLED"
            }
            else {
                Write-WarningMessage ".NET 4.x (64-bit): Strong Crypto NOT enabled"
            }
            
            if ($systemDefaultTls64.SystemDefaultTlsVersions -eq 1) {
                Write-Success ".NET 4.x (64-bit): System Default TLS ENABLED"
            }
            else {
                Write-WarningMessage ".NET 4.x (64-bit): System Default TLS NOT enabled"
            }
        }
    }
    catch {
        Write-ErrorMessage "Failed to check .NET Framework TLS configuration: $($_.Exception.Message)"
    }
    
    Write-Info ""
    
    # Check PowerShell TLS support
    Write-Info "--- PowerShell TLS Support ---"
    try {
        $securityProtocol = [Net.ServicePointManager]::SecurityProtocol
        Write-Info "Current PowerShell Session Security Protocol: $securityProtocol"
        
        if ($securityProtocol -match "Tls12") {
            Write-Success "TLS 1.2 is available in PowerShell"
        }
        else {
            Write-WarningMessage "TLS 1.2 is NOT configured in PowerShell"
            Write-Info "To enable: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
        }
        
        if ($securityProtocol -match "Tls13") {
            Write-Success "TLS 1.3 is available in PowerShell"
        }
    }
    catch {
        Write-ErrorMessage "Failed to check PowerShell TLS configuration: $($_.Exception.Message)"
    }
    
    Write-Info ""
    
    # Check cipher suites
    Write-Info "--- TLS Cipher Suites ---"
    try {
        $cipherSuites = Get-TlsCipherSuite -ErrorAction SilentlyContinue
        if ($cipherSuites) {
            Write-Info "Total Cipher Suites Enabled: $($cipherSuites.Count)"
            Write-Info ""
            Write-Info "Top 10 Enabled Cipher Suites (by priority):"
            $cipherSuites | Select-Object -First 10 | ForEach-Object {
                $suite = $_.Name
                if ($suite -match "TLS_AES|TLS_CHACHA20") {
                    Write-Success "  $suite (TLS 1.3)"
                }
                elseif ($suite -match "GCM|ECDHE") {
                    Write-Success "  $suite (Strong)"
                }
                elseif ($suite -match "CBC") {
                    Write-WarningMessage "  $suite (Consider disabling CBC mode ciphers)"
                }
                else {
                    Write-Info "  $suite"
                }
            }
            
            # Check for weak cipher suites
            Write-Info ""
            Write-Info "Checking for weak/deprecated cipher suites..."
            $weakCiphers = $cipherSuites | Where-Object { 
                $_.Name -match "RC4|DES|3DES|MD5|NULL|EXPORT|anon" 
            }
            
            if ($weakCiphers) {
                Write-ErrorMessage "CRITICAL: Weak cipher suites detected!"
                $weakCiphers | ForEach-Object {
                    Write-WarningMessage "  - $($_.Name)"
                }
            }
            else {
                Write-Success "No weak cipher suites detected"
            }
        }
        else {
            Write-WarningMessage "Could not retrieve cipher suite information (may require Windows Server 2012 R2+)"
        }
    }
    catch {
        Write-WarningMessage "Could not check cipher suites: $($_.Exception.Message)"
    }
    
    Write-Info ""
    
    # Check FIPS Mode
    Write-Info "--- FIPS Mode Compliance ---"
    try {
        $fipsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
        if (Test-Path $fipsKey) {
            $fipsEnabled = (Get-ItemProperty -Path $fipsKey -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
            if ($fipsEnabled -eq 1) {
                Write-Success "FIPS Mode: ENABLED (System is FIPS 140-2 compliant)"
                Write-Info "  Note: Only FIPS-approved cryptographic algorithms are allowed"
            }
            else {
                Write-Info "FIPS Mode: DISABLED"
            }
        }
        else {
            Write-Info "FIPS Mode: Not configured (using system defaults)"
        }
    }
    catch {
        Write-WarningMessage "Could not check FIPS mode: $($_.Exception.Message)"
    }
    Write-Info "--- Quick Fix Commands ---"
    Write-Host @"

To disable TLS 1.0 and 1.1 (RECOMMENDED):
# Disable TLS 1.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force

# Disable TLS 1.1
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force

To enable TLS 1.2:
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force

To enable .NET Framework to use TLS 1.2:
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value 1 -Type DWord

NOTE: A system restart is required after making TLS changes!

"@ -ForegroundColor Cyan
}

function Export-TLSReport {
    <#
    .SYNOPSIS
        Exports TLS configuration to a report file
    .DESCRIPTION
        Creates a detailed report of TLS settings for documentation
    #>
    Write-Header "Exporting TLS Configuration Report"
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPath = Join-Path $script:DefaultLogPath "TLSReport_$($timestamp).txt"
    
    if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
        Write-ErrorMessage "Cannot create report directory"
        return
    }
    
    try {
        $report = @"
========================================
TLS CONFIGURATION REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $($env:COMPUTERNAME)
========================================

"@
        
        # Get all protocol info
        $tlsProtocols = @("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
        
        foreach ($protocol in $tlsProtocols) {
            $report += "`n--- $protocol ---`n"
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol"
            
            if (Test-Path $regPath) {
                # Client
                $clientPath = Join-Path $regPath "Client"
                if (Test-Path $clientPath) {
                    $clientProps = Get-ItemProperty -Path $clientPath -ErrorAction SilentlyContinue
                    $report += "Client Enabled: $($clientProps.Enabled)`n"
                    $report += "Client DisabledByDefault: $($clientProps.DisabledByDefault)`n"
                }
                else {
                    $report += "Client: Not configured`n"
                }
                
                # Server
                $serverPath = Join-Path $regPath "Server"
                if (Test-Path $serverPath) {
                    $serverProps = Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue
                    $report += "Server Enabled: $($serverProps.Enabled)`n"
                    $report += "Server DisabledByDefault: $($serverProps.DisabledByDefault)`n"
                }
                else {
                    $report += "Server: Not configured`n"
                }
            }
            else {
                $report += "Not configured (using system defaults)`n"
            }
        }
        
        # .NET Framework
        $report += "`n--- .NET Framework Configuration ---`n"
        $netFx4Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path) {
            $netProps = Get-ItemProperty -Path $netFx4Path -ErrorAction SilentlyContinue
            $report += "SchUseStrongCrypto (32-bit): $($netProps.SchUseStrongCrypto)`n"
            $report += "SystemDefaultTlsVersions (32-bit): $($netProps.SystemDefaultTlsVersions)`n"
        }
        
        $netFx4Path64 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path64) {
            $netProps64 = Get-ItemProperty -Path $netFx4Path64 -ErrorAction SilentlyContinue
            $report += "SchUseStrongCrypto (64-bit): $($netProps64.SchUseStrongCrypto)`n"
            $report += "SystemDefaultTlsVersions (64-bit): $($netProps64.SystemDefaultTlsVersions)`n"
        }
        
        
        # FIPS Mode
        $report += "`n--- FIPS Mode Compliance ---`n"
        $fipsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
        if (Test-Path $fipsKey) {
            $fipsEnabled = (Get-ItemProperty -Path $fipsKey -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
            $report += "FIPS Mode Enabled: $(if($fipsEnabled -eq 1){'Yes (FIPS 140-2 compliant)'}else{'No'})`n"
        }
        else {
            $report += "FIPS Mode: Not configured`n"
        }
        # Cipher Suites
        $report += "`n--- Enabled Cipher Suites ---`n"
        try {
            $cipherSuites = Get-TlsCipherSuite -ErrorAction SilentlyContinue
            if ($cipherSuites) {
                foreach ($suite in $cipherSuites) {
                    $report += "$($suite.Name)`n"
                }
            }
        }
        catch {
            $report += "Could not retrieve cipher suites`n"
        }
        
        $report | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        Write-Success "TLS Report generated: $($reportPath)"
        
        $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
        if ($open -eq "Y") {
            try {
                notepad $reportPath
            }
            catch {
                Write-WarningMessage "Could not open report automatically. Please navigate to: $($reportPath)"
            }
        }
    }
    catch {
        Write-ErrorMessage "Failed to generate TLS report: $($_.Exception.Message)"
    }
}

function Export-SystemReport {
    <#
    .SYNOPSIS
        Generates a comprehensive system diagnostic report
    .DESCRIPTION
        Creates a detailed text report with system information, resource usage,
        and configuration details
    .EXAMPLE
        Export-SystemReport
    #>
    Write-Header "Generating System Report"
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPath = Join-Path $script:DefaultLogPath "SystemReport_$($timestamp).txt"
    
    if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
        Write-ErrorMessage "Cannot create report directory"
        return
    }
    
    try {
        $report = @"
========================================
SYSTEM DIAGNOSTIC REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $($env:COMPUTERNAME)
========================================

"@
        
        # System Information
        $report += "`n--- SYSTEM INFORMATION ---`n"
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            $report += "OS: $($os.Caption) $($os.Version)`n"
            $report += "Manufacturer: $($cs.Manufacturer)`n"
            $report += "Model: $($cs.Model)`n"
            $report += "Domain: $($cs.Domain)`n"
            $report += "Last Boot: $($os.LastBootUpTime)`n"
        }
        catch {
            $report += "Error retrieving system information: $($_.Exception.Message)`n"
        }
        
        # Memory
        try {
            $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
            $freeMemGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
            $report += "`n--- MEMORY ---`n"
            $report += "Total: $($totalMemGB) GB`n"
            $report += "Free: $($freeMemGB) GB`n"
            $report += "Usage: $([math]::Round((($totalMemGB - $freeMemGB) / $totalMemGB) * 100, 2))%`n"
        }
        catch {
            $report += "Error retrieving memory information`n"
        }
        
        # CPU
        try {
            $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop
            $report += "`n--- PROCESSOR ---`n"
            $report += "Name: $($cpu.Name)`n"
            $report += "Cores: $($cpu.NumberOfCores)`n"
            $report += "Logical Processors: $($cpu.NumberOfLogicalProcessors)`n"
        }
        catch {
            $report += "Error retrieving CPU information`n"
        }
        
        # Disk
        $report += "`n--- DISK SPACE ---`n"
        try {
            $volumes = Get-Volume -ErrorAction Stop | Where-Object { $null -ne $_.DriveLetter }
            foreach ($vol in $volumes) {
                $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
                $totalGB = [math]::Round($vol.Size / 1GB, 2)
                $usedPercent = [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 2)
                $report += "Drive $($vol.DriveLetter): $($usedPercent)% used - $($freeGB) GB free of $($totalGB) GB`n"
            }
        }
        catch {
            $report += "Error retrieving disk information`n"
        }
        
        # Network
        $report += "`n--- NETWORK ADAPTERS ---`n"
        try {
            $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
            foreach ($adapter in $adapters) {
                $report += "$($adapter.Name): $($adapter.Status) - $($adapter.LinkSpeed)`n"
            }
        }
        catch {
            $report += "Error retrieving network adapter information`n"
        }
        
        # Top Processes
        $processAnalysis = Get-ProcessAnalysis
        if ($processAnalysis) {
            $report += "`n--- TOP 10 PROCESSES BY CPU ---`n"
            foreach ($proc in $processAnalysis.ByCPU) {
                $report += "$($proc.Name): CPU=$([math]::Round($proc.CPU, 2))s, Mem=$([math]::Round($proc.WS / 1MB, 2))MB`n"
            }
            
            $report += "`n--- TOP 10 PROCESSES BY MEMORY ---`n"
            foreach ($proc in $processAnalysis.ByMemory) {
                $report += "$($proc.Name): Mem=$([math]::Round($proc.WS / 1MB, 2))MB, CPU=$([math]::Round($proc.CPU, 2))s`n"
            }
        }
        
        # Services
        $report += "`n--- STOPPED AUTOMATIC SERVICES ---`n"
        try {
            $stoppedServices = Get-Service -ErrorAction Stop | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" }
            if ($stoppedServices) {
                foreach ($svc in $stoppedServices) {
                    $report += "$($svc.Name): $($svc.Status)`n"
                }
            }
            else {
                $report += "All automatic services are running`n"
            }
        }
        catch {
            $report += "Error retrieving service information`n"
        }
        
        # Power Plan
        $report += "`n--- POWER PLAN ---`n"
        try {
            $powerPlan = powercfg /getactivescheme
            $report += "$($powerPlan)`n"
        }
        catch {
            $report += "Error retrieving power plan information`n"
        }
        
        # Save report
        $report | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        Write-Success "Report generated: $($reportPath)"
        
        # Open report
        $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
        if ($open -eq "Y") {
            try {
                notepad $reportPath
            }
            catch {
                Write-WarningMessage "Could not open report automatically. Please navigate to: $($reportPath)"
            }
        }
    }
    catch {
        Write-ErrorMessage "Failed to generate system report: $($_.Exception.Message)"
    }
}
#endregion

function Get-ScriptVersion {
    <#
    .SYNOPSIS
        Displays script version information
    .DESCRIPTION
        Shows the current version and last updated date
    .OUTPUTS
        None
    #>
    Write-Header "Script Version Information"
    Write-Info "Script Name: Windows Server Troubleshooting & Log Collection Tool"
    Write-Info "Version: $($script:ScriptVersion)"
    Write-Info "Last Updated: $($script:LastUpdated)"
    Write-Info ""
    Write-Info "This script provides comprehensive diagnostics for:"
    Write-Info "   Network issues (packet loss, slowness, configuration)"
    Write-Info "   Memory issues (high usage, leaks)"
    Write-Info "   CPU issues (high usage, process analysis)"
    Write-Info "   Disk/Storage issues (latency, performance)"
    Write-Info "   Security (TLS configuration, compliance)"
    Write-Info "   System reporting and log collection"
}

function Remove-OldDiagnosticLogs {
    <#
    .SYNOPSIS
        Removes old diagnostic logs
    .DESCRIPTION
        Deletes log files older than the specified retention period
    .PARAMETER DaysToKeep
        Number of days to retain logs (default: uses $LOG_RETENTION_DAYS constant)
    .PARAMETER WhatIf
        Shows what would be deleted without actually deleting
    .OUTPUTS
        None
    #>
    param(
        [int]$DaysToKeep = $LOG_RETENTION_DAYS,
        [switch]$WhatIf
    )
    
    Write-Header "Cleaning Old Diagnostic Logs"
    
    if (-not (Test-Path $script:DefaultLogPath)) {
        Write-Info "No log directory found at: $($script:DefaultLogPath)"
        return
    }
    
    try {
        $cutoffDate = (Get-Date).AddDays(-$DaysToKeep)
        Write-Info "Removing logs older than: $($cutoffDate.ToString('yyyy-MM-dd'))"
        
        $oldFiles = Get-ChildItem -Path $script:DefaultLogPath -Recurse -File -ErrorAction Stop | 
        Where-Object { $_.LastWriteTime -lt $cutoffDate }
        
        if ($oldFiles.Count -eq 0) {
            Write-Success "No old log files found"
            return
        }
        
        $totalSize = ($oldFiles | Measure-Object -Property Length -Sum).Sum / 1MB
        
        if ($WhatIf) {
            Write-Info "Would delete $($oldFiles.Count) files ($([math]::Round($totalSize, 2)) MB)"
            $oldFiles | ForEach-Object {
                Write-Info "   $($_.Name) - $($_.LastWriteTime.ToString('yyyy-MM-dd'))"
            }
        }
        else {
            Write-Info "Found $($oldFiles.Count) old files ($([math]::Round($totalSize, 2)) MB)"
            $confirm = Get-ValidatedChoice -Prompt "Delete these files? (Y/N)" -ValidChoices @("Y", "N")
            
            if ($confirm -eq "Y") {
                $deletedCount = 0
                foreach ($file in $oldFiles) {
                    try {
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        $deletedCount++
                    }
                    catch {
                        Write-WarningMessage "Could not delete: $($file.Name)"
                    }
                }
                Write-Success "Deleted $deletedCount files"
            }
            else {
                Write-Info "Cleanup cancelled"
            }
        }
    }
    catch {
        Write-ErrorMessage "Failed to clean old logs: $($_.Exception.Message)"
    }
}


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
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     WINDOWS SERVER TROUBLESHOOTING & LOG COLLECTION TOOL      ║
║                         Version 2.0                           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-Host "`nPRIMARY DIAGNOSTICS:" -ForegroundColor Yellow
    Write-Host "  1. Network Issues (Packet Loss, Slowness, RSS Check)" -ForegroundColor White
    Write-Host "  2. Memory Issues (High Usage, Top Consumers)" -ForegroundColor White
    Write-Host "  3. CPU Issues (High Usage, Process Analysis)" -ForegroundColor White
    Write-Host "  4. Disk/Storage Issues (Latency, Performance)" -ForegroundColor White
    
    Write-Host "`nADDITIONAL SCENARIOS:" -ForegroundColor Yellow
    Write-Host "  5. Additional Troubleshooting Scenarios" -ForegroundColor White
    Write-Host "     (Reboot, Crash, SQL, Cluster, Patching, etc.)" -ForegroundColor Gray
    
    Write-Host "`nUTILITIES:" -ForegroundColor Yellow
    Write-Host "  6. Generate System Report" -ForegroundColor White
    Write-Host "  7. TLS Configuration Validation" -ForegroundColor White
    Write-Host "  8. Validator Script Information" -ForegroundColor White
    Write-Host "  9. Script Version Information" -ForegroundColor White
    Write-Host " 10. Configure TSS Path" -ForegroundColor White
    Write-Host " 11. Check TSS Status" -ForegroundColor White
    Write-Host " 12. Clean Old Diagnostic Logs" -ForegroundColor White
    
    Write-Host "`n  0. Exit" -ForegroundColor Red
    
    Write-Host "`n" + "═" * 65 -ForegroundColor Cyan
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
        Write-ErrorMessage "This script requires Administrator privileges!"
        Write-Info "Please run PowerShell as Administrator and try again."
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Initialize diagnostic paths
    if (-not (Initialize-DiagnosticPaths)) {
        Write-ErrorMessage "Failed to initialize diagnostic paths. Some features may not work correctly."
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
            Write-WarningMessage "Could not start transcript logging: $($_.Exception.Message)"
            $EnableLogging = $false
        }
    }
    
    try {
        do {
            Show-MainMenu
            $choice = Get-ValidatedChoice -Prompt "`nSelect an option (0-12)" -ValidChoices @("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12")
            
            switch ($choice) {
                "1" {
                    Clear-Host
                    Test-NetworkConfiguration
                    Write-Host "`n"
                    Start-NetworkLogCollection
                }
                "2" {
                    Clear-Host
                    Test-MemoryUsage
                    Write-Host "`n"
                    Start-MemoryLogCollection
                }
                "3" {
                    Clear-Host
                    Test-CPUUsage
                    Write-Host "`n"
                    Start-CPULogCollection
                }
                "4" {
                    Clear-Host
                    Test-DiskPerformance
                    Write-Host "`n"
                    Start-DiskLogCollection
                }
                "5" {
                    Clear-Host
                    Show-AdditionalScenarios
                }
                "6" {
                    Clear-Host
                    Export-SystemReport
                }
                "7" {
                    Clear-Host
                    Test-TLSConfiguration
                    Write-Host "`n"
                    $export = Get-ValidatedChoice -Prompt "Export TLS report? (Y/N)" -ValidChoices @("Y", "N")
                    if ($export -eq "Y") {
                        Export-TLSReport
                    }
                }
                "8" {
                    Clear-Host
                    Show-ValidatorInfo
                }
                "9" {
                    Clear-Host                    Get-ScriptVersion
                }
                "10" {
                    Clear-Host                    Set-TSSPath
                }
                "11" {
                    Clear-Host                    $null = Test-TSSAvailable
                }
                "12" {
                    Clear-Host                    Remove-OldDiagnosticLogs
                }
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
        Write-ErrorMessage "An unexpected error occurred: $($_.Exception.Message)"
        Write-Info "Stack Trace: $($_.ScriptStackTrace)"
    }
    finally {
        # Stop transcript logging if it was enabled
        if ($EnableLogging -and $transcriptPath) {
            try {
                Stop-Transcript
                Write-Success "Transcript saved to: $($transcriptPath)"
            }
            catch {
                Write-WarningMessage "Could not stop transcript: $($_.Exception.Message)"
            }
        }
    }
}
#endregion

#region Script Entry Point
# Script execution starts here
if ($EnableLogging) {
    Start-TroubleshootingTool -EnableLogging
}
else {
    Start-TroubleshootingTool
}
#endregion
