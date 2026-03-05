#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive Windows Server Troubleshooting and Log Collection Script
.DESCRIPTION
    Interactive script to diagnose and collect logs for Network, Memory, CPU, and Disk issues
.PARAMETER EnableLogging
    Enables transcript logging of the entire session
.EXAMPLE
    .\WindowsServertroubleshootingtool_v2.5.ps1
    .\WindowsServertroubleshootingtool_v2.5.ps1 -EnableLogging
.NOTES
    Version: 2.5
    Requires: Administrator privileges
    Enhanced with improved error handling, validation, and best practices
#>

param(
    [switch]$EnableLogging
)

# Requirements: PowerShell 5.1+ and the NetTCPIP module (Get-Net* cmdlets).
# Custom display functions use Write-DiagWarning/Write-DiagError to avoid overriding built-in cmdlets.
# If running on older PowerShell versions, some cmdlets may be unavailable.
#
# LOCALE NOTE: Performance counter names (Get-Counter) are locale-dependent and require
# an English OS installation. External tools (w32tm, net accounts, klist, secedit) also
# produce English-only output that this script parses. On non-English Windows installations,
# some checks may report "Could not..." or display unexpected results.

#region Constants and Configuration
# Threshold Constants (ReadOnly to prevent accidental reassignment)
Set-Variable -Name MEMORY_CRITICAL_THRESHOLD -Value 90 -Option ReadOnly -Force
Set-Variable -Name MEMORY_WARNING_THRESHOLD -Value 80 -Option ReadOnly -Force
Set-Variable -Name CPU_CRITICAL_THRESHOLD -Value 90 -Option ReadOnly -Force
Set-Variable -Name CPU_WARNING_THRESHOLD -Value 80 -Option ReadOnly -Force
Set-Variable -Name DISK_CRITICAL_THRESHOLD -Value 90 -Option ReadOnly -Force
Set-Variable -Name DISK_WARNING_THRESHOLD -Value 80 -Option ReadOnly -Force
Set-Variable -Name DISK_LATENCY_CRITICAL_MS -Value 50 -Option ReadOnly -Force
Set-Variable -Name DISK_LATENCY_WARNING_MS -Value 20 -Option ReadOnly -Force
Set-Variable -Name DISK_LATENCY_ACCEPTABLE_MS -Value 10 -Option ReadOnly -Force
Set-Variable -Name PORT_EXHAUSTION_THRESHOLD -Value 0.8 -Option ReadOnly -Force
Set-Variable -Name NONPAGED_POOL_CRITICAL_MB -Value 300 -Option ReadOnly -Force
Set-Variable -Name NONPAGED_POOL_WARNING_MB -Value 200 -Option ReadOnly -Force
Set-Variable -Name MODIFIED_PAGE_LIST_WARNING_GB -Value 2 -Option ReadOnly -Force
Set-Variable -Name PAGING_CRITICAL_THRESHOLD -Value 1000 -Option ReadOnly -Force
Set-Variable -Name PAGING_WARNING_THRESHOLD -Value 500 -Option ReadOnly -Force
Set-Variable -Name WMI_CPU_WARNING_SECONDS -Value 100 -Option ReadOnly -Force
Set-Variable -Name MONITORING_AGENT_CPU_WARNING -Value 50 -Option ReadOnly -Force
Set-Variable -Name JAVA_CPU_WARNING_SECONDS -Value 100 -Option ReadOnly -Force
Set-Variable -Name SPLIT_IO_WARNING_THRESHOLD -Value 100 -Option ReadOnly -Force
Set-Variable -Name DISK_QUEUE_WARNING_THRESHOLD -Value 2 -Option ReadOnly -Force

# Path Configuration
$script:TempBasePath = Join-Path $env:TEMP "ServerDiagnostics"
$script:DefaultLogPath = Join-Path $script:TempBasePath "Logs"

# TSS Path Configuration - HARDCODED
# Change this path to match your TSS installation location
$script:TSSPath = "C:\TSS"  # Default hardcoded path

# Critical Services to Monitor
$script:CriticalServices = @(
    "DNS", "DHCP", "Spooler", "W32Time", "EventLog",
    "WinRM", "RpcSs", "LanmanServer", "LanmanWorkstation",
    "MSSQLSERVER", "SQLSERVERAGENT", "W3SVC", "IISADMIN",
    "Netlogon", "Schedule", "TermServLicensing"
)

# Common Ports for reachability test
$script:CommonPorts = @(
    @{ Port = 3389; Name = "RDP" },
    @{ Port = 445; Name = "SMB" },
    @{ Port = 135; Name = "RPC" },
    @{ Port = 5985; Name = "WinRM" },
    @{ Port = 1433; Name = "SQL Server" },
    @{ Port = 80; Name = "HTTP" },
    @{ Port = 443; Name = "HTTPS" }
)

# Known Critical Event IDs to scan across categories
$script:KnownCriticalEventIDs = @{
    System      = @(
        @{ Id = 1135; Desc = "Cluster node removed (heartbeat loss)" },
        @{ Id = 1672; Desc = "Cluster node quarantined" },
        @{ Id = 129; Desc = "Storage adapter reset/timeout" },
        @{ Id = 153; Desc = "Disk write retry (storage path failure)" },
        @{ Id = 55; Desc = "NTFS file system corruption" },
        @{ Id = 7034; Desc = "Service terminated unexpectedly" },
        @{ Id = 5719; Desc = "Netlogon cannot connect to domain controller" },
        @{ Id = 36870; Desc = "Schannel TLS fatal error (certificate/key)" },
        @{ Id = 6008; Desc = "Unexpected shutdown" },
        @{ Id = 8018; Desc = "DNS dynamic update failure" },
        @{ Id = 8019; Desc = "DNS dynamic update failure (access denied)" }
    )
    Security    = @(
        @{ Id = 4625; Desc = "Failed logon attempt" },
        @{ Id = 4740; Desc = "Account lockout" }
    )
    Application = @(
        @{ Id = 1000; Desc = "Application crash" },
        @{ Id = 1026; Desc = ".NET runtime error" }
    )
}
#endregion

#region Output and Display Functions

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

function Write-DiagWarning {
    <#
    .SYNOPSIS
        Displays a warning message
    .PARAMETER Text
        The warning message to display
    #>
    param([string]$Text)
    # Forward to the built-in warning cmdlet to preserve expected behavior
    Microsoft.PowerShell.Utility\Write-Warning -Message $Text
}

function Write-DiagError {
    <#
    .SYNOPSIS
        Displays an error message
    .PARAMETER Text
        The error message to display
    #>
    param([string]$Text)
    # Forward to the built-in error cmdlet to preserve error records and streams
    Microsoft.PowerShell.Utility\Write-Error -Message $Text
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

#region Event Message Helper
function Get-EventSnippet {
    <#
    .SYNOPSIS
        Safely extracts a message snippet from an event log entry
    .PARAMETER Event
        The event log entry
    .PARAMETER MaxLength
        Maximum number of characters to return (default: 100)
    #>
    param(
        [Parameter(Mandatory = $true)]$Event,
        [int]$MaxLength = 100
    )
    
    $msg = $Event.Message
    if ([string]::IsNullOrEmpty($msg)) {
        return "(No message available)"
    }
    $msg = $msg -replace '[\r\n]+', ' '
    if ($msg.Length -gt $MaxLength) {
        return $msg.Substring(0, $MaxLength)
    }
    return $msg
}
#endregion

#region Event Query Helper
function Get-RecentEvents {
    <#
    .SYNOPSIS
        Shared helper to query recent Windows Event Log entries
    .PARAMETER LogName
        Event log name (e.g. System, Application, Security)
    .PARAMETER EventIds
        Array of Event IDs to search for
    .PARAMETER HoursBack
        Number of hours to look back (default: 24)
    .PARAMETER DaysBack
        Number of days to look back (overrides HoursBack if specified)
    .PARAMETER MaxEvents
        Maximum events to return (default: 50)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][int[]]$EventIds,
        [int]$HoursBack = 0,
        [int]$DaysBack = 0,
        [int]$MaxEvents = 50
    )
    
    $startTime = if ($DaysBack -gt 0) { (Get-Date).AddDays(-$DaysBack) } elseif ($HoursBack -gt 0) { (Get-Date).AddHours(-$HoursBack) } else { (Get-Date).AddHours(-24) }
    
    try {
        @(Get-WinEvent -FilterHashtable @{
                LogName   = $LogName
                Id        = $EventIds
                StartTime = $startTime
            } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
    }
    catch {
        @()
    }
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
        Write-DiagError "Failed to initialize diagnostic paths: $($_.Exception.Message)"
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
        Write-DiagError "Invalid path format: $($Path)"
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
                Write-DiagError "Cannot create directory: $($_.Exception.Message)"
                return $false
            }
        }
        else {
            Write-DiagWarning "Path does not exist: $($Path)"
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
        
        Write-DiagWarning "Invalid choice. Please enter one of: $($ValidChoices -join ', ')"
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
        Analyzes process resource usage
    .DESCRIPTION
        Gets top processes by CPU and Memory usage in a single call
    .PARAMETER TopCount
        Number of top processes to return (default: 10)
    #>
    param(
        [int]$TopCount = 10
    )
    
    try {
        $processes = Get-Process -ErrorAction Stop
        
        return @{
            ByCPU    = $processes | Sort-Object CPU -Descending | Select-Object -First $TopCount
            ByMemory = $processes | Sort-Object WS -Descending | Select-Object -First $TopCount
            Total    = $processes.Count
        }
    }
    catch {
        Write-DiagError "Failed to retrieve process information: $($_.Exception.Message)"
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
        Write-DiagError "Invalid path: Directory does not exist"
        return $false
    }
    
    # Check if TSS.ps1 exists in the provided path
    $tssScript = Join-Path $userPath "TSS.ps1"
    if (-not (Test-Path $tssScript -PathType Leaf)) {
        Write-DiagError "TSS.ps1 not found in the specified directory: $($userPath)"
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
        Write-DiagWarning "TSS path not configured"
        Write-Info "Please configure TSS path from the main menu (option 8)"
        Write-Info "Download TSS from:"
        Write-Info "  - https://aka.ms/getTSS"
        Write-Info "  - https://aka.ms/getTSSlite"
        Write-Info "  - https://cesdiagtools.blob.core.windows.net/windows/TSS.zip"
        return $false
    }
    
    if (-not (Test-Path $script:TSSPath -PathType Container)) {
        Write-DiagWarning "TSS directory not found at: $($script:TSSPath)"
        Write-Info "Please update TSS path from the main menu (option 8)"
        return $false
    }
    
    $tssScript = Join-Path $script:TSSPath "TSS.ps1"
    if (Test-Path $tssScript) {
        Write-Success "TSS found at: $($tssScript)"
        return $true
    }
    else {
        Write-DiagWarning "TSS.ps1 not found at: $($script:TSSPath)"
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
        Write-DiagError "TSS path not configured. Please configure from main menu (option 8)"
        return $false
    }
    
    if (-not (Test-Path $script:TSSPath -PathType Container)) {
        Write-DiagError "TSS directory not found at: $($script:TSSPath)"
        return $false
    }
    
    $tssScript = Join-Path $script:TSSPath "TSS.ps1"
    if (-not (Test-Path $tssScript)) {
        Write-DiagError "TSS.ps1 not found at: $($tssScript)"
        return $false
    }
    
    # S1: Verify the TSS script has a valid digital signature
    try {
        $sig = Get-AuthenticodeSignature -FilePath $tssScript -ErrorAction Stop
        switch ($sig.Status) {
            'Valid' {
                Write-Success "TSS.ps1 signature verified (signed by: $($sig.SignerCertificate.Subject))"
            }
            'NotSigned' {
                Write-DiagWarning "TSS.ps1 is NOT digitally signed. Verify you downloaded it from an official Microsoft source."
                $proceed = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                if ($proceed -ne "Y") {
                    Write-Info "TSS command cancelled by user."
                    return $false
                }
            }
            default {
                Write-DiagError "TSS.ps1 signature status: $($sig.Status) - $($sig.StatusMessage)"
                $proceed = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                if ($proceed -ne "Y") {
                    Write-Info "TSS command cancelled by user."
                    return $false
                }
            }
        }
    }
    catch {
        Write-DiagWarning "Could not verify TSS.ps1 signature: $($_.Exception.Message)"
    }
    
    try {
        # Change to TSS directory safely
        Push-Location $script:TSSPath
        
        # Execute TSS command using Start-Process to preserve quoted arguments
        Write-Info "Executing: powershell -File '$tssScript' $Command"
        $proc = Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tssScript`" $Command" `
            -Wait -NoNewWindow -PassThru
        if ($proc.ExitCode -ne 0) {
            Write-DiagWarning "TSS process exited with code: $($proc.ExitCode)"
        }
        
        Write-Success "TSS command completed"
        return $true
    }
    catch {
        Write-DiagError "Failed to execute TSS command: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Return to original location
        Pop-Location
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
    [CmdletBinding()]
    param()
    
    Write-Header "Network Configuration Check"
    
    # Cache active adapters once for reuse throughout this function
    $activeAdapters = $null
    try {
        $activeAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
    }
    catch {
        Write-DiagError "Failed to enumerate network adapters: $($_.Exception.Message)"
    }
    
    try {
        # Check RSS (Receive Side Scaling)
        Write-Info "Checking RSS (Receive Side Scaling) status..."
        $adapters = Get-NetAdapterRss -ErrorAction Stop
        
        foreach ($adapter in $adapters) {
            if ($adapter.Enabled -eq $true) {
                Write-Success "RSS is ENABLED on $($adapter.Name)"
            }
            else {
                Write-DiagWarning "RSS is DISABLED on $($adapter.Name)"
                Write-Info "To enable RSS: Set-NetAdapterRss -Name '$($adapter.Name)' -Enabled `$true"
            }
        }
    }
    catch {
        Write-DiagError "Failed to check RSS status: $($_.Exception.Message)"
    }
     
    # Ephemeral Port Usage (Port Exhaustion)
    Write-Info "`nChecking TCP Ephemeral Ports:"
    try {
        $tcpParams = Get-NetTCPSetting -SettingName "Internet" -ErrorAction Stop
        $maxPorts = $tcpParams.DynamicPortRangeNumberOfPorts
        $startPort = $tcpParams.DynamicPortRangeStartPort
        $endPort = $startPort + $maxPorts - 1
        
        # Count only connections in ephemeral range with states that consume ports
        $ephemeralStates = @('Bound', 'Established', 'TimeWait', 'CloseWait', 'FinWait1', 'FinWait2', 'LastAck', 'Closing')
        $allConnections = Get-NetTCPConnection -ErrorAction Stop
        $ephemeralConnections = ($allConnections | Where-Object {
                $_.LocalPort -ge $startPort -and $_.LocalPort -le $endPort -and $_.State -in $ephemeralStates
            }).Count
        
        Write-Info "  Dynamic Port Range: $($startPort) - $($endPort)"
        Write-Info "  Total TCP Connections: $($allConnections.Count)"
        Write-Info "  Ephemeral Ports In Use: $($ephemeralConnections)"
        Write-Info "  Max Dynamic Ports Available: $($maxPorts)"
        
        if ($maxPorts -gt 0 -and $ephemeralConnections -gt ($maxPorts * $PORT_EXHAUSTION_THRESHOLD)) {
            Write-DiagError "  CRITICAL: Potential Port Exhaustion (Using >$($PORT_EXHAUSTION_THRESHOLD * 100)% of available ephemeral ports)"
        }
        else {
            Write-Success "  Port usage is within acceptable range"
        }
    }
    catch {
        Write-DiagError "Failed to check ephemeral ports: $($_.Exception.Message)"
    }

    # Check VMQ (Virtual Machine Queue) Status
    Write-Info "`nChecking VMQ Status (Relevant for Hyper-V Hosts):"
    try {
        $vmq = Get-NetAdapterVmq -ErrorAction SilentlyContinue
        if ($vmq) {
            foreach ($v in $vmq) {
                Write-Info "  $($v.Name): VMQ Enabled: $($v.Enabled)"
                if ($v.Enabled -eq $true) {
                    Write-DiagWarning "    Note: If this is a 1Gbps Broadcom adapter, consider disabling VMQ to prevent packet drops."
                }
            }
        }
        else {
            Write-Info "  No VMQ-capable adapters found or VMQ not available"
        }
    }
    catch {
        Write-DiagWarning "Could not retrieve VMQ information: $($_.Exception.Message)"
    }

    # Check Network Adapter Advanced Properties
    Write-Info "`nChecking Network Adapter Buffer Settings..."
    if ($activeAdapters) {
        foreach ($adapter in $activeAdapters) {
            Write-Info "`nAdapter: $($adapter.Name)"
            try {
                $advProps = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction Stop
                
                # Check Small Rx Buffers
                $smallRxBuffer = $advProps | Where-Object { $_.DisplayName -like "*Small*Rx*Buffer*" -or $_.RegistryKeyword -like "*SmallRxBuffers*" }
                if ($smallRxBuffer) {
                    $currentValue = $smallRxBuffer.DisplayValue
                    Write-Info "  Small Rx Buffers: $($currentValue)"
                    if ($currentValue -ne "8192") {
                        Write-DiagWarning "  Recommended value is 8192"
                    }
                }
                
                # Check Rx Ring Size
                $rxRingSize = $advProps | Where-Object { $_.DisplayName -like "*Rx Ring*" -or $_.RegistryKeyword -like "*RxRing*" }
                if ($rxRingSize) {
                    $currentValue = $rxRingSize.DisplayValue
                    Write-Info "  Rx Ring Size: $($currentValue)"
                    if ($currentValue -ne "4096") {
                        Write-DiagWarning "  Recommended value is 4096"
                    }
                }
            }
            catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
                Write-DiagWarning "  Network adapter $($adapter.Name) does not support advanced properties"
            }
            catch {
                Write-DiagWarning "  Unable to retrieve advanced properties for $($adapter.Name): $($_.Exception.Message)"
            }
        }
    }
    
    # Check Power Plan
    Write-Info "`nChecking Power Plan..."
    try {
        $powerPlan = powercfg /getactivescheme
        if ($powerPlan -like "*High performance*") {
            Write-Success "Power Plan is set to High Performance"
        }
        else {
            Write-DiagWarning "Power Plan is NOT set to High Performance"
            Write-Info "Current: $($powerPlan)"
            Write-Info "To set High Performance: powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        }
    }
    catch {
        Write-DiagError "Failed to check power plan: $($_.Exception.Message)"
    }
    
    # Network Statistics (reuses cached $activeAdapters)
    Write-Info "`nNetwork Interface Statistics:"
    if ($activeAdapters) {
        foreach ($adpt in $activeAdapters) {
            try {
                $stats = Get-NetAdapterStatistics -Name $adpt.Name -ErrorAction Stop
                Write-Info "  $($adpt.Name):"
                Write-Info "    Received Packets: $($stats.ReceivedUnicastPackets)"
                Write-Info "    Sent Packets: $($stats.SentUnicastPackets)"
                Write-Info "    Received Errors: $($stats.ReceivedPacketErrors)"
                Write-Info "    Sent Errors: $($stats.OutboundPacketErrors)"
            }
            catch {
                Write-DiagWarning "  Could not retrieve statistics for $($adpt.Name)"
            }
        }
    }
    else {
        Write-DiagWarning "  No active adapters available"
    }

    # Packet Discards (vmxnet3 alert) — reuses cached $activeAdapters
    Write-Info "`nChecking Packet Discards..."
    if ($activeAdapters) {
        foreach ($adpt in $activeAdapters) {
            try {
                $stats = Get-NetAdapterStatistics -Name $adpt.Name -ErrorAction Stop
                $discardIn = $stats.ReceivedDiscardedPackets
                $discardOut = $stats.OutboundDiscardedPackets
                if ($discardIn -gt 0 -or $discardOut -gt 0) {
                    Write-DiagWarning "  $($adpt.Name): Discards IN=$discardIn OUT=$discardOut"
                    if ($adpt.DriverDescription -like "*vmxnet3*") {
                        Write-DiagError "    vmxnet3 adapter with discards - check ring buffer size and driver version"
                    }
                }
            }
            catch { }
        }
    }

    # Port Reachability (self-telnet) — uses TcpClient with 2s timeout instead of Test-NetConnection
    Write-Info "`nPort Reachability (localhost):"
    foreach ($portDef in $script:CommonPorts) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connectTask = $tcpClient.ConnectAsync('127.0.0.1', $portDef.Port)
            $completed = $connectTask.Wait(2000)  # 2-second timeout
            if ($completed -and $tcpClient.Connected) {
                Write-Success "  $($portDef.Name) (port $($portDef.Port)): OPEN"
            }
            else {
                Write-Info "  $($portDef.Name) (port $($portDef.Port)): Closed/Not listening"
            }
            $tcpClient.Close()
            $tcpClient.Dispose()
        }
        catch {
            Write-Info "  $($portDef.Name) (port $($portDef.Port)): Closed/Not listening"
            if ($tcpClient) { $tcpClient.Dispose() }
        }
    }

    # NIC Teaming / Dual MAC Detection
    Write-Info "`nNIC Teaming Configuration:"
    try {
        $teams = Get-NetLbfoTeam -ErrorAction SilentlyContinue
        if ($teams) {
            foreach ($team in $teams) {
                Write-Info "  Team: $($team.Name) - Mode: $($team.TeamingMode) - LB: $($team.LoadBalancingAlgorithm)"
                if ($team.TeamingMode -eq "SwitchIndependent" -and $team.LoadBalancingAlgorithm -eq "AddressHash") {
                    Write-DiagWarning "    Dual MAC risk: SwitchIndependent + AddressHash may cause connectivity issues"
                }
                $members = Get-NetLbfoTeamMember -Team $team.Name -ErrorAction SilentlyContinue
                foreach ($m in $members) {
                    Write-Info "    Member: $($m.Name) - Status: $($m.AdministrativeMode)"
                }
            }
        }
        else {
            Write-Info "  No NIC teams configured"
        }
    }
    catch {
        Write-Info "  NIC teaming not available (LBFO cmdlets missing)"
    }

    # WAN Heartbeat / Cluster Link Flapping
    Write-Info "`nChecking for WAN/Heartbeat Loss Events (last 24h):"
    try {
        $heartbeatEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1135, 1129
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 5 -ErrorAction SilentlyContinue
        
        if ($heartbeatEvents) {
            Write-DiagError "  Found $($heartbeatEvents.Count) heartbeat/cluster connectivity event(s):"
            foreach ($evt in $heartbeatEvents) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] EventID $($evt.Id): $(Get-EventSnippet -Event $evt -MaxLength 100)"
            }
        }
        else {
            Write-Success "  No heartbeat loss events detected"
        }
    }
    catch {
        Write-Info "  Could not query heartbeat events (Failover Clustering may not be installed)"
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
    [CmdletBinding()]
    param()
    
    Write-Header "Memory Usage Analysis"
    
    try {
        # Get system memory info
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        # TotalVisibleMemorySize and FreePhysicalMemory are in KB;
        # dividing by 1MB (1,048,576) converts KB to GB
        $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeMemGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedMemGB = $totalMemGB - $freeMemGB
        $memUsagePercent = [math]::Round(($usedMemGB / $totalMemGB) * 100, 2)
        
        Write-Info "Total Memory: $($totalMemGB) GB"
        Write-Info "Used Memory: $($usedMemGB) GB"
        Write-Info "Free Memory: $($freeMemGB) GB"
        Write-Info "Memory Usage: $($memUsagePercent)%"
        
        if ($memUsagePercent -gt $MEMORY_CRITICAL_THRESHOLD) {
            Write-DiagError "CRITICAL: Memory usage above $($MEMORY_CRITICAL_THRESHOLD)%!"
        }
        elseif ($memUsagePercent -gt $MEMORY_WARNING_THRESHOLD) {
            Write-DiagWarning "WARNING: Memory usage above $($MEMORY_WARNING_THRESHOLD)%"
        }
        else {
            Write-Success "Memory usage is within normal range"
        }
    }
    catch {
        Write-DiagError "Failed to retrieve memory information: $($_.Exception.Message)"
        return
    }
    
    # Top memory consuming processes
    Write-Info "`nTop 10 Memory Consuming Processes:"
    # Cache process analysis for reuse in CPU diagnostics
    $script:LastProcessAnalysis = Get-ProcessAnalysis
    $processAnalysis = $script:LastProcessAnalysis
    
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
                Write-DiagError "CRITICAL: Committed bytes above $($MEMORY_CRITICAL_THRESHOLD)%!"
            }
        }
    }
    catch {
        Write-DiagWarning "Could not retrieve committed bytes information: $($_.Exception.Message)"
    }

    # NonPagedPool Usage
    Write-Info "`nNonPaged Pool Usage:"
    try {
        $npPool = Get-Counter '\Memory\Pool Nonpaged Bytes' -ErrorAction Stop
        $npMB = [math]::Round($npPool.CounterSamples.CookedValue / 1MB, 2)
        Write-Info "  NonPaged Pool: $npMB MB"
        if ($npMB -gt $NONPAGED_POOL_CRITICAL_MB) {
            Write-DiagError "  CRITICAL: NonPaged Pool >$($NONPAGED_POOL_CRITICAL_MB)MB - possible ETW buffer or driver leak"
        }
        elseif ($npMB -gt $NONPAGED_POOL_WARNING_MB) {
            Write-DiagWarning "  WARNING: NonPaged Pool elevated (>$($NONPAGED_POOL_WARNING_MB)MB)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check NonPaged Pool"
    }

    # Modified Page List (file cache pressure)
    Write-Info "`nModified Page List:"
    try {
        $modPages = Get-Counter '\Memory\Modified Page List Bytes' -ErrorAction Stop
        $modGB = [math]::Round($modPages.CounterSamples.CookedValue / 1GB, 2)
        Write-Info "  Modified Page List: $modGB GB"
        if ($modGB -gt $MODIFIED_PAGE_LIST_WARNING_GB) {
            Write-DiagWarning "  WARNING: Large modified page list ($modGB GB) - file cache consuming RAM"
            Write-Info "  Consider: Disable 'Large System Cache' or tune MaxCacheSizeInMB"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Modified Page List"
    }

    # Paging Spikes
    Write-Info "`nPaging Activity:"
    try {
        $pagesPerSec = Get-Counter '\Memory\Pages/sec' -ErrorAction Stop
        $pps = [math]::Round($pagesPerSec.CounterSamples.CookedValue, 0)
        Write-Info "  Pages/sec: $pps"
        if ($pps -gt $PAGING_CRITICAL_THRESHOLD) {
            Write-DiagError "  CRITICAL: High paging activity (>$($PAGING_CRITICAL_THRESHOLD) pages/sec) - severe memory pressure"
        }
        elseif ($pps -gt $PAGING_WARNING_THRESHOLD) {
            Write-DiagWarning "  WARNING: Elevated paging activity (>$($PAGING_WARNING_THRESHOLD) pages/sec)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check paging activity"
    }

    # Known Leaky Process Detection
    Write-Info "`nKnown Memory-Intensive Processes:"
    $leakSuspects = @("java", "BMCMainEngine", "MonitoringHost", "WinCollect", "sqlservr")
    try {
        foreach ($suspect in $leakSuspects) {
            $procs = Get-Process -Name $suspect -ErrorAction SilentlyContinue
            if ($procs) {
                foreach ($p in $procs) {
                    $wsMB = [math]::Round($p.WorkingSet64 / 1MB, 0)
                    if ($wsMB -gt 1024) {
                        Write-DiagWarning "  $($p.Name) (PID $($p.Id)): $wsMB MB - high memory consumer"
                    }
                    else {
                        Write-Info "  $($p.Name) (PID $($p.Id)): $wsMB MB"
                    }
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check known processes"
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
    
    $tssAvailable = Test-TSSAvailable
    
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
            else {
                Write-DiagWarning "TSS is not available. Please install TSS (option 15) to use this trace."
                Write-Info "Manual alternative: Use Performance Monitor to capture memory counters."
                Show-PerfmonCommand "Memory"
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
            else {
                Write-DiagWarning "TSS is not available. Please install TSS (option 15) to use this trace."
                Write-Info "Manual alternative: Use Performance Monitor to capture memory counters."
                Show-PerfmonCommand "Memory"
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
    [CmdletBinding()]
    param()
    
    Write-Header "CPU Usage Analysis"
    
    # Current CPU usage
    try {
        $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop
        if ($cpuUsage) {
            $cpuPercent = [math]::Round($cpuUsage.CounterSamples.CookedValue, 2)
            Write-Info "Current CPU Usage: $($cpuPercent)%"
            
            if ($cpuPercent -gt $CPU_CRITICAL_THRESHOLD) {
                Write-DiagError "CRITICAL: CPU usage above $($CPU_CRITICAL_THRESHOLD)%!"
            }
            elseif ($cpuPercent -gt $CPU_WARNING_THRESHOLD) {
                Write-DiagWarning "WARNING: CPU usage above $($CPU_WARNING_THRESHOLD)%"
            }
            else {
                Write-Success "CPU usage is within normal range"
            }
        }
    }
    catch {
        Write-DiagError "Failed to retrieve CPU usage: $($_.Exception.Message)"
    }
    
    # Processor information (handle multi-socket servers)
    try {
        $cpus = @(Get-CimInstance Win32_Processor -ErrorAction Stop)
        Write-Info "`nProcessor Information:"
        if ($cpus.Count -gt 1) {
            Write-Info "  Sockets: $($cpus.Count)"
        }
        foreach ($cpu in $cpus) {
            Write-Info "  Name: $($cpu.Name)"
            Write-Info "  Cores: $($cpu.NumberOfCores)"
            Write-Info "  Logical Processors: $($cpu.NumberOfLogicalProcessors)"
        }
        $totalCores = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
        $totalLP = ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        if ($cpus.Count -gt 1) {
            Write-Info "  Total Cores: $totalCores | Total Logical Processors: $totalLP"
        }
    }
    catch {
        Write-DiagError "Failed to retrieve processor information: $($_.Exception.Message)"
    }
    
    # Top CPU consuming processes
    Write-Info "`nTop 10 CPU Consuming Processes:"
    # Reuse cached process data if available (from memory diagnostics), otherwise fetch fresh
    $processAnalysis = if ($script:LastProcessAnalysis) { $script:LastProcessAnalysis } else { Get-ProcessAnalysis }
    
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
            if ($wmiCPU -gt $WMI_CPU_WARNING_SECONDS) {
                Write-DiagWarning "WMI Provider Host is consuming significant CPU time"
                Write-Info "Consider using WMI-specific trace: .\TSS.ps1 -UEX_WMIBase -WIN_Kernel -ETWflags 1 -WPR CPU -Perfmon UEX_WMIPrvSE -PerfIntervalSec 1 -noBasicLog"
            }
        }
    }
    catch {
        Write-DiagWarning "Could not check WMI process: $($_.Exception.Message)"
    }

    # Svchost.exe Breakdown (top consumers)
    Write-Info "`nTop svchost.exe Instances by CPU:"
    try {
        $svchosts = Get-Process -Name "svchost" -ErrorAction SilentlyContinue | Sort-Object CPU -Descending | Select-Object -First 5
        foreach ($sh in $svchosts) {
            $cpuSec = [math]::Round($sh.CPU, 1)
            $memMB = [math]::Round($sh.WorkingSet64 / 1MB, 0)
            # Try to get hosted services
            try {
                $services = Get-CimInstance Win32_Service -Filter "ProcessId = $($sh.Id)" -ErrorAction SilentlyContinue
                $svcNames = ($services.Name | Select-Object -First 3) -join ', '
                Write-Info "  PID $($sh.Id): CPU=${cpuSec}s Mem=${memMB}MB - $svcNames"
            }
            catch {
                Write-Info "  PID $($sh.Id): CPU=${cpuSec}s Mem=${memMB}MB"
            }
        }
    }
    catch {
        Write-DiagWarning "Could not analyze svchost processes"
    }

    # Monitoring Agent Detection
    Write-Info "`nMonitoring Agent CPU Check:"
    $monitoringAgents = @("MonitoringHost", "HealthService", "WinCollect", "MOMAgent")
    try {
        foreach ($agent in $monitoringAgents) {
            $procs = Get-Process -Name $agent -ErrorAction SilentlyContinue
            if ($procs) {
                foreach ($p in $procs) {
                    $cpuSec = [math]::Round($p.CPU, 1)
                    if ($cpuSec -gt $MONITORING_AGENT_CPU_WARNING) {
                        Write-DiagWarning "  $($p.Name) (PID $($p.Id)): CPU=${cpuSec}s - monitoring agent CPU storm"
                    }
                    else {
                        Write-Info "  $($p.Name) (PID $($p.Id)): CPU=${cpuSec}s"
                    }
                }
            }
        }
    }
    catch { }

    # Java.exe High CPU
    try {
        $javaProcs = Get-Process -Name "java" -ErrorAction SilentlyContinue
        if ($javaProcs) {
            Write-Info "`nJava Process CPU Check:"
            foreach ($jp in $javaProcs) {
                $cpuSec = [math]::Round($jp.CPU, 1)
                $memMB = [math]::Round($jp.WorkingSet64 / 1MB, 0)
                if ($cpuSec -gt $JAVA_CPU_WARNING_SECONDS) {
                    Write-DiagWarning "  java.exe (PID $($jp.Id)): CPU=${cpuSec}s Mem=${memMB}MB - high CPU"
                }
                else {
                    Write-Info "  java.exe (PID $($jp.Id)): CPU=${cpuSec}s Mem=${memMB}MB"
                }
            }
        }
    }
    catch { }

    # Split I/O Check (storage fragmentation indicator)
    Write-Info "`nSplit I/O Check:"
    try {
        $splitIO = Get-Counter '\PhysicalDisk(_Total)\Split IO/sec' -ErrorAction Stop
        $splitRate = [math]::Round($splitIO.CounterSamples.CookedValue, 0)
        Write-Info "  Split IO/sec: $splitRate"
        if ($splitRate -gt $SPLIT_IO_WARNING_THRESHOLD) {
            Write-DiagWarning "  HIGH Split I/O ($splitRate/sec) - storage fragmentation may be causing extra CPU load"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Split I/O"
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
    
    $tssAvailable = Test-TSSAvailable
    
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
            else {
                Write-DiagWarning "TSS is not available. Please install TSS (option 15) to use this trace."
                Write-Info "Manual alternative: Use Performance Monitor to capture CPU counters."
                Show-PerfmonCommand "CPU"
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
    [CmdletBinding()]
    param()
    
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
        Write-DiagError "Failed to retrieve physical disk information: $($_.Exception.Message)"
    }
    
    # Logical disk space
    Write-Info "`nLogical Disk Space:"
    try {
        $volumes = Get-Volume -ErrorAction Stop | Where-Object { $null -ne $_.DriveLetter }
        foreach ($vol in $volumes) {
            if ($vol.Size -le 0) { continue }
            $usedSpace = $vol.Size - $vol.SizeRemaining
            $usedPercent = [math]::Round(($usedSpace / $vol.Size) * 100, 2)
            $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
            
            Write-Info "  Drive $($vol.DriveLetter): - $($usedPercent)% used - $($freeGB) GB free"
            if ($usedPercent -gt $DISK_CRITICAL_THRESHOLD) {
                Write-DiagError "    CRITICAL: Less than 10% free space!"
            }
            elseif ($usedPercent -gt $DISK_WARNING_THRESHOLD) {
                Write-DiagWarning "    WARNING: Less than 20% free space"
            }
        }
    }
    catch {
        Write-DiagError "Failed to retrieve volume information: $($_.Exception.Message)"
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
                        Write-DiagError "    CRITICAL: Serious I/O bottleneck (>$($DISK_LATENCY_CRITICAL_MS)ms)"
                    }
                    elseif ($latencyMs -gt $DISK_LATENCY_WARNING_MS) {
                        Write-DiagWarning "    WARNING: Slow, needs attention ($($DISK_LATENCY_WARNING_MS)-$($DISK_LATENCY_CRITICAL_MS)ms)"
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
        Write-DiagWarning "Could not retrieve disk latency metrics: $($_.Exception.Message)"
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
                        Write-DiagWarning "    Recommended cluster size for SQL/Database servers is 64KB"
                    }
                }
            }
            catch {
                Write-DiagWarning "  Could not retrieve cluster size for drive $($vol.DriveLetter)"
            }
        }
    }
    catch {
        Write-DiagError "Failed to check cluster sizes: $($_.Exception.Message)"
    }

    # Storage Disconnect Events (129, 153)
    Write-Info "`nStorage Error Events (last 7 days):"
    try {
        $storageEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 129, 153
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 20 -ErrorAction SilentlyContinue

        if ($storageEvents) {
            $grouped = $storageEvents | Group-Object Id
            foreach ($g in $grouped) {
                Write-DiagError "  Event $($g.Name): $($g.Count) occurrence(s) in last 7 days"
                $g.Group | Select-Object -First 2 | ForEach-Object {
                    Write-DiagWarning "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $_ -MaxLength 80)"
                }
            }
        }
        else {
            Write-Success "  No storage error events (129/153) found"
        }
    }
    catch {
        Write-Info "  Could not query storage events"
    }

    # Disk Queue Length
    Write-Info "`nDisk Queue Length:"
    try {
        $queueLength = Get-Counter '\PhysicalDisk(*)\Current Disk Queue Length' -ErrorAction Stop
        foreach ($sample in $queueLength.CounterSamples) {
            if ($sample.InstanceName -ne "_total" -and $sample.CookedValue -gt 0) {
                Write-Info "  $($sample.InstanceName): Queue Length = $([math]::Round($sample.CookedValue, 1))"
                if ($sample.CookedValue -gt $DISK_QUEUE_WARNING_THRESHOLD) {
                    Write-DiagWarning "    WARNING: Queue length >$($DISK_QUEUE_WARNING_THRESHOLD) - I/O bottleneck on this disk"
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk queue length"
    }

    # Write Latency (supplement to existing read latency)
    Write-Info "`nDisk Write Latency:"
    try {
        $writeLatency = Get-Counter '\PhysicalDisk(*)\Avg. Disk sec/Write' -ErrorAction Stop
        foreach ($sample in $writeLatency.CounterSamples) {
            if ($sample.InstanceName -ne "_total") {
                $latencyMs = [math]::Round($sample.CookedValue * 1000, 2)
                Write-Info "  Write Latency - $($sample.InstanceName): $latencyMs ms"
                if ($latencyMs -gt $DISK_LATENCY_CRITICAL_MS) {
                    Write-DiagError "    CRITICAL: Write latency >$($DISK_LATENCY_CRITICAL_MS)ms"
                }
                elseif ($latencyMs -gt $DISK_LATENCY_WARNING_MS) {
                    Write-DiagWarning "    WARNING: Write latency elevated"
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check write latency"
    }

    # NTFS Metadata / Corruption Errors
    Write-Info "`nNTFS Errors (last 30 days):"
    try {
        $ntfsEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 55
            StartTime = (Get-Date).AddDays(-30)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($ntfsEvents) {
            Write-DiagError "  Found $($ntfsEvents.Count) NTFS corruption event(s)!"
            $ntfsEvents | Select-Object -First 3 | ForEach-Object {
                Write-DiagWarning "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $_ -MaxLength 100)"
            }
            Write-Info "  Run: chkdsk /R on affected volume"
        }
        else {
            Write-Success "  No NTFS errors detected"
        }
    }
    catch {
        Write-Info "  Could not query NTFS events"
    }

    # VM Pause-Critical Risk (>95% full)
    Write-Info "`nVM Pause-Critical Risk Check:"
    try {
        $volumes = Get-Volume -ErrorAction Stop | Where-Object { $null -ne $_.DriveLetter -and $_.Size -gt 0 }
        foreach ($vol in $volumes) {
            $usedPercent = [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 1)
            if ($usedPercent -gt 95) {
                Write-DiagError "  Drive $($vol.DriveLetter): $usedPercent% full - VM MAY PAUSE if disk fills completely!"
            }
        }
    }
    catch { }
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
    Write-Info "  * <$($DISK_LATENCY_ACCEPTABLE_MS)ms: Very good"
    Write-Info "  * $($DISK_LATENCY_ACCEPTABLE_MS)-$($DISK_LATENCY_WARNING_MS)ms: Okay"
    Write-Info "  * $($DISK_LATENCY_WARNING_MS)-$($DISK_LATENCY_CRITICAL_MS)ms: Slow, needs attention"
    Write-Info "  * >$($DISK_LATENCY_CRITICAL_MS)ms: Serious I/O bottleneck"
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
    param([string]$Scenario)
    
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
  * 24 hours: -si 00:01:16 (1 min 16 sec)
  * 4 hours: -si 00:00:14 (14 seconds)
  * 2 hours: -si 00:00:07 (7 seconds)

You can also use -b MM/DD/YYYY HH:MM:SS AM/PM for begin time
and -e MM/DD/YYYY HH:MM:SS AM/PM for end time

"@ -ForegroundColor Cyan
}
#endregion

#region Services Health Diagnostics
function Test-ServicesHealth {
    <#
    .SYNOPSIS
        Analyzes Windows services health
    .DESCRIPTION
        Checks critical services, stopped automatic services, and recently failed services
    .EXAMPLE
        Test-ServicesHealth
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "Windows Services Health Check"
    
    # Check critical services
    Write-Info "Checking Critical Services..."
    try {
        foreach ($svcName in $script:CriticalServices) {
            try {
                $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($null -eq $svc) { continue }
                
                if ($svc.Status -eq "Running") {
                    Write-Success "  $($svc.DisplayName) ($($svc.Name)): Running"
                }
                elseif ($svc.Status -eq "Stopped" -and $svc.StartType -eq "Automatic") {
                    Write-DiagError "  $($svc.DisplayName) ($($svc.Name)): STOPPED (Auto-Start)"
                }
                elseif ($svc.Status -eq "Stopped") {
                    Write-Info "  $($svc.DisplayName) ($($svc.Name)): Stopped ($($svc.StartType))"
                }
                else {
                    Write-DiagWarning "  $($svc.DisplayName) ($($svc.Name)): $($svc.Status)"
                }
            }
            catch {
                # Service not installed on this server, skip
            }
        }
    }
    catch {
        Write-DiagError "Failed to check critical services: $($_.Exception.Message)"
    }
    
    # Stopped automatic services
    Write-Info "`nStopped Automatic Services:"
    try {
        $stoppedAuto = Get-Service -ErrorAction Stop | Where-Object {
            $_.StartType -eq "Automatic" -and $_.Status -ne "Running"
        }
        
        if ($stoppedAuto) {
            Write-DiagWarning "  Found $($stoppedAuto.Count) stopped automatic service(s):"
            foreach ($svc in $stoppedAuto) {
                Write-DiagWarning "    - $($svc.DisplayName) ($($svc.Name)): $($svc.Status)"
            }
        }
        else {
            Write-Success "  All automatic services are running"
        }
    }
    catch {
        Write-DiagError "Failed to enumerate services: $($_.Exception.Message)"
    }
    
    # Disabled services that are typically needed
    Write-Info "`nDisabled Services (may need attention):"
    try {
        $disabledSvcs = Get-Service -ErrorAction Stop | Where-Object {
            $_.StartType -eq "Disabled"
        }
        
        if ($disabledSvcs) {
            Write-Info "  Found $($disabledSvcs.Count) disabled service(s):"
            $disabledSvcs | Select-Object -First 15 | ForEach-Object {
                Write-Info "    - $($_.DisplayName) ($($_.Name))"
            }
            if ($disabledSvcs.Count -gt 15) {
                Write-Info "    ... and $($disabledSvcs.Count - 15) more"
            }
        }
        else {
            Write-Info "  No disabled services found"
        }
    }
    catch {
        Write-DiagError "Failed to check disabled services: $($_.Exception.Message)"
    }
    
    # Recently crashed services (Event 7034)
    Write-Info "`nRecently Crashed/Terminated Services (last 24 hours):"
    try {
        $crashEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 7034
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 10 -ErrorAction SilentlyContinue
        
        if ($crashEvents) {
            Write-DiagWarning "  Found $($crashEvents.Count) service crash event(s):"
            foreach ($evt in $crashEvents) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] $(Get-EventSnippet -Event $evt -MaxLength 120)"
            }
        }
        else {
            Write-Success "  No service crashes detected in the last 24 hours"
        }
    }
    catch {
        Write-Info "  Could not query service crash events"
    }

    # W32Time NTP Sync Status
    Write-Info "`nTime Service (NTP) Sync Status:"
    try {
        $w32tmOutput = w32tm /query /status 2>&1
        if ($LASTEXITCODE -eq 0) {
            $sourceMatch = $w32tmOutput | Select-String 'Source:'
            $stratumMatch = $w32tmOutput | Select-String 'Stratum:'
            $lastSync = $w32tmOutput | Select-String 'Last Successful Sync Time:'
            if ($sourceMatch) { Write-Info "  $($sourceMatch.Line.Trim())" }
            if ($stratumMatch) { Write-Info "  $($stratumMatch.Line.Trim())" }
            if ($lastSync) {
                Write-Info "  $($lastSync.Line.Trim())"
            }
            else {
                Write-DiagWarning "  NTP has never synced successfully"
            }
        }
        else {
            Write-DiagWarning "  W32Time service may not be running"
        }
    }
    catch {
        Write-DiagWarning "  Could not check NTP status"
    }

    # Task Scheduler Health
    Write-Info "`nTask Scheduler Health:"
    try {
        $schedEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-TaskScheduler/Operational'
            Level     = 1, 2
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($schedEvents) {
            Write-DiagWarning "  Found $($schedEvents.Count) Task Scheduler error(s) in last 24h:"
            foreach ($evt in $schedEvents) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] ID:$($evt.Id) $(Get-EventSnippet -Event $evt -MaxLength 80)"
            }
        }
        else {
            Write-Success "  No Task Scheduler errors in last 24 hours"
        }
    }
    catch {
        Write-Info "  Task Scheduler Operational log not accessible"
    }

    # EventLog Service Errors
    Write-Info "`nEventLog Service Errors:"
    try {
        $evtLogErrors = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1108
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 3 -ErrorAction SilentlyContinue

        if ($evtLogErrors) {
            Write-DiagError "  EventLog service errors detected (Event 1108):"
            foreach ($evt in $evtLogErrors) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $evt -MaxLength 80)"
            }
        }
        else {
            Write-Success "  No EventLog service errors"
        }
    }
    catch { Write-Info "  Could not query EventLog errors" }

    # Netlogon / Domain Connectivity Events
    Write-Info "`nNetlogon Events:"
    try {
        $netlogonEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 5719, 7023, 7024
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($netlogonEvents) {
            Write-DiagWarning "  Found Netlogon/Service failure events:"
            foreach ($evt in $netlogonEvents) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] EventID $($evt.Id): $(Get-EventSnippet -Event $evt -MaxLength 80)"
            }
        }
        else {
            Write-Success "  No Netlogon connectivity issues"
        }
    }
    catch { Write-Info "  Could not query Netlogon events" }

    # RDP Licensing Service
    Write-Info "`nRDP Licensing:"
    try {
        $rdpLic = Get-Service -Name "TermServLicensing" -ErrorAction SilentlyContinue
        if ($null -ne $rdpLic) {
            Write-Info "  TermServLicensing: $($rdpLic.Status) ($($rdpLic.StartType))"
        }
        $rdpEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1128, 1129
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 3 -ErrorAction SilentlyContinue
        if ($rdpEvents) {
            Write-DiagWarning "  RDP licensing errors found in last 7 days"
        }
    }
    catch { }
}

function Start-ServicesLogCollection {
    <#
    .SYNOPSIS
        Starts services-related log collection
    .DESCRIPTION
        Provides options for service trace collection and manual diagnostics
    #>
    Write-Header "Services Log Collection"
    
    Write-Info "Services Log Collection Options:"
    Write-Host "1. Export all service status to file" -ForegroundColor Yellow
    Write-Host "2. TSS Performance SDP (includes services)" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-2)" -ValidChoices @("1", "2")
    
    switch ($choice) {
        "1" {
            $exportPath = Join-Path $script:DefaultLogPath "ServiceStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            try {
                if (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist) {
                    Get-Service | Sort-Object Status, Name |
                    Format-Table Name, DisplayName, Status, StartType -AutoSize |
                    Out-String -Width 200 |
                    Out-File -FilePath $exportPath -Encoding UTF8
                    Write-Success "Service status exported to: $exportPath"
                }
            }
            catch {
                Write-DiagError "Failed to export service status: $($_.Exception.Message)"
            }
        }
        "2" {
            Invoke-WithTSSCheck `
                -TSSCommand "-SDP Perf -AcceptEula" `
                -ManualAlternativeAction {
                Write-Info "Manual alternative: Run 'Get-Service | Export-Csv services.csv' to export service info"
            } `
                -Description "Starting TSS Performance SDP collection (includes service information)..."
        }
    }
}
#endregion

#region Event Log Analysis
function Test-EventLogHealth {
    <#
    .SYNOPSIS
        Analyzes Windows Event Logs for issues
    .DESCRIPTION
        Scans System and Application logs for recent errors, groups by EventID,
        and checks log capacity
    .EXAMPLE
        Test-EventLogHealth
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "Event Log Analysis"
    
    $logNames = @("System", "Application")
    
    foreach ($logName in $logNames) {
        Write-Info "`n--- $logName Log ---"
        
        # Check log size and capacity
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $usedMB = [math]::Round($log.FileSize / 1MB, 2)
            $maxMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
            $usedPercent = if ($log.MaximumSizeInBytes -gt 0) {
                [math]::Round(($log.FileSize / $log.MaximumSizeInBytes) * 100, 1)
            }
            else { 0 }
            
            Write-Info "  Log Size: $usedMB MB / $maxMB MB ($usedPercent% used)"
            
            if ($usedPercent -gt 90) {
                Write-DiagWarning "  WARNING: Log is nearly full! Consider increasing max size or archiving."
            }
        }
        catch {
            Write-DiagWarning "  Could not retrieve $logName log properties"
        }
        
        # Scan for Critical and Error events in last 24 hours
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                Level     = 1, 2  # Critical, Error
                StartTime = (Get-Date).AddHours(-24)
            } -MaxEvents 500 -ErrorAction SilentlyContinue
            
            if ($events) {
                Write-DiagWarning "  Found $($events.Count) Critical/Error events in last 24 hours"
                
                # Group by EventID and Source
                $grouped = $events | Group-Object Id, ProviderName | Sort-Object Count -Descending | Select-Object -First 10
                
                Write-Info "  Top Event IDs (by frequency):"
                foreach ($group in $grouped) {
                    $parts = $group.Name -split ', '
                    $eventId = $parts[0]
                    $source = if ($parts.Length -gt 1) { $parts[1] } else { "Unknown" }
                    Write-Info "    EventID $eventId ($source): $($group.Count) occurrence(s)"
                }
                
                # Show last 5 critical/error events
                Write-Info "`n  Last 5 Events:"
                $events | Select-Object -First 5 | ForEach-Object {
                    $levelText = switch ($_.Level) { 1 { "CRITICAL" } 2 { "ERROR" } default { "UNKNOWN" } }
                    $msgSnippet = $(Get-EventSnippet -Event $_ -MaxLength 120)
                    Write-Info "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] [$levelText] ID:$($_.Id) - $msgSnippet"
                }
            }
            else {
                Write-Success "  No Critical/Error events in last 24 hours"
            }
        }
        catch {
            Write-Info "  No matching events found or unable to query $logName log"
        }
    }

    # Cluster Events (1135, 1672)
    Write-Info "`nCluster Heartbeat/Quarantine Events (last 7 days):"
    try {
        $clusterEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1135, 1672
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($clusterEvts) {
            Write-DiagError "  Found $($clusterEvts.Count) cluster event(s):"
            foreach ($g in ($clusterEvts | Group-Object Id)) {
                Write-DiagWarning "    Event $($g.Name): $($g.Count) occurrence(s)"
            }
        }
        else {
            Write-Success "  No cluster heartbeat/quarantine events"
        }
    }
    catch { Write-Info "  Failover Clustering may not be installed" }

    # Storage Events (129, 153)
    Write-Info "`nStorage Adapter Events (129/153, last 7 days):"
    try {
        $storEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 129, 153
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($storEvts) {
            Write-DiagError "  Found $($storEvts.Count) storage error event(s):"
            foreach ($g in ($storEvts | Group-Object Id)) {
                Write-DiagWarning "    Event $($g.Name): $($g.Count) occurrence(s)"
            }
        }
        else {
            Write-Success "  No storage adapter errors"
        }
    }
    catch { }

    # DNS Update Failures (1196)
    Write-Info "`nDNS Update Failure Events:"
    try {
        $dnsEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 8018, 8019
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($dnsEvts) {
            Write-DiagWarning "  Found $($dnsEvts.Count) DNS dynamic update failure(s)"
        }
        else {
            Write-Success "  No DNS update failures"
        }
    }
    catch { }

    # Known Critical Event Summary (from $script:KnownCriticalEventIDs)
    Write-Info "`nHigh-Priority Event Summary (last 24h):"
    foreach ($logName in $script:KnownCriticalEventIDs.Keys) {
        foreach ($evtDef in $script:KnownCriticalEventIDs[$logName]) {
            try {
                # Single query instead of two — get all matching events and count
                $found = @(Get-WinEvent -FilterHashtable @{
                        LogName   = $logName
                        Id        = $evtDef.Id
                        StartTime = (Get-Date).AddHours(-24)
                    } -ErrorAction SilentlyContinue)

                if ($found.Count -gt 0) {
                    Write-DiagWarning "  [$logName] Event $($evtDef.Id) ($($evtDef.Desc)): $($found.Count) occurrence(s)"
                }
            }
            catch { }
        }
    }
}

function Start-EventLogCollection {
    <#
    .SYNOPSIS
        Starts event log collection for analysis
    .DESCRIPTION
        Provides options for event log export and TSS collection
    #>
    Write-Header "Event Log Collection"
    
    Write-Info "Event Log Collection Options:"
    Write-Host "1. Export System, Application, Security logs (.evtx)" -ForegroundColor Yellow
    Write-Host "2. TSS Setup SDP (includes event logs)" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-2)" -ValidChoices @("1", "2")
    
    switch ($choice) {
        "1" {
            $exportPath = Read-Host "Enter export path or press Enter for default"
            if ([string]::IsNullOrWhiteSpace($exportPath)) {
                $exportPath = Join-Path $script:DefaultLogPath "EventLogs"
            }
            
            if (Test-PathValid -Path $exportPath -CreateIfNotExist) {
                try {
                    $logNames = @("System", "Application", "Security")
                    foreach ($log in $logNames) {
                        Write-Info "Exporting $log event log..."
                        $evtxPath = Join-Path $exportPath "$($log.ToLower()).evtx"
                        wevtutil epl $log $evtxPath
                    }
                    Write-Success "Event logs exported to: $exportPath"
                }
                catch {
                    Write-DiagError "Failed to export event logs: $($_.Exception.Message)"
                }
            }
        }
        "2" {
            Invoke-WithTSSCheck `
                -TSSCommand "-SDP Setup -AcceptEula" `
                -ManualAlternativeAction {
                Write-Info "Manual: wevtutil epl System system.evtx"
                Write-Info "        wevtutil epl Application application.evtx"
            } `
                -Description "Starting TSS Setup SDP collection (includes event logs)..."
        }
    }
}
#endregion

#region DNS Health & Connectivity
function Test-DNSHealth {
    <#
    .SYNOPSIS
        Checks DNS health and connectivity
    .DESCRIPTION
        Verifies DNS server configuration, tests resolution, cache stats, and service status
    .EXAMPLE
        Test-DNSHealth
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "DNS Health & Connectivity"
    
    # DNS Client service status
    Write-Info "DNS Client Service Status:"
    try {
        $dnsClient = Get-Service -Name "Dnscache" -ErrorAction Stop
        if ($dnsClient.Status -eq "Running") {
            Write-Success "  DNS Client service is running"
        }
        else {
            Write-DiagError "  DNS Client service is NOT running: $($dnsClient.Status)"
        }
    }
    catch {
        Write-DiagError "  Could not check DNS Client service: $($_.Exception.Message)"
    }
    
    # Configured DNS servers per adapter
    Write-Info "`nConfigured DNS Servers:"
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            $dnsServers = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue |
            Where-Object { $_.AddressFamily -eq 2 }  # IPv4
            
            if ($null -ne $dnsServers -and $null -ne $dnsServers.ServerAddresses -and $dnsServers.ServerAddresses.Count -gt 0) {
                Write-Info "  $($adapter.Name): $($dnsServers.ServerAddresses -join ', ')"
                
                # Ping each DNS server
                foreach ($dns in $dnsServers.ServerAddresses) {
                    try {
                        $ping = Test-Connection -ComputerName $dns -Count 1 -ErrorAction Stop
                        $latency = $ping.ResponseTime
                        if ($latency -lt 50) {
                            Write-Success "    $dns - Reachable (${latency}ms)"
                        }
                        else {
                            Write-DiagWarning "    $dns - Reachable but slow (${latency}ms)"
                        }
                    }
                    catch {
                        Write-DiagError "    $dns - NOT Reachable"
                    }
                }
            }
            else {
                Write-DiagWarning "  $($adapter.Name): No DNS servers configured"
            }
        }
    }
    catch {
        Write-DiagError "Failed to check DNS configuration: $($_.Exception.Message)"
    }
    
    # DNS resolution tests
    Write-Info "`nDNS Resolution Tests:"
    $testDomains = @("microsoft.com", "google.com")
    
    foreach ($domain in $testDomains) {
        try {
            $result = Resolve-DnsName -Name $domain -Type A -ErrorAction Stop
            if ($result) {
                $ip = ($result | Where-Object { $_.Type -eq "A" } | Select-Object -First 1).IPAddress
                Write-Success "  $domain -> $ip"
            }
        }
        catch {
            Write-DiagError "  $domain -> FAILED to resolve: $($_.Exception.Message)"
        }
    }
    
    # Try to resolve the computer's own domain
    try {
        $domain = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain
        if ($domain -and $domain -ne "WORKGROUP") {
            Write-Info "`n  Testing domain resolution: $domain"
            try {
                $result = Resolve-DnsName -Name $domain -Type A -ErrorAction Stop
                Write-Success "  $domain resolved successfully"
            }
            catch {
                Write-DiagError "  $domain -> FAILED to resolve"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not determine computer domain"
    }
    
    # DNS cache statistics
    Write-Info "`nDNS Cache Statistics:"
    try {
        $cache = Get-DnsClientCache -ErrorAction Stop
        if ($cache) {
            $cacheCount = ($cache | Measure-Object).Count
            Write-Info "  Cached entries: $cacheCount"
            Write-Info "  Recent cache entries (last 5):"
            $cache | Select-Object -First 5 | ForEach-Object {
                Write-Info "    $($_.Entry) -> $($_.Data) (TTL: $($_.TimeToLive)s)"
            }
        }
        else {
            Write-Info "  DNS cache is empty"
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve DNS cache: $($_.Exception.Message)"
    }

    # DNS "Bad Key" Errors
    Write-Info "`nDNS 'Bad Key' Errors (cluster CNO/VCO failures):"
    try {
        $badKeyEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'DNS Server'
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*BADKEY*" -or $_.Message -like "*Bad Key*" }

        if ($badKeyEvents) {
            Write-DiagError "  Found $($badKeyEvents.Count) DNS Bad Key event(s) in last 7 days!"
            Write-Info "  This typically means cluster name objects (CNO/VCO) cannot update DNS"
            Write-Info "  Fix: Grant the cluster computer object 'Full Control' on the DNS record"
        }
        else {
            Write-Success "  No DNS Bad Key errors"
        }
    }
    catch {
        Write-Info "  DNS Server log not available (server may not have DNS role)"
    }

    # Cluster Listener Name Resolution
    Write-Info "`nCluster Name Resolution:"
    try {
        $clusterSvc = Get-Service -Name "ClusSvc" -ErrorAction SilentlyContinue
        if ($null -ne $clusterSvc -and $clusterSvc.Status -eq "Running") {
            $clusterName = (Get-Cluster -ErrorAction SilentlyContinue).Name
            if ($clusterName) {
                Write-Info "  Cluster: $clusterName"
                try {
                    $resolved = Resolve-DnsName $clusterName -ErrorAction Stop
                    Write-Success "  $clusterName resolves to $($resolved.IPAddress -join ', ')"
                }
                catch {
                    Write-DiagError "  FAILED to resolve cluster name '$clusterName'!"
                }
            }
        }
        else {
            Write-Info "  Failover Clustering not running on this server"
        }
    }
    catch {
        Write-Info "  Could not check cluster name resolution"
    }

    # AD Secure Dynamic DNS Update Failures
    Write-Info "`nDNS Dynamic Update Failures:"
    try {
        $dnsUpdateFail = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 8018, 8019
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($dnsUpdateFail) {
            Write-DiagWarning "  Found $($dnsUpdateFail.Count) DNS dynamic update failure(s) in last 7 days"
            foreach ($evt in $dnsUpdateFail) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $evt -MaxLength 100)"
            }
        }
        else {
            Write-Success "  No DNS dynamic update failures"
        }
    }
    catch { }

    # Reverse DNS Check
    Write-Info "`nReverse DNS Lookup:"
    try {
        $serverIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' }
        foreach ($ip in $serverIPs | Select-Object -First 2) {
            try {
                $ptr = Resolve-DnsName $ip.IPAddress -Type PTR -ErrorAction Stop
                Write-Success "  $($ip.IPAddress) -> $($ptr.NameHost)"
            }
            catch {
                Write-DiagWarning "  $($ip.IPAddress) -> No PTR record (reverse DNS missing)"
            }
        }
    }
    catch {
        Write-Info "  Could not perform reverse DNS check"
    }
}

function Start-DNSLogCollection {
    <#
    .SYNOPSIS
        Starts DNS-related log collection
    .DESCRIPTION
        Provides options for DNS trace collection
    #>
    Write-Header "DNS Log Collection"
    
    Write-Info "DNS Log Collection Options:"
    Write-Host "1. TSS DNS SDP collection" -ForegroundColor Yellow
    Write-Host "2. Manual DNS debug logging commands" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-2)" -ValidChoices @("1", "2")
    
    switch ($choice) {
        "1" {
            Invoke-WithTSSCheck `
                -TSSCommand "-SDP Net -AcceptEula" `
                -ManualAlternativeAction { Show-DNSDebugCommands } `
                -Description "Starting TSS Network SDP collection (includes DNS diagnostics)..."
        }
        "2" {
            Show-DNSDebugCommands
        }
    }
}

function Show-DNSDebugCommands {
    <#
    .SYNOPSIS
        Displays manual DNS debug commands
    #>
    Write-Info "`nManual DNS Diagnostic Commands:"
    Write-Host @"

FLUSH AND RE-REGISTER DNS:
ipconfig /flushdns
ipconfig /registerdns

DISPLAY DNS CACHE:
ipconfig /displaydns

NSLOOKUP DIAGNOSTICS:
nslookup -debug microsoft.com
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>

EXPORT DNS CLIENT EVENTS:
wevtutil epl Microsoft-Windows-DNS-Client/Operational dns-client.evtx

"@ -ForegroundColor Cyan
}
#endregion

#region Security & Authentication
function Test-SecurityAuthentication {
    <#
    .SYNOPSIS
        Checks security and authentication configuration
    .DESCRIPTION
        Examines account lockout policies, recent failed logons, Kerberos status,
        secure channel, and firewall profiles
    .EXAMPLE
        Test-SecurityAuthentication
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "Security & Authentication Check"
    
    # Account lockout policy
    Write-Info "Account Lockout Policy:"
    try {
        $lockoutPolicy = net accounts 2>&1
        $lockoutThresholdMatch = $lockoutPolicy | Select-String "Lockout threshold"
        $lockoutDurationMatch = $lockoutPolicy | Select-String "Lockout duration"
        $lockoutWindowMatch = $lockoutPolicy | Select-String "Lockout observation window"
        
        if ($null -ne $lockoutThresholdMatch) {
            $lockoutThreshold = $lockoutThresholdMatch.ToString().Trim()
            Write-Info "  $lockoutThreshold"
        }
        if ($null -ne $lockoutDurationMatch) {
            $lockoutDuration = $lockoutDurationMatch.ToString().Trim()
            Write-Info "  $lockoutDuration"
        }
        if ($null -ne $lockoutWindowMatch) {
            $lockoutWindow = $lockoutWindowMatch.ToString().Trim()
            Write-Info "  $lockoutWindow"
        }
        
        if ($null -eq $lockoutThresholdMatch) {
            Write-DiagWarning "  Could not parse lockout policy (non-English locale?)"
        }
        elseif ($lockoutThreshold -match "Never") {
            Write-DiagWarning "  WARNING: No account lockout threshold configured!"
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve lockout policy"
    }
    
    # Recent failed logon events (Event 4625)
    Write-Info "`nRecent Failed Logon Attempts (last 24 hours):"
    try {
        $failedLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        
        if ($failedLogons) {
            Write-DiagWarning "  Found $($failedLogons.Count) failed logon attempt(s)"
            
            # Group by target account
            $grouped = $failedLogons | ForEach-Object {
                try {
                    $xml = [xml]$_.ToXml()
                    $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                    $sourceIP = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                    [PSCustomObject]@{ User = $targetUser; IP = $sourceIP }
                }
                catch {
                    [PSCustomObject]@{ User = "Unknown"; IP = "Unknown" }
                }
            } | Group-Object User | Sort-Object Count -Descending | Select-Object -First 5
            
            Write-Info "  Top targeted accounts:"
            foreach ($g in $grouped) {
                Write-Info "    $($g.Name): $($g.Count) attempt(s)"
            }
        }
        else {
            Write-Success "  No failed logon attempts in last 24 hours"
        }
    }
    catch {
        Write-Info "  Could not query security event log (may require audit policy)"
    }
    
    # Kerberos ticket status
    Write-Info "`nKerberos Ticket Status:"
    try {
        $klistOutput = klist 2>&1
        $ticketCount = ($klistOutput | Select-String "Cached Tickets").ToString()
        Write-Info "  $($ticketCount.Trim())"
        
        # Show ticket details
        $klistOutput | Select-String "Server:" | Select-Object -First 5 | ForEach-Object {
            Write-Info "    $($_.ToString().Trim())"
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve Kerberos ticket information"
    }
    
    # Secure channel with domain
    Write-Info "`nDomain Secure Channel:"
    try {
        $domain = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain
        if ($domain -and $domain -ne "WORKGROUP") {
            $secureChannel = Test-ComputerSecureChannel -ErrorAction Stop
            if ($secureChannel) {
                Write-Success "  Secure channel with '$domain' is healthy"
            }
            else {
                Write-DiagError "  Secure channel with '$domain' is BROKEN"
                Write-Info "  Fix: Test-ComputerSecureChannel -Repair -Credential (Get-Credential)"
            }
        }
        else {
            Write-Info "  Server is not domain-joined (WORKGROUP)"
        }
    }
    catch {
        Write-DiagWarning "  Could not verify secure channel: $($_.Exception.Message)"
    }
    
    # Windows Firewall status
    Write-Info "`nWindows Firewall Status:"
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($profile in $fwProfiles) {
            $status = if ($profile.Enabled) { "ENABLED" } else { "DISABLED" }
            
            if ($profile.Enabled) {
                Write-Success "  $($profile.Name): $status (Inbound: $($profile.DefaultInboundAction), Outbound: $($profile.DefaultOutboundAction))"
            }
            else {
                Write-DiagWarning "  $($profile.Name): $status"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check Firewall status: $($_.Exception.Message)"
    }

    # Account Lockout Events (4740)
    Write-Info "`nAccount Lockout Events (4740, last 24h):"
    try {
        $lockoutEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4740
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($lockoutEvents) {
            Write-DiagWarning "  Found $($lockoutEvents.Count) account lockout event(s):"
            $lockoutEvents | Group-Object { $_.Properties[0].Value } | ForEach-Object {
                Write-DiagWarning "    Account '$($_.Name)': $($_.Count) lockout(s)"
            }
        }
        else {
            Write-Success "  No account lockouts in last 24 hours"
        }
    }
    catch {
        Write-Info "  Could not query lockout events (Security log may require audit policy)"
    }

    # Logon as a Service Policy
    Write-Info "`nLogon as a Service Policy:"
    try {
        $tmpFile = Join-Path $env:TEMP "secedit_export_$(Get-Random).cfg"
        try {
            $null = secedit /export /cfg $tmpFile /quiet 2>&1
            if (Test-Path $tmpFile) {
                # S2: Restrict temp file ACL — only current user + SYSTEM can read
                try {
                    $acl = Get-Acl $tmpFile
                    $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance, remove inherited rules
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $currentUser, 'FullControl', 'Allow')
                    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')
                    $acl.AddAccessRule($userRule)
                    $acl.AddAccessRule($systemRule)
                    Set-Acl $tmpFile $acl -ErrorAction Stop
                }
                catch {
                    Write-DiagWarning "  Could not restrict temp file permissions: $($_.Exception.Message)"
                }
                
                $content = Get-Content $tmpFile -Raw
                $match = [regex]::Match($content, 'SeServiceLogonRight\s*=\s*(.*)')
                if ($match.Success) {
                    Write-Info "  Accounts with 'Log on as a service' right:"
                    $accounts = $match.Groups[1].Value -split ','
                    foreach ($acct in $accounts) {
                        Write-Info "    - $($acct.Trim())"
                    }
                }
                else {
                    Write-DiagWarning "  SeServiceLogonRight not found in security policy"
                }
            }
        }
        finally {
            if (Test-Path $tmpFile -ErrorAction SilentlyContinue) {
                Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Info "  Could not export security policy"
    }

    # Schannel Errors (36870)
    Write-Info "`nSchannel TLS Errors:"
    try {
        $schannelEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 36870, 36871, 36874
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($schannelEvents) {
            Write-DiagError "  Found $($schannelEvents.Count) Schannel error(s) in last 7 days:"
            foreach ($evt in $schannelEvents) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] Event $($evt.Id): $(Get-EventSnippet -Event $evt -MaxLength 80)"
            }
            Write-Info "  Common cause: Certificate private key not readable, or TLS version mismatch"
        }
        else {
            Write-Success "  No Schannel errors"
        }
    }
    catch { }

    # NTLM vs Kerberos Detection
    Write-Info "`nAuthentication Protocol Usage (last 100 logons):"
    try {
        $logonEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 100 -ErrorAction SilentlyContinue

        if ($logonEvents) {
            $ntlmCount = ($logonEvents | Where-Object { $_.Properties[14].Value -eq 'NTLM' -or $_.Properties[14].Value -like 'NtLm*' }).Count
            $kerbCount = ($logonEvents | Where-Object { $_.Properties[14].Value -eq 'Kerberos' }).Count
            Write-Info "  Kerberos logons: $kerbCount"
            Write-Info "  NTLM logons: $ntlmCount"
            if ($ntlmCount -gt $kerbCount -and $ntlmCount -gt 10) {
                Write-DiagWarning "  WARNING: NTLM usage is high - consider investigating Kerberos fallback issues"
            }
        }
    }
    catch {
        Write-Info "  Could not analyze authentication protocols"
    }

    # MachineKeys Permissions
    Write-Info "`nMachineKeys Directory Permissions:"
    try {
        $mkPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
        if (Test-Path $mkPath) {
            $acl = Get-Acl $mkPath -ErrorAction Stop
            $hasSystem = $acl.Access | Where-Object { $_.IdentityReference -like '*SYSTEM*' }
            $hasAdmins = $acl.Access | Where-Object { $_.IdentityReference -like '*Administrators*' }
            if ($hasSystem -and $hasAdmins) {
                Write-Success "  MachineKeys has SYSTEM and Administrators access"
            }
            else {
                Write-DiagError "  MachineKeys missing SYSTEM or Administrators permissions!"
                Write-Info "  This can cause RDP, TLS certificate, and encryption failures"
            }
        }
    }
    catch {
        Write-Info "  Could not check MachineKeys permissions"
    }
}

function Start-SecurityLogCollection {
    <#
    .SYNOPSIS
        Starts security-related log collection
    .DESCRIPTION
        Provides options for authentication traces and firewall exports
    #>
    Write-Header "Security Log Collection"
    
    Write-Info "Security Log Collection Options:"
    Write-Host "1. Export Firewall rules and configuration" -ForegroundColor Yellow
    Write-Host "2. TSS Authentication trace" -ForegroundColor Yellow
    Write-Host "3. Export Security event log" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-3)" -ValidChoices @("1", "2", "3")
    
    switch ($choice) {
        "1" {
            $exportPath = Join-Path $script:DefaultLogPath "FirewallExport_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            if (Test-PathValid -Path $exportPath -CreateIfNotExist) {
                try {
                    $fwRulesPath = Join-Path $exportPath "firewall_rules.txt"
                    $fwConfigPath = Join-Path $exportPath "firewall_config.txt"
                    
                    Write-Info "Exporting firewall rules..."
                    netsh advfirewall firewall show rule name=all > $fwRulesPath
                    
                    Write-Info "Exporting firewall configuration..."
                    netsh advfirewall show allprofiles > $fwConfigPath
                    
                    Write-Success "Firewall configuration exported to: $exportPath"
                }
                catch {
                    Write-DiagError "Failed to export firewall config: $($_.Exception.Message)"
                }
            }
        }
        "2" {
            Invoke-WithTSSCheck `
                -TSSCommand "-Scenario ADS_Auth -AcceptEula" `
                -ManualAlternativeAction {
                Write-Info "Manual: Run 'nltest /sc_query:<domain>' to check secure channel"
                Write-Info "        Run 'klist' to check Kerberos tickets"
            } `
                -Description "Starting TSS Authentication trace..."
        }
        "3" {
            $secEvtxPath = Join-Path $script:DefaultLogPath "security_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
            try {
                if (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist) {
                    Write-Info "Exporting Security event log..."
                    wevtutil epl Security $secEvtxPath
                    Write-Success "Security log exported to: $secEvtxPath"
                }
            }
            catch {
                Write-DiagError "Failed to export security log: $($_.Exception.Message)"
            }
        }
    }
}
#endregion

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
    Write-Info "`nLast 10 Installed Updates:"
    try {
        $updates = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 10
        
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
            Write-DiagWarning "  No hotfix information available"
        }
    }
    catch {
        Write-DiagError "Failed to retrieve update history: $($_.Exception.Message)"
    }
    
    # Pending reboot check
    Write-Info "`nPending Reboot Check:"
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
    Write-Info "`nOS Version Information:"
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
    Write-Info "`nCBS Store Health:"
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
    Write-Info "`nPending.xml Check:"
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
    Write-Info "`nOS Lifecycle Check:"
    try {
        $build = [int]$os.BuildNumber
        if ($build -lt 14393) {
            Write-DiagError "  OS Build $build (Server 2012/2012 R2 or older) - End of extended support"
            Write-Info "  Strongly recommend in-place upgrade or migration to Server 2019/2022"
        }
        elseif ($build -lt 17763) {
            Write-DiagWarning "  OS Build $build (Server 2016) - Consider upgrade to Server 2019/2022"
        }
        else {
            Write-Success "  OS Build $build - supported version"
        }
    }
    catch { }

    # Failed Update Events
    Write-Info "`nFailed Update Events (last 7 days):"
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

#region Cross-Category Health Scorecard
function Test-CrossCategoryHealth {
    <#
    .SYNOPSIS
        Consolidated health scorecard surfacing highest-frequency cross-cutting issues
    .DESCRIPTION
        Quick summary of the most common production issues across all categories:
        cluster/AG instability, storage errors, DNS failures, RDP connectivity
    #>
    [CmdletBinding()]
    param()

    Write-Header "Cross-Category Health Scorecard"
    $issues = 0

    # 1. Cluster / AG Instability (heartbeat loss + network discards)
    Write-Info "1. Cluster / AG Stability:"
    try {
        $clusterEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1135, 1672
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($clusterEvts) {
            $issues++
            Write-DiagError "   ISSUE: $($clusterEvts.Count) cluster heartbeat/quarantine events in 7 days"
        }
        else {
            Write-Success "   OK - No cluster instability events"
        }
    }
    catch {
        Write-Info "   Skipped (Failover Clustering not installed)"
    }

    # 2. Storage 129/153 Errors
    Write-Info "2. Storage Health:"
    try {
        $storEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 129, 153
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($storEvts) {
            $issues++
            Write-DiagError "   ISSUE: $($storEvts.Count) storage adapter errors (129/153) in 7 days"
        }
        else {
            Write-Success "   OK - No storage path errors"
        }
    }
    catch { Write-Info "   Could not check" }

    # 3. DNS Bad Key / Cluster DNS
    Write-Info "3. DNS Health:"
    try {
        $dnsFailures = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 8018, 8019
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($dnsFailures) {
            $issues++
            Write-DiagWarning "   ISSUE: DNS dynamic update failures detected"
        }
        else {
            Write-Success "   OK - No DNS update failures"
        }
    }
    catch { Write-Info "   Could not check" }

    # 4. RDP Connectivity & MachineKeys
    Write-Info "4. RDP Connectivity:"
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync('127.0.0.1', 3389)
        $completed = $connectTask.Wait(2000)  # 2-second timeout
        if ($completed -and $tcpClient.Connected) {
            Write-Success "   OK - RDP port 3389 is listening"
        }
        else {
            $issues++
            Write-DiagError "   ISSUE: RDP port 3389 is NOT listening"
        }
        $tcpClient.Close()
        $tcpClient.Dispose()
    }
    catch {
        Write-Info "   Could not test RDP port"
        if ($tcpClient) { $tcpClient.Dispose() }
    }

    try {
        $mkPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
        if (Test-Path $mkPath) {
            $acl = Get-Acl $mkPath -ErrorAction Stop
            $hasSystem = $acl.Access | Where-Object { $_.IdentityReference -like '*SYSTEM*' }
            if (-not $hasSystem) {
                $issues++
                Write-DiagError "   ISSUE: MachineKeys missing SYSTEM permissions (RDP/TLS may break)"
            }
        }
    }
    catch { }

    # 5. Account Lockouts
    Write-Info "5. Account Lockouts:"
    try {
        $lockouts = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4740
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($lockouts) {
            $issues++
            Write-DiagWarning "   ISSUE: $($lockouts.Count) account lockout(s) in last 24h"
        }
        else {
            Write-Success "   OK - No account lockouts"
        }
    }
    catch { Write-Info "   Could not check (audit policy may be needed)" }

    # 6. Pending Reboot
    Write-Info "6. Pending Reboot:"
    $rebootNeeded = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") -or
    (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
    if ($rebootNeeded) {
        $issues++
        Write-DiagWarning "   ISSUE: Pending reboot detected"
    }
    else {
        Write-Success "   OK - No pending reboot"
    }

    # 7. Schannel / TLS Errors
    Write-Info "7. TLS/Schannel Health:"
    try {
        $schannelEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 36870, 36871
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 3 -ErrorAction SilentlyContinue

        if ($schannelEvts) {
            $issues++
            Write-DiagWarning "   ISSUE: Schannel TLS errors detected ($($schannelEvts.Count) in 7 days)"
        }
        else {
            Write-Success "   OK - No Schannel errors"
        }
    }
    catch { Write-Info "   Could not check" }

    # Summary
    Write-Host ""
    if ($issues -eq 0) {
        Write-Success "SCORECARD: All clear - no cross-category issues detected!"
    }
    else {
        Write-DiagWarning "SCORECARD: $issues issue area(s) need attention (see details above)"
    }
    Write-Info "Run individual diagnostics (options 1-9) for deeper analysis."
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
            }
            else {
                Write-DiagWarning "TSS is not available. Install TSS from the main menu (option 15)."
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
    Write-Info "  * Key server sizing and specifications"
    Write-Info "  * High-level health status"
    Write-Info "  * Configuration details"
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
                        Write-DiagWarning "  Client: DISABLED"
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
                        Write-DiagWarning "  Server: DISABLED"
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
    Write-DiagWarning "TLS 1.0 and TLS 1.1 are deprecated and should be disabled"
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
                Write-DiagWarning ".NET 4.x (32-bit): Strong Crypto NOT enabled"
            }
            
            if ($systemDefaultTls.SystemDefaultTlsVersions -eq 1) {
                Write-Success ".NET 4.x (32-bit): System Default TLS ENABLED"
            }
            else {
                Write-DiagWarning ".NET 4.x (32-bit): System Default TLS NOT enabled"
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
                Write-DiagWarning ".NET 4.x (64-bit): Strong Crypto NOT enabled"
            }
            
            if ($systemDefaultTls64.SystemDefaultTlsVersions -eq 1) {
                Write-Success ".NET 4.x (64-bit): System Default TLS ENABLED"
            }
            else {
                Write-DiagWarning ".NET 4.x (64-bit): System Default TLS NOT enabled"
            }
        }
    }
    catch {
        Write-DiagError "Failed to check .NET Framework TLS configuration: $($_.Exception.Message)"
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
            Write-DiagWarning "TLS 1.2 is NOT configured in PowerShell"
            Write-Info "To enable: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
        }
        
        if ($securityProtocol -match "Tls13") {
            Write-Success "TLS 1.3 is available in PowerShell"
        }
    }
    catch {
        Write-DiagError "Failed to check PowerShell TLS configuration: $($_.Exception.Message)"
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
                    Write-DiagWarning "  $suite (Consider disabling CBC mode ciphers)"
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
                Write-DiagError "CRITICAL: Weak cipher suites detected!"
                $weakCiphers | ForEach-Object {
                    Write-DiagWarning "  - $($_.Name)"
                }
            }
            else {
                Write-Success "No weak cipher suites detected"
            }
        }
        else {
            Write-DiagWarning "Could not retrieve cipher suite information (may require Windows Server 2012 R2+)"
        }
    }
    catch {
        Write-DiagWarning "Could not check cipher suites: $($_.Exception.Message)"
    }
    
    Write-Info ""
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
        Write-DiagError "Cannot create report directory"
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
                Write-DiagWarning "Could not open report automatically. Please navigate to: $($reportPath)"
            }
        }
    }
    catch {
        Write-DiagError "Failed to generate TLS report: $($_.Exception.Message)"
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
        Write-DiagError "Cannot create report directory"
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
        
        # Memory (guard against $os being $null if system info retrieval failed)
        if ($null -ne $os) {
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
        }
        else {
            $report += "`n--- MEMORY ---`nSkipped (system information unavailable)`n"
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
                if ($vol.Size -le 0) { continue }
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
                Write-DiagWarning "Could not open report automatically. Please navigate to: $($reportPath)"
            }
        }
    }
    catch {
        Write-DiagError "Failed to generate system report: $($_.Exception.Message)"
    }
}

function Get-DotNetFrameworkVersion {
    <#
    .SYNOPSIS
        Gets installed .NET Framework and .NET Core versions
    .DESCRIPTION
        Scans registry and outputs all installed versions of .NET framework
    #>
    Write-Header "Checking .NET Framework Versions"
    
    $now = Get-Date

    try {
        $release = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
    }
    catch {
        $release = $null
    }

    $OSVersion = switch ($release) {
        { $_ -ge 533325 } { ".NET Framework 4.8.1"; break }
        { $_ -ge 528040 } { ".NET Framework 4.8"; break }
        { $_ -ge 461808 } { ".NET Framework 4.7.2"; break }
        { $_ -ge 461308 } { ".NET Framework 4.7.1"; break }
        { $_ -ge 460798 } { ".NET Framework 4.7"; break }
        { $_ -ge 394802 } { ".NET Framework 4.6.2"; break }
        { $_ -ge 394254 } { ".NET Framework 4.6.1"; break }
        { $_ -ge 393295 } { ".NET Framework 4.6"; break }
        { $_ -ge 379893 } { ".NET Framework 4.5.2"; break }
        { $_ -ge 378675 } { ".NET Framework 4.5.1"; break }
        { $_ -ge 378389 } { ".NET Framework 4.5"; break }
        default { "No .NET Framework 4.5+ detected" }
    }

    $list = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -ErrorAction SilentlyContinue |
    Get-ItemProperty -Name Version, Release -ErrorAction SilentlyContinue |
    Select-Object @{Name = 'Framework'; Expression = { $_.PSChildName } }, Version, Release |
    Sort-Object Framework, Version, Release;

    $Result = foreach ($item in $list) {
        [pscustomobject]@{
            Product   = '.NET Framework'
            Framework = $item.Framework
            Version   = $item.Version
            Release   = $item.Release
        }
    }

    $Result += [pscustomobject]@{
        Product   = '.NET Framework OS Default'
        Framework = $OSVersion
        Version   = $release
        Release   = ''
    }

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $programs = @()

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $programs += Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        }
    }

    $programs = $programs | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -like "*Core Runtime*" } | Sort-Object DisplayName

    if ($programs) {
        $Result += foreach ($item in $programs) {
            [pscustomobject]@{
                Product   = '.NET Core'
                Framework = $item.DisplayName
                Version   = $item.DisplayVersion
                Release   = ''
            }
        }
    }

    $Result | Format-Table -AutoSize
    
    Write-Info "`n"
    $export = Get-ValidatedChoice -Prompt "Export .NET versions report to CSV? (Y/N)" -ValidChoices @("Y", "N")
    if ($export -eq "Y") {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $reportPath = Join-Path $script:DefaultLogPath "DotNetVersions_$($timestamp).csv"
        
        if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
            Write-DiagError "Cannot create report directory"
            return
        }
        
        # Add metadata for CSV
        $CsvResult = foreach ($item in $Result) {
            [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                Timestamp    = $now.ToString('yyyy/MM/dd HH:mm:ss')
                Product      = $item.Product
                Framework    = $item.Framework
                Version      = $item.Version
                Release      = $item.Release
            }
        }
        
        try {
            $CsvResult | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
            Write-Success "Report generated: $($reportPath)"
            
            $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
            if ($open -eq "Y") {
                try {
                    notepad $reportPath
                }
                catch {
                    Write-DiagWarning "Could not open report automatically."
                }
            }
        }
        catch {
            Write-DiagError "Failed to generate .NET versions report: $($_.Exception.Message)"
        }
    }
}
#endregion

#region IIS Diagnostics
function Test-IISHealth {
    <#
    .SYNOPSIS
        Performs comprehensive IIS health checks
    .DESCRIPTION
        Checks IIS services, AppPools, Websites, and Worker Processes.
    #>
    Write-Header "IIS Health Diagnostics"
    
    # Check if we can determine if IIS is installed (WindowsFeature module might not be available everywhere, so wrap it or ignore)
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $iisInstalled = Get-WindowsFeature -Name Web-Server -ErrorAction Stop
            if (-not $iisInstalled -or $iisInstalled.Installed -eq $false) {
                Write-DiagWarning "IIS Web-Server role is not installed."
                return
            }
        }
    }
    catch {}
    
    # Import WebAdministration
    try {
        Import-Module WebAdministration -ErrorAction Stop
    }
    catch {
        Write-DiagWarning "Could not import WebAdministration module. IIS feature may be missing or corrupt (Requires PowerShell 5.1/Windows). Execute from 64-bit PowerShell if possible."
        return
    }

    # 1. Check IIS Services
    Write-Info "`nChecking IIS Core Services Status..."
    $iisServices = @("W3SVC", "WAS", "IISADMIN")
    foreach ($svc in $iisServices) {
        try {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -eq 'Running') {
                    Write-Success "Service '$svc' is Running."
                }
                else {
                    Write-DiagWarning "Service '$svc' is $($service.Status)."
                }
            }
            else {
                Write-DiagWarning "Service '$svc' not found."
            }
        }
        catch {
            Write-DiagWarning "Failed to query service '$svc'."
        }
    }

    # 2. Check AppPools
    Write-Info "`nChecking Application Pools..."
    try {
        if (Test-Path "IIS:\AppPools") {
            $appPools = Get-ChildItem "IIS:\AppPools" -ErrorAction SilentlyContinue
            if ($appPools) {
                foreach ($pool in $appPools) {
                    $state = $pool.state
                    $identity = $pool.processModel.identityType
                    if ($state -eq 'Started') {
                        Write-Success "AppPool: $($pool.Name) | State: $state | Identity: $identity"
                    }
                    else {
                        Write-DiagWarning "AppPool: $($pool.Name) | State: $state | Identity: $identity"
                    }
                }
            }
            else {
                Write-Info "No Application Pools found."
            }
        }
        else {
            Write-DiagWarning "IIS:\AppPools path not found. Is IIS configured correctly?"
        }
    }
    catch {
        Write-DiagError "Error checking Application Pools: $($_.Exception.Message)"
    }

    # 3. Check Websites
    Write-Info "`nChecking Websites..."
    try {
        if (Test-Path "IIS:\Sites") {
            $sites = Get-ChildItem "IIS:\Sites" -ErrorAction SilentlyContinue
            if ($sites) {
                foreach ($site in $sites) {
                    $state = $site.state
                    $bindings = ($site.bindings.Collection | ForEach-Object { "$($_.protocol)://$($_.bindingInformation)" }) -join ", "
                    $path = $site.physicalPath
                    if ($state -eq 'Started') {
                        Write-Success "Site: $($site.Name) | State: $state | Bindings: $bindings | Path: $path"
                    }
                    else {
                        Write-DiagWarning "Site: $($site.Name) | State: $state | Bindings: $bindings | Path: $path"
                    }
                }
            }
            else {
                Write-Info "No Websites found."
            }
        }
    }
    catch {
        Write-DiagError "Error checking Websites: $($_.Exception.Message)"
    }

    # 4. Check Worker Processes
    Write-Info "`nChecking IIS Worker Processes (w3wp.exe)..."
    try {
        $w3wps = Get-Process -Name w3wp -ErrorAction SilentlyContinue
        if ($w3wps) {
            foreach ($wp in $w3wps) {
                # Attempt to get the AppPool Name from CommandLine
                $appPoolName = "Unknown"
                try {
                    $wmiProc = Get-WmiObject Win32_Process -Filter "ProcessId = $($wp.Id)" -ErrorAction Stop
                    if ($wmiProc.CommandLine -match "-ap `"(?<AppPool>[^`"]+)`"") {
                        $appPoolName = $Matches['AppPool']
                    }
                    elseif ($wmiProc.CommandLine -match "-ap (?<AppPool>\S+)") {
                        $appPoolName = $Matches['AppPool']
                    }
                }
                catch {}
                
                $memMB = [math]::Round($wp.WorkingSet / 1MB, 2)
                $cpuStr = if ($wp.CPU) { [math]::Round($wp.CPU, 2) } else { "N/A" }
                Write-Info "PID: $($wp.Id) | AppPool: $appPoolName | Memory: $memMB MB | CPU Time: $cpuStr sec"
            }
        }
        else {
            Write-Info "No w3wp.exe worker processes currently running."
        }
    }
    catch {
        Write-DiagError "Error checking worker processes: $($_.Exception.Message)"
    }

    # 5. Check AppPool Identities & Permissions
    Write-Info "`nChecking AppPool Identities & Permissions..."
    try {
        if ($appPools) {
            foreach ($pool in $appPools) {
                if ($pool.processModel.identityType -eq 'SpecificUser') {
                    $userName = $pool.processModel.userName
                    Write-Info "AppPool '$($pool.Name)' uses custom identity: $userName"
                    # Check if it's a local user and warn
                    if ($userName -match "^[^\\]+$" -or $userName -match "^\.\\") {
                        $cleanName = $userName -replace "^\.\\", ""
                        $localUser = Get-LocalUser -Name $cleanName -ErrorAction SilentlyContinue
                        if ($localUser) {
                            Write-Success "Local user account '$cleanName' exists."
                        }
                        else {
                            Write-DiagWarning "Local user account '$cleanName' not found. AppPool may fail to start."
                        }
                    }
                    else {
                        Write-Info "Domain/External account detected. Ensure password is not expired and account has 'Log on as a batch job' rights."
                    }
                }
                else {
                    # Built-in identity
                    Write-Success "AppPool '$($pool.Name)' uses built-in identity ($($pool.processModel.identityType))."
                }
            }
        }
        else {
            Write-Info "No Application Pools to check identities for."
        }
    }
    catch {
        Write-DiagError "Error checking AppPool identities: $($_.Exception.Message)"
    }

    # 6. Check Site Authentication Methods
    Write-Info "`nChecking Site Authentication Methods..."
    try {
        if ($sites) {
            foreach ($site in $sites) {
                $siteName = $site.Name
                $authMethods = @()
                
                $anon = Get-WebConfigurationProperty -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name enabled -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
                if ($anon -and $anon.Value -eq $true) { $authMethods += "Anonymous" }
                
                $basic = Get-WebConfigurationProperty -Filter 'system.webServer/security/authentication/basicAuthentication' -Name enabled -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
                if ($basic -and $basic.Value -eq $true) { $authMethods += "Basic" }
                
                $win = Get-WebConfigurationProperty -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name enabled -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
                if ($win -and $win.Value -eq $true) { $authMethods += "Windows" }
                
                if ($authMethods.Count -gt 0) {
                    Write-Info "Site '$siteName' enabled authentication: $($authMethods -join ', ')"
                }
                else {
                    Write-DiagWarning "Site '$siteName' has no primary authentication methods enabled (or could not read config)."
                }
            }
        }
    }
    catch {
        Write-DiagError "Error checking authentication: $($_.Exception.Message)"
    }

    # 7. Check SSL/TLS Certificate Validation
    Write-Info "`nChecking SSL/TLS Certificates..."
    try {
        if ($sites) {
            $checkedHashes = @()
            foreach ($site in $sites) {
                # Look for https bindings
                $httpsBindings = $site.bindings.Collection | Where-Object { $_.protocol -eq 'https' }
                foreach ($binding in $httpsBindings) {
                    $hashStr = ""
                    if ($null -ne $binding.certificateHash) {
                        if ($binding.certificateHash -is [byte[]]) {
                            $hashStr = ($binding.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""
                        }
                        else {
                            $hashStr = $binding.certificateHash.ToString() -replace " ", ""
                        }
                    }
                    
                    if ($hashStr) {
                        if ($checkedHashes -notcontains $hashStr) {
                            $checkedHashes += $hashStr
                             
                            # Search local machine stores
                            $cert = Get-ChildItem -Path Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $hashStr } | Select-Object -First 1
                             
                            if ($cert) {
                                $daysRemaining = ($cert.NotAfter - (Get-Date)).Days
                                if ($daysRemaining -lt 0) {
                                    Write-DiagError "Certificate for '$($site.Name)' is EXPIRED! (Thumbprint: $hashStr, Expired on: $($cert.NotAfter))"
                                }
                                elseif ($daysRemaining -lt 30) {
                                    Write-DiagWarning "Certificate for '$($site.Name)' expires in $daysRemaining days. (Expires: $($cert.NotAfter))"
                                }
                                else {
                                    Write-Success "Certificate for '$($site.Name)' is valid ($daysRemaining days remaining)."
                                }
                            }
                            else {
                                Write-DiagWarning "Bound certificate for '$($site.Name)' (Thumbprint: $hashStr) not found in Local Machine stores. (Check binding correctness)"
                            }
                        }
                    }
                }
            }
            if ($checkedHashes.Count -eq 0) {
                Write-Info "No HTTPS bindings found."
            }
        }
    }
    catch {
        Write-DiagError "Error checking certificates: $($_.Exception.Message)"
    }

    # 8. Check IP Restrictions
    Write-Info "`nChecking IP Security Restrictions..."
    try {
        if ($sites) {
            foreach ($site in $sites) {
                $siteName = $site.Name
                $ipSec = Get-WebConfigurationProperty -Filter 'system.webServer/security/ipSecurity' -Name allowUnlisted -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
                if ($ipSec -and $ipSec.Value -eq $false) {
                    Write-DiagWarning "Site '$siteName' has 'allowUnlisted' IP security set to FALSE. Unlisted IPs are blocked."
                }
                else {
                    # Check for explicit deny rules
                    $denyRules = Get-WebConfiguration -Filter 'system.webServer/security/ipSecurity/add[@allowed="false"]' -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
                    if ($denyRules) {
                        $count = @($denyRules).Count
                        Write-DiagWarning "Site '$siteName' has $count explicit IP deny rules configured."
                    }
                    else {
                        Write-Success "Site '$siteName' has no primary IP restrictions blocking unlisted traffic."
                    }
                }
            }
        }
    }
    catch {
        Write-DiagError "Error checking IP restrictions: $($_.Exception.Message)"
    }
}
#endregion

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
                         Version 2.5                            
                                                                

"@ -ForegroundColor Cyan

    Write-Host "
PRIMARY DIAGNOSTICS:" -ForegroundColor Yellow
    Write-Host "  1. Network Issues (Packet Loss, Slowness, RSS Check)" -ForegroundColor White
    Write-Host "  2. Memory Issues (High Usage, Top Consumers)" -ForegroundColor White
    Write-Host "  3. CPU Issues (High Usage, Process Analysis)" -ForegroundColor White
    Write-Host "  4. Disk/Storage Issues (Latency, Performance)" -ForegroundColor White
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
    
    Write-Host "
  0. Exit" -ForegroundColor Red
    
    Write-Host ("
" + "" * 65) -ForegroundColor Cyan
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
            $choice = Get-ValidatedChoice -Prompt "`nSelect an option (0-18)" -ValidChoices @("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18")
            
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
                    Test-ServicesHealth
                    Write-Host "`n"
                    Start-ServicesLogCollection
                }
                "6" {
                    Clear-Host
                    Test-EventLogHealth
                    Write-Host "`n"
                    Start-EventLogCollection
                }
                "7" {
                    Clear-Host
                    Test-DNSHealth
                    Write-Host "`n"
                    Start-DNSLogCollection
                }
                "8" {
                    Clear-Host
                    Test-SecurityAuthentication
                    Write-Host "`n"
                    Start-SecurityLogCollection
                }
                "9" {
                    Clear-Host
                    Test-WindowsUpdateStatus
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

#region Script Entry Point
# Script execution starts here
if ($EnableLogging) {
    Start-TroubleshootingTool -EnableLogging
}
else {
    Start-TroubleshootingTool
}
#endregion