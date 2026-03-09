#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive Windows Server Troubleshooting and Log Collection Script
.DESCRIPTION
    Interactive diagnostic tool for Windows Server 2019, 2022, and 2025.
    Diagnoses and collects logs for Network, Memory, CPU, Disk, Services, DNS,
    Security, Windows Update, TLS/SSL, IIS, and Cluster/SQL AG environments.

    v3.0 Highlights:
      - 25+ Network checks (gateway, duplex, MTU, offload, routing, proxy, RDMA, NIC drivers)
      - 19 Memory checks (page file, compression, handle/thread leaks, standby cache, RAM hardware)
      - Cluster-safe: detects AG role, CSV paths, heartbeat NICs, quorum health
      - SQL AG awareness: replica role detection, listener DNS, replication counters
      - Server 2025 ready: LBFO→SET fallback, Chimney deprecation handled
      - Clean formatted output with --- Section --- dividers and [ERROR]/[SUCCESS] tags
      - Save-to-file option on all diagnostic sections (options 1-9)
      - Non-English locale detection at startup
.PARAMETER EnableLogging
    Enables transcript logging of the entire session
.EXAMPLE
    .\WSTT_v3.0.ps1
.EXAMPLE
    .\WSTT_v3.0.ps1 -EnableLogging
.NOTES
    Version:  3.0
    Requires: Administrator privileges, PowerShell 5.1+
    Tested:   Windows Server 2019, 2022, 2025

    v3.0 Changes from v2.5:
      [Network]   15 new checks: gateway reachability, duplicate IP, link speed/duplex,
                  TCP offload, MTU consistency, DNS suffix, WINS, proxy/WinHTTP, NIC drivers,
                  binding order, firewall block rules, RDMA/SMB Direct, TCP stack params,
                  NIC error events, routing table analysis
      [Memory]    12 new checks: page file config, available MBytes, memory compression,
                  handle/thread counts, paged pool, system cache, leak trend detection,
                  standby cache breakdown, RAM hardware info, resource exhaustion events,
                  WS trimming rate, per-process private vs WS analysis
      [Cluster]   AG role detection (PRIMARY/SECONDARY) via sys.dm_hadr views,
                  CSV path guard on trace output, heartbeat NIC filtering,
                  FailoverClustering/Operational log, quorum health, AG sync scorecard,
                  AG listener DNS check, active cluster group ownership warnings
      [Compat]    Server 2025: LBFO→SET fallback, Chimney safe-access, OS lifecycle updated
                  Server 2019: Get-HotFix InstalledOn null handling
                  Locale: Non-English detection and warning at startup
      [UX]        Write-DiagError now uses [ERROR] tag (no stack traces), Write-Section
                  dividers, save-to-file prompt on all 9 primary diagnostics
      [Bugs]      Get-WmiObject→Get-CimInstance, WorkingSet→WorkingSet64, klist null-safe,
                  CBS.log path corrected, TSS argument safety, event property bounds check
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
Set-Variable -Name PAGED_POOL_CRITICAL_MB -Value 400 -Option ReadOnly -Force
Set-Variable -Name PAGED_POOL_WARNING_MB -Value 300 -Option ReadOnly -Force
Set-Variable -Name AVAILABLE_MB_CRITICAL -Value 500 -Option ReadOnly -Force
Set-Variable -Name AVAILABLE_MB_WARNING -Value 1024 -Option ReadOnly -Force
Set-Variable -Name HANDLE_LEAK_WARNING -Value 10000 -Option ReadOnly -Force
Set-Variable -Name THREAD_LEAK_WARNING -Value 500 -Option ReadOnly -Force
Set-Variable -Name WS_TRIM_WARNING_THRESHOLD -Value 1000 -Option ReadOnly -Force
Set-Variable -Name PAGEFILE_USAGE_WARNING_PERCENT -Value 70 -Option ReadOnly -Force
Set-Variable -Name PAGEFILE_USAGE_CRITICAL_PERCENT -Value 90 -Option ReadOnly -Force

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

function Write-Section {
    <#
    .SYNOPSIS
        Displays a section divider with title for readable output grouping
    .PARAMETER Text
        The section title
    #>
    param([string]$Text)
    Write-Host ""
    Write-Host "--- $Text ---" -ForegroundColor DarkCyan
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

#region Cluster and SQL AG Helper Functions
function Get-ClusterEnvironmentInfo {
    <#
    .SYNOPSIS
        Detects cluster membership, role, and SQL AG state for the local node
    .DESCRIPTION
        Returns a hashtable with IsClusterNode, ClusterName, NodeName, 
        IsAGInstalled, AGReplicas, and ClusterNetworks information.
        All downstream checks should use this cached result.
    .OUTPUTS
        Hashtable with cluster and AG environment details
    #>
    $info = @{
        IsClusterNode      = $false
        ClusterName        = $null
        NodeName           = $env:COMPUTERNAME
        ClusterNodes       = @()
        ClusterNetworks    = @()
        HeartbeatOnlyNICs  = @()
        CSVPaths           = @()
        QuorumType         = $null
        QuorumResource     = $null
        IsCAUEnabled       = $false
        IsAGInstalled      = $false
        AGDetails          = @()
        LocalReplicaRole   = $null
    }

    # Check if Failover Clustering is running
    try {
        $clusSvc = Get-Service -Name "ClusSvc" -ErrorAction SilentlyContinue
        if ($null -eq $clusSvc -or $clusSvc.Status -ne "Running") {
            return $info
        }
        $info.IsClusterNode = $true
    }
    catch { return $info }

    # Cluster basics
    try {
        $cluster = Get-Cluster -ErrorAction Stop
        $info.ClusterName = $cluster.Name
        $info.ClusterNodes = @(Get-ClusterNode -ErrorAction SilentlyContinue | Select-Object Name, State, NodeWeight)
    }
    catch { }

    # Cluster networks — identify heartbeat-only NICs
    try {
        $networks = Get-ClusterNetwork -ErrorAction SilentlyContinue
        $info.ClusterNetworks = @($networks)
        # Role 1 = Cluster only (heartbeat), Role 3 = Cluster and Client
        $info.HeartbeatOnlyNICs = @($networks | Where-Object { $_.Role -eq 1 } |
            ForEach-Object {
                $netName = $_.Name
                try {
                    $adapters = Get-ClusterNetworkInterface -Network $netName -ErrorAction SilentlyContinue
                    $adapters | Where-Object { $_.Node -eq $env:COMPUTERNAME } | ForEach-Object { $_.Adapter }
                }
                catch { }
            })
    }
    catch { }

    # Cluster Shared Volumes
    try {
        $csvs = Get-ClusterSharedVolume -ErrorAction SilentlyContinue
        $info.CSVPaths = @($csvs | ForEach-Object {
                $_.SharedVolumeInfo.FriendlyVolumeName
            })
    }
    catch { }

    # Quorum
    try {
        $quorum = Get-ClusterQuorum -ErrorAction SilentlyContinue
        if ($quorum) {
            $info.QuorumType = $quorum.QuorumType
            $info.QuorumResource = if ($quorum.QuorumResource) { $quorum.QuorumResource.Name } else { "(none)" }
        }
    }
    catch { }

    # Cluster-Aware Updating
    try {
        $cauRun = Get-CauRun -ErrorAction SilentlyContinue
        if ($null -ne $cauRun -and $cauRun.Status -ne 'Completed' -and $cauRun.Status -ne 'NotStarted') {
            $info.IsCAUEnabled = $true
        }
    }
    catch { }

    # SQL AG Detection
    try {
        $sqlSvc = Get-Service -Name "MSSQLSERVER" -ErrorAction SilentlyContinue
        if ($null -ne $sqlSvc -and $sqlSvc.Status -eq "Running") {
            $info.IsAGInstalled = $true
            try {
                $agQuery = @"
SELECT ag.name AS ag_name,
       ars.role_desc AS local_role,
       ars.synchronization_health_desc AS sync_health,
       al.dns_name AS listener_name,
       al.port AS listener_port
FROM sys.dm_hadr_availability_replica_states ars
JOIN sys.availability_groups ag ON ars.group_id = ag.group_id
LEFT JOIN sys.availability_group_listeners al ON ag.group_id = al.group_id
WHERE ars.is_local = 1
"@
                $agResults = Invoke-Sqlcmd -Query $agQuery -ServerInstance "." -ConnectionTimeout 5 -QueryTimeout 10 -ErrorAction Stop
                $info.AGDetails = @($agResults)
                if ($agResults.Count -gt 0) {
                    $info.LocalReplicaRole = $agResults[0].local_role
                }
            }
            catch {
                # Invoke-Sqlcmd may not be available; try SqlClient directly
                try {
                    $conn = New-Object System.Data.SqlClient.SqlConnection "Server=.;Integrated Security=True;Connection Timeout=5"
                    $conn.Open()
                    $cmd = $conn.CreateCommand()
                    $cmd.CommandText = "SELECT ag.name AS ag_name, ars.role_desc AS local_role, ars.synchronization_health_desc AS sync_health FROM sys.dm_hadr_availability_replica_states ars JOIN sys.availability_groups ag ON ars.group_id = ag.group_id WHERE ars.is_local = 1"
                    $reader = $cmd.ExecuteReader()
                    while ($reader.Read()) {
                        $info.AGDetails += [PSCustomObject]@{
                            ag_name       = $reader["ag_name"]
                            local_role    = $reader["local_role"]
                            sync_health   = $reader["sync_health"]
                            listener_name = $null
                            listener_port = $null
                        }
                        $info.LocalReplicaRole = $reader["local_role"]
                    }
                    $reader.Close()
                    $conn.Close()
                }
                catch { }
            }
        }
    }
    catch { }

    return $info
}

function Test-PathOnCSV {
    <#
    .SYNOPSIS
        Checks if a given path resides on a Cluster Shared Volume
    .PARAMETER Path
        The file system path to validate
    .PARAMETER CSVPaths
        Array of CSV mount points from Get-ClusterEnvironmentInfo
    .OUTPUTS
        Boolean — $true if path is on a CSV
    #>
    param(
        [string]$Path,
        [string[]]$CSVPaths
    )
    if (-not $CSVPaths -or $CSVPaths.Count -eq 0) { return $false }
    foreach ($csv in $CSVPaths) {
        if ($Path -like "$csv*") { return $true }
    }
    return $false
}

function Get-NonHeartbeatGateways {
    <#
    .SYNOPSIS
        Returns default gateways excluding cluster heartbeat-only networks
    .PARAMETER HeartbeatAdapters
        Array of adapter names that are cluster heartbeat-only
    #>
    param(
        [string[]]$HeartbeatAdapters = @()
    )
    try {
        $gateways = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop
        if ($HeartbeatAdapters.Count -eq 0) { return $gateways }
        $filtered = @()
        foreach ($gw in $gateways) {
            $ifAlias = (Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object { $_.ifIndex -eq $gw.InterfaceIndex }).Name
            if ($ifAlias -notin $HeartbeatAdapters) {
                $filtered += $gw
            }
            else {
                Write-Info "  Skipping heartbeat-only adapter '$ifAlias' for gateway ping"
            }
        }
        return $filtered
    }
    catch { return @() }
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
        
        # Execute TSS command — single-string ArgumentList preserves quoted paths in $Command
        Write-Info "Executing: powershell -File '$tssScript' $Command"
        $tssArgString = "-NoProfile -ExecutionPolicy Bypass -File `"$tssScript`" $Command"
        $proc = Start-Process -FilePath "powershell.exe" `
            -ArgumentList $tssArgString `
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
        power plan, network statistics, default gateway, link speed/duplex, TCP offload,
        MTU/jumbo frames, DNS suffix, WINS, proxy, NIC drivers, binding order, firewall
        rules, RDMA/SMB Direct, TCP parameters, NIC error events, and routing table
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
    Write-Section "TCP Ephemeral Ports"
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
    Write-Section "VMQ Status (Relevant for Hyper-V Hosts)"
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
    Write-Section "Network Adapter Buffer Settings"
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
    Write-Section "Power Plan"
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
    Write-Section "Network Interface Statistics"
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
    Write-Section "Packet Discards"
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
            catch {
                Write-Verbose "Could not check discards for $($adpt.Name): $($_.Exception.Message)"
            }
        }
    }

    # Port Reachability (self-telnet) — uses TcpClient with 2s timeout instead of Test-NetConnection
    Write-Section "Port Reachability (localhost)"
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
    Write-Section "NIC Teaming Configuration"
    try {
        $teams = Get-NetLbfoTeam -ErrorAction SilentlyContinue
        if ($teams) {
            foreach ($team in $teams) {
                Write-Info "  [LBFO] Team: $($team.Name) - Mode: $($team.TeamingMode) - LB: $($team.LoadBalancingAlgorithm)"
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
            # Server 2025+ uses Switch Embedded Teaming (SET) instead of LBFO
            $setTeams = Get-NetSwitchTeam -ErrorAction SilentlyContinue
            if ($setTeams) {
                foreach ($st in $setTeams) {
                    Write-Info "  [SET] Team: $($st.Name)"
                    $setMembers = Get-NetSwitchTeamMember -Team $st.Name -ErrorAction SilentlyContinue
                    foreach ($sm in $setMembers) {
                        Write-Info "    Member: $($sm.Name) - Status: $($sm.Status)"
                    }
                }
            }
            else {
                Write-Info "  No NIC teams configured (LBFO or SET)"
            }
        }
    }
    catch {
        # LBFO cmdlets missing (Server 2025+) — try SET
        try {
            $setTeams = Get-NetSwitchTeam -ErrorAction SilentlyContinue
            if ($setTeams) {
                foreach ($st in $setTeams) {
                    Write-Info "  [SET] Team: $($st.Name) (Switch Embedded Teaming)"
                    $setMembers = Get-NetSwitchTeamMember -Team $st.Name -ErrorAction SilentlyContinue
                    foreach ($sm in $setMembers) {
                        Write-Info "    Member: $($sm.Name)"
                    }
                }
            }
            else {
                Write-Info "  No NIC teams configured"
            }
        }
        catch {
            Write-Info "  NIC teaming not available (LBFO/SET cmdlets missing)"
        }
    }

    # WAN Heartbeat / Cluster Link Flapping
    Write-Section "WAN/Heartbeat Loss Events (last 24h)"
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

    #region v3.0 Network Checks

    # 1. Default Gateway Reachability
    Write-Section "Default Gateway Reachability"
    try {
        $gateways = Get-NonHeartbeatGateways -HeartbeatAdapters $script:ClusterEnv.HeartbeatOnlyNICs
        if ($gateways) {
            foreach ($gw in $gateways) {
                $gwIP = $gw.NextHop
                $ifIndex = $gw.InterfaceIndex
                $ifAlias = (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.ifIndex -eq $ifIndex }).Name
                if ([string]::IsNullOrWhiteSpace($ifAlias)) { $ifAlias = "ifIndex $ifIndex" }
                try {
                    $ping = Test-Connection -ComputerName $gwIP -Count 2 -ErrorAction Stop
                    $avgMs = [math]::Round(($ping.ResponseTime | Measure-Object -Average).Average, 1)
                    if ($avgMs -lt 5) {
                        Write-Success "  Gateway $gwIP ($ifAlias): Reachable (avg ${avgMs}ms)"
                    }
                    elseif ($avgMs -lt 50) {
                        Write-Info "  Gateway $gwIP ($ifAlias): Reachable (avg ${avgMs}ms)"
                    }
                    else {
                        Write-DiagWarning "  Gateway $gwIP ($ifAlias): Reachable but HIGH latency (avg ${avgMs}ms)"
                    }
                }
                catch {
                    Write-DiagError "  Gateway $gwIP ($ifAlias): NOT Reachable!"
                }
            }
        }
        else {
            Write-DiagWarning "  No default gateway configured"
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve default gateway: $($_.Exception.Message)"
    }

    # 2. Duplicate IP Detection
    Write-Section "Duplicate IP Detection"
    try {
        $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' }
        $duplicateFound = $false
        foreach ($ip in $ipAddresses) {
            try {
                $arpResult = arp -a $ip.IPAddress 2>&1
                $arpEntries = $arpResult | Select-String '([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}'
                $uniqueMACs = $arpEntries | ForEach-Object {
                    if ($_ -match '(([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})') { $Matches[0] }
                } | Select-Object -Unique
                if ($uniqueMACs -and @($uniqueMACs).Count -gt 1) {
                    $duplicateFound = $true
                    Write-DiagError "  DUPLICATE IP DETECTED: $($ip.IPAddress) has multiple MAC addresses!"
                    foreach ($mac in $uniqueMACs) {
                        Write-DiagWarning "    MAC: $mac"
                    }
                }
            }
            catch { }
        }
        if (-not $duplicateFound) {
            Write-Success "  No duplicate IP addresses detected"
        }
    }
    catch {
        Write-DiagWarning "  Could not perform duplicate IP detection: $($_.Exception.Message)"
    }

    # 3. Network Adapter Link Speed & Duplex
    Write-Section "Adapter Link Speed & Duplex"
    if ($activeAdapters) {
        foreach ($adpt in $activeAdapters) {
            $linkSpeed = $adpt.LinkSpeed
            Write-Info "  $($adpt.Name): Link Speed = $linkSpeed"
            try {
                $duplexProp = Get-NetAdapterAdvancedProperty -Name $adpt.Name -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -like "*Duplex*" -or $_.RegistryKeyword -like "*SpeedDuplex*" }
                if ($duplexProp) {
                    $duplexValue = $duplexProp.DisplayValue
                    Write-Info "    Duplex Setting: $duplexValue"
                    if ($duplexValue -like "*Half*") {
                        Write-DiagError "    HALF DUPLEX detected - this causes severe packet loss and retransmissions!"
                    }
                }
            }
            catch { }
            if ($linkSpeed -match '100\s*(Mbps|M)' -and $adpt.DriverDescription -notlike '*Virtual*') {
                Write-DiagWarning "    WARNING: 100 Mbps link speed on physical adapter - possible autonegotiation failure"
            }
        }
    }

    # 4. TCP Chimney / Task Offload Status
    Write-Section "TCP Offload Settings"
    try {
        $offload = Get-NetOffloadGlobalSetting -ErrorAction Stop
        # Chimney is deprecated/removed on newer OS — access safely
        $chimneyValue = $offload | Select-Object -ExpandProperty Chimney -ErrorAction SilentlyContinue
        if ($null -ne $chimneyValue) {
            Write-Info "  Chimney Offload: $chimneyValue"
            if ($chimneyValue -eq 'Enabled') {
                Write-DiagWarning "  TCP Chimney is ENABLED - deprecated; disable for stability"
                Write-Info "  Disable: Set-NetOffloadGlobalSetting -Chimney Disabled"
            }
        }
        else {
            Write-Info "  Chimney Offload: N/A (removed on this OS version)"
        }
        Write-Info "  Receive Side Coalescing: $($offload.ReceiveSegmentCoalescing)"
        Write-Info "  Network Direct (RDMA): $($offload.NetworkDirect)"
        Write-Info "  Task Offload: $($offload.TaskOffload)"
        Write-Info "  Packet Coalescing Filter: $($offload.PacketCoalescingFilter)"

        if ($offload.TaskOffload -eq 'Disabled') {
            Write-DiagWarning "  Task Offload is DISABLED - CPU will handle all checksum/segmentation work"
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve TCP offload settings: $($_.Exception.Message)"
    }

    # Per-adapter offload
    if ($activeAdapters) {
        foreach ($adpt in $activeAdapters) {
            try {
                $adapterOffload = Get-NetAdapterChecksumOffload -Name $adpt.Name -ErrorAction SilentlyContinue
                if ($adapterOffload) {
                    $txEnabled = $adapterOffload.TcpIPv4Checksum
                    $rxEnabled = $adapterOffload.UdpIPv4Checksum
                    if ($txEnabled -eq 'Disabled' -or $rxEnabled -eq 'Disabled') {
                        Write-DiagWarning "  $($adpt.Name): Some checksum offloads are DISABLED (TCP=$txEnabled, UDP=$rxEnabled)"
                    }
                }
            }
            catch { }
        }
    }

    # 5. MTU / Jumbo Frames Consistency
    Write-Section "MTU Configuration"
    try {
        $mtuSettings = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.ConnectionState -eq 'Connected' } |
            Select-Object InterfaceAlias, NlMtu
        $mtuValues = @()
        foreach ($iface in $mtuSettings) {
            Write-Info "  $($iface.InterfaceAlias): MTU = $($iface.NlMtu)"
            $mtuValues += $iface.NlMtu
            if ($iface.NlMtu -gt 1500) {
                Write-Info "    Jumbo Frames enabled (MTU > 1500)"
            }
        }
        $uniqueMTUs = $mtuValues | Select-Object -Unique
        if (@($uniqueMTUs).Count -gt 1) {
            Write-DiagWarning "  INCONSISTENT MTU values detected across interfaces: $($uniqueMTUs -join ', ')"
            Write-Info "  MTU mismatch can cause fragmentation, black-holed packets, and path MTU discovery failures"
        }
        else {
            Write-Success "  MTU is consistent across all connected interfaces ($($uniqueMTUs[0]))"
        }
    }
    catch {
        Write-DiagWarning "  Could not check MTU settings: $($_.Exception.Message)"
    }

    # 6. DNS Suffix & Search Order
    Write-Section "DNS Suffix Configuration"
    try {
        $dnsGlobal = Get-DnsClientGlobalSetting -ErrorAction Stop
        Write-Info "  Primary DNS Suffix: $(if ($dnsGlobal.SuffixSearchList.Count -gt 0) { $dnsGlobal.SuffixSearchList -join ', ' } else { '(none)' })"
        Write-Info "  Use Devolution: $($dnsGlobal.UseDevolution)"
        Write-Info "  Devolution Level: $($dnsGlobal.DevolutionLevel)"
    }
    catch {
        Write-DiagWarning "  Could not retrieve global DNS suffix settings"
    }
    if ($activeAdapters) {
        foreach ($adpt in $activeAdapters) {
            try {
                $dnsClient = Get-DnsClient -InterfaceAlias $adpt.Name -ErrorAction SilentlyContinue
                if ($dnsClient) {
                    $suffix = if ([string]::IsNullOrWhiteSpace($dnsClient.ConnectionSpecificSuffix)) { "(none)" } else { $dnsClient.ConnectionSpecificSuffix }
                    $registerInDns = $dnsClient.RegisterThisConnectionsAddress
                    Write-Info "  $($adpt.Name): Suffix='$suffix' RegisterInDNS=$registerInDns"
                }
            }
            catch { }
        }
    }

    # 7. WINS Configuration
    Write-Section "WINS Configuration"
    try {
        $winsConfigs = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop |
            Where-Object { $_.IPEnabled -eq $true }
        $winsFound = $false
        foreach ($cfg in $winsConfigs) {
            $primary = $cfg.WINSPrimaryServer
            $secondary = $cfg.WINSSecondaryServer
            if (-not [string]::IsNullOrWhiteSpace($primary) -or -not [string]::IsNullOrWhiteSpace($secondary)) {
                $winsFound = $true
                $desc = $cfg.Description
                Write-Info "  ${desc}:"
                if ($primary) { Write-Info "    Primary WINS: $primary" }
                if ($secondary) { Write-Info "    Secondary WINS: $secondary" }
            }
        }
        if (-not $winsFound) {
            Write-Info "  No WINS servers configured (normal for modern environments)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check WINS configuration: $($_.Exception.Message)"
    }

    # 8. Proxy / WinHTTP Settings
    Write-Section "WinHTTP Proxy Configuration"
    try {
        $proxyOutput = netsh winhttp show proxy 2>&1
        $proxyStr = ($proxyOutput | Out-String).Trim()
        if ($proxyStr -like "*Direct access*") {
            Write-Success "  No proxy configured (direct access)"
        }
        elseif ($proxyStr -like "*Proxy Server*") {
            Write-DiagWarning "  Proxy is configured:"
            foreach ($line in $proxyOutput) {
                $trimmed = $line.ToString().Trim()
                if ($trimmed) { Write-Info "    $trimmed" }
            }
            Write-Info "  Note: Proxy misconfiguration can block Windows Update, activation, and Azure agent connectivity"
        }
        else {
            Write-Info "  $proxyStr"
        }
    }
    catch {
        Write-DiagWarning "  Could not check proxy settings"
    }

    # IE proxy (current user)
    try {
        $ieProxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        if ($ieProxy.ProxyEnable -eq 1) {
            Write-DiagWarning "  IE/System Proxy ENABLED: $($ieProxy.ProxyServer)"
            if ($ieProxy.ProxyOverride) {
                Write-Info "    Bypass list: $($ieProxy.ProxyOverride)"
            }
        }
    }
    catch { }

    # 9. Network Adapter Driver Version & Date
    Write-Section "Network Adapter Driver Information"
    if ($activeAdapters) {
        foreach ($adpt in $activeAdapters) {
            try {
                $driverInfo = Get-NetAdapter -Name $adpt.Name -ErrorAction Stop
                $driverVersion = $driverInfo.DriverVersion
                $driverDate = $driverInfo.DriverDate
                $driverDesc = $driverInfo.DriverDescription
                $driverProvider = $driverInfo.DriverProvider

                Write-Info "  $($adpt.Name):"
                Write-Info "    Driver: $driverDesc"
                Write-Info "    Version: $driverVersion | Provider: $driverProvider"
                if ($driverDate) {
                    $driverAge = ((Get-Date) - $driverDate).Days
                    Write-Info "    Date: $($driverDate.ToString('yyyy-MM-dd')) ($driverAge days old)"
                    if ($driverAge -gt 730) {
                        Write-DiagWarning "    WARNING: Driver is over 2 years old - consider updating"
                    }
                }
                if ($driverDesc -like "*vmxnet3*" -and $driverVersion -lt "1.8") {
                    Write-DiagWarning "    vmxnet3 driver is outdated - upgrade to latest VMware Tools"
                }
            }
            catch {
                Write-DiagWarning "  Could not retrieve driver info for $($adpt.Name)"
            }
        }
    }

    # 10. Network Binding Order
    Write-Section "Network Binding Order"
    try {
        $bindings = Get-NetAdapterBinding -ErrorAction Stop |
            Where-Object { $_.ComponentID -eq 'ms_tcpip' } |
            Sort-Object Name
        if ($bindings) {
            foreach ($bind in $bindings) {
                $status = if ($bind.Enabled) { "Enabled" } else { "Disabled" }
                Write-Info "  $($bind.Name): TCP/IPv4 = $status"
            }
        }

        $ipv6Bindings = Get-NetAdapterBinding -ErrorAction SilentlyContinue |
            Where-Object { $_.ComponentID -eq 'ms_tcpip6' -and $_.Enabled -eq $false }
        if ($ipv6Bindings) {
            Write-Info "  Note: IPv6 is disabled on: $(($ipv6Bindings.Name) -join ', ')"
        }
    }
    catch {
        Write-DiagWarning "  Could not check binding order: $($_.Exception.Message)"
    }

    # 11. Firewall Rules Blocking Common Ports
    Write-Section "Firewall Rules on Common Ports"
    try {
        foreach ($portDef in $script:CommonPorts) {
            $blockRules = Get-NetFirewallPortFilter -Protocol TCP -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalPort -eq $portDef.Port } |
                ForEach-Object {
                    $rule = $_ | Get-NetFirewallRule -ErrorAction SilentlyContinue
                    if ($rule -and $rule.Action -eq 'Block' -and $rule.Enabled -eq 'True') { $rule }
                }
            if ($blockRules) {
                Write-DiagWarning "  $($portDef.Name) (port $($portDef.Port)): BLOCKED by firewall rule(s):"
                foreach ($r in $blockRules) {
                    Write-DiagWarning "    Rule: '$($r.DisplayName)' Direction=$($r.Direction)"
                }
            }
        }
        Write-Success "  Firewall rule check completed"
    }
    catch {
        Write-DiagWarning "  Could not check firewall rules: $($_.Exception.Message)"
    }

    # 12. RDMA / SMB Direct Status
    Write-Section "RDMA / SMB Direct Status"
    try {
        $smbConfig = Get-SmbClientConfiguration -ErrorAction Stop
        $smbMultichannel = $smbConfig.EnableMultiChannel
        Write-Info "  SMB Multichannel: $(if ($smbMultichannel) { 'Enabled' } else { 'Disabled' })"
    }
    catch {
        Write-Info "  Could not check SMB client configuration"
    }
    try {
        $rdmaAdapters = Get-NetAdapterRdma -ErrorAction SilentlyContinue
        if ($rdmaAdapters) {
            foreach ($rdma in $rdmaAdapters) {
                $status = if ($rdma.Enabled) { "Enabled" } else { "Disabled" }
                Write-Info "  $($rdma.Name): RDMA = $status"
                if ($rdma.Enabled) {
                    $rdmaMode = $rdma.RdmaAdapterInfo
                    if ($rdmaMode) { Write-Info "    Mode: $rdmaMode" }
                }
            }
        }
        else {
            Write-Info "  No RDMA-capable adapters found"
        }
    }
    catch {
        Write-Info "  RDMA not available (Get-NetAdapterRdma not supported)"
    }
    try {
        $smbDirect = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($null -ne $smbDirect) {
            Write-Info "  SMB Direct (Server): $(if ($smbDirect.EnableSMBDirect) { 'Enabled' } else { 'Disabled' })"
        }
    }
    catch { }

    # 13. TCP/IP Stack Parameters
    Write-Section "TCP/IP Stack Parameters"
    try {
        $tcpGlobal = Get-NetTCPSetting -SettingName "Internet" -ErrorAction Stop
        Write-Info "  Auto-Tuning Level: $((Get-NetTCPSetting -SettingName Internet -ErrorAction SilentlyContinue).AutoTuningLevelLocal)"
        Write-Info "  Initial Congestion Window: $($tcpGlobal.InitialCongestionWindow)"
        Write-Info "  Congestion Provider: $($tcpGlobal.CongestionProvider)"

        $autoTuning = netsh interface tcp show global 2>&1 | Select-String "Receive Window Auto-Tuning Level"
        if ($autoTuning) {
            $autoTuningValue = $autoTuning.ToString().Trim()
            Write-Info "  $autoTuningValue"
            if ($autoTuningValue -like "*disabled*") {
                Write-DiagWarning "  TCP Auto-Tuning is DISABLED - this limits receive window scaling and throughput"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve TCP global settings"
    }

    # KeepAlive
    try {
        $keepAlive = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'KeepAliveTime' -ErrorAction SilentlyContinue
        if ($keepAlive -and $keepAlive.KeepAliveTime) {
            $kaSeconds = $keepAlive.KeepAliveTime / 1000
            Write-Info "  TCP KeepAlive: $kaSeconds seconds"
            if ($kaSeconds -gt 7200) {
                Write-DiagWarning "  KeepAlive > 2 hours - long-lived idle connections may be dropped by firewalls/load balancers"
            }
        }
        else {
            Write-Info "  TCP KeepAlive: Default (2 hours)"
        }
    }
    catch { }

    # Timestamps
    try {
        $timestamps = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'Tcp1323Opts' -ErrorAction SilentlyContinue
        if ($timestamps -and $null -ne $timestamps.Tcp1323Opts) {
            $tsValue = switch ($timestamps.Tcp1323Opts) {
                0 { "Disabled (no window scaling, no timestamps)" }
                1 { "Window Scaling only" }
                2 { "Timestamps only" }
                3 { "Both Window Scaling and Timestamps (recommended)" }
                default { "Unknown ($($timestamps.Tcp1323Opts))" }
            }
            Write-Info "  TCP 1323 Options: $tsValue"
        }
        else {
            Write-Info "  TCP 1323 Options: OS Default"
        }
    }
    catch { }

    # 14. Network Adapter Error Events
    Write-Section "Network Adapter Error Events (last 7 days)"
    try {
        $nicEventIds = @(27, 32, 1073, 4198, 4199)
        $nicEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = $nicEventIds
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 20 -ErrorAction SilentlyContinue

        if ($nicEvents) {
            $grouped = $nicEvents | Group-Object Id
            foreach ($g in $grouped) {
                $desc = switch ($g.Name) {
                    '27'   { "NIC reset/reconnect" }
                    '32'   { "Network miniport driver error" }
                    '1073' { "Network adapter link state change" }
                    '4198' { "TCP/IP duplicate IP address detected" }
                    '4199' { "TCP/IP duplicate IP address resolved" }
                    default { "Network event" }
                }
                Write-DiagWarning "  Event $($g.Name) ($desc): $($g.Count) occurrence(s)"
            }
            $nicEvents | Select-Object -First 5 | ForEach-Object {
                Write-Info "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] EventID $($_.Id): $(Get-EventSnippet -Event $_ -MaxLength 100)"
            }
        }
        else {
            Write-Success "  No network adapter error events found"
        }
    }
    catch {
        Write-Info "  Could not query network adapter events"
    }

    # 15. Routing Table Sanity Check
    Write-Section "Routing Table Analysis"
    try {
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop

        # Check for multiple default gateways
        $defaultRoutes = $routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }
        if (@($defaultRoutes).Count -gt 1) {
            Write-DiagWarning "  MULTIPLE default gateways detected ($(@($defaultRoutes).Count)):"
            foreach ($dr in $defaultRoutes) {
                $ifAlias = (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.ifIndex -eq $dr.InterfaceIndex }).Name
                if ([string]::IsNullOrWhiteSpace($ifAlias)) { $ifAlias = "ifIndex $($dr.InterfaceIndex)" }
                Write-DiagWarning "    $($dr.NextHop) via $ifAlias (metric $($dr.RouteMetric))"
            }
            Write-Info "  Multiple default gateways can cause intermittent connectivity - remove extras or use route metrics"
        }
        elseif (@($defaultRoutes).Count -eq 1) {
            $dr = $defaultRoutes
            $ifAlias = (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.ifIndex -eq $dr.InterfaceIndex }).Name
            Write-Success "  Single default gateway: $($dr.NextHop) via $ifAlias (metric $($dr.RouteMetric))"
        }
        else {
            Write-DiagError "  NO default gateway configured!"
        }

        # Check for persistent routes
        $persistentRoutes = $routes | Where-Object { $_.Protocol -eq 'NetMgmt' -and $_.DestinationPrefix -ne '0.0.0.0/0' }
        if ($persistentRoutes) {
            Write-Info "  Static/Persistent routes ($(@($persistentRoutes).Count)):"
            $persistentRoutes | Select-Object -First 10 | ForEach-Object {
                Write-Info "    $($_.DestinationPrefix) -> $($_.NextHop) (metric $($_.RouteMetric))"
            }
            if (@($persistentRoutes).Count -gt 10) {
                Write-Info "    ... and $(@($persistentRoutes).Count - 10) more"
            }
        }

        # Check for metric conflicts (same metric on different interfaces for same destination)
        $metricConflicts = $routes | Group-Object DestinationPrefix |
            Where-Object { $_.Count -gt 1 } |
            ForEach-Object {
                $metrics = $_.Group.RouteMetric | Select-Object -Unique
                if (@($metrics).Count -eq 1 -and $_.Name -ne '255.255.255.255/32' -and $_.Name -ne '224.0.0.0/4') {
                    $_
                }
            }
        if ($metricConflicts) {
            Write-DiagWarning "  Route metric conflicts detected (same metric, same destination, different interfaces):"
            foreach ($conflict in $metricConflicts | Select-Object -First 5) {
                Write-DiagWarning "    $($conflict.Name): $($conflict.Count) routes with same metric"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not analyze routing table: $($_.Exception.Message)"
    }

    #endregion v3.0 Network Checks
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
        Checks total memory, usage percentage, top consumers, committed bytes,
        NonPaged/Paged pool, page file, compression, handles/threads, standby cache,
        RAM hardware, resource exhaustion events, WS trimming, and leak detection
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
    Write-Section "Top 10 Memory Consuming Processes"
    # Fetch fresh process data and cache for potential reuse by CPU diagnostics
    $script:LastProcessAnalysis = Get-ProcessAnalysis
    $script:LastProcessAnalysisTime = Get-Date
    $processAnalysis = $script:LastProcessAnalysis
    
    if ($processAnalysis) {
        $processAnalysis.ByMemory | Format-Table Name, 
        @{Label = "Memory(MB)"; Expression = { [math]::Round($_.WS / 1MB, 2) } },
        @{Label = "CPU(s)"; Expression = { [math]::Round($_.CPU, 2) } },
        Id -AutoSize
    }
    
    Write-Section "Committed Memory"
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
    Write-Section "Kernel Memory Pools"
    Write-Info "NonPaged Pool:"
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
    Write-Section "File Cache & Paging"
    Write-Info "Modified Page List:"
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
    Write-Section "Known Memory-Intensive Processes"
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

    #region v3.0 Memory Checks

    # 1. Page File Configuration & Usage
    Write-Section "Page File Configuration & Usage"
    try {
        $pageFiles = Get-CimInstance Win32_PageFileUsage -ErrorAction Stop
        if ($pageFiles) {
            foreach ($pf in $pageFiles) {
                $usedMB = $pf.CurrentUsage
                $totalMB = $pf.AllocatedBaseSize
                $peakMB = $pf.PeakUsage
                $usedPercent = if ($totalMB -gt 0) { [math]::Round(($usedMB / $totalMB) * 100, 1) } else { 0 }
                Write-Info "  $($pf.Name):"
                Write-Info "    Size: $totalMB MB | Used: $usedMB MB ($usedPercent%) | Peak: $peakMB MB"
                if ($usedPercent -gt $PAGEFILE_USAGE_CRITICAL_PERCENT) {
                    Write-DiagError "    CRITICAL: Page file is >$($PAGEFILE_USAGE_CRITICAL_PERCENT)% full!"
                }
                elseif ($usedPercent -gt $PAGEFILE_USAGE_WARNING_PERCENT) {
                    Write-DiagWarning "    WARNING: Page file usage above $($PAGEFILE_USAGE_WARNING_PERCENT)%"
                }
            }
        }
        else {
            Write-DiagWarning "  No page files found (system may crash under memory pressure!)"
        }

        # Check page file settings (system managed vs fixed)
        $pfSettings = Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue
        if ($pfSettings) {
            foreach ($pfs in $pfSettings) {
                if ($pfs.InitialSize -eq 0 -and $pfs.MaximumSize -eq 0) {
                    Write-Success "    $($pfs.Name): System managed (recommended)"
                }
                else {
                    Write-Info "    $($pfs.Name): Fixed size (Initial: $($pfs.InitialSize) MB, Max: $($pfs.MaximumSize) MB)"
                    if ($pfs.MaximumSize -lt 4096) {
                        Write-DiagWarning "    Page file max is under 4 GB - may be insufficient for memory dumps"
                    }
                }
            }
        }
        else {
            # Win32_PageFileSetting is empty when page file is system-managed (most common config)
            Write-Success "  Page file is system-managed (Win32_PageFileSetting empty — normal behavior)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check page file configuration: $($_.Exception.Message)"
    }

    # 2. Available MBytes (more accurate than free memory)
    Write-Section "Available Memory (includes reclaimable cache)"
    try {
        $availMB = Get-Counter '\Memory\Available MBytes' -ErrorAction Stop
        $availVal = [math]::Round($availMB.CounterSamples.CookedValue, 0)
        Write-Info "  Available MBytes: $availVal MB ($([math]::Round($availVal / 1024, 2)) GB)"
        if ($availVal -lt $AVAILABLE_MB_CRITICAL) {
            Write-DiagError "  CRITICAL: Available memory below $($AVAILABLE_MB_CRITICAL) MB!"
        }
        elseif ($availVal -lt $AVAILABLE_MB_WARNING) {
            Write-DiagWarning "  WARNING: Available memory below $($AVAILABLE_MB_WARNING) MB"
        }
        else {
            Write-Success "  Available memory is adequate"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Available MBytes"
    }

    # 3. Memory Compression Ratio
    Write-Section "Memory Compression"
    try {
        $compressProc = Get-Process -Name "Memory Compression" -ErrorAction SilentlyContinue
        if ($compressProc) {
            $compressWS = [math]::Round($compressProc.WorkingSet64 / 1MB, 0)
            Write-Info "  Memory Compression process WS: $compressWS MB"
            try {
                $compressedBytes = Get-Counter '\Memory\Compression Store Size' -ErrorAction Stop
                $compressedMB = [math]::Round($compressedBytes.CounterSamples.CookedValue / 1MB, 0)
                if ($compressWS -gt 0 -and $compressedMB -gt 0) {
                    $ratio = [math]::Round($compressedMB / $compressWS, 2)
                    Write-Info "  Compressed Store: $compressedMB MB | Compression Ratio: ${ratio}:1"
                    if ($compressWS -gt 2048) {
                        Write-DiagWarning "  WARNING: Over 2 GB of compressed memory - system is under significant memory pressure"
                    }
                }
            }
            catch {
                Write-Info "  Compression Store counter not available (Windows 10/2016+)"
            }
        }
        else {
            Write-Info "  Memory Compression process not active"
        }
    }
    catch {
        Write-DiagWarning "  Could not check memory compression"
    }

    # 4. Handle & Thread Count per Process
    Write-Section "Handle & Thread Analysis"
    Write-Info "Top Processes by Handle Count:"
    try {
        $handleProcs = Get-Process -ErrorAction Stop |
            Sort-Object HandleCount -Descending |
            Select-Object -First 10
        foreach ($hp in $handleProcs) {
            $handles = $hp.HandleCount
            $threads = $hp.Threads.Count
            $indicator = ""
            if ($handles -gt $HANDLE_LEAK_WARNING) { $indicator = " [POTENTIAL HANDLE LEAK]" }
            Write-Info "  $($hp.Name) (PID $($hp.Id)): Handles=$handles Threads=$threads$indicator"
        }

        $totalHandles = (Get-Process -ErrorAction Stop | Measure-Object HandleCount -Sum).Sum
        Write-Info "  System Total Handles: $totalHandles"
    }
    catch {
        Write-DiagWarning "  Could not check handle counts"
    }

    Write-Info "`nTop Processes by Thread Count:"
    try {
        $threadProcs = Get-Process -ErrorAction Stop |
            Sort-Object { $_.Threads.Count } -Descending |
            Select-Object -First 5
        foreach ($tp in $threadProcs) {
            $threads = $tp.Threads.Count
            $indicator = ""
            if ($threads -gt $THREAD_LEAK_WARNING) { $indicator = " [HIGH THREAD COUNT]" }
            Write-Info "  $($tp.Name) (PID $($tp.Id)): Threads=$threads$indicator"
        }
    }
    catch {
        Write-DiagWarning "  Could not check thread counts"
    }

    # 5. Paged Pool Usage
    Write-Section "Paged Pool Usage"
    try {
        $pagedPool = Get-Counter '\Memory\Pool Paged Bytes' -ErrorAction Stop
        $ppMB = [math]::Round($pagedPool.CounterSamples.CookedValue / 1MB, 2)
        Write-Info "  Paged Pool: $ppMB MB"
        if ($ppMB -gt $PAGED_POOL_CRITICAL_MB) {
            Write-DiagError "  CRITICAL: Paged Pool >$($PAGED_POOL_CRITICAL_MB)MB - risk of SESSION_POOL_EMPTY bugcheck"
        }
        elseif ($ppMB -gt $PAGED_POOL_WARNING_MB) {
            Write-DiagWarning "  WARNING: Paged Pool elevated (>$($PAGED_POOL_WARNING_MB)MB)"
        }
        else {
            Write-Success "  Paged Pool is within normal range"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Paged Pool"
    }

    # 6. System Cache Working Set
    Write-Section "System Cache Working Set"
    try {
        $cacheBytes = Get-Counter '\Memory\Cache Bytes' -ErrorAction Stop
        $cacheMB = [math]::Round($cacheBytes.CounterSamples.CookedValue / 1MB, 0)
        $cacheGB = [math]::Round($cacheBytes.CounterSamples.CookedValue / 1GB, 2)
        Write-Info "  System Cache: $cacheMB MB ($cacheGB GB)"
        if ($cacheGB -gt 4) {
            Write-DiagWarning "  WARNING: Large system cache ($cacheGB GB) - may be starving user processes"
            Write-Info "  On file servers, consider tuning LargeSystemCache registry key"
        }
    }
    catch {
        Write-DiagWarning "  Could not check system cache"
    }

    # 7. Memory Leak Trend Detection (Private Bytes vs Working Set)
    Write-Section "Memory Leak Indicators (Private Bytes vs Working Set)"
    try {
        $topProcesses = Get-Process -ErrorAction Stop |
            Where-Object { $_.WorkingSet64 -gt 100MB } |
            Sort-Object WorkingSet64 -Descending |
            Select-Object -First 10
        foreach ($proc in $topProcesses) {
            $wsMB = [math]::Round($proc.WorkingSet64 / 1MB, 0)
            $privateMB = [math]::Round($proc.PrivateMemorySize64 / 1MB, 0)
            $virtualMB = [math]::Round($proc.VirtualMemorySize64 / 1MB, 0)
            $gap = $privateMB - $wsMB
            $indicator = ""
            if ($gap -gt 500) {
                $indicator = " [LEAK SUSPECT: private >> WS by ${gap}MB]"
            }
            Write-Info "  $($proc.Name) (PID $($proc.Id)): WS=${wsMB}MB Private=${privateMB}MB Virtual=${virtualMB}MB$indicator"
        }
    }
    catch {
        Write-DiagWarning "  Could not perform leak trend analysis"
    }

    # 8. Standby List Breakdown
    Write-Section "Standby Cache Breakdown"
    try {
        $standbyCore = Get-Counter '\Memory\Standby Cache Core Bytes' -ErrorAction Stop
        $standbyNormal = Get-Counter '\Memory\Standby Cache Normal Priority Bytes' -ErrorAction Stop
        $standbyReserve = Get-Counter '\Memory\Standby Cache Reserve Bytes' -ErrorAction Stop

        $coreMB = [math]::Round($standbyCore.CounterSamples.CookedValue / 1MB, 0)
        $normalMB = [math]::Round($standbyNormal.CounterSamples.CookedValue / 1MB, 0)
        $reserveMB = [math]::Round($standbyReserve.CounterSamples.CookedValue / 1MB, 0)
        $totalStandby = $coreMB + $normalMB + $reserveMB

        Write-Info "  Total Standby: $totalStandby MB ($([math]::Round($totalStandby / 1024, 2)) GB)"
        Write-Info "    Core (high priority): $coreMB MB"
        Write-Info "    Normal priority: $normalMB MB"
        Write-Info "    Reserve (low priority, easily reclaimable): $reserveMB MB"

        if ($totalStandby -gt 0) {
            $reclaimablePercent = [math]::Round(($reserveMB / $totalStandby) * 100, 1)
            Write-Info "  Easily reclaimable: $reclaimablePercent% of standby cache"
            if ($reclaimablePercent -lt 20 -and $totalStandby -gt 2048) {
                Write-DiagWarning "  Low reclaimable standby cache - high-priority file cache is consuming standby memory"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve standby cache breakdown (requires Windows 8/2012+)"
    }

    # 9. RAM Hardware Information
    Write-Section "RAM Hardware Information"
    try {
        $memModules = Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop
        if ($memModules) {
            $totalSlots = (Get-CimInstance Win32_PhysicalMemoryArray -ErrorAction SilentlyContinue).MemoryDevices
            $usedSlots = @($memModules).Count
            Write-Info "  DIMM Slots: $usedSlots used$(if ($totalSlots) { " of $totalSlots total" })"

            $speeds = @()
            $types = @()
            foreach ($mod in $memModules) {
                $sizeMB = [math]::Round($mod.Capacity / 1MB, 0)
                $sizeGB = [math]::Round($mod.Capacity / 1GB, 1)
                $speed = $mod.Speed
                $manufacturer = if ($mod.Manufacturer) { $mod.Manufacturer.Trim() } else { "Unknown" }
                $partNumber = if ($mod.PartNumber) { $mod.PartNumber.Trim() } else { "" }
                $memType = switch ($mod.SMBIOSMemoryType) {
                    20 { "DDR" }
                    21 { "DDR2" }
                    24 { "DDR3" }
                    26 { "DDR4" }
                    34 { "DDR5" }
                    default { "Type $($mod.SMBIOSMemoryType)" }
                }
                $speeds += $speed
                $types += $memType

                Write-Info "  Slot $($mod.DeviceLocator): ${sizeGB}GB $memType @ ${speed}MHz ($manufacturer $partNumber)"
            }

            # Check for mismatched speeds
            $uniqueSpeeds = $speeds | Where-Object { $_ -gt 0 } | Select-Object -Unique
            if (@($uniqueSpeeds).Count -gt 1) {
                Write-DiagError "  MISMATCHED RAM speeds detected: $($uniqueSpeeds -join ', ') MHz"
                Write-Info "  All DIMMs will run at the slowest speed ($($uniqueSpeeds | Sort-Object | Select-Object -First 1) MHz)"
            }

            # Check for mixed types
            $uniqueTypes = $types | Select-Object -Unique
            if (@($uniqueTypes).Count -gt 1) {
                Write-DiagError "  MIXED RAM types detected: $($uniqueTypes -join ', ')"
            }

            # Upgrade suggestion
            if ($totalSlots -and $usedSlots -lt $totalSlots) {
                $emptySlots = $totalSlots - $usedSlots
                Write-Info "  $emptySlots empty DIMM slot(s) available for expansion"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve RAM hardware info: $($_.Exception.Message)"
    }

    # 10. Resource Exhaustion Events (2004)
    Write-Section "Resource Exhaustion Events (last 7 days)"
    try {
        $resExhaustEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 2004
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($resExhaustEvents) {
            Write-DiagError "  FOUND $($resExhaustEvents.Count) resource exhaustion event(s)!"
            foreach ($evt in $resExhaustEvents | Select-Object -First 5) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $evt -MaxLength 120)"
            }
            Write-Info "  Event 2004 = virtual memory exhaustion - increase page file or add RAM"
        }
        else {
            Write-Success "  No resource exhaustion events (Event 2004)"
        }

        # Also check for Event 333 (an LDR for memory low condition in older OS)
        $lowMemEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 333, 2003
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($lowMemEvents) {
            Write-DiagWarning "  Also found $($lowMemEvents.Count) low-memory condition event(s) (333/2003)"
        }
    }
    catch {
        Write-Info "  Could not query resource exhaustion events"
    }

    # 11. Working Set Trimming Rate
    Write-Section "Working Set Trimming Activity"
    try {
        $trimCounter = Get-Counter '\Memory\Transition Pages RePurposed/sec' -ErrorAction Stop
        $trimRate = [math]::Round($trimCounter.CounterSamples.CookedValue, 0)
        Write-Info "  Transition Pages Repurposed/sec: $trimRate"
        if ($trimRate -gt $WS_TRIM_WARNING_THRESHOLD) {
            Write-DiagWarning "  WARNING: High WS trimming rate (>$WS_TRIM_WARNING_THRESHOLD/sec) - OS is aggressively reclaiming memory"
        }

        $cacheFaults = Get-Counter '\Memory\Cache Faults/sec' -ErrorAction Stop
        $cacheFaultRate = [math]::Round($cacheFaults.CounterSamples.CookedValue, 0)
        Write-Info "  Cache Faults/sec: $cacheFaultRate"
        if ($cacheFaultRate -gt 5000) {
            Write-DiagWarning "  WARNING: High cache fault rate - system cache is being evicted frequently"
        }
    }
    catch {
        Write-DiagWarning "  Could not check working set trimming"
    }

    # 12. Per-Process Private Bytes vs Working Set (top suspects)
    Write-Section "Detailed Leak Analysis (Private >> Working Set)"
    try {
        $leakCandidates = Get-Process -ErrorAction Stop |
            Where-Object { $_.PrivateMemorySize64 -gt 200MB } |
            ForEach-Object {
                $wsMB = [math]::Round($_.WorkingSet64 / 1MB, 0)
                $privateMB = [math]::Round($_.PrivateMemorySize64 / 1MB, 0)
                $gdiObjects = 0
                $userObjects = 0
                try {
                    $gdiObjects = $_.GDI_Objects
                    $userObjects = $_.USER_Objects
                }
                catch { }
                [PSCustomObject]@{
                    Name      = $_.Name
                    PID       = $_.Id
                    WS_MB     = $wsMB
                    Private_MB = $privateMB
                    Gap_MB    = $privateMB - $wsMB
                    Handles   = $_.HandleCount
                }
            } |
            Where-Object { $_.Gap_MB -gt 200 } |
            Sort-Object Gap_MB -Descending |
            Select-Object -First 5

        if ($leakCandidates) {
            Write-DiagWarning "  Processes where Private Bytes significantly exceeds Working Set:"
            foreach ($lc in $leakCandidates) {
                Write-DiagWarning "    $($lc.Name) (PID $($lc.PID)): WS=$($lc.WS_MB)MB Private=$($lc.Private_MB)MB Gap=$($lc.Gap_MB)MB Handles=$($lc.Handles)"
            }
            Write-Info "  A large Private-WS gap suggests the process has allocated memory that was paged out (possible leak)"
        }
        else {
            Write-Success "  No significant Private Bytes vs Working Set gaps detected"
        }
    }
    catch {
        Write-DiagWarning "  Could not perform detailed leak analysis"
    }

    #endregion v3.0 Memory Checks
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
                    if ($script:ClusterEnv.IsClusterNode -and (Test-PathOnCSV -Path $logPath -CSVPaths $script:ClusterEnv.CSVPaths)) {
                        Write-DiagWarning "WARNING: Path '$logPath' is on a Cluster Shared Volume!"
                        Write-DiagWarning "Writing large traces to CSV can cause I/O storms affecting all cluster nodes."
                        $csvConfirm = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                        if ($csvConfirm -ne "Y") { return }
                    }
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
                    if ($script:ClusterEnv.IsClusterNode -and (Test-PathOnCSV -Path $logPath -CSVPaths $script:ClusterEnv.CSVPaths)) {
                        Write-DiagWarning "WARNING: Path '$logPath' is on a Cluster Shared Volume!"
                        Write-DiagWarning "Writing large traces to CSV can cause I/O storms affecting all cluster nodes."
                        $csvConfirm = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                        if ($csvConfirm -ne "Y") { return }
                    }
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
        Checks current CPU usage, per-core hotspots, privileged vs user time,
        queue length, context switches, interrupts/DPCs, power throttling,
        process analysis, AV detection, Hyper-V overhead, NUMA, and CPU events
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
        Write-Section "Processor Information"
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
    Write-Section "Top 10 CPU Consuming Processes"
    # Reuse cached process data only if fresh (< 2 minutes old), otherwise fetch new
    $cacheAge = if ($script:LastProcessAnalysisTime) { ((Get-Date) - $script:LastProcessAnalysisTime).TotalMinutes } else { 999 }
    $processAnalysis = if ($script:LastProcessAnalysis -and $cacheAge -lt 2) { $script:LastProcessAnalysis } else { Get-ProcessAnalysis }
    
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
    Write-Section "Top svchost.exe Instances by CPU"
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
    Write-Section "Monitoring Agent CPU Check"
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
    catch {
        Write-Verbose "Could not check monitoring agents: $($_.Exception.Message)"
    }

    # Java.exe High CPU
    try {
        $javaProcs = Get-Process -Name "java" -ErrorAction SilentlyContinue
        if ($javaProcs) {
            Write-Section "Java Process CPU Check"
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
    catch {
        Write-Verbose "Could not check Java processes: $($_.Exception.Message)"
    }

    # Split I/O Check (storage fragmentation indicator)
    Write-Section "Split I/O Check"
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

    # SQL AG Replication Counters (v3.0 cluster-safe)
    if ($script:ClusterEnv.IsAGInstalled) {
        Write-Section "SQL AG Replication Health"
        try {
            $sendQueue = Get-Counter '\SQLServer:Database Replica(*)\Log Send Queue' -ErrorAction Stop
            foreach ($sample in $sendQueue.CounterSamples) {
                if ($sample.InstanceName -ne "_total" -and $sample.CookedValue -gt 0) {
                    $queueKB = [math]::Round($sample.CookedValue, 0)
                    Write-Info "  $($sample.InstanceName): Log Send Queue = $queueKB KB"
                    if ($queueKB -gt 10240) {
                        Write-DiagWarning "    WARNING: Log send queue >10MB - AG replication lag"
                    }
                }
            }
        }
        catch {
            Write-Info "  SQL AG counters not available (AG may not be configured or SQL not running)"
        }
        try {
            $redoQueue = Get-Counter '\SQLServer:Database Replica(*)\Redo Queue Size' -ErrorAction Stop
            foreach ($sample in $redoQueue.CounterSamples) {
                if ($sample.InstanceName -ne "_total" -and $sample.CookedValue -gt 0) {
                    $redoKB = [math]::Round($sample.CookedValue, 0)
                    Write-Info "  $($sample.InstanceName): Redo Queue = $redoKB KB"
                    if ($redoKB -gt 10240) {
                        Write-DiagWarning "    WARNING: Redo queue >10MB - secondary applying changes slowly"
                    }
                }
            }
        }
        catch { }
    }

    #region v3.0 CPU Checks

    # 1. Per-Core CPU Usage
    Write-Section "Per-Core CPU Usage"
    try {
        $perCore = Get-Counter '\Processor(*)\% Processor Time' -ErrorAction Stop
        $hotCores = @()
        foreach ($sample in $perCore.CounterSamples) {
            if ($sample.InstanceName -ne "_total") {
                $corePercent = [math]::Round($sample.CookedValue, 1)
                if ($corePercent -gt 95) {
                    $hotCores += "Core $($sample.InstanceName): $corePercent%"
                }
            }
        }
        $coreCount = ($perCore.CounterSamples | Where-Object { $_.InstanceName -ne "_total" }).Count
        if ($hotCores.Count -gt 0) {
            Write-DiagWarning "  HOT CORE(s) detected ($($hotCores.Count) of $coreCount at >95%):"
            foreach ($hc in $hotCores) {
                Write-DiagWarning "    $hc"
            }
            Write-Info "  Single-threaded bottleneck likely (SQL query, .NET app, or service pinned to one core)"
        }
        else {
            Write-Success "  No hot cores detected ($coreCount cores, all below 95%)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check per-core CPU usage"
    }

    # 2. Privileged vs User Time
    Write-Section "Privileged vs User Time"
    try {
        $privTime = Get-Counter '\Processor(_Total)\% Privileged Time' -ErrorAction Stop
        $userTime = Get-Counter '\Processor(_Total)\% User Time' -ErrorAction Stop
        $privPercent = [math]::Round($privTime.CounterSamples.CookedValue, 1)
        $userPercent = [math]::Round($userTime.CounterSamples.CookedValue, 1)
        Write-Info "  Kernel (Privileged): $privPercent%"
        Write-Info "  Application (User):  $userPercent%"
        if ($privPercent -gt 30) {
            Write-DiagWarning "  HIGH kernel time (>30%) — investigate storage drivers, NIC drivers, or antivirus filter drivers"
        }
        elseif ($privPercent -gt $userPercent -and $privPercent -gt 15) {
            Write-DiagWarning "  Kernel time exceeds User time — driver or OS subsystem issue likely"
        }
        else {
            Write-Success "  Normal kernel/user time ratio"
        }
    }
    catch {
        Write-DiagWarning "  Could not check privileged/user time split"
    }

    # 3. Processor Queue Length
    Write-Section "Processor Queue Length"
    try {
        $queueLen = Get-Counter '\System\Processor Queue Length' -ErrorAction Stop
        $queue = [math]::Round($queueLen.CounterSamples.CookedValue, 0)
        $logicalProcs = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        $threshold = if ($logicalProcs) { $logicalProcs * 2 } else { 4 }
        Write-Info "  Queue Length: $queue (threshold: $threshold for $logicalProcs logical processors)"
        if ($queue -gt $threshold) {
            Write-DiagError "  CRITICAL: Processor queue length $queue > ${threshold} — threads are waiting for CPU!"
            Write-Info "  This server needs more CPU capacity or workload reduction"
        }
        elseif ($queue -gt ($logicalProcs)) {
            Write-DiagWarning "  WARNING: Queue length elevated ($queue) — approaching CPU saturation"
        }
        else {
            Write-Success "  Processor queue length is healthy"
        }
    }
    catch {
        Write-DiagWarning "  Could not check processor queue length"
    }

    # 4. Context Switches/sec
    Write-Section "Context Switches"
    try {
        $ctxSwitches = Get-Counter '\System\Context Switches/sec' -ErrorAction Stop
        $ctxRate = [math]::Round($ctxSwitches.CounterSamples.CookedValue, 0)
        $perCoreRate = if ($logicalProcs -and $logicalProcs -gt 0) { [math]::Round($ctxRate / $logicalProcs, 0) } else { $ctxRate }
        Write-Info "  Context Switches/sec: $ctxRate (${perCoreRate}/core)"
        if ($perCoreRate -gt 15000) {
            Write-DiagWarning "  HIGH context switching (>15K/core) — thread contention, excessive threads, or hypervisor scheduling"
        }
        elseif ($perCoreRate -gt 8000) {
            Write-DiagWarning "  Elevated context switching (>8K/core) — monitor for lock contention"
        }
        else {
            Write-Success "  Context switch rate is normal"
        }
    }
    catch {
        Write-DiagWarning "  Could not check context switches"
    }

    # 5. Interrupt & DPC Time
    Write-Section "Interrupt & DPC Time"
    try {
        $intTime = Get-Counter '\Processor(_Total)\% Interrupt Time' -ErrorAction Stop
        $dpcTime = Get-Counter '\Processor(_Total)\% DPC Time' -ErrorAction Stop
        $intPercent = [math]::Round($intTime.CounterSamples.CookedValue, 2)
        $dpcPercent = [math]::Round($dpcTime.CounterSamples.CookedValue, 2)
        Write-Info "  Interrupt Time: $intPercent%"
        Write-Info "  DPC Time: $dpcPercent%"
        if ($intPercent -gt 15 -or $dpcPercent -gt 15) {
            Write-DiagError "  CRITICAL: High interrupt/DPC time — NIC driver, storage driver, or hardware issue"
            Write-Info "  On Hyper-V hosts, check vmswitch and storage subsystem"
        }
        elseif ($intPercent -gt 5 -or $dpcPercent -gt 5) {
            Write-DiagWarning "  Elevated interrupt/DPC time — investigate NIC RSS settings and storage drivers"
        }
        else {
            Write-Success "  Interrupt and DPC time are normal"
        }
    }
    catch {
        Write-DiagWarning "  Could not check interrupt/DPC time"
    }

    # 6. System Uptime & Last Boot
    Write-Section "System Uptime"
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $uptime = (Get-Date) - $os.LastBootUpTime
        Write-Info "  Last Boot: $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        Write-Info "  Uptime: $($uptime.Days) days, $($uptime.Hours) hours"
        if ($uptime.TotalDays -gt 180) {
            Write-DiagError "  Server running for $([math]::Round($uptime.TotalDays, 0)) days — kernel timer drift and memory fragmentation risk"
        }
        elseif ($uptime.TotalDays -gt 90) {
            Write-DiagWarning "  Server running for $([math]::Round($uptime.TotalDays, 0)) days — consider scheduling maintenance reboot"
        }
    }
    catch {
        Write-DiagWarning "  Could not check system uptime"
    }

    # 7. Power Throttling Detection
    Write-Section "CPU Power Throttling"
    try {
        $perfPercent = Get-Counter '\Processor Information(_Total)\% Processor Performance' -ErrorAction Stop
        $perfVal = [math]::Round($perfPercent.CounterSamples.CookedValue, 1)
        Write-Info "  Processor Performance: $perfVal%"
        if ($perfVal -lt 80) {
            Write-DiagError "  CPU THROTTLED to $perfVal% — check power plan, thermal throttling, or VM host overcommit"
            Write-Info "  Set power plan to High Performance: powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        }
        elseif ($perfVal -lt 95) {
            Write-DiagWarning "  CPU performance at $perfVal% (not running at full speed)"
        }
        else {
            Write-Success "  CPU running at full performance ($perfVal%)"
        }

        # Check processor frequency
        $freqCounter = Get-Counter '\Processor Information(_Total)\Processor Frequency' -ErrorAction SilentlyContinue
        if ($freqCounter) {
            $freqMHz = [math]::Round($freqCounter.CounterSamples.CookedValue, 0)
            Write-Info "  Current Frequency: $freqMHz MHz"
        }
    }
    catch {
        Write-Info "  Processor Performance counter not available (may require newer OS)"
    }

    # 8. Antivirus / Filter Driver CPU Detection
    Write-Section "Antivirus & Security Agent CPU"
    try {
        $avProcesses = @(
            @{ Name = "MsMpEng"; Label = "Windows Defender" },
            @{ Name = "CSFalconService"; Label = "CrowdStrike Falcon" },
            @{ Name = "CSFalconContainer"; Label = "CrowdStrike Container" },
            @{ Name = "SentinelAgent"; Label = "SentinelOne" },
            @{ Name = "SentinelServiceHost"; Label = "SentinelOne Host" },
            @{ Name = "ccSvcHst"; Label = "Symantec/Broadcom" },
            @{ Name = "savservice"; Label = "Sophos" },
            @{ Name = "WRSA"; Label = "Webroot" },
            @{ Name = "cb"; Label = "Carbon Black" },
            @{ Name = "CylanceSvc"; Label = "Cylance" },
            @{ Name = "TaniumClient"; Label = "Tanium" },
            @{ Name = "ds_agent"; Label = "Trend Micro Deep Security" }
        )
        $avFound = $false
        foreach ($av in $avProcesses) {
            $procs = Get-Process -Name $av.Name -ErrorAction SilentlyContinue
            if ($procs) {
                $avFound = $true
                foreach ($p in $procs) {
                    $cpuSec = [math]::Round($p.CPU, 1)
                    $memMB = [math]::Round($p.WorkingSet64 / 1MB, 0)
                    $indicator = ""
                    if ($cpuSec -gt 300) { $indicator = " [HIGH CPU - investigate exclusions]" }
                    Write-Info "  $($av.Label) ($($p.Name), PID $($p.Id)): CPU=${cpuSec}s Mem=${memMB}MB$indicator"
                }
            }
        }
        if (-not $avFound) {
            Write-Info "  No known AV/security agent processes detected"
        }

        # Check filter drivers that could impact CPU
        try {
            $fltmc = fltmc 2>&1
            $filterCount = ($fltmc | Select-String '^\d+' | Measure-Object).Count
            if ($filterCount -gt 0) {
                Write-Info "  File system filter drivers: $filterCount active"
                $highAltitude = $fltmc | Select-String '(WdFilter|csagent|SentinelMonitor|SymEFA|savonaccess|CbFilter)' -ErrorAction SilentlyContinue
                if ($highAltitude) {
                    Write-Info "  AV filter drivers detected in filter stack:"
                    foreach ($f in $highAltitude) {
                        Write-Info "    $($f.Line.Trim())"
                    }
                }
            }
        }
        catch { }
    }
    catch {
        Write-DiagWarning "  Could not check antivirus processes"
    }

    # 9. Hyper-V Hypervisor Overhead
    Write-Section "Hyper-V Hypervisor Overhead"
    try {
        $hvSvc = Get-Service -Name "vmms" -ErrorAction SilentlyContinue
        if ($null -ne $hvSvc -and $hvSvc.Status -eq "Running") {
            try {
                $hvRunTime = Get-Counter '\Hyper-V Hypervisor Logical Processor(_Total)\% Total Run Time' -ErrorAction Stop
                $hvPercent = [math]::Round($hvRunTime.CounterSamples.CookedValue, 1)
                Write-Info "  Hypervisor Total Run Time: $hvPercent%"

                $hvOverhead = Get-Counter '\Hyper-V Hypervisor Logical Processor(_Total)\% Hypervisor Run Time' -ErrorAction SilentlyContinue
                if ($hvOverhead) {
                    $ohPercent = [math]::Round($hvOverhead.CounterSamples.CookedValue, 2)
                    Write-Info "  Hypervisor Overhead: $ohPercent%"
                    if ($ohPercent -gt 5) {
                        Write-DiagWarning "  HIGH hypervisor overhead (>5%) — too many VMs or NUMA misconfiguration"
                    }
                }

                $hvGuest = Get-Counter '\Hyper-V Hypervisor Logical Processor(_Total)\% Guest Run Time' -ErrorAction SilentlyContinue
                if ($hvGuest) {
                    Write-Info "  Guest VM Run Time: $([math]::Round($hvGuest.CounterSamples.CookedValue, 1))%"
                }
            }
            catch {
                Write-Info "  Hyper-V counters not available (may not be a host)"
            }
        }
        else {
            Write-Info "  Hyper-V not running on this server"
        }
    }
    catch {
        Write-Info "  Could not check Hyper-V status"
    }

    # 10. Process CPU Time Trend (two-sample snapshot)
    Write-Section "Real-Time Process CPU (5-second sample)"
    try {
        Write-Info "  Sampling CPU usage over 5 seconds..."
        $snapshot1 = Get-Process -ErrorAction Stop | Where-Object { $_.Id -ne 0 } |
            Select-Object Id, Name, @{N='CPU1';E={$_.TotalProcessorTime.TotalMilliseconds}}
        Start-Sleep -Seconds 5
        $snapshot2 = Get-Process -ErrorAction Stop | Where-Object { $_.Id -ne 0 } |
            Select-Object Id, Name, @{N='CPU2';E={$_.TotalProcessorTime.TotalMilliseconds}}

        $delta = foreach ($p2 in $snapshot2) {
            $p1 = $snapshot1 | Where-Object { $_.Id -eq $p2.Id }
            if ($p1) {
                $cpuDelta = $p2.CPU2 - $p1.CPU1
                if ($cpuDelta -gt 0) {
                    # Approximate % of one core over 5 seconds (5000ms)
                    $cpuPctApprox = [math]::Round(($cpuDelta / 5000) * 100, 1)
                    [PSCustomObject]@{
                        Name   = $p2.Name
                        PID    = $p2.Id
                        DeltaMs = [math]::Round($cpuDelta, 0)
                        ApproxPct = $cpuPctApprox
                    }
                }
            }
        }
        $topDelta = $delta | Sort-Object DeltaMs -Descending | Select-Object -First 10
        if ($topDelta) {
            Write-Info "  Top 10 processes by CURRENT CPU usage (last 5s):"
            foreach ($td in $topDelta) {
                Write-Info "    $($td.Name) (PID $($td.PID)): ${($td.DeltaMs)}ms (~$($td.ApproxPct)% of 1 core)"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not perform real-time CPU sampling"
    }

    # 11. System Threads & Process Count
    Write-Section "System Thread & Process Count"
    try {
        $sysThreads = Get-Counter '\System\Threads' -ErrorAction Stop
        $sysProcesses = Get-Counter '\System\Processes' -ErrorAction Stop
        $threadCount = [math]::Round($sysThreads.CounterSamples.CookedValue, 0)
        $processCount = [math]::Round($sysProcesses.CounterSamples.CookedValue, 0)
        Write-Info "  Total Threads: $threadCount"
        Write-Info "  Total Processes: $processCount"
        if ($threadCount -gt 5000) {
            Write-DiagWarning "  HIGH thread count ($threadCount) — approaching kernel resource limits"
        }
        if ($processCount -gt 500) {
            Write-DiagWarning "  HIGH process count ($processCount) — investigate runaway services or scheduled tasks"
        }
    }
    catch {
        Write-DiagWarning "  Could not check system thread/process counts"
    }

    # 12. DPC Queue Rate
    Write-Section "DPC Queue Rate"
    try {
        $dpcQueued = Get-Counter '\Processor(_Total)\DPCs Queued/sec' -ErrorAction Stop
        $dpcRate = [math]::Round($dpcQueued.CounterSamples.CookedValue, 0)
        Write-Info "  DPCs Queued/sec: $dpcRate"
        $perCoreDPC = if ($logicalProcs -and $logicalProcs -gt 0) { [math]::Round($dpcRate / $logicalProcs, 0) } else { $dpcRate }
        Write-Info "  Per-core DPC rate: $perCoreDPC/sec"
        if ($perCoreDPC -gt 5000) {
            Write-DiagWarning "  HIGH DPC rate (>5K/core) — NIC or storage driver processing bottleneck"
        }
    }
    catch {
        Write-DiagWarning "  Could not check DPC queue rate"
    }

    # 13. NUMA Node Imbalance
    Write-Section "NUMA Node Analysis"
    try {
        $numaNodes = Get-Counter '\NUMA Node Memory(*)\Total MBytes' -ErrorAction Stop
        $nodeData = @()
        foreach ($sample in $numaNodes.CounterSamples) {
            if ($sample.InstanceName -ne "_total") {
                $nodeData += [PSCustomObject]@{
                    Node = $sample.InstanceName
                    TotalMB = [math]::Round($sample.CookedValue, 0)
                }
            }
        }
        if ($nodeData.Count -gt 1) {
            Write-Info "  NUMA Nodes detected: $($nodeData.Count)"
            foreach ($nd in $nodeData) {
                Write-Info "    Node $($nd.Node): $($nd.TotalMB) MB"
            }
            $maxMB = ($nodeData | Measure-Object TotalMB -Maximum).Maximum
            $minMB = ($nodeData | Measure-Object TotalMB -Minimum).Minimum
            if ($maxMB -gt 0) {
                $imbalance = [math]::Round((($maxMB - $minMB) / $maxMB) * 100, 1)
                if ($imbalance -gt 20) {
                    Write-DiagWarning "  NUMA imbalance: $imbalance% memory difference between nodes"
                    Write-Info "  Processes may be hitting remote NUMA memory, causing hidden CPU penalties"
                }
                else {
                    Write-Success "  NUMA memory balanced (${imbalance}% difference)"
                }
            }
        }
        elseif ($nodeData.Count -eq 1) {
            Write-Info "  Single NUMA node ($($nodeData[0].TotalMB) MB) — no imbalance possible"
        }
    }
    catch {
        Write-Info "  NUMA counters not available (single-socket system or counters disabled)"
    }

    # 14. CPU-Related Event Log Entries
    Write-Section "CPU-Related Events (last 7 days)"
    try {
        # WHEA hardware errors (CPU/memory correctable and uncorrectable)
        $wheaEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 19, 47, 17
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($wheaEvents) {
            Write-DiagError "  WHEA hardware errors detected ($($wheaEvents.Count) events):"
            $wheaEvents | Group-Object Id | ForEach-Object {
                $desc = switch ($_.Name) {
                    '17' { "WHEA: Machine check exception" }
                    '19' { "WHEA: Corrected hardware error" }
                    '47' { "WHEA: Fatal hardware error" }
                    default { "WHEA event" }
                }
                Write-DiagError "    Event $($_.Name) ($desc): $($_.Count) occurrence(s)"
            }
            Write-Info "  WHEA errors indicate CPU, memory, or PCIe hardware degradation"
        }
        else {
            Write-Success "  No WHEA hardware errors"
        }

        # Thermal throttling / processor speed change
        $thermalEvents = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'
            StartTime    = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($thermalEvents) {
            Write-DiagWarning "  Kernel-Processor-Power events: $($thermalEvents.Count)"
            $thermalEvents | Select-Object -First 3 | ForEach-Object {
                Write-Info "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] ID:$($_.Id) $(Get-EventSnippet -Event $_ -MaxLength 100)"
            }
        }
        else {
            Write-Success "  No processor power/thermal events"
        }
    }
    catch {
        Write-Info "  Could not query CPU-related events"
    }

    # 15. Process CPU Affinity Check
    Write-Section "Process CPU Affinity"
    try {
        $affinityIssues = @()
        # Calculate full affinity mask for this system
        $fullMask = [long](([math]::Pow(2, $logicalProcs)) - 1)

        $topProcs = Get-Process -ErrorAction Stop |
            Where-Object { $_.CPU -gt 10 -and $_.Id -ne 0 -and $_.Id -ne 4 } |
            Sort-Object CPU -Descending |
            Select-Object -First 20
        foreach ($proc in $topProcs) {
            try {
                $affinity = $proc.ProcessorAffinity.ToInt64()
                if ($affinity -ne $fullMask -and $affinity -gt 0) {
                    $setBits = [Convert]::ToString($affinity, 2).ToCharArray() | Where-Object { $_ -eq '1' }
                    $coreCount = $setBits.Count
                    $affinityIssues += "  $($proc.Name) (PID $($proc.Id)): Affinity=$coreCount of $logicalProcs cores (mask: 0x$($affinity.ToString('X')))"
                }
            }
            catch { }
        }
        if ($affinityIssues.Count -gt 0) {
            Write-DiagWarning "  Processes with restricted CPU affinity:"
            foreach ($ai in $affinityIssues) {
                Write-DiagWarning "  $ai"
            }
            Write-Info "  Restricted affinity limits available CPU and can cause bottlenecks"
        }
        else {
            Write-Success "  No processes with restricted CPU affinity (all using full core set)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check process affinity"
    }

    #endregion v3.0 CPU Checks
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
                    if ($script:ClusterEnv.IsClusterNode -and (Test-PathOnCSV -Path $logPath -CSVPaths $script:ClusterEnv.CSVPaths)) {
                        Write-DiagWarning "WARNING: Path '$logPath' is on a Cluster Shared Volume!"
                        Write-DiagWarning "Writing large traces to CSV can cause I/O storms affecting all cluster nodes."
                        $csvConfirm = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                        if ($csvConfirm -ne "Y") { return }
                    }
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
    
    # Cache volumes once for reuse throughout this function
    $cachedVolumes = $null
    try {
        $cachedVolumes = Get-Volume -ErrorAction Stop | Where-Object { $null -ne $_.DriveLetter }
    }
    catch {
        Write-DiagError "Failed to retrieve volume information: $($_.Exception.Message)"
    }
    
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
    Write-Section "Logical Disk Space"
    if ($cachedVolumes) {
        foreach ($vol in $cachedVolumes) {
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
    else {
        Write-DiagWarning "  No volume information available"
    }
    
    # Disk latency check
    Write-Section "Disk Latency (avg over last few seconds)"
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
    
    # Check cluster size for volumes (reuses cached $cachedVolumes)
    Write-Section "Cluster Size (should be 64KB for databases)"
    if ($cachedVolumes) {
        foreach ($vol in $cachedVolumes) {
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

    # Storage Disconnect Events (129, 153)
    Write-Section "Storage Error Events (last 7 days)"
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
    Write-Section "Disk Queue Length"
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
    Write-Section "Disk Write Latency"
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
    Write-Section "NTFS Errors (last 30 days)"
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

    # VM Pause-Critical Risk (>95% full) — reuses cached $cachedVolumes
    Write-Section "VM Pause-Critical Risk Check"
    if ($cachedVolumes) {
        foreach ($vol in ($cachedVolumes | Where-Object { $_.Size -gt 0 })) {
            $usedPercent = [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 1)
            if ($usedPercent -gt 95) {
                Write-DiagError "  Drive $($vol.DriveLetter): $usedPercent% full - VM MAY PAUSE if disk fills completely!"
            }
        }
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
                    if ($svcName -eq "SQLSERVERAGENT" -and $script:ClusterEnv.IsAGInstalled -and $script:ClusterEnv.LocalReplicaRole -eq "SECONDARY") {
                        Write-Info "  $($svc.DisplayName) ($($svc.Name)): Stopped (expected on AG SECONDARY replica)"
                    }
                    else {
                        Write-DiagError "  $($svc.DisplayName) ($($svc.Name)): STOPPED (Auto-Start)"
                    }
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
    Write-Section "Stopped Automatic Services"
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
    Write-Section "Disabled Services (may need attention)"
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
    Write-Section "Recently Crashed/Terminated Services (last 24 hours)"
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
    Write-Section "Time Service (NTP) Sync Status"
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
    Write-Section "Task Scheduler Health"
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
    Write-Section "EventLog Service Errors"
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
    Write-Section "Netlogon Events"
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
    Write-Section "RDP Licensing"
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
        Write-Section "$logName Log"
        
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
                Write-Section "Last 5 Events"
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
    Write-Section "Cluster Heartbeat/Quarantine Events (last 7 days)"
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

    # FailoverClustering Operational Log (v3.0 cluster-safe)
    if ($script:ClusterEnv.IsClusterNode) {
        Write-Section "Failover Clustering Operational Log (last 24h)"
        try {
            $fcEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-FailoverClustering/Operational'
                Level     = 1, 2, 3
                StartTime = (Get-Date).AddHours(-24)
            } -MaxEvents 20 -ErrorAction SilentlyContinue

            if ($fcEvents) {
                Write-DiagWarning "  Found $($fcEvents.Count) FailoverClustering event(s):"
                $fcGrouped = $fcEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5
                foreach ($g in $fcGrouped) {
                    Write-DiagWarning "    Event $($g.Name): $($g.Count) occurrence(s)"
                }
                $fcEvents | Select-Object -First 3 | ForEach-Object {
                    Write-Info "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] ID:$($_.Id) $(Get-EventSnippet -Event $_ -MaxLength 100)"
                }
            }
            else {
                Write-Success "  No FailoverClustering errors/warnings in last 24 hours"
            }
        }
        catch {
            Write-Info "  FailoverClustering Operational log not available"
        }
    }

    # Storage Events (129, 153)
    Write-Section "Storage Adapter Events (129/153, last 7 days)"
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
    Write-Section "DNS Update Failure Events"
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
    Write-Section "High-Priority Event Summary (last 24h)"
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
    Write-Section "Configured DNS Servers"
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
    Write-Section "DNS Resolution Tests"
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
    Write-Section "DNS Cache Statistics"
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
    Write-Section "DNS Bad Key Errors (cluster CNO/VCO failures)"
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
    Write-Section "Cluster Name Resolution"
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

    # AG Listener Name Resolution (v3.0 cluster-safe)
    if ($script:ClusterEnv.IsAGInstalled -and $script:ClusterEnv.AGDetails.Count -gt 0) {
        Write-Section "AG Listener Name Resolution"
        foreach ($ag in $script:ClusterEnv.AGDetails) {
            if ($ag.listener_name) {
                Write-Info "  AG '$($ag.ag_name)' listener: $($ag.listener_name):$($ag.listener_port)"
                try {
                    $resolved = Resolve-DnsName $ag.listener_name -ErrorAction Stop
                    Write-Success "    Resolves to: $($resolved.IPAddress -join ', ')"
                }
                catch {
                    Write-DiagError "    FAILED to resolve AG listener '$($ag.listener_name)'!"
                    Write-Info "    Stale listener DNS is the #1 cause of AG connectivity failures post-failover"
                }
            }
            else {
                Write-DiagWarning "  AG '$($ag.ag_name)': No listener configured"
            }
        }
    }

    # AD Secure Dynamic DNS Update Failures
    Write-Section "DNS Dynamic Update Failures"
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
    Write-Section "Reverse DNS Lookup"
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
    Write-Section "Recent Failed Logon Attempts (last 24 hours)"
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
    Write-Section "Kerberos Ticket Status"
    try {
        $klistOutput = klist 2>&1
        $ticketMatch = $klistOutput | Select-String "Cached Tickets"
        if ($ticketMatch) {
            Write-Info "  $($ticketMatch.ToString().Trim())"
        }
        else {
            Write-DiagWarning "  Could not determine cached ticket count (non-English locale or no tickets)"
        }
        
        # Show ticket details
        $klistOutput | Select-String "Server:" | Select-Object -First 5 | ForEach-Object {
            Write-Info "    $($_.ToString().Trim())"
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve Kerberos ticket information"
    }
    
    # Secure channel with domain
    Write-Section "Domain Secure Channel"
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
    Write-Section "Windows Firewall Status"
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
    Write-Section "Account Lockout Events (4740, last 24h)"
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
    Write-Section "Logon as a Service Policy"
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
    Write-Section "Schannel TLS Errors"
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
    Write-Section "Authentication Protocol Usage (last 100 logons)"
    try {
        $logonEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 100 -ErrorAction SilentlyContinue

        if ($logonEvents) {
            $ntlmCount = 0
            $kerbCount = 0
            foreach ($evt in $logonEvents) {
                try {
                    $authPkg = if ($evt.Properties.Count -gt 14) { $evt.Properties[14].Value } else { $null }
                    if ($authPkg -eq 'NTLM' -or $authPkg -like 'NtLm*') { $ntlmCount++ }
                    elseif ($authPkg -eq 'Kerberos') { $kerbCount++ }
                }
                catch { }
            }
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
    Write-Section "MachineKeys Directory Permissions"
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

    # 8. Quorum Health (v3.0)
    if ($script:ClusterEnv.IsClusterNode) {
        Write-Info "8. Cluster Quorum Health:"
        try {
            $quorumType = $script:ClusterEnv.QuorumType
            $quorumRes = $script:ClusterEnv.QuorumResource
            Write-Info "   Quorum Type: $quorumType | Witness: $quorumRes"
            
            $downNodes = $script:ClusterEnv.ClusterNodes | Where-Object { $_.State -ne 'Up' }
            if ($downNodes) {
                $issues++
                Write-DiagError "   ISSUE: $(@($downNodes).Count) cluster node(s) not in 'Up' state:"
                foreach ($dn in $downNodes) {
                    Write-DiagWarning "     $($dn.Name): $($dn.State)"
                }
            }
            else {
                Write-Success "   OK - All $(@($script:ClusterEnv.ClusterNodes).Count) cluster nodes are Up"
            }
        }
        catch {
            Write-Info "   Could not check quorum"
        }

        # 9. SQL AG Sync Health (v3.0)
        if ($script:ClusterEnv.IsAGInstalled -and $script:ClusterEnv.AGDetails.Count -gt 0) {
            Write-Info "9. SQL AG Synchronization:"
            foreach ($ag in $script:ClusterEnv.AGDetails) {
                if ($ag.sync_health -eq 'HEALTHY') {
                    Write-Success "   AG '$($ag.ag_name)': $($ag.local_role) - $($ag.sync_health)"
                }
                else {
                    $issues++
                    Write-DiagError "   ISSUE: AG '$($ag.ag_name)': $($ag.local_role) - $($ag.sync_health)"
                }
            }
        }
    }

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

function Export-DiagnosticSection {
    <#
    .SYNOPSIS
        Captures diagnostic output from a script block and offers to save and open it
    .PARAMETER Title
        Report title
    .PARAMETER ScriptBlock
        The diagnostic function to capture output from
    #>
    param(
        [string]$Title,
        [scriptblock]$ScriptBlock
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeTitle = $Title -replace '[^a-zA-Z0-9]', '_'
    $reportPath = Join-Path $script:DefaultLogPath "${safeTitle}_${timestamp}.txt"
    
    if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
        Write-DiagError "Cannot create report directory"
        return
    }
    
    try {
        $report = @()
        $report += "=" * 65
        $report += "$Title Report"
        $report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $report += "Computer:  $($env:COMPUTERNAME)"
        $report += "=" * 65
        $report += ""
        
        # Capture all output streams from the script block
        $output = & $ScriptBlock *>&1
        foreach ($line in $output) {
            $text = $line.ToString()
            # Strip ANSI/color codes if any, and format cleanly
            $report += $text
        }
        
        $report | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        Write-Success "Report saved to: $reportPath"
        
        $open = Get-ValidatedChoice -Prompt "Open report in Notepad? (Y/N)" -ValidChoices @("Y", "N")
        if ($open -eq "Y") {
            try {
                notepad $reportPath
            }
            catch {
                Write-DiagWarning "Could not open report. Navigate to: $reportPath"
            }
        }
    }
    catch {
        Write-DiagError "Failed to save report: $($_.Exception.Message)"
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
    
    # Declare at function scope for reuse across check sections
    $appPools = $null
    $sites = $null
    
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
    Write-Section "IIS Core Services Status"
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
    Write-Section "Application Pools"
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
    Write-Section "Websites"
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
    Write-Section "IIS Worker Processes (w3wp.exe)"
    try {
        $w3wps = Get-Process -Name w3wp -ErrorAction SilentlyContinue
        if ($w3wps) {
            foreach ($wp in $w3wps) {
                # Attempt to get the AppPool Name from CommandLine
                $appPoolName = "Unknown"
                try {
                    $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($wp.Id)" -ErrorAction Stop
                    if ($wmiProc.CommandLine -match "-ap `"(?<AppPool>[^`"]+)`"") {
                        $appPoolName = $Matches['AppPool']
                    }
                    elseif ($wmiProc.CommandLine -match "-ap (?<AppPool>\S+)") {
                        $appPoolName = $Matches['AppPool']
                    }
                }
                catch {}
                
                $memMB = [math]::Round($wp.WorkingSet64 / 1MB, 2)
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
    Write-Section "AppPool Identities & Permissions"
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
    Write-Section "Site Authentication Methods"
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
    Write-Section "SSL/TLS Certificates"
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
    Write-Section "IP Security Restrictions"
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
                         Version 3.0
                                                                

"@ -ForegroundColor Cyan

    Write-Host "
PRIMARY DIAGNOSTICS:" -ForegroundColor Yellow
    Write-Host "  1. Network Issues (Packet Loss, Slowness, RSS, MTU, Routing & 15+ checks)" -ForegroundColor White
    Write-Host "  2. Memory Issues (Usage, Leaks, Page File, Hardware & 19 checks)" -ForegroundColor White
    Write-Host "  3. CPU Issues (Per-Core, Queue, Interrupts, Throttling & 24 checks)" -ForegroundColor White
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
            $choice = Get-ValidatedChoice -Prompt "`nSelect an option (0-18)" -ValidChoices @("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18")
            
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