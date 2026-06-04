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
      - 24 CPU checks (per-core, queue length, interrupts, DPC, power throttling, AV detection, NUMA)
      - 24 Disk checks (IOPS, throughput, SMART, VSS, MPIO, filter drivers, storage tiering)
      - 19 Memory checks (page file, compression, handle/thread leaks, standby cache, RAM hardware)
      - Cluster-safe: detects AG role, CSV paths, heartbeat NICs, quorum health
      - SQL AG awareness: replica role detection, listener DNS, replication counters
      - Server 2025 ready: LBFO→SET fallback, Chimney deprecation handled
      - Server Baseline Validation (AD OU, license, crash dump, drivers, software inventory)
      - Task Scheduler Diagnostics (failed tasks, stuck tasks, orphaned, credential, SDDL audit)
      - HTML Diagnostic Report generation (dark-themed, collapsible, color-coded)
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
      [CPU]       15 new checks: per-core hotspots, privileged vs user time, processor queue,
                  context switches, interrupt/DPC time, uptime, power throttling, AV/filter
                  driver CPU, Hyper-V overhead, real-time 5s sampling, thread/process counts,
                  DPC queue rate, NUMA imbalance, WHEA/thermal events, process affinity
      [Disk]      15 new checks: IOPS, throughput, media type (SSD/HDD), SMART predictive
                  failure, VSS snapshots/writers, Storage Spaces pools, fragmentation,
                  pagefile placement, TempDB location, filter driver stack, disk timeout,
                  MPIO paths, ReFS/NTFS detection, disk busy time, storage tiering
      [TaskSched] 8 checks: failed tasks with error decoding, stuck/long-running tasks,
                  disabled tasks, high-privilege audit, credential failures, SDDL permissions,
                  orphaned executables, trigger health (expired/disabled)
      [Baseline]  9 checks from Validator scripts: AD OU path, license activation, crash dump
                  config, installed software, NIC power save, Windows features, NTFS 8.3,
                  page file clear at shutdown, critical system driver versions
      [Report]    HTML diagnostic report: dark-themed, collapsible sections, color-coded
                  output, runs all 12 diagnostics, opens in browser
      [Fix]       System.Web.HttpUtility→System.Net.WebUtility for Server 2019/Core compat
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
# ----------------------------------------------------------------------------
# SCOM-aligned thresholds (enterprise Management Pack defaults, May 2026).
# Source: SCOM monitoring team - monitoring is metric-driven (no Event-ID
# correlation). WARNING tier is set to the SCOM alert trigger so WSTT triage
# corroborates SCOM at the same threshold. CRITICAL tier (95%) acts as an
# in-script red-flag above SCOM.
#
#   Metric              SCOM alert (WARNING)   In-script CRITICAL
#   CPU                 85 %                   95 %
#   Memory              85 %                   95 %
#   Disk (system drive) 85 %                   95 %
#   Disk (non-system)   90 %                   95 %
# ----------------------------------------------------------------------------
Set-Variable -Name MEMORY_CRITICAL_THRESHOLD          -Value 95 -Option ReadOnly -Force
Set-Variable -Name MEMORY_WARNING_THRESHOLD           -Value 85 -Option ReadOnly -Force   # SCOM alert
Set-Variable -Name CPU_CRITICAL_THRESHOLD             -Value 95 -Option ReadOnly -Force
Set-Variable -Name CPU_WARNING_THRESHOLD              -Value 85 -Option ReadOnly -Force   # SCOM alert
Set-Variable -Name DISK_SYSTEM_CRITICAL_THRESHOLD     -Value 95 -Option ReadOnly -Force
Set-Variable -Name DISK_SYSTEM_WARNING_THRESHOLD      -Value 85 -Option ReadOnly -Force   # SCOM alert (system drive)
Set-Variable -Name DISK_NONSYSTEM_CRITICAL_THRESHOLD  -Value 95 -Option ReadOnly -Force
Set-Variable -Name DISK_NONSYSTEM_WARNING_THRESHOLD   -Value 90 -Option ReadOnly -Force   # SCOM alert (non-system drive)
# Legacy aliases (mapped to non-system values) - retained for any external/test
# consumers that still reference the original names.
Set-Variable -Name DISK_CRITICAL_THRESHOLD            -Value 95 -Option ReadOnly -Force
Set-Variable -Name DISK_WARNING_THRESHOLD             -Value 90 -Option ReadOnly -Force
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
    .DESCRIPTION
        Writes "WARNING: <text>" in yellow to the host. We deliberately use
        Write-Host (and not Write-Warning) so the literal "WARNING:" prefix
        appears in stream-captured output (e.g. *>&1 | Out-String used by
        Export-HTMLReport). The Warning stream's prefix is added by PowerShell's
        console formatter only and is lost when the stream is captured to a
        string, which previously stripped severity styling from the HTML report.
    .PARAMETER Text
        The warning message to display
    #>
    param([string]$Text)
    $safeText = Protect-DiagMessage -Message $Text
    Write-Host "WARNING: $safeText" -ForegroundColor Yellow
    if ($safeText -ne $Text) { Write-Verbose "[WARNING FULL] $Text" }
}

function Protect-DiagMessage {
    <#
    .SYNOPSIS
        Redacts potentially sensitive information from diagnostic messages
    .PARAMETER Message
        The message to sanitize
    #>
    param([string]$Message)
    # Redact UNC paths (\\server\share)
    $Message = $Message -replace '\\\\[^\s\\]+\\[^\s\\]+', '\\\\***\***'
    # Redact email addresses
    $Message = $Message -replace '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '***@***'
    # Redact domain\user patterns
    $Message = $Message -replace '(?<=[^\w])([A-Z][A-Z0-9]+)\\([A-Za-z0-9._-]+)(?=[^\w]|$)', '$1\***'
    return $Message
}

function Write-DiagError {
    <#
    .SYNOPSIS
        Displays an error message
    .PARAMETER Text
        The error message to display
    #>
    param([string]$Text)
    $safeText = Protect-DiagMessage -Message $Text
    Write-Host "[ERROR] $safeText" -ForegroundColor Red
    if ($safeText -ne $Text) { Write-Verbose "[ERROR FULL] $Text" }
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
    
    # Security: Reject path traversal, injection, and non-rooted paths
    if ($Path -match '\.\.' -or $Path -match '[\$\(\)&\|;`]' -or $Path -match '^\s*\\\\[^\\]+\\[^\\]+') {
        Write-DiagError "Path rejected for security: contains traversal, special characters, or UNC path"
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
    Write-Info "TSS (TroubleShootingScript) is the Microsoft-signed toolset used for"
    Write-Info "automated log collection (ETW, network traces, SDP reports, etc.)."
    Write-Info ""
    Write-Info "Download (official):"
    Write-Info "  - https://aka.ms/getTSS                    (TSS.zip - recommended)"
    Write-Info ""
    Write-Info "Documentation:"
    Write-Info "  - https://learn.microsoft.com/troubleshoot/windows-client/windows-tss/introduction-to-troubleshootingscript-toolset-tss"
    Write-Info ""
    Write-Info "Tips:"
    Write-Info "  - Default extraction path is C:\TSS"
    Write-Info "  - After install, run:  .\TSS.ps1 -Update           (self-update to latest)"
    Write-Info "  - For unattended runs, append:  -AcceptEula"
    Write-Info "  - If blocked: Get-ChildItem -Recurse -Path C:\TSS\*.ps* | Unblock-File -Confirm:\$false"
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
        Write-Info "Please configure TSS path from the main menu (option 15)"
        Write-Info "Download TSS from: https://aka.ms/getTSS  (default path: C:\TSS)"
        Write-Info "Docs: https://learn.microsoft.com/troubleshoot/windows-client/windows-tss/introduction-to-troubleshootingscript-toolset-tss"
        return $false
    }
    
    if (-not (Test-Path $script:TSSPath -PathType Container)) {
        Write-DiagWarning "TSS directory not found at: $($script:TSSPath)"
        Write-Info "Please update TSS path from the main menu (option 15)"
        return $false
    }
    
    $tssScript = Join-Path $script:TSSPath "TSS.ps1"
    if (Test-Path $tssScript) {
        Write-Success "TSS found at: $($tssScript)"
        return $true
    }
    else {
        Write-DiagWarning "TSS.ps1 not found at: $($script:TSSPath)"
        Write-Info "Please verify TSS installation or update path from the main menu (option 15)"
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
        [ValidateScript({
            if ($_ -match '[&|;`\$\(\)\{\}]') {
                throw "TSS command contains forbidden shell metacharacters: $($_ -replace '[\w\s\-\\/:.,=]', '*')"
            }
            $true
        })]
        [string]$Command
    )
    
    if ([string]::IsNullOrWhiteSpace($script:TSSPath)) {
        Write-DiagError "TSS path not configured. Please configure from main menu (option 15)"
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

        # Execute TSS via -Command "& '<script>' <args>" instead of -File.
        # TSS.ps1 resolves its helper modules using $PSScriptRoot / $MyInvocation.InvocationName,
        # which behaves differently under -File and causes "There are no traces to start" errors
        # for -Xperf scenarios. Using & '<script>' matches how the user runs TSS manually.
        # See GitHub issues #2 and #3.
        Write-Info "Executing: powershell -Command `"& '$tssScript' $Command`""
        # Pass ArgumentList as an array so .NET quotes each element correctly.
        # A single-string ArgumentList that embeds quotes gets re-tokenized by
        # the native command-line splitter, producing parser errors like
        # "Unexpected token '-NewSession'" inside the child powershell.exe.
        $innerCommand = "& '$tssScript' $Command; exit `$LASTEXITCODE"
        $tssArgList = @(
            '-NoProfile',
            '-ExecutionPolicy', 'RemoteSigned',
            '-Command', $innerCommand
        )
        $proc = Start-Process -FilePath "powershell.exe" `
            -ArgumentList $tssArgList `
            -Wait -NoNewWindow -PassThru
        if ($proc.ExitCode -ne 0) {
            Write-DiagWarning "TSS process exited with code: $($proc.ExitCode)"
            Write-Info "If TSS reported 'There are no traces to start', verify your TSS version supports the requested -Xperf scenario and that xperf.exe is present under '$($script:TSSPath)\BinArch64\'."
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
        # ------------------------------------------------------------
        # RSS = spreads incoming network packets across MULTIPLE CPU cores
        # instead of pinning all RX work to CPU 0. Without RSS, a 10 GbE NIC at
        # full line rate will saturate one logical processor and drop packets
        # while other cores sit idle. Critical on busy servers (DCs, file
        # servers, RDS, Hyper-V hosts).
        # ------------------------------------------------------------
        Write-Section "RSS (Receive Side Scaling) Status"
        Write-Info "  Description: Spreads inbound packet processing across multiple CPU cores."
        Write-Info "               Disabled = single-core RX bottleneck on busy NICs (10 GbE+)."
        $adapters = Get-NetAdapterRss -ErrorAction Stop
        
        foreach ($adapter in $adapters) {
            if ($adapter.Enabled -eq $true) {
                Write-Success "RSS is ENABLED on $($adapter.Name)"
            }
            else {
                Write-DiagWarning "RSS is DISABLED on $($adapter.Name)"
                Write-Info "  Impact: Single-core RX bottleneck possible at high throughput."
                Write-Info "  Remediation: Set-NetAdapterRss -Name '$($adapter.Name)' -Enabled `$true"
            }
        }
    }
    catch {
        Write-DiagError "Failed to check RSS status: $($_.Exception.Message)"
    }
     
    # Ephemeral Port Usage (Port Exhaustion)
    # ------------------------------------------------------------
    # Every outbound TCP connection consumes one ephemeral port from the dynamic
    # range (default 49152-65535 = 16384 ports). Sources of exhaustion:
    # - Apps that open + close many short-lived connections without pooling
    # - TIME_WAIT accumulation (default 4 min retention per closed socket)
    # - SQL/IIS/proxy overload, monitoring agents polling endpoints
    # When exhausted, new connections fail with WSAEADDRINUSE / 10048; symptoms
    # include 'cannot reach DC' / RPC timeouts / random app outages.
    # ------------------------------------------------------------
    Write-Section "TCP Ephemeral Ports"
    Write-Info "  Description: Outbound TCP connections consume ephemeral ports. Exhaustion ="
    Write-Info "               new connections fail with WSAEADDRINUSE (10048). Common cause:"
    Write-Info "               apps not pooling + TIME_WAIT retention (default 4 minutes)."
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
            Write-DiagError "  Potential Port Exhaustion (Using >$($PORT_EXHAUSTION_THRESHOLD * 100)% of available ephemeral ports)"
            Write-Info "    Impact: New outbound TCP connections will start failing with 10048."
            Write-Info "    Likely cause: An app opening many short-lived connections (no pooling),"
            Write-Info "                  or a flood of TIME_WAIT sockets from a chatty client."
            Write-Info "    Diagnosis: 'Get-NetTCPConnection | Group-Object State,OwningProcess |"
            Write-Info "               Sort Count -Desc | Select -First 10' to find the offender."
            Write-Info "    Remediation: Fix the app to pool connections; or expand the dynamic"
            Write-Info "                 port range with: 'netsh int ipv4 set dynamicport tcp"
            Write-Info "                 start=10000 num=55535'."
        }
        else {
            Write-Success "  Port usage is within acceptable range"
        }
    }
    catch {
        Write-DiagError "Failed to check ephemeral ports: $($_.Exception.Message)"
    }

    # Check VMQ (Virtual Machine Queue) Status
    # ------------------------------------------------------------
    # VMQ = hardware feature that lets a NIC deliver VM traffic directly to the
    # right vSwitch queue, bypassing the host-CPU sort step. Great on 10 GbE+.
    # KNOWN BAD: 1 GbE Broadcom NICs (NetXtreme I, BCM57xx series) have buggy
    # VMQ implementations that drop packets randomly under load. Microsoft KB
    # 2902166 explicitly recommends disabling VMQ on those NICs.
    # ------------------------------------------------------------
    Write-Section "VMQ Status (Relevant for Hyper-V Hosts)"
    Write-Info "  Description: Virtual Machine Queue accelerates VM traffic via NIC HW."
    Write-Info "               KNOWN BAD on 1 GbE Broadcom NetXtreme - causes packet drops."
    try {
        $vmq = Get-NetAdapterVmq -ErrorAction SilentlyContinue
        if ($vmq) {
            foreach ($v in $vmq) {
                Write-Info "  $($v.Name): VMQ Enabled: $($v.Enabled)"
                if ($v.Enabled -eq $true) {
                    Write-DiagWarning "    Note: If this is a 1Gbps Broadcom adapter, consider disabling VMQ to prevent packet drops"
                    Write-Info "      Remediation: Disable-NetAdapterVmq -Name '$($v.Name)' (per MS KB 2902166)."
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
    # ------------------------------------------------------------
    # Buffer settings on the NIC driver govern how many packets the NIC can
    # queue before dropping. Default values are tuned for desktops; servers
    # under bursty load (file servers, AG primary, Hyper-V hosts) frequently
    # need larger buffers (Small Rx Buffers = 8192, Rx Ring Size = 4096).
    # Symptoms of undersized buffers: ReceivedDiscardedPackets > 0 (next section).
    # ------------------------------------------------------------
    Write-Section "Network Adapter Buffer Settings"
    Write-Info "  Description: NIC driver receive-side buffers. Defaults are tuned for"
    Write-Info "               desktops; busy servers under bursty load may drop packets"
    Write-Info "               unless buffers are raised (Small Rx=8192, Rx Ring=4096)."
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
                        Write-Info "    Remediation: Set-NetAdapterAdvancedProperty -Name '$($adapter.Name)' -RegistryKeyword '$($smallRxBuffer.RegistryKeyword)' -RegistryValue 8192"
                    }
                }
                
                # Check Rx Ring Size
                $rxRingSize = $advProps | Where-Object { $_.DisplayName -like "*Rx Ring*" -or $_.RegistryKeyword -like "*RxRing*" }
                if ($rxRingSize) {
                    $currentValue = $rxRingSize.DisplayValue
                    Write-Info "  Rx Ring Size: $($currentValue)"
                    if ($currentValue -ne "4096") {
                        Write-DiagWarning "  Recommended value is 4096"
                        Write-Info "    Remediation: Set-NetAdapterAdvancedProperty -Name '$($adapter.Name)' -RegistryKeyword '$($rxRingSize.RegistryKeyword)' -RegistryValue 4096"
                    }
                }

                if (-not $smallRxBuffer -and -not $rxRingSize) {
                    Write-Info "  No tunable Rx buffer / ring size properties exposed by this driver"
                    Write-Info "  (typical for synthetic / virtual NICs - nothing to tune here)."
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
    # ------------------------------------------------------------
    # Windows Server defaults to 'Balanced' power plan, which throttles CPU and
    # NIC PCIe Active State Power Management. On any production server (esp.
    # latency-sensitive workloads: SQL, RDS, real-time apps), this causes
    # measurable latency hits and inconsistent network behaviour. Microsoft
    # explicitly recommends 'High Performance' for SQL and Hyper-V hosts.
    # ------------------------------------------------------------
    Write-Section "Power Plan"
    Write-Info "  Description: 'Balanced' throttles CPU + PCIe ASPM, causing latency on"
    Write-Info "               servers. Microsoft recommends 'High Performance' for SQL,"
    Write-Info "               Hyper-V, RDS, and any latency-sensitive workload."
    try {
        $powerPlan = powercfg /getactivescheme
        if ($powerPlan -like "*High performance*") {
            Write-Success "Power Plan is set to High Performance"
        }
        else {
            Write-DiagWarning "Power Plan is NOT set to High Performance"
            Write-Info "  Current: $($powerPlan)"
            Write-Info "  Impact: CPU may downclock; NIC ASPM may inject 1-2 ms latency."
            Write-Info "  Remediation: powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        }
    }
    catch {
        Write-DiagError "Failed to check power plan: $($_.Exception.Message)"
    }
    
    # Network Statistics (reuses cached $activeAdapters)
    # ------------------------------------------------------------
    # Cumulative packet counters since adapter init. Useful for spotting:
    # - Persistent error rates (errors / total packets > 0.001 is suspect)
    # - Asymmetric in/out (one direction much busier than the other)
    # - Adapters that aren't seeing traffic they should (mis-cabled, mis-VLAN'd)
    # NOTE: counters reset on adapter reset/disable, so a low absolute number
    # may simply mean the NIC was bounced recently.
    # ------------------------------------------------------------
    Write-Section "Network Interface Statistics"
    Write-Info "  Description: Cumulative packet counters since adapter init. Persistent"
    Write-Info "               error rates or asymmetric send/receive volume = investigate."
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

    # Packet Discards (vmxnet3 alert) - reuses cached $activeAdapters
    # ------------------------------------------------------------
    # ReceivedDiscardedPackets / OutboundDiscardedPackets counters increment when
    # a packet was received/queued but the OS or NIC had to drop it (full ring
    # buffer, full host-side queue, malformed packet, no socket listening).
    # Common causes:
    # - vmxnet3 with default ring size on busy VMs (KNOWN ISSUE - bump to 4096)
    # - VMQ enabled on buggy 1 GbE Broadcom
    # - Sudden burst exceeded NIC buffer capacity
    # - Application not draining sockets fast enough
    # ------------------------------------------------------------
    Write-Section "Packet Discards"
    Write-Info "  Description: Packets received/queued but dropped (full buffer, no socket,"
    Write-Info "               or malformed). On vmxnet3 = bump ring size to 4096."
    if ($activeAdapters) {
        $anyDiscards = $false
        foreach ($adpt in $activeAdapters) {
            try {
                $stats = Get-NetAdapterStatistics -Name $adpt.Name -ErrorAction Stop
                $discardIn = $stats.ReceivedDiscardedPackets
                $discardOut = $stats.OutboundDiscardedPackets
                if ($discardIn -gt 0 -or $discardOut -gt 0) {
                    $anyDiscards = $true
                    Write-DiagWarning "  $($adpt.Name): Discards IN=$discardIn OUT=$discardOut"
                    if ($adpt.DriverDescription -like "*vmxnet3*") {
                        Write-DiagError "    vmxnet3 adapter with discards - check ring buffer size and driver version"
                        Write-Info "      Remediation: Set-NetAdapterAdvancedProperty -Name '$($adpt.Name)' "
                        Write-Info "                   -RegistryKeyword '*RxRingSize' -RegistryValue 4096"
                        Write-Info "                   AND ensure latest VMware Tools (vmxnet3 driver >= 1.8)."
                    }
                    else {
                        Write-Info "      Likely cause: Bursty traffic exceeding NIC ring buffer or app not"
                        Write-Info "                    draining sockets. Investigate buffer settings (above)."
                    }
                }
            }
            catch {
                Write-Verbose "Could not check discards for $($adpt.Name): $($_.Exception.Message)"
            }
        }
        if (-not $anyDiscards) {
            Write-Success "  No packet discards detected on any active adapter"
        }
    }
    else {
        Write-Info "  No active adapters to check"
    }

    # Port Reachability (self-telnet) - uses TcpClient with 2s timeout instead of Test-NetConnection
    # ------------------------------------------------------------
    # Confirms which CRITICAL service ports are bound on localhost RIGHT NOW.
    # 'Closed/Not listening' on a port the server is supposed to host = the
    # service is stopped, crashed, or bound to a different interface only.
    # 'OPEN' on an unexpected port = potential rogue listener / unwanted
    # service started by an admin/agent/installer.
    # ------------------------------------------------------------
    Write-Section "Port Reachability (localhost)"
    Write-Info "  Description: Confirms which critical service ports are listening on"
    Write-Info "               127.0.0.1. Closed = service down/misbound. OPEN unexpectedly"
    Write-Info "               = rogue listener."
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
    # ------------------------------------------------------------
    # Two teaming technologies on Windows Server:
    #   LBFO (Load Balancing & Failover) - legacy, deprecated in 2022/2025.
    #     Modes: Static / SwitchIndependent / LACP
    #     Algos: TransportPorts / IPAddresses / MacAddresses / Dynamic / HyperVPort
    #   SET (Switch Embedded Teaming) - modern, integrated with vSwitch.
    #
    # Known bad combo: SwitchIndependent + AddressHash without switch-side
    # awareness can cause inbound packets to come back on a different MAC than
    # the source IP suggests, breaking some load balancers / firewalls.
    # ------------------------------------------------------------
    Write-Section "NIC Teaming Configuration"
    Write-Info "  Description: LBFO (legacy) or SET (modern) teaming. Watch for"
    Write-Info "               SwitchIndependent + AddressHash combo - can cause asymmetric"
    Write-Info "               return paths that break load balancers/firewalls."
    try {
        $teams = Get-NetLbfoTeam -ErrorAction SilentlyContinue
        if ($teams) {
            foreach ($team in $teams) {
                Write-Info "  [LBFO] Team: $($team.Name) - Mode: $($team.TeamingMode) - LB: $($team.LoadBalancingAlgorithm)"
                if ($team.TeamingMode -eq "SwitchIndependent" -and $team.LoadBalancingAlgorithm -eq "AddressHash") {
                    Write-DiagWarning "    Dual MAC risk: SwitchIndependent + AddressHash may cause connectivity issues"
                    Write-Info "      Remediation: Switch to 'Dynamic' load-balancing algorithm, or use LACP"
                    Write-Info "                   teaming mode if the upstream switch supports it."
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
        # LBFO cmdlets missing (Server 2025+) - try SET
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
    # ------------------------------------------------------------
    # Failover-clustering events that indicate inter-node network problems:
    #   1135 - 'Cluster node X was removed from the active failover cluster
    #          membership.' = node lost heartbeat to cluster majority.
    #   1129 - 'Cluster network interface for cluster node X on network Y is
    #          unreachable.' = a specific cluster network went down.
    # Even ONE per day is a serious red flag - they cause failovers, app
    # disruption, and SQL AG re-sync churn.
    # ------------------------------------------------------------
    Write-Section "WAN/Heartbeat Loss Events (last 24h)"
    Write-Info "  Description: Failover Cluster Event 1135 = node removed from cluster"
    Write-Info "               (heartbeat lost). Event 1129 = cluster network unreachable."
    Write-Info "               Even one per day causes app failovers and AG re-syncs."
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
            Write-Info "    Likely cause: Switch port flap, cable seating, NIC driver issue, or"
            Write-Info "                  network saturation pushing heartbeat past timeout."
            Write-Info "    Remediation: Check switch port logs at corresponding timestamps;"
            Write-Info "                 verify cluster network priorities (Get-ClusterNetwork);"
            Write-Info "                 confirm dedicated heartbeat network is on a separate VLAN."
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
    # ------------------------------------------------------------
    # The default gateway is the next hop for ALL traffic outside the local
    # subnet. If unreachable, you keep local connectivity but lose everything
    # else. We exclude cluster heartbeat NICs (which intentionally don't have
    # a gateway) to avoid false positives. Latency thresholds:
    #   < 5 ms : LAN-class - excellent
    #   < 50 ms: WAN-class - normal
    #   > 50 ms: investigate switch/firewall congestion
    # ------------------------------------------------------------
    Write-Section "Default Gateway Reachability"
    Write-Info "  Description: ICMP ping to each non-heartbeat default gateway. Unreachable"
    Write-Info "               = no off-subnet connectivity. >50ms latency = LAN/WAN issue."
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
                        Write-Info "    Likely cause: Saturated uplink, switch CPU overload, or QoS"
                        Write-Info "                  policy delaying ICMP. Affects ALL off-subnet traffic."
                    }
                }
                catch {
                    Write-DiagError "  Gateway $gwIP ($ifAlias): NOT Reachable"
                    Write-Info "    Impact: Server has lost off-subnet connectivity."
                    Write-Info "    Remediation: Verify physical link, switch port, VLAN tag,"
                    Write-Info "                 and that the gateway IP itself is up (ping from another host)."
                }
            }
        }
        else {
            Write-DiagWarning "  No default gateway configured"
            Write-Info "    Impact: Server cannot reach any IP outside its local subnet(s)."
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve default gateway: $($_.Exception.Message)"
    }

    # 2. Duplicate IP Detection
    # ------------------------------------------------------------
    # Two hosts with the same IP = chaos. Symptoms range from intermittent
    # connectivity (ARP cache races) to total outage. Causes:
    # - Static IP conflict with a DHCP-assigned host
    # - Cloned VM that didn't get a sysprep IP reset
    # - Misconfigured NIC team / SET assigning multiple MACs to one IP
    # We detect by ARPing each local IP and counting unique MACs in the reply.
    # ------------------------------------------------------------
    Write-Section "Duplicate IP Detection"
    Write-Info "  Description: ARP each local IP and look for multiple MACs answering. >1"
    Write-Info "               MAC = duplicate IP somewhere on the subnet (cloned VM, static"
    Write-Info "               vs DHCP collision, misconfigured team)."
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
                    Write-DiagError "  DUPLICATE IP DETECTED: $($ip.IPAddress) has multiple MAC addresses"
                    foreach ($mac in $uniqueMACs) {
                        Write-DiagWarning "    MAC: $mac"
                    }
                }
            }
            catch { }
        }
        if ($duplicateFound) {
            Write-Info "    Impact: Intermittent connectivity, random RDP/file/AD failures."
            Write-Info "    Remediation: Identify the OTHER host (search DHCP leases, ARP tables"
            Write-Info "                 on the upstream switch). Reconfigure one of the two."
        }
        else {
            Write-Success "  No duplicate IP addresses detected"
        }
    }
    catch {
        Write-DiagWarning "  Could not perform duplicate IP detection: $($_.Exception.Message)"
    }

    # 3. Network Adapter Link Speed & Duplex
    # ------------------------------------------------------------
    # Half duplex on a physical adapter is ALWAYS bad - usually indicates a
    # negotiation failure with the switch port (one side hardcoded, the other
    # auto-negotiating). Symptoms: collisions, retransmissions, terrible
    # throughput, intermittent timeouts. Almost always caused by a forced-speed
    # config left over from a 100 Mbps era.
    # 100 Mbps on a physical adapter on a modern (1 GbE+) network is also
    # nearly always an autonegotiation failure or a bad cable.
    # ------------------------------------------------------------
    Write-Section "Adapter Link Speed & Duplex"
    Write-Info "  Description: Link speed and duplex per active adapter. HALF DUPLEX = severe"
    Write-Info "               packet loss + retransmits. 100 Mbps on a physical adapter today"
    Write-Info "               = autonegotiation failure or bad cable."
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
                        Write-DiagError "    HALF DUPLEX detected - this causes severe packet loss and retransmissions"
                        Write-Info "      Likely cause: Negotiation mismatch with switch port (one side hardcoded)."
                        Write-Info "      Remediation: Set BOTH sides (server + switch port) to 'Auto', or BOTH to"
                        Write-Info "                   the same hardcoded value (1000Mbps Full Duplex). Never mix."
                    }
                }
            }
            catch { }
            if ($linkSpeed -match '100\s*(Mbps|M)' -and $adpt.DriverDescription -notlike '*Virtual*') {
                Write-DiagWarning "    100 Mbps link speed on physical adapter - possible autonegotiation failure"
                Write-Info "      Remediation: Replace cable, check switch port speed config, swap NIC port."
            }
        }
    }

    # 4. TCP Chimney / Task Offload Status
    # ------------------------------------------------------------
    # Offload features push CPU work (checksum, segmentation, RSS, RSC) onto the
    # NIC silicon. Modern NICs do this well. KNOWN PITFALLS:
    #   Chimney Offload  : DEPRECATED, removed in newer Windows. If still ENABLED,
    #                      can cause RPC/SMB hangs - always disable.
    #   Task Offload     : if Disabled = CPU does ALL checksum work. CPU spike +
    #                      throughput drop on busy servers.
    #   RSC              : great for receive throughput; some old vSwitch + RSC
    #                      combos cause TCP retransmissions on Hyper-V.
    # ------------------------------------------------------------
    Write-Section "TCP Offload Settings"
    Write-Info "  Description: NIC hardware offloads. Chimney = DEPRECATED, disable if on."
    Write-Info "               Task Offload disabled = CPU does ALL checksum work (server-wide hit)."
    try {
        $offload = Get-NetOffloadGlobalSetting -ErrorAction Stop
        # Chimney is deprecated/removed on newer OS - access safely
        $chimneyValue = $offload | Select-Object -ExpandProperty Chimney -ErrorAction SilentlyContinue
        if ($null -ne $chimneyValue) {
            Write-Info "  Chimney Offload: $chimneyValue"
            if ($chimneyValue -eq 'Enabled') {
                Write-DiagWarning "  TCP Chimney is ENABLED - deprecated; disable for stability"
                Write-Info "    Impact: Can cause RPC / SMB hangs and intermittent app failures."
                Write-Info "    Remediation: Set-NetOffloadGlobalSetting -Chimney Disabled"
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
            Write-Info "    Impact: Higher CPU on busy NICs; throughput drop on 10 GbE+."
            Write-Info "    Remediation: Set-NetOffloadGlobalSetting -TaskOffload Enabled (then reboot)."
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
                        Write-Info "    Remediation: Enable-NetAdapterChecksumOffload -Name '$($adpt.Name)'"
                    }
                }
            }
            catch { }
        }
    }

    # 5. MTU / Jumbo Frames Consistency
    # ------------------------------------------------------------
    # Maximum Transmission Unit = largest single packet (in bytes) the link
    # will carry without fragmentation. Default = 1500. Jumbo Frames = 9000
    # (used in storage networks, vMotion, SMB Direct).
    # CRITICAL: every device end-to-end MUST use the same MTU. A mismatch:
    #   - Black-holes packets larger than the smallest hop's MTU
    #   - Breaks path MTU discovery if ICMP Type 3 Code 4 is filtered
    #   - Manifests as 'small files transfer fine, large hang/timeout'
    # ------------------------------------------------------------
    Write-Section "MTU Configuration"
    Write-Info "  Description: Max packet size per link. ALL devices end-to-end must match."
    Write-Info "               Mismatch = packets > smallest MTU are black-holed (small"
    Write-Info "               transfers OK, large ones hang)."
    try {
        # Filter out loopback and tunnel pseudo-interfaces. Loopback reports
        # NlMtu = 4294967295 which trips a false "INCONSISTENT MTU" warning.
        # Also exclude 'Local Area Connection*' placeholders (Hyper-V auto-generated
        # connectoid for the host-side vNIC; reports MTU=1300 by default and is not
        # carrying any production traffic).
        $mtuSettings = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.ConnectionState -eq 'Connected' -and
                $_.InterfaceAlias -notlike '*Loopback*' -and
                $_.InterfaceAlias -notlike '*isatap*' -and
                $_.InterfaceAlias -notlike '*Teredo*' -and
                $_.InterfaceAlias -notlike 'Local Area Connection*' -and
                $_.NlMtu -gt 0 -and $_.NlMtu -lt 65536
            } |
            Select-Object InterfaceAlias, NlMtu
        $mtuValues = @()
        foreach ($iface in $mtuSettings) {
            Write-Info "  $($iface.InterfaceAlias): MTU = $($iface.NlMtu)"
            $mtuValues += $iface.NlMtu
            if ($iface.NlMtu -gt 1500) {
                Write-Info "    Jumbo Frames enabled (MTU > 1500)"
            }
        }
        $uniqueMTUs = @($mtuValues | Select-Object -Unique)
        if ($uniqueMTUs.Count -gt 1) {
            Write-DiagWarning "  INCONSISTENT MTU values detected across interfaces: $($uniqueMTUs -join ', ')"
            Write-Info "    Likely cause: Jumbo Frames enabled on a storage NIC but switch port"
            Write-Info "                  or downstream device still at 1500."
            Write-Info "    Remediation: Either enable Jumbo Frames consistently end-to-end, or"
            Write-Info "                 set all NICs back to 1500: Set-NetIPInterface -InterfaceAlias"
            Write-Info "                 '<name>' -NlMtuBytes 1500"
        }
        elseif ($uniqueMTUs.Count -eq 1) {
            Write-Success "  MTU is consistent across all connected interfaces ($($uniqueMTUs[0]))"
        }
        else {
            Write-Info "  No physical IPv4 interfaces with MTU values found"
        }
    }
    catch {
        Write-DiagWarning "  Could not check MTU settings: $($_.Exception.Message)"
    }

    # 6. DNS Suffix & Search Order
    # ------------------------------------------------------------
    # Suffixes determine how single-label names (e.g. 'fileserver01') get
    # resolved. If the suffix list is wrong, you get NXDOMAIN responses for
    # internal names. Devolution = automatically appending parent domains.
    # Per-NIC RegisterInDNS controls whether the host registers its IP into
    # DNS for that interface; turning OFF on cluster heartbeat NICs prevents
    # DNS from returning the heartbeat IP to clients (a common gotcha).
    # ------------------------------------------------------------
    Write-Section "DNS Suffix Configuration"
    Write-Info "  Description: Suffix list resolves single-label names. Per-NIC"
    Write-Info "               RegisterInDNS=False on heartbeat NICs prevents clients from"
    Write-Info "               getting the wrong IP back."
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
    # ------------------------------------------------------------
    # WINS = legacy NetBIOS name resolution, deprecated since Server 2008.
    # Should be EMPTY on modern environments. If WINS servers are configured:
    # - They may be unreachable, slowing every NetBIOS lookup by ~750ms
    # - Some apps still try WINS first before DNS
    # Recommended: remove WINS entries entirely, force DNS-only resolution.
    # ------------------------------------------------------------
    Write-Section "WINS Configuration"
    Write-Info "  Description: Legacy NetBIOS name resolution. Should be EMPTY on modern envs."
    Write-Info "               Stale entries can add ~750ms to every NetBIOS lookup."
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
        else {
            Write-Info "    Remediation: If those WINS servers are no longer needed, clear them"
            Write-Info "                 via the NIC properties (Advanced TCP/IP > WINS tab) or via"
            Write-Info "                 'Set-DnsClientNrptRule' / netsh."
        }
    }
    catch {
        Write-DiagWarning "  Could not check WINS configuration: $($_.Exception.Message)"
    }

    # 8. Proxy / WinHTTP Settings
    # ------------------------------------------------------------
    # Two separate proxy configs on Windows:
    #   - WinHTTP (system / service-side)  -> used by Windows Update, Defender,
    #                                          MMA/AMA, Azure Arc agent, sfc.
    #   - WinINET / IE (per-user)           -> used by IE/Edge legacy, .NET WebClient.
    # A stale or unreachable proxy here will SILENTLY break Windows Update,
    # MS Defender signature downloads, Azure agent connectivity, and activation.
    # ------------------------------------------------------------
    Write-Section "WinHTTP Proxy Configuration"
    Write-Info "  Description: System-wide proxy used by Windows Update, Defender, MMA/AMA,"
    
    Write-Info "               and Azure Arc. Stale proxy here = silent breakage of all of"
    Write-Info "               those at once."
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
            Write-Info "    Likely impact: Mis-set proxy blocks Windows Update, Defender,"
            Write-Info "                   activation, and Azure agent connectivity."
            Write-Info "    Remediation: Verify proxy URL is reachable; reset with"
            Write-Info "                 'netsh winhttp reset proxy' if no proxy is needed."
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
    # ------------------------------------------------------------
    # Old NIC drivers are a leading cause of Windows Server network bugs:
    # - vmxnet3 < 1.8: known packet-drop bugs on busy VMs
    # - Old Broadcom NetXtreme: VMQ packet loss (KB 2902166)
    # - Old Intel NDIS6 drivers: missing modern offload paths
    # Anything > 2 years old should be reviewed against vendor advisories.
    # ------------------------------------------------------------
    Write-Section "Network Adapter Driver Information"
    Write-Info "  Description: NIC driver vendor / version / age. Drivers > 2 years old ="
    Write-Info "               investigate for known issues (vmxnet3 < 1.8, old Broadcom VMQ)."
    if ($activeAdapters) {
        foreach ($adpt in $activeAdapters) {
            try {
                $driverInfo = Get-NetAdapter -Name $adpt.Name -ErrorAction Stop
                $driverVersion  = $driverInfo.DriverVersion
                $driverDateRaw  = $driverInfo.DriverDate
                $driverDesc     = $driverInfo.DriverDescription
                $driverProvider = $driverInfo.DriverProvider

                Write-Info "  $($adpt.Name):"
                Write-Info "    Driver: $driverDesc"
                Write-Info "    Version: $driverVersion | Provider: $driverProvider"

                # DriverDate may come back as [DateTime], string, or $null depending on
                # the Windows build / driver INF. Coerce defensively so a single bad
                # value doesn't blow away the whole adapter's output.
                $driverDate = $null
                if ($driverDateRaw) {
                    if ($driverDateRaw -is [datetime]) {
                        $driverDate = $driverDateRaw
                    }
                    else {
                        [datetime]$parsed = [datetime]::MinValue
                        if ([datetime]::TryParse([string]$driverDateRaw, [ref]$parsed)) {
                            $driverDate = $parsed
                        }
                    }
                }

                if ($driverDate) {
                    $driverAge = ((Get-Date) - $driverDate).Days
                    Write-Info "    Date: $($driverDate.ToString('yyyy-MM-dd')) ($driverAge days old)"

                    # Synthetic / paravirtualized NIC drivers ship with a
                    # placeholder DriverDate in the INF (commonly 2006-06-21
                    # for Microsoft synthetic drivers). The "real" version
                    # is tied to Windows servicing, not to that date — so
                    # suppress the >2-year warning for these adapters.
                    $isSyntheticDriver = (
                        ($driverProvider -eq 'Microsoft' -and (
                            $driverDesc -like '*Hyper-V Network Adapter*' -or
                            $driverDesc -like '*Hyper-V Virtual*' -or
                            $driverDesc -like '*Loopback*'
                        )) -or
                        $driverDesc -like '*VMware*VMXNET*Loopback*' -or
                        $driverDesc -like '*Microsoft Kernel Debug*'
                    )

                    if ($driverAge -gt 730 -and -not $isSyntheticDriver) {
                        Write-DiagWarning "    Driver is over 2 years old - consider updating"
                        Write-Info "      Remediation: Check vendor site ($driverProvider) for latest;"
                        Write-Info "                   on VMware: update VMware Tools; on Hyper-V: WU."
                    }
                    elseif ($driverAge -gt 730 -and $isSyntheticDriver) {
                        Write-Info "    (Synthetic/virtual NIC - INF DriverDate is a placeholder; age check skipped.)"
                    }
                }
                elseif ($driverDateRaw) {
                    Write-Info "    Date: $driverDateRaw (unparseable - age unknown)"
                }
                else {
                    Write-Info "    Date: (not reported by driver)"
                }

                # Use [version] comparison; string compare ('1.10' -lt '1.8' is $true) is wrong.
                if ($driverDesc -like "*vmxnet3*") {
                    [version]$verObj = $null
                    if ([version]::TryParse([string]$driverVersion, [ref]$verObj) -and $verObj -lt [version]'1.8') {
                        Write-DiagWarning "    vmxnet3 driver is outdated - upgrade to latest VMware Tools"
                        Write-Info "      Impact: Known packet-drop bug on busy VMs."
                    }
                }
            }
            catch {
                Write-DiagWarning "  Could not retrieve driver info for $($adpt.Name): $($_.Exception.Message)"
            }
        }
    }

    # 10. Network Binding Order
    # ------------------------------------------------------------
    # Per-adapter binding controls whether IPv4 / IPv6 are enabled on each NIC.
    # Disabling IPv4 on the primary NIC will break essentially everything.
    # Disabling IPv6 on a NIC sometimes done as 'hardening' but can break
    # DirectAccess, Failover Clustering heartbeats, and some apps that prefer
    # IPv6 by default (e.g. modern AD replication paths).
    # ------------------------------------------------------------
    Write-Section "Network Binding Order"
    Write-Info "  Description: Per-NIC IPv4/IPv6 binding state. Disabling IPv6 wholesale can"
    Write-Info "               break DirectAccess, cluster heartbeats, and some AD paths."
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
            Write-Info "    Caution: Microsoft does NOT recommend disabling IPv6 - prefer the"
            Write-Info "             DisabledComponents registry value over per-NIC unbind."
        }
    }
    catch {
        Write-DiagWarning "  Could not check binding order: $($_.Exception.Message)"
    }

    # 11. Firewall Rules Blocking Common Ports
    # ------------------------------------------------------------
    # Surfaces explicit BLOCK rules on the well-known service ports we care
    # about (RDP, SMB, RPC, WinRM, etc). A BLOCK rule on, say, port 445 (SMB)
    # will silently break file shares, GPO, AD authentication, etc - even if
    # the OS thinks the firewall profile is 'OK'.
    # ------------------------------------------------------------
    Write-Section "Firewall Rules on Common Ports"
    Write-Info "  Description: Surfaces explicit BLOCK rules on critical service ports"
    Write-Info "               (RDP, SMB, RPC, WinRM). Silent breakage source - profile may"
    Write-Info "               look 'enabled OK' while a single block rule kills the service."
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
                Write-Info "    Remediation: Disable the rule with 'Disable-NetFirewallRule"
                Write-Info "                 -DisplayName <name>' or remove with 'Remove-NetFirewallRule'."
            }
        }
        Write-Success "  Firewall rule check completed"
    }
    catch {
        Write-DiagWarning "  Could not check firewall rules: $($_.Exception.Message)"
    }

    # 12. RDMA / SMB Direct Status
    # ------------------------------------------------------------
    # SMB Direct (RDMA over Converged Ethernet / InfiniBand) gives near-zero
    # CPU SMB throughput on storage networks. Only meaningful on dedicated
    # storage NICs (RoCE, iWARP, IB). SMB Multichannel = multi-stream SMB
    # over multiple NICs/queues; massive throughput win on 10 GbE+.
    # ------------------------------------------------------------
    Write-Section "RDMA / SMB Direct Status"
    Write-Info "  Description: RDMA and SMB Multichannel status. Major throughput / CPU"
    Write-Info "               efficiency win on storage / Hyper-V live-migration networks."
    try {
        $smbConfig = Get-SmbClientConfiguration -ErrorAction Stop
        $smbMultichannel = $smbConfig.EnableMultiChannel
        Write-Info "  SMB Multichannel: $(if ($smbMultichannel) { 'Enabled' } else { 'Disabled' })"
        if (-not $smbMultichannel) {
            Write-Info "    Remediation: Set-SmbClientConfiguration -EnableMultiChannel `$true"
        }
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
    # ------------------------------------------------------------
    # AutoTuningLevel = how aggressively Windows scales the TCP receive window:
    #   Disabled / HighlyRestricted = throughput cap on long-fat networks
    #   Normal = default, fine for most workloads
    #   Experimental = max scaling, occasionally breaks old middleboxes
    # CongestionProvider = CUBIC / NewReno / DCTCP. CUBIC is modern default.
    # KeepAliveTime > 2 hours = idle long-lived TCP sessions get killed by
    # firewalls / NAT before keepalive triggers. Common LB / VPN footgun.
    # ------------------------------------------------------------
    Write-Section "TCP/IP Stack Parameters"
    Write-Info "  Description: TCP autotuning / congestion / KeepAlive. Disabled autotune"
    Write-Info "               caps throughput on long-fat networks. KeepAlive > 2 hours ="
    Write-Info "               firewall/NAT can drop idle long-lived sessions."
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
                Write-Info "    Remediation: netsh int tcp set global autotuninglevel=normal"
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
                Write-Info "    Remediation: Lower KeepAliveTime to 1800000 (30 min) for affected"
                Write-Info "                 servers (RDS, SQL, Exchange) via the same registry value."
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
    # ------------------------------------------------------------
    # System-log events that explicitly indicate NIC trouble. Whitelist of IDs
    # we care about (avoid noise from unrelated providers reusing the same
    # numeric ID). Decoded:
    #   27   - 'Network adapter <name> has determined the link is not up' (NIC reset)
    #   32   - 'A miniport encountered an error and was unable to load' (driver fail)
    #   1073 - 'Network adapter link state has changed' (link flap)
    #   4198 - DUPLICATE IP detected by TCPIP
    #   4199 - DUPLICATE IP resolved by TCPIP
    # We DO NOT filter by ProviderName here because these IDs are TCPIP /
    # netbt / nic-driver specific (not reused by Perflib/Kernel-Power like
    # IDs 2003 / 55 are). Still, we report counts grouped by ID + sample 5.
    # ------------------------------------------------------------
    Write-Section "Network Adapter Error Events (last 7 days)"
    Write-Info "  Description: NIC-related System events: link flaps, miniport errors,"
    Write-Info "               duplicate IPs. Even a low count is worth investigating."
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
            Write-Info "    Likely cause: Cable / SFP failure (Event 27/1073), driver bug or"
            Write-Info "                  incompatible firmware (Event 32), or another host with"
            Write-Info "                  the same IP (Event 4198)."
            Write-Info "    Remediation: For 27/1073 = check switch port logs + replace cable/SFP."
            Write-Info "                 For 32 = update NIC driver + firmware."
            Write-Info "                 For 4198 = run the Duplicate IP Detection check (above)."
        }
        else {
            Write-Success "  No network adapter error events found"
        }
    }
    catch {
        Write-Info "  Could not query network adapter events"
    }

    # 15. Routing Table Sanity Check
    # ------------------------------------------------------------
    # The IPv4 routing table determines next-hop for every destination. Common
    # problems we surface:
    #   - Multiple default gateways (0.0.0.0/0): causes asymmetric routing,
    #     intermittent connectivity. Almost never desired on a server.
    #   - Static/persistent routes: documents what an admin pinned manually.
    #   - Same-metric conflicts: two interfaces 'tied' for the same dest =
    #     Windows alternates packets between them = retransmissions, weird
    #     application behaviour.
    # ------------------------------------------------------------
    Write-Section "Routing Table Analysis"
    Write-Info "  Description: IPv4 routing table sanity check. Multiple default gateways ="
    Write-Info "               asymmetric routing. Same-metric ties = Windows alternates"
    Write-Info "               packets between NICs (causes weird app behaviour)."
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
            Write-Info "    Likely cause: Two NICs both got a gateway from DHCP, OR an admin"
            Write-Info "                  set a 2nd default route manually."
            Write-Info "    Remediation: Remove extras: 'Remove-NetRoute -DestinationPrefix"
            Write-Info "                 0.0.0.0/0 -InterfaceIndex <wrong-ifIndex>'. On heartbeat"
            Write-Info "                 NICs, uncheck 'Default Gateway' in IPv4 properties."
        }
        elseif (@($defaultRoutes).Count -eq 1) {
            $dr = $defaultRoutes
            $ifAlias = (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.ifIndex -eq $dr.InterfaceIndex }).Name
            Write-Success "  Single default gateway: $($dr.NextHop) via $ifAlias (metric $($dr.RouteMetric))"
        }
        else {
            Write-DiagError "  NO default gateway configured"
            Write-Info "    Impact: Server cannot reach any IP outside its local subnet(s)."
            Write-Info "    Remediation: Set one via 'New-NetRoute -DestinationPrefix 0.0.0.0/0"
            Write-Info "                 -NextHop <gateway-ip> -InterfaceIndex <primary-NIC>'."
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

        # Check for metric conflicts (same metric on different interfaces for same destination).
        # NOTE: S2D / SMB Direct / SMB Multichannel intentionally place 2+ NICs on the
        # SAME storage subnet so that SMB can stripe traffic across both. That produces
        # broadcast (.255) + subnet routes that share metrics across interfaces - this
        # is BY DESIGN, not a misconfig. Detect SMB/storage NIC names and skip those.
        $smbAdapterIfIndices = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '(?i)SMB|Storage|Heartbeat|Cluster|vMotion|LiveMigration|RDMA|iSCSI'
        } | Select-Object -ExpandProperty ifIndex)
        $metricConflicts = $routes | Group-Object DestinationPrefix |
            Where-Object { $_.Count -gt 1 } |
            ForEach-Object {
                $metrics = $_.Group.RouteMetric | Select-Object -Unique
                if (@($metrics).Count -eq 1 -and $_.Name -ne '255.255.255.255/32' -and $_.Name -ne '224.0.0.0/4') {
                    # Skip if all conflicting routes are on storage/heartbeat NICs (S2D pattern).
                    $conflictIfIndices = @($_.Group.InterfaceIndex | Select-Object -Unique)
                    $allOnStorageNics = ($smbAdapterIfIndices.Count -gt 0) -and
                        (($conflictIfIndices | Where-Object { $_ -notin $smbAdapterIfIndices }).Count -eq 0)
                    if (-not $allOnStorageNics) { $_ }
                }
            }
        if ($metricConflicts) {
            Write-DiagWarning "  Route metric conflicts detected (same metric, same destination, different interfaces):"
            foreach ($conflict in $metricConflicts | Select-Object -First 5) {
                Write-DiagWarning "    $($conflict.Name): $($conflict.Count) routes with same metric"
            }
            Write-Info "    Impact: Windows will alternate packets between the tied routes,"
            Write-Info "            which can confuse stateful firewalls / load balancers."
            Write-Info "    Remediation: Set distinct InterfaceMetric values via"
            Write-Info "                 'Set-NetIPInterface -InterfaceIndex <ifIndex>"
            Write-Info "                 -InterfaceMetric <higher-number-for-non-preferred>'."
        }
        elseif ($smbAdapterIfIndices.Count -gt 0) {
            Write-Info "  (Same-subnet routes on SMB/storage NICs are expected for SMB Multichannel/S2D.)"
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
        Write-Info "  Description: Free Memory shown here is RAW free RAM only and does NOT"
        Write-Info "               include the standby cache. The 'Available MBytes' counter"
        Write-Info "               (Section 2 below) is the more accurate measure for the OS."
        Write-Info "  Thresholds : SCOM alert at $($MEMORY_WARNING_THRESHOLD)% / in-script critical at $($MEMORY_CRITICAL_THRESHOLD)%."

        # Cross-check raw 'used' % against the standby-cache-aware Available MBytes
        # counter. Windows aggressively fills RAM with file cache (this is good
        # behaviour - cache is instantly reclaimable). Reporting raw free as 'used'
        # produces a permanent 85%+ alarm on small-RAM systems doing any I/O at all.
        # Only escalate when BOTH the raw % AND the Available MBytes % cross the line.
        $availPctOfTotal = $null
        try {
            $availMBVal = (Get-Counter '\Memory\Available MBytes' -ErrorAction Stop).CounterSamples.CookedValue
            $totalMBVal = $totalMemGB * 1024
            if ($totalMBVal -gt 0) { $availPctOfTotal = [math]::Round(($availMBVal / $totalMBVal) * 100, 1) }
        }
        catch { $availPctOfTotal = $null }

        if ($memUsagePercent -gt $MEMORY_CRITICAL_THRESHOLD -and ($null -eq $availPctOfTotal -or $availPctOfTotal -lt 5)) {
            Write-DiagError "Memory usage above $($MEMORY_CRITICAL_THRESHOLD)% - critical (SCOM alert at $($MEMORY_WARNING_THRESHOLD)%)"
            Write-Info "    Remediation: Identify top consumers (table above), restart leaking"
            Write-Info "                 services, add RAM, or expand the pagefile."
        }
        elseif ($memUsagePercent -gt $MEMORY_WARNING_THRESHOLD -and ($null -eq $availPctOfTotal -or $availPctOfTotal -lt 10)) {
            Write-DiagWarning "Memory usage above $($MEMORY_WARNING_THRESHOLD)% - SCOM alert threshold (Available MBytes confirms low: $availPctOfTotal% of total)"
        }
        elseif ($memUsagePercent -gt $MEMORY_WARNING_THRESHOLD) {
            Write-Info "  Memory Usage % is high ($memUsagePercent%) but Available MBytes shows $availPctOfTotal% truly free - this is OS file cache and is reclaimable on demand. Not alerting."
            Write-Success "Memory usage adequate when standby cache is included"
        }
        else {
            Write-Success "Memory usage is within normal range (below SCOM $($MEMORY_WARNING_THRESHOLD)% alert)"
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
    Write-Info "  Description: Memory(MB) = current Working Set (resident RAM)."
    Write-Info "               CPU(s) = TOTAL CPU SECONDS since the process started"
    Write-Info "                        (CUMULATIVE lifetime, NOT current %CPU)."
    Write-Info "               A process started at boot 30 days ago will show large CPU(s)"
    Write-Info "               even if it is idle right now. For 'live' %CPU see CPU section."

    if ($processAnalysis) {
        $processAnalysis.ByMemory | Format-Table Name, 
        @{Label = "Memory(MB)"; Expression = { [math]::Round($_.WS / 1MB, 2) } },
        @{Label = "CPU(s)"; Expression = { [math]::Round($_.CPU, 2) } },
        Id -AutoSize
    }
    
    Write-Section "Committed Memory"
    # ------------------------------------------------------------
    # \Memory\% Committed Bytes In Use = (Commit Charge) / (Commit Limit).
    # Commit Charge = total virtual memory the OS has promised to processes.
    # Commit Limit  = physical RAM + total pagefile size.
    # When this hits 100%, processes get OUT-OF-MEMORY errors regardless of free RAM.
    # ------------------------------------------------------------
    try {
        $perfCounter = Get-Counter '\Memory\% Committed Bytes In Use' -ErrorAction Stop
        if ($perfCounter) {
            $committedPercent = [math]::Round($perfCounter.CounterSamples.CookedValue, 2)
            Write-Info "`nCommitted Bytes In Use: $($committedPercent)%"
            Write-Info "  Description: % of (RAM + pagefile) currently promised to processes."
            Write-Info "               At 100%, new allocations FAIL with out-of-memory."
            if ($committedPercent -gt $MEMORY_CRITICAL_THRESHOLD) {
                Write-DiagError "  Committed bytes above $($MEMORY_CRITICAL_THRESHOLD)% - critical (SCOM alert at $($MEMORY_WARNING_THRESHOLD)%)"
                Write-Info "    Remediation: Increase pagefile (raises Commit Limit) or add RAM."
                Write-Info "                 Restarting leaky processes drops Commit Charge fast."
            }
            elseif ($committedPercent -gt $MEMORY_WARNING_THRESHOLD) {
                Write-DiagWarning "  Committed bytes above $($MEMORY_WARNING_THRESHOLD)% - SCOM alert threshold"
            }
            else {
                Write-Success "  Commit charge within safe range (below SCOM $($MEMORY_WARNING_THRESHOLD)% alert)"
            }
        }
    }
    catch {
        Write-DiagWarning "Could not retrieve committed bytes information: $($_.Exception.Message)"
    }

    # NonPagedPool Usage
    # ------------------------------------------------------------
    # NonPaged Pool = kernel memory that MUST stay in physical RAM (cannot be paged
    # to disk). Used by drivers, kernel structures, network buffers, ETW sessions,
    # and filter drivers. Leaks here are dangerous because the OS cannot recover
    # the memory by paging - exhaustion leads to bugcheck 0xC2 (BAD_POOL_CALLER) or
    # general system instability.
    # ------------------------------------------------------------
    Write-Section "Kernel Memory Pools"
    Write-Info "NonPaged Pool:"
    try {
        $npPool = Get-Counter '\Memory\Pool Nonpaged Bytes' -ErrorAction Stop
        $npMB = [math]::Round($npPool.CounterSamples.CookedValue / 1MB, 2)
        Write-Info "  NonPaged Pool: $npMB MB"
        Write-Info "    Description: Kernel memory that cannot be paged to disk (drivers,"
        Write-Info "                 ETW buffers, network stack, filter drivers)."

        # Auto-relax thresholds on cluster / Hyper-V hosts. Failover Clustering +
        # Hyper-V + SMB Direct + S2D + EDR routinely consume 350-450 MB of NPP
        # on a healthy node - the desktop-tuned 200/300 MB thresholds fire
        # constantly with no real problem.
        $npCriticalMB = $NONPAGED_POOL_CRITICAL_MB
        $npWarningMB = $NONPAGED_POOL_WARNING_MB
        $clusterRunning = (Get-Service -Name 'ClusSvc' -ErrorAction SilentlyContinue).Status -eq 'Running'
        $hyperVRunning = (Get-Service -Name 'vmms' -ErrorAction SilentlyContinue).Status -eq 'Running'
        if ($clusterRunning -or $hyperVRunning) {
            $npCriticalMB = 800
            $npWarningMB = 500
            $roleNote = @()
            if ($clusterRunning) { $roleNote += 'Failover Clustering' }
            if ($hyperVRunning) { $roleNote += 'Hyper-V' }
            Write-Info "    (Thresholds relaxed for $($roleNote -join ' + ') host: warn>$($npWarningMB)MB / critical>$($npCriticalMB)MB)"
        }

        if ($npMB -gt $npCriticalMB) {
            Write-DiagError "  NonPaged Pool >${npCriticalMB}MB - possible ETW buffer or driver leak (critical)"
            Write-Info "    Likely culprits: Excessive ETW sessions (logman query -ets),"
            Write-Info "                     buggy NIC/storage/AV drivers, oversized SMB pool."
            Write-Info "    Remediation: Run 'poolmon.exe -p -P -b' (sort by NonPaged) to find"
            Write-Info "                 the leaking driver tag, then update or disable that driver."
        }
        elseif ($npMB -gt $npWarningMB) {
            Write-DiagWarning "  NonPaged Pool elevated (>${npWarningMB}MB)"
        }
        else {
            Write-Success "  NonPaged Pool within normal range"
        }
    }
    catch {
        Write-DiagWarning "  Could not check NonPaged Pool"
    }

    # Modified Page List (file cache pressure)
    # ------------------------------------------------------------
    # Modified Page List = pages whose contents have been changed in memory but
    # have NOT yet been written back to disk. The lazy-writer flushes these to
    # disk in the background. A LARGE modified list means writes are queueing
    # faster than the disk can absorb them - usually disk bottleneck or write storm.
    # ------------------------------------------------------------
    Write-Section "File Cache & Paging"
    Write-Info "Modified Page List:"
    try {
        $modPages = Get-Counter '\Memory\Modified Page List Bytes' -ErrorAction Stop
        $modGB = [math]::Round($modPages.CounterSamples.CookedValue / 1GB, 2)
        Write-Info "  Modified Page List: $modGB GB"
        Write-Info "    Description: Dirty pages waiting to be flushed to disk. A growing"
        Write-Info "                 list = disk cannot keep up with write rate."
        if ($modGB -gt $MODIFIED_PAGE_LIST_WARNING_GB) {
            Write-DiagWarning "  Large modified page list ($modGB GB) - file cache consuming RAM"
            Write-Info "    Likely cause: Slow disk subsystem, write-heavy workload (SQL, backup),"
            Write-Info "                  or 'Large System Cache' enabled on a non-file-server."
            Write-Info "    Remediation: Check disk latency (Section 'Disk'); disable Large System"
            Write-Info "                 Cache; tune MaxCacheSizeInMB; or move workload to faster disk."
        }
        else {
            Write-Success "  Modified Page List within normal range"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Modified Page List"
    }

    # Paging Spikes
    # ------------------------------------------------------------
    # \Memory\Pages/sec = HARD page faults + writes per second (pages read from
    # OR written to DISK to resolve memory references). High = the OS is hitting
    # disk to satisfy what should be RAM requests. Direct hit on app performance.
    # NOTE: Includes BOTH reads (file cache) and writes (modified list) - use
    # \Memory\Pages Input/sec for read-only view if needed.
    # ------------------------------------------------------------
    Write-Info "`nPaging Activity:"
    try {
        $pagesPerSec = Get-Counter '\Memory\Pages/sec' -ErrorAction Stop
        $pps = [math]::Round($pagesPerSec.CounterSamples.CookedValue, 0)
        Write-Info "  Pages/sec: $pps"
        Write-Info "    Description: Pages read from or written to DISK to satisfy memory"
        Write-Info "                 references. Direct indicator of memory pressure hitting disk."
        if ($pps -gt $PAGING_CRITICAL_THRESHOLD) {
            Write-DiagError "  High paging activity (>$($PAGING_CRITICAL_THRESHOLD) pages/sec) - severe memory pressure (critical)"
            Write-Info "    Impact: Application response time will degrade noticeably. Disk"
            Write-Info "            queue depth and latency will spike (check Disk diagnostics)."
            Write-Info "    Remediation: Add RAM, identify and stop runaway memory consumers,"
            Write-Info "                 or move pagefile to a faster disk (SSD/NVMe)."
        }
        elseif ($pps -gt $PAGING_WARNING_THRESHOLD) {
            Write-DiagWarning "  Elevated paging activity (>$($PAGING_WARNING_THRESHOLD) pages/sec)"
        }
        else {
            Write-Success "  Paging activity within normal range"
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
    # ------------------------------------------------------------
    # The pagefile (pagefile.sys) backs the system commit limit and stores process
    # memory paged out under pressure. CurrentUsage tells you how much is actually
    # in use right now; PeakUsage shows the historical high since boot.
    # A pagefile that is >70% used = the system has been UNDER MEMORY PRESSURE.
    # ------------------------------------------------------------
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
                    Write-DiagError "    Page file is >$($PAGEFILE_USAGE_CRITICAL_PERCENT)% full (critical)"
                    Write-Info "      Impact: When pagefile fills, processes hit OUT-OF-MEMORY errors."
                    Write-Info "      Remediation: Increase pagefile size, add RAM, or stop leaks."
                }
                elseif ($usedPercent -gt $PAGEFILE_USAGE_WARNING_PERCENT) {
                    Write-DiagWarning "    Page file usage above $($PAGEFILE_USAGE_WARNING_PERCENT)% - watch for growth"
                }
                if ($peakMB -gt ($totalMB * 0.9)) {
                    Write-DiagWarning "    Peak usage ($peakMB MB) reached >90% of allocation since boot"
                    Write-Info "      => System has hit memory pressure at least once - investigate."
                }
            }
        }
        else {
            Write-DiagWarning "  No page files found (system may crash under memory pressure!)"
            Write-Info "    Remediation: Configure a system-managed pagefile via SystemPropertiesAdvanced."
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
    # ------------------------------------------------------------
    # \Memory\Available MBytes = Free + Standby + Zero page lists.
    # This is the AUTHORITATIVE number for 'how much RAM can the OS hand out
    # right now'. Always trust this over Task Manager's 'Free' figure.
    # ------------------------------------------------------------
    Write-Section "Available Memory (includes reclaimable cache)"
    try {
        $availMB = Get-Counter '\Memory\Available MBytes' -ErrorAction Stop
        $availVal = [math]::Round($availMB.CounterSamples.CookedValue, 0)
        Write-Info "  Available MBytes: $availVal MB ($([math]::Round($availVal / 1024, 2)) GB)"
        Write-Info "    Description: Free + standby + zero page lists. The TRUE measure of"
        Write-Info "                 RAM the OS can immediately allocate to a new request."

        # Use BOTH absolute MB and percentage thresholds. On small VMs (e.g. 3-4 GB)
        # the 1024 MB absolute warning fires almost permanently even though the
        # box has 25% free RAM. Trigger only when BOTH conditions agree, OR when
        # absolute is dangerously low regardless of size.
        $totalRamMB = [math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory / 1MB, 0)
        $availPct = if ($totalRamMB -gt 0) { [math]::Round(($availVal / $totalRamMB) * 100, 1) } else { 100 }

        if ($availVal -lt 256 -or ($availPct -lt 5 -and $availVal -lt $AVAILABLE_MB_CRITICAL)) {
            Write-DiagError "  Available memory critical: $availVal MB ($availPct% of $totalRamMB MB total)"
            Write-Info "    Impact: OS will start aggressive WS trimming and eventually pageout."
            Write-Info "    Remediation: Free RAM by stopping non-essential services or add RAM."
        }
        elseif ($availPct -lt 10 -and $availVal -lt $AVAILABLE_MB_WARNING) {
            Write-DiagWarning "  Available memory low: $availVal MB ($availPct% of $totalRamMB MB total)"
        }
        else {
            Write-Success "  Available memory is adequate ($availVal MB / $availPct% of total)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Available MBytes"
    }

    # 3. Memory Compression Ratio
    # ------------------------------------------------------------
    # Windows 10 / Server 2016+ compresses pages instead of paging them to disk
    # when RAM is tight. The 'Memory Compression' process holds the compressed
    # store. Active compression = system under memory pressure but avoiding disk
    # I/O. >2 GB compressed = pressure is significant.
    # ------------------------------------------------------------
    Write-Section "Memory Compression"
    try {
        $compressProc = Get-Process -Name "Memory Compression" -ErrorAction SilentlyContinue
        if ($compressProc) {
            $compressWS = [math]::Round($compressProc.WorkingSet64 / 1MB, 0)
            Write-Info "  Memory Compression process WS: $compressWS MB"
            Write-Info "    Description: OS is compressing pages in RAM instead of paging"
            Write-Info "                 to disk - active = real memory pressure."
            try {
                $compressedBytes = Get-Counter '\Memory\Compression Store Size' -ErrorAction Stop
                $compressedMB = [math]::Round($compressedBytes.CounterSamples.CookedValue / 1MB, 0)
                if ($compressWS -gt 0 -and $compressedMB -gt 0) {
                    $ratio = [math]::Round($compressedMB / $compressWS, 2)
                    Write-Info "  Compressed Store: $compressedMB MB | Compression Ratio: ${ratio}:1"
                    if ($compressWS -gt 2048) {
                        Write-DiagWarning "  Over 2 GB of compressed memory - system under significant pressure"
                        Write-Info "    Remediation: Add RAM. Compression is a stopgap - the OS is"
                        Write-Info "                 burning CPU cycles to avoid the worse fate of disk paging."
                    }
                }
            }
            catch {
                Write-Info "  Compression Store counter not available (Windows 10/2016+)"
            }
        }
        else {
            Write-Info "  Memory Compression process not active"
            Write-Info "    Description: No compression activity = OS has plenty of RAM"
            Write-Info "                 OR the OS is older than Windows 10 / Server 2016."
        }
    }
    catch {
        Write-DiagWarning "  Could not check memory compression"
    }

    # 4. Handle & Thread Count per Process
    # ------------------------------------------------------------
    # Handles = kernel object references (files, registry keys, events, sockets,
    # mutexes, etc.). Each handle consumes a small amount of pool memory. Normal
    # processes use a few thousand. >10,000 = potential leak. >50,000 = almost
    # certainly leaking. The system-wide ceiling is ~16M, but individual processes
    # crash long before that.
    # Threads = units of execution. >500 in a single process is unusual outside
    # of well-known multi-threaded apps (SQL Server, IIS w/ many app pools).
    # ------------------------------------------------------------
    Write-Section "Handle & Thread Analysis"
    Write-Info "  Description: A handle is a reference to a kernel object (file, socket,"
    Write-Info "               registry key, etc.). Sustained growth indicates a code-level"
    Write-Info "               leak - the process never closes objects it opened."
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

    # 5. Paged Pool Usage  *** PRIMARY KERNEL LEAK INDICATOR ***
    # ------------------------------------------------------------
    # Paged Pool = kernel memory that CAN be paged to disk when needed. Used by
    # filter drivers (AV/EDR/backup), the registry, file system cache structures,
    # and many kernel data structures.
    #
    # Healthy:    < 300 MB on most servers
    # Warning:    > 300 MB - investigate driver/AV behavior
    # Critical:   > 400 MB - bugcheck risk imminent
    #
    # When paged pool exhausts, Windows blue-screens with one of:
    #   0x0000002E  SESSION_POOL_EMPTY
    #   0x0000003F  NO_MORE_SYSTEM_PTES
    #   0x00000077  KERNEL_STACK_INPAGE_ERROR
    #
    # Common culprits (top 95% of cases):
    #   - Antivirus/EDR filter drivers (Symantec srtsp/cyserver, McAfee, CrowdStrike)
    #   - Backup agent file-system filters (Veeam, Commvault, Veritas)
    #   - Storage filter drivers (third-party deduplication, anti-ransomware)
    #   - Registry hive bloat from a chatty service
    #
    # Diagnosis: Run 'poolmon.exe -p -P -b' (sort by Paged, sort by Bytes).
    # The top tag identifies the leaking driver. Look up the tag in pooltag.txt
    # (in WDK) or with: findstr /s /i "TAG" %windir%\System32\drivers\*.sys
    # ------------------------------------------------------------
    Write-Section "Paged Pool Usage"
    try {
        $pagedPool = Get-Counter '\Memory\Pool Paged Bytes' -ErrorAction Stop
        $ppMB = [math]::Round($pagedPool.CounterSamples.CookedValue / 1MB, 2)
        Write-Info "  Paged Pool: $ppMB MB"
        Write-Info "    Description: Pageable kernel memory. Heavy users = filter drivers"
        Write-Info "                 (AV/EDR/backup), registry hives, file cache structures."
        if ($ppMB -gt $PAGED_POOL_CRITICAL_MB) {
            Write-DiagError "  Paged Pool >$($PAGED_POOL_CRITICAL_MB)MB - risk of SESSION_POOL_EMPTY bugcheck (critical)"
            Write-Info "    Impact: Server is at risk of BSOD. Bugchecks 0x2E / 0x3F / 0x77"
            Write-Info "            are typical outcomes; correlated symptoms include Event 333"
            Write-Info "            (registry hive flush failure) - check Section 10."
            Write-Info "    Likely culprits: Antivirus filter (SRTSP/cyserver), backup agent,"
            Write-Info "                     storage filter driver, or third-party EDR."
            Write-Info "    Diagnosis: Run 'poolmon.exe -p -P -b' (from Windows WDK)."
            Write-Info "               Press 'P' twice to sort by Paged. Top tag = the leak."
            Write-Info "    Remediation:"
            Write-Info "      1. Identify pool tag with poolmon, map to driver via pooltag.txt."
            Write-Info "      2. Update or temporarily disable the suspect filter driver."
            Write-Info "      3. Schedule a maintenance reboot to release the leaked pool."
            Write-Info "      4. Open a vendor case if the leak persists after update."
        }
        elseif ($ppMB -gt $PAGED_POOL_WARNING_MB) {
            Write-DiagWarning "  Paged Pool elevated (>$($PAGED_POOL_WARNING_MB)MB)"
            Write-Info "    Trend monitoring recommended. Re-run this check daily; if the"
            Write-Info "    number keeps climbing across reboots, treat as a confirmed leak."
        }
        else {
            Write-Success "  Paged Pool is within normal range"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Paged Pool"
    }

    # 6. System Cache Working Set
    # ------------------------------------------------------------
    # \Memory\Cache Bytes = the OS file system cache (cached file content + metadata).
    # On file servers this is desirable (fast file reads). On application servers,
    # an oversized cache STARVES applications of physical RAM and causes WS trimming.
    # ------------------------------------------------------------
    Write-Section "System Cache Working Set"
    try {
        $cacheBytes = Get-Counter '\Memory\Cache Bytes' -ErrorAction Stop
        $cacheMB = [math]::Round($cacheBytes.CounterSamples.CookedValue / 1MB, 0)
        $cacheGB = [math]::Round($cacheBytes.CounterSamples.CookedValue / 1GB, 2)
        Write-Info "  System Cache: $cacheMB MB ($cacheGB GB)"
        Write-Info "    Description: OS file system cache. Beneficial on file servers,"
        Write-Info "                 problematic on app servers (steals RAM from apps)."
        if ($cacheGB -gt 4) {
            Write-DiagWarning "  Large system cache ($cacheGB GB) - may be starving user processes"
            Write-Info "    Likely cause: 'Large System Cache' enabled, or heavy file-share workload."
            Write-Info "    Remediation: For non-file-server roles, set:"
            Write-Info "      HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            Write-Info "      LargeSystemCache (DWORD) = 0  (favor application memory)"
            Write-Info "      Then reboot. On file servers, tune MaxCacheSizeInMB instead."
        }
        else {
            Write-Success "  System cache size within reasonable range"
        }
    }
    catch {
        Write-DiagWarning "  Could not check system cache"
    }

    # 7. Memory Leak Trend Detection (Private Bytes vs Working Set)
    # ------------------------------------------------------------
    # WS (Working Set)        = pages currently resident in physical RAM.
    # Private Bytes           = total committed memory the process has allocated
    #                           that is NOT shared with other processes.
    # Virtual Bytes           = total VAS reserved by the process. On 64-bit this
    #                           can be huge (TB range) without being a problem -
    #                           reservation != commitment.
    #
    # Leak rule of thumb: if Private >> WS (by >500 MB), the process has allocated
    # memory that has been PAGED OUT to disk - the OS deemed it inactive. That can
    # be normal (idle process) or a sign of a slow leak.
    # The DEFINITIVE leak signal is a steady upward trend in Private Bytes over
    # hours/days with no workload increase. Sample this counter repeatedly.
    # ------------------------------------------------------------
    Write-Section "Memory Leak Indicators (Private Bytes vs Working Set)"
    Write-Info "  Description: WS = RAM-resident pages. Private = total committed memory."
    Write-Info "               A large Private-WS gap means memory was paged out (idle OR leak)."
    Write-Info "               True leak detection requires sampling Private Bytes over TIME."
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
        Write-Info "  Note: Virtual Bytes in the TB range is NORMAL on 64-bit (address-space"
        Write-Info "        reservation, not actual RAM). Focus on Private Bytes growth over time."
    }
    catch {
        Write-DiagWarning "  Could not perform leak trend analysis"
    }

    # 8. Standby List Breakdown
    # ------------------------------------------------------------
    # Standby cache = pages that were in working sets, were trimmed, but are
    # still in RAM (not yet zeroed). They can be reclaimed instantly with no
    # disk hit. Split by priority:
    #   - Core (high priority)    : OS kernel data; reclaimed last
    #   - Normal                  : typical app pages; reclaimed when needed
    #   - Reserve (low priority)  : easily evicted; first to go
    # The healthier the mix toward Reserve, the more headroom the OS has.
    # ------------------------------------------------------------
    Write-Section "Standby Cache Breakdown"
    Write-Info "  Description: Pages trimmed from working sets but still in RAM. Can be"
    Write-Info "               reclaimed instantly (no disk I/O). Split by priority."
    try {
        $standbyCore = Get-Counter '\Memory\Standby Cache Core Bytes' -ErrorAction Stop
        $standbyNormal = Get-Counter '\Memory\Standby Cache Normal Priority Bytes' -ErrorAction Stop
        $standbyReserve = Get-Counter '\Memory\Standby Cache Reserve Bytes' -ErrorAction Stop

        $coreMB = [math]::Round($standbyCore.CounterSamples.CookedValue / 1MB, 0)
        $normalMB = [math]::Round($standbyNormal.CounterSamples.CookedValue / 1MB, 0)
        $reserveMB = [math]::Round($standbyReserve.CounterSamples.CookedValue / 1MB, 0)
        $totalStandby = $coreMB + $normalMB + $reserveMB

        Write-Info "  Total Standby: $totalStandby MB ($([math]::Round($totalStandby / 1024, 2)) GB)"
        Write-Info "    Core (high priority): $coreMB MB    (kernel data; reclaimed last)"
        Write-Info "    Normal priority: $normalMB MB       (typical apps)"
        Write-Info "    Reserve (low priority): $reserveMB MB (easiest to reclaim)"

        if ($totalStandby -gt 0) {
            $reclaimablePercent = [math]::Round(($reserveMB / $totalStandby) * 100, 1)
            Write-Info "  Easily reclaimable: $reclaimablePercent% of standby cache"
            if ($reclaimablePercent -lt 20 -and $totalStandby -gt 2048) {
                Write-DiagWarning "  Low reclaimable standby cache - high-priority file cache is dominating"
                Write-Info "    Impact: When new memory demand arrives, OS has fewer 'free' pages,"
                Write-Info "            forcing it to evict Normal/Core priority pages (slower)."
                Write-Info "    Remediation: Reduce file-cache pressure (see Section 6 'System Cache')"
                Write-Info "                 or run RAMMap.exe to identify what's holding standby pages."
            }
            else {
                Write-Success "  Standby cache priority distribution is healthy"
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

    # 10. Resource Exhaustion Events (2004 / 333 / 2003)
    # ------------------------------------------------------------
    # Event ID reference (memory-related only):
    #   2004  - Resource-Exhaustion-Detector  : Virtual memory low; OS identified top
    #                                            committers. Indicates pagefile/RAM pressure.
    #   333   - Application Popup / Kernel    : Registry hive flush failed (often caused
    #                                            by paged-pool exhaustion or disk I/O issues).
    #   2003  - Microsoft-Windows-Perflib     : Performance counter library failed to
    #                                            load — usually a corrupt perfcounter or
    #                                            low-memory condition during service start.
    #
    # IMPORTANT: Event ID 2003 is reused by MANY unrelated providers (e.g. SRTSP =
    # Symantec Antivirus minifilter load, which is purely informational). We MUST
    # filter by ProviderName so we don't raise false positives.
    # ------------------------------------------------------------
    Write-Section "Resource Exhaustion Events (last 7 days)"
    try {
        $resExhaustEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 2004
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($resExhaustEvents) {
            Write-DiagError "  FOUND $($resExhaustEvents.Count) resource exhaustion event(s) (Event 2004)!"
            Write-Info "    Description: Windows Resource-Exhaustion-Detector logged virtual"
            Write-Info "                 memory low. The OS lists top committers in each event."
            foreach ($evt in $resExhaustEvents | Select-Object -First 5) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $evt -MaxLength 120)"
            }
            Write-Info "  Remediation: Increase pagefile, add RAM, or terminate runaway committers."
        }
        else {
            Write-Success "  No resource exhaustion events (Event 2004)"
        }

        # ----- Event 333: Registry hive flush failure (paged-pool / disk pressure) -----
        $event333 = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 333
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($event333) {
            Write-DiagWarning "  Found $($event333.Count) Event 333 (registry I/O / hive flush failure)"
            Write-Info "    Description: An I/O initiated by the Registry failed unrecoverably."
            Write-Info "                 Most common cause = paged-pool exhaustion (correlates with"
            Write-Info "                 Section 9 'Paged Pool >400MB' alerts) or storage timeouts."
            foreach ($evt in $event333 | Select-Object -First 3) {
                Write-Info "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] $($evt.ProviderName) :: $(Get-EventSnippet -Event $evt -MaxLength 120)"
            }
        }
        else {
            Write-Success "  No Event 333 (registry hive flush failures)"
        }

        # ----- Event 2003: Perflib load failure (filtered to exclude AV/3rd-party noise) -----
        # Whitelist of providers whose Event 2003 actually relates to memory/perf health.
        $relevant2003Providers = @(
            'Microsoft-Windows-Perflib',
            'Perflib',
            'Microsoft-Windows-Resource-Exhaustion-Detector'
        )
        $all2003 = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 2003
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 25 -ErrorAction SilentlyContinue

        $relevant2003 = @($all2003 | Where-Object { $_.ProviderName -in $relevant2003Providers })
        $ignored2003 = @($all2003 | Where-Object { $_.ProviderName -notin $relevant2003Providers })

        if ($relevant2003.Count -gt 0) {
            Write-DiagWarning "  Found $($relevant2003.Count) Event 2003 (Perflib failures - memory-related)"
            Write-Info "    Description: Performance counter library failed to load. Often a sign"
            Write-Info "                 of low memory at service-start or a corrupt perf counter."
            foreach ($evt in $relevant2003 | Select-Object -First 3) {
                Write-Info "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] $($evt.ProviderName) :: $(Get-EventSnippet -Event $evt -MaxLength 120)"
            }
            Write-Info "  Remediation: Run 'lodctr /R' to rebuild perfcounters; investigate memory pressure."
        }
        else {
            Write-Success "  No memory-related Event 2003 (Perflib) entries"
        }

        if ($ignored2003.Count -gt 0) {
            $sources = ($ignored2003 | Group-Object ProviderName | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
            Write-Info "  (Ignored $($ignored2003.Count) unrelated Event 2003 from non-memory providers: $sources)"
            Write-Info "    Note: Event ID 2003 is reused by many components (e.g. SRTSP = Symantec"
            Write-Info "          AV minifilter load - purely informational, NOT a memory issue)."
        }
    }
    catch {
        Write-Info "  Could not query resource exhaustion events: $($_.Exception.Message)"
    }

    # 11. Working Set Trimming Rate
    # ------------------------------------------------------------
    # Counter reference:
    #   \Memory\Transition Pages RePurposed/sec
    #       Pages the Memory Manager pulled OFF a process's working set (or off
    #       standby/modified lists) and handed to a different process. A SUSTAINED
    #       high value means the OS is fighting to satisfy memory demand and is
    #       evicting pages from running processes. Common triggers: a memory-hungry
    #       process (SQL, Java, AV scan), low Available MBytes, or oversized file cache.
    #
    #   \Memory\Cache Faults/sec
    #       Page faults where the requested page was NOT in the active working set
    #       but was found in the standby cache (no disk hit yet). High values are a
    #       leading indicator that file-cache pages are being evicted frequently —
    #       usually the next stage is hard page faults to disk (real performance hit).
    #
    # Both counters are RATES (per second), so a single high spike is normal. Treat
    # sustained values across multiple samples as the real signal.
    # ------------------------------------------------------------
    Write-Section "Working Set Trimming Activity"
    try {
        $trimCounter = Get-Counter '\Memory\Transition Pages RePurposed/sec' -ErrorAction Stop
        $trimRate = [math]::Round($trimCounter.CounterSamples.CookedValue, 0)
        Write-Info "  Transition Pages Repurposed/sec: $trimRate"
        Write-Info "    Description: Rate at which the OS is pulling pages OFF process"
        Write-Info "                 working sets to satisfy other memory demands."
        if ($trimRate -gt $WS_TRIM_WARNING_THRESHOLD) {
            Write-DiagWarning "  High WS trimming rate (>$WS_TRIM_WARNING_THRESHOLD/sec) - OS is aggressively reclaiming memory"
            Write-Info "    Likely cause: Low Available MBytes, oversized file cache, or a memory-"
            Write-Info "                  hungry process (check Section 'Top 10 Memory Consuming Processes')."
            Write-Info "    Remediation: Identify top committers; add RAM; cap file cache; or"
            Write-Info "                 restart the offending service."
        }
        else {
            Write-Success "  WS trimming rate is normal (<= $WS_TRIM_WARNING_THRESHOLD/sec)"
        }

        $cacheFaults = Get-Counter '\Memory\Cache Faults/sec' -ErrorAction Stop
        $cacheFaultRate = [math]::Round($cacheFaults.CounterSamples.CookedValue, 0)
        Write-Info "  Cache Faults/sec: $cacheFaultRate"
        Write-Info "    Description: Rate of page faults satisfied from the standby cache"
        Write-Info "                 (not yet hitting disk). Leading indicator of disk paging."
        if ($cacheFaultRate -gt 5000) {
            Write-DiagWarning "  High cache fault rate (>5000/sec) - system cache is being evicted frequently"
            Write-Info "    Impact: If this continues, expect '\Memory\Pages/sec' to climb and"
            Write-Info "            disk read latency to spike (hard page faults)."
            Write-Info "    Remediation: Same as WS trimming - reduce memory pressure or add RAM."
        }
        else {
            Write-Success "  Cache fault rate is normal (<= 5000/sec)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check working set trimming: $($_.Exception.Message)"
    }

    # 12. Per-Process Private Bytes vs Working Set (top suspects)
    # ------------------------------------------------------------
    # Focused view of Section 7 - lists ONLY processes where Private Bytes
    # exceeds Working Set by >200 MB. These are the strongest leak suspects
    # because the OS has paged out a large amount of their committed memory.
    # ------------------------------------------------------------
    Write-Section "Detailed Leak Analysis (Private >> Working Set)"
    Write-Info "  Description: Processes whose Private Bytes exceeds Working Set by >200 MB."
    Write-Info "               High Gap_MB = lots of committed memory has been paged to disk."
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
            if ($tssAvailable) {
                Write-Info "Starting memory trace - You will need to manually stop with TSS.ps1 -Stop."
                Write-Info "Let trace run for 60 seconds to 3 minutes while memory is high."
                $logPath = Read-Host "Enter log folder path (e.g., D:\Data) or press Enter for default"
                if ([string]::IsNullOrWhiteSpace($logPath)) { $logPath = $script:DefaultLogPath }
                if (Test-PathValid -Path $logPath -CreateIfNotExist) {
                    if ($script:ClusterEnv.IsClusterNode -and (Test-PathOnCSV -Path $logPath -CSVPaths $script:ClusterEnv.CSVPaths)) {
                        Write-DiagWarning "WARNING: Path '$logPath' is on a Cluster Shared Volume!"
                        Write-DiagWarning "Writing large traces to CSV can cause I/O storms affecting all cluster nodes."
                        $csvConfirm = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                        if ($csvConfirm -ne "Y") { return }
                    }
                    $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
                    if ($confirm -eq "Y") {
                        Invoke-TSSCommand -Command "-Xperf Memory -XperfMaxFileMB 4096 -LogFolderPath '$logPath'"
                    }
                }
            }
            else {
                Write-DiagWarning "TSS is not available. Please install TSS (option 15) to use this trace."
                Show-PerfmonCommand "Memory"
            }
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
                        Invoke-TSSCommand -Command "-Xperf Memory -XperfMaxFileMB 4096 -StopWaitTimeInSec 300 -LogFolderPath '$logPath'"
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
                        Invoke-TSSCommand -Command "-Xperf Memory -WaitEvent HighMemory:90 -StopWaitTimeInSec 300 -LogFolderPath '$logPath'"
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
            Write-Info "  Thresholds : SCOM alert at $($CPU_WARNING_THRESHOLD)% / in-script critical at $($CPU_CRITICAL_THRESHOLD)%."

            if ($cpuPercent -gt $CPU_CRITICAL_THRESHOLD) {
                Write-DiagError "CRITICAL: CPU usage above $($CPU_CRITICAL_THRESHOLD)%! (SCOM alert at $($CPU_WARNING_THRESHOLD)%)"
            }
            elseif ($cpuPercent -gt $CPU_WARNING_THRESHOLD) {
                Write-DiagWarning "WARNING: CPU usage above $($CPU_WARNING_THRESHOLD)% - SCOM alert threshold"
            }
            else {
                Write-Success "CPU usage is within normal range (below SCOM $($CPU_WARNING_THRESHOLD)% alert)"
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
    Write-Info "  Description: CPU(s) = TOTAL CPU SECONDS the process has consumed since it"
    Write-Info "                        started. This is CUMULATIVE LIFETIME usage."
    Write-Info "                        It is NOT the same as Task Manager's 'CPU' column,"
    Write-Info "                        which shows INSTANTANEOUS percent in the last second."
    Write-Info "               A long-running service (AV, monitoring, WMI host) often shows"
    Write-Info "               thousands of CPU(s) even when the server is currently idle."
    Write-Info "               => For a real 'right-now' view, see the snapshot table below."

    if ($processAnalysis) {
        $processAnalysis.ByCPU | Format-Table Name, 
        @{Label = "CPU(s)"; Expression = { [math]::Round($_.CPU, 2) } },
        @{Label = "Memory(MB)"; Expression = { [math]::Round($_.WS / 1MB, 2) } },
        Id -AutoSize
    }

    # ------------------------------------------------------------
    # Live (instantaneous) per-process CPU% snapshot
    # ------------------------------------------------------------
    # \Process(*)\% Processor Time returns CPU% summed across ALL cores, so on a
    # 16-core box a single fully-busy thread = 100% (one core). To match Task
    # Manager's 0-100% view we divide by NumberOfLogicalProcessors.
    # The first counter sample is always 0 (counter needs an interval) so we
    # pull two samples 1 second apart and use the second one.
    # ------------------------------------------------------------
    Write-Section "Live CPU% Snapshot (current second, like Task Manager)"
    Write-Info "  Description: Instantaneous %CPU sampled over a 1-second interval, then"
    Write-Info "               normalized to total cores so 100% = the entire box is busy."
    Write-Info "               Compare against the cumulative table above to spot the"
    
    Write-Info "               difference between 'historically busy' vs 'busy right now'."
    try {
        $cores = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors
        if (-not $cores -or $cores -lt 1) { $cores = 1 }
        $samples = Get-Counter '\Process(*)\% Processor Time' -SampleInterval 1 -MaxSamples 2 -ErrorAction Stop
        # Use the SECOND sample (first is always zero for new counter sessions)
        $live = $samples[-1].CounterSamples |
            Where-Object { $_.InstanceName -and $_.InstanceName -ne '_total' -and $_.InstanceName -ne 'idle' } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.InstanceName
                    LiveCPUPct  = [math]::Round(($_.CookedValue / $cores), 1)
                }
            } |
            Where-Object { $_.LiveCPUPct -gt 0 } |
            Sort-Object LiveCPUPct -Descending |
            Select-Object -First 10

        if ($live) {
            $live | Format-Table Name, @{ Label = 'Live CPU%'; Expression = { $_.LiveCPUPct } } -AutoSize
            $top = $live | Select-Object -First 1
            if ($top.LiveCPUPct -lt 1) {
                Write-Success "  Server is currently idle (top process <1% CPU right now)"
            }
            elseif ($top.LiveCPUPct -gt 80) {
                Write-DiagWarning "  '$($top.Name)' is consuming $($top.LiveCPUPct)% CPU right now - active hotspot"
            }
            else {
                Write-Info "  Top live consumer: '$($top.Name)' at $($top.LiveCPUPct)% (normal range)"
            }
        }
        else {
            Write-Success "  No active per-process CPU usage detected (server is idle)"
        }
    }
    catch {
        Write-DiagWarning "  Could not capture live CPU snapshot: $($_.Exception.Message)"
        Write-Info "    (English Get-Counter strings required; on non-English Windows this may fail.)"
    }
    
    # Check for WMI high CPU
    # ------------------------------------------------------------
    # WmiPrvSE.exe = WMI Provider Host. There can be MULTIPLE instances running
    # (one per WMI namespace host process), so Get-Process returns an array.
    # We must iterate and aggregate, not call Round() on a collection (which
    # raises 'Cannot find an overload for Round and the argument count: 2').
    #
    # High WmiPrvSE CPU is usually caused by:
    #   - A monitoring agent running expensive WMI queries (SCOM, Datadog, etc.)
    #   - A misbehaving WMI provider DLL (look for crashes in Event Log)
    #   - Repeated polling of slow classes (Win32_PerfRawData_*, Win32_Product)
    # ------------------------------------------------------------
    try {
        $wmiProcesses = @(Get-Process -Name "WmiPrvSE" -ErrorAction SilentlyContinue)
        if ($wmiProcesses.Count -gt 0) {
            $totalWmiCPU = 0
            $maxWmiCPU = 0
            foreach ($wp in $wmiProcesses) {
                # Defensive: .CPU can be $null for protected processes
                $cpu = if ($null -ne $wp.CPU) { [double]$wp.CPU } else { 0 }
                $totalWmiCPU += $cpu
                if ($cpu -gt $maxWmiCPU) { $maxWmiCPU = $cpu }
            }
            $totalWmiCPU = [math]::Round($totalWmiCPU, 2)
            $maxWmiCPU = [math]::Round($maxWmiCPU, 2)
            Write-Info "`nWMI Provider Host (WmiPrvSE): $($wmiProcesses.Count) instance(s)"
            Write-Info "  Total CPU across instances: $totalWmiCPU seconds"
            Write-Info "  Highest single instance:    $maxWmiCPU seconds"
            Write-Info "    Description: WmiPrvSE hosts WMI providers. Multiple instances are"
            Write-Info "                 normal (one per namespace). High CPU often = a chatty"
            Write-Info "                 monitoring agent issuing expensive queries."

            # Normalize cumulative CPU seconds against system uptime. Absolute
            # threshold (e.g. 100s) trips on every server up more than a day. The
            # real signal is sustained CPU%: warn only when WmiPrvSE has consumed
            # >0.5% of a single core averaged over the system uptime window.
            $uptimeSec = 0
            try {
                $bootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime
                if ($bootTime) { $uptimeSec = [math]::Max(((Get-Date) - $bootTime).TotalSeconds, 1) }
            }
            catch { $uptimeSec = 0 }
            $sustainedPct = if ($uptimeSec -gt 0) { [math]::Round(($maxWmiCPU / $uptimeSec) * 100, 3) } else { 0 }
            if ($uptimeSec -gt 0) { Write-Info "  Sustained CPU% (avg over $([math]::Round($uptimeSec/3600,1))h uptime): $sustainedPct% of one core" }

            $isRunaway = ($maxWmiCPU -gt $WMI_CPU_WARNING_SECONDS) -and
                         (($uptimeSec -le 0) -or ($sustainedPct -gt 0.5))
            if ($isRunaway) {
                Write-DiagWarning "WMI Provider Host is consuming significant CPU time (sustained $sustainedPct% of one core)"
                Write-Info "    Likely cause: A monitoring agent (SCOM, Datadog, BMC, custom"
                Write-Info "                  scripts) is polling WMI too aggressively, OR a"
                Write-Info "                  provider DLL is misbehaving."
                Write-Info "    Diagnosis: Identify the WMI client with:"
                Write-Info "                 wmic /namespace:\\root\cimv2 path Win32_Process where 'Name=\"WmiPrvSE.exe\"' get ProcessId,CommandLine"
                Write-Info "               Then enable WMI activity logging:"
                Write-Info "                 wevtutil sl Microsoft-Windows-WMI-Activity/Trace /e:true"
                Write-Info "    Remediation: Use TSS for a focused WMI trace:"
                Write-Info "                 .\TSS.ps1 -UEX_WMIBase -WIN_Kernel -ETWflags 1 -WPR CPU -Perfmon UEX_WMIPrvSE -PerfIntervalSec 1 -noBasicLog"
            }
            elseif ($maxWmiCPU -gt $WMI_CPU_WARNING_SECONDS) {
                Write-Success "WMI Provider Host total CPU is large but rate is benign ($sustainedPct% sustained over uptime)"
            }
            else {
                Write-Success "WMI Provider Host CPU is within normal range"
            }
        }
        else {
            Write-Info "`nWMI Provider Host (WmiPrvSE): not currently running"
        }
    }
    catch {
        Write-DiagWarning "Could not check WMI process: $($_.Exception.Message)"
    }

    # Svchost.exe Breakdown (top consumers)
    # ------------------------------------------------------------
    # svchost.exe (Service Host) hosts one OR many Windows services per process.
    # On Server 2016+, services are usually 1-per-process; on 2012 R2 they share.
    # High CPU in a svchost = the SERVICE inside it is the real culprit. We map
    # PID -> hosted service names via Win32_Service.ProcessId.
    # ------------------------------------------------------------
    Write-Section "Top svchost.exe Instances by CPU"
    Write-Info "  Description: svchost hosts Windows services. CPU shown belongs to the"
    Write-Info "               service(s) inside, not svchost itself. Investigate the named service."
    try {
        $svchosts = Get-Process -Name "svchost" -ErrorAction SilentlyContinue | Sort-Object CPU -Descending | Select-Object -First 5
        foreach ($sh in $svchosts) {
            # Defensive: .CPU can be $null for protected svchost (e.g. PPL services)
            $cpuSec = if ($null -ne $sh.CPU) { [math]::Round($sh.CPU, 1) } else { 0 }
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
    # ------------------------------------------------------------
    # Common third-party monitoring agents that run as user-mode processes and
    # are notorious for CPU storms when their config is broken or they hit a bug.
    # If CPU per agent > MONITORING_AGENT_CPU_WARNING (50s by default), flag it.
    # ------------------------------------------------------------
    Write-Section "Monitoring Agent CPU Check"
    $monitoringAgents = @("MonitoringHost", "HealthService", "WinCollect", "MOMAgent")
    Write-Info "  Description: Checks well-known monitoring agents (SCOM, QRadar, etc.)"
    Write-Info "               for runaway CPU. These agents commonly storm during config errors."
    try {
        $foundAny = $false
        foreach ($agent in $monitoringAgents) {
            $procs = Get-Process -Name $agent -ErrorAction SilentlyContinue
            if ($procs) {
                $foundAny = $true
                foreach ($p in $procs) {
                    # Defensive: .CPU can be $null for protected processes
                    $cpuSec = if ($null -ne $p.CPU) { [math]::Round($p.CPU, 1) } else { 0 }
                    if ($cpuSec -gt $MONITORING_AGENT_CPU_WARNING) {
                        Write-DiagWarning "  $($p.Name) (PID $($p.Id)): CPU=${cpuSec}s - monitoring agent CPU storm"
                        Write-Info "      Remediation: Restart the agent service; check its config"
                        Write-Info "                   for invalid rules; review agent vendor logs."
                    }
                    else {
                        Write-Info "  $($p.Name) (PID $($p.Id)): CPU=${cpuSec}s"
                    }
                }
            }
        }
        if (-not $foundAny) {
            Write-Info "  No common monitoring agents detected on this server"
        }
    }
    catch {
        Write-Verbose "Could not check monitoring agents: $($_.Exception.Message)"
    }

    # Java.exe High CPU
    # ------------------------------------------------------------
    # Java processes running as services (Tomcat, Elasticsearch, custom apps) are
    # frequent CPU offenders due to GC storms or runaway threads. We sum CPU per
    # PID and flag instances over JAVA_CPU_WARNING_SECONDS.
    # ------------------------------------------------------------
    try {
        $javaProcs = Get-Process -Name "java" -ErrorAction SilentlyContinue
        if ($javaProcs) {
            Write-Section "Java Process CPU Check"
            Write-Info "  Description: Java apps with high CPU often = GC pressure or hot threads."
            Write-Info "               Capture a thread dump (jstack <PID>) for root cause."
            foreach ($jp in $javaProcs) {
                # Defensive: .CPU can be $null for protected processes
                $cpuSec = if ($null -ne $jp.CPU) { [math]::Round($jp.CPU, 1) } else { 0 }
                $memMB = [math]::Round($jp.WorkingSet64 / 1MB, 0)
                if ($cpuSec -gt $JAVA_CPU_WARNING_SECONDS) {
                    Write-DiagWarning "  java.exe (PID $($jp.Id)): CPU=${cpuSec}s Mem=${memMB}MB - high CPU"
                    Write-Info "      Remediation: Run 'jstack $($jp.Id) > thread-dump.txt' to capture"
                    Write-Info "                   thread state; look for BLOCKED/RUNNABLE patterns."
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
    # ------------------------------------------------------------
    # Split I/O = a single I/O request that the storage stack had to break into
    # multiple physical requests because the data is non-contiguous on disk.
    # Sustained high values mean fragmentation is forcing extra CPU cycles per I/O.
    # ------------------------------------------------------------
    Write-Section "Split I/O Check"
    Write-Info "  Description: Split I/O = one logical I/O fragmented into multiple physical"
    Write-Info "               I/Os due to non-contiguous data placement. Each split adds CPU."
    try {
        $splitIO = Get-Counter '\PhysicalDisk(_Total)\Split IO/sec' -ErrorAction Stop
        $splitRate = [math]::Round($splitIO.CounterSamples.CookedValue, 0)
        Write-Info "  Split IO/sec: $splitRate"
        if ($splitRate -gt $SPLIT_IO_WARNING_THRESHOLD) {
            Write-DiagWarning "  HIGH Split I/O ($splitRate/sec) - storage fragmentation may be causing extra CPU load"
            Write-Info "    Likely cause: Heavily fragmented volume, or workload doing large"
            Write-Info "                  non-aligned reads (databases, logs, video)."
            Write-Info "    Remediation: For HDDs run 'defrag C: /A' to assess fragmentation,"
            Write-Info "                 then 'defrag C: /O' to optimize. SSDs do NOT need defrag."
            Write-Info "                 Also align partitions to 1 MB and ensure 64 KB NTFS"
            Write-Info "                 cluster size for SQL/DB workloads."
        }
        else {
            Write-Success "  Split I/O rate is within normal range"
        }
    }
    catch {
        Write-DiagWarning "  Could not check Split I/O"
    }

    # SQL AG Replication Counters (v3.0 cluster-safe)
    # ------------------------------------------------------------
    # On SQL AlwaysOn Availability Group nodes, replication backlog drives CPU on
    # the primary (compressing+sending log) and on the secondary (redoing log).
    # Log Send Queue and Redo Queue are the two canonical AG-lag counters.
    # ------------------------------------------------------------
    if ($script:ClusterEnv.IsAGInstalled) {
        Write-Section "SQL AG Replication Health"
        Write-Info "  Description: Log Send Queue = primary->secondary backlog (KB)."
        Write-Info "               Redo Queue = secondary applying received log (KB)."
        Write-Info "               >10 MB sustained = replication lag impacting failover RTO."
        try {
            $sendQueue = Get-Counter '\SQLServer:Database Replica(*)\Log Send Queue' -ErrorAction Stop
            foreach ($sample in $sendQueue.CounterSamples) {
                if ($sample.InstanceName -ne "_total" -and $sample.CookedValue -gt 0) {
                    $queueKB = [math]::Round($sample.CookedValue, 0)
                    Write-Info "  $($sample.InstanceName): Log Send Queue = $queueKB KB"
                    if ($queueKB -gt 10240) {
                        Write-DiagWarning "    Log send queue >10 MB - AG replication lag"
                        Write-Info "      Likely cause: Network bandwidth saturation between replicas,"
                        Write-Info "                    or primary log generation > network throughput."
                        Write-Info "      Remediation: Check network latency/throughput between nodes;"
                        Write-Info "                   verify endpoint encryption isn't a CPU bottleneck."
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
                        Write-DiagWarning "    Redo queue >10 MB - secondary applying changes slowly"
                        Write-Info "      Likely cause: Secondary disk I/O bottleneck or contention"
                        Write-Info "                    from read-only workload on the secondary."
                        Write-Info "      Remediation: Check disk latency on secondary; reduce read"
                        Write-Info "                   workload; ensure redo threads aren't blocked."
                    }
                }
            }
        }
        catch { }
    }

    #region v3.0 CPU Checks

    # 1. Per-Core CPU Usage
    # ------------------------------------------------------------
    # Aggregate %CPU can look healthy (e.g. 12% on a 16-core box) while a SINGLE
    # core is pinned at 100%. That's a single-threaded bottleneck - typical of
    # a hot SQL query, a .NET app holding a lock, or a service pinned via
    # ProcessorAffinity. Per-core view is the only way to spot this.
    # ------------------------------------------------------------
    Write-Section "Per-Core CPU Usage"
    Write-Info "  Description: Per-core %CPU. Aggregate CPU can hide a single 'hot' core"
    Write-Info "               pinned at 100% - the classic single-threaded bottleneck signature."
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
            Write-Info "    Likely cause: Single-threaded bottleneck (SQL query plan with a"
            Write-Info "                  blocking serial operator, .NET app on lock, or process"
            Write-Info "                  with restricted ProcessorAffinity - see Section 15)."
            Write-Info "    Remediation: Identify pinned process (Live CPU% Snapshot above);"
            Write-Info "                 review SQL plan for parallelism settings (MAXDOP);"
            Write-Info "                 check process affinity with 'Get-Process | select Name,Id,ProcessorAffinity'."
        }
        else {
            Write-Success "  No hot cores detected ($coreCount cores, all below 95%)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check per-core CPU usage"
    }

    # 2. Privileged vs User Time
    # ------------------------------------------------------------
    # %CPU is split into Kernel (Privileged) and Application (User) time.
    #   Privileged > 30%      = something in the kernel is burning cycles. Almost
    #                           always a driver: storage filter, NIC, AV/EDR.
    #   User > Privileged     = normal for application servers (SQL, IIS, Java).
    #   Privileged > User     = abnormal - investigate drivers and OS subsystems.
    # ------------------------------------------------------------
    Write-Section "Privileged vs User Time"
    Write-Info "  Description: %CPU split between kernel-mode (drivers, OS) and user-mode"
    Write-Info "               (applications). Kernel > 30% almost always = a driver issue."
    try {
        $privTime = Get-Counter '\Processor(_Total)\% Privileged Time' -ErrorAction Stop
        $userTime = Get-Counter '\Processor(_Total)\% User Time' -ErrorAction Stop
        $privPercent = [math]::Round($privTime.CounterSamples.CookedValue, 1)
        $userPercent = [math]::Round($userTime.CounterSamples.CookedValue, 1)
        Write-Info "  Kernel (Privileged): $privPercent%"
        Write-Info "  Application (User):  $userPercent%"
        if ($privPercent -gt 30) {
            Write-DiagWarning "  HIGH kernel time (>30%) - investigate storage drivers, NIC drivers, or antivirus filter drivers"
            Write-Info "    Likely cause: AV/EDR filter driver scanning every I/O, a buggy NIC"
            Write-Info "                  driver doing excessive interrupt handling, or storage"
            Write-Info "                  filter (deduplication, encryption) on the I/O path."
            Write-Info "    Diagnosis: Use 'xperf -on PROC_THREAD+LOADER+DPC+INTERRUPT -stackwalk DPC+INTERRUPT'"
            Write-Info "               (Windows Performance Toolkit) for 30 seconds and analyze in WPA."
            Write-Info "    Remediation: Update suspect drivers; review AV exclusions for hot paths;"
            Write-Info "                 check 'fltmc' to enumerate active filter drivers."
        }
        elseif ($privPercent -gt $userPercent -and $privPercent -gt 15) {
            Write-DiagWarning "  Kernel time exceeds User time - driver or OS subsystem issue likely"
        }
        else {
            Write-Success "  Normal kernel/user time ratio"
        }
    }
    catch {
        Write-DiagWarning "  Could not check privileged/user time split"
    }

    # 3. Processor Queue Length
    # ------------------------------------------------------------
    # \System\Processor Queue Length = number of threads READY to run but waiting
    # for a CPU to become available. Sustained queue > 2x logical processors =
    # CPU saturation: workload exceeds capacity. This is the canonical 'CPU
    # bottleneck' signal even when total %CPU looks fine.
    # ------------------------------------------------------------
    Write-Section "Processor Queue Length"
    Write-Info "  Description: # of threads waiting in line for a CPU. Threshold = 2 x cores."
    Write-Info "               Sustained excess = CPU saturation (workload > capacity)."
    try {
        $queueLen = Get-Counter '\System\Processor Queue Length' -ErrorAction Stop
        $queue = [math]::Round($queueLen.CounterSamples.CookedValue, 0)
        $logicalProcs = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        $threshold = if ($logicalProcs) { $logicalProcs * 2 } else { 4 }
        Write-Info "  Queue Length: $queue (threshold: $threshold for $logicalProcs logical processors)"
        if ($queue -gt $threshold) {
            Write-DiagError "  Processor queue length $queue > ${threshold} - threads are waiting for CPU (critical)"
            Write-Info "    Impact: User-perceived response time is degrading. Every queued"
            Write-Info "            thread is one user/transaction stalled."
            Write-Info "    Remediation: Reduce concurrent workload, scale out, add CPU capacity,"
            Write-Info "                 or move CPU-heavy services to a different host."
        }
        elseif ($queue -gt ($logicalProcs)) {
            Write-DiagWarning "  Queue length elevated ($queue) - approaching CPU saturation"
        }
        else {
            Write-Success "  Processor queue length is healthy"
        }
    }
    catch {
        Write-DiagWarning "  Could not check processor queue length"
    }

    # 4. Context Switches/sec
    # ------------------------------------------------------------
    # Context switch = the kernel saves one thread's state and loads another.
    # Some switching is normal. >15K/core/sec sustained = thread thrashing,
    # often due to: too many threads vying for too few cores, lock contention,
    # or a hypervisor with oversubscribed vCPUs (very common on VMs).
    # ------------------------------------------------------------
    Write-Section "Context Switches"
    Write-Info "  Description: Rate of thread context switches. Per-core thresholds:"
    Write-Info "               > 8K/core = monitor for lock contention"
    Write-Info "               > 15K/core = thread thrashing or hypervisor oversubscription"
    try {
        $ctxSwitches = Get-Counter '\System\Context Switches/sec' -ErrorAction Stop
        $ctxRate = [math]::Round($ctxSwitches.CounterSamples.CookedValue, 0)
        $perCoreRate = if ($logicalProcs -and $logicalProcs -gt 0) { [math]::Round($ctxRate / $logicalProcs, 0) } else { $ctxRate }
        Write-Info "  Context Switches/sec: $ctxRate (${perCoreRate}/core)"
        if ($perCoreRate -gt 15000) {
            Write-DiagWarning "  HIGH context switching (>15K/core) - thread contention, excessive threads, or hypervisor scheduling"
            Write-Info "    Likely cause: Too many runnable threads (check 'System Threads' below),"
            Write-Info "                  lock contention, or VM running on oversubscribed host."
            Write-Info "    Remediation: Reduce thread pool sizes; check for spinlock contention"
            Write-Info "                 with WPA; if VM, verify host CPU ratio is < 4:1."
        }
        elseif ($perCoreRate -gt 8000) {
            Write-DiagWarning "  Elevated context switching (>8K/core) - monitor for lock contention"
        }
        else {
            Write-Success "  Context switch rate is normal"
        }
    }
    catch {
        Write-DiagWarning "  Could not check context switches"
    }

    # 5. Interrupt & DPC Time
    # ------------------------------------------------------------
    # %Interrupt Time = CPU spent servicing hardware interrupts (NIC RX, disk IRQ).
    # %DPC Time       = CPU spent in Deferred Procedure Calls (driver follow-up
    #                    work scheduled from interrupt context).
    # Both are KERNEL-MODE work driven by drivers. > 15% sustained = a driver is
    # in trouble (NIC firmware bug, storage driver issue, or storm of interrupts).
    # On Hyper-V hosts, vmswitch and storage VSPs are common offenders.
    # ------------------------------------------------------------
    Write-Section "Interrupt & DPC Time"
    Write-Info "  Description: %CPU spent in hardware interrupts and driver DPCs. High"
    Write-Info "               values = a driver (usually NIC or storage) is misbehaving."
    try {
        $intTime = Get-Counter '\Processor(_Total)\% Interrupt Time' -ErrorAction Stop
        $dpcTime = Get-Counter '\Processor(_Total)\% DPC Time' -ErrorAction Stop
        $intPercent = [math]::Round($intTime.CounterSamples.CookedValue, 2)
        $dpcPercent = [math]::Round($dpcTime.CounterSamples.CookedValue, 2)
        Write-Info "  Interrupt Time: $intPercent%"
        Write-Info "  DPC Time: $dpcPercent%"
        if ($intPercent -gt 15 -or $dpcPercent -gt 15) {
            Write-DiagError "  High interrupt/DPC time - NIC driver, storage driver, or hardware issue (critical)"
            Write-Info "    Impact: All other CPU work competes with driver work. User-mode"
            Write-Info "            apps (SQL, IIS) get less CPU even at moderate %CPU figures."
            Write-Info "    Diagnosis: Use 'xperf -on Base+Interrupt+DPC -stackwalk DPC+ISR'"
            Write-Info "               for 30 seconds; analyze top DPC modules in WPA."
            Write-Info "               On Hyper-V hosts also check vmswitch and storage VSPs."
            Write-Info "    Remediation: Update NIC and storage drivers; enable RSS on NIC;"
            Write-Info "                 check NIC firmware advisories; if VM, ensure SR-IOV"
            Write-Info "                 or VMQ is correctly configured on the host."
        }
        elseif ($intPercent -gt 5 -or $dpcPercent -gt 5) {
            Write-DiagWarning "  Elevated interrupt/DPC time - investigate NIC RSS settings and storage drivers"
        }
        else {
            Write-Success "  Interrupt and DPC time are normal"
        }
    }
    catch {
        Write-DiagWarning "  Could not check interrupt/DPC time"
    }

    # 6. System Uptime & Last Boot
    # ------------------------------------------------------------
    # Long uptime is a double-edged sword: stable, but accumulates kernel timer
    # drift, memory fragmentation, leaked pool/handles, and unpatched OS bugs.
    # > 90 days   : schedule a maintenance reboot
    # > 180 days  : critical - kernel timer drift and resource leaks become real
    # ------------------------------------------------------------
    Write-Section "System Uptime"
    Write-Info "  Description: Days since last boot. Long uptime = unpatched kernel CVEs,"
    Write-Info "               accumulated leaked pool/handles, and possible timer drift."
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $uptime = (Get-Date) - $os.LastBootUpTime
        Write-Info "  Last Boot: $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        Write-Info "  Uptime: $($uptime.Days) days, $($uptime.Hours) hours"
        if ($uptime.TotalDays -gt 180) {
            Write-DiagError "  Server running for $([math]::Round($uptime.TotalDays, 0)) days - kernel timer drift and memory fragmentation risk"
            Write-Info "    Remediation: Schedule a maintenance reboot. Apply pending Windows"
            Write-Info "                 Updates first, then reboot to clear kernel/pool state."
        }
        elseif ($uptime.TotalDays -gt 90) {
            Write-DiagWarning "  Server running for $([math]::Round($uptime.TotalDays, 0)) days - consider scheduling maintenance reboot"
        }
        else {
            Write-Success "  Uptime is within healthy range"
        }
    }
    catch {
        Write-DiagWarning "  Could not check system uptime"
    }

    # 7. Power Throttling Detection
    # ------------------------------------------------------------
    # \Processor Information(_Total)\% Processor Performance = current clock as %
    # of nominal max. < 95% means the CPU is NOT running at full speed. Causes:
    #   - Power plan = Balanced/PowerSaver (most common, easiest fix)
    #   - Thermal throttling (server overheating - check IPMI/iLO/iDRAC)
    #   - VM host CPU overcommit (hypervisor capping vCPU clock)
    #   - Intel SpeedStep / AMD Cool'n'Quiet aggressive scaling
    # ------------------------------------------------------------
    Write-Section "CPU Power Throttling"
    Write-Info "  Description: Current CPU clock as % of nominal max. <95% = throttled."
    Write-Info "               Causes: power plan, thermal limits, or hypervisor overcommit."
    try {
        $perfPercent = Get-Counter '\Processor Information(_Total)\% Processor Performance' -ErrorAction Stop
        $perfVal = [math]::Round($perfPercent.CounterSamples.CookedValue, 1)
        Write-Info "  Processor Performance: $perfVal%"
        if ($perfVal -lt 80) {
            Write-DiagError "  CPU THROTTLED to $perfVal% - check power plan, thermal throttling, or VM host overcommit"
            Write-Info "    Impact: Effectively running on slower CPU - all latency-sensitive"
            Write-Info "            workloads (SQL, IIS, AD) will appear sluggish."
            Write-Info "    Remediation: Set power plan to High Performance:"
            Write-Info "                 powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
            Write-Info "                 Then check BIOS power profile (set to 'Max Performance'),"
            Write-Info "                 and verify server intake temp via iLO/iDRAC/IPMI."
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
    # ------------------------------------------------------------
    # Modern AV/EDR is the #1 source of mysterious CPU on enterprise servers.
    # Each agent registers a file system filter driver (high altitude) that sees
    # every I/O. Misconfigured exclusions cause it to scan the same hot files
    # repeatedly. Symantec ccSvcHst, CrowdStrike CSFalconService, Defender
    # MsMpEng are the usual suspects.
    # ------------------------------------------------------------
    Write-Section "Antivirus & Security Agent CPU"
    Write-Info "  Description: Per-agent cumulative CPU. >300s consistently = a scan loop or"
    Write-Info "               missing exclusion (DB files, log dirs, IIS temp paths)."
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
        $highCpuFound = $false
        foreach ($av in $avProcesses) {
            $procs = Get-Process -Name $av.Name -ErrorAction SilentlyContinue
            if ($procs) {
                $avFound = $true
                foreach ($p in $procs) {
                    # Defensive: .CPU can be $null for protected AV processes (PPL)
                    $cpuSec = if ($null -ne $p.CPU) { [math]::Round($p.CPU, 1) } else { 0 }
                    $memMB = [math]::Round($p.WorkingSet64 / 1MB, 0)
                    $indicator = ""
                    if ($cpuSec -gt 300) {
                        $indicator = " [HIGH CPU - investigate exclusions]"
                        $highCpuFound = $true
                    }
                    Write-Info "  $($av.Label) ($($p.Name), PID $($p.Id)): CPU=${cpuSec}s Mem=${memMB}MB$indicator"
                }
            }
        }
        if ($highCpuFound) {
            Write-Info "    Remediation: Review exclusions per vendor + Microsoft guidance:"
            Write-Info "                 - SQL data/log files and tempdb"
            Write-Info "                 - IIS log + temp directories"
            Write-Info "                 - Cluster CSV mount points"
            Write-Info "                 - Backup staging folders"
            Write-Info "                 Also disable on-access scanning of pagefile.sys."
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
    # ------------------------------------------------------------
    # On Hyper-V hosts, %Total Run Time = combined guest + hypervisor activity.
    # %Hypervisor Run Time alone (>5%) means the host kernel is spending notable
    # cycles on hypervisor work itself - typically NUMA spanning, too many vCPUs
    # per LP, or root-partition driver overhead. This is invisible inside guests.
    # ------------------------------------------------------------
    Write-Section "Hyper-V Hypervisor Overhead"
    Write-Info "  Description: On a Hyper-V host, this shows what % of CPU is consumed by"
    Write-Info "               the hypervisor itself vs guest VMs. >5% overhead = problem."
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
                        Write-DiagWarning "  HIGH hypervisor overhead (>5%) - too many VMs or NUMA misconfiguration"
                        Write-Info "    Likely cause: Too many vCPUs per logical processor, NUMA spanning,"
                        Write-Info "                  or a chatty integration component (KVP, Heartbeat)."
                        Write-Info "    Remediation: Review VM:LP ratio (target <= 4:1 for balanced load),"
                        Write-Info "                 align VMs to NUMA nodes, disable unused integration"
                        Write-Info "                 services on idle VMs."
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
    # ------------------------------------------------------------
    # Wider-window companion to the 'Live CPU% Snapshot' above. Samples
    # TotalProcessorTime per process at T+0 and T+5s, then computes the delta.
    # Catches bursty processes that the 1-second snapshot might miss.
    # NOTE: ApproxPct is % of ONE core (not normalized) - a value > 100 means
    # the process used multiple cores during the sample window.
    # ------------------------------------------------------------
    Write-Section "Real-Time Process CPU (5-second sample)"
    Write-Info "  Description: Wider-window CPU sampler. ApproxPct = % of ONE core averaged"
    Write-Info "               over 5s; values > 100% indicate multi-core usage in the window."
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
                        Name      = $p2.Name
                        PID       = $p2.Id
                        DeltaMs   = [math]::Round($cpuDelta, 0)
                        ApproxPct = $cpuPctApprox
                    }
                }
            }
        }
        $topDelta = $delta | Sort-Object DeltaMs -Descending | Select-Object -First 10
        if ($topDelta) {
            Write-Info "  Top 10 processes by CURRENT CPU usage (last 5s):"
            foreach ($td in $topDelta) {
                Write-Info "    $($td.Name) (PID $($td.PID)): $($td.DeltaMs)ms (~$($td.ApproxPct)% of 1 core)"
            }
        }
        else {
            Write-Success "  No processes consumed measurable CPU in the 5-second window"
        }
    }
    catch {
        Write-DiagWarning "  Could not perform real-time CPU sampling"
    }

    # 11. System Threads & Process Count
    # ------------------------------------------------------------
    # Healthy server: typically < 2000 threads, < 200 processes.
    # Thread count > 5000 = approaching the kernel's per-process and per-system
    # thread quotas. Often caused by a thread-pool leak in a .NET / Java service.
    # Process count > 500 = runaway scheduled tasks or a service forking subprocs.
    # ------------------------------------------------------------
    Write-Section "System Thread & Process Count"
    Write-Info "  Description: System-wide thread + process totals. Excessive counts ="
    Write-Info "               a service is leaking threads or spawning runaway children."
    try {
        $sysThreads = Get-Counter '\System\Threads' -ErrorAction Stop
        $sysProcesses = Get-Counter '\System\Processes' -ErrorAction Stop
        $threadCount = [math]::Round($sysThreads.CounterSamples.CookedValue, 0)
        $processCount = [math]::Round($sysProcesses.CounterSamples.CookedValue, 0)
        Write-Info "  Total Threads: $threadCount"
        Write-Info "  Total Processes: $processCount"
        if ($threadCount -gt 5000) {
            Write-DiagWarning "  HIGH thread count ($threadCount) - approaching kernel resource limits"
            Write-Info "    Remediation: Cross-reference 'Top Processes by Thread Count' from the"
            Write-Info "                 Memory section to identify the leaker; restart that service."
        }
        if ($processCount -gt 500) {
            Write-DiagWarning "  HIGH process count ($processCount) - investigate runaway services or scheduled tasks"
            Write-Info "    Remediation: Run 'Get-Process | Group-Object Name | Sort-Object Count -Descending'"
            Write-Info "                 to find processes with many instances; check Task Scheduler."
        }
        if ($threadCount -le 5000 -and $processCount -le 500) {
            Write-Success "  Thread and process counts are within healthy range"
        }
    }
    catch {
        Write-DiagWarning "  Could not check system thread/process counts"
    }

    # 12. DPC Queue Rate
    # ------------------------------------------------------------
    # DPCs Queued/sec = how often drivers are deferring work from interrupt
    # context. Normal values are usually < 1000 per core. > 5000/core sustained
    # indicates a driver storm - often a NIC under heavy traffic or a storage
    # adapter with a misconfigured queue depth.
    # ------------------------------------------------------------
    Write-Section "DPC Queue Rate"
    Write-Info "  Description: Rate at which drivers queue Deferred Procedure Calls."
    Write-Info "               Companion metric to '%DPC Time' - tracks the FREQUENCY"
    Write-Info "               of driver follow-up work, not the cycles consumed."
    try {
        $dpcQueued = Get-Counter '\Processor(_Total)\DPCs Queued/sec' -ErrorAction Stop
        $dpcRate = [math]::Round($dpcQueued.CounterSamples.CookedValue, 0)
        Write-Info "  DPCs Queued/sec: $dpcRate"
        $perCoreDPC = if ($logicalProcs -and $logicalProcs -gt 0) { [math]::Round($dpcRate / $logicalProcs, 0) } else { $dpcRate }
        Write-Info "  Per-core DPC rate: $perCoreDPC/sec"
        if ($perCoreDPC -gt 5000) {
            Write-DiagWarning "  HIGH DPC rate (>5K/core) - NIC or storage driver processing bottleneck"
            Write-Info "    Likely cause: NIC under heavy traffic without RSS, storage HBA queue"
            Write-Info "                  depth too small, or AV driver intercepting every I/O."
            Write-Info "    Remediation: Enable RSS on NIC (Set-NetAdapterRss); raise storport"
            Write-Info "                 queue depth; capture xperf trace to identify top driver."
        }
        else {
            Write-Success "  DPC queue rate is normal"
        }
    }
    catch {
        Write-DiagWarning "  Could not check DPC queue rate"
    }

    # 13. NUMA Node Imbalance
    # ------------------------------------------------------------
    # NUMA = Non-Uniform Memory Access. On multi-socket servers each CPU has
    # its own attached memory bank ('local'). Accessing the OTHER socket's
    # memory ('remote') costs 1.5-2x more cycles. If processes are pinned
    # to one node but use memory on another, you pay this penalty silently.
    # >20% memory imbalance between nodes = NUMA-unaware workload placement.
    # ------------------------------------------------------------
    Write-Section "NUMA Node Analysis"
    Write-Info "  Description: Memory distribution across NUMA nodes. Imbalance = some"
    Write-Info "               processes are using REMOTE memory (1.5-2x slower than local)."
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
                    Write-Info "    Likely cause: Workload not NUMA-aware. SQL Server, IIS app pools,"
                    Write-Info "                  and Hyper-V VMs need explicit NUMA configuration."
                    Write-Info "    Remediation: For SQL Server set 'soft-NUMA' or align affinity;"
                    Write-Info "                 for IIS use 'Enable NUMA' in app pool advanced settings;"
                    Write-Info "                 for Hyper-V align VM size to a single NUMA node when possible."
                }
                else {
                    Write-Success "  NUMA memory balanced (${imbalance}% difference)"
                }
            }
        }
        elseif ($nodeData.Count -eq 1) {
            Write-Info "  Single NUMA node ($($nodeData[0].TotalMB) MB) - no imbalance possible"
        }
    }
    catch {
        Write-Info "  NUMA counters not available (single-socket system or counters disabled)"
    }

    # 14. CPU-Related Event Log Entries
    # ------------------------------------------------------------
    # Event ID reference (CPU/hardware related):
    #   17  - WHEA-Logger : Machine check exception (severe CPU error)
    #   19  - WHEA-Logger : Corrected hardware error (CPU/memory ECC corrected)
    #   47  - WHEA-Logger : Fatal hardware error (CPU/memory uncorrected)
    # WHEA = Windows Hardware Error Architecture. Even 'corrected' errors mean
    # silicon is degrading - Event 19 today often becomes Event 47 tomorrow.
    # ------------------------------------------------------------
    Write-Section "CPU-Related Events (last 7 days)"
    Write-Info "  Description: WHEA hardware errors + processor power events. WHEA = early"
    Write-Info "               warning that CPU/memory/PCIe silicon is degrading."
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
            Write-Info "    Impact: Hardware is degrading. Corrected errors today predict"
            Write-Info "            uncorrected errors (BSOD) tomorrow. Schedule diagnostics."
            Write-Info "    Remediation: Open vendor case (Dell SupportAssist, HPE ActiveHealth);"
            Write-Info "                 run BIOS-level CPU/memory diagnostics from iLO/iDRAC;"
            Write-Info "                 plan hardware replacement if correlations point to one DIMM/CPU."
        }
        else {
            Write-Success "  No WHEA hardware errors"
        }

        # ----- Kernel-Processor-Power events (filtered to exclude informational noise) -----
        # ------------------------------------------------------------
        # IMPORTANT: Microsoft-Windows-Kernel-Processor-Power emits MANY purely
        # informational events at every boot. We MUST split by Event ID to avoid
        # false positives.
        #
        #   Informational (fires every boot, IGNORE):
        #     55  - Processor capability enumeration (one event per logical proc).
        #           "Processor X in group 0 exposes the following power management
        #           capabilities". Max/Min perf % = 100 means CPU LOCKED AT FULL SPEED.
        #     56  - Idle state info / power source change announcement.
        #    100  - Power source change (AC/DC) — not relevant on servers.
        #    101  - Power source change details.
        #
        #   Noteworthy (actual throttle / parking events):
        #     35  - Processor parked
        #     37  - Processor performance throttle
        #     38  - Processor performance state change
        #     39  - Processor performance throttle ceiling lowered
        #    121  - Throttling has occurred (thermal or PPM)
        #    125  - Processor performance state lowered (sustained)
        # ------------------------------------------------------------
        $infoOnlyKpp = @(55, 56, 100, 101)
        $noteworthyKpp = @(35, 37, 38, 39, 121, 125)
        $allKppEvents = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'
            StartTime    = (Get-Date).AddDays(-7)
        } -MaxEvents 50 -ErrorAction SilentlyContinue

        if ($allKppEvents) {
            $noteworthyEvents = @($allKppEvents | Where-Object { $noteworthyKpp -contains $_.Id })
            $infoEvents       = @($allKppEvents | Where-Object { $infoOnlyKpp   -contains $_.Id })
            $otherEvents      = @($allKppEvents | Where-Object { ($noteworthyKpp + $infoOnlyKpp) -notcontains $_.Id })

            if ($noteworthyEvents.Count -gt 0) {
                Write-DiagWarning "  Processor power/throttle events: $($noteworthyEvents.Count)"
                Write-Info "    Description: Actual throttle or parking events. Frequent occurrences ="
                Write-Info "                 inadequate cooling or aggressive power saving"
                Write-Info "                 (see 'CPU Power Throttling' section above)."
                $noteworthyEvents | Select-Object -First 3 | ForEach-Object {
                    Write-Info "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] ID:$($_.Id) $(Get-EventSnippet -Event $_ -MaxLength 100)"
                }
            }
            else {
                Write-Success "  No processor throttling or parking events"
            }

            if ($infoEvents.Count -gt 0) {
                $idSummary = ($infoEvents | Group-Object Id | ForEach-Object { "ID:$($_.Name)=$($_.Count)" }) -join ', '
                Write-Info "  ($($infoEvents.Count) informational Kernel-Processor-Power events: $idSummary"
                Write-Info "   - capability enumeration / power source notes; fires at every boot, not a problem)"
            }
            if ($otherEvents.Count -gt 0) {
                $otherSummary = ($otherEvents | Group-Object Id | ForEach-Object { "ID:$($_.Name)=$($_.Count)" }) -join ', '
                Write-Info "  (Other Kernel-Processor-Power events: $otherSummary — not classified)"
            }
        }
        else {
            Write-Success "  No processor power events"
        }
    }
    catch {
        Write-Info "  Could not query CPU-related events"
    }

    # 15. Process CPU Affinity Check
    # ------------------------------------------------------------
    # Default: every process can use every logical processor (full affinity mask).
    # If a process has been deliberately PINNED to a subset of cores (via
    # ProcessorAffinity, 'start /affinity', or service config), it artificially
    # caps its own CPU - even when other cores are idle. Common with legacy apps,
    # licensing workarounds, or accidentally-set values that nobody remembers.
    # ------------------------------------------------------------
    Write-Section "Process CPU Affinity"
    Write-Info "  Description: Lists processes pinned to a SUBSET of cores. Restricted"
    Write-Info "               affinity caps CPU even when other cores are idle."
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
            Write-Info "    Likely cause: Service configured with explicit affinity, legacy"
            Write-Info "                  licensing constraint, or 'start /affinity' invocation."
            Write-Info "    Remediation: Reset affinity via Task Manager > Details > right-click"
            Write-Info "                 process > Set Affinity > All Processors. For services,"
            Write-Info "                 review service binary path and registry ImagePath."
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
            if ($tssAvailable) {
                Write-Info "Starting CPU trace - You can manually stop with TSS.ps1 -Stop."
                Write-Info "Run for 60 seconds to 3 minutes while CPU is high (>88%)."
                $logPath = Read-Host "Enter log folder path (e.g., D:\Data) or press Enter for default"
                if ([string]::IsNullOrWhiteSpace($logPath)) { $logPath = $script:DefaultLogPath }
                if (Test-PathValid -Path $logPath -CreateIfNotExist) {
                    if ($script:ClusterEnv.IsClusterNode -and (Test-PathOnCSV -Path $logPath -CSVPaths $script:ClusterEnv.CSVPaths)) {
                        Write-DiagWarning "WARNING: Path '$logPath' is on a Cluster Shared Volume!"
                        Write-DiagWarning "Writing large traces to CSV can cause I/O storms affecting all cluster nodes."
                        $csvConfirm = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                        if ($csvConfirm -ne "Y") { return }
                    }
                    $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
                    if ($confirm -eq "Y") {
                        Invoke-TSSCommand -Command "-Xperf CPU -XperfMaxFileMB 4096 -LogFolderPath '$logPath'"
                    }
                }
            }
            else {
                Write-DiagWarning "TSS is not available. Please install TSS (option 15) to use this trace."
                Show-PerfmonCommand "CPU"
            }
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
                        Invoke-TSSCommand -Command "-Xperf CPU -XperfMaxFileMB 4096 -StopWaitTimeInSec 300 -LogFolderPath '$logPath'"
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
        Checks physical disks, logical disk space, latency, cluster size, IOPS, throughput,
        media type, SMART health, VSS snapshots, Storage Spaces, fragmentation, pagefile
        placement, filter drivers, MPIO, ReFS/NTFS, disk busy time, and storage tiering
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
    # ------------------------------------------------------------
    # Free space below 20% triggers performance degradation:
    # - NTFS becomes more fragmented (file allocations bounce around)
    # - VSS snapshots may auto-delete to make room
    # - VMs running on this volume can pause-critical at 100% full
    # - SQL Server autogrow events become slow & blocking
    # ------------------------------------------------------------
    Write-Section "Logical Disk Space"
    Write-Info "  Description: Free-space % per drive. SCOM alert thresholds:"
    Write-Info "               System drive ($($DISK_SYSTEM_WARNING_THRESHOLD)% used) | Non-system drive ($($DISK_NONSYSTEM_WARNING_THRESHOLD)% used)."
    Write-Info "               In-script CRITICAL fires at $($DISK_SYSTEM_CRITICAL_THRESHOLD)% used (above SCOM)."
    if ($cachedVolumes) {
        # System drive identified once via $env:SystemDrive (handles non-C: OS installs).
        $systemDriveLetter = ($env:SystemDrive -replace ':', '').Trim()
        foreach ($vol in $cachedVolumes) {
            if ($vol.Size -le 0) { continue }
            # Skip mount-point-only volumes / volumes without a drive letter.
            if (-not $vol.DriveLetter) { continue }

            $usedSpace = $vol.Size - $vol.SizeRemaining
            $usedPercent = [math]::Round(($usedSpace / $vol.Size) * 100, 2)
            $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)

            $isSystemDrive = ($vol.DriveLetter -eq $systemDriveLetter)
            if ($isSystemDrive) {
                $crit = $DISK_SYSTEM_CRITICAL_THRESHOLD
                $warn = $DISK_SYSTEM_WARNING_THRESHOLD
                $roleLabel = "system"
            }
            else {
                $crit = $DISK_NONSYSTEM_CRITICAL_THRESHOLD
                $warn = $DISK_NONSYSTEM_WARNING_THRESHOLD
                $roleLabel = "data"
            }

            Write-Info "  Drive $($vol.DriveLetter): ($roleLabel) - $($usedPercent)% used - $($freeGB) GB free  [SCOM alert >= $($warn)%]"
            if ($usedPercent -gt $crit) {
                Write-DiagError "    Above $($crit)% used on $roleLabel drive (critical; SCOM alert at $($warn)%)"
                Write-Info "      Impact: VSS snapshots may auto-delete; VMs risk pause-critical;"
                Write-Info "              NTFS performance degrades; backups may fail."
                Write-Info "      Remediation: Free space (cleanmgr.exe), expand volume, move data,"
                Write-Info "                   or relocate page/log/temp files to another drive."
            }
            elseif ($usedPercent -gt $warn) {
                Write-DiagWarning "    Above $($warn)% used on $roleLabel drive - SCOM alert threshold (schedule cleanup or expansion)"
            }
        }
    }
    else {
        Write-DiagWarning "  No volume information available"
    }
    
    # Disk latency check
    # ------------------------------------------------------------
    # \PhysicalDisk(*)\Avg. Disk sec/Read = average time per READ I/O request
    # (in SECONDS, hence multiply by 1000 for ms). Sustained:
    #   < 10 ms : healthy
    #   10-20 ms: acceptable for HDD, slow for SSD
    #   20-50 ms: real bottleneck - investigate queue depth, AV, or contention
    #   > 50 ms : critical - SAN, fabric, driver, or failing media
    # ------------------------------------------------------------
    Write-Section "Disk Latency (avg over last few seconds)"
    Write-Info "  Description: Average READ latency per disk in milliseconds. The single"
    Write-Info "               most predictive metric for storage health & app responsiveness."
    try {
        $diskReadLatency = Get-Counter '\PhysicalDisk(*)\Avg. Disk sec/Read' -ErrorAction Stop
        
        if ($diskReadLatency) {
            foreach ($sample in $diskReadLatency.CounterSamples) {
                if ($sample.InstanceName -ne "_total") {
                    $latencyMs = [math]::Round($sample.CookedValue * 1000, 2)
                    Write-Info "  Read Latency - $($sample.InstanceName): $($latencyMs) ms"
                    
                    if ($latencyMs -gt $DISK_LATENCY_CRITICAL_MS) {
                        Write-DiagError "    Serious I/O bottleneck (>$($DISK_LATENCY_CRITICAL_MS) ms read latency)"
                        Write-Info "      Likely cause: Failing media, saturated SAN/fabric, AV/EDR scanning"
                        Write-Info "                    every I/O, deep queue depth, or noisy-neighbor on shared storage."
                        Write-Info "      Remediation: Check SMART (Section 'Disk Health'); review filter drivers"
                        Write-Info "                   (Section 'File System Filter Drivers'); contact SAN team for"
                        Write-Info "                   queue/lun analysis; verify MPIO paths are all active."
                    }
                    elseif ($latencyMs -gt $DISK_LATENCY_WARNING_MS) {
                        Write-DiagWarning "    Slow, needs attention ($($DISK_LATENCY_WARNING_MS)-$($DISK_LATENCY_CRITICAL_MS) ms read latency)"
                    }
                    elseif ($latencyMs -gt $DISK_LATENCY_ACCEPTABLE_MS) {
                        Write-Info "    Acceptable ($($DISK_LATENCY_ACCEPTABLE_MS)-$($DISK_LATENCY_WARNING_MS) ms)"
                    }
                    else {
                        Write-Success "    Very good (<$($DISK_LATENCY_ACCEPTABLE_MS) ms)"
                    }
                }
            }
        }
    }
    catch {
        Write-DiagWarning "Could not retrieve disk latency metrics: $($_.Exception.Message)"
    }
    
    # Check cluster size for volumes (reuses cached $cachedVolumes)
    # ------------------------------------------------------------
    # NTFS allocation unit (cluster) size = the smallest chunk of disk the FS
    # tracks. Default = 4 KB. For SQL Server / database volumes, Microsoft
    # recommends 64 KB because:
    # - SQL reads/writes data in 8 KB pages and 64 KB extents
    # - Larger clusters reduce metadata overhead on huge files
    # - Aligns with SAN array stripe sizes
    # Cannot be changed in-place; requires reformat.
    # ------------------------------------------------------------
    Write-Section "Cluster Size (should be 64KB for databases)"
    Write-Info "  Description: NTFS allocation unit size. Default 4 KB is fine for general"
    
    Write-Info "               workloads. SQL/database volumes should be 64 KB (matches SQL"
    Write-Info "               extent size + reduces metadata overhead). Set at format time only."

    # Only emit the 64KB warning when this server actually runs a database
    # workload (SQL Server service installed). On non-DB hosts (and on the
    # system drive) 4 KB is correct and the warning is pure noise.
    $isDbServer = $false
    try {
        $sqlSvc = Get-Service -Name 'MSSQL*', 'SQLAgent*', 'MSSQLSERVER' -ErrorAction SilentlyContinue
        if ($sqlSvc) { $isDbServer = $true }
    } catch { }

    if ($cachedVolumes) {
        foreach ($vol in $cachedVolumes) {
            $drive = $vol.DriveLetter + ":"
            try {
                $clusterSize = (Get-CimInstance -Query "SELECT BlockSize FROM Win32_Volume WHERE DriveLetter='$drive'" -ErrorAction Stop).BlockSize
                if ($clusterSize) {
                    $clusterSizeKB = $clusterSize / 1KB
                    Write-Info "  Drive $($vol.DriveLetter): - Cluster Size: $($clusterSizeKB) KB"
                    if ($clusterSizeKB -ne 64) {
                        # Skip system drive entirely - 4KB is correct there.
                        if ($drive -ieq $env:SystemDrive) {
                            Write-Info "    (System drive: 4 KB is the correct default; 64 KB recommendation does not apply.)"
                        }
                        elseif ($isDbServer) {
                            Write-DiagWarning "    SQL Server detected on this host: recommended cluster size for database/log volumes is 64KB"
                            Write-Info "      Remediation: Cluster size is set at FORMAT time and cannot be"
                            Write-Info "                   changed in place. To fix: backup data, reformat with"
                            Write-Info "                   'format $drive /FS:NTFS /A:64K /Q', restore data."
                        }
                        else {
                            Write-Info "    (No SQL Server detected on this host; 64 KB recommendation does not apply.)"
                        }
                    }
                }
            }
            catch {
                Write-DiagWarning "  Could not retrieve cluster size for drive $($vol.DriveLetter)"
            }
        }
    }

    # Storage Disconnect Events (129, 153)
    # ------------------------------------------------------------
    # Event ID reference (storage transport):
    #   129 - storahci/iaStorA/etc : 'Reset to device, \Device\RaidPort0, was issued.'
    #         The HBA had to reset the bus because an I/O timed out. Indicates
    #         the storage path stopped responding for >TimeOutValue (default 60s).
    #   153 - disk : 'The IO operation at logical block address X for disk N
    #                 was retried.' I/O was retried successfully but at the cost
    #                 of latency. Often a leading indicator of upcoming media failure.
    # Both are STORAGE LAYER complaints, not application bugs.
    # ------------------------------------------------------------
    Write-Section "Storage Error Events (last 7 days)"
    Write-Info "  Description: Event 129 = HBA bus reset (I/O hang); Event 153 = retried I/O."
    Write-Info "               Both indicate storage transport problems below the file-system layer."
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
            Write-Info "    Likely cause (129): SAN fabric flap, MPIO path failure, HBA firmware bug,"
            Write-Info "                        or controller cache battery dying."
            Write-Info "    Likely cause (153): Failing platter/SSD cell, marginal cable/SFP, or"
            Write-Info "                        SAN-side latency spike. Often precedes hard failure."
            Write-Info "    Remediation: Check SAN/HBA logs at corresponding timestamps; verify MPIO"
            Write-Info "                 path health (Section 'MPIO'); update HBA + storport drivers;"
            Write-Info "                 run vendor disk diagnostics from iLO/iDRAC."
        }
        else {
            Write-Success "  No storage error events (129/153) found"
        }
    }
    catch {
        Write-Info "  Could not query storage events"
    }

    # Disk Queue Length
    # ------------------------------------------------------------
    # \PhysicalDisk(*)\Current Disk Queue Length = # of I/O requests waiting at
    # the disk RIGHT NOW. Sustained queue > 2 per spindle = the disk cannot keep
    # up with the workload. On SSDs the threshold is higher (per controller).
    # ------------------------------------------------------------
    Write-Section "Disk Queue Length"
    Write-Info "  Description: # of I/O requests currently waiting at the disk. Threshold = 2"
    Write-Info "               per physical spindle (HDD) or 8+ per SSD controller queue."
    try {
        $queueLength = Get-Counter '\PhysicalDisk(*)\Current Disk Queue Length' -ErrorAction Stop
        $anyHighQueue = $false
        $anyActivity = $false
        foreach ($sample in $queueLength.CounterSamples) {
            if ($sample.InstanceName -ne "_total" -and $sample.CookedValue -gt 0) {
                $anyActivity = $true
                Write-Info "  $($sample.InstanceName): Queue Length = $([math]::Round($sample.CookedValue, 1))"
                if ($sample.CookedValue -gt $DISK_QUEUE_WARNING_THRESHOLD) {
                    Write-DiagWarning "    Queue length >$($DISK_QUEUE_WARNING_THRESHOLD) - I/O bottleneck on this disk"
                    $anyHighQueue = $true
                }
            }
        }
        if ($anyHighQueue) {
            Write-Info "    Likely cause: Workload exceeds disk capacity, contending services"
            Write-Info "                  (backup + AV scan + DB), or an oversaturated SAN LUN."
            Write-Info "    Remediation: Identify top I/O process via Resource Monitor / 'Get-Process'"
            Write-Info "                 sorted by IOReadBytes/IOWriteBytes; stagger backup windows;"
            Write-Info "                 add spindles or move to SSD."
        }
        elseif (-not $anyActivity) {
            Write-Success "  All disks idle (queue length = 0 across all spindles)"
        }
        else {
            Write-Success "  Disk queue length within healthy range"
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk queue length"
    }

    # Write Latency (supplement to existing read latency)
    # ------------------------------------------------------------
    # Same thresholds as read latency. Write latency that is significantly
    # WORSE than read latency points to: write-cache disabled, synchronous
    # replication (SQL AG, Storage Replica), or a controller battery dead
    # (cache flushed to disk on every write).
    # ------------------------------------------------------------
    Write-Section "Disk Write Latency"
    Write-Info "  Description: Average WRITE latency per disk. If much higher than read,"
    Write-Info "               check controller cache state, sync replication, or write throttling."
    try {
        $writeLatency = Get-Counter '\PhysicalDisk(*)\Avg. Disk sec/Write' -ErrorAction Stop
        foreach ($sample in $writeLatency.CounterSamples) {
            if ($sample.InstanceName -ne "_total") {
                $latencyMs = [math]::Round($sample.CookedValue * 1000, 2)
                Write-Info "  Write Latency - $($sample.InstanceName): $latencyMs ms"
                if ($latencyMs -gt $DISK_LATENCY_CRITICAL_MS) {
                    Write-DiagError "    Write latency >$($DISK_LATENCY_CRITICAL_MS) ms (critical)"
                    Write-Info "      Likely cause: Disabled write-back cache (controller battery dead),"
                    Write-Info "                    synchronous replication overhead, or full SSD doing GC."
                    Write-Info "      Remediation: Check RAID controller cache/battery (vendor tool);"
                    Write-Info "                   if AG sync, check 'SQL AG Replication Health' (CPU section)."
                }
                elseif ($latencyMs -gt $DISK_LATENCY_WARNING_MS) {
                    Write-DiagWarning "    Write latency elevated"
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check write latency"
    }

    # NTFS Metadata / Corruption Errors
    # ------------------------------------------------------------
    # Event ID reference:
    #   55 - Microsoft-Windows-Ntfs : The file system structure on volume X is
    #                                 corrupt and unusable. Run chkdsk.
    #
    # IMPORTANT: Event ID 55 in the System log is REUSED by many providers
    # (Microsoft-Windows-Kernel-Processor-Power = informational power capability
    # enumeration that fires every boot, ACPI subsystem, etc.). We MUST filter
    # by ProviderName='Microsoft-Windows-Ntfs' to avoid false positives.
    # ------------------------------------------------------------
    Write-Section "NTFS Errors (last 30 days)"
    Write-Info "  Description: Event 55 from Microsoft-Windows-Ntfs provider = file system"
    
    Write-Info "               structure corruption. Filtered to exclude unrelated Event 55s"
    Write-Info "               from Kernel-Processor-Power and other providers (false positives)."
    try {
        $ntfsEvents = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            Id           = 55
            ProviderName = 'Microsoft-Windows-Ntfs'
            StartTime    = (Get-Date).AddDays(-30)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($ntfsEvents) {
            Write-DiagError "  Found $($ntfsEvents.Count) NTFS corruption event(s)"
            $ntfsEvents | Select-Object -First 3 | ForEach-Object {
                Write-DiagWarning "    [$($_.TimeCreated.ToString('MM-dd HH:mm'))] $(Get-EventSnippet -Event $_ -MaxLength 100)"
            }
            Write-Info "    Impact: File system metadata is damaged. Affected files may be"
            Write-Info "            inaccessible or returning incorrect data."
            Write-Info "    Remediation: 1. Identify affected volume from event detail."
            Write-Info "                 2. Schedule maintenance and run 'chkdsk <drive>: /F /R'."
            Write-Info "                 3. If recurring, suspect failing media - run SMART check"
            Write-Info "                    (Section 'Disk Health & Predictive Failure')."
        }
        else {
            Write-Success "  No NTFS corruption events from Microsoft-Windows-Ntfs provider"
        }
    }
    catch {
        Write-Info "  Could not query NTFS events"
    }

    # VM Pause-Critical Risk (>95% full) - reuses cached $cachedVolumes
    # ------------------------------------------------------------
    # When a Hyper-V dynamic VHDX is on a host volume that fills to 100%, the VM
    # immediately enters Pause-Critical state. The same applies to many third-
    # party hypervisors and any thin-provisioned storage. >95% full = no headroom.
    # ------------------------------------------------------------
    Write-Section "VM Pause-Critical Risk Check"
    Write-Info "  Description: Drives >95% full. If a Hyper-V/VMware host volume hosting"
    Write-Info "               dynamic disks fills completely, child VMs IMMEDIATELY pause."
    if ($cachedVolumes) {
        $anyAtRisk = $false
        foreach ($vol in ($cachedVolumes | Where-Object { $_.Size -gt 0 })) {
            $usedPercent = [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 1)
            if ($usedPercent -gt 95) {
                Write-DiagError "  Drive $($vol.DriveLetter): $usedPercent% full - VM MAY PAUSE if disk fills completely"
                $anyAtRisk = $true
            }
        }
        if ($anyAtRisk) {
            Write-Info "    Remediation: Free space NOW (cleanmgr.exe, delete old logs, move VHDXs);"
            Write-Info "                 expand the underlying LUN; or migrate VMs to a host with capacity."
        }
        else {
            Write-Success "  No volumes above 95% - no immediate VM pause-critical risk"
        }
    }

    #region v3.0 Disk Checks

    # 1. Disk IOPS (Read + Write)
    # ------------------------------------------------------------
    # IOPS = I/O Operations Per Second. Different media tiers cap at:
    #   7.2K HDD : ~80 IOPS sustained
    #   15K HDD  : ~180 IOPS sustained
    #   SATA SSD : 10,000-50,000 IOPS
    #   NVMe SSD : 100,000-1,000,000+ IOPS
    # Compare current IOPS to media tier ceiling (next section) to spot saturation.
    # ------------------------------------------------------------
    Write-Section "Disk IOPS"
    Write-Info "  Description: I/O operations per second per disk. Compare to media-type"
    Write-Info "               ceiling: HDD ~80-180 IOPS, SSD 10K-50K, NVMe 100K+."
    try {
        $readIOPS = Get-Counter '\PhysicalDisk(*)\Disk Reads/sec' -ErrorAction Stop
        $writeIOPS = Get-Counter '\PhysicalDisk(*)\Disk Writes/sec' -ErrorAction Stop
        $anyIopsActivity = $false
        foreach ($sample in $readIOPS.CounterSamples) {
            if ($sample.InstanceName -eq '_total') { continue }
            $wSample = $writeIOPS.CounterSamples | Where-Object { $_.InstanceName -eq $sample.InstanceName }
            $rIOPS = [math]::Round($sample.CookedValue, 0)
            $wIOPS = if ($wSample) { [math]::Round($wSample.CookedValue, 0) } else { 0 }
            $totalIOPS = $rIOPS + $wIOPS
            if ($totalIOPS -gt 0) {
                $anyIopsActivity = $true
                Write-Info "  $($sample.InstanceName): Read=$rIOPS Write=$wIOPS Total=$totalIOPS IOPS"
            }
        }
        if (-not $anyIopsActivity) {
            Write-Info "  All disks idle at sample time (0 IOPS). Re-run while workload is active for a meaningful number."
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk IOPS"
    }

    # 2. Disk Throughput (MB/sec)
    # ------------------------------------------------------------
    # Throughput is the OTHER side of the IOPS coin. Workloads divide into:
    # - Random small I/O (databases, OLTP)        : limited by IOPS
    # - Sequential large I/O (backup, video, ETL) : limited by throughput
    # Compare against link speed: SATA 6 Gb = ~600 MB/s, SAS 12 Gb = ~1.2 GB/s,
    # NVMe Gen3 x4 = ~3.5 GB/s, NVMe Gen4 x4 = ~7 GB/s.
    # ------------------------------------------------------------
    Write-Section "Disk Throughput"
    Write-Info "  Description: MB/sec per disk. Sequential workloads (backup, ETL) cap on"
    Write-Info "               throughput, not IOPS. Compare to link speed (SATA/SAS/NVMe)."
    try {
        $readTP = Get-Counter '\PhysicalDisk(*)\Disk Read Bytes/sec' -ErrorAction Stop
        $writeTP = Get-Counter '\PhysicalDisk(*)\Disk Write Bytes/sec' -ErrorAction Stop
        $anyThroughput = $false
        foreach ($sample in $readTP.CounterSamples) {
            if ($sample.InstanceName -ne "_total" -and ($sample.CookedValue -gt 0 -or ($writeTP.CounterSamples | Where-Object { $_.InstanceName -eq $sample.InstanceName }).CookedValue -gt 0)) {
                $anyThroughput = $true
                $wSample = $writeTP.CounterSamples | Where-Object { $_.InstanceName -eq $sample.InstanceName }
                $rMBs = [math]::Round($sample.CookedValue / 1MB, 2)
                $wMBs = if ($wSample) { [math]::Round($wSample.CookedValue / 1MB, 2) } else { 0 }
                Write-Info "  $($sample.InstanceName): Read=${rMBs} MB/s Write=${wMBs} MB/s"
            }
        }
        if (-not $anyThroughput) {
            Write-Info "  All disks idle at sample time (0 MB/s). Re-run during workload for a meaningful number."
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk throughput"
    }

    # 3. Storage Media Type (SSD vs HDD)
    # ------------------------------------------------------------
    # Get-PhysicalDisk reports MediaType from SMART data:
    #   SSD          : flash-based, low latency, high IOPS
    #   HDD          : spinning rust, ~80-180 IOPS depending on RPM
    #   SCM          : Storage Class Memory (Optane / persistent memory)
    #   Unspecified  : SAN-presented LUN; depends on backend
    # Critical to know for capacity planning and AV exclusion strategy.
    # ------------------------------------------------------------
    Write-Section "Storage Media Type"
    Write-Info "  Description: Physical media classification from SMART data. HDDs need"
    Write-Info "               more aggressive AV exclusions for DB workloads."
    try {
        $physDisks = @(Get-PhysicalDisk -ErrorAction Stop)

        # Group identical disks (same FriendlyName + MediaType + BusType + size).
        # Storage Spaces / S2D pools commonly present 24+ identical capacity drives;
        # listing each one separately produces a wall of duplicate output and a
        # duplicate HDD warning per disk. Roll them into a single line + single warning.
        $diskGroups = $physDisks | Group-Object -Property {
            $mt = if ($_.MediaType) { $_.MediaType } else { 'Unknown' }
            $bt = if ($_.BusType) { $_.BusType } else { 'Unknown' }
            $gb = [math]::Round($_.Size / 1GB, 1)
            "$($_.FriendlyName)|$mt|$bt|$gb"
        }

        $hddWarningEmitted = $false
        foreach ($grp in $diskGroups | Sort-Object Count -Descending) {
            $sample = $grp.Group[0]
            $mediaType = if ($sample.MediaType) { $sample.MediaType } else { 'Unknown' }
            $busType = if ($sample.BusType) { $sample.BusType } else { 'Unknown' }
            $sizeGB = [math]::Round($sample.Size / 1GB, 1)
            $countSuffix = if ($grp.Count -gt 1) { " x$($grp.Count)" } else { '' }
            Write-Info "  $($sample.FriendlyName): $mediaType ($busType) - ${sizeGB}GB$countSuffix"

            if ($mediaType -eq 'HDD' -and -not $hddWarningEmitted) {
                Write-DiagWarning "    HDD detected - expect higher latency than SSD; critical for SQL/database workloads"
                Write-Info "      Remediation: Move DB data + log + tempdb files to SSD/NVMe; ensure"
                Write-Info "                   AV exclusions cover SQL data dirs and backup paths."
                $hddWarningEmitted = $true
            }
            if ($mediaType -eq 'Unspecified' -and $busType -like '*iSCSI*') {
                Write-Info "    iSCSI LUN - media type depends on SAN backend (ask SAN admin)"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not determine storage media types"
    }

    # 4. SMART / Predictive Failure Detection
    # ------------------------------------------------------------
    # SMART (Self-Monitoring, Analysis and Reporting Technology) is firmware-level
    # disk health monitoring. Windows surfaces it via:
    # - Get-PhysicalDisk HealthStatus (Healthy / Warning / Unhealthy)
    # - MSStorageDriver_FailurePredictStatus (PredictFailure boolean)
    # A 'Predictive Failure' = the disk is reporting that it expects to fail SOON
    # (typically days to weeks). Replace immediately, don't wait.
    # ------------------------------------------------------------
    Write-Section "Disk Health & Predictive Failure"
    Write-Info "  Description: SMART-derived disk health. 'PredictFailure' = the disk"
    Write-Info "               firmware says it expects to fail SOON. Replace immediately."
    try {
        $physDisks = Get-PhysicalDisk -ErrorAction Stop
        $anyUnhealthy = $false
        foreach ($pd in $physDisks) {
            $health = $pd.HealthStatus
            $opStatus = $pd.OperationalStatus
            if ($health -ne "Healthy" -or $opStatus -ne "OK") {
                Write-DiagError "  $($pd.FriendlyName): Health=$health OpStatus=$opStatus"
                $anyUnhealthy = $true
                if ($health -like "*Predict*" -or $health -like "*Warning*") {
                    Write-DiagError "    PREDICTIVE FAILURE - replace this disk immediately"
                }
            }
            else {
                Write-Success "  $($pd.FriendlyName): Health=$health OpStatus=$opStatus"
            }
        }
        # Also check via WMI for SMART status
        $smartDisks = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue
        if ($smartDisks) {
            foreach ($sd in $smartDisks) {
                if ($sd.PredictFailure) {
                    Write-DiagError "  SMART Predictive Failure on InstanceName: $($sd.InstanceName)"
                    $anyUnhealthy = $true
                }
            }
        }
        if ($anyUnhealthy) {
            Write-Info "    Remediation: 1. Verify the disk in vendor tool (Dell OMSA, HPE SSA,"
            Write-Info "                    Lenovo XClarity) and capture full SMART log."
            Write-Info "                 2. Open hardware case; ensure recent backup completed."
            Write-Info "                 3. If RAID member, controller will auto-rebuild after swap."
            Write-Info "                 4. Replace before scheduled BSOD - data loss risk."
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk health: $($_.Exception.Message)"
    }

    # 5. Volume Shadow Copy (VSS) Snapshot Space
    # ------------------------------------------------------------
    # VSS = Volume Shadow Copy Service. Snapshots are point-in-time copies used
    # by Windows Backup, System Restore, and most third-party backup software
    # (Veeam, Commvault, etc.). Each snapshot consumes 'diff area' space - hidden
    # from regular file size totals. Orphaned snapshots = silent disk-fill source.
    # ------------------------------------------------------------
    Write-Section "VSS Shadow Copy Usage"
    Write-Info "  Description: VSS snapshots are HIDDEN consumers of disk space. Failed/"
    Write-Info "               orphaned backups can leave dozens of snapshots silently"
    Write-Info "               consuming 100s of GB - common cause of mystery disk fill."
    try {
        $shadows = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
        if ($shadows) {
            $shadowsByVolume = $shadows | Group-Object VolumeName
            foreach ($group in $shadowsByVolume) {
                $count = $group.Count
                Write-Info "  Volume $($group.Name): $count snapshot(s)"
                if ($count -gt 10) {
                    Write-DiagWarning "    $count VSS snapshots - orphaned snapshots consuming hidden disk space"
                    Write-Info "      Remediation: List with 'vssadmin list shadows /for=$($group.Name)';"
                    Write-Info "                   delete oldest with 'vssadmin delete shadows /for=$($group.Name) /oldest';"
                    Write-Info "                   verify backup software is properly cleaning up its snapshots."
                }
            }
            Write-Info "  Total VSS snapshots: $($shadows.Count)"
        }
        else {
            Write-Info "  No VSS shadow copies found"
        }
    }
    catch {
        Write-DiagWarning "  Could not check VSS snapshots"
    }

    # Check VSS writers health
    # ------------------------------------------------------------
    # VSS writers are app-specific components (SQL, Exchange, Hyper-V, IIS)
    # that prepare their state for snapshotting. A failed writer = backups for
    # that app FAIL or produce inconsistent snapshots. Common cause: the writer
    # service is stopped, or it errored on the last attempt.
    # ------------------------------------------------------------
    try {
        $vssWriters = vssadmin list writers 2>&1
        $failedWriters = $vssWriters | Select-String 'State:.*Failed|State:.*Not responding|State:.*Waiting for completion' -ErrorAction SilentlyContinue
        if ($failedWriters) {
            Write-DiagWarning "  VSS Writer issues detected:"
            foreach ($fw in $failedWriters) {
                Write-DiagWarning "    $($fw.Line.Trim())"
            }
            Write-Info "    Impact: Application-consistent backups for the failed writer's app"
            Write-Info "            (SQL/Exchange/Hyper-V) will fail or be crash-consistent only."
            Write-Info "    Remediation: Restart the host service (e.g. SQL Writer Service);"
            Write-Info "                 if persistent, run 'vssadmin list writers' for full output;"
            Write-Info "                 reboot may be required for stuck-state writers."
        }
        else {
            Write-Success "  All VSS writers are stable"
        }
    }
    catch { }

    # 6. Storage Spaces / Pool Health
    # ------------------------------------------------------------
    # Storage Spaces = Microsoft's software-defined storage. A 'pool' aggregates
    # physical disks; 'virtual disks' are carved from pools with redundancy
    # (mirror/parity). Degraded = a member disk failed and the pool is rebuilding
    # or is single-disk-tolerant. Critical timeline matters for redundancy.
    # ------------------------------------------------------------
    Write-Section "Storage Spaces & Pool Health"
    Write-Info "  Description: Software-defined storage pool health. Degraded = disk failed,"
    Write-Info "               pool may be rebuilding. Second disk failure during rebuild ="
    Write-Info "               data loss for non-mirror configurations."
    try {
        $pools = Get-StoragePool -ErrorAction SilentlyContinue | Where-Object { $_.IsPrimordial -eq $false }
        if ($pools) {
            foreach ($pool in $pools) {
                $health = $pool.HealthStatus
                $opStatus = $pool.OperationalStatus
                $sizeGB = [math]::Round($pool.Size / 1GB, 1)
                $allocGB = [math]::Round($pool.AllocatedSize / 1GB, 1)
                Write-Info "  Pool '$($pool.FriendlyName)': $allocGB/$sizeGB GB allocated"
                if ($health -ne "Healthy") {
                    Write-DiagError "    Pool Health: $health ($opStatus)"
                    # Check for degraded virtual disks
                    $vDisks = Get-VirtualDisk -StoragePool $pool -ErrorAction SilentlyContinue
                    foreach ($vd in $vDisks) {
                        if ($vd.HealthStatus -ne "Healthy" -or $vd.OperationalStatus -ne "OK") {
                            Write-DiagError "    VDisk '$($vd.FriendlyName)': $($vd.HealthStatus) / $($vd.OperationalStatus)"
                            if ($vd.OperationalStatus -like "*Degraded*") {
                                Write-DiagError "      DEGRADED - rebuild in progress or missing disk"
                            }
                        }
                    }
                    Write-Info "    Remediation: Run 'Get-PhysicalDisk' to find the failed/missing"
                    Write-Info "                 member; replace; pool will auto-rebuild. Monitor with"
                    Write-Info "                 'Get-StorageJob' for rebuild progress."
                }
                else {
                    Write-Success "    Pool Health: Healthy"
                }
            }
        }
        else {
            Write-Info "  No Storage Spaces pools configured"
        }
    }
    catch {
        Write-Info "  Storage Spaces not available or not configured"
    }

    # 7. Disk Fragmentation Level
    # ------------------------------------------------------------
    # Fragmentation = file data scattered across non-contiguous disk extents.
    # On HDD this DEVASTATES sequential read perf. On SSD it has minimal impact
    # (random access cost is uniform), so Windows uses TRIM instead of defrag.
    # The 'Optimize-Volume -Analyze' command reports current fragmentation %.
    # ------------------------------------------------------------
    Write-Section "Disk Fragmentation"
    Write-Info "  Description: % of files split into non-contiguous extents. Critical on HDD"
    Write-Info "               (kills sequential read), irrelevant on SSD (which uses TRIM)."
    if ($cachedVolumes) {
        foreach ($vol in ($cachedVolumes | Where-Object { $_.DriveLetter -and $_.Size -gt 0 })) {
            try {
                $defragInfo = Optimize-Volume -DriveLetter $vol.DriveLetter -Analyze -Verbose 4>&1 -ErrorAction Stop
                $fragLine = $defragInfo | Select-String 'fragmented|Current' -ErrorAction SilentlyContinue
                if ($fragLine) {
                    Write-Info "  Drive $($vol.DriveLetter): $($fragLine.Line.Trim())"
                }
                else {
                    Write-Info "  Drive $($vol.DriveLetter): Analysis completed (check verbose output for details)"
                }
            }
            catch {
                # Optimize-Volume may fail on system volumes or SSDs (TRIM instead)
                Write-Info "  Drive $($vol.DriveLetter): Cannot analyze (SSD uses TRIM, or volume is in use)"
            }
        }
    }

    # 8. Pagefile Disk Placement
    # ------------------------------------------------------------
    # Pagefile (pagefile.sys) is the most write-active file on the OS drive when
    # under memory pressure. Co-locating it with OS + apps + logs creates I/O
    # contention. Best practice: dedicated fast (SSD) drive, separate from OS.
    # On modern servers with abundant RAM this matters less, but still avoid
    # putting it on the same spindle as a busy database log.
    # ------------------------------------------------------------
    Write-Section "Pagefile Disk Placement"
    Write-Info "  Description: Pagefile is heavily I/O-active under memory pressure."
    Write-Info "               Sharing a spindle with OS + DB log = contention. Move to SSD."
    try {
        $pageFiles = Get-CimInstance Win32_PageFileUsage -ErrorAction Stop

        # Detect whether there is even a candidate "other" drive to move the
        # pagefile to. On single-disk VMs (most cloud / Hyper-V dev hosts)
        # warning about pagefile-on-C: is unactionable noise.
        $candidateDrives = @()
        try {
            $candidateDrives = @(
                Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop |
                    Where-Object { $_.DeviceID -ne $env:SystemDrive -and $_.Size -gt 10GB }
            )
        } catch { }

        if ($pageFiles) {
            foreach ($pf in $pageFiles) {
                $pfDrive = $pf.Name.Substring(0, 2)
                Write-Info "  Page file: $($pf.Name) ($($pf.AllocatedBaseSize) MB)"
                # Check if pagefile is on the OS drive
                $osDrive = $env:SystemDrive
                if ($pfDrive -ieq $osDrive) {
                    if ($candidateDrives.Count -eq 0) {
                        Write-Info "    Page file is on the OS drive ($osDrive). Single-disk host -"
                        Write-Info "    no alternate drive available; this is expected."
                    }
                    else {
                        Write-DiagWarning "    Page file is on the OS drive ($osDrive) - may cause I/O contention"
                        Write-Info "      Candidate alternate drive(s): $((@($candidateDrives) | ForEach-Object DeviceID) -join ', ')"
                        Write-Info "      Remediation: For high-performance servers, configure pagefile on"
                        Write-Info "                   a dedicated SSD volume. Keep a small (1 GB) pagefile on"
                        Write-Info "                   the OS drive for crash dump support."
                    }
                }
                else {
                    Write-Success "    Page file is on a non-OS drive ($pfDrive) - good"
                }
            }
        }
        else {
            Write-Info "  No active pagefiles reported (system-managed pagefile may be off)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check pagefile placement: $($_.Exception.Message)"
    }

    # 9. Temp/TempDB Disk Check
    # ------------------------------------------------------------
    # SQL Server's tempdb is HEAVILY used: temp tables, sort spills, hash spills,
    # version store, snapshot isolation. Co-locating with OS or with user DB data
    # = serious contention. Best practice: dedicated SSD, multiple data files
    # (1 per logical core, up to 8). We just check placement here.
    # ------------------------------------------------------------
    Write-Section "TEMP & SQL TempDB Location"
    Write-Info "  Description: SQL tempdb is heavily I/O-active. Sharing a disk with the"
    Write-Info "               OS or user databases causes severe contention on busy servers."
    try {
        $tempPath = $env:TEMP
        $tempDrive = $tempPath.Substring(0, 2)
        $osDrive = $env:SystemDrive
        Write-Info "  Windows TEMP: $tempPath (Drive: $tempDrive)"
        if ($tempDrive -eq $osDrive) {
            Write-Info "    TEMP is on OS drive - normal for most servers"
        }

        # Check SQL TempDB if SQL is running
        if ($script:ClusterEnv.IsAGInstalled -or (Get-Service -Name "MSSQLSERVER" -ErrorAction SilentlyContinue)) {
            try {
                $conn = New-Object System.Data.SqlClient.SqlConnection "Server=.;Integrated Security=True;Connection Timeout=5"
                $conn.Open()
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = "SELECT physical_name FROM sys.master_files WHERE database_id = DB_ID('tempdb')"
                $reader = $cmd.ExecuteReader()
                while ($reader.Read()) {
                    $tempDbPath = $reader["physical_name"]
                    $tempDbDrive = $tempDbPath.Substring(0, 2)
                    Write-Info "  SQL TempDB: $tempDbPath"
                    if ($tempDbDrive -eq $osDrive) {
                        Write-DiagWarning "    TempDB on OS drive ($osDrive) - move to a dedicated fast disk for production"
                        Write-Info "      Remediation: ALTER DATABASE tempdb MODIFY FILE (NAME=tempdev,"
                        Write-Info "                   FILENAME='X:\TempDB\tempdb.mdf'); restart SQL service."
                        Write-Info "                   Add data files (1 per core, up to 8) for allocation contention."
                    }
                }
                $reader.Close()
                $conn.Close()
            }
            catch {
                Write-Info "  Could not query SQL TempDB location"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check TEMP locations"
    }

    # 10. Filter Driver Stack (fltmc)
    # ------------------------------------------------------------
    # File system minifilters intercept EVERY I/O on their attached volumes.
    # AV/EDR (WdFilter, csagent, SentinelMonitor), backup (Veeam, Commvault),
    # encryption (BitLocker), and dedup all stack here. More filters = more
    # latency. >10 filters on a busy DB server = measurable I/O cost.
    # ------------------------------------------------------------
    Write-Section "File System Filter Drivers"
    Write-Info "  Description: Each minifilter intercepts EVERY file I/O. Stack depth"
    Write-Info "               directly multiplies per-IO latency. Top offenders: AV, backup,"
    Write-Info "               encryption, dedup, ransomware-protection drivers."
    try {
        $fltmcOutput = fltmc 2>&1
        $filterLines = $fltmcOutput | Select-String '^\s*\d+' -ErrorAction SilentlyContinue
        if ($filterLines) {
            $filterCount = $filterLines.Count
            Write-Info "  Active filter drivers: $filterCount"
            foreach ($fl in $filterLines | Select-Object -First 15) {
                $line = $fl.Line.Trim()
                # Flag known high-impact AV filters
                if ($line -match 'WdFilter|csagent|SentinelMonitor|SymEFA|savonaccess|CbFilter|epfw|tmPreFilter') {
                    Write-DiagWarning "    $line  [AV/Security filter - impacts I/O latency]"
                }
                else {
                    Write-Info "    $line"
                }
            }
            if ($filterCount -gt 15) {
                Write-Info "    ... and $($filterCount - 15) more"
            }
            if ($filterCount -gt 10) {
                Write-DiagWarning "  $filterCount filter drivers is HIGH - each adds latency to every I/O operation"
                Write-Info "    Remediation: Audit installed filters - retire unused backup agents,"
                Write-Info "                 remove redundant AV after vendor migration, ensure DB"
                Write-Info "                 paths are excluded from AV/EDR file scanning."
            }
        }
        else {
            Write-Info "  No filter drivers detected (or fltmc not available)"
        }
    }
    catch {
        Write-DiagWarning "  Could not enumerate filter drivers"
    }

    # Check filter instances
    try {
        $fltmcInst = fltmc instances 2>&1
        $instanceCount = ($fltmcInst | Select-String '^\s*\S+' | Where-Object { $_.Line -notmatch 'Filter|Instance|---' }).Count
        if ($instanceCount -gt 0) {
            Write-Info "  Filter instances attached to volumes: $instanceCount"
        }
    }
    catch { }

    # 11. Disk Timeout & Retry Settings
    # ------------------------------------------------------------
    # HKLM\SYSTEM\CurrentControlSet\Services\Disk\TimeOutValue (REG_DWORD,
    # seconds) controls how long Windows waits for a disk I/O before considering
    # it failed. Default = 60s. SAN-attached servers often need this raised to
    # 90-120s to ride out transient fabric blips. iSCSI has its own LinkDownTime.
    # ------------------------------------------------------------
    Write-Section "Disk Timeout Configuration"
    Write-Info "  Description: How long Windows waits for a disk I/O before treating it as"
    Write-Info "               failed. Default 60s. SAN servers may need 90-120s; values"
    Write-Info "               below 30s cause premature errors during fabric flaps."
    try {
        $diskTimeout = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Disk' -Name 'TimeOutValue' -ErrorAction SilentlyContinue
        $timeoutValue = if ($diskTimeout -and $diskTimeout.TimeOutValue) { $diskTimeout.TimeOutValue } else { 60 }
        Write-Info "  Disk I/O Timeout: $timeoutValue seconds"
        if ($timeoutValue -eq 60) {
            Write-Info "    Default value (60s) - appropriate for most configurations"
        }
        elseif ($timeoutValue -lt 30) {
            Write-DiagWarning "    LOW timeout (${timeoutValue}s) - may cause premature I/O failures on slow SAN paths"
            Write-Info "      Remediation: Raise to vendor recommended value (often 60-90s)"
            Write-Info "                   in HKLM\SYSTEM\CurrentControlSet\Services\Disk\TimeOutValue."
        }
        elseif ($timeoutValue -gt 120) {
            Write-DiagWarning "    HIGH timeout (${timeoutValue}s) - I/O hangs will take very long to surface as errors"
            Write-Info "      Remediation: Lower to ~90s unless storage vendor specifically requires more."
        }

        # Check SAN-specific timeout for iSCSI
        $iscsiTimeout = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}\0000' -Name 'LinkDownTime' -ErrorAction SilentlyContinue
        if ($iscsiTimeout -and $iscsiTimeout.LinkDownTime) {
            Write-Info "  iSCSI Link Down Time: $($iscsiTimeout.LinkDownTime) seconds"
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk timeout settings"
    }

    # 12. MPIO (Multipath I/O) Status
    # ------------------------------------------------------------
    # MPIO = Multiple physical paths to the same SAN LUN, for redundancy and/or
    # load balancing. If a path fails, traffic auto-fails over. A 'Standby' or
    # 'Failed' path means the failover happened (good!) but you're now running
    # without redundancy until the path is restored.
    # ------------------------------------------------------------
    Write-Section "MPIO (Multipath I/O)"
    Write-Info "  Description: SAN multi-path redundancy. 'Failed' or 'Standby' paths"
    Write-Info "               mean failover already occurred - no redundancy until fixed."
    try {
        $mpioFeature = Get-WindowsFeature -Name Multipath-IO -ErrorAction SilentlyContinue
        if ($mpioFeature -and $mpioFeature.Installed) {
            Write-Success "  MPIO feature is installed"
            try {
                $mpioDevices = Get-MSDSMSupportedHW -ErrorAction SilentlyContinue
                if ($mpioDevices) {
                    Write-Info "  Supported MPIO hardware entries: $(@($mpioDevices).Count)"
                }
            }
            catch { }

            # Check MPIO paths
            try {
                $mpioDisks = mpclaim -s -d 2>&1
                $pathLines = $mpioDisks | Select-String 'MPIO Disk' -ErrorAction SilentlyContinue
                if ($pathLines) {
                    Write-Info "  MPIO disks detected: $($pathLines.Count)"
                    # Look for degraded paths
                    $degradedPaths = $mpioDisks | Select-String 'Failed|Standby' -ErrorAction SilentlyContinue
                    if ($degradedPaths) {
                        Write-DiagWarning "  DEGRADED MPIO paths detected:"
                        foreach ($dp in $degradedPaths | Select-Object -First 5) {
                            Write-DiagWarning "    $($dp.Line.Trim())"
                        }
                        Write-Info "    Remediation: Check SAN fabric (zoning, switch port, HBA, SFP);"
                        Write-Info "                 vendor MPIO tool (Dell EqualLogic HIT, EMC PowerPath,"
                        Write-Info "                 NetApp DSM) for detailed path state; restore redundancy ASAP."
                    }
                    else {
                        Write-Success "  All MPIO paths are active"
                    }
                }
            }
            catch {
                Write-Info "  Could not query MPIO disk paths (mpclaim not available)"
            }
        }
        else {
            Write-Info "  MPIO feature not installed (not needed for local storage)"
        }
    }
    catch {
        Write-Info "  Could not check MPIO status (Get-WindowsFeature may not be available)"
    }

    # 13. ReFS vs NTFS Detection
    # ------------------------------------------------------------
    # NTFS  = battle-tested, supports compression / EFS / quotas / dedup
    # ReFS  = Resilient File System; designed for huge volumes (SOFS, Hyper-V,
    #         Veeam repos, S2D). Has integrity streams, auto-repair from mirror.
    #         Does NOT support: file-level compression, EFS, quotas, page file,
    #         OS install, removable media. Choose carefully.
    # ------------------------------------------------------------
    Write-Section "File System Type per Volume"
    Write-Info "  Description: NTFS is the default, fully featured. ReFS is for very large"
    Write-Info "               volumes (Hyper-V, backup repos, S2D) but lacks compression,"
    
    Write-Info "               EFS, quotas, and cannot host the OS or page file."
    if ($cachedVolumes) {
        foreach ($vol in ($cachedVolumes | Where-Object { $_.DriveLetter -and $_.Size -gt 0 })) {
            $fsType = $vol.FileSystemType
            $sizeGB = [math]::Round($vol.Size / 1GB, 1)
            Write-Info "  Drive $($vol.DriveLetter): $fsType (${sizeGB}GB)"
            if ($fsType -eq "ReFS") {
                Write-Info "    ReFS: Integrity streams, auto-repair. Optimal for Hyper-V, Veeam, Storage Spaces Direct"
                Write-Info "    Note: ReFS does not support file-level compression or encryption"
            }
        }
    }

    # 14. Disk Busy Time %
    # ------------------------------------------------------------
    # \PhysicalDisk(*)\% Disk Time = % of elapsed time disk was servicing
    # requests. NOTE: this counter can exceed 100% on multi-spindle arrays
    # (each spindle counts toward the total) - we cap display at 100% but flag
    # the underlying value. >80% sustained = disk is the bottleneck.
    # ------------------------------------------------------------
    Write-Section "Disk Busy Time"
    Write-Info "  Description: % of time the disk is servicing I/O. >80% = disk is the"
    Write-Info "               bottleneck. Counter can exceed 100% on multi-spindle arrays"
    Write-Info "               (one count per spindle); display is capped at 100%."
    try {
        $diskTime = Get-Counter '\PhysicalDisk(*)\% Disk Time' -ErrorAction Stop
        $anyBusy = $false
        $anyActivity = $false
        foreach ($sample in $diskTime.CounterSamples) {
            if ($sample.InstanceName -ne "_total") {
                $busyPercent = [math]::Round($sample.CookedValue, 1)
                # % Disk Time can exceed 100% on multi-spindle arrays; cap display
                $displayPercent = [math]::Min($busyPercent, 100)
                if ($busyPercent -gt 80) {
                    Write-DiagWarning "  $($sample.InstanceName): $displayPercent% busy - disk is the bottleneck"
                    $anyBusy = $true
                    $anyActivity = $true
                }
                elseif ($busyPercent -gt 50) {
                    Write-Info "  $($sample.InstanceName): $displayPercent% busy (moderate load)"
                    $anyActivity = $true
                }
                elseif ($busyPercent -gt 0) {
                    Write-Info "  $($sample.InstanceName): $displayPercent% busy"
                    $anyActivity = $true
                }
            }
        }
        if ($anyBusy) {
            Write-Info "    Remediation: Identify the top I/O process (Resource Monitor / Process"
            Write-Info "                 Explorer / 'Get-Process | Sort IOReadBytes -Descending');"
            Write-Info "                 stagger backup + AV scan windows; consider faster media."
        }
        elseif (-not $anyActivity) {
            Write-Success "  All disks idle (0% busy time across all spindles)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check disk busy time"
    }

    # 15. Storage Tiering Status (Storage Spaces Direct / Tiered Volumes)
    # ------------------------------------------------------------
    # Storage tiering = mixing fast (SSD) and slow (HDD) media in one volume,
    # with the OS dynamically promoting hot data to the SSD tier. Requires the
    # 'Storage Tiers Optimization' scheduled task to actually do the promotion.
    # If the task is disabled/broken, hot data stays on slow tier = no benefit.
    # ------------------------------------------------------------
    Write-Section "Storage Tiering"
    Write-Info "  Description: Tiered volumes auto-promote hot data to SSD. Requires the"
    Write-Info "               'Storage Tiers Optimization' task to be Ready/Running -"
    Write-Info "               if disabled, hot data stays on slow tier and you get no benefit."
    try {
        $tiers = Get-StorageTier -ErrorAction SilentlyContinue
        if ($tiers) {
            Write-Info "  Storage tiers configured:"
            foreach ($tier in $tiers) {
                $tierSizeGB = [math]::Round($tier.Size / 1GB, 1)
                $mediaType = $tier.MediaType
                Write-Info "    $($tier.FriendlyName): $mediaType - ${tierSizeGB}GB"
            }

            # Check tier optimization schedule
            try {
                $tierTask = Get-ScheduledTask -TaskName "Storage Tiers Optimization" -ErrorAction SilentlyContinue
                if ($tierTask) {
                    Write-Info "  Tiering optimization task: $($tierTask.State)"
                    if ($tierTask.State -ne 'Ready' -and $tierTask.State -ne 'Running') {
                        Write-DiagWarning "    Tiering task is $($tierTask.State) - hot data may not be promoted to SSD tier"
                        Write-Info "      Remediation: Enable+start the 'Storage Tiers Optimization' task"
                        Write-Info "                   under \Microsoft\Windows\Storage Tiers Management;"
                        Write-Info "                   confirm Last Run Result = 0x0."
                    }
                }
            }
            catch { }
        }
        else {
            Write-Info "  No storage tiers configured (standard non-tiered storage)"
        }
    }
    catch {
        Write-Info "  Storage tiering not available"
    }

    #endregion v3.0 Disk Checks
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
    # ------------------------------------------------------------
    # CriticalServices = curated list of services whose absence/failure breaks
    # core OS functionality (RPC, EventLog, LanmanServer, Schedule, W32Time,
    # Netlogon, etc.) or business-critical roles (SQL, Cluster, IIS).
    # Special case: SQLSERVERAGENT being Stopped on an AG SECONDARY replica is
    # NORMAL (Agent only runs on the PRIMARY). We suppress the alert there.
    # ------------------------------------------------------------
    Write-Section "Critical Services"
    Write-Info "  Description: Curated set of services that MUST be running for the OS or"
    Write-Info "               its primary role to function (RPC, EventLog, LanmanServer,"
    Write-Info "               Schedule, W32Time, Netlogon, plus role-specific services)."
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
                        Write-Info "    Impact: An auto-start critical service is offline. Dependent"
                        Write-Info "            features (auth, file share, scheduled tasks) may fail."
                        Write-Info "    Remediation: Start-Service '$($svc.Name)'; if it fails, check"
                        Write-Info "                 System log for the latest error from $($svc.Name)."
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
    # ------------------------------------------------------------
    # Any service set to StartType=Automatic SHOULD be running. If it isn't,
    # either: (a) it crashed and Recovery options aren't restarting it,
    # (b) a dependency failed, or (c) an admin manually stopped it without
    # disabling. NOTE: 'Automatic (Delayed Start)' services may legitimately
    # show Stopped briefly during the first ~2 minutes after boot.
    # ------------------------------------------------------------
    Write-Section "Stopped Automatic Services"
    Write-Info "  Description: Services configured for auto-start that are not running."
    Write-Info "               Indicates crash, failed dependency, or unexplained manual stop."
    Write-Info "               Trigger-start services (e.g. sppsvc, edgeupdate, RemoteRegistry)"
    Write-Info "               are filtered out - they self-stop when their trigger is idle."
    try {
        # Known trigger-start / on-demand auto services that legitimately stop
        # themselves between activations. Listing them as "stopped automatic"
        # is a chronic false-positive and trains operators to ignore the section.
        $triggerStartAllowList = @(
            'sppsvc',          # Software Protection - starts/stops on activation events
            'WbioSrvc',        # Windows Biometric - on-demand
            'TabletInputService',
            'tiledatamodelsvc',
            'RemoteRegistry',  # often disabled by hardening, also trigger-start
            'TrustedInstaller',
            'MapsBroker',      # downloaded maps - triggers on Maps app launch
            'WSearch',         # search service may pause
            'gpsvc',           # rare, but trigger-start in some builds
            'CDPSvc',          # Connected Devices Platform
            'CDPUserSvc',
            'BITS',            # background transfer - explicit start
            'wuauserv',        # Windows Update - trigger-start since Win10
            'InstallService',
            'DoSvc',           # Delivery Optimization - trigger-start
            'WaaSMedicSvc'     # Windows Update medic - trigger-start
        )
        # Edge update / Office click-to-run / GoogleUpdate etc. all share a
        # 'edgeupdate*' / 'gupdate*' / 'OneSync*' naming pattern.
        $triggerStartPatterns = @(
            'edgeupdate*',
            'gupdate*',
            'GoogleUpdate*',
            'MicrosoftEdgeElevation*',
            'ClickToRunSvc*',
            'OneSyncSvc*',
            'WpnUserService*',
            'cbdhsvc*',
            'BcastDVRUserService*',
            'DevicesFlow*',
            'PimIndexMaintenanceSvc*',
            'UnistoreSvc*',
            'UserDataSvc*',
            'InventorySvc*'    # PerSession diagnostic service
        )

        $stoppedAuto = Get-Service -ErrorAction Stop | Where-Object {
            $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'
        }

        # Filter out the known trigger-start / on-demand services
        $reportable = @()
        foreach ($svc in @($stoppedAuto)) {
            if ($triggerStartAllowList -contains $svc.Name) { continue }
            $matchedPattern = $false
            foreach ($p in $triggerStartPatterns) {
                if ($svc.Name -like $p) { $matchedPattern = $true; break }
            }
            if ($matchedPattern) { continue }

            # Final check: ask sc.exe whether the service has a trigger
            # configured. If yes, it's expected to be stopped when idle.
            try {
                $triggerInfo = & sc.exe qtriggerinfo $svc.Name 2>$null
                if ($LASTEXITCODE -eq 0 -and ($triggerInfo -join "`n") -notmatch 'START SERVICE\s*:\s*0') {
                    if (($triggerInfo -join "`n") -match 'START SERVICE') {
                        # Has at least one start trigger - skip
                        continue
                    }
                }
            }
            catch { }

            $reportable += $svc
        }

        if ($reportable.Count -gt 0) {
            Write-DiagWarning "  Found $($reportable.Count) stopped automatic service(s):"
            foreach ($svc in $reportable) {
                Write-DiagWarning "    - $($svc.DisplayName) ($($svc.Name)): $($svc.Status)"
            }
            Write-Info "  Remediation: Start each one and watch System log. Persistent failure"
            Write-Info "               => check service Recovery tab and the dependency chain"
            Write-Info "               via 'sc.exe qc <ServiceName>'."
        }
        else {
            $skipped = (@($stoppedAuto).Count - $reportable.Count)
            if ($skipped -gt 0) {
                Write-Success "  All non-trigger automatic services are running ($skipped trigger-start services skipped)"
            }
            else {
                Write-Success "  All automatic services are running"
            }
        }
    }
    catch {
        Write-DiagError "Failed to enumerate services: $($_.Exception.Message)"
    }
    
    # Disabled services that are typically needed
    # ------------------------------------------------------------
    # StartType=Disabled means the service CANNOT start, even on demand. Often
    # done as 'hardening' (e.g. SecurityHealthService, RemoteRegistry, WinRM)
    # but mis-applied disabling regularly causes outages months later when an
    # admin or feature tries to use the service. Review the list against the
    # server's role: a DC needs Netlogon enabled, a file server needs
    # LanmanServer, an Arc-enrolled box needs himds + GuestConfigArc, etc.
    # ------------------------------------------------------------
    Write-Section "Disabled Services (may need attention)"
    Write-Info "  Description: Services explicitly set to StartType=Disabled. Often the"
    Write-Info "               result of past hardening; verify none are needed by the"
    Write-Info "               server's current role (DC, file server, Arc, RDS, etc.)."
    try {
        $disabledSvcs = @(Get-Service -ErrorAction Stop | Where-Object {
            $_.StartType -eq "Disabled"
        })
        
        if ($disabledSvcs.Count -gt 0) {
            Write-Info "  Found $($disabledSvcs.Count) disabled service(s):"
            # Issue #1: enumerate ALL disabled services so the file-save path captures the
            # full list (previously truncated to 15 entries with "... and N more").
            foreach ($svc in $disabledSvcs) {
                Write-Info "    - $($svc.DisplayName) ($($svc.Name))"
            }
            Write-Info "  Remediation: To re-enable a service:"
            Write-Info "               Set-Service -Name <Name> -StartupType Automatic; Start-Service <Name>"
        }
        else {
            Write-Info "  No disabled services found"
        }
    }
    catch {
        Write-DiagError "Failed to check disabled services: $($_.Exception.Message)"
    }
    
    # Recently crashed services (Event 7034)
    # ------------------------------------------------------------
    # System Event 7034 = 'The X service terminated unexpectedly.'
    # Logged by Service Control Manager when a service process exits without
    # going through the normal Stop sequence. The accompanying message includes
    # how many times the service has crashed since boot - the fact that we see
    # it logged means SCM did NOT successfully restart it via the Recovery tab.
    # Companion events to look for:
    #   1000  - Application Error (the actual exception in the service .exe)
    #   7031  - Service crashed but Recovery action triggered
    #   7032  - Recovery action failed
    # ------------------------------------------------------------
    Write-Section "Recently Crashed/Terminated Services (last 24 hours)"
    Write-Info "  Description: SCM Event 7034 = a service process terminated unexpectedly"
    
    Write-Info "               (no clean Stop). Check Application log Event 1000 around the"
    Write-Info "               same timestamp for the actual unhandled exception/faulting module."
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
            Write-Info "  Remediation: Configure service Recovery actions (sc.exe failure <Name>"
            Write-Info "               reset= 86400 actions= restart/60000/restart/60000/run/60000)"
            Write-Info "               and capture a user-mode dump via WER LocalDumps for the next crash."
        }
        else {
            Write-Success "  No service crashes detected in the last 24 hours"
        }
    }
    catch {
        Write-Info "  Could not query service crash events"
    }

    # W32Time NTP Sync Status
    # ------------------------------------------------------------
    # Time skew > 5 minutes from the domain hierarchy will break Kerberos
    # authentication (KRB_AP_ERR_SKEW), causing logon failures, GPO failures,
    # cluster heartbeat issues, AD replication failures, and SQL AG endpoint
    # auth failures. Stratum tells you where in the time hierarchy you are
    # (1 = direct from a stratum-0 source; 16 = unsynchronized / offline).
    # In an AD domain, every member should sync from its PDC Emulator chain;
    # the PDC Emulator should sync from a reliable external NTP source.
    # ------------------------------------------------------------
    Write-Section "Time Service (NTP) Sync Status"
    Write-Info "  Description: Source = current NTP peer; Stratum = distance from authoritative"
    Write-Info "               clock (1=best, 16=unsynced); Last Sync = recency. >5min skew"
    Write-Info "               from the domain breaks Kerberos => mass auth failures."
    try {
        $w32tmOutput = w32tm /query /status 2>&1
        if ($LASTEXITCODE -eq 0) {
            $sourceMatch  = $w32tmOutput | Select-String 'Source:'
            $stratumMatch = $w32tmOutput | Select-String 'Stratum:'
            $lastSync     = $w32tmOutput | Select-String 'Last Successful Sync Time:'

            $sourceText  = if ($sourceMatch)  { $sourceMatch.Line.Trim() }  else { '' }
            $stratumText = if ($stratumMatch) { $stratumMatch.Line.Trim() } else { '' }
            $lastSyncText= if ($lastSync)     { $lastSync.Line.Trim() }     else { '' }

            if ($sourceText)  { Write-Info "  $sourceText" }
            if ($stratumText) { Write-Info "  $stratumText" }
            if ($lastSyncText){ Write-Info "  $lastSyncText" }

            # Stratum classification
            $stratumValue = $null
            if ($stratumText -match 'Stratum:\s*(\d+)') { $stratumValue = [int]$Matches[1] }
            if ($null -ne $stratumValue) {
                if ($stratumValue -ge 16) {
                    Write-DiagError "  Stratum is $stratumValue - clock is UNSYNCHRONIZED"
                    Write-Info "    Remediation: 'w32tm /resync /force'; check UDP/123 outbound + source NTP server reachability."
                }
                elseif ($stratumValue -ge 6) {
                    Write-DiagWarning "  Stratum is $stratumValue - poor NTP hierarchy depth (target <= 4)"
                    Write-Info "    Likely cause: chained syncing through several intermediates."
                    Write-Info "    Remediation: Point W32Time directly at a known good NTP peer."
                }
                else {
                    Write-Success "  Stratum $stratumValue is healthy"
                }
            }

            # Source classification
            if ($sourceText -match 'VM IC Time') {
                # AD-joined member relying on host clock instead of domain hierarchy
                $isDomainJoined = $false
                try {
                    $isDomainJoined = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
                } catch { }
                if ($isDomainJoined) {
                    Write-DiagWarning "  Time source is the Hyper-V host (VM IC Time Synchronization Provider)."
                    Write-Info "    Domain members should sync from the AD time hierarchy, not the host."
                    Write-Info "    Remediation: Disable the 'Time synchronization' integration service on"
                    Write-Info "                 the VM, or run 'w32tm /config /syncfromflags:domhier /update'"
                    Write-Info "                 then 'Restart-Service W32Time'."
                }
                else {
                    Write-Info "  (Workgroup VM syncing from Hyper-V host - acceptable.)"
                }
            }

            # Last-sync recency
            if ($lastSyncText -match 'Last Successful Sync Time:\s*(.+)$') {
                $lastSyncRaw = $Matches[1].Trim()
                [datetime]$lastSyncDate = [datetime]::MinValue
                if ([datetime]::TryParse($lastSyncRaw, [ref]$lastSyncDate) -and $lastSyncDate -gt [datetime]::MinValue) {
                    $hoursSince = ((Get-Date) - $lastSyncDate).TotalHours
                    if ($hoursSince -gt 24) {
                        Write-DiagWarning "  Last successful sync was $([math]::Round($hoursSince,1)) hours ago - clock may be drifting"
                    }
                }
                elseif ($lastSyncRaw -match 'unspecified|never') {
                    Write-DiagWarning "  NTP has never synced successfully"
                    Write-Info "    Impact: Clock will drift; Kerberos auth will fail when skew > 5 min."
                    Write-Info "    Remediation: 'w32tm /resync /force'; check UDP/123 outbound."
                }
            }
            elseif (-not $lastSyncText) {
                Write-DiagWarning "  NTP has never synced successfully"
                Write-Info "    Impact: Clock will drift; Kerberos auth will fail when skew > 5 min."
                Write-Info "    Remediation: 'w32tm /resync /force' then 'w32tm /query /status' again."
                Write-Info "                 If still failing, check the source with 'w32tm /query /source'"
                Write-Info "                 and firewall UDP/123 outbound."
            }
        }
        else {
            Write-DiagWarning "  W32Time service may not be running"
            Write-Info "    Remediation: Start-Service W32Time; Set-Service W32Time -StartupType Automatic"
        }
    }
    catch {
        Write-DiagWarning "  Could not check NTP status: $($_.Exception.Message)"
    }

    # Task Scheduler Health
    # ------------------------------------------------------------
    # Errors here usually fall into a few buckets:
    #   - Stored credentials no longer valid (account password rotated/expired)
    #   - 'At log on' / 'On idle' triggers on missing user accounts
    #   - Action exe path no longer exists (after uninstall/upgrade)
    #   - Task running under SYSTEM but trying to access mapped drives
    # The Operational log surfaces these as Level 1 (critical) / 2 (error).
    # The full Task Scheduler diagnostic deep-dive lives in its own section.
    # ------------------------------------------------------------
    Write-Section "Task Scheduler Health"
    Write-Info "  Description: High-level scan of TaskScheduler/Operational error events."
    Write-Info "               Common causes: stale stored creds, missing exe paths, accounts"
    Write-Info "               that no longer exist. See dedicated Task Scheduler section for detail."
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
            Write-Info "  Remediation: Open Task Scheduler, sort by 'Last Run Result' != 0x0,"
            Write-Info "               re-enter credentials, fix action paths, or use the dedicated"
            Write-Info "               Task Scheduler diagnostic option for a focused report."
        }
        else {
            Write-Success "  No Task Scheduler errors in last 24 hours"
        }
    }
    catch {
        Write-Info "  Task Scheduler Operational log not accessible"
    }

    # EventLog Service Errors
    # ------------------------------------------------------------
    # System Event 1108 = 'The Event Logging service encountered an error
    # while processing an incoming event published from <provider>.'
    # Why it matters: when 1108s appear, you are LOSING event records (the
    # log subsystem itself is dropping them). Common root causes:
    #   - Malformed manifest from a 3rd-party provider
    #   - Disk full on %WinDir%\System32\winevt\Logs
    #   - Permissions on a custom .evtx file
    #   - High-volume audit policy overrunning the log subsystem
    # If 1108 is firing, NOTHING in the System/Security/Application logs is
    # 100% trustworthy until you fix the underlying cause.
    # ------------------------------------------------------------
    Write-Section "EventLog Service Errors"
    Write-Info "  Description: Event 1108 = the EventLog service itself is dropping events."
    Write-Info "               Severity is HIGH - your audit/diagnostic trail has gaps."
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
            Write-Info "  Remediation: Check disk space on %WinDir%\System32\winevt\Logs;"
            Write-Info "               identify the offending provider in the message and update"
            Write-Info "               or uninstall it; if Security log is overrunning, retune"
            Write-Info "               audit policy or increase log size (wevtutil sl Security /ms:)."
        }
        else {
            Write-Success "  No EventLog service errors"
        }
    }
    catch { Write-Info "  Could not query EventLog errors" }

    # Netlogon / Domain Connectivity Events
    # ------------------------------------------------------------
    # Event ID reference (System log):
    #   5719  - Netlogon : 'No Domain Controller is available for domain X'
    #           => DNS, network, or ALL DCs unreachable. Auth will fail.
    #   7023  - SCM      : 'The X service terminated with the following error'
    #           Often pairs with a service that depends on Netlogon/RPC.
    #   7024  - SCM      : 'The X service terminated with service-specific
    #           error <code>'. The error code is usually the real story.
    # IMPORTANT: 7023/7024 are SCM events used by ALL services - we surface
    # them here because Netlogon/auth-stack issues frequently cascade into
    # them. The text payload identifies the actual service.
    # ------------------------------------------------------------
    Write-Section "Netlogon Events"
    Write-Info "  Description: 5719 = no DC reachable (DNS/network/all-DCs-down)."
    Write-Info "               7023/7024 = a service failed to start (often cascades from"
    Write-Info "               Netlogon/RPC failure). Look at the message for the real cause."
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
            Write-Info "  Remediation: For 5719: 'nltest /sc_query:<DOMAIN>' to test secure channel;"
            Write-Info "               'nltest /dsgetdc:<DOMAIN>' to find a DC; verify DNS server list"
            Write-Info "               on the NIC. For 7023/7024: open the related service in services.msc,"
            Write-Info "               check dependencies (services.msc -> Properties -> Dependencies)."
        }
        else {
            Write-Success "  No Netlogon connectivity issues"
        }
    }
    catch { Write-Info "  Could not query Netlogon events" }

    # RDP Licensing Service
    # ------------------------------------------------------------
    # On RDS (Remote Desktop Session Host) servers, the RD Licensing service
    # issues per-device or per-user CALs. If the service is stopped or no RD
    # License Server is reachable, users hit the 120-day grace period - and
    # after expiry, RDP sessions are refused with 'No Remote Desktop license
    # servers available'. Common system events:
    #   1128 - 'RD Session Host server cannot connect to license server'
    #   1129 - 'RD Session Host server cannot issue a license'
    # Note: TermServLicensing is only present if the RD Licensing role is
    # installed; absence is normal on non-RDS servers.
    # ------------------------------------------------------------
    Write-Section "RDP Licensing"
    Write-Info "  Description: Status of RD Licensing service + recent license issuance errors."
    Write-Info "               Only meaningful on RDS / RD Session Host servers."
    try {
        $rdpLic = Get-Service -Name "TermServLicensing" -ErrorAction SilentlyContinue
        if ($null -ne $rdpLic) {
            Write-Info "  TermServLicensing: $($rdpLic.Status) ($($rdpLic.StartType))"
        }
        else {
            Write-Info "  TermServLicensing service not present (not an RD Licensing server)"
        }
        $rdpEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1128, 1129
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 3 -ErrorAction SilentlyContinue
        if ($rdpEvents) {
            Write-DiagWarning "  RDP licensing errors found in last 7 days"
            Write-Info "    Impact: New RDP sessions may fail once the 120-day grace period ends."
            Write-Info "    Remediation: Verify the RD License Server is online and reachable from"
            Write-Info "                 this host; confirm the licensing mode in 'Set-RDLicenseConfiguration'."
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
        # ------------------------------------------------------------
        # When an event log fills, the default retention policy 'Overwrite events
        # as needed' silently rotates - meaning historical evidence for an
        # incident may already be GONE by the time you investigate. Critical for
        # Security log especially: high-volume audit policy + small max size =
        # only a few hours of audit history retained.
        # ------------------------------------------------------------
        Write-Info "  Description: Current size vs configured maximum. >90% full ="
        Write-Info "               imminent rollover. Historical events may already be lost."
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
                Write-Info "    Remediation: 'wevtutil sl $logName /ms:268435456' (sets max to 256 MB)"
                Write-Info "                 or archive with 'wevtutil epl $logName archive.evtx'."
            }
        }
        catch {
            Write-DiagWarning "  Could not retrieve $logName log properties"
        }
        
        # Scan for Critical and Error events in last 24 hours
        # ------------------------------------------------------------
        # Level 1 = Critical, Level 2 = Error. We pull the last 24 h, group by
        # (EventID, ProviderName) so a recurring single event isn't masked by
        # a one-off flood of unrelated errors. Top 10 by frequency are the
        # actionable signal; the trailing list of 5 most-recent is for context.
        # ------------------------------------------------------------
        Write-Info "  Description: Critical (Level 1) + Error (Level 2) events in last 24h."
        Write-Info "               Grouped by EventID+Provider so recurring failures stand out."
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
    # ------------------------------------------------------------
    # System Event ID reference for Failover Clustering:
    #   1135 - 'Cluster node X was removed from the active failover cluster
    #          membership.' = a node lost heartbeat / quorum and was evicted.
    #          Almost always points to network blip or PAUSED-by-monitoring.
    #   1672 - 'Cluster node X is not joined to the cluster' (quarantine).
    #          Triggered when a node fails 3+ times in 1 hour - quarantined
    #          for 2 hours and cannot re-join automatically.
    # Both events almost always correlate with one of:
    #   - Network adapter / NIC driver flap (check Section 'Network Adapter Error Events')
    #   - VMQ-related packet drops on Hyper-V hosts
    #   - SAN / iSCSI path loss
    #   - Antivirus filter holding a registry key during cluster snapshot
    # ------------------------------------------------------------
    Write-Section "Cluster Heartbeat/Quarantine Events (last 7 days)"
    Write-Info "  Description: 1135 = node evicted from cluster (heartbeat/quorum loss)."
    Write-Info "               1672 = node quarantined after 3+ failures in 1 hour."
    Write-Info "               Correlate timestamps with NIC events + storage path events."
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
            Write-Info "  Remediation: Run 'Get-ClusterLog -TimeSpan 60 -Destination C:\Temp'"
            Write-Info "               and search for 'STATUS_LIVEDUMP_GENERATED' or 'NETFT' entries"
            Write-Info "               near the event time. Verify cluster network priority order"
            Write-Info "               with 'Get-ClusterNetwork | Select Name,Role,Metric'."
        }
        else {
            Write-Success "  No cluster heartbeat/quarantine events"
        }
    }
    catch { Write-Info "  Failover Clustering may not be installed" }

    # FailoverClustering Operational Log (v3.0 cluster-safe)
    # ------------------------------------------------------------
    # The Operational channel captures Critical / Error / Warning entries from
    # the cluster service that don't always surface in System log. Common IDs
    # of interest:
    #   1146  - RHS (Resource Host) terminated unexpectedly
    #   1230  - Cluster resource entered FAILED state
    #   1564  - File Share Witness offline (FSW path unreachable)
    #   1561  - Cluster lost quorum
    #   1809  - Cluster heartbeat dropped
    # We collect Levels 1/2/3 (Critical/Error/Warning) over 24 h, group by
    # ID for at-a-glance frequency, then sample 3 for context.
    # ------------------------------------------------------------
    if ($script:ClusterEnv.IsClusterNode) {
        Write-Section "Failover Clustering Operational Log (last 24h)"
        Write-Info "  Description: Critical/Error/Warning entries from the cluster service."
        Write-Info "               Watch for 1146 (RHS crash), 1230 (resource failed), 1564 (FSW lost),"
        Write-Info "               1561 (quorum lost), 1809 (heartbeat dropped)."
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
    # ------------------------------------------------------------
    # System Event ID reference (Provider = disk / storahci / iaStorAVC / etc.):
    #   129 - 'Reset to device, \Device\RaidPort0, was issued.' = the storage
    #         driver had to issue a SCSI bus reset because the controller stopped
    #         responding to a command in time. Often the precursor to a RAID
    #         path failover or to data-corruption events.
    #   153 - 'The IO operation at logical block address X was retried.' = a
    #         transient I/O failure that the driver recovered from. Single events
    #         are routine; >10/day on the same disk = degrading drive or path.
    # Both IDs are reused by SOME unrelated providers, but on Server SKUs they
    # are overwhelmingly storage-related. Cross-reference with the 'Disk' section.
    # ------------------------------------------------------------
    Write-Section "Storage Adapter Events (129/153, last 7 days)"
    Write-Info "  Description: 129 = storage driver issued bus reset (controller hung)."
    Write-Info "               153 = transient I/O retry (>10/day on same disk = degrading)."
    Write-Info "               Correlate with disk latency spikes in the Disk diagnostic."
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
            Write-Info "  Remediation: Update HBA / RAID controller firmware + driver to vendor's"
            Write-Info "               latest. Run 'Get-PhysicalDisk | ? HealthStatus -ne Healthy'."
            Write-Info "               If on SAN, ask storage team to check fabric / array logs at"
            Write-Info "               the same timestamps for path errors."
        }
        else {
            Write-Success "  No storage adapter errors"
        }
    }
    catch { }

    # DNS Update Failures (1196)
    # ------------------------------------------------------------
    # System Event ID reference (Provider = NETLOGON / DnsApi):
    #   8018 - 'Active Directory could not register DNS records' (DC-side)
    #   8019 - 'DNS update failed for hostname X.Y.Z'
    # Triggered when the host tries to dynamically register/refresh its A/PTR
    # record and the DNS server refuses or is unreachable. Symptoms: stale
    # records pointing to an old IP, name resolution failures from peers,
    # Kerberos ticket failures (SPN/host mismatch).
    # NOTE: A/PTR registration relies on UPDATE permission; on Secure-only
    # zones, only the matching computer account can update its own records.
    # ------------------------------------------------------------
    Write-Section "DNS Update Failure Events"
    Write-Info "  Description: 8018/8019 = host failed to dynamically register its A/PTR"
    Write-Info "               record. Result: stale DNS, name resolution failures from peers,"
    Write-Info "               possible Kerberos issues."
    try {
        $dnsEvts = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 8018, 8019
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($dnsEvts) {
            Write-DiagWarning "  Found $($dnsEvts.Count) DNS dynamic update failure(s)"
            Write-Info "  Remediation: 'ipconfig /registerdns' to force re-registration; check"
            Write-Info "               that the DNS server allows secure dynamic updates and the"
            Write-Info "               computer account has Write permission on its DNS record."
        }
        else {
            Write-Success "  No DNS update failures"
        }
    }
    catch { }

    # Known Critical Event Summary (from $script:KnownCriticalEventIDs)
    # ------------------------------------------------------------
    # $script:KnownCriticalEventIDs is a hand-curated lookup of high-impact
    # event IDs the support team has decided are 'never normal' (e.g. bugcheck
    # 1001, USER32 1074 unplanned shutdown, SCM 7001 dependency failure, etc.).
    # Defined near the top of the script under #region Constants.
    # We surface ANY occurrence in the last 24 h - even one is worth noting.
    # ------------------------------------------------------------
    Write-Section "High-Priority Event Summary (last 24h)"
    Write-Info "  Description: Curated list of high-impact event IDs (bugcheck, unplanned"
    
    Write-Info "               shutdown, SCM dependency failure, etc.). Even one occurrence"
    Write-Info "               in the last 24 h warrants investigation."
    $foundAny = $false
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
                    $foundAny = $true
                }
            }
            catch { }
        }
    }
    if (-not $foundAny) {
        Write-Success "  No high-priority events found in the last 24 hours"
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
    # ------------------------------------------------------------
    # Dnscache (DNS Client) is the user-mode service that caches name lookups,
    # handles dynamic registration, and proxies queries to the configured
    # resolvers. If it's stopped, every name resolution falls back to a direct
    # query and registry/HOSTS-file behavior changes - many apps will appear
    # 'slow' and dynamic A/PTR record updates won't happen at boot.
    # ------------------------------------------------------------
    Write-Section "DNS Client Service Status"
    Write-Info "  Description: The Dnscache service handles name resolution + dynamic A/PTR"
    Write-Info "               registration. Stopped = direct queries on every lookup, no"
    Write-Info "               registration at boot, slow application name resolution."
    try {
        $dnsClient = Get-Service -Name "Dnscache" -ErrorAction Stop
        if ($dnsClient.Status -eq "Running") {
            Write-Success "  DNS Client service is running"
        }
        else {
            Write-DiagError "  DNS Client service is NOT running: $($dnsClient.Status)"
            Write-Info "    Remediation: Start-Service Dnscache; Set-Service Dnscache -StartupType Automatic"
        }
    }
    catch {
        Write-DiagError "  Could not check DNS Client service: $($_.Exception.Message)"
    }
    
    # Configured DNS servers per adapter
    # ------------------------------------------------------------
    # The IPv4 DNS server list per active NIC plus a sub-50ms ping check on each.
    # Common pitfalls:
    #   - Empty server list on a NIC that's actually being used (DHCP failed)
    #   - Public resolver (8.8.8.8) listed on a domain-joined server -> AD
    #     SRV lookups won't resolve (kerberos/group policy will fail)
    #   - Multiple NICs each with their own DNS list -> 'split-horizon' query
    #     order can be unpredictable (see Get-DnsClientNrptPolicy)
    # ------------------------------------------------------------
    Write-Section "Configured DNS Servers"
    Write-Info "  Description: IPv4 DNS resolver list per active NIC, with reachability /"
    Write-Info "               latency check. Domain members must use AD DNS, NOT public 8.8.8.8."
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" })

        # Storage / heartbeat NICs (SMB Direct, iSCSI, cluster heartbeat) deliberately
        # have NO DNS servers configured - DNS on a non-default-route NIC can confuse
        # the resolver. Don't WARN for these; emit INFO instead.
        $storageNicPattern = '(?i)SMB|Storage|Heartbeat|Cluster|vMotion|LiveMigration|RDMA|iSCSI|Backup|Repl'

        # Pre-scan: does ANY adapter have DNS configured? If at least one does,
        # missing DNS on others is far more likely a deliberate choice than breakage.
        $anyDnsConfigured = $false
        foreach ($a in $adapters) {
            $d = Get-DnsClientServerAddress -InterfaceAlias $a.Name -ErrorAction SilentlyContinue |
                Where-Object { $_.AddressFamily -eq 2 }
            if ($null -ne $d -and $null -ne $d.ServerAddresses -and $d.ServerAddresses.Count -gt 0) {
                $anyDnsConfigured = $true; break
            }
        }

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
                $isStorageNic = $adapter.Name -match $storageNicPattern
                if ($isStorageNic -and $anyDnsConfigured) {
                    Write-Info "  $($adapter.Name): No DNS servers configured (expected on storage/heartbeat NIC)"
                }
                elseif ($anyDnsConfigured) {
                    # Other NIC has DNS; this one missing it is mildly unusual but rarely a real outage
                    Write-Info "  $($adapter.Name): No DNS servers configured (resolver will use other NIC)"
                }
                else {
                    Write-DiagWarning "  $($adapter.Name): No DNS servers configured"
                }
            }
        }
    }
    catch {
        Write-DiagError "Failed to check DNS configuration: $($_.Exception.Message)"
    }
    
    # DNS resolution tests
    # ------------------------------------------------------------
    # Two external (microsoft.com / google.com) + the local computer's domain.
    # External tests prove resolver path + internet egress; local-domain test
    # proves the AD DNS chain works for SRV/Kerberos discovery.
    # NOTE: A successful resolution here does NOT prove DNSSEC validation -
    # use 'Resolve-DnsName -DnsSecOk' if DNSSEC matters in your environment.
    # ------------------------------------------------------------
    Write-Section "DNS Resolution Tests"
    Write-Info "  Description: External (microsoft.com / google.com) + local domain."
    Write-Info "               Failures here = resolver path broken, firewall block, or"
    Write-Info "               configured DNS servers themselves down."
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
    # ------------------------------------------------------------
    # The local DNS resolver cache holds answers up to their TTL. We surface a
    # count + a small sample so an operator can spot stale CNAME/A entries that
    # are 'sticking' due to long TTLs (>1 hour) - common cause of post-DR or
    # post-failover apps still hitting the OLD endpoint.
    # ------------------------------------------------------------
    Write-Section "DNS Cache Statistics"
    Write-Info "  Description: Local resolver cache contents. Stale entries with long TTLs"
    Write-Info "               (>1 hour) are a common cause of post-failover 'wrong endpoint'"
    Write-Info "               issues. Flush with 'ipconfig /flushdns' if needed."
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
    # ------------------------------------------------------------
    # A "BADKEY" response from the DNS server during a TSIG-signed dynamic
    # update means the requesting principal's signing key (typically the AD
    # computer/cluster name object) does not match the key the DNS server
    # expects, OR the principal does not have permission to update the record.
    # On a Failover Cluster, this most often manifests as the Cluster Name
    # Object (CNO) or Virtual Computer Object (VCO) being unable to update its
    # A record after a failover -> stale DNS pointing to the previous owner.
    # NOTE: Querying 'DNS Server' log only works on machines actually running
    # the DNS Server role; on a member server the catch returns 'not available'.
    # ------------------------------------------------------------
    Write-Section "DNS Bad Key Errors (cluster CNO/VCO failures)"
    Write-Info "  Description: BADKEY = TSIG-signed dynamic update was rejected. Common"
    Write-Info "               cluster CNO/VCO failure - cluster name cannot update its A"
    Write-Info "               record after failover, leaving stale DNS pointing to old owner."
    try {
        $badKeyEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'DNS Server'
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*BADKEY*" -or $_.Message -like "*Bad Key*" }

        if ($badKeyEvents) {
            Write-DiagError "  Found $($badKeyEvents.Count) DNS Bad Key event(s) in last 7 days!"
            Write-Info "  This typically means cluster name objects (CNO/VCO) cannot update DNS"
            Write-Info "  Fix: Grant the cluster computer object 'Full Control' on the DNS record"
            Write-Info "       (DNS Manager -> right-click record -> Properties -> Security tab),"
            Write-Info "       OR delete the stale DNS record and let the CNO re-register."
        }
        else {
            Write-Success "  No DNS Bad Key errors"
        }
    }
    catch {
        Write-Info "  DNS Server log not available (server may not have DNS role)"
    }

    # Cluster Listener Name Resolution
    # ------------------------------------------------------------
    # The Cluster Name (CNO) is the network identity used by clients to reach
    # the cluster. If the CNO does not resolve, every client connecting via the
    # cluster's virtual name (file shares, generic services) breaks - even though
    # the underlying nodes are individually reachable.
    # ------------------------------------------------------------
    Write-Section "Cluster Name Resolution"
    Write-Info "  Description: The Cluster Name Object (CNO) is the virtual name clients use."
    Write-Info "               Resolution failure = no client can reach the cluster identity"
    Write-Info "               even if the underlying nodes are healthy."
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
    # ------------------------------------------------------------
    # SQL AlwaysOn Availability Group Listeners are virtual network names backed
    # by Windows cluster resources. If the listener DNS record is stale (still
    # points to the previous PRIMARY's IP) after a failover, applications using
    # the listener experience login timeouts even though SQL is healthy on the
    # new PRIMARY. This is the #1 cause of post-failover AG connectivity issues.
    # ------------------------------------------------------------
    if ($script:ClusterEnv.IsAGInstalled -and $script:ClusterEnv.AGDetails.Count -gt 0) {
        Write-Section "AG Listener Name Resolution"
        Write-Info "  Description: SQL AG listener virtual name. Stale DNS post-failover is"
        Write-Info "               the #1 cause of AG client connection timeouts."
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
    # ------------------------------------------------------------
    # Same 8018/8019 IDs surfaced in the Event Log section, but here in the
    # context of DNS health (is the host's own A/PTR registration current?).
    # If failing, expect symptoms like:
    #   - Other servers cannot reach this host by name
    #   - Kerberos failures (SPN <-> A record mismatch)
    #   - GPO 'computer config' policies failing to apply
    # ------------------------------------------------------------
    Write-Section "DNS Dynamic Update Failures"
    Write-Info "  Description: 8018/8019 = host failed to register/refresh its A/PTR. Other"
    Write-Info "               servers may not be able to resolve this host's name."
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
            Write-Info "  Remediation: 'ipconfig /registerdns' to retry; verify the DNS zone"
            Write-Info "               allows secure dynamic updates and the computer object"
            Write-Info "               has Write permission on its DNS record."
        }
        else {
            Write-Success "  No DNS dynamic update failures"
        }
    }
    catch { }

    # Reverse DNS Check
    # ------------------------------------------------------------
    # Reverse zones (in-addr.arpa) map IP -> name. Many enterprise services rely
    # on PTR records:
    #   - Email servers (anti-spam reverse-lookup)
    #   - Kerberos (SPN validation in some configurations)
    #   - SQL Server log shipping with hostnames
    #   - Audit / SIEM reverse-resolution for IP source enrichment
    # We sample the first 2 IPs to keep this fast on multi-NIC servers.
    # ------------------------------------------------------------
    Write-Section "Reverse DNS Lookup"
    Write-Info "  Description: PTR (reverse) lookup for the server's first 2 IPs. Missing"
    Write-Info "               PTRs break SMTP anti-spam, some Kerberos paths, and SIEM"
    Write-Info "               IP-to-hostname enrichment."
    try {
        $serverIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' }
        foreach ($ip in $serverIPs | Select-Object -First 2) {
            try {
                $ptr = Resolve-DnsName $ip.IPAddress -Type PTR -ErrorAction Stop
                Write-Success "  $($ip.IPAddress) -> $($ptr.NameHost)"
            }
            catch {
                Write-DiagWarning "  $($ip.IPAddress) -> No PTR record (reverse DNS missing)"
                Write-Info "    Remediation: Create PTR in the matching in-addr.arpa zone, or"
                Write-Info "                 enable PTR auto-creation on the forward zone properties."
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
    # ------------------------------------------------------------
    # Local 'net accounts' surfaces three policy settings that determine how
    # the OS responds to bad-password floods:
    #   Lockout threshold           = N bad attempts before account locks
    #   Lockout duration            = how long it stays locked (minutes)
    #   Lockout observation window  = sliding window for counting attempts
    # NOTE: On a domain-joined machine, the domain GPO usually OVERRIDES the
    # local policy shown here for domain accounts. We still surface local
    # policy because it applies to local accounts (e.g. local Administrator).
    # ------------------------------------------------------------
    Write-Section "Account Lockout Policy"
    Write-Info "  Description: Local lockout settings (threshold/duration/observation window)."
    Write-Info "               Domain GPO overrides these for domain accounts; local policy"
    Write-Info "               still applies to local accounts (e.g. local Administrator)."
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
            Write-Info "    Impact: Accounts can be brute-forced indefinitely with no lockout."
            Write-Info "    Remediation: 'net accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30'"
            Write-Info "                 (or apply the equivalent GPO from a Domain Controller)."
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve lockout policy"
    }
    
    # Recent failed logon events (Event 4625)
    # ------------------------------------------------------------
    # Security Event 4625 = 'An account failed to log on.' Requires the audit
    # policy 'Audit Logon - Failure' to be enabled (it usually is by default
    # on Server 2016+). The XML payload contains TargetUserName + IpAddress
    # which we extract to spot:
    #   - One account being repeatedly hammered (likely brute force)
    #   - One source IP probing many accounts (password spraying)
    # We sample the top 5 targeted accounts; the source IP grouping is left
    # to the operator's manual follow-up if needed.
    # ------------------------------------------------------------
    Write-Section "Recent Failed Logon Attempts (last 24 hours)"
    Write-Info "  Description: Security Event 4625 = failed logon. Requires 'Audit Logon"
    Write-Info "               (Failure)' policy enabled. Top 5 targeted accounts shown."
    Write-Info "               High count on one account = brute force; low count across many"
    Write-Info "               accounts from one IP = password spraying."
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
    # ------------------------------------------------------------
    # 'klist' lists the Kerberos tickets currently cached for the running user.
    # Useful checks:
    #   - Cached Tickets count = 0 -> user has not authenticated to AD this
    #     session, OR Kerberos is failing and falling back to NTLM
    #   - Server: krbtgt/<DOMAIN> -> the TGT (Ticket Granting Ticket); without
    #     this nothing else will work
    #   - Long expired tickets still cached -> stale; 'klist purge' to clear
    # NOTE: This shows tickets for the WSTT-running user only. Use 'klist -li 0x3e7'
    # for SYSTEM (computer account) tickets.
    # ------------------------------------------------------------
    Write-Section "Kerberos Ticket Status"
    Write-Info "  Description: Cached Kerberos tickets for the current user. Count=0 means"
    Write-Info "               no AD auth this session OR Kerberos failed and fell back to NTLM."
    Write-Info "               For SYSTEM (computer-account) tickets use 'klist -li 0x3e7'."
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
    # ------------------------------------------------------------
    # Every domain-joined computer maintains a 'secure channel' to a Domain
    # Controller using the computer-account password (rotated every ~30 days
    # by Netlogon). If the local machine and AD disagree on this password
    # (typical causes: VM rolled back from snapshot, machine rejoined after
    # being orphaned, replication divergence), the secure channel breaks and
    # symptoms include:
    #   - 'Trust relationship between this workstation and primary domain failed'
    #   - GPO doesn't apply
    #   - Group Policy errors 1058/1006/1030
    # Repair: Test-ComputerSecureChannel -Repair (needs domain-admin creds) OR
    # 'netdom resetpwd /server:<DC> /userd:<admin> /passwordd:*'
    # ------------------------------------------------------------
    Write-Section "Domain Secure Channel"
    Write-Info "  Description: Computer-account password sync between this host and AD."
    Write-Info "               Broken = 'trust relationship failed' errors, GPO failures,"
    Write-Info "               group policy events 1058/1006/1030."
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
                Write-Info "       (provide a domain admin credential when prompted). Alternative:"
                Write-Info "       'netdom resetpwd /server:<DC> /userd:<admin> /passwordd:*'."
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
    # ------------------------------------------------------------
    # Three profiles - Domain, Private, Public. Default behaviour SHOULD be
    # all three Enabled with Inbound=Block, Outbound=Allow. Common mistakes:
    #   - Disabling the Public profile so 'wifi just works' on a server
    #   - Setting DefaultInboundAction=Allow to 'troubleshoot' and forgetting
    #   - Per-rule allows piling up over time; the 'show rule' export is the
    #     real audit (see Network Diagnostics 'Firewall Rules on Common Ports')
    # ------------------------------------------------------------
    Write-Section "Windows Firewall Status"
    Write-Info "  Description: Per-profile (Domain/Private/Public) enabled state + default"
    Write-Info "               actions. Disabling a profile = NO host firewall on networks of"
    Write-Info "               that type. Default Inbound MUST be Block on a hardened server."
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($fwProfile in $fwProfiles) {
            $status = if ($fwProfile.Enabled) { "ENABLED" } else { "DISABLED" }
            
            if ($fwProfile.Enabled) {
                Write-Success "  $($fwProfile.Name): $status (Inbound: $($fwProfile.DefaultInboundAction), Outbound: $($fwProfile.DefaultOutboundAction))"
            }
            else {
                Write-DiagWarning "  $($fwProfile.Name): $status"
                Write-Info "    Remediation: Set-NetFirewallProfile -Profile $($fwProfile.Name) -Enabled True"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check Firewall status: $($_.Exception.Message)"
    }

    # Account Lockout Events (4740)
    # ------------------------------------------------------------
    # Security Event 4740 = 'A user account was locked out.' Logged on the DC
    # that processed the lockout (so on a member server you'll only see locals).
    # The first Property of the event = locked-out account name; we group on it.
    # If you see the same account locking out repeatedly, check:
    #   - Stored credentials in saved RDP files, scheduled tasks, IIS app pools
    #   - Service accounts whose password was changed but a reference was missed
    #   - Mobile devices with cached old passwords (ActiveSync / Outlook)
    # ------------------------------------------------------------
    Write-Section "Account Lockout Events (4740, last 24h)"
    Write-Info "  Description: Event 4740 = account was locked out. On member servers, only"
    Write-Info "               local-account lockouts appear here. For domain accounts, query"
    Write-Info "               the DC that holds the PDC Emulator role."
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
            Write-Info "  Remediation: Find the source of bad-password attempts using the LockoutStatus"
            Write-Info "               sysinternals tool, or query Event 4625 across all DCs grouped by"
            Write-Info "               IpAddress / WorkstationName for the locked-out account."
        }
        else {
            Write-Success "  No account lockouts in last 24 hours"
        }
    }
    catch {
        Write-Info "  Could not query lockout events (Security log may require audit policy)"
    }

    # Logon as a Service Policy
    # ------------------------------------------------------------
    # SeServiceLogonRight = the SIDs allowed to host a Windows service. Every
    # service identity that's not LocalSystem / LocalService / NetworkService
    # MUST appear in this list, otherwise the service fails to start with:
    #   1069 'The service did not start due to a logon failure.'
    # We export the local security policy via secedit and parse the right.
    # SECURITY: secedit's output contains policy data; we tighten the temp file
    # ACL to current-user + SYSTEM only before reading, then delete it.
    # ------------------------------------------------------------
    Write-Section "Logon as a Service Policy"
    Write-Info "  Description: SeServiceLogonRight = identities allowed to run as a service."
    Write-Info "               Missing from this list = service fails with Event 1069 'logon failure'."
    try {
        $tmpFile = Join-Path $env:TEMP "secedit_export_$([System.Guid]::NewGuid().ToString('N')).cfg"
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
    # ------------------------------------------------------------
    # System Event ID reference (Provider = Schannel):
    #   36870 - 'A fatal error occurred when attempting to access the SSL
    #           server credential private key.' = the cert's private key is
    #           inaccessible (ACL on MachineKeys folder is wrong, key was
    #           moved/deleted, or the cert was imported without 'mark key
    #           exportable').
    #   36871 - 'A fatal error occurred while creating an SSL client credential.'
    #           Often paired with 36870; client side of the same problem.
    #   36874 - 'An TLS 1.x connection request was received from a remote
    #           client application, but none of the cipher suites supported
    #           by the client application are supported by the server.'
    #           = TLS version / cipher suite mismatch (client TLS 1.0 hitting
    #           a TLS 1.2-only server, or DH/RSA cipher requirements).
    # ------------------------------------------------------------
    Write-Section "Schannel TLS Errors"
    Write-Info "  Description: 36870/36871 = TLS cert private key inaccessible (ACL/missing key)."
    Write-Info "               36874 = client/server TLS version or cipher suite mismatch."
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
    # ------------------------------------------------------------
    # Security Event 4624 = 'An account was successfully logged on.' Property
    # index [14] is the AuthenticationPackageName. Healthy modern servers
    # should overwhelmingly use Kerberos; high NTLM share suggests:
    #   - SPN missing on the target service (Kerberos can't find a target)
    #   - Connection by IP instead of hostname (NTLM-only path)
    #   - Cross-trust / cross-forest path with broken Kerberos delegation
    #   - Legacy clients/scripts that explicitly request NTLM
    # NTLMv1 in particular is a major audit / compliance finding (cracked in
    # seconds on modern hardware) - check Event 4624 + property 'LmPackageName'.
    # ------------------------------------------------------------
    Write-Section "Authentication Protocol Usage (last 100 logons)"
    Write-Info "  Description: Kerberos vs NTLM ratio over last 100 successful logons."
    Write-Info "               High NTLM share = SPN issues, IP-based connections, or legacy"
    Write-Info "               clients. NTLMv1 in particular is a compliance finding."
    try {
        $logonEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 100 -ErrorAction SilentlyContinue

        if ($logonEvents) {
            $ntlmCount = 0
            $kerbCount = 0
            $unknownCount = 0
            foreach ($evt in $logonEvents) {
                try {
                    # Use named XML field lookup instead of a fixed Properties[14]
                    # index. The position of AuthenticationPackageName in 4624
                    # has shifted between Windows versions, which caused this
                    # check to silently report 0/0 on Server 2025.
                    $authPkg = $null
                    try {
                        [xml]$xml = $evt.ToXml()
                        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'AuthenticationPackageName' } | Select-Object -First 1
                        if ($node) { $authPkg = [string]$node.'#text' }
                        if (-not $authPkg) {
                            $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LmPackageName' } | Select-Object -First 1
                            if ($node) { $authPkg = [string]$node.'#text' }
                        }
                    }
                    catch { }

                    # Fallback to positional property if XML parse failed
                    if (-not $authPkg -and $evt.Properties.Count -gt 14) {
                        $authPkg = [string]$evt.Properties[14].Value
                    }

                    if ($authPkg -match '^NTLM' -or $authPkg -like 'NtLm*') { $ntlmCount++ }
                    elseif ($authPkg -eq 'Kerberos') { $kerbCount++ }
                    elseif ($authPkg -eq 'Negotiate') {
                        # Negotiate wraps Kerberos OR NTLM. Treat as Kerberos
                        # only if LmPackageName is empty/'-'.
                        $kerbCount++
                    }
                    else { $unknownCount++ }
                }
                catch { $unknownCount++ }
            }
            Write-Info "  Kerberos logons: $kerbCount"
            Write-Info "  NTLM logons: $ntlmCount"
            if ($unknownCount -gt 0) {
                Write-Info "  Unclassified logons: $unknownCount (auth package not reported)"
            }
            if ($ntlmCount -eq 0 -and $kerbCount -eq 0) {
                Write-Info "  No classifiable logon events in the last 24h (host may be idle or"
                Write-Info "  Audit Logon Events not enabled)."
            }
            elseif ($ntlmCount -gt $kerbCount -and $ntlmCount -gt 10) {
                Write-DiagWarning "  NTLM usage is high - consider investigating Kerberos fallback issues"
                Write-Info "    Diagnosis: Enable NTLM auditing via GPO 'Network security: Restrict NTLM:"
                Write-Info "               Audit Incoming NTLM Traffic' to see WHICH calls are using NTLM."
                Write-Info "               Often points to apps connecting by IP, missing SPNs, or cross-trust paths."
            }
            else {
                Write-Success "  Authentication mix looks healthy (Kerberos-dominant)"
            }
        }
        else {
            Write-Info "  No 4624 events in the last 24h (Audit Logon may be disabled, or host idle)"
        }
    }
    catch {
        Write-Info "  Could not analyze authentication protocols"
    }

    # MachineKeys Permissions
    # ------------------------------------------------------------
    # %ProgramData%\Microsoft\Crypto\RSA\MachineKeys holds the private keys for
    # machine-scope certificates (RDP cert, IIS cert, AD authentication cert,
    # etc.). Required ACL: SYSTEM = Full, Administrators = Full, Everyone =
    # Read-attributes (the third is what lets normal apps see WHICH keys exist
    # without being able to read them).
    # When ACLs are wrong (often after restoring an old image, applying a
    # heavy-handed CIS hardening template, or running 'icacls /reset'):
    #   - RDP fails: 'No remote desktop license servers available' OR connection
    #     just disconnects mid-handshake
    #   - IIS HTTPS bindings serve a wrong cert / no cert
    #   - Schannel logs 36870 events (see above)
    # ------------------------------------------------------------
    Write-Section "MachineKeys Directory Permissions"
    Write-Info "  Description: Required ACL on MachineKeys: SYSTEM Full + Administrators Full."
    Write-Info "               Wrong ACL = RDP/IIS HTTPS / TLS apps fail with Schannel 36870."
    try {
        $mkPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
        if (Test-Path $mkPath) {
            $acl = Get-Acl $mkPath -ErrorAction Stop

            # Translate IdentityReference to SID and check the well-known SIDs
            # SYSTEM (S-1-5-18) and BUILTIN\Administrators (S-1-5-32-544).
            # String matching like '*SYSTEM*' fails on localized OS builds and
            # on ACEs stored as raw SIDs.
            $hasSystem = $false
            $hasAdmins = $false
            foreach ($ace in $acl.Access) {
                try {
                    $sid = if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                        $ace.IdentityReference
                    }
                    else {
                        $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                    }
                    if ($sid.Value -eq 'S-1-5-18') { $hasSystem = $true }
                    if ($sid.Value -eq 'S-1-5-32-544') { $hasAdmins = $true }
                }
                catch {
                    # Translation can fail for orphaned SIDs - fall back to string match
                    if ($ace.IdentityReference.Value -like '*SYSTEM*' -or $ace.IdentityReference.Value -eq 'NT AUTHORITY\SYSTEM') { $hasSystem = $true }
                    if ($ace.IdentityReference.Value -like '*Administrators*' -or $ace.IdentityReference.Value -eq 'BUILTIN\Administrators') { $hasAdmins = $true }
                }
            }

            if ($hasSystem -and $hasAdmins) {
                Write-Success "  MachineKeys has SYSTEM and Administrators access"
            }
            else {
                Write-DiagError "  MachineKeys missing SYSTEM or Administrators permissions!"
                Write-Info "    SYSTEM ACE present:        $hasSystem"
                Write-Info "    Administrators ACE present: $hasAdmins"
                Write-Info "  This can cause RDP, TLS certificate, and encryption failures"
                Write-Info "  Remediation: 'icacls $env:ProgramData\Microsoft\Crypto\RSA\MachineKeys /grant SYSTEM:F'"
                Write-Info "               'icacls $env:ProgramData\Microsoft\Crypto\RSA\MachineKeys /grant Administrators:F'"
            }
        }
        else {
            Write-Info "  MachineKeys directory not found at $mkPath (skipping)"
        }
    }
    catch {
        Write-Info "  Could not check MachineKeys permissions: $($_.Exception.Message)"
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
    # ------------------------------------------------------------
    # Two services drive Windows Update:
    #   wuauserv  (Windows Update)            - the agent itself; orchestrates
    #                                            scan, download, install
    #   BITS      (Background Intelligent     - the download transport that
    #              Transfer Service)            wuauserv hands jobs to
    # On modern Windows, BOTH are typically StartType=Manual (triggered) and
    # only run on demand. Disabled = updates will never apply (a real risk
    # introduced by some hardening templates that misread STIG guidance).
    # ------------------------------------------------------------
    Write-Section "Windows Update Service Status"
    Write-Info "  Description: wuauserv = the WU agent; BITS = its download transport."
    Write-Info "               Both should be Manual (triggered) on modern Windows. Disabled"
    Write-Info "               on either = updates will never apply."
    try {
        $wuService = Get-Service -Name "wuauserv" -ErrorAction Stop
        $bitsService = Get-Service -Name "BITS" -ErrorAction Stop
        
        Write-Info "  Windows Update (wuauserv): $($wuService.Status) ($($wuService.StartType))"
        Write-Info "  BITS: $($bitsService.Status) ($($bitsService.StartType))"

        if ($wuService.StartType -eq 'Disabled') {
            Write-DiagError "  wuauserv is DISABLED - patches cannot install on this server."
            Write-Info "    Remediation: 'Set-Service wuauserv -StartupType Manual' (or Automatic)."
        }
        if ($bitsService.StartType -eq 'Disabled') {
            Write-DiagError "  BITS is DISABLED - WU and SCCM downloads will fail."
            Write-Info "    Remediation: 'Set-Service BITS -StartupType Manual'."
        }
    }
    catch {
        Write-DiagError "Failed to check Windows Update services: $($_.Exception.Message)"
    }
    
    # Last installed updates
    # ------------------------------------------------------------
    # Get-HotFix wraps Win32_QuickFixEngineering; it ONLY shows updates that
    # MSI/CBS recorded with a KB ID. So 'platform' updates (driver, defender
    # definition, OOB feature updates) won't appear here - that's why a server
    # may show 'last updated 200 days ago' yet still be relatively current.
    # Known issue: on Server 2019 the InstalledOn property is often $null;
    # we capture those separately so the operator at least knows they exist.
    # Thresholds: >90d = critical (likely missing security rollups);
    #             >30d = warning (one full Patch Tuesday cycle missed).
    # ------------------------------------------------------------
    Write-Section "Last 10 Installed Updates"
    Write-Info "  Description: KB updates from CBS/MSI history. Drivers + Defender defs are"
    Write-Info "               NOT included. >90d since last KB = critical, >30d = warning."
    Write-Info "               Server 2019 commonly returns InstalledOn=$null for some KBs."
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
                    Write-Info "    Impact: Likely missing 3+ security rollups; high CVE exposure."
                    Write-Info "    Remediation: Run 'sconfig' option 6, or PSWindowsUpdate module:"
                    Write-Info "                 Install-Module PSWindowsUpdate -Force; Get-WUInstall -AcceptAll -AutoReboot"
                }
                elseif ($daysSinceUpdate -gt 30) {
                    Write-DiagWarning "  WARNING: Server has not been updated in over 30 days"
                    Write-Info "    Recommendation: Schedule next maintenance window; one Patch Tuesday cycle missed."
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
    # ------------------------------------------------------------
    # Three independent registry signals indicate Windows wants a reboot:
    #   1. CBS\RebootPending           - servicing stack queued changes that
    #                                     can only be applied during boot
    #   2. WindowsUpdate\RebootRequired - WU installed binaries waiting to
    #                                     activate
    #   3. PendingFileRenameOperations  - files locked by running processes;
    #                                     SMSS will rename/delete on next boot
    # If ANY of these is present, fresh updates / role installs will likely
    # fail with vague errors until the box reboots. The 'Reasons' list below
    # is critical because operators often see 'Reboot pending' and reboot,
    # only to have it return - the underlying source needs cleanup.
    # ------------------------------------------------------------
    Write-Section "Pending Reboot Check"
    Write-Info "  Description: Three signals (CBS, Windows Update, PendingFileRenameOperations)."
    Write-Info "               Any present = subsequent updates / role installs may fail until reboot."
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
            Write-Info "    Remediation: Schedule reboot. If 'Reboot pending' returns immediately"
            Write-Info "                 after reboot, run 'DISM /online /cleanup-image /restorehealth'"
            Write-Info "                 followed by 'sfc /scannow' to repair the servicing stack."
        }
        else {
            Write-Success "  No pending reboot detected"
        }
    }
    catch {
        Write-DiagWarning "  Could not determine pending reboot status: $($_.Exception.Message)"
    }
    
    # OS version info
    # ------------------------------------------------------------
    # Win32_OperatingSystem.Caption is the friendly name (e.g. 'Microsoft
    # Windows Server 2022 Standard'). BuildNumber is the canonical version
    # identifier and is what we cross-reference against the lifecycle table
    # in the next check. LastBootUpTime is in WMI/CIM time format which gets
    # converted to a [DateTime] automatically by the modern Get-CimInstance.
    # >90 days uptime is flagged because:
    #   - Patches that need restart can't have been applied recently
    #   - Memory leaks accumulate; non-paged pool exhaustion becomes likely
    #   - On 2008 R2, uptime counter wraps around 497 days (TickCount32)
    # ------------------------------------------------------------
    Write-Section "OS Version Information"
    Write-Info "  Description: OS edition + build + uptime. Build number = canonical version"
    Write-Info "               identifier (matched against lifecycle table below)."
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
            Write-Info "    Impact: Reboot-required patches cannot have applied; non-paged pool may be elevated."
            Write-Info "    Recommendation: Plan a maintenance reboot at the next available window."
        }
    }
    catch {
        Write-DiagError "Failed to retrieve OS information: $($_.Exception.Message)"
    }

    # CBS Store Health
    # ------------------------------------------------------------
    # %SystemRoot%\Logs\CBS\CBS.log is the Component Based Servicing log -
    # every install/uninstall/repair operation logs here. Heuristic check:
    # if the LAST 200 lines contain >10 ERROR entries, the servicing stack
    # is probably struggling (corrupted manifest, missing payload, ACL on
    # WinSxS folder, etc.). Full health check is:
    #   DISM /Online /Cleanup-Image /CheckHealth      (fast - just checks)
    #   DISM /Online /Cleanup-Image /ScanHealth       (slow - deep scan)
    #   DISM /Online /Cleanup-Image /RestoreHealth    (slow - actually fix)
    #   sfc /scannow                                  (verifies system files)
    # Tail-only sampling keeps this check fast even on multi-GB CBS.log files.
    # ------------------------------------------------------------
    Write-Section "CBS Store Health"
    Write-Info "  Description: Heuristic - if last 200 lines of CBS.log contain >10 ERROR entries,"
    Write-Info "               the servicing stack is struggling. Sampling tail keeps this fast."
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
    # ------------------------------------------------------------
    # %SystemRoot%\WinSxS\pending.xml is the queue of CBS operations the OS
    # plans to perform during the next servicing-aware boot. A NORMAL system
    # has no pending.xml. If it exists and persists across reboots:
    #   - A previous install was interrupted (power loss, BSOD mid-update)
    #   - 'TrustedInstaller' service couldn't drain the queue (often due to
    #     ACL damage on WinSxS or a stuck reboot)
    # Symptoms: 'Add Roles & Features' wizard fails with vague errors;
    # subsequent CU installs error out with 0x800f0922 / 0x80070bc9.
    # Recovery: usually a clean reboot. If the file persists, you may need
    # 'Stop-Service trustedinstaller' + manual XML parsing or DISM repair.
    # ------------------------------------------------------------
    Write-Section "Pending.xml Check"
    Write-Info "  Description: WinSxS\pending.xml = CBS reboot queue. Should NOT exist normally."
    Write-Info "               If persistent across reboots, blocks role installs and CU updates."
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
    # ------------------------------------------------------------
    # Build numbers and corresponding products (kept inline for offline use):
    #   <14393  -> Server 2012 / 2012 R2 (and earlier) - end of EXTENDED support
    #              (2012 R2 ext support ended Oct 2023; ESU available)
    #    14393  -> Server 2016         - mainstream ended Jan 2022, ext until Jan 2027
    #    17763  -> Server 2019         - mainstream until Jan 2024, ext until Jan 2029
    #    20348  -> Server 2022         - mainstream until Oct 2026, ext until Oct 2031
    #    26100  -> Server 2025         - latest GA build
    # We don't currently surface the precise EOL date but flag the stages so
    # operators know whether they're on a refresh path or a critical migration.
    # ------------------------------------------------------------
    Write-Section "OS Lifecycle Check"
    Write-Info "  Description: Maps build number to product + support tier. <14393 = end of"
    Write-Info "               extended support; 14393 (2016) approaches mainstream end;"
    Write-Info "               17763 (2019) and newer = supported."
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
    # ------------------------------------------------------------
    # The Setup event log is where role/feature/update install events land
    # (separate from System log). Levels: 1=Critical, 2=Error, 3=Warning.
    # Common error events include:
    #   - 'Update for ... failed to install with error 0x80070643' (generic
    #     install failure - often disk space or AV interference)
    #   - '0x800f0922' (CBS couldn't reserve space or write to WinSxS)
    #   - '0x800f0831' (corrupt source - feed in a /source: pointer)
    # We just surface the events; manual triage is needed to interpret the
    # specific error code. Reference: Microsoft Update error codes KB938205.
    # ------------------------------------------------------------
    Write-Section "Failed Update Events (last 7 days)"
    Write-Info "  Description: Setup event log Critical/Error/Warning entries. Cross-reference"
    Write-Info "               error codes with KB938205 (Windows Update error code list)."
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
            Write-Info "  Triage: 'wuauclt /resetauthorization /detectnow' to refresh WU; if that fails,"
            Write-Info "          'DISM /online /cleanup-image /restorehealth' to repair the servicing stack."
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
    # ------------------------------------------------------------
    # PURPOSE: Fast 9-point triage that surfaces the highest-frequency
    # production issues across all WSTT categories. Each check is INTENTIONALLY
    # narrow - it only flags an issue area; the operator is expected to drop
    # into the dedicated diagnostic (menu options 1-9) for root cause.
    #
    # SCORING: $issues counter increments once per failing check. The final
    # 'SCORECARD' line summarises the count. Any non-zero count = follow-up
    # required. The order of checks reflects real-world incident frequency:
    #   1. Cluster heartbeat / quarantine     (HA outages)
    #   2. Storage adapter resets             (SAN/disk fabric issues)
    #   3. DNS dynamic update failures        (auth + GPO issues)
    #   4. RDP listener + MachineKeys         (remote access + cert ACLs)
    #   5. Account lockouts                   (security + service account drift)
    #   6. Pending reboot                     (blocking patch installs)
    #   7. Schannel TLS errors                (cert/private-key issues)
    #   8. Cluster quorum + node state        (only if cluster member)
    #   9. SQL AG synchronization             (only if AG is installed)
    # ------------------------------------------------------------
    Write-Info "Cross-cutting triage - flags issue AREAS only. Use main-menu options 1-9"
    Write-Info "for root-cause analysis on anything flagged below."
    Write-Host ""
    $issues = 0

    # 1. Cluster / AG Instability (heartbeat loss + network discards)
    # Events 1135 = 'Cluster node was removed from the active failover
    # cluster membership' (heartbeat loss). 1672 = node placed in QUARANTINE
    # by Windows after 3 ungraceful failures within an hour. Either is a
    # serious HA red flag.
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
    # Event 129 'Reset to device, \Device\RaidPort0, was issued' = HBA reset.
    # Event 153 'IO operation retried/failed on device' = path/timeout failure.
    # Repeated occurrences = SAN fabric / driver / cabling / firmware issue.
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
    # Events 8018/8019 = 'The dynamic registration of the DNS record failed'
    # (BADKEY = secure update authentication failed). Common with secure
    # channel breaks, stale TSIG keys, or wrong DNS scavenging windows.
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
    # Two related checks: (a) is RDP port 3389 actually listening on loopback,
    # and (b) does the MachineKeys folder still grant SYSTEM access (broken
    # ACL = RDP TLS handshake fails because it can't read the cert private key).
    # Loopback test avoids firewall noise - just confirms the listener exists.
    Write-Info "4. RDP Connectivity:"
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync('127.0.0.1', 3389)
        $completed = $connectTask.Wait(2000)  # 2-second timeout
        if ($completed -and $tcpClient.Connected) {
            Write-Success "   OK - RDP port 3389 is listening"
        }
        else {
            # Before flagging as a real ISSUE, check whether RDP is INTENTIONALLY off.
            # On hardened cluster nodes / Server Core / SCONFIG-managed boxes, RDP is
            # often disabled in favor of PowerShell Remoting (WinRM/5985) - that's a
            # security posture choice, not a misconfiguration.
            $rdpDisabledByPolicy = $false
            try {
                $tsKey = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
                if ($tsKey.fDenyTSConnections -eq 1) { $rdpDisabledByPolicy = $true }
            }
            catch { }
            $termSvc = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
            $termSvcDisabled = $termSvc -and ($termSvc.StartType -eq 'Disabled' -or $termSvc.Status -ne 'Running')
            $winRMRunning = (Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue).Status -eq 'Running'

            if ($rdpDisabledByPolicy -or $termSvcDisabled) {
                $reason = if ($rdpDisabledByPolicy) { 'fDenyTSConnections=1 (Allow Remote Desktop = OFF)' } else { "TermService is $($termSvc.Status)/$($termSvc.StartType)" }
                $altMgmt = if ($winRMRunning) { '; PowerShell Remoting (WinRM/5985) IS available as alternative' } else { '' }
                Write-Info "   INFO: RDP port 3389 not listening - intentionally disabled ($reason)$altMgmt"
            }
            else {
                $issues++
                Write-DiagError "   ISSUE: RDP port 3389 is NOT listening"
            }
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
    # Event 4740 = lockout. Member servers only see local-account lockouts;
    # for domain accounts the equivalent live on the PDC Emulator role-holder.
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
    # Cheap registry-key existence test - if EITHER key exists, a reboot is
    # queued (CBS or WindowsUpdate). Pending reboot blocks new patch installs
    # and many role/feature operations.
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
    # Events 36870/36871 = TLS server/client credential creation failed,
    # almost always due to private-key inaccessibility (MachineKeys ACL,
    # missing key file, cert imported without 'mark exportable').
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
    # Only runs on cluster nodes. Inspects the cached $script:ClusterEnv
    # populated earlier by Get-ClusterEnvironmentInfo. Any node not in 'Up'
    # state is flagged - includes Paused, Down, Joining, Isolated, Quarantined.
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
        # Only runs if SQL Always On Availability Groups are detected. Reads
        # sys.dm_hadr_database_replica_states.synchronization_health (mapped to
        # text by AGDetails query). HEALTHY = both sync_state=SYNCHRONIZED and
        # database_state=ONLINE. Anything else = data movement issue.
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
    # ------------------------------------------------------------
    # PURPOSE: Curated runbook menu for the 9 most common Microsoft Support
    # case scenarios. Each option maps to a Microsoft TSS (Troubleshooting
    # Script Suite) collection profile (-SDP / -Scenario / -Collectlog) plus
    # any manual fall-back guidance.
    #
    # DESIGN: This is a USER-FACING runbook, not an automated diagnostic.
    # We surface the exact TSS commands so the operator can copy-paste into
    # their data-collection workflow. If TSS is not installed, we surface
    # manual-equivalent guidance (procdump, sfc, DISM, perfmon, etc.).
    #
    # Cluster awareness: scenarios 6 (Cluster) and 7 (Patch) check $script:ClusterEnv
    # to warn before destructive actions on an active cluster owner.
    # ------------------------------------------------------------
    
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
            # Unexpected Reboot - SDP Perf for performance counters around the event,
            # SDP Setup for OS/role context, DND_Setup for servicing logs. Memory.dmp
            # at C:\Windows\Memory.dmp is the most valuable artifact if a complete
            # memory dump was configured BEFORE the crash.
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
            # Slow Boot / Slow Logon - ADS_SBSL is a TSS auto-logger scenario that
            # captures ETW traces across the boot phase. Requires reboot to start
            # collecting; manual stop after the slow logon is reproduced.
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
            # Server Crash / BugCheck / Hang - the ONLY actionable artifact for kernel
            # crashes is a complete memory dump. Active dump (Server 2016+) excludes
            # zero pages so it's smaller. If the customer hasn't configured a complete
            # dump beforehand, this scenario is mostly forward-looking guidance.
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
            # Application Crash - ProcDump in monitor mode (-i) registers itself
            # as the postmortem debugger so subsequent crashes auto-generate a dump.
            # -ma = full memory; collect 2-3 dumps so the support engineer can spot
            # patterns vs one-off corruption. Always uninstall (-u) afterwards.
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
            # SQL Related Issues - SDP SQLBase grabs SQL Server error logs, default
            # trace, system_health XEvent, sp_BlitzCache-equivalent diagnostics, and
            # Windows perf data. -noPSR skips the slow PSR (Problem Steps Recorder).
            # On FCI clusters, combine SDP Cluster + SDP SQLBase to get both views.
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
            # Cluster Related Issues - SDP Cluster is heavy; collect on ALL nodes
            # so MS support can correlate timestamps. Pre-flight check: warn if THIS
            # node owns active groups (collecting on owner can cause brief perf hit).
            # SHA_MsCluster + WaitEvent is for INTERMITTENT issues - it idles waiting
            # for the next 1135 event then captures everything around it.
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
            # OS Patch Issues - standard servicing-stack repair sequence:
            # DISM /RestoreHealth (uses Windows Update; /Source: needed for offline)
            # sfc /scannow (verifies + repairs system files from the component store)
            # SoftwareDistribution rename forces WU to redownload the catalog.
            # CRITICAL on cluster nodes: Cluster-Aware Updating (CAU) orchestrates
            # patching - manually stopping wuauserv mid-CAU run will break the run.
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
            # Server Assessment - 'baseline this server' workflow. Collects all SDPs
            # plus a 4-hour perfmon at 1-minute interval (long enough to capture a
            # peak load period). Shipped with the validator HTML report.
            Write-Info "Server Assessment:"
            Write-Info "Collect 4-hour perfmon with 1-minute interval + validator script"
            if ($tssAvailable) {
                Write-Host "Get-psSDP.ps1 Perf -savePath D:\MS_DATA" -ForegroundColor Cyan
                Write-Host "TSS.ps1 -sdp ALL -LogFolderPath E:\MS_Data" -ForegroundColor Cyan
            }
            Show-PerfmonCommand "Assessment"
        }
        "9" {
            # Export Event Logs - 'wevtutil epl' (Export Log) writes the binary .evtx
            # file (preserves XML payload, can be re-opened in Event Viewer on any
            # Windows machine). Default path is $script:DefaultLogPath\EventLogs.
            # Security log export requires SeSecurityPrivilege (admin shell).
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

    # Track which legacy protocols are explicitly enabled so the recommendations
    # block at the bottom only fires when there is something to remediate.
    $explicitlyEnabled = @{}

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
                        $explicitlyEnabled["$protocolName Client"] = $true
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
                        $explicitlyEnabled["$protocolName Server"] = $true
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
    $legacyEnabled = @($explicitlyEnabled.Keys | Where-Object { $_ -like 'TLS 1.0*' -or $_ -like 'TLS 1.1*' })
    if ($legacyEnabled.Count -gt 0) {
        Write-DiagWarning "TLS 1.0 / 1.1 are explicitly ENABLED on this host: $($legacyEnabled -join ', ')"
        Write-Info "  Both protocols are deprecated by Microsoft, IETF (RFC 8996), and PCI-DSS."
        Write-Info "  Remediation: Set 'Enabled'=0 and 'DisabledByDefault'=1 under each Protocol\Client and Protocol\Server key, then reboot."
    }
    else {
        Write-Success "TLS 1.0 / 1.1 are not explicitly enabled (using OS-default disable / not present)"
    }
    Write-Success "TLS 1.2 should be enabled (minimum requirement)"
    Write-Success "TLS 1.3 should be enabled for best security (Windows Server 2022+)"
    Write-Info ""
    
    # Check .NET Framework TLS support
    Write-Info "--- .NET Framework TLS Support ---"
    Write-Info "  Note: On Server 2019+ / Windows 10 1809+, .NET Framework defaults to"
    Write-Info "        SchUseStrongCrypto = ON and SystemDefaultTlsVersions = ON even when"
    Write-Info "        the registry value is absent. We only flag it as a warning when the"
    Write-Info "        value is explicitly set to 0 (i.e., legacy override is present)."
    try {
        $netFx4Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path) {
            $schUseStrongCrypto = Get-ItemProperty -Path $netFx4Path -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
            $systemDefaultTls = Get-ItemProperty -Path $netFx4Path -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue

            if ($null -eq $schUseStrongCrypto) {
                Write-Info ".NET 4.x (32-bit): Strong Crypto registry value not set (using OS default = ON)"
            }
            elseif ($schUseStrongCrypto.SchUseStrongCrypto -eq 1) {
                Write-Success ".NET 4.x (32-bit): Strong Crypto ENABLED"
            }
            else {
                Write-DiagWarning ".NET 4.x (32-bit): Strong Crypto explicitly DISABLED (value=0)"
            }

            if ($null -eq $systemDefaultTls) {
                Write-Info ".NET 4.x (32-bit): SystemDefaultTlsVersions not set (using OS default = ON)"
            }
            elseif ($systemDefaultTls.SystemDefaultTlsVersions -eq 1) {
                Write-Success ".NET 4.x (32-bit): System Default TLS ENABLED"
            }
            else {
                Write-DiagWarning ".NET 4.x (32-bit): System Default TLS explicitly DISABLED (value=0)"
            }
        }
        
        $netFx4Path64 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path64) {
            $schUseStrongCrypto64 = Get-ItemProperty -Path $netFx4Path64 -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
            $systemDefaultTls64 = Get-ItemProperty -Path $netFx4Path64 -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue

            if ($null -eq $schUseStrongCrypto64) {
                Write-Info ".NET 4.x (64-bit): Strong Crypto registry value not set (using OS default = ON)"
            }
            elseif ($schUseStrongCrypto64.SchUseStrongCrypto -eq 1) {
                Write-Success ".NET 4.x (64-bit): Strong Crypto ENABLED"
            }
            else {
                Write-DiagWarning ".NET 4.x (64-bit): Strong Crypto explicitly DISABLED (value=0)"
            }

            if ($null -eq $systemDefaultTls64) {
                Write-Info ".NET 4.x (64-bit): SystemDefaultTlsVersions not set (using OS default = ON)"
            }
            elseif ($systemDefaultTls64.SystemDefaultTlsVersions -eq 1) {
                Write-Success ".NET 4.x (64-bit): System Default TLS ENABLED"
            }
            else {
                Write-DiagWarning ".NET 4.x (64-bit): System Default TLS explicitly DISABLED (value=0)"
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
    Write-DiagWarning "IMPORTANT: The commands below are for REFERENCE ONLY. They are NOT auto-executed."
    Write-DiagWarning "Review each command carefully before running manually. Registry changes require a system restart."
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
    # ------------------------------------------------------------
    # PURPOSE: 8-point IIS health sweep covering core services, AppPool / Site
    # state, worker processes, identity health, authentication config, SSL/TLS
    # certificates, and IP-restriction rules.
    #
    # PRE-REQUISITES:
    #   - IIS Web-Server role installed (we exit early if not)
    #   - WebAdministration PowerShell module loadable (provides 'IIS:\' drive)
    #   - Run from 64-bit PowerShell - the 32-bit module bitness mismatch
    #     'There is no provider with the specified name' is a common gotcha
    #
    # NOTE: We declare $appPools and $sites at function scope so later sections
    # (identities, auth, certs, IP restrictions) can reuse the enumeration
    # rather than re-querying IIS:\ paths multiple times.
    # ------------------------------------------------------------
    
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
    # ------------------------------------------------------------
    # IIS depends on three Windows services:
    #   W3SVC    - World Wide Web Publishing Service (HTTP listener + request
    #              dispatcher). Stopped = no sites respond.
    #   WAS      - Windows Process Activation Service (manages w3wp.exe lifecycle
    #              based on requests; replaces the IIS6 'aspnet_wp' model).
    #              Stopped = AppPools cannot start, all sites fail with 503.
    #   IISADMIN - IIS6 metabase compatibility service. Modern IIS (7.0+)
    #              uses applicationHost.config instead, so this service may
    #              legitimately not exist on 2019/2022 - we treat 'not found'
    #              as informational, not an error.
    # ------------------------------------------------------------
    Write-Section "IIS Core Services Status"
    Write-Info "  Description: W3SVC = HTTP listener; WAS = AppPool process manager;"
    Write-Info "               IISADMIN = legacy IIS6 metabase (often absent on modern OS)."
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
    # ------------------------------------------------------------
    # An Application Pool is the .NET CLR + worker-process container. Each
    # pool runs in its own w3wp.exe instance under a chosen identity. State
    # values:
    #   Started   - healthy; w3wp will spawn on first request
    #   Stopped   - admin disabled OR rapid-fail protection tripped (5 failures
    #               in 5 minutes by default -> AppPool auto-stops to protect
    #               the box). Look for events 5002/5117 in Application log.
    #   Stopping  - in transition; usually transient
    # Identity types: ApplicationPoolIdentity (default, virtual SID), LocalSystem,
    # LocalService, NetworkService, SpecificUser (custom domain/local account).
    # ------------------------------------------------------------
    Write-Section "Application Pools"
    Write-Info "  Description: AppPool = .NET CLR container + w3wp.exe identity. Stopped"
    Write-Info "               state may indicate rapid-fail protection (Application events"
    Write-Info "               5002/5117) - auto-stops after 5 failures in 5 min."
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
    # ------------------------------------------------------------
    # A Website binds protocol+IP+port+host to a physical path. Bindings format:
    # protocol://IP:port:hostname (empty IP = '*' = all unassigned IPs).
    # Common bindings issues:
    #   - Two sites bound to *:80: + same host header -> port conflict (only
    #     one will start; the other shows state=Stopped)
    #   - HTTPS binding referencing a deleted certificate -> binding errors
    #     in System log (HttpEvent 15301)
    #   - Physical path on missing/dismounted drive -> 500.19 or 503 errors
    # ------------------------------------------------------------
    Write-Section "Websites"
    Write-Info "  Description: Site state + bindings + physical path. Stopped sites often"
    Write-Info "               indicate port conflicts or missing physical path drives."
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
    # ------------------------------------------------------------
    # w3wp.exe = the actual hosting process for a request. There can be:
    #   0 instances per pool   - no requests received yet (pool warm-up pending)
    #   1 instance per pool    - normal
    #   N instances per pool   - 'Web Garden' (maxProcesses>1, rare)
    # We extract the AppPool name from the command-line argument (-ap "PoolName")
    # which is how WAS identifies which pool a w3wp belongs to.
    # WorkingSet64 is the resident memory; very high values (>2-3 GB) suggest
    # a memory leak in the application code or excessive caching.
    # CPU time is cumulative since process start - not a 'right now' value.
    # ------------------------------------------------------------
    Write-Section "IIS Worker Processes (w3wp.exe)"
    Write-Info "  Description: w3wp.exe instances per AppPool. Memory >2-3 GB suggests leak"
    Write-Info "               or excessive caching. CPU time is cumulative (not real-time %)."
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
    # ------------------------------------------------------------
    # SpecificUser identities are the #1 source of 'AppPool keeps stopping'
    # tickets. Common failure modes:
    #   - Account password expired (no reminder; AppPool just won't start)
    #   - Account locked out (Event 4625 in Security log)
    #   - Account missing 'Log on as a batch job' right (SeBatchLogonRight)
    #     -> Event 1057 'failed to start because of an error in the
    #     application configuration. Logon failure: the user has not been
    #     granted the requested logon type at this computer.'
    #   - Local user referenced as '.\name' but actually deleted
    # We can verify local-user existence here; domain/external accounts we just
    # surface a warning since we can't query AD reliably from a member server.
    # ------------------------------------------------------------
    Write-Section "AppPool Identities & Permissions"
    Write-Info "  Description: Custom (SpecificUser) identities - validate local accounts"
    Write-Info "               exist; for domain accounts check 'Log on as a batch job' right"
    Write-Info "               (Event 1057 if missing) and password expiry."
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
    # ------------------------------------------------------------
    # Three primary IIS authentication providers (there are more, like Forms
    # and Client Certificate, but these three cover ~95% of cases):
    #   Anonymous  - default; uses IUSR identity. Required for public sites.
    #   Basic      - HTTP Basic auth (base64-encoded username:password). MUST
    #                only be used over HTTPS - sends credentials in plaintext.
    #   Windows    - Integrated Windows Auth (NTLM/Kerberos). Best for
    #                intranet sites with AD-joined clients.
    # Sites with NO auth methods enabled are misconfigured (or admin couldn't
    # read config - happens if running as a non-admin user).
    # ------------------------------------------------------------
    Write-Section "Site Authentication Methods"
    Write-Info "  Description: Surfaces enabled auth providers per site. Basic auth = MUST"
    Write-Info "               be HTTPS-only. No methods enabled = misconfigured site."
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
    # ------------------------------------------------------------
    # For each https binding we extract the certificate hash (thumbprint),
    # search both Cert:\LocalMachine\My (Personal) and \WebHosting (CCS-style
    # binding store), and report expiry. Common issues:
    #   - Hash present in binding but cert deleted from store -> handshake
    #     fails with Schannel 36870 / HttpEvent 15301
    #   - Cert expired -> browser shows NET::ERR_CERT_DATE_INVALID
    #   - <30 days remaining -> renew now to avoid weekend page-call
    # We deduplicate by hash because most servers reuse the same wildcard cert
    # across many sites - no point reporting the same cert N times.
    # ------------------------------------------------------------
    Write-Section "SSL/TLS Certificates"
    Write-Info "  Description: Per-binding cert lookup in LocalMachine\My + \WebHosting."
    Write-Info "               Hash present but cert missing = Schannel 36870 / HttpEvent 15301."
    Write-Info "               <30 days remaining = renew now; expired = production outage risk."
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
    # ------------------------------------------------------------
    # 'IP and Domain Restrictions' role feature lets you whitelist or blacklist
    # client IPs at the IIS layer. Two modes:
    #   allowUnlisted=true  + add[@allowed=false] entries -> blacklist mode
    #   allowUnlisted=false + add[@allowed=true]  entries -> whitelist mode
    # Whitelist mode is much stricter; we flag it explicitly because many
    # 'site is down' tickets turn out to be whitelist + new client IP combo.
    # ------------------------------------------------------------
    Write-Section "IP Security Restrictions"
    Write-Info "  Description: Surfaces ipSecurity allowUnlisted + explicit deny rules."
    Write-Info "               allowUnlisted=false = whitelist mode (strict); common cause of"
    Write-Info "               '403 Forbidden' for legitimate clients with new IPs."
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

#region Task Scheduler Diagnostics
function Test-TaskSchedulerHealth {
    <#
    .SYNOPSIS
        Performs comprehensive Task Scheduler diagnostics
    .DESCRIPTION
        Checks failed tasks, long-running tasks, disabled tasks, high-privilege tasks,
        credential failures, SDDL permissions, orphaned executables, and trigger health
    .EXAMPLE
        Test-TaskSchedulerHealth
    #>
    [CmdletBinding()]
    param()

    Write-Header "Task Scheduler Diagnostics"
    # ------------------------------------------------------------
    # PURPOSE: 8-point Task Scheduler audit covering failures, stuck tasks,
    # disabled tasks, privilege escalation surface, credential health, ACL
    # permissions, orphaned executables, and trigger expiry.
    #
    # SCOPE FILTERING: Most checks exclude '\Microsoft\*' tasks because the
    # OS ships with hundreds of inbox tasks (defrag, telemetry, defender, etc.)
    # whose failures are usually benign or not under our control. We surface
    # them as a count only - operator can use 'Get-ScheduledTask' to drill in.
    #
    # IMPLEMENTATION: We enumerate ALL tasks once via Get-ScheduledTask and
    # cache (Task + Info) tuples in $allTaskInfo. Subsequent checks filter
    # this cache rather than re-enumerating - saves significant time on
    # servers with large task inventories.
    # ------------------------------------------------------------

    $allTasks = $null
    try {
        $allTasks = Get-ScheduledTask -ErrorAction Stop
        Write-Info "  Total scheduled tasks: $(@($allTasks).Count)"
    }
    catch {
        Write-DiagError "  Could not enumerate scheduled tasks: $($_.Exception.Message)"
        return
    }

    $allTaskInfo = @()
    foreach ($t in $allTasks) {
        try {
            $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            $allTaskInfo += [PSCustomObject]@{
                Task     = $t
                Info     = $info
                FullName = if ($t.TaskPath) { "$($t.TaskPath)$($t.TaskName)" } else { $t.TaskName }
            }
        }
        catch {
            $allTaskInfo += [PSCustomObject]@{
                Task     = $t
                Info     = $null
                FullName = if ($t.TaskPath) { "$($t.TaskPath)$($t.TaskName)" } else { $t.TaskName }
            }
        }
    }

    # 1. Failed Tasks (Last Run Result != 0)
    # ------------------------------------------------------------
    # LastTaskResult is the HRESULT returned by the action's Execute call.
    # 0 = success. We also exclude 0x00041325 = 'task is currently running'
    # which is just informational, not a failure.
    # Common error codes (decoded inline below):
    #   0x8007052E - Logon failure (expired password, locked account, wrong
    #                principal). Check Security log Event 4625.
    #   0x80070005 - Access denied. Most often missing 'Log on as a batch job'
    #                right (SeBatchLogonRight) or NTFS ACL on the script.
    #   0x80041326 - Task not yet run (scheduled for future time).
    #   0x800710E0 - 'Operator or admin refused' - usually triggered when a
    #                'run only when user logged on' task fires while logged off.
    #   0x00041306 - Task terminated by user (or by 'stop if runs longer than
    #                X' setting in Settings tab).
    #   0x00041301 - Task is currently running (informational).
    # We surface non-Microsoft failures verbosely; Microsoft tasks get a count.
    # ------------------------------------------------------------
    Write-Section "Failed Tasks (Last Run Result != 0)"
    Write-Info "  Description: HRESULT-decoded analysis of LastTaskResult. Microsoft inbox"
    Write-Info "               tasks are summarised as a count; non-Microsoft tasks shown verbosely."
    try {
        $failedTasks = $allTaskInfo | Where-Object {
            $_.Info -and $_.Info.LastTaskResult -ne 0 -and $_.Info.LastTaskResult -ne 0x00041325 -and
            $_.Task.State -ne 'Disabled' -and $_.Task.TaskPath -notlike '\Microsoft\*'
        }
        if ($failedTasks) {
            Write-DiagWarning "  $(@($failedTasks).Count) non-Microsoft task(s) with failed last run:"
            foreach ($ft in $failedTasks | Select-Object -First 15) {
                $resultHex = "0x{0:X8}" -f $ft.Info.LastTaskResult
                $lastRun = if ($ft.Info.LastRunTime -and $ft.Info.LastRunTime.Year -gt 1999) { $ft.Info.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { "Never" }
                Write-DiagWarning "    $($ft.FullName): Result=$resultHex LastRun=$lastRun"
                # Decode common error codes
                switch ($ft.Info.LastTaskResult) {
                    0x8007052E { Write-DiagError "      → Logon failure (expired password or invalid credentials)" }
                    0x80070005 { Write-DiagError "      → Access denied (insufficient permissions)" }
                    0x80041326 { Write-Info "        → Task not yet run (scheduled for future)" }
                    0x800710E0 { Write-DiagWarning "      → Operator or administrator refused the request" }
                    0x00041306 { Write-DiagWarning "      → Task terminated by user" }
                    0x00041301 { Write-Info "        → Task is currently running" }
                }
            }
        }
        else {
            Write-Success "  No failed non-Microsoft tasks detected"
        }

        # Also show Microsoft tasks with failures (separate)
        $msFailedTasks = $allTaskInfo | Where-Object {
            $_.Info -and $_.Info.LastTaskResult -ne 0 -and $_.Info.LastTaskResult -ne 0x00041325 -and
            $_.Task.State -ne 'Disabled' -and $_.Task.TaskPath -like '\Microsoft\*'
        }
        if ($msFailedTasks -and @($msFailedTasks).Count -gt 0) {
            Write-Info "  Microsoft tasks with failures: $(@($msFailedTasks).Count) (use Get-ScheduledTask for details)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check failed tasks: $($_.Exception.Message)"
    }

    # 2. Tasks Running Longer Than Expected (currently running)
    # ------------------------------------------------------------
    # State='Running' + LastRunTime is how long the current invocation has
    # been executing. Heuristic thresholds:
    #   < 1 hour    : informational (long-running batch jobs are normal)
    #   1-4 hours   : warning (could be hung; could be legitimate ETL)
    #   > 4 hours   : flagged as STUCK (most legit jobs finish well before this)
    # Operators should cross-reference with the task's 'Stop the task if it
    # runs longer than' setting in the Settings tab. If that's not configured,
    # a hung action will run forever, blocking subsequent triggers.
    # ------------------------------------------------------------
    Write-Section "Long-Running / Stuck Tasks"
    Write-Info "  Description: Currently executing tasks + duration. >4h flagged as likely stuck."
    Write-Info "               Mitigate via Settings tab > 'Stop task if runs longer than X'."
    try {
        $runningTasks = $allTaskInfo | Where-Object { $_.Task.State -eq 'Running' }
        if ($runningTasks) {
            Write-DiagWarning "  $(@($runningTasks).Count) task(s) currently running:"
            foreach ($rt in $runningTasks) {
                $runTime = ""
                if ($rt.Info -and $rt.Info.LastRunTime -and $rt.Info.LastRunTime.Year -gt 1999) {
                    $duration = (Get-Date) - $rt.Info.LastRunTime
                    $runTime = "$([math]::Round($duration.TotalMinutes, 0)) min"
                    if ($duration.TotalHours -gt 4) {
                        Write-DiagError "    $($rt.FullName): Running for $runTime — POSSIBLY STUCK"
                    }
                    elseif ($duration.TotalHours -gt 1) {
                        Write-DiagWarning "    $($rt.FullName): Running for $runTime"
                    }
                    else {
                        Write-Info "    $($rt.FullName): Running for $runTime"
                    }
                }
                else {
                    Write-Info "    $($rt.FullName): Running (start time unknown)"
                }
            }
        }
        else {
            Write-Info "  No tasks currently running"
        }
    }
    catch {
        Write-DiagWarning "  Could not check running tasks"
    }

    # 3. Disabled Tasks (non-Microsoft)
    # ------------------------------------------------------------
    # Disabled tasks are tracked because they often represent forgotten
    # remediation actions: 'we'll fix it later, just disable it for now'.
    # Consider whether each one should be deleted, re-enabled, or left as is.
    # Microsoft tasks are excluded - inbox tasks like 'XblGameSaveTask' are
    # legitimately disabled on server SKUs and don't need attention.
    # ------------------------------------------------------------
    Write-Section "Disabled Tasks"
    Write-Info "  Description: Non-Microsoft tasks in Disabled state. Often forgotten remediation;"
    Write-Info "               review whether to delete, re-enable, or leave alone."
    try {
        $disabledTasks = $allTasks | Where-Object {
            $_.State -eq 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'
        }
        if ($disabledTasks) {
            Write-Info "  $(@($disabledTasks).Count) non-Microsoft task(s) are disabled:"
            foreach ($dt in $disabledTasks | Select-Object -First 15) {
                Write-Info "    $($dt.TaskPath)$($dt.TaskName)"
            }
            if (@($disabledTasks).Count -gt 15) {
                Write-Info "    ... and $(@($disabledTasks).Count - 15) more"
            }
        }
        else {
            Write-Success "  No disabled non-Microsoft tasks"
        }
    }
    catch {
        Write-DiagWarning "  Could not check disabled tasks"
    }

    # 4. Tasks Running As SYSTEM / High Privilege
    # ------------------------------------------------------------
    # SYSTEM (S-1-5-18) + RunLevel=Highest = unrestricted local access.
    # If the executable referenced by such a task is writable by a normal
    # user, that user can effectively elevate to SYSTEM by replacing the
    # binary - a classic privilege-escalation pattern (see CVE-2020-0796
    # mitigation guidance and many AV/EDR detections).
    # We flag these for REVIEW only - many legitimate enterprise tasks
    # (backup agents, monitoring, patching) need SYSTEM. The follow-up step
    # should be 'icacls <Execute path>' to confirm only privileged accounts
    # can write to the target binary.
    # ------------------------------------------------------------
    Write-Section "High-Privilege Task Audit"
    Write-Info "  Description: SYSTEM + Highest RunLevel tasks. Privilege-escalation surface"
    Write-Info "               IF the target executable is writable by non-admins. Verify with"
    Write-Info "               'icacls <ExePath>' for each flagged task."
    try {
        $highPrivTasks = $allTasks | Where-Object {
            $_.Principal.UserId -in @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18') -and
            $_.Principal.RunLevel -eq 'Highest' -and
            $_.TaskPath -notlike '\Microsoft\*' -and
            $_.State -ne 'Disabled'
        }
        if ($highPrivTasks) {
            Write-DiagWarning "  $(@($highPrivTasks).Count) non-Microsoft task(s) run as SYSTEM with Highest privilege:"
            foreach ($hp in $highPrivTasks | Select-Object -First 10) {
                $actionExe = ($hp.Actions | Select-Object -First 1).Execute
                Write-DiagWarning "    $($hp.TaskPath)$($hp.TaskName) → $actionExe"
            }
            Write-Info "  Review these tasks — SYSTEM + Highest is a security risk if the executable is writable"
        }
        else {
            Write-Success "  No non-Microsoft high-privilege tasks found"
        }
    }
    catch {
        Write-DiagWarning "  Could not audit task privileges"
    }

    # 5. Tasks With Expired/Invalid Credentials (logon failure)
    # ------------------------------------------------------------
    # Specifically isolates the two error codes that map to credential issues:
    #   0x8007052E - Logon failure: bad username or password. Most common
    #                cause is a service-account password change where the
    #                Task Scheduler reference wasn't updated.
    #   0x80070005 - Access denied. Could be NTFS, but for tasks usually
    #                means the principal is missing 'Log on as a batch job'
    #                right (secpol.msc -> Local Policies -> User Rights
    #                Assignment).
    # We surface the principal so operator knows WHICH account to fix.
    # ------------------------------------------------------------
    Write-Section "Credential Failures (Logon Error 0x8007052E)"
    Write-Info "  Description: Tasks failing with 0x8007052E (bad creds) or 0x80070005 (access denied)."
    Write-Info "               Top cause: service-account password change without updating task references."
    try {
        $credFailed = $allTaskInfo | Where-Object {
            $_.Info -and ($_.Info.LastTaskResult -eq 0x8007052E -or $_.Info.LastTaskResult -eq 0x80070005) -and
            $_.Task.State -ne 'Disabled'
        }
        if ($credFailed) {
            Write-DiagError "  $(@($credFailed).Count) task(s) failing due to credential/access issues:"
            foreach ($cf in $credFailed) {
                $principal = $cf.Task.Principal.UserId
                $resultHex = "0x{0:X8}" -f $cf.Info.LastTaskResult
                Write-DiagError "    $($cf.FullName): RunAs='$principal' Error=$resultHex"
                if ($cf.Info.LastTaskResult -eq 0x8007052E) {
                    Write-Info "      Fix: Update password for '$principal' in Task Scheduler properties"
                }
                elseif ($cf.Info.LastTaskResult -eq 0x80070005) {
                    Write-Info "      Fix: Grant '$principal' the 'Log on as a batch job' right"
                }
            }
        }
        else {
            Write-Success "  No credential-related task failures"
        }
    }
    catch {
        Write-DiagWarning "  Could not check credential failures"
    }

    # 6. Task SDDL Permission Audit
    # ------------------------------------------------------------
    # Each scheduled task has its own ACL stored as SDDL (Security Descriptor
    # Definition Language). We use the COM 'Schedule.Service' API since the
    # PS cmdlets don't expose this directly. SDDL ACE format we look for:
    #   (A;;FA;;;S-1-1-0)   = Allow / Full Access / Everyone (S-1-1-0)
    #   (A;;FA;;;S-1-5-11)  = Allow / Full Access / Authenticated Users
    # Either pattern means anyone logged in can MODIFY the task definition
    # (change the action, change the principal, etc.) which combined with a
    # SYSTEM/Highest task = trivial privilege escalation.
    # NOTE: We only scan the root folder. A full recursive scan is possible
    # but expensive on large inventories - skipping for now.
    # ------------------------------------------------------------
    Write-Section "Task Permission Audit (SDDL)"
    Write-Info "  Description: Surfaces tasks where Everyone (S-1-1-0) or Authenticated Users"
    Write-Info "               (S-1-5-11) have Full Access. Combined with SYSTEM run-level ="
    Write-Info "               privilege escalation. Root folder only (recursive scan is expensive)."
    try {
        $service = New-Object -ComObject "Schedule.Service"
        $service.Connect()
        $rootFolder = $service.GetFolder("\")
        $comTasks = $rootFolder.GetTasks(0)
        $permIssues = 0
        foreach ($ct in $comTasks) {
            try {
                $sddl = $ct.GetSecurityDescriptor(4)
                # Flag tasks where Everyone (S-1-1-0) or Authenticated Users (S-1-5-11) have Full Access
                if ($sddl -match '\(A;;FA;;;S-1-1-0\)' -or $sddl -match '\(A;;FA;;;S-1-5-11\)') {
                    $permIssues++
                    Write-DiagWarning "    $($ct.Name): Overly permissive — Everyone or Authenticated Users have Full Access"
                }
            }
            catch { }
        }
        if ($permIssues -eq 0) {
            Write-Success "  No overly permissive task SDDL entries found (root folder)"
        }
        else {
            Write-DiagWarning "  $permIssues task(s) with overly broad permissions"
        }
    }
    catch {
        Write-DiagWarning "  Could not audit task SDDL permissions (COM access may be restricted)"
    }

    # 7. Orphaned Tasks (missing executables)
    # ------------------------------------------------------------
    # Tasks whose Execute path no longer exists on disk. Common causes:
    #   - Application uninstalled but its task wasn't cleaned up
    #   - Drive letter changed (D:\ became E:\ after disk add)
    #   - Operator deleted the script but forgot the task
    # Skips list:
    #   - 'COM handler' (these have no .exe; they invoke a CLSID)
    #   - Paths starting with '%' (env-var expansion - we don't resolve those)
    #   - Built-in shells (powershell.exe / cmd.exe / wscript.exe / cscript.exe /
    #     mshta.exe) which are guaranteed present in System32
    #   - .com files (legacy DOS executables, often still extant)
    # ------------------------------------------------------------
    Write-Section "Orphaned Tasks (Missing Executables)"
    Write-Info "  Description: Tasks whose Execute path no longer exists on disk. Excludes"
    Write-Info "               COM-handler tasks, env-var paths, and built-in shells."
    try {
        $orphaned = @()
        $tasksWithActions = $allTasks | Where-Object {
            $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' -and $_.Actions.Count -gt 0
        }
        foreach ($t in $tasksWithActions) {
            foreach ($action in $t.Actions) {
                $exe = $action.Execute
                if ($exe -and $exe -notlike 'COM handler*' -and $exe -notlike '%*') {
                    # Strip quotes
                    $cleanExe = $exe.Trim('"', "'", ' ')
                    # Skip built-in commands
                    if ($cleanExe -notin @('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe') -and
                        $cleanExe -notlike '*.com' -and -not (Test-Path $cleanExe -ErrorAction SilentlyContinue)) {
                        $orphaned += [PSCustomObject]@{
                            Task = "$($t.TaskPath)$($t.TaskName)"
                            Exe  = $cleanExe
                        }
                    }
                }
            }
        }
        if ($orphaned) {
            Write-DiagWarning "  $(@($orphaned).Count) task(s) reference missing executables:"
            foreach ($o in $orphaned | Select-Object -First 10) {
                Write-DiagWarning "    $($o.Task) → $($o.Exe) [NOT FOUND]"
            }
            if (@($orphaned).Count -gt 10) {
                Write-Info "    ... and $(@($orphaned).Count - 10) more"
            }
        }
        else {
            Write-Success "  All non-Microsoft task executables exist on disk"
        }
    }
    catch {
        Write-DiagWarning "  Could not check for orphaned tasks: $($_.Exception.Message)"
    }

    # 8. Task Trigger Health (expired/no triggers)
    # ------------------------------------------------------------
    # Three trigger anti-patterns:
    #   1. NO triggers defined - task can only be invoked manually or by
    #      another process (Start-ScheduledTask). Often a leftover from a
    #      'one-time run' that should now be deleted.
    #   2. EndBoundary in the past - trigger is technically still configured
    #      but will never fire again. Typically means a holiday/maintenance
    #      window task whose end date wasn't cleared.
    #   3. Trigger explicitly disabled - even if the task itself is enabled,
    #      a disabled trigger won't fire. Easy to miss in the GUI.
    # We don't currently flag overlapping triggers (e.g. two 'every 5 min'
    # triggers); could be a future enhancement.
    # ------------------------------------------------------------
    Write-Section "Task Trigger Health"
    Write-Info "  Description: Detects 3 anti-patterns: no triggers, expired EndBoundary,"
    Write-Info "               or per-trigger Enabled=false (easy to miss in the GUI)."
    try {
        $triggerIssues = @()
        $activeTasks = $allTasks | Where-Object {
            $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'
        }
        foreach ($t in $activeTasks) {
            $triggers = $t.Triggers
            if (-not $triggers -or $triggers.Count -eq 0) {
                $triggerIssues += [PSCustomObject]@{
                    Task  = "$($t.TaskPath)$($t.TaskName)"
                    Issue = "No triggers defined"
                }
                continue
            }
            foreach ($trigger in $triggers) {
                # Check for expired end boundaries
                if ($trigger.EndBoundary) {
                    try {
                        $endDate = [datetime]$trigger.EndBoundary
                        if ($endDate -lt (Get-Date)) {
                            $triggerIssues += [PSCustomObject]@{
                                Task  = "$($t.TaskPath)$($t.TaskName)"
                                Issue = "Trigger expired on $($endDate.ToString('yyyy-MM-dd'))"
                            }
                        }
                    }
                    catch { }
                }
                # Check for disabled triggers
                if ($trigger.Enabled -eq $false) {
                    $triggerIssues += [PSCustomObject]@{
                        Task  = "$($t.TaskPath)$($t.TaskName)"
                        Issue = "Trigger is disabled"
                    }
                }
            }
        }
        if ($triggerIssues) {
            Write-DiagWarning "  $(@($triggerIssues).Count) trigger issue(s) found:"
            foreach ($ti in $triggerIssues | Select-Object -First 15) {
                Write-DiagWarning "    $($ti.Task): $($ti.Issue)"
            }
            if (@($triggerIssues).Count -gt 15) {
                Write-Info "    ... and $(@($triggerIssues).Count - 15) more"
            }
        }
        else {
            Write-Success "  All active task triggers are healthy"
        }
    }
    catch {
        Write-DiagWarning "  Could not check task triggers: $($_.Exception.Message)"
    }

    # Summary
    Write-Host ""
    $taskSummary = @{
        Total    = @($allTasks).Count
        Ready    = @($allTasks | Where-Object { $_.State -eq 'Ready' }).Count
        Running  = @($allTasks | Where-Object { $_.State -eq 'Running' }).Count
        Disabled = @($allTasks | Where-Object { $_.State -eq 'Disabled' }).Count
    }
    Write-Info "Task Summary: Total=$($taskSummary.Total) Ready=$($taskSummary.Ready) Running=$($taskSummary.Running) Disabled=$($taskSummary.Disabled)"
}
#endregion

function Test-ServerBaseline {
    <#
    .SYNOPSIS
        Performs SOE baseline validation checks from Validator scripts
    .DESCRIPTION
        Checks AD OU, license activation, crash dump config, installed software,
        NIC power save, Windows features, NTFS 8.3, page file clear, and driver versions
    #>
    [CmdletBinding()]
    param()

    Write-Header "Server Baseline Validation"

    # 1. AD OU Path Detection
    Write-Section "Active Directory OU Path"
    try {
        $domain = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain
        if ($domain -and $domain -ne "WORKGROUP") {
            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.Filter = "(&(objectClass=computer)(name=$env:COMPUTERNAME))"
                $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
                $result = $searcher.FindOne()
                if ($result) {
                    $dn = $result.Properties["distinguishedname"][0]
                    $ou = $dn.Substring($env:COMPUTERNAME.Length + 4)
                    Write-Info "  Computer: $env:COMPUTERNAME"
                    Write-Info "  DN: $dn"
                    Write-Info "  OU: $ou"
                }
                else {
                    Write-Info "  Computer object not found in AD (search returned no results - may be a join issue)"
                }
            }
            catch {
                # 'An operations error occurred' from LDAP usually means the local
                # security context cannot bind anonymously and ADWS isn't reachable
                # on this NIC - common on isolated mgmt VMs with default ACLs.
                # Demote to INFO; this is not an actionable production issue.
                $msg = $_.Exception.Message
                if ($msg -match 'operations error|server is not operational|access is denied') {
                    Write-Info "  AD lookup skipped (LDAP bind not permitted in this security context: $msg)"
                    Write-Info "  Domain (from CimInstance): $domain"
                }
                else {
                    Write-DiagWarning "  Could not query AD: $msg"
                }
            }
        }
        else {
            Write-Info "  Server is not domain-joined (WORKGROUP)"
        }
    }
    catch {
        Write-DiagWarning "  Could not determine domain membership"
    }

    # 2. Windows License/Activation Status
    Write-Section "Windows License & Activation"
    try {
        $license = Get-CimInstance SoftwareLicensingProduct -ErrorAction Stop |
            Where-Object { $_.PartialProductKey -and $_.ApplicationId -eq '55c92734-d682-4d71-983e-d6ec3f16059f' } |
            Select-Object -First 1
        if ($license) {
            $statusText = switch ($license.LicenseStatus) {
                0 { "Unlicensed" }
                1 { "Licensed" }
                2 { "OOBGrace (Out-of-Box Grace)" }
                3 { "OOTGrace (Out-of-Tolerance Grace)" }
                4 { "NonGenuineGrace" }
                5 { "Notification" }
                6 { "ExtendedGrace" }
                default { "Unknown ($($license.LicenseStatus))" }
            }
            Write-Info "  Product: $($license.Name)"
            Write-Info "  Status: $statusText"
            Write-Info "  Partial Key: $($license.PartialProductKey)"
            if ($license.LicenseStatus -ne 1) {
                Write-DiagError "  SERVER IS NOT PROPERLY LICENSED!"
                Write-Info "  Run: slmgr /ato to attempt activation"
            }
            else {
                Write-Success "  Windows is properly activated"
            }
        }
        else {
            Write-DiagWarning "  Could not determine license status"
        }
    }
    catch {
        Write-DiagWarning "  Could not check activation: $($_.Exception.Message)"
    }

    # 3. Crash Dump Configuration
    Write-Section "Crash Dump Configuration"
    try {
        $crashCtrl = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction Stop
        $dumpType = switch ($crashCtrl.CrashDumpEnabled) {
            0 { "None (CRITICAL - no dump on crash!)" }
            1 { "Complete Memory Dump" }
            2 { "Kernel Memory Dump" }
            3 { "Small Memory Dump (minidump)" }
            7 { "Automatic Memory Dump (recommended)" }
            default { "Unknown ($($crashCtrl.CrashDumpEnabled))" }
        }
        Write-Info "  Dump Type: $dumpType"
        Write-Info "  Dump File: $($crashCtrl.DumpFile)"
        Write-Info "  Auto Restart: $(if ($crashCtrl.AutoReboot -eq 1) { 'Yes' } else { 'No' })"
        Write-Info "  Overwrite Existing: $(if ($crashCtrl.Overwrite -eq 1) { 'Yes' } else { 'No' })"

        if ($crashCtrl.CrashDumpEnabled -eq 0) {
            Write-DiagError "  NO crash dumps configured! Enable Automatic Memory Dump for debugging"
        }
        elseif ($crashCtrl.CrashDumpEnabled -eq 3) {
            Write-DiagWarning "  Small dumps only — insufficient for most crash analysis. Recommend Automatic (7) or Kernel (2)"
        }

        # Check if dedicated dump file location has space
        $dumpPath = Split-Path $crashCtrl.DumpFile -Parent -ErrorAction SilentlyContinue
        if ($dumpPath) {
            $dumpDrive = $dumpPath.Substring(0, 2)
            $vol = Get-Volume -DriveLetter $dumpDrive[0] -ErrorAction SilentlyContinue
            if ($vol) {
                $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 1)
                $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory / 1GB, 0)
                Write-Info "  Dump drive ($dumpDrive): ${freeGB}GB free (RAM: ${ramGB}GB)"
                if ($freeGB -lt $ramGB) {
                    Write-DiagWarning "  Dump drive has less free space than RAM — complete dump may fail"
                }
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check crash dump config: $($_.Exception.Message)"
    }

    # 4. Installed Software Inventory (non-Microsoft, top 20)
    Write-Section "Installed Software (non-Microsoft, top 20)"
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $software = foreach ($path in $regPaths) {
            if (Test-Path $path) {
                Get-ItemProperty $path -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -and $_.Publisher -and $_.Publisher -notlike '*Microsoft*' } |
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
            }
        }
        $software = $software | Sort-Object DisplayName -Unique
        if ($software) {
            Write-Info "  Non-Microsoft software: $(@($software).Count) packages"
            $software | Select-Object -First 20 | ForEach-Object {
                $ver = if ($_.DisplayVersion) { "v$($_.DisplayVersion)" } else { "" }
                Write-Info "    $($_.DisplayName) $ver ($($_.Publisher))"
            }
            if (@($software).Count -gt 20) {
                Write-Info "    ... and $(@($software).Count - 20) more"
            }
        }
        else {
            Write-Info "  No non-Microsoft software found"
        }
    }
    catch {
        Write-DiagWarning "  Could not enumerate installed software"
    }

    # 5. NIC Power Save Setting
    Write-Section "NIC Power Management (Allow Turn Off)"
    try {
        $netAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
        $checked = 0
        foreach ($nic in $netAdapters) {
            try {
                $pnpDevice = Get-CimInstance Win32_NetworkAdapter -Filter "NetConnectionID='$($nic.Name)'" -ErrorAction SilentlyContinue
                if ($pnpDevice -and $pnpDevice.PNPDeviceID) {
                    $powerMgmt = Get-CimInstance MSPower_DeviceEnable -Namespace root\wmi -ErrorAction SilentlyContinue |
                        Where-Object { $_.InstanceName -like "*$($pnpDevice.PNPDeviceID)*" }
                    if ($powerMgmt) {
                        $checked++
                        if ($powerMgmt.Enable) {
                            Write-DiagWarning "  $($nic.Name): Power save ENABLED — can cause intermittent disconnects on servers!"
                            Write-Info "    Disable: Device Manager → NIC → Power Management → Uncheck 'Allow to turn off'"
                        }
                        else {
                            Write-Success "  $($nic.Name): Power save disabled (good for servers)"
                        }
                    }
                }
            }
            catch { }
        }
        if ($checked -eq 0) {
            Write-Info "  No power-managed adapters reported MSPower_DeviceEnable data"
            Write-Info "  (typical for Hyper-V synthetic / virtual NICs - host owns power policy)."
        }
    }
    catch {
        Write-DiagWarning "  Could not check NIC power management"
    }

    # 6. Windows Features Installed
    Write-Section "Installed Windows Features"
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $features = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed -eq $true })

            # Get-WindowsFeature.FeatureType: 'Role', 'Role Service', 'Feature'
            #   Roles        : top-level workloads (e.g. File and Storage Services, Web Server)
            #   Role Service : sub-component of a Role (Path starts with parent role Name)
            #   Feature      : standalone OS feature (.NET, BitLocker, Failover Clustering, etc.)
            $roles = @($features | Where-Object { $_.FeatureType -eq 'Role' })
            $roleServices = @($features | Where-Object { $_.FeatureType -eq 'Role Service' })
            $plainFeatures = @($features | Where-Object { $_.FeatureType -eq 'Feature' })

            # Server 2016+ default OS components - always installed on Desktop Experience SKUs.
            # Surfacing them in the "deliberately installed" list is noise; bucket separately.
            $osBaselineNames = @(
                'PowerShellRoot', 'PowerShell', 'PowerShell-V2', 'PowerShell-ISE',
                'WoW64-Support', 'Server-Gui-Mgmt-Infra', 'Server-Gui-Shell',
                'XPS-Viewer', 'Windows-Defender', 'Wireless-Networking',
                'System-DataArchiver', 'PNRP', 'WAS', 'WAS-Process-Model',
                'WAS-Config-APIs', 'Direct-Play', 'NET-Framework-Core',
                'NET-Framework-Features'
            )

            # RSAT bucket: admin consoles for managing OTHER servers, not workload features
            $rsatTools = @($plainFeatures | Where-Object { $_.Path -like 'Remote Server Administration Tools*' -or $_.Name -like 'RSAT*' -or $_.Name -in @('Hyper-V-Tools', 'Hyper-V-PowerShell') })

            # Default OS components bucket
            $remaining = @($plainFeatures | Where-Object {
                $_.Path -notlike 'Remote Server Administration Tools*' -and $_.Name -notlike 'RSAT*' -and $_.Name -notin @('Hyper-V-Tools', 'Hyper-V-PowerShell')
            })
            $osBaseline = @($remaining | Where-Object { $_.Name -in $osBaselineNames })

            # Workload features = what was deliberately added beyond the OS baseline
            $workloadFeatures = @($remaining | Where-Object { $_.Name -notin $osBaselineNames })

            # --- Roles + their Role Services (nested) ---
            Write-Info "  Installed Roles: $($roles.Count)"
            if ($roles.Count -eq 0) {
                Write-Info "    (none - File and Storage Services is normally always present; if missing, server is a non-standard install)"
            }
            foreach ($role in $roles | Sort-Object DisplayName) {
                Write-Info "    [Role] $($role.DisplayName) ($($role.Name))"
                $childServices = @($roleServices | Where-Object { $_.Path -like "$($role.Name)\*" -or $_.Path -like "$($role.DisplayName)\*" })
                foreach ($svc in $childServices | Sort-Object DisplayName) {
                    Write-Info "         + $($svc.DisplayName)"
                }
            }
            # Orphan role services (parent role not detected) - rare but possible
            $orphanServices = @($roleServices | Where-Object {
                $svcPath = $_.Path
                $svcName = $_.Name
                -not ($roles | Where-Object { $svcPath -like "$($_.Name)\*" -or $svcPath -like "$($_.DisplayName)\*" -or $svcName -like "$($_.Name)*" })
            })
            if ($orphanServices.Count -gt 0) {
                Write-Info "  Other Role Services: $($orphanServices.Count)"
                foreach ($svc in $orphanServices | Sort-Object DisplayName) {
                    Write-Info "    - $($svc.DisplayName)"
                }
            }

            # --- Workload features (what was DELIBERATELY installed) ---
            Write-Info "  Workload Features Installed: $($workloadFeatures.Count)"
            if ($workloadFeatures.Count -eq 0) {
                Write-Info "    (none beyond OS baseline)"
            }
            else {
                foreach ($f in $workloadFeatures | Sort-Object DisplayName) {
                    Write-Info "    - $($f.DisplayName) ($($f.Name))"
                }
            }

            # --- RSAT Tools (admin consoles, separate bucket) ---
            if ($rsatTools.Count -gt 0) {
                Write-Info "  RSAT Admin Tools: $($rsatTools.Count) installed (managing other servers - not workloads)"
            }

            # --- OS baseline (always-installed components) ---
            if ($osBaseline.Count -gt 0) {
                Write-Info "  Default OS Components: $($osBaseline.Count) (PowerShell, Defender, .NET, etc. - shipped with Server)"
            }
        }
        else {
            Write-Info "  Get-WindowsFeature not available (workstation OS)"
        }
    }
    catch {
        Write-DiagWarning "  Could not enumerate Windows features"
    }

    # 7. NTFS 8.3 Short Name Setting
    Write-Section "NTFS 8.3 Short Name Generation"
    try {
        $ntfs83 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisable8dot3NameCreation' -ErrorAction SilentlyContinue
        $val = if ($ntfs83) { $ntfs83.NtfsDisable8dot3NameCreation } else { 0 }
        $statusText = switch ($val) {
            0 { "Enabled on all volumes (default — performance overhead on large volumes)" }
            1 { "Disabled on all volumes (recommended for servers)" }
            2 { "Enabled per-volume (NTFS setting)" }
            3 { "Disabled except system volume" }
            default { "Unknown ($val)" }
        }
        Write-Info "  NtfsDisable8dot3NameCreation: $val — $statusText"
        if ($val -eq 0) {
            Write-DiagWarning "  Consider disabling 8.3 names for performance on high-file-count volumes"
            Write-Info "  Set: fsutil behavior set disable8dot3 1"
        }
    }
    catch {
        Write-DiagWarning "  Could not check 8.3 name setting"
    }

    # 8. Clear Page File at Shutdown
    Write-Section "Clear Page File at Shutdown"
    try {
        $clearPF = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -ErrorAction SilentlyContinue
        $enabled = if ($clearPF -and $clearPF.ClearPageFileAtShutdown -eq 1) { $true } else { $false }
        if ($enabled) {
            Write-Success "  Page file cleared at shutdown (security compliant)"
            Write-Info "  Note: This can significantly increase shutdown/restart time"
        }
        else {
            Write-Info "  Page file NOT cleared at shutdown (faster restarts, but memory artifacts persist)"
            Write-Info "  For compliance: Set ClearPageFileAtShutdown=1 in Memory Management registry"
        }
    }
    catch {
        Write-DiagWarning "  Could not check page file clear setting"
    }

    # 9. System Driver File Versions
    Write-Section "Critical System Driver Versions"
    try {
        $criticalDrivers = @(
            @{ Path = "$env:SystemRoot\System32\drivers\tcpip.sys"; Name = "TCP/IP Stack" },
            @{ Path = "$env:SystemRoot\System32\drivers\afd.sys"; Name = "Ancillary Function Driver (Winsock)" },
            @{ Path = "$env:SystemRoot\System32\drivers\storport.sys"; Name = "Storage Port Driver" },
            @{ Path = "$env:SystemRoot\System32\drivers\ntfs.sys"; Name = "NTFS File System" },
            @{ Path = "$env:SystemRoot\System32\drivers\mpio.sys"; Name = "Multipath I/O" },
            @{ Path = "$env:SystemRoot\System32\drivers\mrxsmb.sys"; Name = "SMB Redirector" },
            @{ Path = "$env:SystemRoot\System32\drivers\srv2.sys"; Name = "SMB Server" },
            @{ Path = "$env:SystemRoot\System32\drivers\http.sys"; Name = "HTTP Protocol Stack" },
            @{ Path = "$env:SystemRoot\System32\drivers\fltMgr.sys"; Name = "Filter Manager" },
            @{ Path = "$env:SystemRoot\System32\drivers\ndis.sys"; Name = "NDIS Network Stack" }
        )
        foreach ($drv in $criticalDrivers) {
            if (Test-Path $drv.Path) {
                $fileInfo = Get-Item $drv.Path -ErrorAction SilentlyContinue
                $ver = $fileInfo.VersionInfo.FileVersion
                $lastWrite = $fileInfo.LastWriteTime.ToString('yyyy-MM-dd')
                Write-Info "  $($drv.Name): v$ver ($lastWrite)"
            }
            else {
                Write-Info "  $($drv.Name): Not present"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check driver versions"
    }
}

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Generates a comprehensive HTML diagnostic report
    .DESCRIPTION
        Runs all diagnostic checks and produces a styled, collapsible HTML report
    #>
    Write-Header "Generating HTML Diagnostic Report"

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPath = Join-Path $script:DefaultLogPath "ServerReport_${env:COMPUTERNAME}_${timestamp}.html"

    if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
        Write-DiagError "Cannot create report directory"
        return
    }

    Write-Info "Running all diagnostics and capturing output..."
    Write-Info "This may take 2-5 minutes..."

    # Capture output from all major diagnostic functions
    $sections = @(
        @{ Title = "Server Baseline Validation"; Cmd = { Test-ServerBaseline } },
        @{ Title = "Network Configuration"; Cmd = { Test-NetworkConfiguration } },
        @{ Title = "Memory Usage Analysis"; Cmd = { Test-MemoryUsage } },
        @{ Title = "CPU Usage Analysis"; Cmd = { Test-CPUUsage } },
        @{ Title = "Disk Performance Analysis"; Cmd = { Test-DiskPerformance } },
        @{ Title = "Windows Services Health"; Cmd = { Test-ServicesHealth } },
        @{ Title = "Event Log Analysis"; Cmd = { Test-EventLogHealth } },
        @{ Title = "DNS Health"; Cmd = { Test-DNSHealth } },
        @{ Title = "Security & Authentication"; Cmd = { Test-SecurityAuthentication } },
        @{ Title = "Windows Update Status"; Cmd = { Test-WindowsUpdateStatus } },
        @{ Title = "TLS Configuration"; Cmd = { Test-TLSConfiguration } },
        @{ Title = "Cross-Category Scorecard"; Cmd = { Test-CrossCategoryHealth } }
    )

    # Build HTML
    $css = @"
<style>
body { font-family: Consolas, 'Courier New', monospace; background: #1e1e1e; color: #d4d4d4; margin: 20px; font-size: 13px; }
h1 { color: #569cd6; border-bottom: 2px solid #569cd6; padding-bottom: 10px; }
h2 { color: #4ec9b0; cursor: pointer; padding: 8px; background: #252526; border-left: 3px solid #4ec9b0; margin-top: 20px; }
h2:hover { background: #2d2d30; }
.section { padding: 10px 15px; background: #1e1e1e; border-left: 1px solid #333; display: none; }
.section.visible { display: block; }
pre { white-space: pre-wrap; word-wrap: break-word; margin: 0; line-height: 1.5; }
.success { color: #6a9955; }
.warning { color: #ce9178; }
.error { color: #f44747; font-weight: bold; }
.info { color: #d4d4d4; }
.section-header { color: #c586c0; }
.meta { color: #808080; font-size: 12px; margin-bottom: 20px; }
.summary { background: #252526; padding: 15px; border: 1px solid #333; margin: 15px 0; }
.expand-all { color: #569cd6; cursor: pointer; text-decoration: underline; margin-left: 15px; font-size: 12px; }
</style>
"@

    $js = @"
<script>
function toggleSection(id) {
    var el = document.getElementById(id);
    el.classList.toggle('visible');
}
function toggleAll() {
    var sections = document.querySelectorAll('.section');
    var anyHidden = Array.from(sections).some(s => !s.classList.contains('visible'));
    sections.forEach(s => { if (anyHidden) s.classList.add('visible'); else s.classList.remove('visible'); });
}
</script>
"@

    $htmlBody = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Server Diagnostic Report - $env:COMPUTERNAME</title>
$css
</head>
<body>
<h1>Server Diagnostic Report — $env:COMPUTERNAME</h1>
<div class="meta">
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Tool: WSTT v3.0 | OS: $((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption)
<span class="expand-all" onclick="toggleAll()">[Expand/Collapse All]</span>
</div>
<div class="meta" style="color:#9cdcfe;">
SCOM-aligned thresholds in effect: CPU $($CPU_WARNING_THRESHOLD)%, Memory $($MEMORY_WARNING_THRESHOLD)%, System drive $($DISK_SYSTEM_WARNING_THRESHOLD)%, Non-system drive $($DISK_NONSYSTEM_WARNING_THRESHOLD)%. In-script CRITICAL fires at $($CPU_CRITICAL_THRESHOLD)%.
</div>
$js
"@

    $sectionIndex = 0
    foreach ($section in $sections) {
        $sectionIndex++
        Write-Info "  [$sectionIndex/$($sections.Count)] $($section.Title)..."

        # Capture all output streams
        $output = & $section.Cmd *>&1 | Out-String

        # Colorize the output for HTML
        $htmlOutput = [System.Net.WebUtility]::HtmlEncode($output)
        $htmlOutput = $htmlOutput -replace '\[SUCCESS\]', '<span class="success">[SUCCESS]</span>'
        $htmlOutput = $htmlOutput -replace '\[ERROR\]', '<span class="error">[ERROR]</span>'
        # Match WARNING: only at start of a line (after optional whitespace) so
        # we don't double-wrap occurrences inside message bodies.
        $htmlOutput = $htmlOutput -replace '(?m)^(\s*)WARNING:', '$1<span class="warning">WARNING:</span>'
        $htmlOutput = $htmlOutput -replace '\[INFO\]', '<span class="info">[INFO]</span>'
        $htmlOutput = $htmlOutput -replace '---\s(.+?)\s---', '<span class="section-header">--- $1 ---</span>'
        $htmlOutput = $htmlOutput -replace '={40}', '<span class="section-header">========================================</span>'

        $htmlBody += @"

<h2 onclick="toggleSection('section$sectionIndex')">▸ $($section.Title)</h2>
<div class="section" id="section$sectionIndex">
<pre>$htmlOutput</pre>
</div>
"@
    }

    $htmlBody += @"

</body>
</html>
"@

    try {
        $htmlBody | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        Write-Success "HTML Report generated: $reportPath"
        Write-Info "  File size: $([math]::Round((Get-Item $reportPath).Length / 1KB, 1)) KB"

        $open = Get-ValidatedChoice -Prompt "Open report in browser? (Y/N)" -ValidChoices @("Y", "N")
        if ($open -eq "Y") {
            Start-Process $reportPath
        }
    }
    catch {
        Write-DiagError "Failed to generate HTML report: $($_.Exception.Message)"
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

                                                                
     WINDOWS SERVER TROUBLESHOOTING & LOG COLLECTION TOOL       
                         Version 3.0
                                                                

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
            $choice = Get-ValidatedChoice -Prompt "`nSelect an option (0-21)" -ValidChoices @("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21")
            
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

#region Script Entry Point
# Script execution starts here
if ($EnableLogging) {
    Start-TroubleshootingTool -EnableLogging
}
else {
    Start-TroubleshootingTool
}
#endregion