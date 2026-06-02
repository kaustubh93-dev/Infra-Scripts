# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Constants and Configuration
# Source lines: 111 - 194
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
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
