#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive Windows Server Troubleshooting and Log Collection Script
.DESCRIPTION
    Interactive script to diagnose and collect logs for Network, Memory, CPU, Disk, Services, Event Logs, DNS, Security, and Windows Update issues
.PARAMETER EnableLogging
    Enables transcript logging of the entire session
.EXAMPLE
    .\WindowsServertroubleshootingtool_v2.1.ps1
    .\WindowsServertroubleshootingtool_v2.1.ps1 -EnableLogging
.NOTES
    Version: 2.1
    Requires: Administrator privileges
    New Features: Services Health, Event Log Analysis, DNS Diagnostics, Security & Authentication, Windows Update Status
#>

param(
    [switch]$EnableLogging
)

#region Constants and Configuration
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
$DNS_RESOLUTION_WARNING_MS = 30
$DNS_RESOLUTION_CRITICAL_MS = 100

# Path Configuration
$script:TempBasePath = Join-Path $env:TEMP "ServerDiagnostics"
$script:DefaultLogPath = Join-Path $script:TempBasePath "Logs"

# TSS Path Configuration - HARDCODED
$script:TSSPath = "C:\TSS"

# Critical Services to Monitor
$script:CriticalServices = @(
    "DNS", "DHCP", "Spooler", "W32Time", "EventLog",
    "WinRM", "RpcSs", "LanmanServer", "LanmanWorkstation",
    "MSSQLSERVER", "SQLSERVERAGENT", "W3SVC", "IISADMIN"
)
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
    param([string]$Text)
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Text)
    Write-Host "[SUCCESS] $($Text)" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Text)
    Microsoft.PowerShell.Utility\Write-Warning -Message $Text
}

function Write-Error {
    param([string]$Text)
    Microsoft.PowerShell.Utility\Write-Error -Message $Text
}

function Write-Info {
    param([string]$Text)
    Write-Host "[INFO] $($Text)" -ForegroundColor White
}
#endregion

#region Helper Functions
function Initialize-DiagnosticPaths {
    try {
        if (-not (Test-Path $script:TempBasePath)) {
            New-Item -Path $script:TempBasePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Info "Created diagnostic base path: $($script:TempBasePath)"
        }
        
        if (-not (Test-Path $script:DefaultLogPath)) {
            New-Item -Path $script:DefaultLogPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        
        return $true
    } catch {
        Write-Error "Failed to initialize diagnostic paths: $($_.Exception.Message)"
        return $false
    }
}

function Test-PathValid {
    param(
        [string]$Path,
        [switch]$CreateIfNotExist
    )
    
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    
    if (-not (Test-Path $Path -IsValid)) {
        Write-Error "Invalid path format: $($Path)"
        return $false
    }
    
    if (-not (Test-Path $Path)) {
        if ($CreateIfNotExist) {
            try {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Success "Created directory: $($Path)"
                return $true
            } catch {
                Write-Error "Cannot create directory: $($_.Exception.Message)"
                return $false
            }
        } else {
            Write-Warning "Path does not exist: $($Path)"
            return $false
        }
    }
    
    return $true
}

function Get-ValidatedChoice {
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
        
        Write-Warning "Invalid choice. Please enter one of: $($ValidChoices -join ', ')"
    } while ($true)
}

function Invoke-WithTSSCheck {
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
    } else {
        if ($ManualAlternativeAction) {
            & $ManualAlternativeAction
        }
    }
}

function Get-ProcessAnalysis {
    param(
        [int]$TopCount = 10
    )
    
    try {
        $processes = Get-Process -ErrorAction Stop
        
        return @{
            ByCPU = $processes | Sort-Object CPU -Descending | Select-Object -First $TopCount
            ByMemory = $processes | Sort-Object WS -Descending | Select-Object -First $TopCount
            Total = $processes.Count
        }
    } catch {
        Write-Error "Failed to retrieve process information: $($_.Exception.Message)"
        return $null
    }
}
#endregion

#region TSS Functions
function Set-TSSPath {
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
    
    if (-not (Test-Path $userPath -PathType Container)) {
        Write-Error "Invalid path: Directory does not exist"
        return $false
    }
    
    $tssScript = Join-Path $userPath "TSS.ps1"
    if (-not (Test-Path $tssScript -PathType Leaf)) {
        Write-Error "TSS.ps1 not found in the specified directory: $($userPath)"
        Write-Info "Please ensure TSS.ps1 exists in the folder you specified."
        return $false
    }
    
    $script:TSSPath = $userPath
    Write-Success "TSS path updated to: $($script:TSSPath)"
    return $true
}

function Test-TSSAvailable {
    if ([string]::IsNullOrWhiteSpace($script:TSSPath)) {
        Write-Warning "TSS path not configured"
        Write-Info "Please configure TSS path from the main menu (option 12)"
        Write-Info "Download TSS from:"
        Write-Info "  - https://aka.ms/getTSS"
        Write-Info "  - https://aka.ms/getTSSlite"
        Write-Info "  - https://cesdiagtools.blob.core.windows.net/windows/TSS.zip"
        return $false
    }
    
    if (-not (Test-Path $script:TSSPath -PathType Container)) {
        Write-Warning "TSS directory not found at: $($script:TSSPath)"
        Write-Info "Please update TSS path from the main menu (option 12)"
        return $false
    }
    
    $tssScript = Join-Path $script:TSSPath "TSS.ps1"
    if (Test-Path $tssScript) {
        Write-Success "TSS found at: $($tssScript)"
        return $true
    } else {
        Write-Warning "TSS.ps1 not found at: $($script:TSSPath)"
        Write-Info "Please verify TSS installation or update path from the main menu (option 12)"
        return $false
    }
}

function Invoke-TSSCommand {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Command
    )
    
    if ([string]::IsNullOrWhiteSpace($script:TSSPath)) {
        Write-Error "TSS path not configured. Please configure from main menu (option 12)"
        return $false
    }
    
    if (-not (Test-Path $script:TSSPath -PathType Container)) {
        Write-Error "TSS directory not found at: $($script:TSSPath)"
        return $false
    }
    
    $tssScript = Join-Path $script:TSSPath "TSS.ps1"
    if (-not (Test-Path $tssScript)) {
        Write-Error "TSS.ps1 not found at: $($tssScript)"
        return $false
    }
    
    $currentLocation = Get-Location
    
    try {
        Set-Location $script:TSSPath
        $fullCommand = "& '$tssScript' $Command"
        Write-Info "Executing: $fullCommand"
        Invoke-Expression $fullCommand
        Write-Success "TSS command completed"
        return $true
    } catch {
        Write-Error "Failed to execute TSS command: $($_.Exception.Message)"
        return $false
    } finally {
        Set-Location $currentLocation
    }
}
#endregion

#region Network Diagnostics - Sub-Functions

function Test-TCPIPConfiguration {
    <#
    .SYNOPSIS
        Checks TCP/IP configuration for all active network adapters
    #>
    Write-Info "`n=== TCP/IP Configuration ==="
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.Status -eq "Up"}
        
        foreach ($adapter in $adapters) {
            Write-Info "`nAdapter: $($adapter.Name) [$($adapter.InterfaceDescription)]"
            
            # IPv4 Configuration
            $ipv4 = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($ipv4) {
                Write-Info "  IPv4 Address: $($ipv4.IPAddress)/$($ipv4.PrefixLength)"
                $dhcpEnabled = $ipv4.PrefixOrigin -eq 'Dhcp'
                Write-Info "  DHCP Enabled: $dhcpEnabled"
                
                if (-not $dhcpEnabled) {
                    Write-Success "    Static IP configuration"
                }
            }
            
            # IPv6 Configuration
            $ipv6 = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {$_.AddressState -eq "Preferred"}
            if ($ipv6) {
                Write-Info "  IPv6 Address: $($ipv6.IPAddress)"
            }
            
            # Default Gateway
            $gateway = Get-NetRoute -InterfaceAlias $adapter.Name -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
            if ($gateway) {
                Write-Info "  Default Gateway: $($gateway.NextHop)"
                
                # Test gateway connectivity
                $pingResult = Test-Connection -ComputerName $gateway.NextHop -Count 2 -Quiet -ErrorAction SilentlyContinue
                if ($pingResult) {
                    $ping = Test-Connection -ComputerName $gateway.NextHop -Count 1 -ErrorAction SilentlyContinue
                    if ($ping) {
                        $latency = $ping.ResponseTime
                        if ($latency -lt 5) {
                            Write-Success "    Gateway Reachable (${latency}ms - Excellent)"
                        } elseif ($latency -lt 20) {
                            Write-Info "    Gateway Reachable (${latency}ms - Good)"
                        } else {
                            Write-Warning "    Gateway Reachable (${latency}ms - High Latency)"
                        }
                    }
                } else {
                    Write-Error "    Gateway NOT Reachable!"
                }
            } else {
                Write-Warning "  No default gateway configured"
            }
            
            # Check for IP conflicts
            $ipConfig = Get-NetIPConfiguration -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue
            if ($ipConfig) {
                $interfaceMetric = $ipConfig.IPv4DefaultGateway.InterfaceMetric
                Write-Info "  Interface Metric: $interfaceMetric"
            }
        }
    } catch {
        Write-Error "Failed to check TCP/IP configuration: $($_.Exception.Message)"
    }
}

function Test-NetworkDriverInfo {
    <#
    .SYNOPSIS
        Checks network adapter driver information
    #>
    Write-Info "`n=== Network Adapter Driver Information ==="
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.Status -eq "Up"}
        
        foreach ($adapter in $adapters) {
            Write-Info "`nAdapter: $($adapter.Name)"
            
            try {
                $driver = Get-NetAdapterDriver -Name $adapter.Name -ErrorAction Stop
                
                Write-Info "  Driver Version: $($driver.DriverVersion)"
                Write-Info "  Driver Date: $($driver.DriverDate.ToString('yyyy-MM-dd'))"
                Write-Info "  Driver Provider: $($driver.DriverProvider)"
                Write-Info "  Driver Description: $($driver.DriverDescription)"
                
                # Check driver age
                $driverAge = (New-TimeSpan -Start $driver.DriverDate -End (Get-Date)).Days
                Write-Info "  Driver Age: $driverAge days"
                
                if ($driverAge -gt 730) {  # 2 years
                    Write-Warning "    Driver is over 2 years old - consider updating"
                } elseif ($driverAge -gt 365) {  # 1 year
                    Write-Info "    Driver is over 1 year old - check for updates"
                } else {
                    Write-Success "    Driver is relatively current"
                }
                
                # Hardware Info
                Write-Info "  Link Speed: $($adapter.LinkSpeed)"
                Write-Info "  Media Type: $($adapter.MediaType)"
                Write-Info "  Physical Media Type: $($adapter.PhysicalMediaType)"
                
            } catch {
                Write-Warning "  Could not retrieve driver information: $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Error "Failed to enumerate adapters for driver check: $($_.Exception.Message)"
    }
}

function Test-NetworkPerformanceMetrics {
    <#
    .SYNOPSIS
        Retrieves real-time network performance metrics
    #>
    Write-Info "`n=== Network Performance Metrics ==="
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.Status -eq "Up"}
        
        foreach ($adapter in $adapters) {
            Write-Info "`nAdapter: $($adapter.Name)"
            
            try {
                # Get current statistics
                $stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction Stop
                
                Write-Info "  Received Packets: $($stats.ReceivedUnicastPackets)"
                Write-Info "  Sent Packets: $($stats.SentUnicastPackets)"
                Write-Info "  Received Bytes: $([math]::Round($stats.ReceivedBytes / 1GB, 2)) GB"
                Write-Info "  Sent Bytes: $([math]::Round($stats.SentBytes / 1GB, 2)) GB"
                
                # Errors
                if ($stats.ReceivedPacketErrors -gt 0 -or $stats.OutboundPacketErrors -gt 0) {
                    Write-Warning "  Received Errors: $($stats.ReceivedPacketErrors)"
                    Write-Warning "  Sent Errors: $($stats.OutboundPacketErrors)"
                } else {
                    Write-Success "  No packet errors detected"
                }
                
                if ($stats.ReceivedDiscardedPackets -gt 0 -or $stats.OutboundDiscardedPackets -gt 0) {
                    Write-Warning "  Received Discarded: $($stats.ReceivedDiscardedPackets)"
                    Write-Warning "  Sent Discarded: $($stats.OutboundDiscardedPackets)"
                }
                
                # Try to get performance counters
                try {
                    $nicName = $adapter.InterfaceDescription
                    $outputQueue = Get-Counter "\Network Interface($nicName)\Output Queue Length" -ErrorAction SilentlyContinue
                    if ($outputQueue) {
                        $queueLength = [math]::Round($outputQueue.CounterSamples.CookedValue, 2)
                        Write-Info "  Output Queue Length: $queueLength"
                        if ($queueLength -gt 2) {
                            Write-Warning "    High output queue - possible bottleneck"
                        }
                    }
                } catch {
                    # Performance counter not available
                }
                
            } catch {
                Write-Warning "  Could not retrieve performance metrics: $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Error "Failed to check network performance: $($_.Exception.Message)"
    }
}

function Test-NetworkOffloading {
    <#
    .SYNOPSIS
        Checks network adapter offloading features
    #>
    Write-Info "`n=== Network Adapter Offloading Features ==="
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.Status -eq "Up"}
        
        foreach ($adapter in $adapters) {
            Write-Info "`nAdapter: $($adapter.Name)"
            
            try {
                # Get offload settings
                $checksumOffload = Get-NetAdapterChecksumOffload -Name $adapter.Name -ErrorAction Stop
                $lsoOffload = Get-NetAdapterLso -Name $adapter.Name -ErrorAction Stop
                
                # Checksum Offload
                Write-Info "  IPv4 Checksum Offload:"
                Write-Info "    Tx: $($checksumOffload.IpIPv4Enabled)"
                Write-Info "    Rx: $($checksumOffload.IpIPv4Enabled)"
                
                Write-Info "  TCP Checksum Offload (IPv4):"
                Write-Info "    Tx: $($checksumOffload.TcpIPv4Enabled)"
                Write-Info "    Rx: $($checksumOffload.TcpIPv4Enabled)"
                
                Write-Info "  UDP Checksum Offload (IPv4):"
                Write-Info "    Tx: $($checksumOffload.UdpIPv4Enabled)"
                Write-Info "    Rx: $($checksumOffload.UdpIPv4Enabled)"
                
                # Large Send Offload
                Write-Info "  Large Send Offload v2 (IPv4): $($lsoOffload.IPv4Enabled)"
                
                # RSC (Receive Segment Coalescing)
                try {
                    $rsc = Get-NetAdapterRsc -Name $adapter.Name -ErrorAction SilentlyContinue
                    if ($rsc) {
                        Write-Info "  Receive Segment Coalescing (IPv4): $($rsc.IPv4Enabled)"
                    }
                } catch {
                    # RSC not available on this adapter
                }
                
                # Recommendations
                $offloadCount = 0
                if ($checksumOffload.TcpIPv4Enabled) { $offloadCount++ }
                if ($lsoOffload.IPv4Enabled) { $offloadCount++ }
                
                if ($offloadCount -eq 0) {
                    Write-Warning "    Consider enabling offload features for better performance"
                } else {
                    Write-Success "    Offload features are enabled"
                }
                
            } catch {
                Write-Warning "  Could not retrieve offload settings: $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Error "Failed to check offload features: $($_.Exception.Message)"
    }
}

function Test-SMBConfiguration {
    <#
    .SYNOPSIS
        Checks SMB/CIFS configuration and status
    #>
    Write-Info "`n=== SMB/CIFS Configuration ==="
    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        
        Write-Info "SMB Server Configuration:"
        Write-Info "  SMB Signing Required: $($smbConfig.RequireSecuritySignature)"
        Write-Info "  SMB Encryption Required: $($smbConfig.EncryptData)"
        Write-Info "  SMB Multichannel Enabled: $($smbConfig.EnableMultiChannel)"
        
        # Check SMB1 status
        Write-Info "`nSMB Protocol Versions:"
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1Feature) {
            if ($smb1Feature.State -eq "Enabled") {
                Write-Error "  SMB 1.0: ENABLED - CRITICAL SECURITY RISK!"
                Write-Info "    Disable with: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
            } else {
                Write-Success "  SMB 1.0: Disabled (Secure)"
            }
        }
        
        Write-Info "  SMB 2.0/2.1: $($smbConfig.EnableSMB2Protocol)"
        
        # Check active SMB sessions
        $smbSessions = Get-SmbSession -ErrorAction SilentlyContinue
        Write-Info "`nActive SMB Sessions: $($smbSessions.Count)"
        
        if ($smbSessions.Count -gt 0) {
            $smb3Sessions = $smbSessions | Where-Object {$_.Dialect -like "3.*"}
            $smb2Sessions = $smbSessions | Where-Object {$_.Dialect -like "2.*"}
            
            Write-Info "  SMB 3.x Sessions: $($smb3Sessions.Count)"
            Write-Info "  SMB 2.x Sessions: $($smb2Sessions.Count)"
            
            if ($smb3Sessions.Count -eq 0 -and $smbSessions.Count -gt 0) {
                Write-Warning "    No SMB 3.x sessions - older clients may be connecting"
            }
        }
        
        # Check SMB shares
        $smbShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {$_.Special -eq $false}
        if ($smbShares) {
            Write-Info "`nSMB Shares: $($smbShares.Count) non-system shares"
        }
        
        # SMB Performance
        try {
            $smbClient = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
            if ($smbClient) {
                Write-Info "`nSMB Client Configuration:"
                Write-Info "  Connection Count: $($smbClient.ConnectionCountPerRssNetworkInterface)"
                Write-Info "  Multichannel: $($smbClient.EnableMultiChannel)"
            }
        } catch {
            # Not available on this system
        }
        
    } catch {
        Write-Warning "Could not check SMB configuration: $($_.Exception.Message)"
        Write-Info "  SMB server may not be installed or running"
    }
}

function Test-ConnectivityTests {
    <#
    .SYNOPSIS
        Performs connectivity tests to key destinations
    #>
    Write-Info "`n=== Network Connectivity Tests ==="
    
    # Test internet connectivity
    Write-Info "`nInternet Connectivity:"
    $testHosts = @(
        @{Name="Google DNS"; IP="8.8.8.8"},
        @{Name="Cloudflare DNS"; IP="1.1.1.1"},
        @{Name="Microsoft"; IP="microsoft.com"}
    )
    
    foreach ($testHost in $testHosts) {
        try {
            $result = Test-Connection -ComputerName $testHost.IP -Count 2 -ErrorAction SilentlyContinue
            if ($result) {
                $avgLatency = ($result | Measure-Object -Property ResponseTime -Average).Average
                $avgLatency = [math]::Round($avgLatency, 2)
                
                if ($avgLatency -lt 50) {
                    Write-Success "  $($testHost.Name): Reachable (${avgLatency}ms - Good)"
                } elseif ($avgLatency -lt 150) {
                    Write-Info "  $($testHost.Name): Reachable (${avgLatency}ms - Acceptable)"
                } else {
                    Write-Warning "  $($testHost.Name): Reachable (${avgLatency}ms - High Latency)"
                }
            } else {
                Write-Error "  $($testHost.Name): NOT Reachable"
            }
        } catch {
            Write-Error "  $($testHost.Name): Connection test failed"
        }
    }
    
    # Test for packet loss
    Write-Info "`nPacket Loss Test (Google DNS - 10 packets):"
    try {
        $lossTest = Test-Connection -ComputerName "8.8.8.8" -Count 10 -ErrorAction SilentlyContinue
        if ($lossTest) {
            $received = $lossTest.Count
            $loss = ((10 - $received) / 10) * 100
            
            if ($loss -eq 0) {
                Write-Success "  Packet Loss: 0% (Excellent)"
            } elseif ($loss -lt 5) {
                Write-Info "  Packet Loss: $loss% (Acceptable)"
            } elseif ($loss -lt 10) {
                Write-Warning "  Packet Loss: $loss% (Concerning)"
            } else {
                Write-Error "  Packet Loss: $loss% (CRITICAL)"
            }
        } else {
            Write-Error "  Could not complete packet loss test"
        }
    } catch {
        Write-Warning "Packet loss test failed: $($_.Exception.Message)"
    }
}

function Test-NICTeaming {
    <#
    .SYNOPSIS
        Checks NIC Teaming configuration
    #>
    Write-Info "`n=== NIC Teaming Status ==="
    try {
        $teams = Get-NetLbfoTeam -ErrorAction SilentlyContinue
        
        if ($teams) {
            Write-Info "Found $($teams.Count) NIC Team(s):"
            
            foreach ($team in $teams) {
                Write-Info "`nTeam: $($team.Name)"
                Write-Info "  Status: $($team.Status)"
                Write-Info "  Teaming Mode: $($team.TeamingMode)"
                Write-Info "  Load Balancing Algorithm: $($team.LoadBalancingAlgorithm)"
                Write-Info "  Member Adapters: $($team.Members -join ', ')"
                
                if ($team.Status -ne "Up") {
                    Write-Error "    CRITICAL: Team is not fully operational!"
                } else {
                    Write-Success "    Team is operational"
                }
                
                # Check team members
                $teamMembers = Get-NetLbfoTeamMember -Team $team.Name -ErrorAction SilentlyContinue
                if ($teamMembers) {
                    Write-Info "  Member Status:"
                    foreach ($member in $teamMembers) {
                        $status = if ($member.AdministrativeMode -eq "Active") {
                            "Active"
                        } else {
                            "Standby"
                        }
                        Write-Info "    $($member.Name): $status - $($member.OperationalStatus)"
                    }
                }
            }
        } else {
            Write-Info "No NIC Teams configured"
        }
    } catch {
        Write-Info "NIC Teaming is not available or not configured"
    }
}

function Test-RoutingAndARP {
    <#
    .SYNOPSIS
        Checks routing table and ARP cache
    #>
    Write-Info "`n=== Routing Table ==="
    try {
        # Get default routes
        $defaultRoutes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop
        
        Write-Info "Default Routes:"
        foreach ($route in $defaultRoutes) {
            Write-Info "  Interface: $($route.InterfaceAlias)"
            Write-Info "  Next Hop: $($route.NextHop)"
            Write-Info "  Metric: $($route.RouteMetric)"
        }
        
        # Get static routes
        $staticRoutes = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            $_.DestinationPrefix -ne "0.0.0.0/0" -and 
            $_.DestinationPrefix -notlike "127.*" -and
            $_.DestinationPrefix -notlike "169.254.*" -and
            $_.DestinationPrefix -notlike "224.*" -and
            $_.DestinationPrefix -notlike "255.*" -and
            $_.NextHop -ne "0.0.0.0"
        }
        
        if ($staticRoutes) {
            Write-Info "`nStatic/Additional Routes: $($staticRoutes.Count)"
            $staticRoutes | Select-Object -First 10 | ForEach-Object {
                Write-Info "  $($_.DestinationPrefix) via $($_.NextHop) [$($_.InterfaceAlias)]"
            }
        }
        
    } catch {
        Write-Warning "Could not retrieve routing table: $($_.Exception.Message)"
    }
    
    # ARP Cache
    Write-Info "`nARP Cache:"
    try {
        $arpCache = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object {$_.State -ne "Unreachable"}
        Write-Info "  Total ARP Entries: $($arpCache.Count)"
        
        $reachable = $arpCache | Where-Object {$_.State -eq "Reachable"}
        $stale = $arpCache | Where-Object {$_.State -eq "Stale"}
        
        Write-Info "  Reachable: $($reachable.Count)"
        Write-Info "  Stale: $($stale.Count)"
        
        if ($stale.Count -gt 100) {
            Write-Warning "    Large number of stale ARP entries - consider clearing cache"
        }
    } catch {
        Write-Warning "Could not retrieve ARP cache: $($_.Exception.Message)"
    }
}

function Test-MTUConfiguration {
    <#
    .SYNOPSIS
        Checks MTU and Jumbo Frame configuration
    #>
    Write-Info "`n=== MTU and Jumbo Frames Configuration ==="
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.Status -eq "Up"}
        
        foreach ($adapter in $adapters) {
            Write-Info "`nAdapter: $($adapter.Name)"
            
            # Get MTU from IP interface
            $ipInterface = Get-NetIPInterface -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($ipInterface) {
                $mtu = $ipInterface.NlMtu
                Write-Info "  MTU Size: $mtu bytes"
                
                if ($mtu -eq 1500) {
                    Write-Success "    Standard Ethernet MTU"
                } elseif ($mtu -ge 9000) {
                    Write-Success "    Jumbo Frames Enabled ($mtu bytes)"
                } elseif ($mtu -gt 1500) {
                    Write-Info "    Custom MTU configured"
                } else {
                    Write-Warning "    MTU is below standard (may cause issues)"
                }
            }
            
            # Check Jumbo Packet support
            try {
                $advProps = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue
                $jumboPacket = $advProps | Where-Object {$_.DisplayName -like "*Jumbo*" -or $_.RegistryKeyword -like "*JumboPacket*"}
                
                if ($jumboPacket) {
                    Write-Info "  Jumbo Packet Setting: $($jumboPacket.DisplayValue)"
                }
            } catch {
                # Jumbo packet setting not available
            }
        }
    } catch {
        Write-Error "Failed to check MTU configuration: $($_.Exception.Message)"
    }
}

function Test-NetworkAdapterAdvancedSettings {
    <#
    .SYNOPSIS
        Checks critical network adapter advanced settings
    #>
    Write-Info "`n=== Network Adapter Advanced Settings ==="
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.Status -eq "Up"}
        
        foreach ($adapter in $adapters) {
            Write-Info "`nAdapter: $($adapter.Name)"
            
            try {
                $advProps = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction Stop
                
                # Key settings to check
                $keySettings = @{
                    "*InterruptModeration" = "Interrupt Moderation"
                    "*FlowControl" = "Flow Control"
                    "*SpeedDuplex" = "Speed & Duplex"
                    "*EEE" = "Energy Efficient Ethernet"
                    "*PriorityVLANTag" = "Priority & VLAN"
                }
                
                foreach ($setting in $keySettings.GetEnumerator()) {
                    $prop = $advProps | Where-Object {$_.RegistryKeyword -eq $setting.Key}
                    if ($prop) {
                        Write-Info "  $($setting.Value): $($prop.DisplayValue)"
                    }
                }
                
                # Check RSS settings
                $rss = Get-NetAdapterRss -Name $adapter.Name -ErrorAction SilentlyContinue
                if ($rss) {
                    Write-Info "  RSS Enabled: $($rss.Enabled)"
                    if ($rss.Enabled) {
                        Write-Info "  RSS Processor Count: $($rss.NumberOfReceiveQueues)"
                    }
                }
                
            } catch {
                Write-Warning "  Could not retrieve advanced settings: $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Error "Failed to check adapter settings: $($_.Exception.Message)"
    }
}

function Test-TCPIPPerformanceTuning {
    <#
    .SYNOPSIS
        Checks TCP/IP performance tuning parameters
    #>
    Write-Info "`n=== TCP/IP Performance Tuning ==="
    try {
        # Get TCP Global Settings
        $tcpSettings = Get-NetTCPSetting -ErrorAction Stop | Where-Object {$_.SettingName -eq "Internet"}
        
        if ($tcpSettings) {
            Write-Info "TCP Configuration (Internet Profile):"
            Write-Info "  Congestion Provider: $($tcpSettings.CongestionProvider)"
            Write-Info "  Window Scaling: $($tcpSettings.ScalingHeuristics)"
            Write-Info "  Timestamps: $($tcpSettings.Timestamps)"
            Write-Info "  Initial RTO (ms): $($tcpSettings.InitialRto)"
            Write-Info "  Max SYN Retransmissions: $($tcpSettings.MaxSynRetransmissions)"
            
            # Check auto-tuning level
            $autoTuningLevel = netsh interface tcp show global | Select-String "Receive Window Auto-Tuning Level"
            if ($autoTuningLevel) {
                Write-Info "  $($autoTuningLevel)"
            }
            
            # Recommendations
            if ($tcpSettings.CongestionProvider -eq "None") {
                Write-Warning "    Consider enabling CTCP or CUBIC for better performance"
            }
        }
        
        # TCP Connection Statistics
        Write-Info "`nTCP Connection Statistics:"
        $tcpConnections = Get-NetTCPConnection -ErrorAction Stop
        $established = ($tcpConnections | Where-Object {$_.State -eq "Established"}).Count
        $timeWait = ($tcpConnections | Where-Object {$_.State -eq "TimeWait"}).Count
        $closeWait = ($tcpConnections | Where-Object {$_.State -eq "CloseWait"}).Count
        
        Write-Info "  Established Connections: $established"
        Write-Info "  Time-Wait Connections: $timeWait"
        Write-Info "  Close-Wait Connections: $closeWait"
        
        if ($timeWait -gt 1000) {
            Write-Warning "    High number of TIME_WAIT connections"
        }
        
        if ($closeWait -gt 100) {
            Write-Warning "    High number of CLOSE_WAIT connections - possible application issue"
        }
        
    } catch {
        Write-Warning "Could not retrieve TCP/IP tuning parameters: $($_.Exception.Message)"
    }
}

function Test-NetBIOSAndWINS {
    <#
    .SYNOPSIS
        Checks NetBIOS and WINS configuration
    #>
    Write-Info "`n=== NetBIOS and WINS Configuration ==="
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.Status -eq "Up"}
        
        foreach ($adapter in $adapters) {
            Write-Info "`nAdapter: $($adapter.Name)"
            
            # Check NetBIOS over TCP/IP setting
            $adapterConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "Index='$($adapter.ifIndex)'" -ErrorAction SilentlyContinue
            
            if ($adapterConfig) {
                $netbiosOption = $adapterConfig.TcpipNetbiosOptions
                
                $netbiosStatus = switch ($netbiosOption) {
                    0 { "Enabled via DHCP" }
                    1 { "Enabled" }
                    2 { "Disabled" }
                    default { "Unknown" }
                }
                
                Write-Info "  NetBIOS over TCP/IP: $netbiosStatus"
                
                if ($netbiosOption -ne 2) {
                    Write-Warning "    Consider disabling NetBIOS if not needed for security"
                } else {
                    Write-Success "    NetBIOS is disabled (Secure)"
                }
                
                # Check WINS configuration
                if ($adapterConfig.WINSPrimaryServer) {
                    Write-Info "  Primary WINS Server: $($adapterConfig.WINSPrimaryServer)"
                    if ($adapterConfig.WINSSecondaryServer) {
                        Write-Info "  Secondary WINS Server: $($adapterConfig.WINSSecondaryServer)"
                    }
                } else {
                    Write-Info "  WINS: Not configured"
                }
            }
        }
        
        # Check NetBIOS name cache
        try {
            $nbtstat = nbtstat -c 2>$null
            if ($nbtstat) {
                $cacheEntries = ($nbtstat | Select-String "entries in the cache" | Out-String).Trim()
                if ($cacheEntries) {
                    Write-Info "`nNetBIOS Name Cache: $cacheEntries"
                }
            }
        } catch {
            # nbtstat not available or failed
        }
        
    } catch {
        Write-Warning "Could not check NetBIOS/WINS configuration: $($_.Exception.Message)"
    }
}

function Test-RSSStatus {
    <#
    .SYNOPSIS
        Checks RSS (Receive Side Scaling) status
    #>
    Write-Info "`n=== RSS (Receive Side Scaling) Status ==="
    try {
        $adapters = Get-NetAdapterRss -ErrorAction Stop
        
        foreach ($adapter in $adapters) {
            Write-Info "Adapter: $($adapter.Name)"
            if ($adapter.Enabled -eq $true) {
                Write-Success "  RSS: ENABLED"
                Write-Info "  Base Processor: $($adapter.BaseProcessorNumber)"
                Write-Info "  Max Processors: $($adapter.MaxProcessors)"
                Write-Info "  Max Processor Number: $($adapter.MaxProcessorNumber)"
                Write-Info "  Number of Receive Queues: $($adapter.NumberOfReceiveQueues)"
            } else {
                Write-Warning "  RSS: DISABLED"
                Write-Info "  To enable: Set-NetAdapterRss -Name '$($adapter.Name)' -Enabled `$true"
            }
        }
    } catch {
        Write-Error "Failed to check RSS status: $($_.Exception.Message)"
    }
}

function Test-VMQStatus {
    <#
    .SYNOPSIS
        Checks VMQ (Virtual Machine Queue) status
    #>
    Write-Info "`n=== VMQ (Virtual Machine Queue) Status ==="
    try {
        $vmq = Get-NetAdapterVmq -ErrorAction SilentlyContinue
        if ($vmq) {
            foreach ($v in $vmq) {
                Write-Info "Adapter: $($v.Name)"
                Write-Info "  VMQ Enabled: $($v.Enabled)"
                
                if ($v.Enabled -eq $true) {
                    Write-Info "  Base Processor: $($v.BaseProcessorNumber)"
                    Write-Info "  Max Processors: $($v.MaxProcessors)"
                    Write-Warning "    Note: If this is a 1Gbps Broadcom adapter, consider disabling VMQ to prevent packet drops"
                } else {
                    Write-Info "  VMQ is disabled"
                }
            }
        } else {
            Write-Info "No VMQ-capable adapters found or VMQ not available"
        }
    } catch {
        Write-Warning "Could not retrieve VMQ information: $($_.Exception.Message)"
    }
}

function Test-EphemeralPorts {
    <#
    .SYNOPSIS
        Checks TCP ephemeral port usage
    #>
    Write-Info "`n=== TCP Ephemeral Port Usage ==="
    try {
        $tcpParams = Get-NetTCPSetting -ErrorAction Stop | Select-Object -First 1 -Property DynamicPortRangeStartPort, DynamicPortRangeNumberOfPorts
        $currentConnections = (Get-NetTCPConnection -ErrorAction Stop).Count
        $maxPorts = $tcpParams.DynamicPortRangeNumberOfPorts
        
        Write-Info "Active TCP Connections: $currentConnections"
        Write-Info "Max Dynamic Ports Available: $maxPorts"
        Write-Info "Dynamic Port Range Start: $($tcpParams.DynamicPortRangeStartPort)"
        
        $usagePercent = [math]::Round(($currentConnections / $maxPorts) * 100, 2)
        Write-Info "Port Usage: $usagePercent%"
        
        if ($currentConnections -gt ($maxPorts * $PORT_EXHAUSTION_THRESHOLD)) {
            Write-Error "CRITICAL: Potential Port Exhaustion (Using >$($PORT_EXHAUSTION_THRESHOLD * 100)% of available ports)"
            Write-Info "  Consider increasing dynamic port range:"
            Write-Info "  netsh int ipv4 set dynamicport tcp start=10000 num=55536"
        } elseif ($usagePercent -gt 50) {
            Write-Warning "Port usage is above 50% - monitor for exhaustion"
        } else {
            Write-Success "Port usage is within acceptable range"
        }
    } catch {
        Write-Error "Failed to check ephemeral ports: $($_.Exception.Message)"
    }
}

function Test-PowerPlan {
    <#
    .SYNOPSIS
        Checks system power plan
    #>
    Write-Info "`n=== System Power Plan ==="
    try {
        $powerPlan = powercfg /getactivescheme
        if ($powerPlan -like "*High performance*") {
            Write-Success "Power Plan: High Performance (Optimal for servers)"
        } elseif ($powerPlan -like "*Balanced*") {
            Write-Warning "Power Plan: Balanced"
            Write-Info "  Recommendation: Switch to High Performance for consistent network performance"
            Write-Info "  Command: powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        } else {
            Write-Warning "Power Plan: $($powerPlan)"
            Write-Info "  Recommendation: Switch to High Performance"
            Write-Info "  Command: powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        }
    } catch {
        Write-Error "Failed to check power plan: $($_.Exception.Message)"
    }
}

#endregion

#region Network Diagnostics - Main Function
function Test-NetworkConfiguration {
    <#
    .SYNOPSIS
        Comprehensive network configuration and health check
    .DESCRIPTION
        Performs all network diagnostics including TCP/IP, drivers, performance, and configurations
    #>
    Write-Header "Comprehensive Network Configuration Check"
    
    # HIGH PRIORITY CHECKS
    Test-TCPIPConfiguration
    Test-NetworkDriverInfo
    Test-NetworkPerformanceMetrics
    Test-NetworkOffloading
    Test-SMBConfiguration
    Test-ConnectivityTests
    
    # MEDIUM PRIORITY CHECKS
    Test-NICTeaming
    Test-RoutingAndARP
    Test-MTUConfiguration
    Test-NetworkAdapterAdvancedSettings
    Test-TCPIPPerformanceTuning
    Test-NetBIOSAndWINS
    
    # EXISTING CHECKS (Reorganized)
    Test-RSSStatus
    Test-VMQStatus
    Test-EphemeralPorts
    Test-PowerPlan
    
    # Summary
    Write-Info "`n========================================
"
    Write-Success "Network diagnostic check completed!"
    Write-Info "Review warnings and errors above for issues requiring attention."
}
#endregion

function Start-NetworkLogCollection {
    Write-Header "Network Issue Log Collection"
    
    $tssAvailable = Test-TSSAvailable
    
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
    Write-Info "`nManual Network Trace Commands:"
    Write-Host @"
    
START TRACE:
netsh trace start scenario=netconnection globallevel=5 capture=yes report=no overwrite=yes persistent=yes maxsize=1024 tracefile=C:\temp\casedata\%computername%.etl

STOP TRACE:
netsh trace stop

"@ -ForegroundColor Cyan
}
#endregion

#region Memory Diagnostics - Sub-Functions

function Test-PageFileConfiguration {
    <#
    .SYNOPSIS
        Analyzes page file configuration and usage
    #>
    Write-Info "`n=== Page File Configuration & Usage ==="
    try {
        $pageFiles = Get-CimInstance Win32_PageFileUsage -ErrorAction Stop
        $pageFileSettings = Get-CimInstance Win32_PageFileSetting -ErrorAction Stop
        
        $os = Get-CimInstance Win32_OperatingSystem
        $totalRAM_GB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        
        Write-Info "Physical RAM: $totalRAM_GB GB"
        
        if ($pageFiles.Count -eq 0) {
            Write-Error "No page file configured - System may crash under memory pressure!"
            Write-Info "  Recommendation: Configure page file at 1.5x-3x RAM size"
            return
        }
        
        Write-Info "`nPage File Configuration:"
        foreach ($pf in $pageFiles) {
            $currentSize_GB = [math]::Round($pf.AllocatedBaseSize / 1024, 2)
            $currentUsage_GB = [math]::Round($pf.CurrentUsage / 1024, 2)
            $usagePercent = [math]::Round(($pf.CurrentUsage / $pf.AllocatedBaseSize) * 100, 2)
            
            Write-Info "`nLocation: $($pf.Name)"
            Write-Info "  Allocated Size: $currentSize_GB GB"
            Write-Info "  Current Usage: $currentUsage_GB GB ($usagePercent%)"
            
            if ($usagePercent -gt 90) {
                Write-Error "    CRITICAL: Page file usage above 90%! System may run out of virtual memory"
            } elseif ($usagePercent -gt 80) {
                Write-Warning "    WARNING: Page file usage above 80%"
            } else {
                Write-Success "    Page file usage is acceptable"
            }
            
            # Check if on system drive
            if ($pf.Name -like "C:*") {
                Write-Warning "    Page file is on system drive - consider additional page file on separate disk"
            }
        }
        
        # Page file settings
        if ($pageFileSettings) {
            foreach ($setting in $pageFileSettings) {
                $initialSize_GB = [math]::Round($setting.InitialSize / 1024, 2)
                $maxSize_GB = [math]::Round($setting.MaximumSize / 1024, 2)
                
                Write-Info "`nPage File Settings: $($setting.Name)"
                if ($setting.InitialSize -eq 0 -and $setting.MaximumSize -eq 0) {
                    Write-Info "  Type: System-managed"
                } else {
                    Write-Info "  Initial Size: $initialSize_GB GB"
                    Write-Info "  Maximum Size: $maxSize_GB GB"
                    
                    if ($initialSize_GB -ne $maxSize_GB) {
                        Write-Warning "    Initial and maximum sizes differ - can cause fragmentation"
                    }
                }
            }
        }
        
        # Commit charge analysis
        $committedBytes = Get-Counter '\Memory\Committed Bytes' -ErrorAction Stop
        $commitLimit = Get-Counter '\Memory\Commit Limit' -ErrorAction Stop
        
        $committed_GB = [math]::Round($committedBytes.CounterSamples.CookedValue / 1GB, 2)
        $commitLimit_GB = [math]::Round($commitLimit.CounterSamples.CookedValue / 1GB, 2)
        $commitPercent = [math]::Round(($committed_GB / $commitLimit_GB) * 100, 2)
        
        Write-Info "`nSystem Commit Charge:"
        Write-Info "  Committed: $committed_GB GB"
        Write-Info "  Commit Limit: $commitLimit_GB GB (RAM + Page Files)"
        Write-Info "  Usage: $commitPercent%"
        
        if ($commitPercent -gt 90) {
            Write-Error "    CRITICAL: System near commit limit - may crash!"
        } elseif ($commitPercent -gt 80) {
            Write-Warning "    WARNING: High commit charge - monitor closely"
        } else {
            Write-Success "    Commit charge is healthy"
        }
        
        # Recommendations
        $recommendedMin = [math]::Round($totalRAM_GB * 1.5, 0)
        $recommendedMax = [math]::Round($totalRAM_GB * 3, 0)
        
        Write-Info "`nRecommendations:"
        Write-Info "  Recommended page file: $recommendedMin - $recommendedMax GB"
        Write-Info "  Set initial = maximum size to prevent fragmentation"
        Write-Info "  Consider page files on multiple physical disks for performance"
        
    } catch {
        Write-Error "Failed to analyze page file: $($_.Exception.Message)"
    }
}

function Test-MemoryPools {
    <#
    .SYNOPSIS
        Analyzes paged and non-paged pool usage
    #>
    Write-Info "`n=== Memory Pools (Paged & Non-Paged) ==="
    try {
        # Paged Pool
        $pagedPool = Get-Counter '\Memory\Pool Paged Bytes' -ErrorAction Stop
        $pagedPool_GB = [math]::Round($pagedPool.CounterSamples.CookedValue / 1GB, 3)
        $pagedPool_MB = [math]::Round($pagedPool.CounterSamples.CookedValue / 1MB, 0)
        
        Write-Info "Paged Pool:"
        Write-Info "  Size: $pagedPool_MB MB ($pagedPool_GB GB)"
        
        # Non-Paged Pool
        $nonPagedPool = Get-Counter '\Memory\Pool Nonpaged Bytes' -ErrorAction Stop
        $nonPagedPool_GB = [math]::Round($nonPagedPool.CounterSamples.CookedValue / 1GB, 3)
        $nonPagedPool_MB = [math]::Round($nonPagedPool.CounterSamples.CookedValue / 1MB, 0)
        
        Write-Info "`nNon-Paged Pool:"
        Write-Info "  Size: $nonPagedPool_MB MB ($nonPagedPool_GB GB)"
        
        # Estimate limits
        $os = Get-CimInstance Win32_OperatingSystem
        $totalRAM_GB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        
        # Rough estimates for non-paged pool limits
        if ($totalRAM_GB -le 4) {
            $nonPagedLimit_GB = 2
        } elseif ($totalRAM_GB -le 8) {
            $nonPagedLimit_GB = 3
        } else {
            $nonPagedLimit_GB = [math]::Min($totalRAM_GB * 0.75, 128)
        }
        
        $nonPagedPercent = [math]::Round(($nonPagedPool_GB / $nonPagedLimit_GB) * 100, 2)
        Write-Info "  Estimated Usage: $nonPagedPercent% of limit (~$nonPagedLimit_GB GB)"
        
        if ($nonPagedPercent -gt 85) {
            Write-Error "    CRITICAL: Non-Paged Pool near limit - kernel may run out of memory!"
        } elseif ($nonPagedPercent -gt 75) {
            Write-Warning "    WARNING: Non-Paged Pool usage high"
        } else {
            Write-Success "    Non-Paged Pool usage is acceptable"
        }
        
        # Pool allocation failures
        try {
            $poolAllocFailures = Get-Counter '\Memory\Pool Nonpaged Alloc Failure' -ErrorAction SilentlyContinue
            if ($poolAllocFailures -and $poolAllocFailures.CounterSamples.CookedValue -gt 0) {
                $failures = $poolAllocFailures.CounterSamples.CookedValue
                Write-Error "`nPool Allocation Failures: $failures"
                Write-Info "  System has failed to allocate pool memory!"
            }
        } catch {
            # Counter not available
        }
        
        # Session pool (for Terminal Services)
        try {
            $sessionPool = Get-Counter '\Memory\System Cache Resident Bytes' -ErrorAction SilentlyContinue
            if ($sessionPool) {
                $sessionPool_MB = [math]::Round($sessionPool.CounterSamples.CookedValue / 1MB, 0)
                Write-Info "`nSystem Cache Resident: $sessionPool_MB MB"
            }
        } catch {
            # Not available
        }
        
    } catch {
        Write-Error "Failed to analyze memory pools: $($_.Exception.Message)"
    }
}

function Test-ProcessWorkingSetAnalysis {
    <#
    .SYNOPSIS
        Deep analysis of process working sets
    #>
    Write-Info "`n=== Process Working Set Deep Analysis ==="
    try {
        $processes = Get-Process -ErrorAction Stop
        
        Write-Info "`nTop 15 Processes by Working Set:"
        Write-Info ("=" * 95)
        Write-Info ("{0,-25} {1,12} {2,12} {3,12} {4,12}" -f "Process", "WS (MB)", "Private (MB)", "Shared (MB)", "Peak WS (MB)")
        Write-Info ("-" * 95)
        
        $topProcesses = $processes | Sort-Object WS -Descending | Select-Object -First 15
        
        foreach ($proc in $topProcesses) {
            $ws_MB = [math]::Round($proc.WS / 1MB, 0)
            $privateWS_MB = [math]::Round($proc.PrivateMemorySize / 1MB, 0)
            $peakWS_MB = [math]::Round($proc.PeakWorkingSet / 1MB, 0)
            $sharedWS_MB = $ws_MB - $privateWS_MB
            if ($sharedWS_MB -lt 0) { $sharedWS_MB = 0 }
            
            $line = "{0,-25} {1,12} {2,12} {3,12} {4,12}" -f $proc.Name, $ws_MB, $privateWS_MB, $sharedWS_MB, $peakWS_MB
            
            if ($ws_MB -gt 4096) {
                Write-Host $line -ForegroundColor Red
            } elseif ($ws_MB -gt 2048) {
                Write-Host $line -ForegroundColor Yellow
            } else {
                Write-Host $line -ForegroundColor White
            }
        }
        
        # Analysis summary
        $totalWS_GB = [math]::Round(($processes | Measure-Object -Property WS -Sum).Sum / 1GB, 2)
        $totalPrivate_GB = [math]::Round(($processes | Measure-Object -Property PrivateMemorySize -Sum).Sum / 1GB, 2)
        
        Write-Info "`nSummary:"
        Write-Info "  Total Process Working Set: $totalWS_GB GB"
        Write-Info "  Total Private Bytes: $totalPrivate_GB GB"
        Write-Info "  Shared/Cache Memory: $([math]::Round($totalWS_GB - $totalPrivate_GB, 2)) GB"
        
        # Check for processes with large WS but low private (cache heavy)
        $cacheHeavyProcs = $processes | Where-Object {
            $_.WS -gt 100MB -and ($_.PrivateMemorySize / $_.WS) -lt 0.5
        }
        
        if ($cacheHeavyProcs) {
            Write-Info "`nCache-Heavy Processes (WS > Private):"
            $cacheHeavyProcs | Select-Object -First 5 | ForEach-Object {
                $wsGB = [math]::Round($_.WS / 1GB, 2)
                $privateGB = [math]::Round($_.PrivateMemorySize / 1GB, 2)
                Write-Info "  $($_.Name): WS=$($wsGB)GB, Private=$($privateGB)GB"
            }
        }
        
    } catch {
        Write-Error "Failed to analyze process working sets: $($_.Exception.Message)"
    }
}

function Test-MemoryLeakDetection {
    <#
    .SYNOPSIS
        Detects memory leaks by comparing snapshots
    #>
    Write-Info "`n=== Memory Leak Detection ==="
    Write-Info "This check takes 5 minutes to detect growing processes..."
    
    $confirm = Get-ValidatedChoice -Prompt "Run 5-minute leak detection? (Y/N)" -ValidChoices @("Y", "N")
    
    if ($confirm -eq "N") {
        Write-Info "Skipping leak detection - you can run this separately when needed"
        return
    }
    
    try {
        Write-Info "`nTaking first snapshot..."
        $snapshot1 = Get-Process | Select-Object Id, Name, 
            @{Name='WS_MB';Expression={[math]::Round($_.WS/1MB,2)}},
            @{Name='Private_MB';Expression={[math]::Round($_.PrivateMemorySize/1MB,2)}},
            @{Name='Virtual_MB';Expression={[math]::Round($_.VirtualMemorySize/1MB,2)}},
            HandleCount
        
        $snapshot1Time = Get-Date
        
        Write-Info "Waiting 5 minutes (300 seconds)..."
        for ($i = 1; $i -le 30; $i++) {
            Write-Progress -Activity "Memory Leak Detection" -Status "Waiting... $($i*10) seconds elapsed" -PercentComplete (($i / 30) * 100)
            Start-Sleep -Seconds 10
        }
        Write-Progress -Activity "Memory Leak Detection" -Completed
        
        Write-Info "Taking second snapshot..."
        $snapshot2 = Get-Process | Select-Object Id, Name,
            @{Name='WS_MB';Expression={[math]::Round($_.WS/1MB,2)}},
            @{Name='Private_MB';Expression={[math]::Round($_.PrivateMemorySize/1MB,2)}},
            @{Name='Virtual_MB';Expression={[math]::Round($_.VirtualMemorySize/1MB,2)}},
            HandleCount
        
        $snapshot2Time = Get-Date
        $durationMinutes = ($snapshot2Time - $snapshot1Time).TotalMinutes
        
        Write-Info "`nAnalyzing memory growth..."
        Write-Info ("=" * 110)
        Write-Info ("{0,-25} {1,10} {2,12} {3,12} {4,15} {5,15}" -f "Process", "PID", "Private Δ", "Handle Δ", "Growth Rate", "Leak Severity")
        Write-Info ("-" * 110)
        
        $leaksFound = $false
        $leakData = @()
        
        foreach ($proc1 in $snapshot1) {
            $proc2 = $snapshot2 | Where-Object {$_.Id -eq $proc1.Id}
            if ($proc2) {
                $privateGrowth = $proc2.Private_MB - $proc1.Private_MB
                $handleGrowth = $proc2.HandleCount - $proc1.HandleCount
                $virtualGrowth = $proc2.Virtual_MB - $proc1.Virtual_MB
                
                # Calculate growth rate per hour
                $privateGrowthRate = [math]::Round(($privateGrowth / $durationMinutes) * 60, 2)
                $handleGrowthRate = [math]::Round(($handleGrowth / $durationMinutes) * 60, 0)
                
                # Determine severity
                $severity = "None"
                if ($privateGrowthRate -gt 500 -or $handleGrowthRate -gt 2000) {
                    $severity = "CRITICAL"
                    $leaksFound = $true
                } elseif ($privateGrowthRate -gt 200 -or $handleGrowthRate -gt 1000) {
                    $severity = "HIGH"
                    $leaksFound = $true
                } elseif ($privateGrowthRate -gt 50 -or $handleGrowthRate -gt 500) {
                    $severity = "MEDIUM"
                    $leaksFound = $true
                }
                
                if ($severity -ne "None") {
                    $leakData += [PSCustomObject]@{
                        Name = $proc2.Name
                        PID = $proc2.Id
                        PrivateGrowth = $privateGrowth
                        HandleGrowth = $handleGrowth
                        GrowthRate = "$($privateGrowthRate) MB/hr"
                        Severity = $severity
                    }
                }
            }
        }
        
        if ($leakData) {
            $leakData | Sort-Object {
                switch ($_.Severity) {
                    "CRITICAL" { 1 }
                    "HIGH" { 2 }
                    "MEDIUM" { 3 }
                    default { 4 }
                }
            } | ForEach-Object {
                $line = "{0,-25} {1,10} {2,12} {3,12} {4,15} {5,15}" -f $_.Name, $_.PID, "+$($_.PrivateGrowth)", "+$($_.HandleGrowth)", $_.GrowthRate, $_.Severity
                
                switch ($_.Severity) {
                    "CRITICAL" { Write-Host $line -ForegroundColor Red }
                    "HIGH" { Write-Host $line -ForegroundColor Yellow }
                    "MEDIUM" { Write-Host $line -ForegroundColor Cyan }
                }
            }
            
            Write-Info "`nLeak Detection Summary:"
            Write-Warning "  Found $($leakData.Count) processes with potential memory leaks"
            Write-Info "  CRITICAL: >500 MB/hr or >2000 handles/hr"
            Write-Info "  HIGH: >200 MB/hr or >1000 handles/hr"
            Write-Info "  MEDIUM: >50 MB/hr or >500 handles/hr"
        } else {
            Write-Success "`nNo significant memory leaks detected during this period"
        }
        
    } catch {
        Write-Error "Failed to detect memory leaks: $($_.Exception.Message)"
    }
}

function Test-HandleCountAnalysis {
    <#
    .SYNOPSIS
        Analyzes system handle usage
    #>
    Write-Info "`n=== Handle Count Analysis ==="
    try {
        $processes = Get-Process -ErrorAction Stop
        
        $totalHandles = ($processes | Measure-Object -Property HandleCount -Sum).Sum
        Write-Info "Total System Handles: $totalHandles"
        
        if ($totalHandles -gt 50000) {
            Write-Warning "  High total handle count - monitor for leaks"
        } else {
            Write-Success "  System handle count is acceptable"
        }
        
        Write-Info "`nTop 10 Processes by Handle Count:"
        $topHandles = $processes | Sort-Object HandleCount -Descending | Select-Object -First 10
        
        foreach ($proc in $topHandles) {
            $handleCount = $proc.HandleCount
            $status = if ($handleCount -gt 20000) {
                "CRITICAL"
            } elseif ($handleCount -gt 10000) {
                "WARNING"
            } else {
                "OK"
            }
            
            $line = "  {0,-30} {1,10} handles - {2}" -f "$($proc.Name) (PID: $($proc.Id))", $handleCount, $status
            
            if ($status -eq "CRITICAL") {
                Write-Host $line -ForegroundColor Red
            } elseif ($status -eq "WARNING") {
                Write-Host $line -ForegroundColor Yellow
            } else {
                Write-Info $line
            }
        }
        
        # Check GDI/USER objects (requires additional tools or WMI, simplified here)
        Write-Info "`nHandle Leak Indicators:"
        $suspiciousProcs = $processes | Where-Object {$_.HandleCount -gt 10000}
        if ($suspiciousProcs) {
            Write-Warning "  $($suspiciousProcs.Count) processes with >10,000 handles"
            Write-Info "  These processes should be monitored for handle leaks"
        } else {
            Write-Success "  No processes with excessive handle counts"
        }
        
    } catch {
        Write-Error "Failed to analyze handles: $($_.Exception.Message)"
    }
}

function Test-SystemCacheAnalysis {
    <#
    .SYNOPSIS
        Analyzes system file cache usage
    #>
    Write-Info "`n=== System Cache Analysis ==="
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $totalRAM_GB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        
        # System cache working set
        $cacheBytes = Get-Counter '\Memory\Cache Bytes' -ErrorAction Stop
        $cache_GB = [math]::Round($cacheBytes.CounterSamples.CookedValue / 1GB, 2)
        $cache_MB = [math]::Round($cacheBytes.CounterSamples.CookedValue / 1MB, 0)
        $cachePercent = [math]::Round(($cache_GB / $totalRAM_GB) * 100, 2)
        
        Write-Info "System Cache Working Set:"
        Write-Info "  Size: $cache_MB MB ($cache_GB GB)"
        Write-Info "  Percentage of RAM: $cachePercent%"
        
        if ($cachePercent -gt 50) {
            Write-Warning "    Cache is consuming >50% of RAM"
            Write-Info "    This is normal for file servers but may indicate memory pressure on app servers"
        } elseif ($cachePercent -gt 30) {
            Write-Info "    Cache usage is moderate"
        } else {
            Write-Success "    Cache usage is low"
        }
        
        # Cache faults
        $cacheFaults = Get-Counter '\Memory\Cache Faults/sec' -ErrorAction SilentlyContinue
        if ($cacheFaults) {
            $faultsPerSec = [math]::Round($cacheFaults.CounterSamples.CookedValue, 2)
            Write-Info "`nCache Faults: $faultsPerSec /sec"
            
            if ($faultsPerSec -gt 100) {
                Write-Warning "    High cache fault rate - may indicate memory pressure"
            }
        }
        
        # System cache resident bytes
        $cacheResident = Get-Counter '\Memory\System Cache Resident Bytes' -ErrorAction SilentlyContinue
        if ($cacheResident) {
            $resident_GB = [math]::Round($cacheResident.CounterSamples.CookedValue / 1GB, 2)
            Write-Info "System Cache Resident: $resident_GB GB"
        }
        
        # Peak cache bytes
        $peakCache = Get-Counter '\Memory\Cache Bytes Peak' -ErrorAction SilentlyContinue
        if ($peakCache) {
            $peak_GB = [math]::Round($peakCache.CounterSamples.CookedValue / 1GB, 2)
            Write-Info "Peak Cache: $peak_GB GB"
        }
        
    } catch {
        Write-Error "Failed to analyze system cache: $($_.Exception.Message)"
    }
}

function Test-AvailableMemoryBreakdown {
    <#
    .SYNOPSIS
        Breaks down available memory into components
    #>
    Write-Info "`n=== Available Memory Breakdown ==="
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $totalRAM_GB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $availableRAM_GB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        
        Write-Info "Total Physical RAM: $totalRAM_GB GB"
        Write-Info "Available Memory: $availableRAM_GB GB"
        
        # Get detailed memory counters
        $freeMemory = Get-Counter '\Memory\Free & Zero Page List Bytes' -ErrorAction SilentlyContinue
        $standbyMemory = Get-Counter '\Memory\Standby Cache Normal Priority Bytes' -ErrorAction SilentlyContinue
        $modifiedMemory = Get-Counter '\Memory\Modified Page List Bytes' -ErrorAction SilentlyContinue
        
        Write-Info "`nMemory State Breakdown:"
        
        if ($freeMemory) {
            $free_GB = [math]::Round($freeMemory.CounterSamples.CookedValue / 1GB, 2)
            Write-Info "  Free & Zeroed: $free_GB GB (immediately available)"
        }
        
        if ($standbyMemory) {
            $standby_GB = [math]::Round($standbyMemory.CounterSamples.CookedValue / 1GB, 2)
            Write-Info "  Standby Cache: $standby_GB GB (can be repurposed)"
        }
        
        if ($modifiedMemory) {
            $modified_GB = [math]::Round($modifiedMemory.CounterSamples.CookedValue / 1GB, 2)
            Write-Info "  Modified Pages: $modified_GB GB (needs to be written to disk)"
            
            if ($modified_GB -gt 2) {
                Write-Warning "    Large modified page list - possible I/O bottleneck"
            }
        }
        
        # Try to get all standby priority levels
        try {
            $standbyCore = Get-Counter '\Memory\Standby Cache Core Bytes' -ErrorAction SilentlyContinue
            $standbyReserve = Get-Counter '\Memory\Standby Cache Reserve Bytes' -ErrorAction SilentlyContinue
            
            if ($standbyCore) {
                $core_GB = [math]::Round($standbyCore.CounterSamples.CookedValue / 1GB, 2)
                Write-Info "  Standby (Core): $core_GB GB"
            }
            
            if ($standbyReserve) {
                $reserve_GB = [math]::Round($standbyReserve.CounterSamples.CookedValue / 1GB, 2)
                Write-Info "  Standby (Reserve): $reserve_GB GB"
            }
        } catch {
            # These counters may not be available on all systems
        }
        
        Write-Info "`nMemory State Flow:"
        Write-Info "  Free → Zeroed → Standby → Modified → Active"
        Write-Info "  Available = Free + Standby (can be immediately allocated)"
        
    } catch {
        Write-Error "Failed to analyze available memory: $($_.Exception.Message)"
    }
}

function Test-NUMAMemoryAnalysis {
    <#
    .SYNOPSIS
        Analyzes NUMA node memory distribution
    #>
    Write-Info "`n=== NUMA Memory Analysis ==="
    try {
        # Check if NUMA is present
        $numaNodes = Get-CimInstance -ClassName Win32_NumaNode -ErrorAction SilentlyContinue
        
        if (-not $numaNodes -or $numaNodes.Count -le 1) {
            Write-Info "System has single NUMA node or NUMA not configured"
            Write-Info "  NUMA analysis not applicable for this system"
            return
        }
        
        Write-Info "NUMA Nodes Detected: $($numaNodes.Count)"
        Write-Info ""
        
        foreach ($node in $numaNodes) {
            Write-Info "NUMA Node $($node.NodeId):"
            
            # This requires more detailed WMI/performance counters which may not be readily available
            # Simplified display
            Write-Info "  Status: $($node.Status)"
            
            # Try to get per-node memory info (requires specific counters)
            try {
                $nodeCounter = Get-Counter "\NUMA Node Memory(*)\Total MBytes" -ErrorAction SilentlyContinue
                if ($nodeCounter) {
                    $nodeSamples = $nodeCounter.CounterSamples | Where-Object {$_.InstanceName -eq $node.NodeId}
                    if ($nodeSamples) {
                        $nodeMB = $nodeSamples.CookedValue
                        Write-Info "  Memory: $nodeMB MB"
                    }
                }
            } catch {
                Write-Info "  Detailed per-node memory counters not available"
            }
        }
        
        Write-Info "`nNUMA Recommendations:"
        Write-Info "  • Ensure applications are NUMA-aware"
        Write-Info "  • SQL Server: Configure max server memory per NUMA node"
        Write-Info "  • Monitor for NUMA node memory imbalance"
        Write-Info "  • Check process NUMA affinity with Task Manager"
        
    } catch {
        Write-Info "NUMA information not available on this system"
    }
}

function Test-MemoryCompression {
    <#
    .SYNOPSIS
        Analyzes memory compression (Windows 10/Server 2016+)
    #>
    Write-Info "`n=== Memory Compression Analysis ==="
    try {
        # Check for Memory Compression process
        $memCompression = Get-Process -Name "Memory Compression" -ErrorAction SilentlyContinue
        
        if (-not $memCompression) {
            Write-Info "Memory Compression not active or not supported on this OS version"
            Write-Info "  (Available on Windows 10/Server 2016 and later)"
            return
        }
        
        Write-Success "Memory Compression is active"
        
        $compWS_MB = [math]::Round($memCompression.WorkingSet / 1MB, 0)
        Write-Info "  Memory Compression Process WS: $compWS_MB MB"
        Write-Info "    (This represents compressed memory pages)"
        
        # Get compression statistics if available
        try {
            $compressionCounter = Get-Counter '\Memory\*compress*' -ErrorAction SilentlyContinue
            if ($compressionCounter) {
                foreach ($sample in $compressionCounter.CounterSamples) {
                    $name = $sample.Path.Split('\')[-1]
                    $value = [math]::Round($sample.CookedValue, 0)
                    Write-Info "  $name`: $value"
                }
            }
        } catch {
            # Compression counters not available
        }
        
        # Estimate compression ratio
        $os = Get-CimInstance Win32_OperatingSystem
        $totalRAM_GB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        
        # Rough estimate: compressed size shown in WS represents expanded memory
        $estimatedRatio = [math]::Round($compWS_MB / [math]::Max($compWS_MB / 3, 1), 1)
        
        Write-Info "`nEstimated Benefits:"
        Write-Info "  Compressed data in RAM: ~$compWS_MB MB"
        Write-Info "  Estimated original size: ~$([math]::Round($compWS_MB * 3, 0)) MB"
        Write-Info "  Approximate savings: ~$([math]::Round($compWS_MB * 2, 0)) MB"
        Write-Success "  Memory compression is helping reduce physical RAM usage"
        
    } catch {
        Write-Warning "Could not analyze memory compression: $($_.Exception.Message)"
    }
}

function Test-ModifiedPageList {
    <#
    .SYNOPSIS
        Analyzes modified page list
    #>
    Write-Info "`n=== Modified Page List Analysis ==="
    try {
        $modifiedPages = Get-Counter '\Memory\Modified Page List Bytes' -ErrorAction Stop
        $modified_GB = [math]::Round($modifiedPages.CounterSamples.CookedValue / 1GB, 2)
        $modified_MB = [math]::Round($modifiedPages.CounterSamples.CookedValue / 1MB, 0)
        
        Write-Info "Modified Page List Size: $modified_MB MB ($modified_GB GB)"
        Write-Info "  (Dirty pages waiting to be written to disk)"
        
        if ($modified_GB -gt 4) {
            Write-Error "    CRITICAL: Modified page list >4GB - severe I/O bottleneck!"
            Write-Info "    Pages cannot be written to disk fast enough"
            Write-Info "    Check disk performance and storage subsystem"
        } elseif ($modified_GB -gt 2) {
            Write-Warning "    WARNING: Modified page list >2GB - possible I/O bottleneck"
            Write-Info "    Monitor disk write performance"
        } else {
            Write-Success "    Modified page list is acceptable"
        }
        
        # Get page write rate
        $pageWrites = Get-Counter '\Memory\Pages Output/sec' -ErrorAction SilentlyContinue
        if ($pageWrites) {
            $writesPerSec = [math]::Round($pageWrites.CounterSamples.CookedValue, 2)
            Write-Info "`nPage Output Rate: $writesPerSec pages/sec"
            
            if ($writesPerSec -gt 1000) {
                Write-Warning "    High page output rate - heavy write activity"
            }
        }
        
        # Dirty page threshold (when modified writer kicks in)
        Write-Info "`nModified Page Writer:"
        Write-Info "  The system writes dirty pages to disk when:"
        Write-Info "  • Modified list gets too large"
        Write-Info "  • Available memory drops below threshold"
        Write-Info "  • Pages have been modified for too long"
        
    } catch {
        Write-Error "Failed to analyze modified pages: $($_.Exception.Message)"
    }
}

function Test-StandbyMemoryAnalysis {
    <#
    .SYNOPSIS
        Detailed standby memory analysis
    #>
    Write-Info "`n=== Standby Memory Analysis ==="
    try {
        # Get various standby priority levels
        $standbyNormal = Get-Counter '\Memory\Standby Cache Normal Priority Bytes' -ErrorAction SilentlyContinue
        $standbyCore = Get-Counter '\Memory\Standby Cache Core Bytes' -ErrorAction SilentlyContinue
        $standbyReserve = Get-Counter '\Memory\Standby Cache Reserve Bytes' -ErrorAction SilentlyContinue
        
        Write-Info "Standby Memory by Priority:"
        Write-Info "  (Lower priority = more easily reclaimable)"
        Write-Info ""
        
        $totalStandby = 0
        
        if ($standbyNormal) {
            $normal_GB = [math]::Round($standbyNormal.CounterSamples.CookedValue / 1GB, 2)
            Write-Info "  Normal Priority: $normal_GB GB"
            $totalStandby += $normal_GB
        }
        
        if ($standbyCore) {
            $core_GB = [math]::Round($standbyCore.CounterSamples.CookedValue / 1GB, 2)
            Write-Info "  Core Priority: $core_GB GB"
            $totalStandby += $core_GB
        }
        
        if ($standbyReserve) {
            $reserve_GB = [math]::Round($standbyReserve.CounterSamples.CookedValue / 1GB, 2)
            Write-Info "  Reserve Priority: $reserve_GB GB"
            $totalStandby += $reserve_GB
        }
        
        if ($totalStandby -gt 0) {
            Write-Info "`nTotal Standby: $totalStandby GB"
            Write-Success "  Standby memory acts as fast disk cache"
            Write-Info "  Can be immediately repurposed for applications"
        }
        
        # Repurposed standby pages
        $repurposed = Get-Counter '\Memory\Standby Cache Reserve Bytes' -ErrorAction SilentlyContinue
        if ($repurposed) {
            Write-Info "`nStandby memory is frequently repurposed when:"
            Write-Info "  • Applications need more memory"
            Write-Info "  • Memory pressure increases"
            Write-Info "  • Priority system processes need memory"
        }
        
    } catch {
        Write-Warning "Could not analyze standby memory: $($_.Exception.Message)"
    }
}

function Test-KernelMemoryAnalysis {
    <#
    .SYNOPSIS
        Deep kernel memory analysis
    #>
    Write-Info "`n=== Kernel Memory Analysis ==="
    try {
        # Kernel paged
        $kernelPaged = Get-Counter '\Memory\Pool Paged Bytes' -ErrorAction Stop
        $kernelPaged_MB = [math]::Round($kernelPaged.CounterSamples.CookedValue / 1MB, 0)
        
        # Kernel non-paged
        $kernelNonPaged = Get-Counter '\Memory\Pool Nonpaged Bytes' -ErrorAction Stop
        $kernelNonPaged_MB = [math]::Round($kernelNonPaged.CounterSamples.CookedValue / 1MB, 0)
        
        # System code
        $systemCode = Get-Counter '\Memory\System Code Total Bytes' -ErrorAction SilentlyContinue
        $systemDriver = Get-Counter '\Memory\System Driver Total Bytes' -ErrorAction SilentlyContinue
        
        Write-Info "Kernel Memory Components:"
        Write-Info "  Paged Pool: $kernelPaged_MB MB"
        Write-Info "  Non-Paged Pool: $kernelNonPaged_MB MB"
        
        if ($systemCode) {
            $code_MB = [math]::Round($systemCode.CounterSamples.CookedValue / 1MB, 0)
            Write-Info "  System Code: $code_MB MB"
        }
        
        if ($systemDriver) {
            $driver_MB = [math]::Round($systemDriver.CounterSamples.CookedValue / 1MB, 0)
            Write-Info "  System Drivers: $driver_MB MB"
        }
        
        $totalKernel_MB = $kernelPaged_MB + $kernelNonPaged_MB
        Write-Info "`nTotal Kernel Pool Usage: $totalKernel_MB MB"
        
        if ($totalKernel_MB -gt 2048) {
            Write-Warning "  Kernel memory usage is high (>2GB)"
            Write-Info "  Check for driver memory leaks or excessive filter drivers"
        } else {
            Write-Success "  Kernel memory usage is normal"
        }
        
        # System PTEs
        try {
            $freePTEs = Get-Counter '\Memory\Free System Page Table Entries' -ErrorAction SilentlyContinue
            if ($freePTEs) {
                $pteCount = $freePTEs.CounterSamples.CookedValue
                Write-Info "`nFree System PTEs: $pteCount"
                
                if ($pteCount -lt 5000) {
                    Write-Error "    CRITICAL: Low system PTEs! System may become unstable"
                } elseif ($pteCount -lt 10000) {
                    Write-Warning "    WARNING: System PTEs are low"
                }
            }
        } catch {
            # PTE counter not available
        }
        
    } catch {
        Write-Error "Failed to analyze kernel memory: $($_.Exception.Message)"
    }
}

function Test-DriverMemoryUsage {
    <#
    .SYNOPSIS
        Analyzes memory usage by drivers
    #>
    Write-Info "`n=== Driver Memory Usage ==="
    try {
        # Get loaded drivers
        $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object {$_.State -eq "Running"}
        
        Write-Info "Total Loaded Drivers: $($drivers.Count)"
        
        # Note: Detailed per-driver memory is difficult to get without kernel debugging
        # We can show driver info but memory per driver requires special tools
        
        Write-Info "`nTop System Drivers (by load order):"
        $drivers | Sort-Object Started -Descending | Select-Object -First 10 | ForEach-Object {
            $driverType = if ($_.PathName -like "*\Windows\*") { "Microsoft" } else { "Third-Party" }
            Write-Info "  $($_.Name) - $driverType"
        }
        
        # Check for third-party drivers
        $thirdParty = $drivers | Where-Object {
            $_.PathName -notlike "*\Windows\*" -and $_.PathName -notlike "*\Program Files\Windows Defender\*"
        }
        
        if ($thirdParty) {
            Write-Info "`nThird-Party Drivers: $($thirdParty.Count)"
            Write-Warning "  Third-party drivers can cause memory leaks"
            Write-Info "  Top third-party drivers:"
            $thirdParty | Select-Object -First 5 | ForEach-Object {
                Write-Info "    $($_.Name) - $($_.PathName)"
            }
        }
        
        Write-Info "`nNote: Detailed per-driver memory usage requires:"
        Write-Info "  • PoolMon utility (from WDK)"
        Write-Info "  • Kernel debugger"
        Write-Info "  • Driver Verifier with pool tracking"
        
    } catch {
        Write-Error "Failed to analyze driver memory: $($_.Exception.Message)"
    }
}

function Test-PrivateVsVirtualBytes {
    <#
    .SYNOPSIS
        Analyzes private vs virtual memory per process
    #>
    Write-Info "`n=== Private vs Virtual Bytes Analysis ==="
    try {
        $processes = Get-Process -ErrorAction Stop
        
        Write-Info "Top 10 Processes by Virtual Memory:"
        Write-Info ("=" * 95)
        Write-Info ("{0,-25} {1,12} {2,12} {3,15} {4,15}" -f "Process", "Private (MB)", "Virtual (MB)", "Reserved (MB)", "Commit (MB)")
        Write-Info ("-" * 95)
        
        $topVirtual = $processes | Sort-Object VirtualMemorySize -Descending | Select-Object -First 10
        
        foreach ($proc in $topVirtual) {
            $private_MB = [math]::Round($proc.PrivateMemorySize / 1MB, 0)
            $virtual_MB = [math]::Round($proc.VirtualMemorySize / 1MB, 0)
            $reserved_MB = $virtual_MB - $private_MB
            if ($reserved_MB -lt 0) { $reserved_MB = 0 }
            
            $line = "{0,-25} {1,12} {2,12} {3,15} {4,15}" -f $proc.Name, $private_MB, $virtual_MB, $reserved_MB, $private_MB
            
            # Highlight processes with large virtual vs private difference (lots of reserved space)
            if ($reserved_MB -gt 2048) {
                Write-Host $line -ForegroundColor Yellow
            } else {
                Write-Host $line -ForegroundColor White
            }
        }
        
        Write-Info "`nMemory Types:"
        Write-Info "  Private: Actually committed memory (uses RAM/page file)"
        Write-Info "  Virtual: Address space reserved (doesn't use RAM until committed)"
        Write-Info "  Reserved: Virtual - Private (address space not yet committed)"
        
        # Check for address space exhaustion (32-bit processes)
        $largeVirtual = $processes | Where-Object {$_.VirtualMemorySize -gt 2GB}
        if ($largeVirtual) {
            Write-Info "`nProcesses with >2GB Virtual Memory:"
            $largeVirtual | Select-Object -First 5 | ForEach-Object {
                $virt_GB = [math]::Round($_.VirtualMemorySize / 1GB, 2)
                Write-Info "  $($_.Name): $virt_GB GB"
            }
        }
        
    } catch {
        Write-Error "Failed to analyze private vs virtual bytes: $($_.Exception.Message)"
    }
}

function Test-MemoryMappedFiles {
    <#
    .SYNOPSIS
        Analyzes memory-mapped files usage
    #>
    Write-Info "`n=== Memory-Mapped Files Analysis ==="
    try {
        # Get mapped file bytes
        $mappedFiles = Get-Counter '\Memory\Cache Bytes' -ErrorAction Stop
        $mapped_GB = [math]::Round($mappedFiles.CounterSamples.CookedValue / 1GB, 2)
        
        Write-Info "System Cache (includes memory-mapped files): $mapped_GB GB"
        
        # Processes with large working sets often use memory-mapped files
        $processes = Get-Process -ErrorAction Stop
        
        Write-Info "`nProcesses Likely Using Memory-Mapped Files:"
        Write-Info "  (Processes with large WS but relatively low private bytes)"
        Write-Info ""
        
        $mappedProcs = $processes | Where-Object {
            $_.WS -gt 100MB -and 
            ($_.PrivateMemorySize / [math]::Max($_.WS, 1)) -lt 0.5
        } | Sort-Object WS -Descending | Select-Object -First 10
        
        if ($mappedProcs) {
            foreach ($proc in $mappedProcs) {
                $ws_GB = [math]::Round($proc.WS / 1GB, 2)
                $private_GB = [math]::Round($proc.PrivateMemorySize / 1GB, 2)
                $shared_GB = [math]::Round($ws_GB - $private_GB, 2)
                
                Write-Info "  $($proc.Name):"
                Write-Info "    WS: $ws_GB GB, Private: $private_GB GB, Shared/Mapped: ~$shared_GB GB"
            }
        } else {
            Write-Info "  No processes with significant mapped file usage detected"
        }
        
        Write-Info "`nCommon Uses of Memory-Mapped Files:"
        Write-Info "  • Database files (SQL Server, Oracle)"
        Write-Info "  • IIS static content caching"
        Write-Info "  • Application file caching"
        Write-Info "  • Shared DLLs and executables"
        
    } catch {
        Write-Error "Failed to analyze memory-mapped files: $($_.Exception.Message)"
    }
}

function Test-SystemCommitCharge {
    <#
    .SYNOPSIS
        Detailed system commit charge analysis
    #>
    Write-Info "`n=== System Commit Charge Details ==="
    try {
        $committedBytes = Get-Counter '\Memory\Committed Bytes' -ErrorAction Stop
        $commitLimit = Get-Counter '\Memory\Commit Limit' -ErrorAction Stop
        $commitPeak = Get-Counter '\Memory\% Committed Bytes In Use' -ErrorAction Stop
        
        $committed_GB = [math]::Round($committedBytes.CounterSamples.CookedValue / 1GB, 2)
        $limit_GB = [math]::Round($commitLimit.CounterSamples.CookedValue / 1GB, 2)
        $usage_Percent = [math]::Round($commitPeak.CounterSamples.CookedValue, 2)
        
        Write-Info "Current Commit Charge: $committed_GB GB"
        Write-Info "Commit Limit: $limit_GB GB"
        Write-Info "Commit Usage: $usage_Percent%"
        
        if ($usage_Percent -gt 90) {
            Write-Error "  CRITICAL: Commit charge above 90% - system may crash!"
            Write-Info "  Add more RAM or increase page file size immediately"
        } elseif ($usage_Percent -gt 80) {
            Write-Warning "  WARNING: Commit charge above 80%"
            Write-Info "  Consider adding RAM or increasing page file"
        } else {
            Write-Success "  Commit charge is healthy"
        }
        
        # Calculate components
        $os = Get-CimInstance Win32_OperatingSystem
        $totalRAM_GB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $pageFiles = Get-CimInstance Win32_PageFileUsage
        $totalPageFile_GB = 0
        foreach ($pf in $pageFiles) {
            $totalPageFile_GB += [math]::Round($pf.AllocatedBaseSize / 1024, 2)
        }
        
        Write-Info "`nCommit Limit Breakdown:"
        Write-Info "  Physical RAM: $totalRAM_GB GB"
        Write-Info "  Page Files: $totalPageFile_GB GB"
        Write-Info "  Total Limit: $limit_GB GB"
        
        $available_GB = $limit_GB - $committed_GB
        Write-Info "  Available Commit: $available_GB GB"
        
        if ($available_GB -lt 2) {
            Write-Error "    Less than 2GB commit space available!"
        } elseif ($available_GB -lt 4) {
            Write-Warning "    Less than 4GB commit space available"
        }
        
    } catch {
        Write-Error "Failed to analyze commit charge: $($_.Exception.Message)"
    }
}

function Test-PageFaultAnalysis {
    <#
    .SYNOPSIS
        Analyzes page fault rates
    #>
    Write-Info "`n=== Page Fault Analysis ==="
    try {
        # Hard page faults
        $hardFaults = Get-Counter '\Memory\Page Reads/sec' -ErrorAction Stop
        $hardFaultsRate = [math]::Round($hardFaults.CounterSamples.CookedValue, 2)
        
        Write-Info "Hard Page Faults: $hardFaultsRate reads/sec"
        Write-Info "  (Reading pages from disk)"
        
        if ($hardFaultsRate -gt 1000) {
            Write-Error "    CRITICAL: Very high hard page fault rate - severe memory pressure!"
        } elseif ($hardFaultsRate -gt 100) {
            Write-Warning "    WARNING: High hard page fault rate - memory pressure detected"
        } elseif ($hardFaultsRate -gt 10) {
            Write-Info "    Moderate page fault activity"
        } else {
            Write-Success "    Low page fault rate - good"
        }
        
        # Page input
        $pageInput = Get-Counter '\Memory\Pages Input/sec' -ErrorAction SilentlyContinue
        if ($pageInput) {
            $inputRate = [math]::Round($pageInput.CounterSamples.CookedValue, 2)
            Write-Info "`nPages Input: $inputRate pages/sec"
        }
        
        # Page output
        $pageOutput = Get-Counter '\Memory\Pages Output/sec' -ErrorAction SilentlyContinue
        if ($pageOutput) {
            $outputRate = [math]::Round($pageOutput.CounterSamples.CookedValue, 2)
            Write-Info "Pages Output: $outputRate pages/sec"
        }
        
        # Transition faults
        $transitionFaults = Get-Counter '\Memory\Transition Faults/sec' -ErrorAction SilentlyContinue
        if ($transitionFaults) {
            $transRate = [math]::Round($transitionFaults.CounterSamples.CookedValue, 2)
            Write-Info "Transition Faults: $transRate /sec"
            Write-Info "  (Soft faults - pages found in standby/modified lists)"
        }
        
        Write-Info "`nPage Fault Interpretation:"
        Write-Info "  Hard Faults <10/sec: Excellent"
        Write-Info "  Hard Faults 10-100/sec: Acceptable"
        Write-Info "  Hard Faults 100-1000/sec: Memory pressure"
        Write-Info "  Hard Faults >1000/sec: Critical memory shortage"
        
    } catch {
        Write-Error "Failed to analyze page faults: $($_.Exception.Message)"
    }
}

function Test-BasicMemoryUsage {
    <#
    .SYNOPSIS
        Basic memory usage check (original functionality)
    #>
    Write-Info "`n=== Basic Memory Usage ==="
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeMemGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedMemGB = $totalMemGB - $freeMemGB
        $memUsagePercent = [math]::Round(($usedMemGB / $totalMemGB) * 100, 2)
        
        Write-Info "Total Memory: $totalMemGB GB"
        Write-Info "Used Memory: $usedMemGB GB"
        Write-Info "Free Memory: $freeMemGB GB"
        Write-Info "Memory Usage: $memUsagePercent%"
        
        if ($memUsagePercent -gt $MEMORY_CRITICAL_THRESHOLD) {
            Write-Error "CRITICAL: Memory usage above $MEMORY_CRITICAL_THRESHOLD%!"
        } elseif ($memUsagePercent -gt $MEMORY_WARNING_THRESHOLD) {
            Write-Warning "WARNING: Memory usage above $MEMORY_WARNING_THRESHOLD%"
        } else {
            Write-Success "Memory usage is within normal range"
        }
        
        # Top memory consuming processes
        Write-Info "`nTop 10 Memory Consuming Processes:"
        $processAnalysis = Get-ProcessAnalysis
        
        if ($processAnalysis) {
            $processAnalysis.ByMemory | Format-Table Name, 
                @{Label="Memory(MB)"; Expression={[math]::Round($_.WS / 1MB, 2)}},
                @{Label="CPU(s)"; Expression={[math]::Round($_.CPU, 2)}},
                Id -AutoSize
        }
        
        # Committed bytes
        $perfCounter = Get-Counter '\Memory\% Committed Bytes In Use' -ErrorAction Stop
        if ($perfCounter) {
            $committedPercent = [math]::Round($perfCounter.CounterSamples.CookedValue, 2)
            Write-Info "`nCommitted Bytes In Use: $committedPercent%"
            if ($committedPercent -gt $MEMORY_CRITICAL_THRESHOLD) {
                Write-Error "CRITICAL: Committed bytes above $MEMORY_CRITICAL_THRESHOLD%!"
            }
        }
    } catch {
        Write-Error "Failed to retrieve memory information: $($_.Exception.Message)"
    }
}

#endregion

#region Memory Diagnostics - Main Function
function Test-MemoryUsage {
    <#
    .SYNOPSIS
        Comprehensive memory usage and health check
    .DESCRIPTION
        Performs all memory diagnostics including usage, leaks, pools, and configurations
    #>
    Write-Header "Comprehensive Memory Usage Analysis"
    
    # Basic overview first
    Test-BasicMemoryUsage
    
    # HIGH PRIORITY CHECKS
    Test-PageFileConfiguration
    Test-MemoryPools
    Test-ProcessWorkingSetAnalysis
    Test-HandleCountAnalysis
    Test-SystemCacheAnalysis
    Test-AvailableMemoryBreakdown
    
    # MEDIUM PRIORITY CHECKS
    Test-MemoryCompression
    Test-ModifiedPageList
    Test-StandbyMemoryAnalysis
    Test-KernelMemoryAnalysis
    Test-DriverMemoryUsage
    Test-PrivateVsVirtualBytes
    Test-MemoryMappedFiles
    Test-SystemCommitCharge
    Test-PageFaultAnalysis
    
    # Optional: NUMA analysis (only if multi-socket)
    Test-NUMAMemoryAnalysis
    
    # Optional: Memory leak detection (time-consuming, ask user)
    Test-MemoryLeakDetection
    
    # Summary
    Write-Info "`n========================================
"
    Write-Success "Memory diagnostic check completed!"
    Write-Info "Review warnings and errors above for issues requiring attention."
    Write-Info "`nKey Actions to Take:"
    Write-Info "  • Red (ERROR): Immediate action required"
    Write-Info "  • Yellow (WARNING): Monitor and plan remediation"
    Write-Info "  • Green (SUCCESS): No action needed"
}
#endregion

function Start-MemoryLogCollection {
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

#region CPU Diagnostics (Existing)
function Test-CPUUsage {
    Write-Header "CPU Usage Analysis"
    
    try {
        $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop
        if ($cpuUsage) {
            $cpuPercent = [math]::Round($cpuUsage.CounterSamples.CookedValue, 2)
            Write-Info "Current CPU Usage: $($cpuPercent)%"
            
            if ($cpuPercent -gt $CPU_CRITICAL_THRESHOLD) {
                Write-Error "CRITICAL: CPU usage above $($CPU_CRITICAL_THRESHOLD)%!"
            } elseif ($cpuPercent -gt $CPU_WARNING_THRESHOLD) {
                Write-Warning "WARNING: CPU usage above $($CPU_WARNING_THRESHOLD)%"
            } else {
                Write-Success "CPU usage is within normal range"
            }
        }
    } catch {
        Write-Error "Failed to retrieve CPU usage: $($_.Exception.Message)"
    }
    
    try {
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop
        Write-Info "`nProcessor Information:"
        Write-Info "  Name: $($cpu.Name)"
        Write-Info "  Cores: $($cpu.NumberOfCores)"
        Write-Info "  Logical Processors: $($cpu.NumberOfLogicalProcessors)"
    } catch {
        Write-Error "Failed to retrieve processor information: $($_.Exception.Message)"
    }
    
    Write-Info "`nTop 10 CPU Consuming Processes:"
    $processAnalysis = Get-ProcessAnalysis
    
    if ($processAnalysis) {
        $processAnalysis.ByCPU | Format-Table Name, 
            @{Label="CPU(s)"; Expression={[math]::Round($_.CPU, 2)}},
            @{Label="Memory(MB)"; Expression={[math]::Round($_.WS / 1MB, 2)}},
            Id -AutoSize
    }
    
    try {
        $wmiProcess = Get-Process -Name "WmiPrvSE" -ErrorAction SilentlyContinue
        if ($wmiProcess) {
            $wmiCPU = [math]::Round($wmiProcess.CPU, 2)
            Write-Info "`nWMI Provider Host (WmiPrvSE) CPU Usage: $($wmiCPU) seconds"
            if ($wmiCPU -gt 100) {
                Write-Warning "WMI Provider Host is consuming significant CPU time"
                Write-Info "Consider using WMI-specific trace: .\TSS.ps1 -UEX_WMIBase -WIN_Kernel -ETWflags 1 -WPR CPU -Perfmon UEX_WMIPrvSE -PerfIntervalSec 1 -noBasicLog"
            }
        }
    } catch {
        Write-Warning "Could not check WMI process: $($_.Exception.Message)"
    }
}

function Start-CPULogCollection {
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

#region Disk/Storage Diagnostics (Existing)
function Test-DiskPerformance {
    Write-Header "Disk Performance Analysis"
    
    try {
        $disks = Get-PhysicalDisk -ErrorAction Stop
        Write-Info "Physical Disks:"
        foreach ($disk in $disks) {
            Write-Info "  $($disk.FriendlyName) - Size: $([math]::Round($disk.Size / 1GB, 2)) GB - Health: $($disk.HealthStatus)"
        }
    } catch {
        Write-Error "Failed to retrieve physical disk information: $($_.Exception.Message)"
    }
    
    Write-Info "`nLogical Disk Space:"
    try {
        $volumes = Get-Volume -ErrorAction Stop | Where-Object {$_.DriveLetter -ne $null}
        foreach ($vol in $volumes) {
            $usedSpace = $vol.Size - $vol.SizeRemaining
            $usedPercent = [math]::Round(($usedSpace / $vol.Size) * 100, 2)
            $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
            
            Write-Info "  Drive $($vol.DriveLetter): - $($usedPercent)% used - $($freeGB) GB free"
            if ($usedPercent -gt $DISK_CRITICAL_THRESHOLD) {
                Write-Error "    CRITICAL: Less than 10% free space!"
            } elseif ($usedPercent -gt $DISK_WARNING_THRESHOLD) {
                Write-Warning "    WARNING: Less than 20% free space"
            }
        }
    } catch {
        Write-Error "Failed to retrieve volume information: $($_.Exception.Message)"
    }
    
    Write-Info "`nChecking Disk Latency (avg over last few seconds)..."
    try {
        $diskReadLatency = Get-Counter '\PhysicalDisk(*)\Avg. Disk sec/Read' -ErrorAction Stop
        
        if ($diskReadLatency) {
            foreach ($sample in $diskReadLatency.CounterSamples) {
                if ($sample.InstanceName -ne "_total") {
                    $latencyMs = [math]::Round($sample.CookedValue * 1000, 2)
                    Write-Info "  Read Latency - $($sample.InstanceName): $($latencyMs) ms"
                    
                    if ($latencyMs -gt $DISK_LATENCY_CRITICAL_MS) {
                        Write-Error "    CRITICAL: Serious I/O bottleneck (>$($DISK_LATENCY_CRITICAL_MS)ms)"
                    } elseif ($latencyMs -gt $DISK_LATENCY_WARNING_MS) {
                        Write-Warning "    WARNING: Slow, needs attention ($($DISK_LATENCY_WARNING_MS)-$($DISK_LATENCY_CRITICAL_MS)ms)"
                    } elseif ($latencyMs -gt $DISK_LATENCY_ACCEPTABLE_MS) {
                        Write-Info "    INFO: Acceptable ($($DISK_LATENCY_ACCEPTABLE_MS)-$($DISK_LATENCY_WARNING_MS)ms)"
                    } else {
                        Write-Success "    GOOD: Very good (<$($DISK_LATENCY_ACCEPTABLE_MS)ms)"
                    }
                }
            }
        }
    } catch {
        Write-Warning "Could not retrieve disk latency metrics: $($_.Exception.Message)"
    }
    
    Write-Info "`nChecking Cluster Size (should be 64KB for databases):"
    try {
        $volumes = Get-Volume -ErrorAction Stop | Where-Object {$_.DriveLetter -ne $null}
        foreach ($vol in $volumes) {
            $drive = $vol.DriveLetter + ":"
            try {
                $clusterSize = (Get-CimInstance -Query "SELECT BlockSize FROM Win32_Volume WHERE DriveLetter='$drive'" -ErrorAction Stop).BlockSize
                if ($clusterSize) {
                    $clusterSizeKB = $clusterSize / 1KB
                    Write-Info "  Drive $($vol.DriveLetter): - Cluster Size: $($clusterSizeKB) KB"
                    if ($clusterSizeKB -ne 64) {
                        Write-Warning "    Recommended cluster size for SQL/Database servers is 64KB"
                    }
                }
            } catch {
                Write-Warning "  Could not retrieve cluster size for drive $($vol.DriveLetter)"
            }
        }
    } catch {
        Write-Error "Failed to check cluster sizes: $($_.Exception.Message)"
    }
}

function Start-DiskLogCollection {
    Write-Header "Disk/Storage Issue Log Collection"
    
    $tssAvailable = Test-TSSAvailable
    
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
  • 24 hours: -si 00:01:16 (1 min 16 sec)
  • 4 hours: -si 00:00:14 (14 seconds)
  • 2 hours: -si 00:00:07 (7 seconds)

You can also use -b MM/DD/YYYY HH:MM:SS AM/PM for begin time
and -e MM/DD/YYYY HH:MM:SS AM/PM for end time

"@ -ForegroundColor Cyan
}
#endregion

#region NEW: Services Health Diagnostics
function Test-ServicesHealth {
    <#
    .SYNOPSIS
        Analyzes Windows Services health and status
    .DESCRIPTION
        Checks critical services, automatic services, service failures, and recovery actions
    .EXAMPLE
        Test-ServicesHealth
    #>
    Write-Header "Windows Services Health Check"
    
    # Check automatic services that are stopped
    Write-Info "Checking Automatic Services Status..."
    try {
        $stoppedAutoServices = Get-Service -ErrorAction Stop | Where-Object {
            $_.StartType -eq "Automatic" -and $_.Status -ne "Running"
        }
        
        if ($stoppedAutoServices) {
            Write-Error "Found $($stoppedAutoServices.Count) automatic services NOT running:"
            $stoppedAutoServices | ForEach-Object {
                Write-Warning "  - $($_.DisplayName) ($($_.Name)): $($_.Status)"
            }
        } else {
            Write-Success "All automatic services are running"
        }
    } catch {
        Write-Error "Failed to check automatic services: $($_.Exception.Message)"
    }
    
    # Check critical services
    Write-Info "`nCritical Services Status:"
    $criticalServicesFound = 0
    foreach ($svcName in $script:CriticalServices) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) {
                $criticalServicesFound++
                if ($svc.Status -eq "Running") {
                    Write-Success "  $($svc.DisplayName): Running"
                } else {
                    Write-Error "  $($svc.DisplayName): $($svc.Status)"
                }
            }
        } catch {
            # Service doesn't exist (not installed)
        }
    }
    
    if ($criticalServicesFound -eq 0) {
        Write-Info "  No critical services found (may not be installed on this server)"
    }
    
    # Check for recent service failures (last 24 hours)
    Write-Info "`nChecking for Service Failures (Last 24 hours)..."
    try {
        $yesterday = (Get-Date).AddHours(-24)
        $serviceErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ID = 7000,7001,7031,7034
            StartTime = $yesterday
        } -ErrorAction SilentlyContinue
        
        if ($serviceErrors) {
            Write-Warning "Found $($serviceErrors.Count) service-related errors"
            
            # Group by Event ID
            $groupedErrors = $serviceErrors | Group-Object Id
            foreach ($group in $groupedErrors) {
                $eventId = $group.Name
                $count = $group.Count
                
                $description = switch ($eventId) {
                    "7000" { "Service failed to start" }
                    "7001" { "Service depends on another service" }
                    "7031" { "Service terminated unexpectedly" }
                    "7034" { "Service terminated unexpectedly" }
                    default { "Service error" }
                }
                
                Write-Info "  Event ID $($eventId) ($description): $($count) occurrences"
            }
            
            # Show top 5 failing services
            Write-Info "`n  Top 5 Failing Services:"
            $serviceErrors | ForEach-Object {
                if ($_.Message -match 'service (.+?) ') {
                    [PSCustomObject]@{
                        Service = $matches[1]
                        Time = $_.TimeCreated
                        EventID = $_.Id
                    }
                }
            } | Group-Object Service | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                Write-Warning "    - $($_.Name): $($_.Count) failures"
            }
        } else {
            Write-Success "No service failures in the last 24 hours"
        }
    } catch {
        Write-Warning "Could not retrieve service failure events: $($_.Exception.Message)"
    }
    
    # Check services running under specific accounts (security check)
    Write-Info "`nServices Running Under Non-Standard Accounts:"
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.StartName -notlike "LocalSystem" -and 
            $_.StartName -notlike "NT AUTHORITY\*" -and 
            $_.StartName -ne $null
        }
        
        if ($services) {
            Write-Warning "Found $($services.Count) services running under custom accounts:"
            $services | Select-Object -First 10 | ForEach-Object {
                Write-Info "  - $($_.DisplayName): $($_.StartName)"
            }
            if ($services.Count -gt 10) {
                Write-Info "  ... and $($services.Count - 10) more"
            }
        } else {
            Write-Success "All services running under standard accounts"
        }
    } catch {
        Write-Warning "Could not check service accounts: $($_.Exception.Message)"
    }
    
    # Check service recovery actions
    Write-Info "`nServices Without Recovery Actions Configured:"
    try {
        $servicesNoRecovery = @()
        $criticalServicesToCheck = Get-Service -ErrorAction Stop | Where-Object {
            $_.StartType -eq "Automatic" -and $_.Name -in $script:CriticalServices
        }
        
        foreach ($svc in $criticalServicesToCheck) {
            $recoveryActions = sc.exe qfailure $svc.Name 2>&1
            if ($recoveryActions -match "RESTART_NO_ACTIONS") {
                $servicesNoRecovery += $svc.DisplayName
            }
        }
        
        if ($servicesNoRecovery.Count -gt 0) {
            Write-Warning "Found $($servicesNoRecovery.Count) critical services without recovery actions:"
            $servicesNoRecovery | ForEach-Object {
                Write-Info "  - $_"
            }
            Write-Info "`nTo configure recovery actions, use: sc.exe failure <ServiceName> reset= 86400 actions= restart/60000/restart/60000/restart/60000"
        } else {
            Write-Success "All critical services have recovery actions configured"
        }
    } catch {
        Write-Warning "Could not check service recovery actions: $($_.Exception.Message)"
    }
    
    # Check for disabled services that should be automatic
    Write-Info "`nDisabled Services (Manual Review Recommended):"
    try {
        $disabledServices = Get-Service -ErrorAction Stop | Where-Object {
            $_.StartType -eq "Disabled"
        }
        
        if ($disabledServices.Count -gt 0) {
            Write-Info "Found $($disabledServices.Count) disabled services (showing first 10):"
            $disabledServices | Select-Object -First 10 | ForEach-Object {
                Write-Info "  - $($_.DisplayName) ($($_.Name))"
            }
        }
    } catch {
        Write-Warning "Could not check disabled services: $($_.Exception.Message)"
    }
}

function Start-ServicesLogCollection {
    <#
    .SYNOPSIS
        Starts service-related log collection
    .DESCRIPTION
        Collects service configuration, event logs, and diagnostic information
    #>
    Write-Header "Services Issue Log Collection"
    
    $tssAvailable = Test-TSSAvailable
    
    Write-Info "Select Service Issue Type:"
    Write-Host "1. Service Start Failure / Service Crash" -ForegroundColor Yellow
    Write-Host "2. Service Hanging / Not Responding" -ForegroundColor Yellow
    Write-Host "3. Export Service Configuration" -ForegroundColor Yellow
    Write-Host "4. Comprehensive Service Diagnostics (TSS)" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-4)" -ValidChoices @("1", "2", "3", "4")
    
    switch ($choice) {
        "1" {
            Write-Info "Collecting Service Failure Information..."
            $exportPath = Read-Host "Enter export path or press Enter for default"
            if ([string]::IsNullOrWhiteSpace($exportPath)) {
                $exportPath = Join-Path $script:DefaultLogPath "ServiceFailure"
            }
            
            if (Test-PathValid -Path $exportPath -CreateIfNotExist) {
                try {
                    # Export service configuration
                    Write-Info "Exporting service configuration..."
                    Get-Service | Export-Csv -Path (Join-Path $exportPath "AllServices.csv") -NoTypeInformation
                    
                    # Export failed services events
                    Write-Info "Exporting service failure events (last 7 days)..."
                    $sevenDaysAgo = (Get-Date).AddDays(-7)
                    Get-WinEvent -FilterHashtable @{
                        LogName = 'System'
                        ID = 7000,7001,7031,7034,7022,7023,7024
                        StartTime = $sevenDaysAgo
                    } -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $exportPath "ServiceErrors.csv") -NoTypeInformation
                    
                    Write-Success "Service failure information exported to: $exportPath"
                } catch {
                    Write-Error "Failed to export service information: $($_.Exception.Message)"
                }
            }
        }
        "2" {
            Write-Info "For hanging services, collect a process dump of the service process"
            Write-Info "1. Identify the service process: Get-Process | Where-Object {`$_.Name -like '*ServiceName*'}"
            Write-Info "2. Download ProcDump: https://learn.microsoft.com/sysinternals/downloads/procdump"
            Write-Info "3. Capture dump: procdump -ma <PID> <OutputPath>\ServiceHang.dmp"
            Write-Host "`nPress any key to return to menu..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "3" {
            Write-Info "Exporting complete service configuration..."
            $exportPath = Read-Host "Enter export path or press Enter for default"
            if ([string]::IsNullOrWhiteSpace($exportPath)) {
                $exportPath = Join-Path $script:DefaultLogPath "ServiceConfig"
            }
            
            if (Test-PathValid -Path $exportPath -CreateIfNotExist) {
                try {
                    # Export all services with details
                    Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
                        Export-Csv -Path (Join-Path $exportPath "ServiceDetails.csv") -NoTypeInformation
                    
                    # Export service dependencies
                    $dependencyReport = @()
                    Get-Service | ForEach-Object {
                        if ($_.DependentServices.Count -gt 0 -or $_.ServicesDependedOn.Count -gt 0) {
                            $dependencyReport += [PSCustomObject]@{
                                Service = $_.Name
                                DisplayName = $_.DisplayName
                                DependsOn = ($_.ServicesDependedOn.Name -join ', ')
                                DependentServices = ($_.DependentServices.Name -join ', ')
                            }
                        }
                    }
                    $dependencyReport | Export-Csv -Path (Join-Path $exportPath "ServiceDependencies.csv") -NoTypeInformation
                    
                    Write-Success "Service configuration exported to: $exportPath"
                } catch {
                    Write-Error "Failed to export service configuration: $($_.Exception.Message)"
                }
            }
        }
        "4" {
            Invoke-WithTSSCheck `
                -TSSCommand "-SDP Setup -AcceptEula" `
                -Description "Running comprehensive service diagnostics with TSS..."
        }
    }
}
#endregion

#region NEW: Event Log Analysis
function Test-EventLogHealth {
    <#
    .SYNOPSIS
        Analyzes Windows Event Logs for critical errors and patterns
    .DESCRIPTION
        Checks for critical errors, warnings, patterns, and security issues in event logs
    .EXAMPLE
        Test-EventLogHealth
    #>
    Write-Header "Event Log Health Analysis"
    
    # Check event log sizes and status
    Write-Info "Event Log Status:"
    try {
        $eventLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object {
            $_.RecordCount -gt 0 -and $_.LogName -in @('System', 'Application', 'Security')
        }
        
        foreach ($log in $eventLogs) {
            $sizeGB = [math]::Round($log.FileSize / 1GB, 2)
            $maxSizeGB = [math]::Round($log.MaximumSizeInBytes / 1GB, 2)
            $percentFull = [math]::Round(($log.FileSize / $log.MaximumSizeInBytes) * 100, 2)
            
            Write-Info "  $($log.LogName):"
            Write-Info "    Size: $sizeGB GB / $maxSizeGB GB ($percentFull% full)"
            Write-Info "    Record Count: $($log.RecordCount)"
            
            if ($percentFull -gt 90) {
                Write-Warning "    WARNING: Log is over 90% full!"
            }
        }
    } catch {
        Write-Error "Failed to retrieve event log information: $($_.Exception.Message)"
    }
    
    # Check for critical errors in last 24 hours
    Write-Info "`nCritical Errors (Last 24 Hours):"
    try {
        $yesterday = (Get-Date).AddHours(-24)
        $criticalErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'System', 'Application'
            Level = 1,2  # Critical and Error
            StartTime = $yesterday
        } -ErrorAction SilentlyContinue
        
        if ($criticalErrors) {
            Write-Warning "Found $($criticalErrors.Count) critical/error events"
            
            # Group by Event ID and show top 10
            $topErrors = $criticalErrors | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10
            
            Write-Info "`n  Top 10 Error Event IDs:"
            foreach ($error in $topErrors) {
                $sample = $criticalErrors | Where-Object {$_.Id -eq $error.Name} | Select-Object -First 1
                Write-Warning "    Event ID $($error.Name): $($error.Count) occurrences"
                Write-Info "      Source: $($sample.ProviderName)"
                Write-Info "      Message: $($sample.Message.Substring(0, [Math]::Min(100, $sample.Message.Length)))..."
            }
        } else {
            Write-Success "No critical errors in the last 24 hours"
        }
    } catch {
        Write-Warning "Could not retrieve critical errors: $($_.Exception.Message)"
    }
    
    # Check for specific problematic event IDs
    Write-Info "`nChecking for Known Problematic Events (Last 48 Hours):"
    try {
        $twoDaysAgo = (Get-Date).AddHours(-48)
        
        # Event ID 15: Disk - The device is not ready
        $diskNotReady = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ID = 15
            StartTime = $twoDaysAgo
        } -ErrorAction SilentlyContinue
        
        if ($diskNotReady) {
            Write-Error "  Event ID 15 (Disk not ready): $($diskNotReady.Count) occurrences - Check disk health!"
        } else {
            Write-Success "  No disk 'not ready' errors"
        }
        
        # Event ID 4625: Failed login attempts
        $failedLogins = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4625
            StartTime = $twoDaysAgo
        } -ErrorAction SilentlyContinue
        
        if ($failedLogins) {
            if ($failedLogins.Count -gt 50) {
                Write-Error "  Event ID 4625 (Failed logins): $($failedLogins.Count) occurrences - Possible brute force attack!"
            } else {
                Write-Warning "  Event ID 4625 (Failed logins): $($failedLogins.Count) occurrences"
            }
        } else {
            Write-Success "  No failed login attempts"
        }
        
        # Event ID 1000: Application crashes
        $appCrashes = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ID = 1000
            StartTime = $twoDaysAgo
        } -ErrorAction SilentlyContinue
        
        if ($appCrashes) {
            Write-Warning "  Event ID 1000 (Application crashes): $($appCrashes.Count) occurrences"
            $crashedApps = $appCrashes | ForEach-Object {
                if ($_.Message -match 'Application: (.+?\.exe)') {
                    $matches[1]
                }
            } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5
            
            Write-Info "    Top crashing applications:"
            $crashedApps | ForEach-Object {
                Write-Info "      - $($_.Name): $($_.Count) crashes"
            }
        } else {
            Write-Success "  No application crashes"
        }
        
        # Event ID 7031/7034: Service crashes
        $serviceCrashes = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ID = 7031,7034
            StartTime = $twoDaysAgo
        } -ErrorAction SilentlyContinue
        
        if ($serviceCrashes) {
            Write-Warning "  Event ID 7031/7034 (Service crashes): $($serviceCrashes.Count) occurrences"
        } else {
            Write-Success "  No service crashes"
        }
        
        # Event ID 1074: System restart/shutdown
        $systemRestart = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ID = 1074
            StartTime = $twoDaysAgo
        } -ErrorAction SilentlyContinue
        
        if ($systemRestart) {
            Write-Info "  Event ID 1074 (System restart): $($systemRestart.Count) occurrences"
            $lastRestart = $systemRestart | Select-Object -First 1
            Write-Info "    Last restart: $($lastRestart.TimeCreated)"
        }
        
    } catch {
        Write-Warning "Could not check for problematic events: $($_.Exception.Message)"
    }
    
    # Check for Event Log service health
    Write-Info "`nEvent Log Service Health:"
    try {
        $eventLogSvc = Get-Service -Name "EventLog" -ErrorAction Stop
        if ($eventLogSvc.Status -eq "Running") {
            Write-Success "Event Log service is running"
        } else {
            Write-Error "Event Log service is NOT running: $($eventLogSvc.Status)"
        }
    } catch {
        Write-Error "Failed to check Event Log service: $($_.Exception.Message)"
    }
}

function Start-EventLogCollection {
    <#
    .SYNOPSIS
        Exports and collects event logs for analysis
    .DESCRIPTION
        Provides options for exporting event logs and generating reports
    #>
    Write-Header "Event Log Collection"
    
    Write-Info "Select Event Log Collection Type:"
    Write-Host "1. Export System, Application, Security logs (last 7 days)" -ForegroundColor Yellow
    Write-Host "2. Export all logs (complete backup)" -ForegroundColor Yellow
    Write-Host "3. Generate Event Log Report (Critical/Error summary)" -ForegroundColor Yellow
    Write-Host "4. Export specific Event IDs" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-4)" -ValidChoices @("1", "2", "3", "4")
    
    $exportPath = Read-Host "Enter export path or press Enter for default"
    if ([string]::IsNullOrWhiteSpace($exportPath)) {
        $exportPath = Join-Path $script:DefaultLogPath "EventLogs"
    }
    
    if (-not (Test-PathValid -Path $exportPath -CreateIfNotExist)) {
        return
    }
    
    switch ($choice) {
        "1" {
            Write-Info "Exporting System, Application, and Security logs (last 7 days)..."
            try {
                $sevenDaysAgo = (Get-Date).AddDays(-7)
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                
                # Export System log
                Write-Info "Exporting System log..."
                Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$sevenDaysAgo} -ErrorAction SilentlyContinue |
                    Export-Csv -Path (Join-Path $exportPath "System_$timestamp.csv") -NoTypeInformation
                
                # Export Application log
                Write-Info "Exporting Application log..."
                Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$sevenDaysAgo} -ErrorAction SilentlyContinue |
                    Export-Csv -Path (Join-Path $exportPath "Application_$timestamp.csv") -NoTypeInformation
                
                # Export Security log
                Write-Info "Exporting Security log..."
                Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$sevenDaysAgo} -ErrorAction SilentlyContinue |
                    Export-Csv -Path (Join-Path $exportPath "Security_$timestamp.csv") -NoTypeInformation
                
                # Also export as .evtx for Event Viewer
                Write-Info "Exporting native .evtx files..."
                wevtutil epl System (Join-Path $exportPath "System_$timestamp.evtx") "/q:*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]"
                wevtutil epl Application (Join-Path $exportPath "Application_$timestamp.evtx") "/q:*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]"
                
                Write-Success "Event logs exported to: $exportPath"
            } catch {
                Write-Error "Failed to export event logs: $($_.Exception.Message)"
            }
        }
        "2" {
            Write-Info "Exporting all event logs (this may take several minutes)..."
            try {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $allLogsPath = Join-Path $exportPath "AllLogs_$timestamp"
                New-Item -Path $allLogsPath -ItemType Directory -Force | Out-Null
                
                $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object {$_.RecordCount -gt 0}
                $totalLogs = $logs.Count
                $current = 0
                
                foreach ($log in $logs) {
                    $current++
                    Write-Progress -Activity "Exporting Event Logs" -Status "Processing $($log.LogName)" -PercentComplete (($current / $totalLogs) * 100)
                    
                    $safeFileName = $log.LogName -replace '[\\/:*?"<>|]', '_'
                    $outputFile = Join-Path $allLogsPath "$safeFileName.evtx"
                    
                    try {
                        wevtutil epl $log.LogName $outputFile 2>$null
                    } catch {
                        # Skip logs that can't be exported
                    }
                }
                
                Write-Progress -Activity "Exporting Event Logs" -Completed
                Write-Success "All event logs exported to: $allLogsPath"
            } catch {
                Write-Error "Failed to export all logs: $($_.Exception.Message)"
            }
        }
        "3" {
            Write-Info "Generating Event Log Report..."
            try {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $reportPath = Join-Path $exportPath "EventLogReport_$timestamp.txt"
                
                $sevenDaysAgo = (Get-Date).AddDays(-7)
                
                $report = @"
========================================
EVENT LOG REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $($env:COMPUTERNAME)
Period: Last 7 days
========================================

"@
                
                # Critical and Error events
                $criticalErrors = Get-WinEvent -FilterHashtable @{
                    LogName = 'System', 'Application'
                    Level = 1,2
                    StartTime = $sevenDaysAgo
                } -ErrorAction SilentlyContinue
                
                $report += "`n--- CRITICAL AND ERROR EVENTS ---`n"
                $report += "Total: $($criticalErrors.Count)`n`n"
                
                if ($criticalErrors) {
                    $topErrors = $criticalErrors | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 20
                    $report += "Top 20 Event IDs:`n"
                    foreach ($error in $topErrors) {
                        $sample = $criticalErrors | Where-Object {$_.Id -eq $error.Name} | Select-Object -First 1
                        $report += "  Event ID $($error.Name): $($error.Count) occurrences`n"
                        $report += "    Source: $($sample.ProviderName)`n"
                        $report += "    Level: $($sample.LevelDisplayName)`n"
                        $report += "`n"
                    }
                }
                
                # Warning events
                $warnings = Get-WinEvent -FilterHashtable @{
                    LogName = 'System', 'Application'
                    Level = 3
                    StartTime = $sevenDaysAgo
                } -ErrorAction SilentlyContinue
                
                $report += "`n--- WARNING EVENTS ---`n"
                $report += "Total: $($warnings.Count)`n"
                
                $report | Out-File -FilePath $reportPath -Encoding UTF8
                Write-Success "Event log report generated: $reportPath"
                
                $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
                if ($open -eq "Y") {
                    notepad $reportPath
                }
            } catch {
                Write-Error "Failed to generate report: $($_.Exception.Message)"
            }
        }
        "4" {
            Write-Info "Export Specific Event IDs"
            $eventIds = Read-Host "Enter Event IDs (comma-separated, e.g., 1000,7000,4625)"
            
            if (-not [string]::IsNullOrWhiteSpace($eventIds)) {
                try {
                    $idArray = $eventIds -split ',' | ForEach-Object { $_.Trim() }
                    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                    
                    $sevenDaysAgo = (Get-Date).AddDays(-7)
                    $events = Get-WinEvent -FilterHashtable @{
                        LogName = 'System', 'Application', 'Security'
                        ID = $idArray
                        StartTime = $sevenDaysAgo
                    } -ErrorAction SilentlyContinue
                    
                    if ($events) {
                        $outputFile = Join-Path $exportPath "EventIDs_$($eventIds -replace ',', '_')_$timestamp.csv"
                        $events | Export-Csv -Path $outputFile -NoTypeInformation
                        Write-Success "Exported $($events.Count) events to: $outputFile"
                    } else {
                        Write-Warning "No events found with the specified Event IDs"
                    }
                } catch {
                    Write-Error "Failed to export specific Event IDs: $($_.Exception.Message)"
                }
            }
        }
    }
}
#endregion

#region NEW: Security & Authentication Diagnostics
function Test-SecurityAuthentication {
    <#
    .SYNOPSIS
        Analyzes security and authentication status
    .DESCRIPTION
        Checks certificates, Kerberos, NTLM, account lockouts, firewall, and Windows Defender
    .EXAMPLE
        Test-SecurityAuthentication
    #>
    Write-Header "Security & Authentication Analysis"
    
    # Check SSL/TLS Certificates
    Write-Info "Checking SSL/TLS Certificates..."
    try {
        $certStore = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop
        $now = Get-Date
        $thirtyDaysFromNow = $now.AddDays(30)
        
        $expiringCerts = @()
        $expiredCerts = @()
        $validCerts = @()
        
        foreach ($cert in $certStore) {
            if ($cert.NotAfter -lt $now) {
                $expiredCerts += $cert
            } elseif ($cert.NotAfter -lt $thirtyDaysFromNow) {
                $expiringCerts += $cert
            } else {
                $validCerts += $cert
            }
        }
        
        Write-Info "  Total Certificates: $($certStore.Count)"
        
        if ($expiredCerts.Count -gt 0) {
            Write-Error "  EXPIRED Certificates: $($expiredCerts.Count)"
            $expiredCerts | ForEach-Object {
                Write-Warning "    - $($_.Subject) (Expired: $($_.NotAfter))"
            }
        } else {
            Write-Success "  No expired certificates"
        }
        
        if ($expiringCerts.Count -gt 0) {
            Write-Warning "  Certificates Expiring in 30 days: $($expiringCerts.Count)"
            $expiringCerts | ForEach-Object {
                Write-Warning "    - $($_.Subject) (Expires: $($_.NotAfter))"
            }
        } else {
            Write-Success "  No certificates expiring in next 30 days"
        }
        
        Write-Info "  Valid Certificates: $($validCerts.Count)"
    } catch {
        Write-Error "Failed to check certificates: $($_.Exception.Message)"
    }
    
    # Check for certificate trust chain issues
    Write-Info "`nChecking Certificate Trust Chains..."
    try {
        $invalidChainCerts = $certStore | Where-Object {
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = "NoCheck"
            -not $chain.Build($_)
        }
        
        if ($invalidChainCerts) {
            Write-Warning "  Found $($invalidChainCerts.Count) certificates with trust chain issues:"
            $invalidChainCerts | Select-Object -First 5 | ForEach-Object {
                Write-Warning "    - $($_.Subject)"
            }
        } else {
            Write-Success "  All certificates have valid trust chains"
        }
    } catch {
        Write-Warning "Could not validate certificate trust chains: $($_.Exception.Message)"
    }
    
    # Check Kerberos tickets
    Write-Info "`nChecking Kerberos Tickets..."
    try {
        $klistOutput = klist tickets 2>&1
        
        if ($klistOutput -match "Current LogonId is") {
            Write-Success "  Kerberos is functioning"
            
            # Count tickets
            $ticketCount = ($klistOutput | Select-String "Server:").Count
            Write-Info "    Active Kerberos Tickets: $ticketCount"
            
            # Check for ticket issues
            if ($klistOutput -match "A ticket to .* is not available") {
                Write-Warning "    Some Kerberos tickets are unavailable"
            }
        } else {
            Write-Warning "  Could not retrieve Kerberos ticket information"
        }
    } catch {
        Write-Warning "Could not check Kerberos tickets: $($_.Exception.Message)"
    }
    
    # Check for account lockouts
    Write-Info "`nChecking for Account Lockouts (Last 24 hours)..."
    try {
        $yesterday = (Get-Date).AddHours(-24)
        $lockoutEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4740  # Account lockout
            StartTime = $yesterday
        } -ErrorAction SilentlyContinue
        
        if ($lockoutEvents) {
            Write-Warning "  Found $($lockoutEvents.Count) account lockout events!"
            
            # Parse and group by account
            $lockedAccounts = @{}
            foreach ($event in $lockoutEvents) {
                $xml = [xml]$event.ToXml()
                $targetAccount = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
                $callerComputer = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetDomainName'} | Select-Object -ExpandProperty '#text'
                
                if (-not $lockedAccounts.ContainsKey($targetAccount)) {
                    $lockedAccounts[$targetAccount] = 0
                }
                $lockedAccounts[$targetAccount]++
            }
            
            Write-Info "    Locked Accounts:"
            $lockedAccounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
                Write-Warning "      - $($_.Key): $($_.Value) lockouts"
            }
        } else {
            Write-Success "  No account lockouts in the last 24 hours"
        }
    } catch {
        Write-Warning "Could not check for account lockouts: $($_.Exception.Message)"
    }
    
    # Check failed login attempts
    Write-Info "`nAnalyzing Failed Login Attempts (Last 24 hours)..."
    try {
        $yesterday = (Get-Date).AddHours(-24)
        $failedLogins = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4625  # Failed logon
            StartTime = $yesterday
        } -ErrorAction SilentlyContinue
        
        if ($failedLogins) {
            $failedCount = $failedLogins.Count
            Write-Info "  Total Failed Login Attempts: $failedCount"
            
            if ($failedCount -gt 100) {
                Write-Error "    CRITICAL: Possible brute force attack! ($failedCount attempts)"
            } elseif ($failedCount -gt 50) {
                Write-Warning "    WARNING: High number of failed logins"
            }
            
            # Group by username
            $failedByUser = @{}
            foreach ($event in $failedLogins) {
                $xml = [xml]$event.ToXml()
                $targetUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
                
                if (-not $failedByUser.ContainsKey($targetUser)) {
                    $failedByUser[$targetUser] = 0
                }
                $failedByUser[$targetUser]++
            }
            
            Write-Info "    Top 5 Accounts with Failed Logins:"
            $failedByUser.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object {
                Write-Warning "      - $($_.Key): $($_.Value) failures"
            }
        } else {
            Write-Success "  No failed login attempts in the last 24 hours"
        }
    } catch {
        Write-Warning "Could not analyze failed logins: $($_.Exception.Message)"
    }
    
    # Check Windows Firewall status
    Write-Info "`nWindows Firewall Status:"
    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
        
        foreach ($profile in $firewallProfiles) {
            Write-Info "  $($profile.Name) Profile:"
            if ($profile.Enabled) {
                Write-Success "    Status: Enabled"
                Write-Info "    Default Inbound Action: $($profile.DefaultInboundAction)"
                Write-Info "    Default Outbound Action: $($profile.DefaultOutboundAction)"
            } else {
                Write-Warning "    Status: DISABLED"
            }
        }
        
        # Count firewall rules
        $firewallRules = Get-NetFirewallRule -ErrorAction Stop
        $enabledRules = $firewallRules | Where-Object {$_.Enabled -eq $true}
        Write-Info "`n  Firewall Rules: $($firewallRules.Count) total, $($enabledRules.Count) enabled"
        
    } catch {
        Write-Error "Failed to check firewall status: $($_.Exception.Message)"
    }
    
    # Check Windows Defender status
    Write-Info "`nWindows Defender Status:"
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        
        if ($defenderStatus.AntivirusEnabled) {
            Write-Success "  Antivirus: Enabled"
            Write-Info "    Real-time Protection: $($defenderStatus.RealTimeProtectionEnabled)"
            Write-Info "    Behavior Monitor: $($defenderStatus.BehaviorMonitorEnabled)"
            Write-Info "    IoavProtection: $($defenderStatus.IoavProtectionEnabled)"
            Write-Info "    OnAccessProtection: $($defenderStatus.OnAccessProtectionEnabled)"
        } else {
            Write-Error "  Antivirus: DISABLED"
        }
        
        # Check signature age
        $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
        Write-Info "  Signature Age: $([math]::Round($signatureAge.TotalDays, 1)) days"
        
        if ($signatureAge.TotalDays -gt 7) {
            Write-Error "    CRITICAL: Signatures are outdated (>7 days old)"
        } elseif ($signatureAge.TotalDays -gt 3) {
            Write-Warning "    WARNING: Signatures should be updated (>3 days old)"
        } else {
            Write-Success "    Signatures are up to date"
        }
        
        # Check for recent threats
        $recentThreats = Get-MpThreatDetection -ErrorAction SilentlyContinue
        if ($recentThreats) {
            Write-Warning "  Recent Threat Detections: $($recentThreats.Count)"
        } else {
            Write-Success "  No recent threat detections"
        }
        
    } catch {
        Write-Warning "Could not check Windows Defender status: $($_.Exception.Message)"
        Write-Info "  Windows Defender may not be installed or managed by third-party AV"
    }
    
    # Check for critical security events
    Write-Info "`nCritical Security Events (Last 7 days):"
    try {
        $sevenDaysAgo = (Get-Date).AddDays(-7)
        
        # Event 4720: User account created
        $accountCreated = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4720
            StartTime = $sevenDaysAgo
        } -ErrorAction SilentlyContinue
        
        if ($accountCreated) {
            Write-Info "  User Accounts Created: $($accountCreated.Count)"
        }
        
        # Event 4732: Member added to security-enabled local group
        $groupChanges = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4732,4733
            StartTime = $sevenDaysAgo
        } -ErrorAction SilentlyContinue
        
        if ($groupChanges) {
            Write-Warning "  Local Group Membership Changes: $($groupChanges.Count)"
        }
        
        # Event 1102: Audit log was cleared
        $logCleared = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 1102
            StartTime = $sevenDaysAgo
        } -ErrorAction SilentlyContinue
        
        if ($logCleared) {
            Write-Error "  CRITICAL: Audit log was cleared $($logCleared.Count) time(s)!"
        } else {
            Write-Success "  Audit log has not been cleared"
        }
        
    } catch {
        Write-Warning "Could not check security events: $($_.Exception.Message)"
    }
}

function Start-SecurityLogCollection {
    <#
    .SYNOPSIS
        Collects security and authentication diagnostic information
    .DESCRIPTION
        Exports security logs, certificate information, and authentication details
    #>
    Write-Header "Security & Authentication Log Collection"
    
    Write-Info "Select Security Collection Type:"
    Write-Host "1. Export Security Event Logs (7 days)" -ForegroundColor Yellow
    Write-Host "2. Export Certificate Information" -ForegroundColor Yellow
    Write-Host "3. Export Firewall Configuration" -ForegroundColor Yellow
    Write-Host "4. Complete Security Audit Report" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-4)" -ValidChoices @("1", "2", "3", "4")
    
    $exportPath = Read-Host "Enter export path or press Enter for default"
    if ([string]::IsNullOrWhiteSpace($exportPath)) {
        $exportPath = Join-Path $script:DefaultLogPath "Security"
    }
    
    if (-not (Test-PathValid -Path $exportPath -CreateIfNotExist)) {
        return
    }
    
    switch ($choice) {
        "1" {
            Write-Info "Exporting Security event logs..."
            try {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $sevenDaysAgo = (Get-Date).AddDays(-7)
                
                # Failed logins (4625)
                Write-Info "Exporting failed login attempts..."
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = 4625
                    StartTime = $sevenDaysAgo
                } -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $exportPath "FailedLogins_$timestamp.csv") -NoTypeInformation
                
                # Account lockouts (4740)
                Write-Info "Exporting account lockouts..."
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = 4740
                    StartTime = $sevenDaysAgo
                } -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $exportPath "AccountLockouts_$timestamp.csv") -NoTypeInformation
                
                # Successful logins (4624)
                Write-Info "Exporting successful logins..."
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = 4624
                    StartTime = $sevenDaysAgo
                } -ErrorAction SilentlyContinue | Select-Object -First 1000 | Export-Csv -Path (Join-Path $exportPath "SuccessfulLogins_$timestamp.csv") -NoTypeInformation
                
                # Account changes (4720, 4722, 4723, 4724, 4725, 4726)
                Write-Info "Exporting account changes..."
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = 4720,4722,4723,4724,4725,4726
                    StartTime = $sevenDaysAgo
                } -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $exportPath "AccountChanges_$timestamp.csv") -NoTypeInformation
                
                Write-Success "Security logs exported to: $exportPath"
            } catch {
                Write-Error "Failed to export security logs: $($_.Exception.Message)"
            }
        }
        "2" {
            Write-Info "Exporting certificate information..."
            try {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                
                # Export all certificates
                $allCerts = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop
                $certInfo = $allCerts | Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint, @{Name='DaysUntilExpiry';Expression={(New-TimeSpan -End $_.NotAfter).Days}}
                $certInfo | Export-Csv -Path (Join-Path $exportPath "Certificates_$timestamp.csv") -NoTypeInformation
                
                # Export certificate details
                $certReport = @"
CERTIFICATE REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $($env:COMPUTERNAME)

Total Certificates: $($allCerts.Count)

"@
                
                foreach ($cert in $allCerts) {
                    $daysUntilExpiry = (New-TimeSpan -End $cert.NotAfter).Days
                    $certReport += "`n--- Certificate ---`n"
                    $certReport += "Subject: $($cert.Subject)`n"
                    $certReport += "Issuer: $($cert.Issuer)`n"
                    $certReport += "Valid From: $($cert.NotBefore)`n"
                    $certReport += "Valid Until: $($cert.NotAfter)`n"
                    $certReport += "Days Until Expiry: $daysUntilExpiry`n"
                    $certReport += "Thumbprint: $($cert.Thumbprint)`n"
                }
                
                $certReport | Out-File -FilePath (Join-Path $exportPath "CertificateDetails_$timestamp.txt") -Encoding UTF8
                Write-Success "Certificate information exported to: $exportPath"
            } catch {
                Write-Error "Failed to export certificates: $($_.Exception.Message)"
            }
        }
        "3" {
            Write-Info "Exporting firewall configuration..."
            try {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                
                # Export firewall profiles
                Get-NetFirewallProfile | Export-Csv -Path (Join-Path $exportPath "FirewallProfiles_$timestamp.csv") -NoTypeInformation
                
                # Export enabled firewall rules
                Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | Export-Csv -Path (Join-Path $exportPath "FirewallRules_$timestamp.csv") -NoTypeInformation
                
                # Export firewall settings using netsh
                netsh advfirewall show allprofiles > (Join-Path $exportPath "FirewallSettings_$timestamp.txt")
                
                Write-Success "Firewall configuration exported to: $exportPath"
            } catch {
                Write-Error "Failed to export firewall configuration: $($_.Exception.Message)"
            }
        }
        "4" {
            Write-Info "Generating complete security audit report..."
            try {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $reportPath = Join-Path $exportPath "SecurityAuditReport_$timestamp.txt"
                
                $report = @"
========================================
SECURITY AUDIT REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $($env:COMPUTERNAME)
========================================

"@
                
                # Certificates
                $report += "`n--- CERTIFICATES ---`n"
                $certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
                $expiredCerts = $certs | Where-Object {$_.NotAfter -lt (Get-Date)}
                $expiringCerts = $certs | Where-Object {$_.NotAfter -lt (Get-Date).AddDays(30) -and $_.NotAfter -gt (Get-Date)}
                
                $report += "Total Certificates: $($certs.Count)`n"
                $report += "Expired: $($expiredCerts.Count)`n"
                $report += "Expiring in 30 days: $($expiringCerts.Count)`n"
                
                # Failed logins
                $report += "`n--- FAILED LOGINS (Last 24 hours) ---`n"
                $yesterday = (Get-Date).AddHours(-24)
                $failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625;StartTime=$yesterday} -ErrorAction SilentlyContinue
                $report += "Total: $($failedLogins.Count)`n"
                
                # Account lockouts
                $report += "`n--- ACCOUNT LOCKOUTS (Last 24 hours) ---`n"
                $lockouts = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4740;StartTime=$yesterday} -ErrorAction SilentlyContinue
                $report += "Total: $($lockouts.Count)`n"
                
                # Firewall status
                $report += "`n--- FIREWALL STATUS ---`n"
                $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                foreach ($profile in $fwProfiles) {
                    $report += "$($profile.Name): $($profile.Enabled)`n"
                }
                
                # Windows Defender
                $report += "`n--- WINDOWS DEFENDER ---`n"
                try {
                    $defender = Get-MpComputerStatus -ErrorAction Stop
                    $report += "Antivirus Enabled: $($defender.AntivirusEnabled)`n"
                    $report += "Real-time Protection: $($defender.RealTimeProtectionEnabled)`n"
                    $report += "Last Signature Update: $($defender.AntivirusSignatureLastUpdated)`n"
                } catch {
                    $report += "Windows Defender status unavailable`n"
                }
                
                $report | Out-File -FilePath $reportPath -Encoding UTF8
                Write-Success "Security audit report generated: $reportPath"
                
                $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
                if ($open -eq "Y") {
                    notepad $reportPath
                }
            } catch {
                Write-Error "Failed to generate security report: $($_.Exception.Message)"
            }
        }
    }
}
#endregion

#region NEW: Windows Update Diagnostics
function Test-WindowsUpdateStatus {
    <#
    .SYNOPSIS
        Analyzes Windows Update status and health
    .DESCRIPTION
        Checks update history, pending updates, failed updates, and service status
    .EXAMPLE
        Test-WindowsUpdateStatus
    #>
    Write-Header "Windows Update Status Analysis"
    
    # Check Windows Update service
    Write-Info "Windows Update Service Status:"
    try {
        $wuService = Get-Service -Name "wuauserv" -ErrorAction Stop
        if ($wuService.Status -eq "Running") {
            Write-Success "  Service: Running"
        } else {
            Write-Warning "  Service: $($wuService.Status)"
        }
        Write-Info "  Startup Type: $($wuService.StartType)"
    } catch {
        Write-Error "Failed to check Windows Update service: $($_.Exception.Message)"
    }
    
    # Check BITS service
    Write-Info "`nBackground Intelligent Transfer Service (BITS):"
    try {
        $bitsService = Get-Service -Name "BITS" -ErrorAction Stop
        if ($bitsService.Status -eq "Running") {
            Write-Success "  Service: Running"
        } else {
            Write-Warning "  Service: $($bitsService.Status)"
        }
    } catch {
        Write-Error "Failed to check BITS service: $($_.Exception.Message)"
    }
    
    # Get update history using COM object
    Write-Info "`nChecking Update History..."
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $historyCount = $updateSearcher.GetTotalHistoryCount()
        
        Write-Info "  Total Updates in History: $historyCount"
        
        if ($historyCount -gt 0) {
            $updateHistory = $updateSearcher.QueryHistory(0, [Math]::Min(50, $historyCount))
            
            # Get last successful update
            $successfulUpdates = $updateHistory | Where-Object {$_.ResultCode -eq 2} # 2 = Succeeded
            if ($successfulUpdates) {
                $lastSuccessful = $successfulUpdates | Sort-Object Date -Descending | Select-Object -First 1
                $daysSinceUpdate = (New-TimeSpan -Start $lastSuccessful.Date -End (Get-Date)).Days
                
                Write-Info "  Last Successful Update: $($lastSuccessful.Date.ToString('yyyy-MM-dd HH:mm:ss'))"
                Write-Info "  Days Since Last Update: $daysSinceUpdate"
                
                if ($daysSinceUpdate -gt 60) {
                    Write-Error "    CRITICAL: Server has not been updated in over 60 days!"
                } elseif ($daysSinceUpdate -gt 30) {
                    Write-Warning "    WARNING: Server has not been updated in over 30 days"
                } else {
                    Write-Success "    Update schedule is current"
                }
            } else {
                Write-Warning "  No successful updates found in recent history"
            }
            
            # Check for failed updates (last 30 days)
            $thirtyDaysAgo = (Get-Date).AddDays(-30)
            $failedUpdates = $updateHistory | Where-Object {
                $_.ResultCode -eq 4 -and $_.Date -gt $thirtyDaysAgo  # 4 = Failed
            }
            
            if ($failedUpdates) {
                Write-Error "  Failed Updates (Last 30 days): $($failedUpdates.Count)"
                
                # Group by update
                $failedGroups = $failedUpdates | Group-Object Title | Sort-Object Count -Descending | Select-Object -First 5
                Write-Info "    Top Failed Updates:"
                foreach ($group in $failedGroups) {
                    Write-Warning "      - $($group.Name): $($group.Count) failures"
                }
            } else {
                Write-Success "  No failed updates in last 30 days"
            }
        }
    } catch {
        Write-Error "Failed to retrieve update history: $($_.Exception.Message)"
    }
    
    # Check for pending updates
    Write-Info "`nChecking for Pending Updates..."
    try {
        $updateSearcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        
        $pendingUpdates = $searchResult.Updates
        
        if ($pendingUpdates.Count -gt 0) {
            Write-Warning "  Pending Updates: $($pendingUpdates.Count)"
            
            $securityUpdates = $pendingUpdates | Where-Object {$_.MsrcSeverity -ne $null}
            $criticalUpdates = $pendingUpdates | Where-Object {$_.MsrcSeverity -eq "Critical"}
            $importantUpdates = $pendingUpdates | Where-Object {$_.MsrcSeverity -eq "Important"}
            
            Write-Info "    Critical: $($criticalUpdates.Count)"
            Write-Info "    Important: $($importantUpdates.Count)"
            Write-Info "    Other: $($pendingUpdates.Count - $securityUpdates.Count)"
            
            Write-Info "`n    Top 5 Pending Updates:"
            $pendingUpdates | Select-Object -First 5 | ForEach-Object {
                Write-Info "      - $($_.Title)"
            }
        } else {
            Write-Success "  No pending updates"
        }
    } catch {
        Write-Warning "Could not check for pending updates: $($_.Exception.Message)"
    }
    
    # Check if reboot is required
    Write-Info "`nPending Reboot Status:"
    try {
        $rebootRequired = $false
        $rebootReasons = @()
        
        # Check Windows Update reboot flag
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $rebootRequired = $true
            $rebootReasons += "Windows Update"
        }
        
        # Check Component Based Servicing reboot flag
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $rebootRequired = $true
            $rebootReasons += "Component Based Servicing"
        }
        
        # Check pending file rename operations
        $pendingFileRename = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($pendingFileRename) {
            $rebootRequired = $true
            $rebootReasons += "Pending File Rename"
        }
        
        if ($rebootRequired) {
            Write-Warning "  Reboot Required: YES"
            Write-Info "    Reasons: $($rebootReasons -join ', ')"
        } else {
            Write-Success "  Reboot Required: NO"
        }
    } catch {
        Write-Warning "Could not determine reboot status: $($_.Exception.Message)"
    }
    
    # Check WSUS configuration
    Write-Info "`nWSUS Configuration:"
    try {
        $wuServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue).WUServer
        $wuStatusServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -ErrorAction SilentlyContinue).WUStatusServer
        
        if ($wuServer) {
            Write-Info "  WSUS Server: $wuServer"
            Write-Info "  WSUS Status Server: $wuStatusServer"
            
            # Test connectivity to WSUS
            try {
                $uri = [System.Uri]$wuServer
                $wsusReachable = Test-NetConnection -ComputerName $uri.Host -Port $uri.Port -InformationLevel Quiet -ErrorAction SilentlyContinue
                if ($wsusReachable) {
                    Write-Success "    WSUS Server: Reachable"
                } else {
                    Write-Error "    WSUS Server: NOT reachable"
                }
            } catch {
                Write-Warning "    Could not test WSUS connectivity"
            }
        } else {
            Write-Info "  WSUS: Not configured (using Microsoft Update)"
        }
    } catch {
        Write-Info "  WSUS: Not configured (using Microsoft Update)"
    }
    
    # Check SoftwareDistribution folder size
    Write-Info "`nUpdate Cache Status:"
    try {
        $softwareDistPath = "$env:SystemRoot\SoftwareDistribution"
        if (Test-Path $softwareDistPath) {
            $cacheSize = (Get-ChildItem -Path $softwareDistPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            $cacheSizeGB = [math]::Round($cacheSize / 1GB, 2)
            
            Write-Info "  Cache Location: $softwareDistPath"
            Write-Info "  Cache Size: $cacheSizeGB GB"
            
            if ($cacheSizeGB -gt 10) {
                Write-Warning "    Cache is large (>10GB). Consider cleanup if disk space is limited."
            }
        }
    } catch {
        Write-Warning "Could not check update cache: $($_.Exception.Message)"
    }
    
    # Check if update is currently in progress
    Write-Info "`nUpdate Installation Status:"
    try {
        $updateInstaller = New-Object -ComObject Microsoft.Update.Installer
        if ($updateInstaller.IsBusy) {
            Write-Warning "  Update installation is currently IN PROGRESS"
        } else {
            Write-Success "  No update installation in progress"
        }
    } catch {
        Write-Info "  Could not determine installation status"
    }
    
    # Check recent Windows Update errors
    Write-Info "`nRecent Windows Update Errors (Last 7 days):"
    try {
        $sevenDaysAgo = (Get-Date).AddDays(-7)
        $updateErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Microsoft-Windows-WindowsUpdateClient'
            Level = 2  # Error
            StartTime = $sevenDaysAgo
        } -ErrorAction SilentlyContinue
        
        if ($updateErrors) {
            Write-Warning "  Found $($updateErrors.Count) Windows Update errors"
            
            # Group by Event ID
            $errorGroups = $updateErrors | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5
            Write-Info "    Top Error Event IDs:"
            foreach ($group in $errorGroups) {
                Write-Warning "      Event ID $($group.Name): $($group.Count) occurrences"
            }
        } else {
            Write-Success "  No Windows Update errors in last 7 days"
        }
    } catch {
        Write-Warning "Could not check Windows Update error events: $($_.Exception.Message)"
    }
}

function Start-WindowsUpdateLogCollection {
    <#
    .SYNOPSIS
        Collects Windows Update diagnostic information
    .DESCRIPTION
        Exports update history, pending updates, and troubleshooting logs
    #>
    Write-Header "Windows Update Log Collection"
    
    Write-Info "Select Windows Update Collection Type:"
    Write-Host "1. Export Update History & Status" -ForegroundColor Yellow
    Write-Host "2. Generate WindowsUpdate.log" -ForegroundColor Yellow
    Write-Host "3. Export Windows Update Event Logs" -ForegroundColor Yellow
    Write-Host "4. Reset Windows Update Components (Troubleshooting)" -ForegroundColor Yellow
    Write-Host "5. Complete Update Health Report" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-5)" -ValidChoices @("1", "2", "3", "4", "5")
    
    $exportPath = Read-Host "Enter export path or press Enter for default"
    if ([string]::IsNullOrWhiteSpace($exportPath)) {
        $exportPath = Join-Path $script:DefaultLogPath "WindowsUpdate"
    }
    
    if (-not (Test-PathValid -Path $exportPath -CreateIfNotExist)) {
        return
    }
    
    switch ($choice) {
        "1" {
            Write-Info "Exporting update history..."
            try {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                
                $updateSession = New-Object -ComObject Microsoft.Update.Session
                $updateSearcher = $updateSession.CreateUpdateSearcher()
                $historyCount = $updateSearcher.GetTotalHistoryCount()
                
                if ($historyCount -gt 0) {
                    $updateHistory = $updateSearcher.QueryHistory(0, $historyCount)
                    
                    $historyReport = $updateHistory | Select-Object @{Name='Date';Expression={$_.Date}}, 
                                                                     @{Name='Title';Expression={$_.Title}},
                                                                     @{Name='Result';Expression={
                                                                         switch ($_.ResultCode) {
                                                                             0 {"NotStarted"}
                                                                             1 {"InProgress"}
                                                                             2 {"Succeeded"}
                                                                             3 {"SucceededWithErrors"}
                                                                             4 {"Failed"}
                                                                             5 {"Aborted"}
                                                                             default {"Unknown"}
                                                                         }
                                                                     }},
                                                                     @{Name='HResult';Expression={$_.HResult}}
                    
                    $historyReport | Export-Csv -Path (Join-Path $exportPath "UpdateHistory_$timestamp.csv") -NoTypeInformation
                    Write-Success "Update history exported to: $exportPath"
                } else {
                    Write-Warning "No update history available"
                }
                
                # Export pending updates
                $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
                if ($searchResult.Updates.Count -gt 0) {
                    $pendingReport = $searchResult.Updates | Select-Object @{Name='Title';Expression={$_.Title}},
                                                                            @{Name='Severity';Expression={$_.MsrcSeverity}},
                                                                            @{Name='IsDownloaded';Expression={$_.IsDownloaded}},
                                                                            @{Name='Size(MB)';Expression={[math]::Round($_.MaxDownloadSize/1MB,2)}}
                    
                    $pendingReport | Export-Csv -Path (Join-Path $exportPath "PendingUpdates_$timestamp.csv") -NoTypeInformation
                }
                
            } catch {
                Write-Error "Failed to export update history: $($_.Exception.Message)"
            }
        }
        "2" {
            Write-Info "Generating WindowsUpdate.log..."
            Write-Info "This may take several minutes..."
            try {
                $logPath = Join-Path $exportPath "WindowsUpdate.log"
                Get-WindowsUpdateLog -LogPath $logPath -ErrorAction Stop
                Write-Success "WindowsUpdate.log generated at: $logPath"
            } catch {
                Write-Error "Failed to generate WindowsUpdate.log: $($_.Exception.Message)"
                Write-Info "Alternative: Check C:\Windows\Logs\WindowsUpdate\ for ETL files"
            }
        }
        "3" {
            Write-Info "Exporting Windows Update event logs..."
            try {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $sevenDaysAgo = (Get-Date).AddDays(-7)
                
                # Export Windows Update Client events
                Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ProviderName = 'Microsoft-Windows-WindowsUpdateClient'
                    StartTime = $sevenDaysAgo
                } -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $exportPath "WindowsUpdateEvents_$timestamp.csv") -NoTypeInformation
                
                # Export Setup events
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Setup'
                    StartTime = $sevenDaysAgo
                } -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $exportPath "SetupEvents_$timestamp.csv") -NoTypeInformation
                
                Write-Success "Event logs exported to: $exportPath"
            } catch {
                Write-Error "Failed to export event logs: $($_.Exception.Message)"
            }
        }
        "4" {
            Write-Warning "This will reset Windows Update components."
            Write-Warning "This action will:"
            Write-Info "  1. Stop Windows Update services"
            Write-Info "  2. Rename SoftwareDistribution folder"
            Write-Info "  3. Rename Catroot2 folder"
            Write-Info "  4. Restart Windows Update services"
            Write-Info ""
            
            $confirm = Get-ValidatedChoice -Prompt "Continue with reset? (Y/N)" -ValidChoices @("Y", "N")
            
            if ($confirm -eq "Y") {
                try {
                    Write-Info "Stopping Windows Update services..."
                    Stop-Service -Name wuauserv -Force -ErrorAction Stop
                    Stop-Service -Name bits -Force -ErrorAction Stop
                    Stop-Service -Name cryptsvc -Force -ErrorAction Stop
                    
                    Write-Info "Renaming SoftwareDistribution folder..."
                    $softDistPath = "$env:SystemRoot\SoftwareDistribution"
                    if (Test-Path $softDistPath) {
                        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                        Rename-Item -Path $softDistPath -NewName "SoftwareDistribution.old_$timestamp" -ErrorAction Stop
                    }
                    
                    Write-Info "Renaming Catroot2 folder..."
                    $catroot2Path = "$env:SystemRoot\System32\catroot2"
                    if (Test-Path $catroot2Path) {
                        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                        Rename-Item -Path $catroot2Path -NewName "catroot2.old_$timestamp" -ErrorAction Stop
                    }
                    
                    Write-Info "Starting Windows Update services..."
                    Start-Service -Name wuauserv -ErrorAction Stop
                    Start-Service -Name bits -ErrorAction Stop
                    Start-Service -Name cryptsvc -ErrorAction Stop
                    
                    Write-Success "Windows Update components have been reset successfully"
                    Write-Info "Please try running Windows Update again"
                    
                } catch {
                    Write-Error "Failed to reset Windows Update components: $($_.Exception.Message)"
                }
            }
        }
        "5" {
            Write-Info "Generating complete Windows Update health report..."
            try {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $reportPath = Join-Path $exportPath "WindowsUpdateHealthReport_$timestamp.txt"
                
                $report = @"
========================================
WINDOWS UPDATE HEALTH REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $($env:COMPUTERNAME)
========================================

"@
                
                # Service status
                $report += "`n--- SERVICE STATUS ---`n"
                $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
                $report += "Windows Update: $($wuService.Status)`n"
                $bitsService = Get-Service -Name BITS -ErrorAction SilentlyContinue
                $report += "BITS: $($bitsService.Status)`n"
                
                # Update history
                $report += "`n--- UPDATE HISTORY ---`n"
                try {
                    $updateSession = New-Object -ComObject Microsoft.Update.Session
                    $updateSearcher = $updateSession.CreateUpdateSearcher()
                    $historyCount = $updateSearcher.GetTotalHistoryCount()
                    $report += "Total Updates in History: $historyCount`n"
                    
                    if ($historyCount -gt 0) {
                        $history = $updateSearcher.QueryHistory(0, [Math]::Min(10, $historyCount))
                        $lastSuccessful = $history | Where-Object {$_.ResultCode -eq 2} | Select-Object -First 1
                        if ($lastSuccessful) {
                            $report += "Last Successful Update: $($lastSuccessful.Date)`n"
                            $report += "  Title: $($lastSuccessful.Title)`n"
                        }
                    }
                } catch {
                    $report += "Error retrieving update history`n"
                }
                
                # Pending updates
                $report += "`n--- PENDING UPDATES ---`n"
                try {
                    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
                    $report += "Total Pending: $($searchResult.Updates.Count)`n"
                    
                    if ($searchResult.Updates.Count -gt 0) {
                        $critical = ($searchResult.Updates | Where-Object {$_.MsrcSeverity -eq "Critical"}).Count
                        $important = ($searchResult.Updates | Where-Object {$_.MsrcSeverity -eq "Important"}).Count
                        $report += "Critical: $critical`n"
                        $report += "Important: $important`n"
                    }
                } catch {
                    $report += "Error checking pending updates`n"
                }
                
                # Reboot status
                $report += "`n--- REBOOT STATUS ---`n"
                $rebootRequired = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
                $report += "Reboot Required: $rebootRequired`n"
                
                # WSUS configuration
                $report += "`n--- WSUS CONFIGURATION ---`n"
                $wuServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue).WUServer
                if ($wuServer) {
                    $report += "WSUS Server: $wuServer`n"
                } else {
                    $report += "WSUS: Not configured (using Microsoft Update)`n"
                }
                
                $report | Out-File -FilePath $reportPath -Encoding UTF8
                Write-Success "Windows Update health report generated: $reportPath"
                
                $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
                if ($open -eq "Y") {
                    notepad $reportPath
                }
            } catch {
                Write-Error "Failed to generate report: $($_.Exception.Message)"
            }
        }
    }
}
#endregion

#region NEW: DNS Diagnostics
function Test-DNSHealth {
    <#
    .SYNOPSIS
        Analyzes DNS configuration and connectivity
    .DESCRIPTION
        Checks DNS server connectivity, resolution performance, and configuration
    .EXAMPLE
        Test-DNSHealth
    #>
    Write-Header "DNS Health & Connectivity Analysis"
    
    # Get configured DNS servers
    Write-Info "Configured DNS Servers:"
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.Status -eq "Up"}
        
        foreach ($adapter in $adapters) {
            Write-Info "`n  Adapter: $($adapter.Name)"
            try {
                $dnsServers = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction Stop
                
                if ($dnsServers.ServerAddresses.Count -eq 0) {
                    Write-Warning "    No DNS servers configured"
                } else {
                    foreach ($dnsServer in $dnsServers.ServerAddresses) {
                        Write-Info "    DNS Server: $dnsServer"
                        
                        # Test connectivity to DNS server
                        $pingResult = Test-Connection -ComputerName $dnsServer -Count 1 -Quiet -ErrorAction SilentlyContinue
                        if ($pingResult) {
                            $ping = Test-Connection -ComputerName $dnsServer -Count 1 -ErrorAction SilentlyContinue
                            $latency = $ping.ResponseTime
                            Write-Success "      Connectivity: OK (${latency}ms)"
                        } else {
                            Write-Error "      Connectivity: FAILED"
                        }
                    }
                }
            } catch {
                Write-Warning "    Could not retrieve DNS configuration"
            }
        }
    } catch {
        Write-Error "Failed to enumerate network adapters: $($_.Exception.Message)"
    }
    
    # Test DNS resolution performance
    Write-Info "`nDNS Resolution Performance:"
    $testDomains = @("microsoft.com", "google.com", "cloudflare.com")
    
    foreach ($domain in $testDomains) {
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Resolve-DnsName -Name $domain -ErrorAction Stop
            $stopwatch.Stop()
            
            $resolutionTime = $stopwatch.ElapsedMilliseconds
            
            Write-Info "  $domain`: resolved to $($result[0].IPAddress)"
            
            if ($resolutionTime -gt $DNS_RESOLUTION_CRITICAL_MS) {
                Write-Error "    Resolution Time: ${resolutionTime}ms (CRITICAL: >${DNS_RESOLUTION_CRITICAL_MS}ms)"
            } elseif ($resolutionTime -gt $DNS_RESOLUTION_WARNING_MS) {
                Write-Warning "    Resolution Time: ${resolutionTime}ms (WARNING: >${DNS_RESOLUTION_WARNING_MS}ms)"
            } else {
                Write-Success "    Resolution Time: ${resolutionTime}ms"
            }
        } catch {
            Write-Error "  $domain`: Resolution FAILED - $($_.Exception.Message)"
        }
    }
    
    # Check DNS cache
    Write-Info "`nDNS Cache Statistics:"
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction Stop
        Write-Info "  Total cached entries: $($dnsCache.Count)"
        
        # Check for failed lookups in cache
        $failedLookups = $dnsCache | Where-Object {$_.Status -ne 0}
        if ($failedLookups) {
            Write-Warning "  Failed lookups in cache: $($failedLookups.Count)"
        } else {
            Write-Success "  No failed lookups in cache"
        }
    } catch {
        Write-Warning "Could not retrieve DNS cache: $($_.Exception.Message)"
    }
    
    # Check for DNS Client service
    Write-Info "`nDNS Client Service:"
    try {
        $dnsClientSvc = Get-Service -Name "Dnscache" -ErrorAction Stop
        if ($dnsClientSvc.Status -eq "Running") {
            Write-Success "DNS Client service is running"
        } else {
            Write-Error "DNS Client service is NOT running: $($dnsClientSvc.Status)"
        }
    } catch {
        Write-Error "Failed to check DNS Client service: $($_.Exception.Message)"
    }
    
    # Check DNS suffix configuration
    Write-Info "`nDNS Suffix Configuration:"
    try {
        $dnsConfig = Get-DnsClient -ErrorAction Stop
        foreach ($config in $dnsConfig) {
            if ($config.ConnectionSpecificSuffix) {
                Write-Info "  Interface $($config.InterfaceAlias): $($config.ConnectionSpecificSuffix)"
            }
        }
        
        $dnsSuffixList = (Get-DnsClientGlobalSetting -ErrorAction Stop).SuffixSearchList
        if ($dnsSuffixList) {
            Write-Info "  Suffix Search List: $($dnsSuffixList -join ', ')"
        }
    } catch {
        Write-Warning "Could not retrieve DNS suffix configuration: $($_.Exception.Message)"
    }
    
    # Check for DNS Server role (if installed)
    Write-Info "`nDNS Server Role Check:"
    try {
        $dnsServerFeature = Get-WindowsFeature -Name "DNS" -ErrorAction SilentlyContinue
        if ($dnsServerFeature -and $dnsServerFeature.Installed) {
            Write-Success "DNS Server role is installed"
            
            # Check DNS Server service
            $dnsServerSvc = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
            if ($dnsServerSvc) {
                if ($dnsServerSvc.Status -eq "Running") {
                    Write-Success "  DNS Server service is running"
                } else {
                    Write-Error "  DNS Server service is NOT running: $($dnsServerSvc.Status)"
                }
            }
        } else {
            Write-Info "DNS Server role is not installed (client-only)"
        }
    } catch {
        Write-Info "Could not check DNS Server role (may not be domain controller)"
    }
    
    # Test reverse DNS lookup
    Write-Info "`nReverse DNS Lookup Test:"
    try {
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -ne "127.0.0.1"
        } | Select-Object -First 1).IPAddress
        
        if ($localIP) {
            Write-Info "  Testing reverse lookup for: $localIP"
            try {
                $reverseResult = Resolve-DnsName -Name $localIP -ErrorAction Stop
                Write-Success "    Reverse lookup successful: $($reverseResult.NameHost)"
            } catch {
                Write-Warning "    Reverse lookup failed"
            }
        }
    } catch {
        Write-Warning "Could not perform reverse DNS lookup test"
    }
}

function Start-DNSLogCollection {
    <#
    .SYNOPSIS
        Collects DNS-related diagnostic information
    .DESCRIPTION
        Exports DNS configuration, cache, and event logs
    #>
    Write-Header "DNS Log Collection"
    
    $tssAvailable = Test-TSSAvailable
    
    Write-Info "Select DNS Collection Type:"
    Write-Host "1. Export DNS Configuration & Cache" -ForegroundColor Yellow
    Write-Host "2. DNS Resolution Trace (netsh)" -ForegroundColor Yellow
    Write-Host "3. Comprehensive DNS Diagnostics (TSS)" -ForegroundColor Yellow
    Write-Host "4. Export DNS Event Logs" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-4)" -ValidChoices @("1", "2", "3", "4")
    
    switch ($choice) {
        "1" {
            Write-Info "Exporting DNS configuration and cache..."
            $exportPath = Read-Host "Enter export path or press Enter for default"
            if ([string]::IsNullOrWhiteSpace($exportPath)) {
                $exportPath = Join-Path $script:DefaultLogPath "DNSConfig"
            }
            
            if (Test-PathValid -Path $exportPath -CreateIfNotExist) {
                try {
                    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                    
                    # Export DNS client configuration
                    Get-DnsClient | Export-Csv -Path (Join-Path $exportPath "DNSClient_$timestamp.csv") -NoTypeInformation
                    
                    # Export DNS server addresses
                    Get-DnsClientServerAddress | Export-Csv -Path (Join-Path $exportPath "DNSServerAddresses_$timestamp.csv") -NoTypeInformation
                    
                    # Export DNS cache
                    Get-DnsClientCache | Export-Csv -Path (Join-Path $exportPath "DNSCache_$timestamp.csv") -NoTypeInformation
                    
                    # Run ipconfig /displaydns
                    ipconfig /displaydns > (Join-Path $exportPath "IPConfigDNS_$timestamp.txt")
                    
                    # Run nslookup tests
                    $nslookupOutput = @"
DNS NSLOOKUP TESTS
==================

Test 1: Default server lookup
$(nslookup microsoft.com 2>&1)

Test 2: Google DNS lookup
$(nslookup microsoft.com 8.8.8.8 2>&1)

Test 3: Local server lookup
$(nslookup $env:COMPUTERNAME 2>&1)
"@
                    $nslookupOutput | Out-File -FilePath (Join-Path $exportPath "NSLookupTests_$timestamp.txt")
                    
                    Write-Success "DNS configuration exported to: $exportPath"
                } catch {
                    Write-Error "Failed to export DNS configuration: $($_.Exception.Message)"
                }
            }
        }
        "2" {
            Write-Info "Manual DNS Trace Commands:"
            Write-Host @"

START DNS TRACE:
netsh trace start scenario=InternetClient_dbg capture=yes report=yes persistent=no maxsize=1024 tracefile=C:\temp\dnstrace.etl

REPRODUCE THE DNS ISSUE

STOP DNS TRACE:
netsh trace stop

ALTERNATIVE - ETW TRACE:
logman create trace "DNS-Trace" -ow -o c:\temp\dns.etl -p "Microsoft-Windows-DNS-Client" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

STOP ETW TRACE:
logman stop "DNS-Trace" -ets

"@ -ForegroundColor Cyan
        }
        "3" {
            Invoke-WithTSSCheck `
                -TSSCommand "-Scenario NET_DNScli" `
                -Description "Running comprehensive DNS diagnostics with TSS..."
        }
        "4" {
            Write-Info "Exporting DNS-related event logs..."
            $exportPath = Read-Host "Enter export path or press Enter for default"
            if ([string]::IsNullOrWhiteSpace($exportPath)) {
                $exportPath = Join-Path $script:DefaultLogPath "DNSEvents"
            }
            
            if (Test-PathValid -Path $exportPath -CreateIfNotExist) {
                try {
                    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                    $sevenDaysAgo = (Get-Date).AddDays(-7)
                    
                    # Export DNS Client events
                    Write-Info "Exporting DNS Client events..."
                    Get-WinEvent -FilterHashtable @{
                        LogName = 'Microsoft-Windows-DNS-Client/Operational'
                        StartTime = $sevenDaysAgo
                    } -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $exportPath "DNSClient_Events_$timestamp.csv") -NoTypeInformation
                    
                    # If DNS Server role installed, export DNS Server events
                    $dnsServerLog = Get-WinEvent -ListLog "DNS Server" -ErrorAction SilentlyContinue
                    if ($dnsServerLog) {
                        Write-Info "Exporting DNS Server events..."
                        Get-WinEvent -FilterHashtable @{
                            LogName = 'DNS Server'
                            StartTime = $sevenDaysAgo
                        } -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $exportPath "DNSServer_Events_$timestamp.csv") -NoTypeInformation
                    }
                    
                    Write-Success "DNS event logs exported to: $exportPath"
                } catch {
                    Write-Error "Failed to export DNS events: $($_.Exception.Message)"
                }
            }
        }
    }
}
#endregion

#region Additional Scenarios (Existing - Keeping as is)
function Show-AdditionalScenarios {
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
                try {
                    Write-Info "Exporting System event log..."
                    wevtutil epl System (Join-Path $exportPath "system.evtx")
                    
                    Write-Info "Exporting Application event log..."
                    wevtutil epl Application (Join-Path $exportPath "application.evtx")
                    
                    Write-Info "Exporting Security event log..."
                    wevtutil epl Security (Join-Path $exportPath "security.evtx")
                    
                    Write-Success "Event logs exported to: $($exportPath)"
                } catch {
                    Write-Error "Failed to export event logs: $($_.Exception.Message)"
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

#region Report Functions (Existing)
function Show-ValidatorInfo {
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
    Write-Header "TLS Configuration Validation"
    
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
        
        if (Test-Path $regPath) {
            $clientPath = Join-Path $regPath "Client"
            if (Test-Path $clientPath) {
                try {
                    $clientEnabled = Get-ItemProperty -Path $clientPath -Name "Enabled" -ErrorAction SilentlyContinue
                    $clientDisabledByDefault = Get-ItemProperty -Path $clientPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue
                    
                    if ($clientEnabled.Enabled -eq 1 -and $clientDisabledByDefault.DisabledByDefault -eq 0) {
                        Write-Success "  Client: ENABLED"
                    } elseif ($clientEnabled.Enabled -eq 0 -or $clientDisabledByDefault.DisabledByDefault -eq 1) {
                        Write-Warning "  Client: DISABLED"
                    } else {
                        Write-Info "  Client: Not explicitly configured (using system default)"
                    }
                } catch {
                    Write-Info "  Client: Not explicitly configured (using system default)"
                }
            } else {
                Write-Info "  Client: Not explicitly configured (using system default)"
            }
            
            $serverPath = Join-Path $regPath "Server"
            if (Test-Path $serverPath) {
                try {
                    $serverEnabled = Get-ItemProperty -Path $serverPath -Name "Enabled" -ErrorAction SilentlyContinue
                    $serverDisabledByDefault = Get-ItemProperty -Path $serverPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue
                    
                    if ($serverEnabled.Enabled -eq 1 -and $serverDisabledByDefault.DisabledByDefault -eq 0) {
                        Write-Success "  Server: ENABLED"
                    } elseif ($serverEnabled.Enabled -eq 0 -or $serverDisabledByDefault.DisabledByDefault -eq 1) {
                        Write-Warning "  Server: DISABLED"
                    } else {
                        Write-Info "  Server: Not explicitly configured (using system default)"
                    }
                } catch {
                    Write-Info "  Server: Not explicitly configured (using system default)"
                }
            } else {
                Write-Info "  Server: Not explicitly configured (using system default)"
            }
        } else {
            Write-Info "  Protocol registry key does not exist (using system default)"
        }
        
        Write-Info ""
    }
    
    Write-Info "--- Security Recommendations ---"
    Write-Warning "TLS 1.0 and TLS 1.1 are deprecated and should be disabled"
    Write-Success "TLS 1.2 should be enabled (minimum requirement)"
    Write-Success "TLS 1.3 should be enabled for best security (Windows Server 2022+)"
    Write-Info ""
    
    Write-Info "--- .NET Framework TLS Support ---"
    try {
        $netFx4Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path) {
            $schUseStrongCrypto = Get-ItemProperty -Path $netFx4Path -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
            $systemDefaultTls = Get-ItemProperty -Path $netFx4Path -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue
            
            if ($schUseStrongCrypto.SchUseStrongCrypto -eq 1) {
                Write-Success ".NET 4.x (32-bit): Strong Crypto ENABLED"
            } else {
                Write-Warning ".NET 4.x (32-bit): Strong Crypto NOT enabled"
            }
            
            if ($systemDefaultTls.SystemDefaultTlsVersions -eq 1) {
                Write-Success ".NET 4.x (32-bit): System Default TLS ENABLED"
            } else {
                Write-Warning ".NET 4.x (32-bit): System Default TLS NOT enabled"
            }
        }
        
        $netFx4Path64 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path64) {
            $schUseStrongCrypto64 = Get-ItemProperty -Path $netFx4Path64 -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
            $systemDefaultTls64 = Get-ItemProperty -Path $netFx4Path64 -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue
            
            if ($schUseStrongCrypto64.SchUseStrongCrypto -eq 1) {
                Write-Success ".NET 4.x (64-bit): Strong Crypto ENABLED"
            } else {
                Write-Warning ".NET 4.x (64-bit): Strong Crypto NOT enabled"
            }
            
            if ($systemDefaultTls64.SystemDefaultTlsVersions -eq 1) {
                Write-Success ".NET 4.x (64-bit): System Default TLS ENABLED"
            } else {
                Write-Warning ".NET 4.x (64-bit): System Default TLS NOT enabled"
            }
        }
    } catch {
        Write-Error "Failed to check .NET Framework TLS configuration: $($_.Exception.Message)"
    }
    
    Write-Info ""
    Write-Info "--- PowerShell TLS Support ---"
    try {
        $securityProtocol = [Net.ServicePointManager]::SecurityProtocol
        Write-Info "Current PowerShell Session Security Protocol: $securityProtocol"
        
        if ($securityProtocol -match "Tls12") {
            Write-Success "TLS 1.2 is available in PowerShell"
        } else {
            Write-Warning "TLS 1.2 is NOT configured in PowerShell"
            Write-Info "To enable: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
        }
        
        if ($securityProtocol -match "Tls13") {
            Write-Success "TLS 1.3 is available in PowerShell"
        }
    } catch {
        Write-Error "Failed to check PowerShell TLS configuration: $($_.Exception.Message)"
    }
    
    Write-Info ""
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
                } elseif ($suite -match "GCM|ECDHE") {
                    Write-Success "  $suite (Strong)"
                } elseif ($suite -match "CBC") {
                    Write-Warning "  $suite (Consider disabling CBC mode ciphers)"
                } else {
                    Write-Info "  $suite"
                }
            }
            
            Write-Info ""
            Write-Info "Checking for weak/deprecated cipher suites..."
            $weakCiphers = $cipherSuites | Where-Object { 
                $_.Name -match "RC4|DES|3DES|MD5|NULL|EXPORT|anon" 
            }
            
            if ($weakCiphers) {
                Write-Error "CRITICAL: Weak cipher suites detected!"
                $weakCiphers | ForEach-Object {
                    Write-Warning "  - $($_.Name)"
                }
            } else {
                Write-Success "No weak cipher suites detected"
            }
        } else {
            Write-Warning "Could not retrieve cipher suite information (may require Windows Server 2012 R2+)"
        }
    } catch {
        Write-Warning "Could not check cipher suites: $($_.Exception.Message)"
    }
}

function Export-TLSReport {
    Write-Header "Exporting TLS Configuration Report"
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPath = Join-Path $script:DefaultLogPath "TLSReport_$($timestamp).txt"
    
    if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
        Write-Error "Cannot create report directory"
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
        
        $tlsProtocols = @("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
        
        foreach ($protocol in $tlsProtocols) {
            $report += "`n--- $protocol ---`n"
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol"
            
            if (Test-Path $regPath) {
                $clientPath = Join-Path $regPath "Client"
                if (Test-Path $clientPath) {
                    $clientProps = Get-ItemProperty -Path $clientPath -ErrorAction SilentlyContinue
                    $report += "Client Enabled: $($clientProps.Enabled)`n"
                    $report += "Client DisabledByDefault: $($clientProps.DisabledByDefault)`n"
                } else {
                    $report += "Client: Not configured`n"
                }
                
                $serverPath = Join-Path $regPath "Server"
                if (Test-Path $serverPath) {
                    $serverProps = Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue
                    $report += "Server Enabled: $($serverProps.Enabled)`n"
                    $report += "Server DisabledByDefault: $($serverProps.DisabledByDefault)`n"
                } else {
                    $report += "Server: Not configured`n"
                }
            } else {
                $report += "Not configured (using system defaults)`n"
            }
        }
        
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
        
        $report += "`n--- Enabled Cipher Suites ---`n"
        try {
            $cipherSuites = Get-TlsCipherSuite -ErrorAction SilentlyContinue
            if ($cipherSuites) {
                foreach ($suite in $cipherSuites) {
                    $report += "$($suite.Name)`n"
                }
            }
        } catch {
            $report += "Could not retrieve cipher suites`n"
        }
        
        $report | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        Write-Success "TLS Report generated: $($reportPath)"
        
        $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
        if ($open -eq "Y") {
            try {
                notepad $reportPath
            } catch {
                Write-Warning "Could not open report automatically. Please navigate to: $($reportPath)"
            }
        }
    } catch {
        Write-Error "Failed to generate TLS report: $($_.Exception.Message)"
    }
}

function Export-SystemReport {
    Write-Header "Generating System Report"
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPath = Join-Path $script:DefaultLogPath "SystemReport_$($timestamp).txt"
    
    if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
        Write-Error "Cannot create report directory"
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
        
        Write-Info "--- SYSTEM INFORMATION ---"
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            $report += "`n--- SYSTEM INFORMATION ---`n"
            $report += "OS: $($os.Caption) $($os.Version)`n"
            $report += "Manufacturer: $($cs.Manufacturer)`n"
            $report += "Model: $($cs.Model)`n"
            $report += "Domain: $($cs.Domain)`n"
            $report += "Last Boot: $($os.LastBootUpTime)`n"
        } catch {
            $report += "Error retrieving system information: $($_.Exception.Message)`n"
        }
        
        try {
            $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
            $freeMemGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
            $report += "`n--- MEMORY ---`n"
            $report += "Total: $($totalMemGB) GB`n"
            $report += "Free: $($freeMemGB) GB`n"
            $report += "Usage: $([math]::Round((($totalMemGB - $freeMemGB) / $totalMemGB) * 100, 2))%`n"
        } catch {
            $report += "Error retrieving memory information`n"
        }
        
        try {
            $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop
            $report += "`n--- PROCESSOR ---`n"
            $report += "Name: $($cpu.Name)`n"
            $report += "Cores: $($cpu.NumberOfCores)`n"
            $report += "Logical Processors: $($cpu.NumberOfLogicalProcessors)`n"
        } catch {
            $report += "Error retrieving CPU information`n"
        }
        
        $report += "`n--- DISK SPACE ---`n"
        try {
            $volumes = Get-Volume -ErrorAction Stop | Where-Object {$_.DriveLetter -ne $null}
            foreach ($vol in $volumes) {
                $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
                $totalGB = [math]::Round($vol.Size / 1GB, 2)
                $usedPercent = [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 2)
                $report += "Drive $($vol.DriveLetter): $($usedPercent)% used - $($freeGB) GB free of $($totalGB) GB`n"
            }
        } catch {
            $report += "Error retrieving disk information`n"
        }
        
        $report += "`n--- NETWORK ADAPTERS ---`n"
        try {
            $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object {$_.Status -eq "Up"}
            foreach ($adapter in $adapters) {
                $report += "$($adapter.Name): $($adapter.Status) - $($adapter.LinkSpeed)`n"
            }
        } catch {
            $report += "Error retrieving network adapter information`n"
        }
        
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
        
        $report += "`n--- STOPPED AUTOMATIC SERVICES ---`n"
        try {
            $stoppedServices = Get-Service -ErrorAction Stop | Where-Object {$_.StartType -eq "Automatic" -and $_.Status -ne "Running"}
            if ($stoppedServices) {
                foreach ($svc in $stoppedServices) {
                    $report += "$($svc.Name): $($svc.Status)`n"
                }
            } else {
                $report += "All automatic services are running`n"
            }
        } catch {
            $report += "Error retrieving service information`n"
        }
        
        $report += "`n--- POWER PLAN ---`n"
        try {
            $powerPlan = powercfg /getactivescheme
            $report += "$($powerPlan)`n"
        } catch {
            $report += "Error retrieving power plan information`n"
        }
        
        $report | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        Write-Success "Report generated: $($reportPath)"
        
        $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
        if ($open -eq "Y") {
            try {
                notepad $reportPath
            } catch {
                Write-Warning "Could not open report automatically. Please navigate to: $($reportPath)"
            }
        }
    } catch {
        Write-Error "Failed to generate system report: $($_.Exception.Message)"
    }
}
#endregion

#region Main Menu and Execution
function Show-MainMenu {
    Clear-Host
    Write-Host @"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     WINDOWS SERVER TROUBLESHOOTING & LOG COLLECTION TOOL      ║
║                         Version 2.1                           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-Host "`nPRIMARY DIAGNOSTICS:" -ForegroundColor Yellow
    Write-Host "  1. Network Issues (Packet Loss, Slowness, RSS Check)" -ForegroundColor White
    Write-Host "  2. Memory Issues (High Usage, Top Consumers)" -ForegroundColor White
    Write-Host "  3. CPU Issues (High Usage, Process Analysis)" -ForegroundColor White
    Write-Host "  4. Disk/Storage Issues (Latency, Performance)" -ForegroundColor White
    Write-Host "  5. Windows Services Health" -ForegroundColor White
    Write-Host "  6. Event Log Analysis" -ForegroundColor White
    Write-Host "  7. DNS Health & Connectivity" -ForegroundColor White
    Write-Host "  8. Security & Authentication (NEW)" -ForegroundColor Green
    Write-Host "  9. Windows Update Status (NEW)" -ForegroundColor Green
    
    Write-Host "`nADDITIONAL SCENARIOS:" -ForegroundColor Yellow
    Write-Host " 10. Additional Troubleshooting Scenarios" -ForegroundColor White
    Write-Host "     (Reboot, Crash, SQL, Cluster, Patching, etc.)" -ForegroundColor Gray
    
    Write-Host "`nUTILITIES:" -ForegroundColor Yellow
    Write-Host " 11. Generate System Report" -ForegroundColor White
    Write-Host " 12. TLS Configuration Validation" -ForegroundColor White
    Write-Host " 13. Validator Script Information" -ForegroundColor White
    Write-Host " 14. Configure TSS Path" -ForegroundColor White
    Write-Host " 15. Check TSS Status" -ForegroundColor White
    
    Write-Host "`n  0. Exit" -ForegroundColor Red
    
    Write-Host "`n" + "═" * 65 -ForegroundColor Cyan
}

function Start-TroubleshootingTool {
    param(
        [switch]$EnableLogging
    )
    
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Error "This script requires Administrator privileges!"
        Write-Info "Please run PowerShell as Administrator and try again."
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    if (-not (Initialize-DiagnosticPaths)) {
        Write-Error "Failed to initialize diagnostic paths. Some features may not work correctly."
    }
    
    $transcriptPath = $null
    if ($EnableLogging) {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $transcriptPath = Join-Path $script:DefaultLogPath "TroubleshootingTool_$($timestamp).log"
        try {
            Start-Transcript -Path $transcriptPath -ErrorAction Stop
            Write-Success "Transcript logging enabled: $($transcriptPath)"
        } catch {
            Write-Warning "Could not start transcript logging: $($_.Exception.Message)"
            $EnableLogging = $false
        }
    }
    
    try {
        do {
            Show-MainMenu
            $choice = Get-ValidatedChoice -Prompt "`nSelect an option (0-15)" -ValidChoices @("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15")
            
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
                    Show-AdditionalScenarios
                }
                "11" {
                    Clear-Host
                    Export-SystemReport
                }
                "12" {
                    Clear-Host
                    Test-TLSConfiguration
                    Write-Host "`n"
                    $export = Get-ValidatedChoice -Prompt "Export TLS report? (Y/N)" -ValidChoices @("Y", "N")
                    if ($export -eq "Y") {
                        Export-TLSReport
                    }
                }
                "13" {
                    Clear-Host
                    Show-ValidatorInfo
                }
                "14" {
                    Clear-Host
                    Set-TSSPath
                }
                "15" {
                    Clear-Host
                    $null = Test-TSSAvailable
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
    } catch {
        Write-Error "An unexpected error occurred: $($_.Exception.Message)"
        Write-Info "Stack Trace: $($_.ScriptStackTrace)"
    } finally {
        if ($EnableLogging -and $transcriptPath) {
            try {
                Stop-Transcript
                Write-Success "Transcript saved to: $($transcriptPath)"
            } catch {
                Write-Warning "Could not stop transcript: $($_.Exception.Message)"
            }
        }
    }
}
#endregion

#region Script Entry Point
if ($EnableLogging) {
    Start-TroubleshootingTool -EnableLogging
} else {
    Start-TroubleshootingTool
}
#endregion