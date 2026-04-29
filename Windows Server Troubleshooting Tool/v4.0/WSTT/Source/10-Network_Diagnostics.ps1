# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Network Diagnostics
# Source lines: 1084 - 1975
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
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
                    if ($driverAge -gt 730) {
                        Write-DiagWarning "    WARNING: Driver is over 2 years old - consider updating"
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
                    }
                }
            }
            catch {
                Write-DiagWarning "  Could not retrieve driver info for $($adpt.Name): $($_.Exception.Message)"
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
