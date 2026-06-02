# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: DNS Health & Connectivity
# Source lines: 4637 - 4918
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
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
