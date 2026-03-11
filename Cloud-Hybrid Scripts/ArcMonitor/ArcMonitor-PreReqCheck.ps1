#Requires -Version 5.1
Set-StrictMode -Version Latest
<#
.SYNOPSIS
    Azure Arc — Remote Prerequisite Validation Module
.DESCRIPTION
    Validates ALL Azure Arc onboarding prerequisites REMOTELY on target machines.
    Runs from a centralized management server — never assumes the local machine is the target.
    Auto-detects platform type (VMware, Azure Local, Hyper-V, Physical, Azure Native).
.NOTES
    All checks execute via Invoke-Command on the remote target.
    Azure native VMs are auto-excluded from onboarding.
#>

# ─── Platform Detection ─────────────────────────────────────────────────────────

function Get-TargetPlatform {
    <#
    .SYNOPSIS
        Auto-detects the hosting platform of a remote machine via WMI.
    .OUTPUTS
        Hashtable: @{ Platform; Manufacturer; Model; IsVirtual; IsAzureVM }
    #>
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    $result = Invoke-Command -Session $Session -ScriptBlock {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $manufacturer = ($cs.Manufacturer).Trim()
        $model = ($cs.Model).Trim()

        # Detect platform
        $platform = "Physical"
        $isVirtual = $false
        $isAzureVM = $false

        switch -Wildcard ($manufacturer) {
            "VMware*"                    { $platform = "VMware";   $isVirtual = $true }
            "Microsoft Corporation"      {
                if ($model -match "Virtual Machine") {
                    # Could be Hyper-V or Azure
                    $isVirtual = $true
                    # Check Azure metadata endpoint
                    try {
                        $metadata = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" `
                                                      -Headers @{ Metadata = "true" } -TimeoutSec 3 -ErrorAction Stop
                        if ($metadata.compute.azEnvironment) {
                            $platform = "AzureNativeVM"
                            $isAzureVM = $true
                        } else {
                            $platform = "HyperV"
                        }
                    }
                    catch {
                        $platform = "HyperV"
                    }
                }
                elseif ($model -match "Azure Stack HCI" -or (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).ProductName -match "Azure Stack") {
                    $platform = "AzureLocal"
                    $isVirtual = $false
                }
                else {
                    $platform = "Physical"
                }
            }
            "QEMU"                       { $platform = "KVM";      $isVirtual = $true }
            "Xen"                        { $platform = "Xen";      $isVirtual = $true }
            "Nutanix"                    { $platform = "Nutanix";   $isVirtual = $true }
            "Amazon EC2"                 { $platform = "AWS-EC2";   $isVirtual = $true }
            "Google"                     { $platform = "GCP";       $isVirtual = $true }
            default {
                if ($cs.HypervisorPresent) { $isVirtual = $true; $platform = "Virtual-Unknown" }
            }
        }

        return @{
            Platform     = $platform
            Manufacturer = $manufacturer
            Model        = $model
            IsVirtual    = $isVirtual
            IsAzureVM    = $isAzureVM
            BIOSSerial   = $bios.SerialNumber
        }
    } -ErrorAction Stop

    return $result
}

# ─── Full Remote Prerequisite Check ─────────────────────────────────────────────

function Test-ArcPrerequisites {
    <#
    .SYNOPSIS
        Runs ALL Azure Arc prerequisites REMOTELY on a target machine.
    .DESCRIPTION
        Validates: OS version, PS version, .NET, TLS 1.2, WinRM, internet access,
        admin rights, existing agent, HIMDS service, disk space, platform type.
        All checks run on the TARGET — not on the management server.
    .OUTPUTS
        Hashtable with check results, overall pass/fail, and platform info.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [string]$ProxyServer = $null
    )

    $result = @{
        ComputerName = $ComputerName
        Timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Reachable    = $false
        Checks       = @{}
        Platform     = @{}
        OverallPass  = $false
        FailedChecks = @()
        Warnings     = @()
    }

    # ── Check 1: Network Reachability ────────────────────────────────────────────
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcp.ConnectAsync($ComputerName, 5985)
        $connected = $connectTask.Wait(5000)
        if ($connected -and $tcp.Connected) {
            $result.Reachable = $true
            $result.Checks["Reachability"] = @{ Status = "Pass"; Detail = "WinRM port 5985 reachable" }
        } else {
            $result.Checks["Reachability"] = @{ Status = "Fail"; Detail = "WinRM port 5985 not reachable (timeout)" }
            $result.FailedChecks += "Reachability"
            return $result
        }
        $tcp.Close(); $tcp.Dispose()
    }
    catch {
        $result.Checks["Reachability"] = @{ Status = "Fail"; Detail = "Cannot connect: $($_.Exception.Message)" }
        $result.FailedChecks += "Reachability"
        return $result
    }

    # ── Establish Remote Session ─────────────────────────────────────────────────
    # SECURITY: Prefer WinRM over HTTPS (port 5986) in production environments.
    # Configure with: winrm quickconfig -transport:https
    $session = $null
    $sessionOpts = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 60000
    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential `
                                 -SessionOption $sessionOpts -ErrorAction Stop
    }
    catch {
        $result.Checks["RemoteSession"] = @{ Status = "Fail"; Detail = "WinRM session failed: $($_.Exception.Message)" }
        $result.FailedChecks += "RemoteSession"
        return $result
    }
    $result.Checks["RemoteSession"] = @{ Status = "Pass"; Detail = "WinRM session established" }

    try {
        # ── Check 2: Platform Detection ──────────────────────────────────────────
        try {
            $platformResult = Get-TargetPlatform -Session $session
            $result.Platform = $platformResult
            $pName  = if ($platformResult['Platform'])     { $platformResult['Platform'] }     else { "Unknown" }
            $pMfg   = if ($platformResult['Manufacturer']) { $platformResult['Manufacturer'] } else { "Unknown" }
            $pModel = if ($platformResult['Model'])        { $platformResult['Model'] }        else { "Unknown" }
            $result.Checks["PlatformDetect"] = @{
                Status = "Pass"
                Detail = "$pName ($pMfg / $pModel)"
            }

            # Auto-exclude Azure native VMs
            $isAzVM = if ($platformResult['IsAzureVM']) { $platformResult['IsAzureVM'] } else { $false }
            if ($isAzVM) {
                $result.Checks["AzureVMExclusion"] = @{
                    Status = "Fail"
                    Detail = "Azure native VM detected — must NOT be onboarded to Arc"
                }
                $result.FailedChecks += "AzureVMExclusion"
                return $result
            }
        }
        catch {
            $result.Checks["PlatformDetect"] = @{ Status = "Warn"; Detail = "Could not detect platform: $($_.Exception.Message)" }
            $result.Warnings += "PlatformDetect"
        }

        # ── Check 3–12: All Remote Checks ───────────────────────────────────────
        $remoteChecks = Invoke-Command -Session $session -ScriptBlock {
            param($ProxyServer)
            $checks = @{}

            # 3. OS Version + Server SKU validation
            # Ref: https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems
            $os = Get-CimInstance Win32_OperatingSystem
            $osVersion = [version]$os.Version
            $osName = $os.Caption
            $isServerOS = ($os.ProductType -ge 2)  # 1=Workstation, 2=DC, 3=Server
            $versionOk = ($osVersion.Major -ge 10) -or ($osVersion.Major -eq 6 -and $osVersion.Minor -ge 3)
            $supported = $isServerOS -and $versionOk
            $checks["OSVersion"] = @{
                Status = if ($supported) { "Pass" } elseif (-not $isServerOS) { "Fail" } else { "Fail" }
                Detail = if (-not $isServerOS) { "$osName — Client OS not supported (only Windows Server)" }
                         elseif (-not $versionOk) { "$osName — OS version too old (Server 2012 R2+ required)" }
                         else { "$osName (Build $($os.Version))" }
            }

            # 4. PowerShell Version
            $psVer = $PSVersionTable.PSVersion
            $psOk = ($psVer.Major -ge 5)
            $checks["PSVersion"] = @{
                Status = if ($psOk) { "Pass" } else { "Fail" }
                Detail = "PowerShell $($psVer.Major).$($psVer.Minor)"
            }

            # 5. .NET Framework Version
            try {
                $dotnetKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction Stop
                $dotnetRelease = $dotnetKey.Release
                $dotnetVer = switch ([int]$dotnetRelease) {
                    { $_ -ge 528040 } { "4.8+" }
                    { $_ -ge 461808 } { "4.7.2" }
                    { $_ -ge 461308 } { "4.7.1" }
                    { $_ -ge 460798 } { "4.7" }
                    { $_ -ge 394802 } { "4.6.2" }
                    { $_ -ge 394254 } { "4.6.1" }
                    default           { "4.6 or lower" }
                }
                $dotnetOk = ($dotnetRelease -ge 394802)  # 4.6.2+ required
                $checks["DotNetVersion"] = @{
                    Status = if ($dotnetOk) { "Pass" } else { "Fail" }
                    Detail = ".NET Framework $dotnetVer (Release $dotnetRelease)"
                }
            }
            catch {
                $checks["DotNetVersion"] = @{ Status = "Fail"; Detail = ".NET Framework 4 not found" }
            }

            # 6. TLS 1.2 Configuration
            $tls12Client = $null
            try {
                $tls12Client = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -ErrorAction SilentlyContinue
            } catch {}
            $tlsEnabled = [Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12
            $tlsRegOk = (-not $tls12Client) -or ($tls12Client.Enabled -ne 0 -and $tls12Client.DisabledByDefault -ne 1)
            $checks["TLS12"] = @{
                Status = if ($tlsEnabled -or $tlsRegOk) { "Pass" } else { "Fail" }
                Detail = if ($tlsEnabled) { "TLS 1.2 enabled in SecurityProtocol" } elseif ($tlsRegOk) { "TLS 1.2 enabled in registry" } else { "TLS 1.2 NOT enabled" }
            }

            # 7. Admin Rights (current session)
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            $checks["AdminRights"] = @{
                Status = if ($isAdmin) { "Pass" } else { "Fail" }
                Detail = if ($isAdmin) { "Running as Administrator" } else { "NOT running as Administrator" }
            }

            # 8. Disk Space (system drive, need at least 2GB)
            $sysDrive = if ($env:SystemDrive) { $env:SystemDrive } else { "C:" }
            $cDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'"
            $freeGB = [Math]::Round($cDrive.FreeSpace / 1GB, 2)
            $checks["DiskSpace"] = @{
                Status = if ($freeGB -ge 2) { "Pass" } else { "Fail" }
                Detail = "$freeGB GB free on $sysDrive"
            }

            # 8b. Clock Skew Check (>5 min drift breaks Kerberos/TLS/token auth → error 17)
            # Ref: https://learn.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-agent-onboard
            try {
                $w32tmOutput = & w32tm /stripchart /computer:time.windows.com /dataonly /samples:1 2>&1
                $skewMatch = [regex]::Match(($w32tmOutput | Out-String), '([+-]?\d+\.\d+)s')
                if ($skewMatch.Success) {
                    $skewSeconds = [Math]::Abs([double]$skewMatch.Groups[1].Value)
                    $checks["ClockSkew"] = @{
                        Status = if ($skewSeconds -lt 300) { "Pass" } else { "Fail" }
                        Detail = "Clock skew: $([Math]::Round($skewSeconds, 1))s$(if ($skewSeconds -ge 300) {' — exceeds 5 min, will cause auth failures'})"
                    }
                } else {
                    $checks["ClockSkew"] = @{ Status = "Warn"; Detail = "Could not measure clock skew (NTP unreachable?)" }
                }
            }
            catch {
                $checks["ClockSkew"] = @{ Status = "Warn"; Detail = "Clock skew check failed: $($_.Exception.Message)" }
            }

            # 8c. Pending Reboot Check (blocks MSI installs, service registration)
            $rebootPending = $false
            $rebootReasons = [System.Collections.Generic.List[string]]::new()
            if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
                $rebootPending = $true; $rebootReasons.Add("CBS")
            }
            $pfro = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
            if ($pfro.PendingFileRenameOperations) {
                $rebootPending = $true; $rebootReasons.Add("PendingFileRename")
            }
            if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
                $rebootPending = $true; $rebootReasons.Add("WindowsUpdate")
            }
            $checks["PendingReboot"] = @{
                Status = if ($rebootPending) { "Warn" } else { "Pass" }
                Detail = if ($rebootPending) { "Reboot pending ($($rebootReasons -join ', ')) — may block agent install" } else { "No pending reboot" }
            }

            # 9. Existing Arc Agent Check (with Disconnected/Expired handling)
            $agentPath = "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe"
            $agentInstalled = Test-Path $agentPath
            $agentStatus = "NotInstalled"
            if ($agentInstalled) {
                try {
                    $agentJson = & $agentPath show --json 2>$null | ConvertFrom-Json
                    $agentStatus = $agentJson.status
                }
                catch { $agentStatus = "InstalledButError" }
            }
            $checks["ExistingAgent"] = @{
                Status = if (-not $agentInstalled) { "Pass" }
                         elseif ($agentStatus -eq "Connected") { "Warn" }
                         elseif ($agentStatus -eq "Disconnected") { "Warn" }
                         elseif ($agentStatus -eq "Expired") { "Fail" }
                         else { "Pass" }
                Detail = if (-not $agentInstalled) { "No existing agent — ready for fresh install" }
                         elseif ($agentStatus -eq "Connected") { "Agent already connected to Azure Arc" }
                         elseif ($agentStatus -eq "Disconnected") { "Agent DISCONNECTED — will attempt reconnect" }
                         elseif ($agentStatus -eq "Expired") { "Agent EXPIRED — must run: azcmagent disconnect --force-local-only, then reconnect" }
                         else { "Agent installed but status: $agentStatus" }
            }

            # 10. HIMDS Service Check
            $himdsSvc = Get-Service -Name "himds" -ErrorAction SilentlyContinue
            $checks["HIMDSService"] = @{
                Status = if (-not $himdsSvc) { "Info" }
                         elseif ($himdsSvc.Status -eq "Running") { "Pass" }
                         else { "Warn" }
                Detail = if (-not $himdsSvc) { "HIMDS service not present (expected before install)" }
                         elseif ($himdsSvc.Status -eq "Running") { "HIMDS service running" }
                         else { "HIMDS service exists but status: $($himdsSvc.Status)" }
            }

            # 11. Internet Connectivity to Azure Arc Required Endpoints
            # Ref: https://learn.microsoft.com/en-us/azure/azure-arc/servers/network-requirements#urls
            $azureEndpoints = @(
                @{ Name = "Azure ARM";           Host = "management.azure.com";                Port = 443 }
                @{ Name = "Entra ID (login)";    Host = "login.microsoftonline.com";           Port = 443 }
                @{ Name = "Entra ID (pas)";      Host = "pas.windows.net";                     Port = 443 }
                @{ Name = "Arc HIS (metadata)";  Host = "his.arc.azure.com";                   Port = 443 }
                @{ Name = "Arc GBL (global)";    Host = "gbl.his.arc.azure.com";               Port = 443 }
                @{ Name = "Guest Config";        Host = "guestconfiguration.azure.com";        Port = 443 }
                @{ Name = "Guest Notify";        Host = "guestnotificationservice.azure.com";  Port = 443 }
                @{ Name = "Service Bus";         Host = "servicebus.windows.net";              Port = 443 }
                @{ Name = "Agent Download";      Host = "download.microsoft.com";              Port = 443 }
                @{ Name = "Packages (Linux)";    Host = "packages.microsoft.com";              Port = 443 }
            )

            $endpointResults = [System.Collections.Generic.List[string]]::new()
            $allEndpointsOk = $true
            foreach ($ep in $azureEndpoints) {
                try {
                    $tcpTest = New-Object System.Net.Sockets.TcpClient
                    $task = $tcpTest.ConnectAsync($ep.Host, $ep.Port)
                    $ok = $task.Wait(5000)
                    $reachable = ($ok -and $tcpTest.Connected)
                    $tcpTest.Close(); $tcpTest.Dispose()
                }
                catch { $reachable = $false }

                $endpointResults.Add("$($ep.Name): $(if ($reachable) {'OK'} else {'BLOCKED'})")
                if (-not $reachable) { $allEndpointsOk = $false }
            }
            $checks["AzureEndpoints"] = @{
                Status = if ($allEndpointsOk) { "Pass" } else { "Fail" }
                Detail = $endpointResults -join " | "
            }

            # 12. Windows Services Required
            $requiredSvcs = @("WinRM", "W32Time")
            $svcResults = [System.Collections.Generic.List[string]]::new()
            $allSvcsOk = $true
            foreach ($svcName in $requiredSvcs) {
                $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq "Running") {
                    $svcResults.Add("$svcName : Running")
                } else {
                    $svcResults.Add("$svcName : NOT Running")
                    $allSvcsOk = $false
                }
            }
            $checks["RequiredServices"] = @{
                Status = if ($allSvcsOk) { "Pass" } else { "Fail" }
                Detail = $svcResults -join " | "
            }

            # 13. Proxy Configuration (if applicable)
            if ($ProxyServer) {
                try {
                    $proxyTest = Invoke-WebRequest -Uri "https://management.azure.com" `
                                                   -Proxy $ProxyServer -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                    $checks["ProxyConfig"] = @{ Status = "Pass"; Detail = "Proxy $ProxyServer reachable to Azure" }
                }
                catch {
                    $checks["ProxyConfig"] = @{ Status = "Fail"; Detail = "Proxy $ProxyServer cannot reach Azure: $($_.Exception.Message)" }
                }
            }

            return $checks
        } -ArgumentList $ProxyServer -ErrorAction Stop

        # Merge remote checks into result
        foreach ($key in $remoteChecks.Keys) {
            $result.Checks[$key] = $remoteChecks[$key]
        }

        # Tally failures and warnings
        foreach ($key in $result.Checks.Keys) {
            if ($result.Checks[$key].Status -eq "Fail") { $result.FailedChecks += $key }
            if ($result.Checks[$key].Status -eq "Warn") { $result.Warnings += $key }
        }

        $result.OverallPass = (@($result.FailedChecks).Count -eq 0)
    }
    finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    }

    return $result
}

# ─── Reachability Quick Check ────────────────────────────────────────────────────

function Test-ServerReachability {
    <#
    .SYNOPSIS
        Quick reachability check for a list of servers (ICMP + WinRM port).
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$Servers,

        [int]$TimeoutMs = 3000
    )

    $results = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($srv in $Servers) {
        $entry = @{ Server = $srv; ICMP = $false; WinRM = $false; Reachable = $false }

        # ICMP ping
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($srv, $TimeoutMs)
            $entry.ICMP = ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
            $ping.Dispose()
        }
        catch { $entry.ICMP = $false }

        # WinRM TCP 5985
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $task = $tcp.ConnectAsync($srv, 5985)
            $connected = $task.Wait($TimeoutMs)
            $entry.WinRM = ($connected -and $tcp.Connected)
            $tcp.Close(); $tcp.Dispose()
        }
        catch { $entry.WinRM = $false }

        $entry.Reachable = ($entry.ICMP -or $entry.WinRM)
        $results.Add($entry)
    }

    return $results
}

# ─── Display PreReq Results ──────────────────────────────────────────────────────

function Show-PreReqResults {
    <#
    .SYNOPSIS
        Renders prerequisite check results as a formatted table.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Result
    )

    $server = $Result.ComputerName
    $pass = $Result.OverallPass

    Write-Host ""
    if ($pass) {
        Write-Host "  [$server] " -NoNewline -ForegroundColor White
        Write-Host "PASSED" -ForegroundColor Green
    } else {
        Write-Host "  [$server] " -NoNewline -ForegroundColor White
        Write-Host "FAILED ($(@($Result.FailedChecks).Count) issue(s))" -ForegroundColor Red
    }

    if ($Result.Platform -and $Result.Platform['Platform']) {
        Write-Host "  Platform: $($Result.Platform['Platform']) | $($Result.Platform['Manufacturer']) | $($Result.Platform['Model'])" -ForegroundColor DarkGray
    }

    Write-Host ""
    foreach ($key in ($Result.Checks.Keys | Sort-Object)) {
        $check = $Result.Checks[$key]
        $icon = switch ($check.Status) {
            "Pass" { "[PASS]" }
            "Fail" { "[FAIL]" }
            "Warn" { "[WARN]" }
            "Info" { "[INFO]" }
            default { "[----]" }
        }
        $color = switch ($check.Status) {
            "Pass" { "Green" }
            "Fail" { "Red" }
            "Warn" { "Yellow" }
            "Info" { "Cyan" }
            default { "Gray" }
        }

        Write-Host "    $icon " -NoNewline -ForegroundColor $color
        Write-Host "$($key.PadRight(20))" -NoNewline -ForegroundColor White
        Write-Host " $($check.Detail)" -ForegroundColor DarkGray
    }
    Write-Host ""

    # Show remediation guidance for failed checks
    if (@($Result.FailedChecks).Count -gt 0) {
        Show-RemediationGuidance -FailedChecks $Result.FailedChecks -Checks $Result.Checks
    }
}

# ─── Remediation Guidance & Auto-Fix ────────────────────────────────────────────

# Official Microsoft Azure Arc-enabled servers documentation references
# Base: https://learn.microsoft.com/en-us/azure/azure-arc/servers/
$Script:ArcDocsBase = "https://learn.microsoft.com/en-us/azure/azure-arc/servers"
$Script:MicrosoftDocs = @{
    Overview         = "$($Script:ArcDocsBase)/overview"
    Prerequisites    = "$($Script:ArcDocsBase)/prerequisites"
    Reachability     = "$($Script:ArcDocsBase)/network-requirements"
    RemoteSession    = "https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands"
    OSVersion        = "$($Script:ArcDocsBase)/prerequisites#supported-operating-systems"
    PSVersion        = "$($Script:ArcDocsBase)/prerequisites#software-and-system-requirements"
    DotNetVersion    = "$($Script:ArcDocsBase)/prerequisites#software-and-system-requirements"
    TLS12            = "$($Script:ArcDocsBase)/prerequisites#transport-layer-security-12-protocol"
    AdminRights      = "$($Script:ArcDocsBase)/onboard-service-principal"
    DiskSpace        = "$($Script:ArcDocsBase)/prerequisites#software-and-system-requirements"
    ExistingAgent    = "$($Script:ArcDocsBase)/manage-agent"
    AzureEndpoints   = "$($Script:ArcDocsBase)/network-requirements#urls"
    RequiredServices = "$($Script:ArcDocsBase)/prerequisites#software-and-system-requirements"
    AzureVMExclusion = "$($Script:ArcDocsBase)/overview"
    ProxyConfig      = "$($Script:ArcDocsBase)/manage-agent#update-or-remove-proxy-settings"
    PlatformDetect   = "$($Script:ArcDocsBase)/prerequisites#supported-environments"
    PrivateLink      = "$($Script:ArcDocsBase)/private-link-security"
    DeployOptions    = "$($Script:ArcDocsBase)/deployment-options"
    ArcGateway       = "$($Script:ArcDocsBase)/arc-gateway"
}

function Show-RemediationGuidance {
    <#
    .SYNOPSIS
        Shows fix guidance and Microsoft docs for each failed prereq check.
    #>
    param(
        [string[]]$FailedChecks,
        [hashtable]$Checks
    )

    Write-Host "  ┌─ REMEDIATION GUIDANCE ──────────────────────────────────────────" -ForegroundColor Yellow
    Write-Host ""

    foreach ($checkName in $FailedChecks) {
        $check = $Checks[$checkName]
        $docUrl = if ($Script:MicrosoftDocs[$checkName]) { $Script:MicrosoftDocs[$checkName] } else { "" }

        Write-Host "    ✖ $checkName" -ForegroundColor Red
        Write-Host "      Status : $($check.Detail)" -ForegroundColor DarkGray

        switch ($checkName) {
            "Reachability" {
                Write-Host "      Fix    : Enable WinRM on the target server." -ForegroundColor White
                Write-Host "      Run on target: " -NoNewline -ForegroundColor DarkGray
                Write-Host "Enable-PSRemoting -Force" -ForegroundColor Cyan
                Write-Host "      Also verify: " -NoNewline -ForegroundColor DarkGray
                Write-Host "Firewall allows TCP 5985/5986 from management server" -ForegroundColor Cyan
                Write-Host "      CanFix : YES (run auto-fix option below)" -ForegroundColor Green
            }
            "RemoteSession" {
                Write-Host "      Fix    : Enable and configure WinRM on the target." -ForegroundColor White
                Write-Host "      Run on target:" -ForegroundColor DarkGray
                Write-Host "        Enable-PSRemoting -Force" -ForegroundColor Cyan
                Write-Host "        Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<target-hostname>' -Force  # NEVER use '*'" -ForegroundColor Cyan
                Write-Host "      Or on management server:" -ForegroundColor DarkGray
                Write-Host "        Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<target>' -Force" -ForegroundColor Cyan
                Write-Host "      CanFix : PARTIAL (requires manual action on target)" -ForegroundColor Yellow
            }
            "OSVersion" {
                Write-Host "      Fix    : Azure Arc requires a supported OS version." -ForegroundColor White
                Write-Host "      (Per: learn.microsoft.com/azure/azure-arc/servers/prerequisites#supported-operating-systems)" -ForegroundColor DarkGray
                Write-Host "      Supported Windows:" -ForegroundColor DarkGray
                Write-Host "        Windows Server 2012, 2012 R2, 2016, 2019, 2022, 2025" -ForegroundColor Cyan
                Write-Host "        Windows 10/11 (server-like use only)" -ForegroundColor Cyan
                Write-Host "      Supported Linux:" -ForegroundColor DarkGray
                Write-Host "        Ubuntu 18.04/20.04/22.04/24.04, RHEL 7/8/9/10" -ForegroundColor Cyan
                Write-Host "        SLES 12 SP5/15 SP4+, Debian 11/12, Oracle 7/8/9" -ForegroundColor Cyan
                Write-Host "        AlmaLinux 8/9, Rocky 8/9, Amazon Linux 2/2023" -ForegroundColor Cyan
                Write-Host "      Note   : x86-64 fully supported. Arm64 has limited support." -ForegroundColor DarkGray
                Write-Host "      CanFix : NO (OS upgrade required)" -ForegroundColor Red
            }
            "PSVersion" {
                Write-Host "      Fix    : Install Windows Management Framework (WMF) 5.1 or later." -ForegroundColor White
                Write-Host "      Download: https://aka.ms/wmf5download" -ForegroundColor Cyan
                Write-Host "      CanFix : YES (WMF install via auto-fix)" -ForegroundColor Green
            }
            "DotNetVersion" {
                Write-Host "      Fix    : Install .NET Framework 4.6.2 or later on the target." -ForegroundColor White
                Write-Host "      Download: https://dotnet.microsoft.com/download/dotnet-framework" -ForegroundColor Cyan
                Write-Host "      Run on target:" -ForegroundColor DarkGray
                Write-Host "        # Install .NET 4.8 offline installer" -ForegroundColor Cyan
                Write-Host "        Start-Process ndp48-x86-x64-allos-enu.exe -ArgumentList '/quiet /norestart' -Wait" -ForegroundColor Cyan
                Write-Host "      CanFix : YES (remote install via auto-fix)" -ForegroundColor Green
            }
            "TLS12" {
                Write-Host "      Fix    : Enable TLS 1.2 in registry and .NET SecurityProtocol." -ForegroundColor White
                Write-Host "      Run on target:" -ForegroundColor DarkGray
                Write-Host "        # Enable TLS 1.2 for Server" -ForegroundColor Cyan
                Write-Host "        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force" -ForegroundColor Cyan
                Write-Host "        New-ItemProperty -Path '...\TLS 1.2\Server' -Name Enabled -Value 1 -Type DWord" -ForegroundColor Cyan
                Write-Host "        New-ItemProperty -Path '...\TLS 1.2\Server' -Name DisabledByDefault -Value 0 -Type DWord" -ForegroundColor Cyan
                Write-Host "        # Enable TLS 1.2 for Client" -ForegroundColor Cyan
                Write-Host "        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force" -ForegroundColor Cyan
                Write-Host "        New-ItemProperty -Path '...\TLS 1.2\Client' -Name Enabled -Value 1 -Type DWord" -ForegroundColor Cyan
                Write-Host "        New-ItemProperty -Path '...\TLS 1.2\Client' -Name DisabledByDefault -Value 0 -Type DWord" -ForegroundColor Cyan
                Write-Host "        # Enable TLS 1.2 for .NET Framework" -ForegroundColor Cyan
                Write-Host "        Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name SchUseStrongCrypto -Value 1 -Type DWord" -ForegroundColor Cyan
                Write-Host "        Set-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name SchUseStrongCrypto -Value 1 -Type DWord" -ForegroundColor Cyan
                Write-Host "      NOTE   : Reboot required after registry changes." -ForegroundColor Yellow
                Write-Host "      CanFix : YES (remote registry via auto-fix, reboot needed)" -ForegroundColor Green
            }
            "AdminRights" {
                Write-Host "      Fix    : Ensure the credential used has local Administrator rights on target." -ForegroundColor White
                Write-Host "      Options:" -ForegroundColor DarkGray
                Write-Host "        - Use a domain admin or local admin account" -ForegroundColor Cyan
                Write-Host "        - Add user to local Administrators group on target:" -ForegroundColor Cyan
                Write-Host "          Add-LocalGroupMember -Group 'Administrators' -Member '<user>'" -ForegroundColor Cyan
                Write-Host "      CanFix : NO (requires credential change)" -ForegroundColor Red
            }
            "DiskSpace" {
                Write-Host "      Fix    : Free at least 2 GB on C: drive of the target server." -ForegroundColor White
                Write-Host "      Run on target:" -ForegroundColor DarkGray
                Write-Host "        # Clean temp files" -ForegroundColor Cyan
                Write-Host "        Remove-Item `$env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue" -ForegroundColor Cyan
                Write-Host "        # Run disk cleanup" -ForegroundColor Cyan
                Write-Host "        cleanmgr /sagerun:1" -ForegroundColor Cyan
                Write-Host "      CanFix : PARTIAL (auto-clean temp files via auto-fix)" -ForegroundColor Yellow
            }
            "AzureEndpoints" {
                Write-Host "      Fix    : Allow outbound HTTPS (TCP 443) to Azure Arc required endpoints." -ForegroundColor White
                Write-Host "      The following URLs must be reachable FROM THE TARGET server:" -ForegroundColor DarkGray
                Write-Host "      (Per: learn.microsoft.com/azure/azure-arc/servers/network-requirements#urls)" -ForegroundColor DarkGray
                Write-Host ""
                Write-Host "        REQUIRED (Always):" -ForegroundColor Yellow
                Write-Host "          login.microsoftonline.com        Microsoft Entra ID authentication" -ForegroundColor Cyan
                Write-Host "          *.login.microsoft.com            Microsoft Entra ID authentication" -ForegroundColor Cyan
                Write-Host "          pas.windows.net                  Microsoft Entra ID authentication" -ForegroundColor Cyan
                Write-Host "          management.azure.com             Azure Resource Manager (connect/disconnect)" -ForegroundColor Cyan
                Write-Host "          *.his.arc.azure.com              Hybrid Identity Service (metadata)" -ForegroundColor Cyan
                Write-Host "          *.guestconfiguration.azure.com   Extension + Guest Configuration service" -ForegroundColor Cyan
                Write-Host "          guestnotificationservice.azure.com  Notification service (extensions)" -ForegroundColor Cyan
                Write-Host "          *.servicebus.windows.net         Notification service (extensions)" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "        REQUIRED (Installation time):" -ForegroundColor Yellow
                Write-Host "          download.microsoft.com           Windows agent download" -ForegroundColor Cyan
                Write-Host "          packages.microsoft.com           Linux agent packages" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "        OPTIONAL:" -ForegroundColor DarkGray
                Write-Host "          *.waconazure.com                 Windows Admin Center connectivity" -ForegroundColor DarkGray
                Write-Host "          www.microsoft.com/pkiops/certs   ESU certificate updates" -ForegroundColor DarkGray
                Write-Host ""
                Write-Host "      Service Tags: AzureActiveDirectory, AzureTrafficManager," -ForegroundColor DarkGray
                Write-Host "        AzureResourceManager, AzureArcInfrastructure, Storage" -ForegroundColor DarkGray
                Write-Host ""
                Write-Host "      Proxy : azcmagent config set proxy.url 'http://proxy:port'" -ForegroundColor Cyan
                Write-Host "      Alt   : Use Azure Arc Gateway to reduce endpoints:" -ForegroundColor DarkGray
                Write-Host "              $($Script:MicrosoftDocs['ArcGateway'])" -ForegroundColor DarkCyan
                Write-Host "      Alt   : Use Private Link for private connectivity:" -ForegroundColor DarkGray
                Write-Host "              $($Script:MicrosoftDocs['PrivateLink'])" -ForegroundColor DarkCyan
                Write-Host "      CanFix : NO (firewall/network team must allow endpoints)" -ForegroundColor Red
            }
            "RequiredServices" {
                Write-Host "      Fix    : Start required Windows services on the target." -ForegroundColor White
                Write-Host "      Run on target:" -ForegroundColor DarkGray
                Write-Host "        Set-Service WinRM -StartupType Automatic; Start-Service WinRM" -ForegroundColor Cyan
                Write-Host "        Set-Service W32Time -StartupType Automatic; Start-Service W32Time" -ForegroundColor Cyan
                Write-Host "      CanFix : YES (remote service start via auto-fix)" -ForegroundColor Green
            }
            "AzureVMExclusion" {
                Write-Host "      Fix    : Azure native VMs must NOT be onboarded to Arc." -ForegroundColor White
                Write-Host "      Azure VMs already have the Azure VM Agent and metadata service." -ForegroundColor DarkGray
                Write-Host "      Remove this server from the onboarding list." -ForegroundColor Yellow
                Write-Host "      CanFix : N/A (by design — not an error to fix)" -ForegroundColor DarkGray
            }
            "ProxyConfig" {
                Write-Host "      Fix    : Verify proxy server is reachable and allows Azure endpoints." -ForegroundColor White
                Write-Host "      Test  : Invoke-WebRequest -Uri 'https://management.azure.com' -Proxy '<proxy>'" -ForegroundColor Cyan
                Write-Host "      After agent install, configure proxy:" -ForegroundColor DarkGray
                Write-Host "        azcmagent config set proxy.url 'http://proxy:port'" -ForegroundColor Cyan
                Write-Host "      CanFix : NO (network/proxy team must verify)" -ForegroundColor Red
            }
            default {
                Write-Host "      Fix    : Review the check detail above and resolve manually." -ForegroundColor White
            }
        }

        if ($docUrl) {
            Write-Host "      Docs   : $docUrl" -ForegroundColor DarkCyan
        }
        Write-Host ""
    }

    Write-Host "  ── Azure Arc-enabled servers documentation ─────────────────────────" -ForegroundColor DarkGray
    Write-Host "     Main       : $($Script:ArcDocsBase)/" -ForegroundColor DarkCyan
    Write-Host "     PreReqs    : $($Script:MicrosoftDocs['Prerequisites'])" -ForegroundColor DarkCyan
    Write-Host "     Network    : $($Script:MicrosoftDocs['Reachability'])" -ForegroundColor DarkCyan
    Write-Host "     Deployment : $($Script:MicrosoftDocs['DeployOptions'])" -ForegroundColor DarkCyan
    Write-Host ""
}

# ─── Auto-Remediation (Fix What We Can Remotely) ────────────────────────────────

function Repair-ArcPrerequisites {
    <#
    .SYNOPSIS
        Attempts to auto-fix remediable prerequisites on a remote target.
    .DESCRIPTION
        Fixes: TLS 1.2, Required Services, Disk Cleanup.
        Cannot fix: OS version, admin rights, firewall/endpoints, Azure VM exclusion.
        Ref: https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$FailedChecks
    )

    # Determine what can be auto-fixed
    $autoFixable = @("TLS12", "RequiredServices", "DiskSpace", "PSVersion", "DotNetVersion")
    [string[]]$fixable = @($FailedChecks | Where-Object { $_ -in $autoFixable })
    [string[]]$notFixable = @($FailedChecks | Where-Object { $_ -notin $autoFixable })

    if ($fixable.Count -eq 0) {
        Write-Host "    No auto-fixable issues found. Manual intervention required." -ForegroundColor Yellow
        return $false
    }

    Write-Host ""
    Write-Host "    Auto-fixable issues on ${ComputerName}:" -ForegroundColor Cyan
    foreach ($f in $fixable)    { Write-Host "      ✓ $f" -ForegroundColor Green }
    foreach ($nf in $notFixable) { Write-Host "      ✖ $nf (manual fix required)" -ForegroundColor Red }
    Write-Host ""

    if (-not $PSCmdlet.ShouldProcess($ComputerName, "Apply auto-fixes: $($fixable -join ', ')")) {
        return $false
    }

    $confirm = Read-Host "    Apply auto-fixes to $ComputerName ? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return $false }

    $session = $null
    $fixedCount = 0
    $rebootNeeded = $false

    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop

        foreach ($check in $fixable) {
            Write-Host "    Fixing: $check..." -NoNewline -ForegroundColor Yellow

            switch ($check) {
                "TLS12" {
                    # Ref: https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#transport-layer-security-12-protocol
                    $tlsResult = Invoke-Command -Session $session -ScriptBlock {
                        try {
                            # TLS 1.2 Server
                            $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
                            New-Item $serverPath -Force -ErrorAction SilentlyContinue | Out-Null
                            New-ItemProperty -Path $serverPath -Name "Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
                            New-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 0 -PropertyType DWord -Force | Out-Null

                            # TLS 1.2 Client
                            $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
                            New-Item $clientPath -Force -ErrorAction SilentlyContinue | Out-Null
                            New-ItemProperty -Path $clientPath -Name "Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
                            New-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 0 -PropertyType DWord -Force | Out-Null

                            # .NET Framework strong crypto
                            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord -Force
                            if (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319") {
                                Set-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord -Force
                            }

                            # Enable in current session
                            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

                            return @{ Fixed = $true; RebootNeeded = $true }
                        }
                        catch { return @{ Fixed = $false; Error = $_.Exception.Message } }
                    } -ErrorAction Stop

                    if ($tlsResult.Fixed) {
                        Write-Host " FIXED (reboot needed)" -ForegroundColor Green
                        $fixedCount++
                        $rebootNeeded = $true
                    } else {
                        Write-Host " FAILED: $($tlsResult.Error)" -ForegroundColor Red
                    }
                }

                "RequiredServices" {
                    $svcResult = Invoke-Command -Session $session -ScriptBlock {
                        $fixed = @()
                        foreach ($svcName in @("WinRM", "W32Time")) {
                            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                            if ($svc) {
                                Set-Service -Name $svcName -StartupType Automatic -ErrorAction SilentlyContinue
                                if ($svc.Status -ne "Running") {
                                    Start-Service -Name $svcName -ErrorAction SilentlyContinue
                                }
                                $fixed += $svcName
                            }
                        }
                        return @{ Fixed = ($fixed.Count -gt 0); Services = $fixed }
                    } -ErrorAction Stop

                    if ($svcResult.Fixed) {
                        Write-Host " FIXED ($($svcResult.Services -join ', '))" -ForegroundColor Green
                        $fixedCount++
                    } else {
                        Write-Host " FAILED" -ForegroundColor Red
                    }
                }

                "DiskSpace" {
                    $diskResult = Invoke-Command -Session $session -ScriptBlock {
                        try {
                            # Clean temp files
                            $cleaned = 0
                            $tempPaths = @($env:TEMP, "$env:SystemRoot\Temp", "$env:SystemRoot\SoftwareDistribution\Download")
                            foreach ($p in $tempPaths) {
                                if (Test-Path $p) {
                                    $items = Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue
                                    $sizeMB = ($items | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum / 1MB
                                    Remove-Item "$p\*" -Recurse -Force -ErrorAction SilentlyContinue
                                    $cleaned += $sizeMB
                                }
                            }
                            $freeGB = [Math]::Round((Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB, 2)
                            return @{ Fixed = ($freeGB -ge 2); FreedMB = [Math]::Round($cleaned, 1); FreeGB = $freeGB }
                        }
                        catch { return @{ Fixed = $false; Error = $_.Exception.Message } }
                    } -ErrorAction Stop

                    if ($diskResult.Fixed) {
                        Write-Host " FIXED (freed $($diskResult.FreedMB) MB, now $($diskResult.FreeGB) GB free)" -ForegroundColor Green
                        $fixedCount++
                    } else {
                        Write-Host " Cleaned $($diskResult.FreedMB) MB but still under 2 GB ($($diskResult.FreeGB) GB)" -ForegroundColor Yellow
                    }
                }

                default {
                    Write-Host " Skipped (manual fix required)" -ForegroundColor Yellow
                }
            }
        }
    }
    catch {
        Write-Host ""
        Write-Host "    ✖ Auto-fix session failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    }

    Write-Host ""
    Write-Host "    Auto-fix complete: $fixedCount/$($fixable.Count) issues resolved." -ForegroundColor $(if ($fixedCount -eq $fixable.Count) { 'Green' } else { 'Yellow' })

    if ($rebootNeeded) {
        Write-Host ""
        Write-Host "    ⚠ REBOOT REQUIRED on $ComputerName for TLS/registry changes to take effect." -ForegroundColor Red
        Write-Host "    ⚠ WARNING: This will immediately restart the remote server!" -ForegroundColor Red
        $rebootNow = Read-Host "    Reboot $ComputerName now? (Y/N)"
        if (($rebootNow -eq 'Y' -or $rebootNow -eq 'y') -and $PSCmdlet.ShouldProcess($ComputerName, "Restart remote server")) {
            Write-ArcLog "REBOOT initiated on $ComputerName by $($env:USERNAME)" -Level "WARN"
            try {
                Restart-Computer -ComputerName $ComputerName -Credential $Credential -Force -ErrorAction Stop
                Write-Host "    ✓ Reboot initiated. Wait 2-3 minutes then re-run prereq check." -ForegroundColor Green
            }
            catch {
                Write-Host "    ✖ Reboot failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "    Manually reboot: Restart-Computer -ComputerName $ComputerName -Force" -ForegroundColor DarkGray
            }
        }
    }

    return ($fixedCount -gt 0)
}

Write-Host "  PreReq validation module loaded." -ForegroundColor Green
