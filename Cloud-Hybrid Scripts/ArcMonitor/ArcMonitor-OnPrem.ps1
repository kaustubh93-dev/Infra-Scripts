<#
.SYNOPSIS
    On-Premises Servers — Arc Onboarding Monitor
.DESCRIPTION
    Monitors Azure Arc Connected Machine Agent deployment on general on-premises servers
    (physical or virtual, Windows or Linux) via PowerShell Remoting (WinRM) or SSH.
.NOTES
    Prerequisites:
      - WinRM enabled on Windows targets (Enable-PSRemoting)
      - SSH enabled on Linux targets
      - Azure Service Principal for Arc registration
      - Network: Targets must reach Azure Arc endpoints
.EXAMPLE
    .\ArcMonitor-OnPrem.ps1
    .\ArcMonitor-OnPrem.ps1 -ServerList "srv01","srv02" -PollInterval 30
#>

[CmdletBinding()]
param(
    [string[]]$ServerList,
    [PSCredential]$WinCredential,
    [string]$SSHUser,
    [string]$SSHKeyPath,
    [int]$PollInterval = 60,
    [int]$MaxPolls = 120
)

# ─── Load Dependencies ─────────────────────────────────────────────────────────
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$scriptRoot\ArcMonitor-TUI.ps1"
. "$scriptRoot\ArcMonitor-Config.ps1"

# Override config
if ($WinCredential) { $OnPremConfig.WinRMCredential = $WinCredential }
if ($SSHUser)       { $OnPremConfig.SSHUser = $SSHUser }
if ($SSHKeyPath)    { $OnPremConfig.SSHKeyPath = $SSHKeyPath }

# ─── Deploy Arc Agent — Windows ──────────────────────────────────────────────────

function Deploy-ArcAgent-Windows {
    param(
        [string]$ServerName,
        [PSCredential]$Credential
    )

    Write-ArcLog "Deploying Arc agent to Windows server: $ServerName"

    try {
        $job = Invoke-Command -ComputerName $ServerName -Credential $Credential -AsJob -ScriptBlock {
            param($Sub, $Tenant, $RG, $Location, $Cloud, $SPId, $SPSecret)

            $ProgressPreference = 'SilentlyContinue'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            # Create working directory
            $workDir = "C:\ArcAgent"
            if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir -Force | Out-Null }

            # Download agent installer
            $installerPath = "$workDir\AzureConnectedMachineAgent.msi"
            if (-not (Test-Path $installerPath)) {
                Invoke-WebRequest -Uri "https://aka.ms/AzureConnectedMachineAgent" `
                                  -OutFile $installerPath
            }

            # Install agent
            $installLog = "$workDir\install.log"
            Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn /l*v `"$installLog`"" -Wait -NoNewWindow

            # Connect to Azure Arc
            & "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" connect `
                --resource-group $RG `
                --tenant-id $Tenant `
                --location $Location `
                --subscription-id $Sub `
                --service-principal-id $SPId `
                --service-principal-secret $SPSecret `
                --cloud $Cloud

        } -ArgumentList $ArcConfig.SubscriptionId, $ArcConfig.TenantId, $ArcConfig.ResourceGroup, `
                        $ArcConfig.Location, $ArcConfig.Cloud, `
                        $ArcConfig.ServicePrincipal.AppId, $ArcConfig.ServicePrincipal.Secret

        return $job
    }
    catch {
        Write-ArcLog "Failed to start deployment on $ServerName : $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# ─── Deploy Arc Agent — Linux ────────────────────────────────────────────────────

function Deploy-ArcAgent-Linux {
    param(
        [string]$ServerName,
        [string]$SSHUser,
        [string]$SSHKeyPath
    )

    Write-ArcLog "Deploying Arc agent to Linux server: $ServerName"

    try {
        $sshCmd = @"
wget https://aka.ms/azcmagent -O ~/install_linux_azcmagent.sh 2>/dev/null && \
bash ~/install_linux_azcmagent.sh && \
sudo azcmagent connect \
    --resource-group '$($ArcConfig.ResourceGroup)' \
    --tenant-id '$($ArcConfig.TenantId)' \
    --location '$($ArcConfig.Location)' \
    --subscription-id '$($ArcConfig.SubscriptionId)' \
    --service-principal-id '$($ArcConfig.ServicePrincipal.AppId)' \
    --service-principal-secret '$($ArcConfig.ServicePrincipal.Secret)' \
    --cloud '$($ArcConfig.Cloud)'
"@

        $keyArg = if ($SSHKeyPath) { "-i `"$SSHKeyPath`"" } else { "" }

        # Run via SSH (PowerShell 7+ native SSH or ssh.exe)
        $job = Start-Job -ScriptBlock {
            param($host_, $user, $key, $cmd)
            $sshArgs = @("-o", "StrictHostKeyChecking=no")
            if ($key) { $sshArgs += @("-i", $key) }
            $sshArgs += @("$user@$host_", $cmd)
            & ssh @sshArgs 2>&1
        } -ArgumentList $ServerName, $SSHUser, $SSHKeyPath, $sshCmd

        return $job
    }
    catch {
        Write-ArcLog "Failed to start deployment on $ServerName : $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# ─── Poll Server Arc Status ─────────────────────────────────────────────────────

function Get-ServerArcStatus {
    param(
        [hashtable]$Server
    )

    $name = $Server.Name ?? $Server.IP
    $os   = $Server.OS   ?? "Windows"
    $proto = $Server.Protocol ?? "WinRM"

    $status = @{
        Name       = $name
        Download   = "────"
        Install    = "────"
        ArcReg     = "────"
        Agent      = "────"
        OS         = $os
        DownloadPct = 0
        DownloadMB  = 0
        DownloadStatus = "Pending"
        Events     = @()
    }

    try {
        if ($proto -eq "WinRM") {
            $result = Invoke-Command -ComputerName $name -Credential $OnPremConfig.WinRMCredential -ScriptBlock {
                $info = @{ AgentInstalled = $false; Status = "NotInstalled" }

                $agentPath = "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe"
                if (Test-Path $agentPath) {
                    $info.AgentInstalled = $true
                    try {
                        $json = & $agentPath show --json 2>$null | ConvertFrom-Json
                        $info.Status = $json.status
                        $info.ResourceName = $json.resourceName
                        $info.LastHeartbeat = $json.lastHeartbeat
                    }
                    catch { $info.Status = "Error" }
                }

                # Check for installer in progress
                $msiRunning = Get-Process msiexec -ErrorAction SilentlyContinue
                $info.Installing = ($null -ne $msiRunning)

                # Check download file
                $msiPath = "C:\ArcAgent\AzureConnectedMachineAgent.msi"
                if (Test-Path $msiPath) {
                    $info.DownloadMB = [Math]::Round((Get-Item $msiPath).Length / 1MB, 2)
                    $info.Downloaded = $true
                }

                return $info
            } -ErrorAction Stop

            if ($result.AgentInstalled) {
                $status.Download = "Succeeded"
                $status.Install  = "Succeeded"

                switch ($result.Status) {
                    "Connected"    { $status.ArcReg = "Succeeded"; $status.Agent = "Connected" }
                    "Disconnected" { $status.ArcReg = "Failed"; $status.Agent = "Disconnected"
                                     $status.Events += @{ Node = $name; Message = "Agent disconnected"; Severity = "Error" } }
                    "Error"        { $status.ArcReg = "Failed"; $status.Agent = "Error" }
                    default        { $status.ArcReg = "InProgress"; $status.Agent = $result.Status }
                }
                $status.DownloadPct = 100
                $status.DownloadStatus = "Complete"
            }
            elseif ($result.Installing) {
                $status.Download = "Succeeded"
                $status.Install  = "InProgress"
                $status.DownloadPct = 100
                $status.DownloadStatus = "Complete"
            }
            elseif ($result.Downloaded) {
                $status.Download = "Succeeded"
                $status.Install  = "Pending"
                $status.DownloadPct = 100
                $status.DownloadMB  = $result.DownloadMB
                $status.DownloadStatus = "Complete"
            }
        }
        elseif ($proto -eq "SSH") {
            $keyArg = if ($OnPremConfig.SSHKeyPath) { "-i `"$($OnPremConfig.SSHKeyPath)`"" } else { "" }
            $sshTarget = "$($OnPremConfig.SSHUser)@$name"

            $output = & ssh -o StrictHostKeyChecking=no $keyArg $sshTarget "azcmagent show --json 2>/dev/null || echo '{\"status\":\"NotInstalled\"}'" 2>$null
            $agentInfo = $output | ConvertFrom-Json -ErrorAction SilentlyContinue

            if ($agentInfo -and $agentInfo.status -ne "NotInstalled") {
                $status.Download = "Succeeded"
                $status.Install  = "Succeeded"
                $status.DownloadPct = 100
                $status.DownloadStatus = "Complete"

                switch ($agentInfo.status) {
                    "Connected"    { $status.ArcReg = "Succeeded"; $status.Agent = "Connected" }
                    "Disconnected" { $status.ArcReg = "Failed"; $status.Agent = "Disconnected" }
                    default        { $status.ArcReg = "InProgress"; $status.Agent = $agentInfo.status }
                }
            }
        }
    }
    catch {
        $status.Events += @{ Node = $name; Message = "Poll error: $($_.Exception.Message)"; Severity = "Warning" }
        Write-ArcLog "Failed to poll $name : $($_.Exception.Message)" -Level "WARN"
    }

    return $status
}

# ─── Main On-Prem Monitor Loop ──────────────────────────────────────────────────

function Start-OnPremMonitor {

    $servers = if ($ServerList) {
        $ServerList | ForEach-Object { @{ Name = $_; OS = "Windows"; Protocol = "WinRM" } }
    } else {
        $OnPremConfig.Servers
    }

    if ($servers.Count -eq 0) {
        Write-Host "  No servers configured. Edit ArcMonitor-Config.ps1." -ForegroundColor Red
        return
    }

    # Prompt for credentials
    $hasWindows = $servers | Where-Object { $_.OS -eq "Windows" }
    if ($hasWindows -and -not $OnPremConfig.WinRMCredential) {
        Write-Host "`n  Enter Windows admin credentials:" -ForegroundColor Cyan
        $OnPremConfig.WinRMCredential = Get-Credential -Message "Windows Server Admin"
    }

    $columns = @(
        @{ Header = "Server";    Key = "Name";     Width = 20 }
        @{ Header = "OS";        Key = "OS";       Width = 10 }
        @{ Header = "Download";  Key = "Download";  Width = 12 }
        @{ Header = "Install";   Key = "Install";   Width = 12 }
        @{ Header = "Arc Reg";   Key = "ArcReg";    Width = 12 }
        @{ Header = "Agent";     Key = "Agent";     Width = 14 }
    )

    $startTime = Get-Date
    $pollCount = 0

    Write-ArcLog "On-Prem monitor started for $($servers.Count) servers"

    while ($pollCount -lt $MaxPolls) {
        $pollCount++
        $elapsed = (Get-Date) - $startTime
        $allNodeStatus = @()
        $allDownloads  = @()
        $allEvents     = @()
        $runCount = 0; $doneCount = 0; $failCount = 0

        foreach ($srv in $servers) {
            $srvStatus = Get-ServerArcStatus -Server $srv
            $allNodeStatus += $srvStatus
            $allEvents     += $srvStatus.Events

            $shortName = $srv.Name.Substring(0, [Math]::Min(8, $srv.Name.Length))
            $allDownloads += @{
                Node    = $shortName
                Percent = $srvStatus.DownloadPct
                SizeMB  = $srvStatus.DownloadMB
                Status  = $srvStatus.DownloadStatus
            }

            if ($srvStatus.Agent -eq "Connected") { $doneCount++ }
            elseif ($srvStatus.Agent -in @("Failed","Disconnected","Error")) { $failCount++ }
            else { $runCount++ }
        }

        $dashState = @{
            Title        = "ARC ONBOARDING MONITOR"
            Subtitle     = "On-Premises Servers — Azure Connected Machine Agent"
            Mode         = "OnPrem"
            NodeCount    = $servers.Count
            Elapsed      = $elapsed
            CurrentPoll  = $pollCount
            MaxPoll      = $MaxPolls
            Nodes        = $allNodeStatus
            Columns      = $columns
            Downloads    = $allDownloads
            Events       = $allEvents
            Running      = $runCount
            Succeeded    = $doneCount
            Failed       = $failCount
            NextRefreshSeconds = $PollInterval
        }

        Render-ArcDashboard -State $dashState

        if (($doneCount + $failCount) -eq $servers.Count) {
            Write-Host "`n  ✓ All servers processed. $doneCount connected, $failCount failed." -ForegroundColor $(if ($failCount -eq 0) {'Green'} else {'Yellow'})
            break
        }

        Start-Sleep -Seconds $PollInterval
    }

    Write-ArcLog "On-Prem monitor completed — $doneCount connected, $failCount failed"
}

# ─── Guide ──────────────────────────────────────────────────────────────────────

function Show-OnPremGuide {
    Clear-Host
    Write-Host @"

  ╔══════════════════════════════════════════════════════════════════════════╗
  ║        ON-PREMISES SERVERS — ARC ONBOARDING GUIDE                      ║
  ╚══════════════════════════════════════════════════════════════════════════╝

  PREREQUISITES:
  ──────────────────────────────────────────────────────────────────────────
  1. Windows: PowerShell Remoting (WinRM) enabled — Run: Enable-PSRemoting -Force
  2. Linux:   SSH access with key-based auth (recommended)
  3. Azure Service Principal with Contributor role on target resource group
  4. Network: Servers must reach Azure Arc endpoints:
     • *.his.arc.azure.com            (Hybrid Identity Service)
     • *.guestconfiguration.azure.com (Guest Configuration)
     • login.microsoftonline.com      (Azure AD / Entra ID)
     • management.azure.com           (Azure Resource Manager)

  SUPPORTED SERVER TYPES:
  ──────────────────────────────────────────────────────────────────────────
  • Windows Server 2012 R2+  (via WinRM / PowerShell Remoting)
  • Ubuntu 18.04+, RHEL 7+, SLES 15+, Debian 10+  (via SSH)
  • Physical servers, Hyper-V VMs, KVM VMs, or any non-VMware VMs

  PROCESS FLOW:
  ──────────────────────────────────────────────────────────────────────────
  Step 1 ─► Download Azure Connected Machine agent (.msi / .sh)
  Step 2 ─► Install the agent silently
  Step 3 ─► Run 'azcmagent connect' with Service Principal credentials
  Step 4 ─► Monitor status → Connected = success
  Step 5 ─► Verify in Azure Portal → Azure Arc → Servers

  QUICK START:
  ──────────────────────────────────────────────────────────────────────────
  # Edit ArcMonitor-Config.ps1 with server list + Azure details, then:

  .\ArcMonitor-OnPrem.ps1                                # Interactive
  .\ArcMonitor-OnPrem.ps1 -ServerList "srv01","srv02"    # Specific servers

"@ -ForegroundColor Cyan

    Write-Host "  Press any key to start monitoring, or Ctrl+C to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ─── Entry Point ────────────────────────────────────────────────────────────────
Show-OnPremGuide
Start-OnPremMonitor
