<#
.SYNOPSIS
    VMware vSphere VMs — Arc Onboarding Monitor
.DESCRIPTION
    Monitors Azure Arc Connected Machine Agent deployment on VMware vSphere VMs.
    Uses PowerCLI for VM discovery and guest operations, then monitors azcmagent status.
.NOTES
    Prerequisites:
      - VMware.PowerCLI module
      - Az.ConnectedMachine module
      - vCenter credentials with guest operations permissions
      - Guest OS credentials (admin/root)
      - Service Principal for Arc registration
.EXAMPLE
    .\ArcMonitor-VMware.ps1
    .\ArcMonitor-VMware.ps1 -vCenterServer "vcenter.local" -PollInterval 30
#>

[CmdletBinding()]
param(
    [string]$vCenterServer,
    [PSCredential]$vCenterCredential,
    [PSCredential]$GuestCredential,
    [string]$VMFolder,
    [string]$VMTag,
    [string[]]$VMNames,
    [int]$PollInterval = 60,
    [int]$MaxPolls = 120
)

# ─── Load Dependencies ─────────────────────────────────────────────────────────
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$scriptRoot\ArcMonitor-TUI.ps1"
. "$scriptRoot\ArcMonitor-Config.ps1"

# Override config with params
if ($vCenterServer)     { $VMwareConfig.vCenterServer = $vCenterServer }
if ($vCenterCredential) { $VMwareConfig.vCenterCred   = $vCenterCredential }
if ($GuestCredential)   { $VMwareConfig.GuestCred     = $GuestCredential }

# ─── VMware Connection ──────────────────────────────────────────────────────────

function Connect-VCenter {
    try {
        if (-not (Get-Module VMware.PowerCLI -ListAvailable)) {
            Write-Host "  Installing VMware.PowerCLI..." -ForegroundColor Yellow
            Install-Module VMware.PowerCLI -Force -AllowClobber -Scope CurrentUser
        }
        Import-Module VMware.PowerCLI -ErrorAction Stop
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

        if (-not $VMwareConfig.vCenterCred) {
            Write-Host "`n  Enter vCenter credentials:" -ForegroundColor Cyan
            $VMwareConfig.vCenterCred = Get-Credential -Message "vCenter Admin"
        }

        Connect-VIServer -Server $VMwareConfig.vCenterServer `
                         -Credential $VMwareConfig.vCenterCred `
                         -ErrorAction Stop | Out-Null

        Write-Host "  ✓ Connected to vCenter: $($VMwareConfig.vCenterServer)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  ✖ Failed to connect to vCenter: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ─── Discover Target VMs ────────────────────────────────────────────────────────

function Get-TargetVMs {
    <#
    .SYNOPSIS
        Discovers VMs to onboard from vCenter based on filters.
    #>
    $vms = @()

    if ($VMNames) {
        # Explicit VM list
        foreach ($name in $VMNames) {
            $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
            if ($vm) { $vms += $vm }
        }
    }
    elseif ($VMFolder) {
        $vms = Get-VM -Location (Get-Folder $VMFolder) -ErrorAction SilentlyContinue
    }
    elseif ($VMTag) {
        $vms = Get-VM -Tag $VMTag -ErrorAction SilentlyContinue
    }
    elseif ($VMwareConfig.TargetVMs.Count -gt 0) {
        foreach ($t in $VMwareConfig.TargetVMs) {
            $vm = Get-VM -Name $t.Name -ErrorAction SilentlyContinue
            if ($vm) { $vms += $vm }
        }
    }
    else {
        Write-Host "  No VM filter specified. Discovering all powered-on VMs..." -ForegroundColor Yellow
        $vms = Get-VM | Where-Object { $_.PowerState -eq 'PoweredOn' -and $_.ExtensionData.Guest.ToolsRunningStatus -eq 'guestToolsRunning' }
    }

    Write-Host "  Found $($vms.Count) target VMs for Arc onboarding" -ForegroundColor Cyan
    return $vms
}

# ─── Deploy Arc Agent to VM ─────────────────────────────────────────────────────

function Deploy-ArcAgentToVM {
    <#
    .SYNOPSIS
        Deploys the Azure Connected Machine agent to a VMware VM via guest operations.
    #>
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [PSCredential]$GuestCred
    )

    $vmName = $VM.Name
    $guestOS = $VM.ExtensionData.Guest.GuestFamily  # windowsGuest | linuxGuest

    Write-ArcLog "Deploying Arc agent to $vmName (OS: $guestOS)"

    try {
        if ($guestOS -match "windows") {
            # Windows: Download and install via PowerShell
            $script = @"
`$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri 'https://aka.ms/azcmagent-windows' -OutFile C:\ArcAgent\Install-AzCMAgent.ps1
& C:\ArcAgent\Install-AzCMAgent.ps1
azcmagent connect ``
    --resource-group '$($ArcConfig.ResourceGroup)' ``
    --tenant-id '$($ArcConfig.TenantId)' ``
    --location '$($ArcConfig.Location)' ``
    --subscription-id '$($ArcConfig.SubscriptionId)' ``
    --service-principal-id '$($ArcConfig.ServicePrincipal.AppId)' ``
    --service-principal-secret '$($ArcConfig.ServicePrincipal.Secret)' ``
    --cloud '$($ArcConfig.Cloud)'
"@
            Invoke-VMScript -VM $VM -ScriptText $script -GuestCredential $GuestCred `
                           -ScriptType PowerShell -ErrorAction Stop
        }
        else {
            # Linux: Download and install via bash
            $script = @"
export DEBIAN_FRONTEND=noninteractive
wget https://aka.ms/azcmagent -O ~/install_linux_azcmagent.sh 2>/dev/null
bash ~/install_linux_azcmagent.sh
azcmagent connect \
    --resource-group '$($ArcConfig.ResourceGroup)' \
    --tenant-id '$($ArcConfig.TenantId)' \
    --location '$($ArcConfig.Location)' \
    --subscription-id '$($ArcConfig.SubscriptionId)' \
    --service-principal-id '$($ArcConfig.ServicePrincipal.AppId)' \
    --service-principal-secret '$($ArcConfig.ServicePrincipal.Secret)' \
    --cloud '$($ArcConfig.Cloud)'
"@
            Invoke-VMScript -VM $VM -ScriptText $script -GuestCredential $GuestCred `
                           -ScriptType Bash -ErrorAction Stop
        }

        Write-ArcLog "Arc agent deployment initiated on $vmName"
        return $true
    }
    catch {
        Write-ArcLog "Failed to deploy Arc agent to $vmName : $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# ─── Poll VM Arc Status ─────────────────────────────────────────────────────────

function Get-VMArcStatus {
    <#
    .SYNOPSIS
        Checks the Arc agent status on a VMware VM via guest script execution.
    #>
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [PSCredential]$GuestCred
    )

    $vmName = $VM.Name
    $guestOS = $VM.ExtensionData.Guest.GuestFamily

    $status = @{
        Name       = $vmName
        Download   = "────"
        Install    = "────"
        ArcReg     = "────"
        Agent      = "────"
        DownloadPct = 0
        DownloadMB  = 0
        DownloadStatus = "Pending"
        Events     = @()
    }

    try {
        $checkScript = if ($guestOS -match "windows") {
            'if (Get-Command azcmagent -ErrorAction SilentlyContinue) { azcmagent show --json } else { Write-Output "{\"status\":\"NotInstalled\"}" }'
        } else {
            'if command -v azcmagent &>/dev/null; then azcmagent show --json; else echo "{\"status\":\"NotInstalled\"}"; fi'
        }

        $scriptType = if ($guestOS -match "windows") { "PowerShell" } else { "Bash" }

        $result = Invoke-VMScript -VM $VM -ScriptText $checkScript -GuestCredential $GuestCred `
                                 -ScriptType $scriptType -ErrorAction Stop

        $agentInfo = $result.ScriptOutput | ConvertFrom-Json -ErrorAction SilentlyContinue

        if ($agentInfo) {
            $agentStatus = $agentInfo.status ?? "NotInstalled"

            switch ($agentStatus) {
                "Connected" {
                    $status.Download = "Succeeded"
                    $status.Install  = "Succeeded"
                    $status.ArcReg   = "Succeeded"
                    $status.Agent    = "Connected"
                    $status.DownloadPct = 100
                    $status.DownloadStatus = "Complete"
                }
                "Disconnected" {
                    $status.Download = "Succeeded"
                    $status.Install  = "Succeeded"
                    $status.ArcReg   = "Failed"
                    $status.Agent    = "Disconnected"
                    $status.DownloadPct = 100
                    $status.DownloadStatus = "Complete"
                    $status.Events += @{ Node = $vmName; Message = "Agent disconnected — check network"; Severity = "Error" }
                }
                "NotInstalled" {
                    $status.Download = "Pending"
                    $status.Install  = "Pending"
                    $status.ArcReg   = "Pending"
                    $status.Agent    = "────"
                }
                default {
                    $status.Download = "InProgress"
                    $status.Install  = "InProgress"
                    $status.Agent    = $agentStatus
                }
            }
        }
    }
    catch {
        $status.Events += @{ Node = $vmName; Message = "Poll failed: $($_.Exception.Message)"; Severity = "Warning" }
        Write-ArcLog "Failed to poll $vmName : $($_.Exception.Message)" -Level "WARN"
    }

    return $status
}

# ─── Main VMware Monitor Loop ───────────────────────────────────────────────────

function Start-VMwareMonitor {

    # Connect to vCenter
    if (-not (Connect-VCenter)) { return }

    # Discover VMs
    $targetVMs = Get-TargetVMs
    if ($targetVMs.Count -eq 0) {
        Write-Host "  No target VMs found. Check your filters." -ForegroundColor Red
        return
    }

    # Guest credentials
    if (-not $VMwareConfig.GuestCred) {
        Write-Host "`n  Enter Guest OS credentials:" -ForegroundColor Cyan
        $VMwareConfig.GuestCred = Get-Credential -Message "VM Guest Admin"
    }

    $columns = @(
        @{ Header = "VM Name";   Key = "Name";     Width = 20 }
        @{ Header = "Download";  Key = "Download";  Width = 12 }
        @{ Header = "Install";   Key = "Install";   Width = 12 }
        @{ Header = "Arc Reg";   Key = "ArcReg";    Width = 12 }
        @{ Header = "Agent";     Key = "Agent";     Width = 14 }
    )

    $startTime = Get-Date
    $pollCount = 0

    Write-ArcLog "VMware monitor started for $($targetVMs.Count) VMs"

    while ($pollCount -lt $MaxPolls) {
        $pollCount++
        $elapsed = (Get-Date) - $startTime
        $allNodeStatus = @()
        $allDownloads  = @()
        $allEvents     = @()
        $runCount = 0; $doneCount = 0; $failCount = 0

        foreach ($vm in $targetVMs) {
            $vmStatus = Get-VMArcStatus -VM $vm -GuestCred $VMwareConfig.GuestCred
            $allNodeStatus += $vmStatus
            $allEvents     += $vmStatus.Events

            $allDownloads += @{
                Node    = $vm.Name.Substring(0, [Math]::Min(8, $vm.Name.Length))
                Percent = $vmStatus.DownloadPct
                SizeMB  = $vmStatus.DownloadMB
                Status  = $vmStatus.DownloadStatus
            }

            if ($vmStatus.Agent -eq "Connected") { $doneCount++ }
            elseif ($vmStatus.Agent -in @("Failed","Disconnected")) { $failCount++ }
            else { $runCount++ }
        }

        $dashState = @{
            Title        = "ARC ONBOARDING MONITOR"
            Subtitle     = "VMware vSphere VMs — Arc Connected Machine Agent"
            Mode         = "VMware"
            NodeCount    = $targetVMs.Count
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

        if (($doneCount + $failCount) -eq $targetVMs.Count) {
            Write-Host "`n  ✓ All VMs processed. $doneCount connected, $failCount failed." -ForegroundColor $(if ($failCount -eq 0) {'Green'} else {'Yellow'})
            break
        }

        Start-Sleep -Seconds $PollInterval
    }

    Disconnect-VIServer -Confirm:$false -ErrorAction SilentlyContinue
    Write-ArcLog "VMware monitor completed — $doneCount connected, $failCount failed"
}

# ─── Guide ──────────────────────────────────────────────────────────────────────

function Show-VMwareGuide {
    Clear-Host
    Write-Host @"

  ╔══════════════════════════════════════════════════════════════════════════╗
  ║           VMWARE vSPHERE — ARC ONBOARDING GUIDE                        ║
  ╚══════════════════════════════════════════════════════════════════════════╝

  PREREQUISITES:
  ──────────────────────────────────────────────────────────────────────────
  1. VMware.PowerCLI module (auto-installed if missing)
  2. vCenter Server credentials with guest operations permissions
  3. VMware Tools running on target VMs
  4. Guest OS admin credentials
  5. Azure Service Principal for Arc registration (Contributor role)
  6. Network: VMs must reach *.guestconfiguration.azure.com, login.microsoftonline.com

  PROCESS FLOW:
  ──────────────────────────────────────────────────────────────────────────
  Step 1 ─► Connect to vCenter via PowerCLI
  Step 2 ─► Discover target VMs (by folder, tag, or explicit list)
  Step 3 ─► For each VM via Invoke-VMScript:
            a. Download Azure Connected Machine agent
            b. Install the agent
            c. Run 'azcmagent connect' with Service Principal
  Step 4 ─► Monitor agent status (Connected / Disconnected / Error)
  Step 5 ─► Verify in Azure Portal → Azure Arc → Servers

  QUICK START:
  ──────────────────────────────────────────────────────────────────────────
  # Edit ArcMonitor-Config.ps1 with vCenter + Azure details, then:

  .\ArcMonitor-VMware.ps1                                # Interactive
  .\ArcMonitor-VMware.ps1 -VMNames "vm01","vm02"         # Specific VMs
  .\ArcMonitor-VMware.ps1 -VMFolder "Production VMs"     # By folder
  .\ArcMonitor-VMware.ps1 -VMTag "arc-onboard"           # By tag

"@ -ForegroundColor Cyan

    Write-Host "  Press any key to start monitoring, or Ctrl+C to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ─── Entry Point ────────────────────────────────────────────────────────────────
Show-VMwareGuide
Start-VMwareMonitor
