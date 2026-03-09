<#
.SYNOPSIS
    Azure Local (Azure Stack HCI) — Arc Bootstrap Monitor
.DESCRIPTION
    Monitors the Arc bootstrap and initialization process for Azure Local cluster nodes.
    Tracks: Bootstrap → Update → Arc Registration → Extension Install → Agent Status
.NOTES
    Prerequisites:
      - AzsHCI.ARCInstaller module
      - Az.Accounts, Az.ConnectedMachine, Az.Resources modules
      - Admin access to Azure Local nodes (WinRM/PowerShell Remoting)
      - Azure credentials with Contributor + User Access Administrator roles
.EXAMPLE
    # Interactive — prompts for credentials
    .\ArcMonitor-AzureLocal.ps1

    # Automated — pass parameters
    .\ArcMonitor-AzureLocal.ps1 -Nodes @("hci-01","hci-02") -SubscriptionId "xxx" -TenantId "xxx"
#>

[CmdletBinding()]
param(
    [string[]]$Nodes,
    [string]$SubscriptionId,
    [string]$TenantId,
    [string]$ResourceGroup,
    [string]$Location = "eastus",
    [PSCredential]$Credential,
    [int]$PollInterval = 60,
    [int]$MaxPolls = 120
)

# ─── Load Dependencies ─────────────────────────────────────────────────────────
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$scriptRoot\ArcMonitor-TUI.ps1"
. "$scriptRoot\ArcMonitor-Config.ps1"

# Override config with params if provided
if ($Nodes)          { $AzureLocalConfig.Nodes = $Nodes | ForEach-Object { @{ Name = $_; IP = $_ } } }
if ($SubscriptionId) { $ArcConfig.SubscriptionId = $SubscriptionId }
if ($TenantId)       { $ArcConfig.TenantId = $TenantId }
if ($ResourceGroup)  { $ArcConfig.ResourceGroup = $ResourceGroup }
if ($Location)       { $ArcConfig.Location = $Location }
if ($Credential)     { $AzureLocalConfig.Credential = $Credential }

# ─── Prompt for credentials if not provided ─────────────────────────────────────
if (-not $AzureLocalConfig.Credential) {
    Write-Host "`n  Enter credentials for Azure Local nodes:" -ForegroundColor Cyan
    $AzureLocalConfig.Credential = Get-Credential -Message "Azure Local Node Admin"
}

# ─── Bootstrap Status Polling Function ──────────────────────────────────────────

function Get-AzureLocalBootstrapStatus {
    <#
    .SYNOPSIS
        Polls bootstrap status from an Azure Local node via CIM/PowerShell Remoting.
    .DESCRIPTION
        Retrieves the current bootstrap, update, and Arc configuration status by
        invoking Get-AzStackHciBootstrapStatus (or equivalent WMI queries) on the node.
    #>
    param(
        [string]$NodeName,
        [PSCredential]$Credential
    )

    $status = @{
        Name       = $NodeName
        Bootstrap  = "────"
        Update     = "────"
        ArcReg     = "────"
        Agent      = "────"
        DownloadPct = 0
        DownloadMB  = 0
        DownloadStatus = "Pending"
        Events     = @()
    }

    try {
        $session = New-PSSession -ComputerName $NodeName -Credential $Credential -ErrorAction Stop

        # Get bootstrap state (Azure Local specific)
        $bootstrapState = Invoke-Command -Session $session -ScriptBlock {
            try {
                # Primary: use AzsHCI module if available
                if (Get-Command Get-AzStackHciArcIntegration -ErrorAction SilentlyContinue) {
                    $arcInfo = Get-AzStackHciArcIntegration
                    return @{
                        Bootstrap = $arcInfo.BootstrapStatus       # NotStarted|InProgress|Succeeded|Failed
                        Update    = $arcInfo.UpdateStatus           # NotApplicable|RebootPending|Install|Succeeded
                        ArcReg    = $arcInfo.ArcRegistrationStatus  # NotStarted|InProgress|Succeeded|Failed
                        Agent     = $arcInfo.ArcAgentStatus         # NotInstalled|Connected|Disconnected
                    }
                }

                # Fallback: check azcmagent status + bootstrap markers
                $agentStatus = "────"
                if (Get-Command azcmagent -ErrorAction SilentlyContinue) {
                    $agentJson = azcmagent show --json 2>$null | ConvertFrom-Json
                    $agentStatus = $agentJson.status  # Connected | Disconnected | etc
                }

                # Check update status via Windows Update or WUSA
                $pendingReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"

                # Check bootstrap progress via registry/log markers
                $bootstrapKey = "HKLM:\SOFTWARE\Microsoft\AzureStack\HCI\Bootstrap"
                $bsState = if (Test-Path $bootstrapKey) {
                    (Get-ItemProperty $bootstrapKey -ErrorAction SilentlyContinue).Status
                } else { "NotStarted" }

                return @{
                    Bootstrap = ($bsState ?? "NotStarted")
                    Update    = if ($pendingReboot) { "RebootPending" } else { "NotApplicable" }
                    ArcReg    = "NotStarted"
                    Agent     = $agentStatus
                }
            }
            catch {
                return @{
                    Bootstrap = "Error"
                    Update    = "Error"
                    ArcReg    = "Error"
                    Agent     = "Error"
                    Error     = $_.Exception.Message
                }
            }
        } -ErrorAction Stop

        $status.Bootstrap = $bootstrapState.Bootstrap ?? "────"
        $status.Update    = $bootstrapState.Update    ?? "────"
        $status.ArcReg    = $bootstrapState.ArcReg    ?? "────"
        $status.Agent     = $bootstrapState.Agent     ?? "────"

        # Get download/install progress
        $dlProgress = Invoke-Command -Session $session -ScriptBlock {
            try {
                # Check Windows Update download progress
                $updateSession = New-Object -ComObject Microsoft.Update.Session
                $searcher = $updateSession.CreateUpdateSearcher()
                $results = $searcher.Search("IsInstalled=0")
                $totalSize = ($results.Updates | Measure-Object -Property MaxDownloadSize -Sum).Sum / 1MB
                $downloaded = ($results.Updates | Where-Object { $_.IsDownloaded } | 
                              Measure-Object -Property MaxDownloadSize -Sum).Sum / 1MB

                # Check for AzsHCI specific download progress
                $hciLogPath = "$env:ProgramData\AzureStackHCI\Logs"
                $latestLog = if (Test-Path $hciLogPath) {
                    Get-ChildItem $hciLogPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                }

                return @{
                    Percent = if ($totalSize -gt 0) { [Math]::Min(100, [Math]::Round($downloaded / $totalSize * 100)) } else { 0 }
                    SizeMB  = $totalSize
                    Status  = if ($downloaded -ge $totalSize -and $totalSize -gt 0) { "Complete" } else { "Downloading" }
                }
            }
            catch { return @{ Percent = 0; SizeMB = 0; Status = "Unknown" } }
        } -ErrorAction SilentlyContinue

        if ($dlProgress) {
            $status.DownloadPct    = $dlProgress.Percent
            $status.DownloadMB     = $dlProgress.SizeMB
            $status.DownloadStatus = $dlProgress.Status
        }

        # Check for events (reboot pending, errors, etc.)
        if ($bootstrapState.Update -eq "RebootPending") {
            $status.Events += @{ Node = $NodeName; Message = "REBOOT PENDING"; Severity = "Warning" }
        }
        if ($bootstrapState.Bootstrap -eq "Failed" -or $bootstrapState.ArcReg -eq "Failed") {
            $errMsg = $bootstrapState.Error ?? "Bootstrap or Arc registration failed"
            $status.Events += @{ Node = $NodeName; Message = $errMsg; Severity = "Error" }
        }

        Remove-PSSession $session -ErrorAction SilentlyContinue
    }
    catch {
        $status.Bootstrap = "Error"
        $status.Events += @{ Node = $NodeName; Message = "Connection failed: $($_.Exception.Message)"; Severity = "Error" }
        Write-ArcLog "Failed to poll $NodeName : $($_.Exception.Message)" -Level "ERROR"
    }

    return $status
}

# ─── Pre-flight: Install Required Modules on Nodes ──────────────────────────────

function Install-ArcPrerequisites {
    <#
    .SYNOPSIS
        Installs required PowerShell modules on Azure Local nodes for Arc initialization.
    #>
    param(
        [string]$NodeName,
        [PSCredential]$Credential
    )

    Write-Host "  Installing prerequisites on $NodeName..." -ForegroundColor Yellow

    try {
        Invoke-Command -ComputerName $NodeName -Credential $Credential -ScriptBlock {
            # Register PSGallery if needed
            if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
                Register-PSRepository -Default -InstallationPolicy Trusted
            }
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

            $modules = @('AzsHCI.ARCInstaller', 'Az.Accounts', 'Az.ConnectedMachine', 'Az.Resources')
            foreach ($mod in $modules) {
                if (-not (Get-Module -ListAvailable -Name $mod)) {
                    Install-Module $mod -Force -AllowClobber -Scope AllUsers
                    Write-Output "  Installed $mod"
                }
            }
        } -ErrorAction Stop
        Write-Host "  ✓ Prerequisites ready on $NodeName" -ForegroundColor Green
    }
    catch {
        Write-Host "  ✖ Failed on $NodeName : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Trigger Arc Initialization ─────────────────────────────────────────────────

function Start-ArcInitialization {
    <#
    .SYNOPSIS
        Triggers Invoke-AzStackHciArcInitialization on a node (runs as background job).
    #>
    param(
        [string]$NodeName,
        [PSCredential]$Credential,
        [string]$SubscriptionId,
        [string]$ResourceGroup,
        [string]$TenantId,
        [string]$Location,
        [string]$ArmToken,
        [string]$AccountId
    )

    Write-Host "  Starting Arc initialization on $NodeName..." -ForegroundColor Yellow

    $job = Invoke-Command -ComputerName $NodeName -Credential $Credential -AsJob -ScriptBlock {
        param($Sub, $RG, $Tenant, $Region, $Token, $AcctId)

        Import-Module AzsHCI.ARCInstaller -Force

        Invoke-AzStackHciArcInitialization `
            -SubscriptionID $Sub `
            -ResourceGroup $RG `
            -TenantID $Tenant `
            -Region $Region `
            -Cloud "AzureCloud" `
            -ArmAccessToken $Token `
            -AccountID $AcctId
    } -ArgumentList $SubscriptionId, $ResourceGroup, $TenantId, $Location, $ArmToken, $AccountId

    return $job
}

# ─── Main Monitor Loop ──────────────────────────────────────────────────────────

function Start-AzureLocalMonitor {
    <#
    .SYNOPSIS
        Main monitoring loop for Azure Local Arc bootstrap process.
    .DESCRIPTION
        Polls all configured nodes at the specified interval and renders the TUI dashboard.
    #>

    $nodeList = $AzureLocalConfig.Nodes
    if ($nodeList.Count -eq 0) {
        Write-Host "  No nodes configured. Edit ArcMonitor-Config.ps1." -ForegroundColor Red
        return
    }

    $startTime = Get-Date
    $pollCount = 0

    Write-ArcLog "Azure Local monitor started for $($nodeList.Count) nodes"

    # ─── Monitor Loop ───────────────────────────────────────────────────────────
    while ($pollCount -lt $MaxPolls) {
        $pollCount++
        $elapsed = (Get-Date) - $startTime
        $allNodeStatus = @()
        $allDownloads  = @()
        $allEvents     = @()
        $runCount      = 0
        $doneCount     = 0
        $failCount     = 0

        # Poll each node
        foreach ($node in $nodeList) {
            $nodeName = $node.Name ?? $node.IP ?? $node
            $nodeStatus = Get-AzureLocalBootstrapStatus -NodeName $nodeName -Credential $AzureLocalConfig.Credential

            $allNodeStatus += $nodeStatus
            $allEvents     += $nodeStatus.Events

            $shortName = if ($nodeName.Length -gt 5) { $nodeName.Substring($nodeName.Length - 3) } else { $nodeName }
            $allDownloads += @{
                Node    = "n$($shortName)"
                Percent = $nodeStatus.DownloadPct
                SizeMB  = $nodeStatus.DownloadMB
                Status  = $nodeStatus.DownloadStatus
            }

            # Count status
            if ($nodeStatus.Bootstrap -in @('InProgress','Install','Downloading','Registering')) { $runCount++ }
            elseif ($nodeStatus.Bootstrap -eq 'Succeeded' -and $nodeStatus.ArcReg -eq 'Succeeded') { $doneCount++ }
            elseif ($nodeStatus.Bootstrap -eq 'Failed' -or $nodeStatus.ArcReg -eq 'Failed') { $failCount++ }
            else { $runCount++ }
        }

        # Render dashboard
        $dashState = @{
            Title        = "ARC BOOTSTRAP MONITOR"
            Subtitle     = "Azure Local (Azure Stack HCI) — Arc Registration"
            Mode         = "AzureLocal"
            NodeCount    = $nodeList.Count
            Elapsed      = $elapsed
            CurrentPoll  = $pollCount
            MaxPoll      = $MaxPolls
            Nodes        = $allNodeStatus
            Downloads    = $allDownloads
            Events       = $allEvents
            Running      = $runCount
            Succeeded    = $doneCount
            Failed       = $failCount
            NextRefreshSeconds = $PollInterval
        }

        Render-ArcDashboard -State $dashState
        Write-ArcLog "Poll $pollCount : Running=$runCount Succeeded=$doneCount Failed=$failCount"

        # Exit if all done or all failed
        if (($doneCount + $failCount) -eq $nodeList.Count) {
            Write-Host "`n  ══════════════════════════════════════════════════" -ForegroundColor Cyan
            if ($failCount -eq 0) {
                Write-Host "  ✓ All nodes successfully onboarded to Azure Arc!" -ForegroundColor Green
            } else {
                Write-Host "  ▲ Completed with $failCount failure(s). Check logs." -ForegroundColor Yellow
            }
            Write-Host "  ══════════════════════════════════════════════════`n" -ForegroundColor Cyan
            break
        }

        # Wait for next poll
        Start-Sleep -Seconds $PollInterval
    }

    Write-ArcLog "Azure Local monitor completed — $doneCount succeeded, $failCount failed"
}

# ─── Step-by-Step Guide (when run without action) ───────────────────────────────

function Show-AzureLocalGuide {
    Clear-Host
    Write-Host @"

  ╔══════════════════════════════════════════════════════════════════════════╗
  ║           AZURE LOCAL — ARC BOOTSTRAP ONBOARDING GUIDE                 ║
  ╚══════════════════════════════════════════════════════════════════════════╝

  PREREQUISITES:
  ──────────────────────────────────────────────────────────────────────────
  1. Azure Local (Azure Stack HCI) nodes with OS installed
  2. PowerShell Remoting (WinRM) enabled between management station & nodes
  3. Azure subscription with Contributor + User Access Administrator roles
  4. Required PowerShell modules (auto-installed by this script):
     • AzsHCI.ARCInstaller
     • Az.Accounts, Az.ConnectedMachine, Az.Resources

  PROCESS FLOW:
  ──────────────────────────────────────────────────────────────────────────
  Step 1 ─► Install prerequisites on each node
  Step 2 ─► Authenticate to Azure (Connect-AzAccount)
  Step 3 ─► Get ARM access token for Arc initialization
  Step 4 ─► Run Invoke-AzStackHciArcInitialization on each node
  Step 5 ─► Monitor bootstrap phases:
            • NetworkConfig → RemoteConfig → WebProxy → TimeServer
            • HostName → ArcConfiguration
            • ArtifactsUpload → ConnectivityValidation
            • ArcRegistration → ArcExtensionInstall
  Step 6 ─► Nodes reboot as needed during update installation
  Step 7 ─► Verify Arc registration in Azure Portal

  QUICK START:
  ──────────────────────────────────────────────────────────────────────────
  # Edit ArcMonitor-Config.ps1 with your environment details, then:

  .\ArcMonitor-AzureLocal.ps1                           # Interactive mode
  .\ArcMonitor-AzureLocal.ps1 -Nodes "n01","n02"        # Specify nodes
  .\ArcMonitor-AzureLocal.ps1 -PollInterval 30          # Faster polling

"@ -ForegroundColor Cyan

    Write-Host "  Press any key to start monitoring, or Ctrl+C to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ─── Entry Point ────────────────────────────────────────────────────────────────

Show-AzureLocalGuide
Start-AzureLocalMonitor
