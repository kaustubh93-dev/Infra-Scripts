#Requires -Version 5.1
Set-StrictMode -Version Latest
<#
.SYNOPSIS
    Azure Arc — Unified Onboarding Script
.DESCRIPTION
    Single onboarding framework that works for ALL platforms:
    VMware, Azure Local (HCI), Hyper-V, Physical, KVM, Nutanix.
    Auto-detects platform via WMI. Excludes Azure native VMs.
    Runs from a centralized management server — targets are remote.
.NOTES
    Replaces separate AzureLocal/VMware/OnPrem onboarding scripts.
    All operations execute REMOTELY on the target machine.
#>

# ─── Load Dependencies ─────────────────────────────────────────────────────────
# When dot-sourced, $PSScriptRoot is set correctly. Store it for use inside functions.
$script:OnboardScriptRoot = $PSScriptRoot
if (-not $script:OnboardScriptRoot) {
    $script:OnboardScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if (-not $script:OnboardScriptRoot) {
    $script:OnboardScriptRoot = $PWD.Path
}

. "$($script:OnboardScriptRoot)\ArcMonitor-TUI.ps1"
. "$($script:OnboardScriptRoot)\ArcMonitor-Config.ps1"
. "$($script:OnboardScriptRoot)\ArcMonitor-PreReqCheck.ps1"

# ─── Deploy Arc Agent to Remote Target ──────────────────────────────────────────

function Install-ArcAgentRemote {
    <#
    .SYNOPSIS
        Installs the Azure Connected Machine agent on a remote Windows server.
    .DESCRIPTION
        Downloads and installs the agent via Invoke-Command on the remote target.
        Does NOT run locally — all operations are on the remote machine.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [ValidateNotNullOrEmpty()]
        [string]$AgentDownloadUrl = "https://gbl.his.arc.azure.com/azcmagent-windows",

        [string]$ProxyServer = $null
    )

    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($DownloadUrl, $Proxy)

        $status = @{ Downloaded = $false; Installed = $false; Error = $null }

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072

            $workDir = Join-Path $env:SystemRoot "AzureConnectedMachineAgent"
            if (-not (Test-Path $workDir)) {
                New-Item -Path $workDir -ItemType Directory -Force | Out-Null
            }

            $tempDir = Join-Path $workDir "temp"
            if (-not (Test-Path $tempDir)) {
                New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
            }

            $installScript = Join-Path $tempDir "install_windows_azcmagent.ps1"

            # Download agent installer
            $dlParams = @{
                Uri             = $DownloadUrl
                OutFile         = $installScript
                UseBasicParsing = $true
                TimeoutSec      = 120
            }
            if ($Proxy) { $dlParams["Proxy"] = $Proxy }

            Invoke-WebRequest @dlParams -ErrorAction Stop
            $status.Downloaded = $true

            # Verify Authenticode signature before execution
            $sig = Get-AuthenticodeSignature -FilePath $installScript -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft') {
                $status.SignatureValid = $true
            } elseif ($sig -and $sig.Status -eq 'NotSigned') {
                # Microsoft install scripts from aka.ms may not always be signed;
                # warn but continue if downloaded from known Microsoft URL
                if ($DownloadUrl -match '\.azure\.com|aka\.ms|microsoft\.com') {
                    $status.SignatureValid = $false
                    $status.SignatureWarning = "Script not Authenticode-signed but from trusted Microsoft domain"
                } else {
                    $status.Error = "Downloaded script is NOT signed and NOT from a known Microsoft URL. Aborting for safety."
                    return $status
                }
            } else {
                $status.SignatureValid = ($sig.Status -eq 'Valid')
            }

            # Install the agent
            & $installScript
            if ($LASTEXITCODE -ne 0) {
                $status.Error = "Agent installer exited with code $LASTEXITCODE"
                return $status
            }

            Start-Sleep -Seconds 5
            $status.Installed = $true
        }
        catch {
            $status.Error = $_.Exception.Message
        }
        finally {
            # Clean up downloaded installer script
            if ($installScript -and (Test-Path $installScript)) {
                Remove-Item $installScript -Force -ErrorAction SilentlyContinue
            }
        }

        return $status
    } -ArgumentList $AgentDownloadUrl, $ProxyServer -ErrorAction Stop

    return $result
}

# ─── Connect Arc Agent ───────────────────────────────────────────────────────────

function Connect-ArcAgentRemote {
    <#
    .SYNOPSIS
        Runs azcmagent connect on a remote target with Service Principal auth.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroup,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Location,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SPAppId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SPSecret,

        [string]$Cloud = "AzureCloud",

        [string]$CorrelationId = "",

        [string]$ProxyServer = $null
    )

    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($Sub, $RG, $Tenant, $Loc, $AppId, $Secret, $CloudEnv, $CorrId, $Proxy)

        $status = @{ Connected = $false; AgentStatus = "Unknown"; Error = $null; ExitCode = $null }

        # azcmagent exit code reference:
        # https://learn.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-agent-onboard
        $exitCodeMap = @{
            1  = "Generic error — check %ProgramData%\AzureConnectedMachineAgent\Log\azcmagent.log"
            2  = "Invalid command-line options — verify config values"
            16 = "Network/transport error — check firewall, proxy, DNS (TCP 443)"
            17 = "Authentication failed — SP secret expired/wrong, or Entra ID issue"
            18 = "HTTP 4xx — wrong subscription, missing RBAC role, or Microsoft.HybridCompute not registered"
            19 = "HTTP 5xx — transient Azure error, retry in a few minutes"
            20 = "Resource already exists — run: azcmagent disconnect --force-local-only"
            21 = "Request timeout — network latency, retry with backoff"
            23 = "Invalid argument — TenantId/SubscriptionId not valid GUID format"
        }

        try {
            $agentExe = "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe"
            if (-not (Test-Path $agentExe)) {
                $agentExe = "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe"
            }
            if (-not (Test-Path $agentExe)) {
                $status.Error = "azcmagent.exe not found — agent not installed"
                return $status
            }

            # Pass SP secret via env var to avoid exposure in process listings
            # Ref: https://learn.microsoft.com/en-us/azure/azure-arc/servers/onboard-service-principal
            $env:IDENTITY_SECRET = $Secret
            try {
                $connectArgs = @(
                    "connect",
                    "--service-principal-id", $AppId,
                    "--service-principal-secret", $env:IDENTITY_SECRET,
                    "--resource-group", $RG,
                    "--tenant-id", $Tenant,
                    "--location", $Loc,
                    "--subscription-id", $Sub,
                    "--cloud", $CloudEnv
                )
                if ($CorrId) { $connectArgs += @("--correlation-id", $CorrId) }
                if ($Proxy)  { $connectArgs += @("--proxy-url", $Proxy) }

                # Retry for transient errors (exit codes 16, 19, 21)
                $retryableCodes = @(16, 19, 21)
                for ($attempt = 0; $attempt -le 2; $attempt++) {
                    $output = & $agentExe @connectArgs 2>&1
                    $exitCode = $LASTEXITCODE
                    $status.ExitCode = $exitCode
                    if ($exitCode -eq 0) { break }
                    if ($attempt -lt 2 -and $exitCode -in $retryableCodes) {
                        Start-Sleep -Seconds (10 * ($attempt + 1))
                        continue
                    }
                    break
                }
            }
            finally {
                Remove-Item Env:\IDENTITY_SECRET -ErrorAction SilentlyContinue
            }

            if ($exitCode -eq 0) {
                $status.Connected = $true
                Start-Sleep -Seconds 3
                try {
                    $agentJson = & $agentExe show --json 2>$null | ConvertFrom-Json
                    $status.AgentStatus = $agentJson.status
                }
                catch { $status.AgentStatus = "Connected" }
            }
            else {
                $guidance = if ($exitCodeMap.ContainsKey($exitCode)) { $exitCodeMap[$exitCode] } else { "Unknown — check azcmagent.log" }
                $status.Error = "azcmagent connect failed (exit $exitCode): $guidance`nOutput: $output"
            }
        }
        catch {
            $status.Error = $_.Exception.Message
        }

        return $status
    } -ArgumentList $SubscriptionId, $ResourceGroup, $TenantId, $Location, `
                    $SPAppId, $SPSecret, $Cloud, $CorrelationId, $ProxyServer `
       -ErrorAction Stop

    return $result
}

# ─── Verify HIMDS Service ────────────────────────────────────────────────────────

function Test-HIMDSServiceRemote {
    <#
    .SYNOPSIS
        Verifies the HIMDS (Hybrid Instance Metadata) service is running after onboarding.
    #>
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    $result = Invoke-Command -Session $Session -ScriptBlock {
        $svc = Get-Service -Name "himds" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            return @{ Running = $true; Status = $svc.Status }
        }
        elseif ($svc) {
            return @{ Running = $false; Status = $svc.Status }
        }
        else {
            return @{ Running = $false; Status = "NotFound" }
        }
    } -ErrorAction Stop

    return $result
}

# ─── Get Remote Agent Status ─────────────────────────────────────────────────────

function Get-ArcAgentStatusRemote {
    <#
    .SYNOPSIS
        Checks the current Arc agent status on a remote machine.
    #>
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    $result = Invoke-Command -Session $Session -ScriptBlock {
        $agentExe = "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe"
        if (-not (Test-Path $agentExe)) {
            return @{ Installed = $false; Status = "NotInstalled" }
        }

        try {
            $agentJson = & $agentExe show --json 2>$null | ConvertFrom-Json
            return @{
                Installed     = $true
                Status        = $agentJson.status
                ResourceName  = $agentJson.resourceName
                ResourceGroup = $agentJson.resourceGroup
                LastHeartbeat = $agentJson.lastHeartbeat
                AgentVersion  = $agentJson.agentVersion
            }
        }
        catch {
            return @{ Installed = $true; Status = "Error"; Error = $_.Exception.Message }
        }
    } -ErrorAction Stop

    return $result
}

# ─── Full Onboarding Pipeline — Separate Monitor Window ──────────────────────────

function Start-ArcOnboarding {
    <#
    .SYNOPSIS
        Unified onboarding pipeline. Launches TUI monitor in a SEPARATE window.
    .DESCRIPTION
        - Opens a dedicated monitor window that shows the live TUI dashboard
        - Main window runs prereq, install, connect phases silently
        - Status is shared via a JSON state file that the monitor window reads
        - No VERBOSE/install output pollutes the dashboard
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$Servers,

        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [switch]$SkipPreReqCheck,

        [int]$PollInterval = 30,

        [int]$MaxPolls = 60
    )

    $startTime = Get-Date
    $theScriptRoot = $script:OnboardScriptRoot

    # ── Shared state file (JSON) for monitor window ──────────────────────────────
    $stateDir = Join-Path $theScriptRoot "Logs"
    if (-not (Test-Path $stateDir)) { New-Item -Path $stateDir -ItemType Directory -Force | Out-Null }
    $stateFile = Join-Path $stateDir "onboard-state.json"

    # Initialize state for all servers
    $serverState = @{}
    foreach ($srv in $Servers) {
        $serverState[$srv] = @{
            Name     = $srv
            Platform = "----"
            PreReq   = "Pending"
            Install  = "----"
            ArcReg   = "----"
            Agent    = "----"
            HIMDS    = "----"
            Phase    = "Waiting"
            Error    = $null
            Events   = @()
        }
    }

    # Helper: write state to JSON file (atomic write via temp + rename)
    $writeState = {
        param([string]$Msg, [bool]$IsComplete)
        $stateObj = @{
            Servers  = @()
            Message  = $Msg
            Complete = $IsComplete
        }
        foreach ($srv in $Servers) {
            $stateObj.Servers += $serverState[$srv]
        }
        $tempFile = "$stateFile.tmp"
        $stateObj | ConvertTo-Json -Depth 5 | Out-File -FilePath $tempFile -Encoding UTF8 -Force
        Move-Item -Path $tempFile -Destination $stateFile -Force
    }

    # Write initial state
    & $writeState "Initializing..." $false

    # ── Launch Monitor Window ────────────────────────────────────────────────────
    $monitorScript = Join-Path $theScriptRoot "ArcMonitor-MonitorWindow.ps1"
    $pwshExe = if ($PSVersionTable.PSEdition -eq 'Core') { "pwsh" } else { "powershell" }

    Write-Host ""
    Write-Host "  Launching monitor dashboard in separate window..." -ForegroundColor Cyan

    $monitorArgs = "-ExecutionPolicy RemoteSigned -File `"$monitorScript`" -StateFile `"$stateFile`" -PollInterval 3"
    Start-Process $pwshExe -ArgumentList $monitorArgs
    Start-Sleep -Seconds 2

    Write-Host "  Monitor window opened. Onboarding in progress below." -ForegroundColor Green
    Write-Host "  (This window shows detailed logs. Monitor window shows live dashboard.)" -ForegroundColor DarkGray
    Write-Host ""

    # ── Process each server ──────────────────────────────────────────────────────
    foreach ($srv in $Servers) {
        $s = $serverState[$srv]

        Write-Host "  ============================================================" -ForegroundColor DarkGray
        Write-Host "  Processing: $srv" -ForegroundColor White
        Write-Host "  ============================================================" -ForegroundColor DarkGray

        # ── Phase 1: PreReq ──────────────────────────────────────────────────────
        if (-not $SkipPreReqCheck) {
            $s.Phase  = "PreReq"
            $s.PreReq = "InProgress"
            & $writeState "Checking prerequisites on $srv..." $false

            Write-Host "  [1/4] Running prerequisites on $srv..." -ForegroundColor Yellow
            try {
                $prereqResult = Test-ArcPrerequisites -ComputerName $srv -Credential $Credential `
                                                      -ProxyServer $ArcConfig.ProxyServer

                $s.Platform = if ($prereqResult.Platform -and $prereqResult.Platform.PSObject.Properties.Name -contains 'Platform') { $prereqResult.Platform.Platform } else { "Unknown" }

                if ($prereqResult.OverallPass) {
                    $s.PreReq = "Succeeded"
                    Write-Host "  [PASS] Prerequisites passed" -ForegroundColor Green
                    & $writeState "$srv : Prerequisites passed" $false
                }
                else {
                    $s.PreReq = "Failed"
                    & $writeState "$srv : Prerequisites FAILED" $false

                    Show-PreReqResults -Result $prereqResult

                    Write-Host "  Options:" -ForegroundColor Yellow
                    Write-Host "    [F] Auto-fix  [S] Skip  [I] Ignore and proceed" -ForegroundColor DarkGray
                    $fixChoice = Read-Host "  Select"

                    if ($fixChoice -eq 'F' -or $fixChoice -eq 'f') {
                        $s.PreReq = "Fixing"
                        & $writeState "$srv : Attempting auto-fix..." $false
                        Repair-ArcPrerequisites -ComputerName $srv -Credential $Credential `
                                                -FailedChecks $prereqResult.FailedChecks

                        $prereqResult = Test-ArcPrerequisites -ComputerName $srv -Credential $Credential `
                                                               -ProxyServer $ArcConfig.ProxyServer
                        if ($prereqResult.OverallPass) {
                            $s.PreReq = "Succeeded"
                            Write-Host "  [PASS] Prerequisites passed after fix" -ForegroundColor Green
                        } else {
                            $s.PreReq = "Failed"; $s.Phase = "Failed"
                            $s.Error = "PreReq failed: $($prereqResult.FailedChecks -join ', ')"
                            $s.Events += @{ Node = $srv; Message = "PreReq failed after auto-fix"; Severity = "Error" }
                            & $writeState "$srv : Still failing after fix" $false
                            Write-Host "  [FAIL] Still failing — skipping" -ForegroundColor Red
                            continue
                        }
                    }
                    elseif ($fixChoice -eq 'I' -or $fixChoice -eq 'i') {
                        $s.PreReq = "Ignored"
                        $s.Events += @{ Node = $srv; Message = "PreReq ignored by operator"; Severity = "Warning" }
                        Write-Host "  [WARN] Proceeding despite failures" -ForegroundColor Yellow
                    }
                    else {
                        $s.PreReq = "Failed"; $s.Phase = "Skipped"
                        $s.Events += @{ Node = $srv; Message = "Skipped by operator"; Severity = "Warning" }
                        & $writeState "$srv : Skipped" $false
                        Write-Host "  [SKIP] Server skipped" -ForegroundColor DarkGray
                        continue
                    }
                }

                # Already connected?
                if ($prereqResult.Checks["ExistingAgent"] -and
                    $prereqResult.Checks["ExistingAgent"].Status -eq "Warn") {
                    $s.Install = "Succeeded"; $s.ArcReg = "Succeeded"
                    $s.Agent = "Connected"; $s.HIMDS = "Running"; $s.Phase = "Done"
                    $s.Events += @{ Node = $srv; Message = "Already connected to Arc"; Severity = "Info" }
                    & $writeState "$srv : Already connected" $false
                    Write-Host "  [INFO] Already connected — skipping" -ForegroundColor Cyan
                    continue
                }
            }
            catch {
                $s.PreReq = "Error"; $s.Phase = "Failed"
                $s.Error = $_.Exception.Message
                $s.Events += @{ Node = $srv; Message = "PreReq error: $($_.Exception.Message)"; Severity = "Error" }
                & $writeState "$srv : PreReq error" $false
                Write-Host "  [FAIL] PreReq error: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }
        } else {
            $s.PreReq = "Skipped"
        }

        & $writeState "Installing agent on $srv..." $false

        # ── Phase 2: Install ─────────────────────────────────────────────────────
        $s.Phase   = "Install"
        $s.Install = "Downloading"
        & $writeState "$srv : Downloading agent..." $false

        Write-Host "  [2/4] Installing agent on $srv..." -ForegroundColor Yellow
        $session = $null
        try {
            $session = New-PSSession -ComputerName $srv -Credential $Credential -ErrorAction Stop

            $installResult = Install-ArcAgentRemote -Session $session `
                                                     -AgentDownloadUrl $AgentURLs.WindowsAgent `
                                                     -ProxyServer $ArcConfig.ProxyServer

            if ($installResult.Installed) {
                $s.Install = "Succeeded"
                $s.Events += @{ Node = $srv; Message = "Agent installed"; Severity = "Info" }
                & $writeState "$srv : Agent installed" $false
                Write-Host "  [PASS] Agent installed" -ForegroundColor Green
                Write-ArcLog "$srv : Agent installed" -Level "INFO"
            }
            else {
                $errMsg = if ($installResult.Error) { $installResult.Error } else { "Install error" }
                $s.Install = "Failed"; $s.Phase = "Failed"; $s.Error = $errMsg
                $s.Events += @{ Node = $srv; Message = "Install failed: $errMsg"; Severity = "Error" }
                & $writeState "$srv : Install FAILED" $false
                Write-Host "  [FAIL] Install failed: $errMsg" -ForegroundColor Red
                Write-ArcLog "$srv : Install FAILED — $errMsg" -Level "ERROR"
                continue
            }

            # ── Phase 3: Connect ─────────────────────────────────────────────────
            $s.Phase  = "Connect"
            $s.ArcReg = "Registering"
            & $writeState "$srv : Connecting to Azure Arc..." $false

            Write-Host "  [3/4] Connecting to Azure Arc..." -ForegroundColor Yellow
            $connectResult = Connect-ArcAgentRemote -Session $session `
                -SubscriptionId $ArcConfig.SubscriptionId `
                -ResourceGroup  $ArcConfig.ResourceGroup `
                -TenantId       $ArcConfig.TenantId `
                -Location       $ArcConfig.Location `
                -SPAppId        $ArcConfig.ServicePrincipal.AppId `
                -SPSecret       $ArcConfig.ServicePrincipal.Secret `
                -Cloud          $ArcConfig.Cloud `
                -CorrelationId  $ArcConfig.CorrelationId `
                -ProxyServer    $ArcConfig.ProxyServer

            if ($connectResult.Connected) {
                $s.ArcReg = "Succeeded"
                $s.Agent  = $connectResult.AgentStatus
                $s.Events += @{ Node = $srv; Message = "Connected to Azure Arc"; Severity = "Info" }
                & $writeState "$srv : Connected!" $false
                Write-Host "  [PASS] Connected (Status: $($connectResult.AgentStatus))" -ForegroundColor Green
                Write-ArcLog "$srv : Connected — $($connectResult.AgentStatus)" -Level "INFO"
            }
            else {
                $errMsg = if ($connectResult.Error) { $connectResult.Error } else { "Connect failed" }
                $s.ArcReg = "Failed"; $s.Agent = "Error"; $s.Error = $errMsg
                $s.Events += @{ Node = $srv; Message = "Connect failed: $errMsg"; Severity = "Error" }
                & $writeState "$srv : Connect FAILED" $false
                Write-Host "  [FAIL] Connect failed: $errMsg" -ForegroundColor Red
                Write-ArcLog "$srv : Connect FAILED — $errMsg" -Level "ERROR"
            }

            # ── Phase 4: Verify HIMDS ────────────────────────────────────────────
            $s.Phase = "Verify"
            & $writeState "$srv : Verifying HIMDS..." $false
            Write-Host "  [4/4] Verifying HIMDS..." -ForegroundColor Yellow
            Start-Sleep -Seconds 3

            $himdsResult = Test-HIMDSServiceRemote -Session $session
            $s.HIMDS = if ($himdsResult.Running) { "Running" } else { $himdsResult.Status }

            if ($connectResult.Connected) {
                $s.Phase = "Done"
                Write-Host "  [DONE] $srv onboarded successfully" -ForegroundColor Green
            } else {
                $s.Phase = "Failed"
            }
        }
        catch {
            $s.Phase = "Failed"; $s.Error = $_.Exception.Message
            $s.Events += @{ Node = $srv; Message = $_.Exception.Message; Severity = "Error" }
            Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
            Write-ArcLog "$srv : EXCEPTION — $($_.Exception.Message)" -Level "ERROR"
        }
        finally {
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }

        & $writeState "$srv : phase complete" $false
    }

    # ── Mark complete — monitor window will detect and show final state ───────────
    & $writeState "Onboarding complete" $true

    # ── Summary in main window ───────────────────────────────────────────────────
    $elapsed = (Get-Date) - $startTime
    $doneCount   = @($Servers | Where-Object { $serverState[$_].Phase -eq "Done" }).Count
    $failedCount = @($Servers | Where-Object { $serverState[$_].Phase -ne "Done" }).Count

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  ONBOARDING COMPLETE" -ForegroundColor Cyan
    Write-Host "  Total: $(@($Servers).Count) | Succeeded: $doneCount | Failed: $failedCount | Time: $($elapsed.ToString('mm\:ss'))" -ForegroundColor White
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($srv in $Servers) {
        $s = $serverState[$srv]
        $icon = if ($s.Phase -eq "Done") { "[OK]" } else { "[XX]" }
        $color = if ($s.Phase -eq "Done") { "Green" } else { "Red" }
        $detail = if ($s.Error) { " -- $($s.Error)" } else { " -- $($s.Platform)" }
        Write-Host "  $icon $($srv.PadRight(25)) $detail" -ForegroundColor $color
    }

    Write-Host ""
    Write-Host "  Monitor window shows live dashboard. It will close automatically." -ForegroundColor DarkGray
    Write-ArcLog "Onboarding complete: $doneCount/$(@($Servers).Count) in $($elapsed.ToString('mm\:ss'))"

    # Build return
    $onboardResults = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($srv in $Servers) {
        $s = $serverState[$srv]
        $onboardResults.Add(@{
            Server    = $srv
            Platform  = $s.Platform
            Installed = ($s.Install -eq "Succeeded")
            Connected = ($s.ArcReg -eq "Succeeded")
            HIMDS     = ($s.HIMDS -eq "Running")
            Phase     = $s.Phase
            Error     = $s.Error
        })
    }
    return $onboardResults
}

Write-Host "  Unified onboarding module loaded." -ForegroundColor Green
