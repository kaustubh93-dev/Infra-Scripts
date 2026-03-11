#Requires -Version 5.1
<#
.SYNOPSIS
    Arc Onboarding Orchestrator — Unified launcher for all server types
.DESCRIPTION
    Interactive menu-driven launcher that lets you choose which type of servers
    to onboard to Azure Arc, then runs the appropriate monitor.
    Auto-elevates to Administrator if not already running elevated.
.EXAMPLE
    .\Start-ArcMonitor.ps1               # Interactive menu
    .\Start-ArcMonitor.ps1 -Mode Onboard -Targets "srv01","srv02"
    .\Start-ArcMonitor.ps1 -Mode PreCheck -Targets "srv01"
    .\Start-ArcMonitor.ps1 -Mode Setup
#>

[CmdletBinding()]
param(
    [ValidateSet("Onboard", "PreCheck", "Setup")]
    [string]$Mode,
    [string[]]$Targets,
    [int]$PollInterval = 60,
    [int]$MaxPolls = 120
)

$script:scriptPath = $MyInvocation.MyCommand.Definition
$scriptRoot = Split-Path -Parent $script:scriptPath
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Audit Transcript ───────────────────────────────────────────────────────────
$transcriptDir = Join-Path $scriptRoot "Logs"
if (-not (Test-Path $transcriptDir)) { New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null }
$transcriptFile = Join-Path $transcriptDir "ArcMonitor_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
try { Start-Transcript -Path $transcriptFile -Append -Force | Out-Null } catch {}

# ─── Admin Elevation ────────────────────────────────────────────────────────────
# Cannot use #Requires -RunAsAdministrator because it blocks before our code runs.
# Instead we detect and auto-relaunch in an elevated window with all parameters.

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ([System.Environment]::UserInteractive) {
        $pwshExe = if ($PSVersionTable.PSEdition -eq 'Core') { "pwsh" } else { "powershell" }

        # Rebuild the argument list to pass all parameters through
        $argParts = @("-NoExit", "-ExecutionPolicy", "RemoteSigned", "-File", "`"$script:scriptPath`"")
        if ($Mode)    { $argParts += "-Mode"; $argParts += $Mode }
        if ($Targets) { $argParts += "-Targets"; $argParts += ($Targets | ForEach-Object { "`"$_`"" }) -join "," }
        if ($PollInterval -ne 60)  { $argParts += "-PollInterval"; $argParts += $PollInterval }
        if ($MaxPolls -ne 120)     { $argParts += "-MaxPolls"; $argParts += $MaxPolls }

        try {
            Write-Host ""
            Write-Host "  Elevating to Administrator..." -ForegroundColor Yellow
            Start-Process $pwshExe -Verb RunAs -ArgumentList ($argParts -join " ")
            exit 0
        }
        catch {
            Write-Host "  Failed to elevate. Please right-click and 'Run as Administrator'." -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Error "This script requires Administrator privileges. Run as Administrator."
        exit 1
    }
}

# ─── Input Validation ───────────────────────────────────────────────────────────

function Test-ValidServerName {
    <#
    .SYNOPSIS
        Validates a server name/IP is a safe, well-formed hostname or IPv4 address.
    #>
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    # Allow valid hostnames (RFC 1123) and IPv4 addresses
    $hostnamePattern = '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    $ipv4Pattern = '^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    return ($Name -match $hostnamePattern -or $Name -match $ipv4Pattern)
}

# ─── Banner ─────────────────────────────────────────────────────────────────────

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ████████                          ██████   ██████                      ███   █████                " -ForegroundColor Cyan
    Write-Host "  ███▒▒▒▒▒███                       ▒▒██████ ██████                      ▒▒▒   ▒▒███               " -ForegroundColor Cyan
    Write-Host " ▒███    ▒███  ████████   ██████     ▒███▒█████▒███   ██████  ████████   ████  ███████    ██████  ████████" -ForegroundColor Cyan
    Write-Host " ▒███████████ ▒▒███▒▒███ ███▒▒███    ▒███▒▒███ ▒███  ███▒▒███▒▒███▒▒███ ▒▒███ ▒▒▒███▒    ███▒▒███▒▒███▒▒███" -ForegroundColor Cyan
    Write-Host " ▒███▒▒▒▒▒███  ▒███ ▒▒▒ ▒███ ▒▒▒     ▒███ ▒▒▒  ▒███ ▒███ ▒███ ▒███ ▒███  ▒███   ▒███    ▒███ ▒███ ▒███ ▒▒▒" -ForegroundColor Cyan
    Write-Host " ▒███    ▒███  ▒███     ▒███  ███    ▒███      ▒███ ▒███ ▒███ ▒███ ▒███  ▒███   ▒███ ███▒███ ▒███ ▒███" -ForegroundColor Cyan
    Write-Host " █████   █████ █████    ▒▒██████     █████     █████▒▒██████  ████ █████ █████  ▒▒█████ ▒▒██████  █████" -ForegroundColor Cyan
    Write-Host "▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒      ▒▒▒▒▒▒     ▒▒▒▒▒     ▒▒▒▒▒  ▒▒▒▒▒▒  ▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒▒  ▒▒▒▒▒" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Azure Arc Onboarding Monitor" -ForegroundColor White
    Write-Host "  Unified framework for onboarding servers to Azure Arc" -ForegroundColor DarkGray
    Write-Host "  Supports: VMware | Azure Local | Hyper-V | Physical | KVM | Nutanix" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host ("  " + ("=" * 72)) -ForegroundColor DarkCyan
    Write-Host ""
}

# ─── Setup Wizard ───────────────────────────────────────────────────────────────

function Start-SetupWizard {
    <#
    .SYNOPSIS
        Interactive setup to create Service Principal and validate prerequisites.
    #>
    Write-Host "`n  ── AZURE ARC SETUP WIZARD ──────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    # Step 1: Check Azure CLI / Az Modules
    Write-Host "  [1/6] Checking Azure prerequisites..." -ForegroundColor Yellow
    $hasAzCLI = Get-Command az -ErrorAction SilentlyContinue
    if ($hasAzCLI) { Write-Host "    ✓ Azure CLI found" -ForegroundColor Green }
    else           { Write-Host "    ○ Azure CLI not found (optional)" -ForegroundColor DarkGray }

    $requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.ConnectedMachine')
    foreach ($mod in $requiredModules) {
        if (Get-Module $mod -ListAvailable -ErrorAction SilentlyContinue) {
            Write-Host "    ✓ $mod found" -ForegroundColor Green
        } else {
            Write-Host "    ▲ Installing $mod..." -ForegroundColor Yellow
            Install-Module $mod -Force -AllowClobber -Scope CurrentUser -SkipPublisherCheck
            Write-Host "    ✓ $mod installed" -ForegroundColor Green
        }
    }
    # Import all modules after install (order matters: Accounts first)
    foreach ($mod in $requiredModules) {
        try {
            Import-Module $mod -Force -ErrorAction Stop
            Write-Host "    ✓ $mod loaded" -ForegroundColor Green
        }
        catch {
            Write-Host "    ✖ Failed to load $mod : $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Step 2: Azure Login
    Write-Host "`n  [2/6] Authenticating to Azure..." -ForegroundColor Yellow
    try {
        Connect-AzAccount -ErrorAction Stop | Out-Null
        $ctx = Get-AzContext
        Write-Host "    ✓ Logged in as: $($ctx.Account.Id)" -ForegroundColor Green
        Write-Host "    ✓ Subscription: $($ctx.Subscription.Name)" -ForegroundColor Green
    }
    catch {
        Write-Host "    ✖ Login failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Step 3: Service Principal
    Write-Host "`n  [3/6] Service Principal for Arc onboarding..." -ForegroundColor Yellow
    $spAppId = $null
    $spSecret = $null
    $spCreatedNew = $false

    # Search for existing Arc-related service principals
    Write-Host "    Searching for existing service principals..." -ForegroundColor DarkGray
    try {
        $existingSPs = Get-AzADServicePrincipal -DisplayNameBeginsWith "sp-arc" -ErrorAction SilentlyContinue
        if (-not $existingSPs) {
            $existingSPs = @()
        }
        # Also search for common Arc onboarding SP names
        $otherSPs = Get-AzADServicePrincipal -DisplayNameBeginsWith "arc-" -ErrorAction SilentlyContinue
        if ($otherSPs) { $existingSPs = @($existingSPs) + @($otherSPs) }
        # Deduplicate by AppId
        $existingSPs = $existingSPs | Sort-Object AppId -Unique | Sort-Object DisplayName
    }
    catch { $existingSPs = @() }

    if ($existingSPs.Count -gt 0) {
        Write-Host ""
        Write-Host "    Found $($existingSPs.Count) existing Arc service principal(s):" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "      #   Display Name                          App ID" -ForegroundColor DarkGray
        Write-Host "      ──  ────────────────────────────────────  ────────────────────────────────────" -ForegroundColor DarkGray
        for ($i = 0; $i -lt $existingSPs.Count; $i++) {
            $spItem = $existingSPs[$i]
            $dispName = $spItem.DisplayName
            if ($dispName.Length -gt 38) { $dispName = $dispName.Substring(0, 35) + "..." }
            Write-Host "      [$($($i + 1).ToString().PadLeft(1))] " -NoNewline -ForegroundColor Yellow
            Write-Host "$($dispName.PadRight(38))" -NoNewline -ForegroundColor White
            Write-Host "  $($spItem.AppId)" -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host "      [N] Create a new Service Principal" -ForegroundColor Yellow
        Write-Host ""

        $spChoice = Read-Host "    Select an option (1-$($existingSPs.Count) or N)"

        if ($spChoice -ne 'N' -and $spChoice -ne 'n') {
            $idx = 0
            if ([int]::TryParse($spChoice, [ref]$idx) -and $idx -ge 1 -and $idx -le $existingSPs.Count) {
                $chosenSP = $existingSPs[$idx - 1]
                $spAppId = $chosenSP.AppId
                Write-Host "    ✓ Using existing SP: $($chosenSP.DisplayName)" -ForegroundColor Green
                Write-Host "    ► App ID: $spAppId" -ForegroundColor White
                Write-Host ""
                Write-Host "    Do you have the existing secret for this SP?" -ForegroundColor Yellow
                $hasSecret = Read-Host "    (Y)es — I will enter it / (N)o — generate a new secret"

                if ($hasSecret -eq 'Y' -or $hasSecret -eq 'y') {
                    $spSecret = Read-Host "    Enter the client secret"
                } else {
                    Write-Host "    Generating new client secret..." -ForegroundColor Yellow
                    try {
                        $newCred = New-AzADSpCredential -ObjectId $chosenSP.Id -ErrorAction Stop
                        $spSecret = $newCred.SecretText
                        Write-Host "    ✓ New secret generated" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "    ✖ Failed to generate secret: $($_.Exception.Message)" -ForegroundColor Red
                        Write-Host "    You can reset it manually in the Azure Portal (App registrations)." -ForegroundColor DarkGray
                    }
                }
            } else {
                Write-Host "    Invalid selection. Will create a new SP." -ForegroundColor Yellow
                $spChoice = 'N'
            }
        }
    } else {
        Write-Host "    No existing Arc service principals found." -ForegroundColor DarkGray
        $spChoice = 'N'
    }

    # Create new SP if requested or no existing ones found
    if ($spChoice -eq 'N' -or $spChoice -eq 'n' -or -not $spAppId) {
        $defaultName = "sp-arc-onboarding-$(Get-Random -Maximum 9999)"
        $customName = Read-Host "    Enter SP display name (default: $defaultName)"
        if (-not $customName) { $customName = $defaultName }

        try {
            $sp = New-AzADServicePrincipal -DisplayName $customName -ErrorAction Stop
            Start-Sleep -Seconds 5  # Allow AAD replication
            $spAppId = $sp.AppId
            $spSecret = $sp.PasswordCredentials.SecretText
            $spCreatedNew = $true

            # Assign Contributor role
            New-AzRoleAssignment -ApplicationId $spAppId `
                -RoleDefinitionName "Contributor" `
                -Scope "/subscriptions/$($ctx.Subscription.Id)" -ErrorAction Stop

            # Assign Azure Connected Machine Onboarding role
            New-AzRoleAssignment -ApplicationId $spAppId `
                -RoleDefinitionName "Azure Connected Machine Onboarding" `
                -Scope "/subscriptions/$($ctx.Subscription.Id)" -ErrorAction SilentlyContinue

            Write-Host "    ✓ Service Principal created: $customName" -ForegroundColor Green
            Write-Host "    ✓ Assigned Contributor + Azure Connected Machine Onboarding roles" -ForegroundColor Green
        }
        catch {
            Write-Host "    ✖ SP creation failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "    Tip: Create manually with Azure CLI:" -ForegroundColor DarkGray
            Write-Host "    az ad sp create-for-rbac --name `"$customName`" --role Contributor --scopes /subscriptions/$($ctx.Subscription.Id)" -ForegroundColor DarkGray
        }
    }

    # Display credentials (mask secret)
    if ($spAppId -and $spSecret) {
        $maskedSecret = if ($spSecret.Length -gt 4) { ("*" * ($spSecret.Length - 4)) + $spSecret.Substring($spSecret.Length - 4) } else { "****" }
        Write-Host ""
        Write-Host "    ╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "    ║  SERVICE PRINCIPAL CREDENTIALS                      ║" -ForegroundColor Cyan
        Write-Host "    ╠══════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "    ║  App ID : $($spAppId.PadRight(40))║" -ForegroundColor White
        Write-Host "    ║  Secret : $($maskedSecret.Substring(0, [Math]::Min(40, $maskedSecret.Length)).PadRight(40))║" -ForegroundColor White
        Write-Host "    ║  Tenant : $($ctx.Tenant.Id.PadRight(40))║" -ForegroundColor White
        Write-Host "    ╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""

        # Save credentials securely using DPAPI encryption (user-scoped)
        $saveChoice = Read-Host "    Save credentials securely (DPAPI-encrypted)? (Y/N)"
        if ($saveChoice -eq 'Y' -or $saveChoice -eq 'y') {
            $credFile = Join-Path $scriptRoot "ArcSPN-Credentials.xml"
            $secureSecret = ConvertTo-SecureString $spSecret -AsPlainText -Force
            $credObj = @{
                TenantId       = $ctx.Tenant.Id
                SubscriptionId = $ctx.Subscription.Id
                AppId          = $spAppId
                Secret         = $secureSecret
                CreatedAt      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            }
            $credObj | Export-Clixml -Path $credFile -Force
            Write-Host "    ✓ Credentials saved (DPAPI-encrypted): $credFile" -ForegroundColor Green
            Write-Host "    ⚠ This file can only be decrypted by this user on this machine." -ForegroundColor Yellow
        }
    } elseif ($spAppId -and -not $spSecret) {
        Write-Host ""
        Write-Host "    ► App ID: $spAppId" -ForegroundColor White
        Write-Host "    ► Secret: (not available — enter manually in ArcMonitor-Config.ps1)" -ForegroundColor Yellow
    }

    # Step 4: Location selection
    Write-Host "`n  [4/6] Azure region selection..." -ForegroundColor Yellow
    $selectedLocation = $null

    try {
        Write-Host "    Fetching available Azure regions..." -ForegroundColor DarkGray
        $locations = Get-AzLocation | Where-Object { $_.RegionType -eq 'Physical' } |
                     Sort-Object DisplayName |
                     Select-Object DisplayName, Location

        if ($locations.Count -gt 0) {
            # Group into columns for display
            $popular = @('eastus', 'eastus2', 'westus2', 'westus3', 'centralus',
                         'westeurope', 'northeurope', 'uksouth', 'southeastasia',
                         'australiaeast', 'japaneast', 'canadacentral', 'centralindia')
            $popularLocs = $locations | Where-Object { $_.Location -in $popular }
            $otherLocs   = $locations | Where-Object { $_.Location -notin $popular }

            Write-Host ""
            Write-Host "    Popular regions:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $popularLocs.Count; $i++) {
                $loc = $popularLocs[$i]
                $label = "      [$($i + 1)] $($loc.DisplayName) ($($loc.Location))"
                Write-Host $label -ForegroundColor White
            }
            Write-Host "      [A] Show all $($locations.Count) regions" -ForegroundColor DarkGray
            Write-Host "      [D] Use default (eastus)" -ForegroundColor Yellow
            Write-Host ""

            $locChoice = Read-Host "    Select region (1-$($popularLocs.Count), A, or D)"

            if ($locChoice -eq 'D' -or $locChoice -eq 'd' -or -not $locChoice) {
                $selectedLocation = "eastus"
            }
            elseif ($locChoice -eq 'A' -or $locChoice -eq 'a') {
                Write-Host ""
                Write-Host "    All available regions:" -ForegroundColor Cyan
                $allIdx = 1
                foreach ($loc in $locations) {
                    Write-Host "      [$allIdx] $($loc.DisplayName) ($($loc.Location))" -ForegroundColor White
                    $allIdx++
                }
                Write-Host ""
                $allChoice = Read-Host "    Select region (1-$($locations.Count))"
                $aIdx = 0
                if ([int]::TryParse($allChoice, [ref]$aIdx) -and $aIdx -ge 1 -and $aIdx -le $locations.Count) {
                    $selectedLocation = $locations[$aIdx - 1].Location
                } else {
                    $selectedLocation = "eastus"
                    Write-Host "    Invalid selection, using default." -ForegroundColor Yellow
                }
            }
            else {
                $lIdx = 0
                if ([int]::TryParse($locChoice, [ref]$lIdx) -and $lIdx -ge 1 -and $lIdx -le $popularLocs.Count) {
                    $selectedLocation = $popularLocs[$lIdx - 1].Location
                } else {
                    $selectedLocation = "eastus"
                    Write-Host "    Invalid selection, using default." -ForegroundColor Yellow
                }
            }
        }
    }
    catch {
        Write-Host "    Could not fetch regions: $($_.Exception.Message)" -ForegroundColor Yellow
        $manualLoc = Read-Host "    Enter Azure region manually (default: eastus)"
        $selectedLocation = if ($manualLoc) { $manualLoc } else { "eastus" }
    }

    if (-not $selectedLocation) { $selectedLocation = "eastus" }
    Write-Host "    ✓ Selected region: $selectedLocation" -ForegroundColor Green

    # Step 5: Resource Group
    Write-Host "`n  [5/6] Resource Group setup..." -ForegroundColor Yellow
    $rgName = $null

    try {
        Write-Host "    Fetching existing resource groups..." -ForegroundColor DarkGray
        $existingRGs = Get-AzResourceGroup -ErrorAction SilentlyContinue |
                       Sort-Object ResourceGroupName |
                       Select-Object ResourceGroupName, Location

        if ($existingRGs -and $existingRGs.Count -gt 0) {
            Write-Host ""
            Write-Host "    Existing resource groups:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $existingRGs.Count; $i++) {
                $rg = $existingRGs[$i]
                Write-Host "      [$($i + 1)] $($rg.ResourceGroupName)  ($($rg.Location))" -ForegroundColor White
            }
            Write-Host "      [N] Create a new resource group" -ForegroundColor Yellow
            Write-Host ""

            $rgChoice = Read-Host "    Select resource group (1-$($existingRGs.Count) or N)"

            if ($rgChoice -ne 'N' -and $rgChoice -ne 'n') {
                $rIdx = 0
                if ([int]::TryParse($rgChoice, [ref]$rIdx) -and $rIdx -ge 1 -and $rIdx -le $existingRGs.Count) {
                    $rgName = $existingRGs[$rIdx - 1].ResourceGroupName
                    Write-Host "    ✓ Using existing resource group: $rgName" -ForegroundColor Green
                } else {
                    Write-Host "    Invalid selection. Will create a new resource group." -ForegroundColor Yellow
                    $rgChoice = 'N'
                }
            }
        } else {
            Write-Host "    No existing resource groups found." -ForegroundColor DarkGray
            $rgChoice = 'N'
        }
    }
    catch {
        Write-Host "    Could not list resource groups: $($_.Exception.Message)" -ForegroundColor Yellow
        $rgChoice = 'N'
    }

    # Create new resource group if requested
    if ($rgChoice -eq 'N' -or $rgChoice -eq 'n' -or -not $rgName) {
        $newRGName = Read-Host "    Enter new resource group name (default: rg-arc-onboarding)"
        if (-not $newRGName) { $newRGName = "rg-arc-onboarding" }

        try {
            New-AzResourceGroup -Name $newRGName -Location $selectedLocation -ErrorAction Stop | Out-Null
            $rgName = $newRGName
            Write-Host "    ✓ Created resource group: $rgName in $selectedLocation" -ForegroundColor Green
        }
        catch {
            Write-Host "    ✖ Failed to create resource group: $($_.Exception.Message)" -ForegroundColor Red
            $rgName = $newRGName  # Store the name anyway for config file
        }
    }

    # Step 6: Save directly into ArcMonitor-Config.ps1
    Write-Host "`n  [6/6] Configuration summary" -ForegroundColor Yellow
    Write-Host ""
    $boxW = 62
    $lblW = 18
    $valW = $boxW - $lblW - 4  # 4 = "║  " + "║"
    Write-Host "    ╔$('═' * $boxW)╗" -ForegroundColor Cyan
    Write-Host "    ║  $('ARC ONBOARDING CONFIGURATION'.PadRight($boxW - 2))║" -ForegroundColor Cyan
    Write-Host "    ╠$('═' * $boxW)╣" -ForegroundColor Cyan
    Write-Host "    ║  Tenant ID      : $($ctx.Tenant.Id.PadRight($valW))║" -ForegroundColor White
    Write-Host "    ║  Subscription   : $($ctx.Subscription.Id.PadRight($valW))║" -ForegroundColor White
    Write-Host "    ║  Resource Group : $($rgName.PadRight($valW))║" -ForegroundColor White
    Write-Host "    ║  Location       : $($selectedLocation.PadRight($valW))║" -ForegroundColor White
    if ($spAppId) {
    Write-Host "    ║  SP App ID      : $($spAppId.PadRight($valW))║" -ForegroundColor White
    }
    Write-Host "    ╚$('═' * $boxW)╝" -ForegroundColor Cyan

    Write-Host ""
    $saveAll = Read-Host "    Save config directly to ArcMonitor-Config.ps1? (Y/N)"
    if ($saveAll -eq 'Y' -or $saveAll -eq 'y') {
        $configPs1 = Join-Path $scriptRoot "ArcMonitor-Config.ps1"
        $secretDisplay = if ($spSecret) { $spSecret } else { "<YOUR-SP-SECRET>" }
        $appIdDisplay  = if ($spAppId)  { $spAppId }  else { "<YOUR-SP-APP-ID>" }
        $correlationId = [guid]::NewGuid().ToString()

        $configContent = @"
<#
.SYNOPSIS
    Arc Monitor Configuration Module
.DESCRIPTION
    Centralized configuration for Azure Arc Bootstrap Monitor.
    Auto-generated by Setup Wizard on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Values can also be set via the Setup Wizard: .\Start-ArcMonitor.ps1 -Mode Setup
#>

# === Azure Identity ═══════════════════════════════════════════════════════════
`$ArcConfig = @{
    TenantId       = "$($ctx.Tenant.Id)"
    SubscriptionId = "$($ctx.Subscription.Id)"
    ResourceGroup  = "$rgName"
    Location       = "$selectedLocation"
    Cloud          = "AzureCloud"              # AzureCloud | AzureUSGovernment | AzureChinaCloud
    AuthType       = "principal"               # principal | token | interactive
    CorrelationId  = "$correlationId"          # For tracking in Azure Arc logs

    # Service Principal (for at-scale / automated onboarding)
    ServicePrincipal = @{
        AppId  = "$appIdDisplay"
        Secret = "$secretDisplay"              # Use Key Vault in production!
    }

    # Proxy (optional)
    ProxyServer = `$null                        # e.g. "http://proxy.corp.local:8080"
}

# === Set environment variables for onboarding scripts ═════════════════════════
# These env vars are used by the Azure Arc onboarding agent (azcmagent connect)
`$env:SUBSCRIPTION_ID = `$ArcConfig.SubscriptionId
`$env:RESOURCE_GROUP  = `$ArcConfig.ResourceGroup
`$env:TENANT_ID       = `$ArcConfig.TenantId
`$env:LOCATION        = `$ArcConfig.Location
`$env:AUTH_TYPE       = `$ArcConfig.AuthType
`$env:CORRELATION_ID  = `$ArcConfig.CorrelationId
`$env:CLOUD           = `$ArcConfig.Cloud

# Service Principal credentials (used by azcmagent connect --service-principal-id)
`$ServicePrincipalId           = `$ArcConfig.ServicePrincipal.AppId
`$ServicePrincipalClientSecret = `$ArcConfig.ServicePrincipal.Secret

# === Azure Local (Azure Stack HCI) Nodes ═════════════════════════════════════
`$AzureLocalConfig = @{
    Nodes = @(
        @{ Name = "hci-node-01"; IP = "10.0.0.11" }
        @{ Name = "hci-node-02"; IP = "10.0.0.12" }
        # Add more nodes as needed
    )
    Credential      = `$null                     # Set via Get-Credential at runtime
    SolutionVersion = `$null                     # e.g. "10.2505.0.x" - leave null for latest
}

# === VMware vSphere Environment ═══════════════════════════════════════════════
`$VMwareConfig = @{
    vCenterServer  = "vcenter.corp.local"
    vCenterCred    = `$null                     # Set via Get-Credential at runtime
    GuestCred      = `$null                     # Guest OS credential for VM operations
    TargetVMs      = @(
        # Populate from vCenter or list manually
        # @{ Name = "vm-web-01"; GuestOS = "Windows" }
        # @{ Name = "vm-db-01";  GuestOS = "Linux" }
    )
    # Filter for auto-discovery (alternative to manual list)
    VMFilter = @{
        Folder    = `$null                      # e.g. "Production VMs"
        Tag       = `$null                      # e.g. "arc-onboard"
        Cluster   = `$null                      # e.g. "Prod-Cluster"
    }
}

# === General On-Prem Servers ══════════════════════════════════════════════════
`$OnPremConfig = @{
    Servers = @(
        @{ Name = "srv-app-01"; IP = "10.1.0.21"; OS = "Windows"; Protocol = "WinRM" }
        @{ Name = "srv-app-02"; IP = "10.1.0.22"; OS = "Windows"; Protocol = "WinRM" }
        @{ Name = "srv-linux-01"; IP = "10.1.0.31"; OS = "Linux"; Protocol = "SSH" }
        # Add more servers as needed
    )
    WinRMCredential = `$null                    # Set via Get-Credential at runtime
    SSHKeyPath      = "~/.ssh/id_rsa"          # For Linux servers
    SSHUser         = "arcadmin"
}

# === Monitor Dashboard Settings ══════════════════════════════════════════════
`$MonitorSettings = @{
    PollIntervalSeconds  = 60                  # How often to refresh status
    MaxPolls             = 120                 # Maximum poll attempts before timeout
    LogPath              = ".\ArcMonitor\Logs" # Log file directory
    EnableLogging        = `$true
    ShowDownloadProgress = `$true
    ShowEvents           = `$true
    AnimateHeader        = `$true
}

# === Agent Download URLs ═════════════════════════════════════════════════════
`$AgentURLs = @{
    WindowsAgent    = "https://gbl.his.arc.azure.com/azcmagent-windows"
    WindowsAgentAlt = "https://aka.ms/azcmagent-windows"
    LinuxAgent      = "https://aka.ms/azcmagent"
    ArcInstaller    = "https://aka.ms/AzsHCIARCInstallerModule"
}

# === Onboarding Command Template ═════════════════════════════════════════════
# This is the azcmagent connect command used by all monitor scripts.
# Changing it here changes the command everywhere.
`$ArcConnectArgs = @{
    Windows = @(
        "--service-principal-id", `$ServicePrincipalId,
        "--service-principal-secret", `$ServicePrincipalClientSecret,
        "--resource-group", `$env:RESOURCE_GROUP,
        "--tenant-id", `$env:TENANT_ID,
        "--location", `$env:LOCATION,
        "--subscription-id", `$env:SUBSCRIPTION_ID,
        "--cloud", `$env:CLOUD
    )
    Linux = @(
        "--service-principal-id", `$ServicePrincipalId,
        "--service-principal-secret", `$ServicePrincipalClientSecret,
        "--resource-group", `$env:RESOURCE_GROUP,
        "--tenant-id", `$env:TENANT_ID,
        "--location", `$env:LOCATION,
        "--subscription-id", `$env:SUBSCRIPTION_ID,
        "--cloud", `$env:CLOUD
    )
}
if (`$env:CORRELATION_ID) {
    `$ArcConnectArgs.Windows += @("--correlation-id", `$env:CORRELATION_ID)
    `$ArcConnectArgs.Linux   += @("--correlation-id", `$env:CORRELATION_ID)
}

# === Export ═══════════════════════════════════════════════════════════════════
`$script:ArcMonitorConfig = @{
    Arc          = `$ArcConfig
    AzureLocal   = `$AzureLocalConfig
    VMware       = `$VMwareConfig
    OnPrem       = `$OnPremConfig
    Monitor      = `$MonitorSettings
    AgentURLs    = `$AgentURLs
    ConnectArgs  = `$ArcConnectArgs
}

Write-Host "  Arc Monitor configuration loaded." -ForegroundColor Green
"@
        # Write with UTF-8 BOM for PowerShell 5.1 compatibility
        $utf8Bom = New-Object System.Text.UTF8Encoding($true)
        [System.IO.File]::WriteAllText($configPs1, $configContent, $utf8Bom)
        Write-Host "    ✓ ArcMonitor-Config.ps1 updated with your values!" -ForegroundColor Green
        Write-Host "    File: $configPs1" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "  ── Setup complete! ──────────────────────────────────────────" -ForegroundColor Green
    Write-Host ""
    Read-Host "  Press Enter to return to main menu"
}

# ─── Network Validation ─────────────────────────────────────────────────────────

function Test-ArcNetworkRequirements {
    <#
    .SYNOPSIS
        Tests network connectivity to Azure Arc required endpoints from remote target servers.
    .DESCRIPTION
        Prompts for target server(s) and credentials, then runs endpoint reachability checks
        REMOTELY on each target via Invoke-Command — verifying the targets can reach Azure.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  AZURE ARC — REMOTE NETWORK CONNECTIVITY TEST              ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Tests run REMOTELY on target servers (not on this machine)." -ForegroundColor DarkGray
    Write-Host "  Verifies each target can reach Azure Arc required endpoints." -ForegroundColor DarkGray
    Write-Host ""

    # Collect targets
    Write-Host "  Enter target server names/IPs to test." -ForegroundColor Yellow
    Write-Host "  (Comma-separated, or one per line. Enter blank line when done.)" -ForegroundColor DarkGray
    Write-Host ""
    [string[]]$servers = @()
    while ($true) {
        $serverInput = Read-Host "  Server(s)"
        if (-not $serverInput) { break }
        $parsed = $serverInput -split '[,;\s]+' | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }
        $servers += @($parsed)
    }

    if (@($servers).Count -eq 0) {
        Write-Host "  No servers specified." -ForegroundColor Yellow
        return
    }
    [string[]]$servers = @($servers | Select-Object -Unique)

    # Get credentials
    Write-Host ""
    Write-Host "  Enter admin credentials for remote servers:" -ForegroundColor Cyan
    $cred = Get-Credential -Message "Remote Server Admin"
    if (-not $cred) {
        Write-Host "  No credentials provided. Aborting." -ForegroundColor Red
        return
    }

    $endpoints = @(
        @{ Name = "Azure Resource Manager";   Host = "management.azure.com";              Port = 443 }
        @{ Name = "Azure AD / Entra ID";      Host = "login.microsoftonline.com";         Port = 443 }
        @{ Name = "Entra ID (pas)";           Host = "pas.windows.net";                   Port = 443 }
        @{ Name = "Azure Arc HIS";            Host = "his.arc.azure.com";                 Port = 443 }
        @{ Name = "Azure Arc GBL";            Host = "gbl.his.arc.azure.com";             Port = 443 }
        @{ Name = "Guest Configuration";      Host = "guestconfiguration.azure.com";      Port = 443 }
        @{ Name = "Guest Notification";       Host = "guestnotificationservice.azure.com"; Port = 443 }
        @{ Name = "Download (MS)";            Host = "download.microsoft.com";            Port = 443 }
        @{ Name = "Packages (Microsoft)";     Host = "packages.microsoft.com";            Port = 443 }
    )

    foreach ($srv in $servers) {
        Write-Host ""
        Write-Host "  ── $srv ──────────────────────────────────────────────" -ForegroundColor White

        $session = $null
        try {
            $sessionOpts = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000
            $session = New-PSSession -ComputerName $srv -Credential $cred `
                                     -SessionOption $sessionOpts -ErrorAction Stop

            $remoteResults = Invoke-Command -Session $session -ScriptBlock {
                param($Endpoints)
                $results = @()
                foreach ($ep in $Endpoints) {
                    $reachable = $false
                    try {
                        $tcp = New-Object System.Net.Sockets.TcpClient
                        $task = $tcp.ConnectAsync($ep.Host, $ep.Port)
                        $ok = $task.Wait(5000)
                        $reachable = ($ok -and $tcp.Connected)
                        $tcp.Close(); $tcp.Dispose()
                    }
                    catch { $reachable = $false }
                    $results += @{ Name = $ep.Name; Host = $ep.Host; Reachable = $reachable }
                }
                return $results
            } -ArgumentList (,$endpoints) -ErrorAction Stop

            $passCount = 0; $failCount = 0
            foreach ($r in $remoteResults) {
                if ($r.Reachable) {
                    Write-Host "    ✓ $($r.Name.PadRight(28)) $($r.Host)" -ForegroundColor Green
                    $passCount++
                } else {
                    Write-Host "    ✖ $($r.Name.PadRight(28)) $($r.Host) — BLOCKED" -ForegroundColor Red
                    $failCount++
                }
            }
            Write-Host ""
            if ($failCount -eq 0) {
                Write-Host "    All $passCount endpoint(s) reachable from $srv" -ForegroundColor Green
            } else {
                Write-Host "    $passCount passed, $failCount BLOCKED from $srv" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "    ✖ Cannot connect to $srv : $($_.Exception.Message)" -ForegroundColor Red
        }
        finally {
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }
    }
    Write-Host ""
}

# ─── Interactive Onboarding (Unified) ────────────────────────────────────────────

function Start-InteractiveOnboarding {
    <#
    .SYNOPSIS
        Interactive mode: prompt for target servers, run prereqs, onboard eligible.
    #>
    param([string[]]$PresetTargets)

    # Load onboarding module
    . "$scriptRoot\ArcMonitor-Onboard.ps1"

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  AZURE ARC UNIFIED ONBOARDING — SETUP MODE                 ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This script runs from your management server." -ForegroundColor DarkGray
    Write-Host "  All checks and installs execute REMOTELY on the target machines." -ForegroundColor DarkGray
    Write-Host ""

    # Step 1: Collect target servers
    [string[]]$servers = @()
    if ($PresetTargets -and @($PresetTargets).Count -gt 0) {
        [string[]]$servers = @($PresetTargets)
        Write-Host "  Target servers (from parameter): $($servers -join ', ')" -ForegroundColor White
    }
    else {
        Write-Host "  Enter target server names/IPs for Arc onboarding." -ForegroundColor Yellow
        Write-Host "  (Comma-separated, or one per line. Enter blank line when done.)" -ForegroundColor DarkGray
        Write-Host ""

        while ($true) {
            $serverInput = Read-Host "  Server(s)"
            if (-not $serverInput) { break }
            $parsed = $serverInput -split '[,;\s]+' | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }
            $servers += @($parsed)
        }
    }

    if (@($servers).Count -eq 0) {
        Write-Host "  No servers specified. Returning to menu." -ForegroundColor Yellow
        return
    }

    # Deduplicate and validate
    [string[]]$servers = @($servers | Select-Object -Unique)
    [string[]]$invalidServers = @($servers | Where-Object { -not (Test-ValidServerName $_) })
    if ($invalidServers.Count -gt 0) {
        Write-Host "  ⚠ Invalid server name(s) removed: $($invalidServers -join ', ')" -ForegroundColor Yellow
        [string[]]$servers = @($servers | Where-Object { Test-ValidServerName $_ })
    }
    if (@($servers).Count -eq 0) {
        Write-Host "  No valid servers remaining." -ForegroundColor Red
        return
    }
    Write-Host ""
    Write-Host "  Targets ($($servers.Count)): $($servers -join ', ')" -ForegroundColor Cyan

    # Step 2: Quick reachability check
    Write-Host ""
    Write-Host "  Checking reachability..." -ForegroundColor Yellow
    $reachResults = Test-ServerReachability -Servers $servers
    [string[]]$reachable = @()
    [string[]]$unreachable = @()

    foreach ($r in $reachResults) {
        $icmpIcon = if ($r.ICMP) { "✓" } else { "✖" }
        $winrmIcon = if ($r.WinRM) { "✓" } else { "✖" }
        $color = if ($r.Reachable) { "Green" } else { "Red" }

        Write-Host "    $($r.Server.PadRight(25)) " -NoNewline -ForegroundColor White
        Write-Host "ICMP: $icmpIcon " -NoNewline -ForegroundColor $color
        Write-Host "WinRM: $winrmIcon" -ForegroundColor $color

        if ($r.Reachable) { $reachable += $r.Server }
        else { $unreachable += $r.Server }
    }

    if (@($unreachable).Count -gt 0) {
        Write-Host ""
        Write-Host "  ▲ $(@($unreachable).Count) server(s) unreachable — will be skipped." -ForegroundColor Yellow
    }

    if (@($reachable).Count -eq 0) {
        Write-Host "  ✖ No reachable servers. Check network/WinRM." -ForegroundColor Red
        return
    }

    # Step 3: Get credentials
    Write-Host ""
    Write-Host "  Enter admin credentials for remote servers:" -ForegroundColor Cyan
    $cred = Get-Credential -Message "Remote Server Admin (must be local admin on targets)"
    if (-not $cred) {
        Write-Host "  No credentials provided. Aborting." -ForegroundColor Red
        return
    }

    # Step 4: Validate config is not placeholders
    . "$scriptRoot\ArcMonitor-Config.ps1"  # Re-source to pick up any Setup Wizard changes

    if ($ArcConfig.TenantId -match '<YOUR-' -or
        $ArcConfig.SubscriptionId -match '<YOUR-' -or
        $ArcConfig.ServicePrincipal.AppId -match '<YOUR-') {
        Write-Host ""
        Write-Host "  ✖ ArcMonitor-Config.ps1 still has placeholder values!" -ForegroundColor Red
        Write-Host "    TenantId : $($ArcConfig.TenantId)" -ForegroundColor DarkGray
        Write-Host "    SubId    : $($ArcConfig.SubscriptionId)" -ForegroundColor DarkGray
        Write-Host "    SP AppId : $($ArcConfig.ServicePrincipal.AppId)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Run Setup Wizard first (menu option 3) to configure Azure identity." -ForegroundColor Yellow
        Write-Host ""
        Read-Host "  Press Enter to return to menu"
        return
    }

    # Step 4b: Validate GUID format (prevents azcmagent error code 23)
    # Ref: https://learn.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-agent-onboard
    $guidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    if ($ArcConfig.TenantId -notmatch $guidPattern) {
        Write-Host ""
        Write-Host "  ✖ TenantId is not a valid GUID: $($ArcConfig.TenantId)" -ForegroundColor Red
        Write-Host "    Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ForegroundColor DarkGray
        Write-Host "    This would cause azcmagent error code 23." -ForegroundColor DarkGray
        Read-Host "  Press Enter to return to menu"
        return
    }
    if ($ArcConfig.SubscriptionId -notmatch $guidPattern) {
        Write-Host ""
        Write-Host "  ✖ SubscriptionId is not a valid GUID: $($ArcConfig.SubscriptionId)" -ForegroundColor Red
        Write-Host "    Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ForegroundColor DarkGray
        Write-Host "    This would cause azcmagent error code 23." -ForegroundColor DarkGray
        Read-Host "  Press Enter to return to menu"
        return
    }

    # Step 5: Confirm and proceed
    Write-Host ""
    Write-Host "  Ready to onboard $(@($reachable).Count) server(s) to Azure Arc:" -ForegroundColor White
    foreach ($s in $reachable) { Write-Host "    - $s" -ForegroundColor Cyan }
    Write-Host ""
    Write-Host "  Azure config:" -ForegroundColor DarkGray
    Write-Host "    Subscription : $($ArcConfig.SubscriptionId)" -ForegroundColor DarkGray
    Write-Host "    Resource Grp : $($ArcConfig.ResourceGroup)" -ForegroundColor DarkGray
    Write-Host "    Location     : $($ArcConfig.Location)" -ForegroundColor DarkGray
    Write-Host ""

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "  Aborted." -ForegroundColor Yellow
        return
    }

    # Step 6: Run unified onboarding (TUI dashboard renders LIVE during this)
    $results = Start-ArcOnboarding -Servers $reachable -Credential $cred `
                                    -PollInterval $PollInterval -MaxPolls $MaxPolls

    Write-Host ""
    Read-Host "  Press Enter to return to menu"
    return $results
}

# ─── Interactive PreReq Check Only ──────────────────────────────────────────────

function Start-InteractivePreCheck {
    <#
    .SYNOPSIS
        Run remote prerequisite checks without onboarding.
    #>
    param([string[]]$PresetTargets)

    . "$scriptRoot\ArcMonitor-Config.ps1"
    . "$scriptRoot\ArcMonitor-PreReqCheck.ps1"

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  AZURE ARC — REMOTE PREREQUISITE CHECK                     ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    [string[]]$servers = @()
    if ($PresetTargets -and @($PresetTargets).Count -gt 0) {
        [string[]]$servers = @($PresetTargets)
    }
    else {
        Write-Host "  Enter target server names/IPs to validate." -ForegroundColor Yellow
        Write-Host "  (Comma-separated, or one per line. Enter blank line when done.)" -ForegroundColor DarkGray
        Write-Host ""
        while ($true) {
            $serverInput = Read-Host "  Server(s)"
            if (-not $serverInput) { break }
            $parsed = $serverInput -split '[,;\s]+' | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }
            $servers += @($parsed)
        }
    }

    if (@($servers).Count -eq 0) {
        Write-Host "  No servers specified." -ForegroundColor Yellow
        return
    }

    [string[]]$servers = @($servers | Select-Object -Unique)
    [string[]]$invalidServers = @($servers | Where-Object { -not (Test-ValidServerName $_) })
    if ($invalidServers.Count -gt 0) {
        Write-Host "  ⚠ Invalid server name(s) removed: $($invalidServers -join ', ')" -ForegroundColor Yellow
        [string[]]$servers = @($servers | Where-Object { Test-ValidServerName $_ })
    }
    if (@($servers).Count -eq 0) {
        Write-Host "  No valid servers remaining." -ForegroundColor Red
        return
    }
    Write-Host ""
    Write-Host "  Enter admin credentials for remote servers:" -ForegroundColor Cyan
    $cred = Get-Credential -Message "Remote Server Admin"

    $passCount = 0; $failCount = 0
    foreach ($srv in $servers) {
        Write-Host "  ──────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  Checking: $srv" -ForegroundColor White
        try {
            $prereq = Test-ArcPrerequisites -ComputerName $srv -Credential $cred `
                                            -ProxyServer $ArcConfig.ProxyServer
            Show-PreReqResults -Result $prereq
            if ($prereq.OverallPass) { $passCount++ } else { $failCount++ }
        }
        catch {
            Write-Host "    ✖ Error: $($_.Exception.Message)" -ForegroundColor Red
            $failCount++
        }
    }

    Write-Host "  ══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Results: $passCount PASSED | $failCount FAILED | Total: $($servers.Count)" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Yellow' })
    Write-Host ""
    Read-Host "  Press Enter to return to menu"
}

# ─── Interactive Menu ───────────────────────────────────────────────────────────

function Show-Menu {
    Show-Banner

    Write-Host "  SELECT MODE:" -ForegroundColor White
    Write-Host ""
    Write-Host "    [1]  Onboard Servers to Azure Arc (Recommended)" -ForegroundColor Green
    Write-Host "         Enter targets  ->  PreReq check  ->  Install  ->  Connect"
    Write-Host "         Live TUI dashboard opens in a separate monitor window"
    Write-Host ""
    Write-Host "    [2]  PreReq Check Only" -ForegroundColor Cyan
    Write-Host "         Validate remote servers without onboarding"
    Write-Host ""
    Write-Host "    [3]  Setup Wizard" -ForegroundColor Yellow
    Write-Host "         Create Service Principal, configure Azure identity"
    Write-Host ""
    Write-Host "    [4]  Test Network Connectivity" -ForegroundColor Yellow
    Write-Host "         Test Azure Arc endpoint reachability from REMOTE target servers"
    Write-Host ""
    Write-Host "    [Q]  Quit" -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "  Enter selection"
    return $choice
}

# ─── Main ───────────────────────────────────────────────────────────────────────

if ($Mode) {
    switch ($Mode) {
        "Onboard"  { Start-InteractiveOnboarding -PresetTargets $Targets }
        "PreCheck" { Start-InteractivePreCheck -PresetTargets $Targets }
        "Setup"    { Start-SetupWizard }
    }
}
else {
    # Interactive menu loop
    do {
        $choice = Show-Menu
        switch ($choice) {
            "1" { Start-InteractiveOnboarding }
            "2" { Start-InteractivePreCheck }
            "3" { Start-SetupWizard }
            "4" { Test-ArcNetworkRequirements; Read-Host "  Press Enter to continue" }
            "Q" { Write-Host "`n  Goodbye!`n" -ForegroundColor Cyan; exit }
            "q" { Write-Host "`n  Goodbye!`n" -ForegroundColor Cyan; exit }
            default { Write-Host "  Invalid selection." -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}
