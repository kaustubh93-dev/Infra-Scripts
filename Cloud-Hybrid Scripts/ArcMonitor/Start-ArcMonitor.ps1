<#
.SYNOPSIS
    Arc Onboarding Orchestrator — Unified launcher for all server types
.DESCRIPTION
    Interactive menu-driven launcher that lets you choose which type of servers
    to onboard to Azure Arc, then runs the appropriate monitor.
.EXAMPLE
    .\Start-ArcMonitor.ps1               # Interactive menu
    .\Start-ArcMonitor.ps1 -Mode AzureLocal
    .\Start-ArcMonitor.ps1 -Mode VMware
    .\Start-ArcMonitor.ps1 -Mode OnPrem
    .\Start-ArcMonitor.ps1 -Mode All      # Monitor all types in sequence
#>

[CmdletBinding()]
param(
    [ValidateSet("AzureLocal", "VMware", "OnPrem", "All", "Setup")]
    [string]$Mode,
    [int]$PollInterval = 60,
    [int]$MaxPolls = 120
)

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# ─── Banner ─────────────────────────────────────────────────────────────────────

function Show-Banner {
    Clear-Host
    Write-Host @"

  ╔══════════════════════════════════════════════════════════════════════════════╗
  ║                                                                            ║
  ║     █████╗ ██████╗  ██████╗    ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ║
  ║    ██╔══██╗██╔══██╗██╔════╝    ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝ ║
  ║    ███████║██████╔╝██║         ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║    ║
  ║    ██╔══██║██╔══██╗██║         ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║    ║
  ║    ██║  ██║██║  ██║╚██████╗    ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║    ║
  ║    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ║
  ║                                                                            ║
  ║          Azure Arc Bootstrap Monitor — Unified Onboarding Dashboard        ║
  ║                                                                            ║
  ╚══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
}

# ─── Setup Wizard ───────────────────────────────────────────────────────────────

function Start-SetupWizard {
    <#
    .SYNOPSIS
        Interactive setup to create Service Principal and validate prerequisites.
    #>
    Write-Host "`n  ── AZURE ARC SETUP WIZARD ──────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    # Step 1: Check Azure CLI / Az Module
    Write-Host "  [1/5] Checking Azure prerequisites..." -ForegroundColor Yellow
    $hasAzCLI   = Get-Command az -ErrorAction SilentlyContinue
    $hasAzModule = Get-Module Az.Accounts -ListAvailable -ErrorAction SilentlyContinue

    if ($hasAzCLI)    { Write-Host "    ✓ Azure CLI found" -ForegroundColor Green }
    else              { Write-Host "    ○ Azure CLI not found (optional)" -ForegroundColor DarkGray }
    if ($hasAzModule) { Write-Host "    ✓ Az PowerShell module found" -ForegroundColor Green }
    else {
        Write-Host "    ▲ Installing Az.Accounts module..." -ForegroundColor Yellow
        Install-Module Az.Accounts -Force -AllowClobber -Scope CurrentUser
    }

    # Step 2: Azure Login
    Write-Host "`n  [2/5] Authenticating to Azure..." -ForegroundColor Yellow
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

    # Step 3: Create Service Principal
    Write-Host "`n  [3/5] Creating Service Principal for Arc onboarding..." -ForegroundColor Yellow
    $spName = "sp-arc-onboarding-$(Get-Random -Maximum 9999)"

    try {
        $sp = New-AzADServicePrincipal -DisplayName $spName -Role "Contributor" `
                                        -Scope "/subscriptions/$($ctx.Subscription.Id)"

        Write-Host "    ✓ Service Principal created: $spName" -ForegroundColor Green
        Write-Host "    ► App ID:  $($sp.AppId)" -ForegroundColor White
        Write-Host "    ► Secret:  $($sp.PasswordCredentials.SecretText)" -ForegroundColor White
        Write-Host "    ► Tenant:  $($ctx.Tenant.Id)" -ForegroundColor White
        Write-Host ""
        Write-Host "    ⚠ SAVE THESE VALUES — the secret cannot be retrieved again!" -ForegroundColor Red

        # Also assign Azure Connected Machine Onboarding role
        New-AzRoleAssignment -ApplicationId $sp.AppId `
            -RoleDefinitionName "Azure Connected Machine Onboarding" `
            -Scope "/subscriptions/$($ctx.Subscription.Id)" -ErrorAction SilentlyContinue
        Write-Host "    ✓ Assigned 'Azure Connected Machine Onboarding' role" -ForegroundColor Green
    }
    catch {
        Write-Host "    ✖ SP creation failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Step 4: Create Resource Group
    Write-Host "`n  [4/5] Resource Group setup..." -ForegroundColor Yellow
    $rgName = Read-Host "    Enter resource group name (default: rg-arc-onboarding)"
    if (-not $rgName) { $rgName = "rg-arc-onboarding" }
    $location = Read-Host "    Enter Azure region (default: eastus)"
    if (-not $location) { $location = "eastus" }

    try {
        $rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
        if (-not $rg) {
            New-AzResourceGroup -Name $rgName -Location $location | Out-Null
            Write-Host "    ✓ Created resource group: $rgName in $location" -ForegroundColor Green
        } else {
            Write-Host "    ✓ Resource group exists: $rgName" -ForegroundColor Green
        }
    }
    catch { Write-Host "    ✖ $($_.Exception.Message)" -ForegroundColor Red }

    # Step 5: Update config
    Write-Host "`n  [5/5] Update ArcMonitor-Config.ps1 with these values." -ForegroundColor Yellow
    Write-Host "    File: $scriptRoot\ArcMonitor-Config.ps1" -ForegroundColor White
    Write-Host ""
    Write-Host "  ── Setup complete! ──────────────────────────────────" -ForegroundColor Green
    Write-Host ""
    Read-Host "  Press Enter to return to main menu"
}

# ─── Network Validation ─────────────────────────────────────────────────────────

function Test-ArcNetworkRequirements {
    <#
    .SYNOPSIS
        Tests network connectivity to Azure Arc required endpoints.
    #>
    param([string]$FromServer = "localhost")

    Write-Host "`n  Testing Azure Arc network requirements..." -ForegroundColor Yellow
    $endpoints = @(
        @{ Name = "Azure Resource Manager";   Host = "management.azure.com";              Port = 443 }
        @{ Name = "Azure AD / Entra ID";      Host = "login.microsoftonline.com";         Port = 443 }
        @{ Name = "Azure Arc HIS";            Host = "his.arc.azure.com";                 Port = 443 }
        @{ Name = "Guest Configuration";      Host = "guestconfiguration.azure.com";      Port = 443 }
        @{ Name = "Azure Arc Data";           Host = "gbl.his.arc.azure.com";             Port = 443 }
        @{ Name = "Download (MS)";            Host = "aka.ms";                            Port = 443 }
        @{ Name = "Packages (Microsoft)";     Host = "packages.microsoft.com";            Port = 443 }
    )

    foreach ($ep in $endpoints) {
        try {
            $result = Test-NetConnection -ComputerName $ep.Host -Port $ep.Port -WarningAction SilentlyContinue
            if ($result.TcpTestSucceeded) {
                Write-Host "    ✓ $($ep.Name.PadRight(28)) $($ep.Host)" -ForegroundColor Green
            } else {
                Write-Host "    ✖ $($ep.Name.PadRight(28)) $($ep.Host) — BLOCKED" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "    ▲ $($ep.Name.PadRight(28)) $($ep.Host) — Cannot test" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# ─── Interactive Menu ───────────────────────────────────────────────────────────

function Show-Menu {
    Show-Banner

    Write-Host "  SELECT ONBOARDING MODE:" -ForegroundColor White
    Write-Host ""
    Write-Host "    [1]  Azure Local (Azure Stack HCI)" -ForegroundColor Cyan
    Write-Host "         Bootstrap + Arc registration for HCI cluster nodes"
    Write-Host ""
    Write-Host "    [2]  VMware vSphere VMs" -ForegroundColor Cyan
    Write-Host "         Deploy Arc agent to VMs via PowerCLI guest operations"
    Write-Host ""
    Write-Host "    [3]  On-Premises Servers (Windows/Linux)" -ForegroundColor Cyan
    Write-Host "         Deploy Arc agent via WinRM (Windows) or SSH (Linux)"
    Write-Host ""
    Write-Host "    [4]  Setup Wizard" -ForegroundColor Yellow
    Write-Host "         Create Service Principal, validate prerequisites"
    Write-Host ""
    Write-Host "    [5]  Test Network Connectivity" -ForegroundColor Yellow
    Write-Host "         Verify Azure Arc endpoint reachability"
    Write-Host ""
    Write-Host "    [Q]  Quit" -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "  Enter selection"
    return $choice
}

# ─── Main ───────────────────────────────────────────────────────────────────────

if ($Mode) {
    switch ($Mode) {
        "AzureLocal" { & "$scriptRoot\ArcMonitor-AzureLocal.ps1" -PollInterval $PollInterval -MaxPolls $MaxPolls }
        "VMware"     { & "$scriptRoot\ArcMonitor-VMware.ps1"     -PollInterval $PollInterval -MaxPolls $MaxPolls }
        "OnPrem"     { & "$scriptRoot\ArcMonitor-OnPrem.ps1"     -PollInterval $PollInterval -MaxPolls $MaxPolls }
        "Setup"      { Start-SetupWizard }
        "All"        {
            Write-Host "  Running all monitors sequentially..." -ForegroundColor Cyan
            & "$scriptRoot\ArcMonitor-AzureLocal.ps1" -PollInterval $PollInterval -MaxPolls $MaxPolls
            & "$scriptRoot\ArcMonitor-VMware.ps1"     -PollInterval $PollInterval -MaxPolls $MaxPolls
            & "$scriptRoot\ArcMonitor-OnPrem.ps1"     -PollInterval $PollInterval -MaxPolls $MaxPolls
        }
    }
}
else {
    # Interactive menu loop
    do {
        $choice = Show-Menu
        switch ($choice) {
            "1" { & "$scriptRoot\ArcMonitor-AzureLocal.ps1" -PollInterval $PollInterval -MaxPolls $MaxPolls }
            "2" { & "$scriptRoot\ArcMonitor-VMware.ps1"     -PollInterval $PollInterval -MaxPolls $MaxPolls }
            "3" { & "$scriptRoot\ArcMonitor-OnPrem.ps1"     -PollInterval $PollInterval -MaxPolls $MaxPolls }
            "4" { Start-SetupWizard }
            "5" { Test-ArcNetworkRequirements; Read-Host "  Press Enter to continue" }
            "Q" { Write-Host "`n  Goodbye!`n" -ForegroundColor Cyan; exit }
            "q" { Write-Host "`n  Goodbye!`n" -ForegroundColor Cyan; exit }
            default { Write-Host "  Invalid selection." -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}
