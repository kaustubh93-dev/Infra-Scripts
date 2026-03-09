<div align="center">

# Azure Arc Bootstrap Monitor

**A unified PowerShell TUI dashboard for monitoring Azure Arc onboarding across hybrid infrastructure**

[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)](#prerequisites)
[![Azure Arc](https://img.shields.io/badge/Azure-Arc-0078D4?logo=microsoftazure&logoColor=white)](#overview)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?logo=windows&logoColor=white)](#prerequisites)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [File Structure](#file-structure)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [1. Configure Your Environment](#1-configure-your-environment)
  - [2. Run the Setup Wizard](#2-run-the-setup-wizard-optional)
  - [3. Launch the Monitor](#3-launch-the-monitor)
- [Onboarding Modes](#onboarding-modes)
  - [Azure Local (Azure Stack HCI)](#azure-local-azure-stack-hci)
  - [VMware vSphere VMs](#vmware-vsphere-vms)
  - [On-Premises Servers](#on-premises-servers-windowslinux)
- [Dashboard Reference](#dashboard-reference)
- [Configuration Reference](#configuration-reference)
- [Command-Line Parameters](#command-line-parameters)
- [Network Requirements](#network-requirements)
- [Service Principal Setup](#service-principal-setup)
- [Logging](#logging)
- [Troubleshooting](#troubleshooting)

---

## Overview

Arc Bootstrap Monitor is a set of PowerShell scripts that provide a **real-time, text-based dashboard** for monitoring Azure Arc onboarding across three classes of hybrid infrastructure:

| Mode | Infrastructure Type | Connection Method | Onboarding Mechanism |
|------|---------------------|-------------------|----------------------|
| **Azure Local** | Azure Stack HCI cluster nodes | WinRM (PS Remoting) | `Invoke-AzStackHciArcInitialization` via `AzsHCI.ARCInstaller` |
| **VMware** | vSphere virtual machines | PowerCLI (`Invoke-VMScript`) | `azcmagent connect` with Service Principal |
| **On-Prem** | Physical & virtual Windows/Linux servers | WinRM or SSH | `azcmagent connect` with Service Principal |

The dashboard renders directly in your terminal and includes:

- Animated header with spinner indicator
- Per-node status table with color-coded phase tracking
- Visual download progress bars per node
- Events panel surfacing reboots, errors, and warnings
- Auto-refresh with configurable polling interval
- Structured log files written per day

> **Design influence** — The TUI layout mirrors the bootstrap monitor used in native Azure Local deployments (animated header → stats bar → status table → progress → events → footer). This project extends that pattern to VMware and general on-premises servers.

---

## Architecture

```
Start-ArcMonitor.ps1           ← Interactive menu launcher / CLI entry point
        │
        ├── ArcMonitor-Config.ps1      ← Centralized configuration (edit first)
        ├── ArcMonitor-TUI.ps1         ← Shared TUI rendering engine
        │
        ├── ArcMonitor-AzureLocal.ps1  ← Azure Local (Azure Stack HCI) monitor
        ├── ArcMonitor-VMware.ps1      ← VMware vSphere monitor
        └── ArcMonitor-OnPrem.ps1      ← General on-prem servers monitor
```

**Data flow per poll cycle:**

```
┌─────────────┐     WinRM / SSH / PowerCLI     ┌────────────────┐
│  Management  │ ─────────────────────────────► │  Target Nodes  │
│   Station    │ ◄───────────────────────────── │  (Servers/VMs) │
│              │        Status response          └────────────────┘
│  ArcMonitor  │
│   Scripts    │──► Render-ArcDashboard ──► Terminal (TUI)
│              │──► Write-ArcLog        ──► Logs/*.log
└─────────────┘
```

Each monitor script follows the same lifecycle:

1. **Load** — Dot-source `ArcMonitor-TUI.ps1` and `ArcMonitor-Config.ps1`.
2. **Authenticate** — Prompt for or accept credentials (node admin, vCenter, SSH).
3. **Poll** — Query each target for agent/bootstrap status via the appropriate protocol.
4. **Render** — Pass collected state to `Render-ArcDashboard` for terminal output.
5. **Repeat** — Sleep for the configured poll interval, then loop until all nodes finish or max polls are reached.

---

## File Structure

```
ArcMonitor/
├── Start-ArcMonitor.ps1          Main launcher — interactive menu or -Mode parameter
├── ArcMonitor-Config.ps1         Configuration — Azure identity, node lists, settings
├── ArcMonitor-TUI.ps1            TUI engine — header, table, progress bars, events
├── ArcMonitor-AzureLocal.ps1     Azure Local bootstrap + Arc registration monitor
├── ArcMonitor-VMware.ps1         VMware vSphere VM onboarding monitor
├── ArcMonitor-OnPrem.ps1         On-prem Windows/Linux server onboarding monitor
├── README.md                     This file
└── Logs/                         Auto-created — daily log files (ArcMonitor_YYYYMMDD.log)
```

---

## Prerequisites

### All Modes

| Requirement | Details |
|---|---|
| **PowerShell** | 5.1 or later. PowerShell 7+ recommended for SSH support. |
| **Azure subscription** | Contributor **and** User Access Administrator roles on the target subscription. |
| **Service Principal** | Application registration with **Azure Connected Machine Onboarding** role. See [Service Principal Setup](#service-principal-setup). |
| **Network** | Management station and all target servers must reach Azure Arc endpoints. See [Network Requirements](#network-requirements). |

### Azure Local (Azure Stack HCI)

| Requirement | Details |
|---|---|
| `AzsHCI.ARCInstaller` module | Installed on each HCI node (the script can install it automatically). |
| `Az.Accounts`, `Az.ConnectedMachine`, `Az.Resources` | Required for token acquisition and Arc operations. |
| WinRM / PS Remoting | Enabled between the management station and every cluster node. |
| Azure Local OS | Nodes must be running a supported Azure Local (Azure Stack HCI) build. |

### VMware vSphere

| Requirement | Details |
|---|---|
| `VMware.PowerCLI` module | Auto-installed if missing on first run. |
| vCenter credentials | Account with **Guest Operations** privileges on target VMs. |
| VMware Tools | Must be installed and running inside each target VM. |
| Guest OS credentials | Admin (Windows) or root/sudo-capable (Linux) account on each VM. |

### On-Premises Servers (Windows / Linux)

| Requirement | Details |
|---|---|
| **Windows** | WinRM enabled on target. Run `Enable-PSRemoting -Force` on each server. |
| **Linux** | SSH access from management station. Key-based auth recommended. |
| Supported OS | Windows Server 2012 R2+, Ubuntu 18.04+, RHEL 7+, SLES 15+, Debian 10+. |

---

## Getting Started

### 1. Configure Your Environment

Open `ArcMonitor-Config.ps1` in your editor and fill in the required values:

```powershell
notepad .\ArcMonitor\ArcMonitor-Config.ps1
```

At minimum you must set:

```powershell
$ArcConfig = @{
    TenantId       = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    SubscriptionId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ResourceGroup  = "rg-arc-onboarding"
    Location       = "eastus"

    ServicePrincipal = @{
        AppId  = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        Secret = "<your-service-principal-secret>"
    }
}
```

Then populate the server/node list for the mode you intend to use (`$AzureLocalConfig.Nodes`, `$VMwareConfig`, or `$OnPremConfig.Servers`).

### 2. Run the Setup Wizard (optional)

The built-in wizard automates Service Principal creation and validates prerequisites:

```powershell
.\ArcMonitor\Start-ArcMonitor.ps1 -Mode Setup
```

The wizard performs five steps:

1. **Check prerequisites** — Verifies Azure CLI and Az PowerShell module availability.
2. **Authenticate** — Opens an interactive Azure login (`Connect-AzAccount`).
3. **Create Service Principal** — Generates a new SP with Contributor + Azure Connected Machine Onboarding roles.
4. **Create resource group** — Prompts for name and region, creates if missing.
5. **Outputs credentials** — Displays the App ID, Secret, and Tenant ID for you to save and paste into `ArcMonitor-Config.ps1`.

> ⚠️ **Save the secret immediately** — it cannot be retrieved after creation.

### 3. Launch the Monitor

**Interactive mode** — presents a numbered menu:

```powershell
.\ArcMonitor\Start-ArcMonitor.ps1
```

**Direct mode** — skip the menu and run a specific monitor:

```powershell
# Azure Local (Azure Stack HCI)
.\ArcMonitor\Start-ArcMonitor.ps1 -Mode AzureLocal

# VMware vSphere
.\ArcMonitor\Start-ArcMonitor.ps1 -Mode VMware

# On-prem Windows/Linux servers
.\ArcMonitor\Start-ArcMonitor.ps1 -Mode OnPrem

# Run all modes sequentially
.\ArcMonitor\Start-ArcMonitor.ps1 -Mode All
```

**Run individual monitor scripts directly:**

```powershell
.\ArcMonitor\ArcMonitor-AzureLocal.ps1 -Nodes "hci-01","hci-02" -PollInterval 30
.\ArcMonitor\ArcMonitor-VMware.ps1 -VMNames "vm-web-01","vm-db-01"
.\ArcMonitor\ArcMonitor-OnPrem.ps1 -ServerList "srv-app-01","srv-linux-01"
```

---

## Onboarding Modes

### Azure Local (Azure Stack HCI)

This mode monitors the full Azure Local bootstrap and Arc initialization lifecycle, which involves multi-phase operations across cluster nodes.

**Process flow:**

```
Step 1   Install PS modules on each node (AzsHCI.ARCInstaller, Az.Accounts, etc.)
Step 2   Authenticate to Azure (Connect-AzAccount)
Step 3   Acquire ARM access token
Step 4   Run Invoke-AzStackHciArcInitialization on each node
Step 5   Monitor bootstrap phases:
           NetworkConfig → RemoteConfig → WebProxy → TimeServer →
           HostName → ArcConfiguration
Step 6   Monitor Arc configuration sub-phases:
           ArtifactsUpload → ConnectivityValidation →
           ArcRegistration → ArcExtensionInstall
Step 7   Nodes reboot as required during OS/firmware updates
Step 8   Verify registration: Azure Portal → Azure Arc → Servers
```

**Dashboard columns:**

| Column | Values |
|--------|--------|
| Node | Hostname of the HCI node |
| Bootstrap | `NotStarted` → `InProgress` → `Succeeded` / `Failed` |
| Update | `NotApplicable` / `Install` / `RebootPending` / `Succeeded` |
| Arc Reg | `NotStarted` → `InProgress` → `Succeeded` / `Failed` |
| Agent | `NotInstalled` / `Connected` / `Disconnected` |

**Status polling** uses `Get-AzStackHciArcIntegration` when the `AzsHCI.ARCInstaller` module is available, and falls back to registry markers + `azcmagent show --json` otherwise.

**Example:**

```powershell
.\ArcMonitor\ArcMonitor-AzureLocal.ps1 `
    -Nodes "tplabs-01-n01","tplabs-01-n02" `
    -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroup "rg-hci-arc" `
    -Location "eastus" `
    -PollInterval 60
```

---

### VMware vSphere VMs

This mode discovers VMs in a vCenter inventory and deploys the Azure Connected Machine agent via PowerCLI guest operations (`Invoke-VMScript`).

**Process flow:**

```
Step 1   Connect to vCenter Server via PowerCLI
Step 2   Discover target VMs by folder, tag, name list, or config file
Step 3   For each VM (via Invoke-VMScript):
           a. Download the Azure Connected Machine agent
           b. Install the agent silently
           c. Run  azcmagent connect  with Service Principal credentials
Step 4   Monitor agent status (Connected / Disconnected / Error)
Step 5   Verify: Azure Portal → Azure Arc → Servers
```

**VM discovery options:**

| Parameter | Behavior |
|-----------|----------|
| `-VMNames "vm01","vm02"` | Onboard specific VMs by name |
| `-VMFolder "Production VMs"` | Onboard all VMs in a vCenter folder |
| `-VMTag "arc-onboard"` | Onboard VMs with a specific vSphere tag |
| Config file `$VMwareConfig.TargetVMs` | Onboard VMs listed in configuration |
| *(no filter)* | Discovers all powered-on VMs with running VMware Tools |

**Dashboard columns:**

| Column | Values |
|--------|--------|
| VM Name | vSphere VM display name |
| Download | `Pending` → `InProgress` → `Succeeded` |
| Install | `Pending` → `InProgress` → `Succeeded` |
| Arc Reg | `Pending` → `InProgress` → `Succeeded` / `Failed` |
| Agent | `Connected` / `Disconnected` / `────` (not installed) |

**Example:**

```powershell
.\ArcMonitor\ArcMonitor-VMware.ps1 `
    -vCenterServer "vcenter.corp.local" `
    -VMFolder "Production VMs" `
    -PollInterval 30
```

---

### On-Premises Servers (Windows/Linux)

This mode deploys the Arc agent to general-purpose servers via native remote execution — WinRM for Windows and SSH for Linux.

**Process flow:**

```
Step 1   Download the Azure Connected Machine agent
           Windows: .msi from https://aka.ms/AzureConnectedMachineAgent
           Linux:   install script from https://aka.ms/azcmagent
Step 2   Install silently (msiexec /qn on Windows, bash script on Linux)
Step 3   Run  azcmagent connect  with Service Principal credentials
Step 4   Monitor agent status → Connected = success
Step 5   Verify: Azure Portal → Azure Arc → Servers
```

**Server definition format** (in `ArcMonitor-Config.ps1`):

```powershell
$OnPremConfig = @{
    Servers = @(
        @{ Name = "srv-app-01";   IP = "10.1.0.21"; OS = "Windows"; Protocol = "WinRM" }
        @{ Name = "srv-linux-01"; IP = "10.1.0.31"; OS = "Linux";   Protocol = "SSH"   }
    )
    SSHKeyPath = "~/.ssh/id_rsa"
    SSHUser    = "arcadmin"
}
```

**Dashboard columns:**

| Column | Values |
|--------|--------|
| Server | Hostname of the target server |
| OS | `Windows` / `Linux` |
| Download | `Pending` → `Succeeded` |
| Install | `Pending` → `InProgress` → `Succeeded` |
| Arc Reg | `Pending` → `InProgress` → `Succeeded` / `Failed` |
| Agent | `Connected` / `Disconnected` / `Error` |

**Example:**

```powershell
.\ArcMonitor\ArcMonitor-OnPrem.ps1 `
    -ServerList "srv-app-01","srv-app-02","srv-linux-01" `
    -PollInterval 45
```

---

## Dashboard Reference

The TUI dashboard is rendered by `ArcMonitor-TUI.ps1` and shared across all three modes. Each poll cycle clears the screen and redraws the following panels:

### 1. Header

```
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │                          ARC BOOTSTRAP MONITOR —                            │
  └──────────────────────────────────────────────────────────────────────────────┘
```

The spinner character (`—`, `\`, `|`, `/`) cycles on every refresh to indicate liveness.

### 2. Stats Bar

```
  Nodes: 2  │  Elapsed: 00:09:50  │  Poll: 10/120  │  Mode: Azure Local
```

### 3. Status Table

Columns adapt to the active mode. Values are color-coded:

| Color | Meaning |
|-------|---------|
| 🟢 Green | `Succeeded`, `Connected`, `Complete`, `Done` |
| 🟡 Yellow | `InProgress`, `Install`, `Downloading`, `Registering` |
| 🟠 Dark Yellow | `Pending` |
| ⚪ Gray | `NotStarted` |
| 🔵 Cyan | `RebootPending` |
| 🔴 Red | `Failed`, `Error`, `Disconnected` |

### 4. Download Progress

```
  ┌─ DOWNLOAD PROGRESS ──────────────────────────────────────────────
    n01:    [██████████████████████████████] 100%  5059.65 MB  Complete
    n02:    [██████████████████████████████] 100%  5059.65 MB  Complete
```

Green bar at 100%, yellow above 50%, dark yellow below 50%.

### 5. Events Panel

```
  ┌─ EVENTS ──────────────────────────────────────────────────────────
    ▲ n01: REBOOT PENDING
    ▲ n02: REBOOT PENDING
```

| Icon | Severity |
|------|----------|
| `○` | Info |
| `▲` | Warning |
| `✖` | Error |
| `◆` | Critical |

### 6. Footer

```
  Last refresh: 23:51:31  │  Next: 60s  │  Ctrl+C to exit
```

---

## Configuration Reference

All configuration lives in `ArcMonitor-Config.ps1`. The file exports a `$Global:ArcMonitorConfig` hashtable consumed by every module.

### Azure Identity (`$ArcConfig`)

| Key | Type | Description |
|-----|------|-------------|
| `TenantId` | `string` | Microsoft Entra ID (Azure AD) tenant ID. |
| `SubscriptionId` | `string` | Target Azure subscription ID. |
| `ResourceGroup` | `string` | Resource group for Arc-enabled server resources. |
| `Location` | `string` | Azure region (e.g., `eastus`, `westeurope`). |
| `Cloud` | `string` | `AzureCloud`, `AzureUSGovernment`, or `AzureChinaCloud`. |
| `ServicePrincipal.AppId` | `string` | Service Principal application (client) ID. |
| `ServicePrincipal.Secret` | `string` | Service Principal client secret. Use Key Vault in production. |
| `ProxyServer` | `string` / `$null` | HTTP proxy URL (e.g., `http://proxy.corp.local:8080`). |

### Azure Local Nodes (`$AzureLocalConfig`)

| Key | Type | Description |
|-----|------|-------------|
| `Nodes` | `array` | Array of `@{ Name; IP }` hashtables, one per HCI node. |
| `Credential` | `PSCredential` / `$null` | Set at runtime via `Get-Credential` if null. |
| `SolutionVersion` | `string` / `$null` | Target solution version. Leave null for latest. |

### VMware (`$VMwareConfig`)

| Key | Type | Description |
|-----|------|-------------|
| `vCenterServer` | `string` | vCenter Server FQDN or IP. |
| `vCenterCred` | `PSCredential` / `$null` | vCenter credentials. Prompted at runtime if null. |
| `GuestCred` | `PSCredential` / `$null` | Guest OS credentials. Prompted at runtime if null. |
| `TargetVMs` | `array` | Array of `@{ Name; GuestOS }` hashtables. |
| `VMFilter.Folder` | `string` / `$null` | vCenter folder name to filter by. |
| `VMFilter.Tag` | `string` / `$null` | vSphere tag to filter by. |
| `VMFilter.Cluster` | `string` / `$null` | vSphere cluster to filter by. |

### On-Prem Servers (`$OnPremConfig`)

| Key | Type | Description |
|-----|------|-------------|
| `Servers` | `array` | Array of `@{ Name; IP; OS; Protocol }` hashtables. OS: `Windows`/`Linux`. Protocol: `WinRM`/`SSH`. |
| `WinRMCredential` | `PSCredential` / `$null` | Windows admin credential. Prompted at runtime if null. |
| `SSHKeyPath` | `string` | Path to SSH private key for Linux servers. |
| `SSHUser` | `string` | SSH username for Linux servers. |

### Monitor Settings (`$MonitorSettings`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `PollIntervalSeconds` | `int` | `60` | Seconds between status polls. |
| `MaxPolls` | `int` | `120` | Maximum poll cycles before the monitor exits. |
| `LogPath` | `string` | `.\ArcMonitor\Logs` | Directory for log files. |
| `EnableLogging` | `bool` | `$true` | Write structured logs to disk. |
| `ShowDownloadProgress` | `bool` | `$true` | Display the download progress panel. |
| `ShowEvents` | `bool` | `$true` | Display the events panel. |
| `AnimateHeader` | `bool` | `$true` | Animate the spinner in the header. |

---

## Command-Line Parameters

### `Start-ArcMonitor.ps1` (Launcher)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Mode` | `string` | Interactive menu | `AzureLocal`, `VMware`, `OnPrem`, `All`, or `Setup`. |
| `-PollInterval` | `int` | `60` | Seconds between polls. Passed to the selected monitor. |
| `-MaxPolls` | `int` | `120` | Maximum poll cycles. Passed to the selected monitor. |

### `ArcMonitor-AzureLocal.ps1`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Nodes` | `string[]` | Config file | Hostnames or IPs of Azure Local nodes. |
| `-SubscriptionId` | `string` | Config file | Azure subscription ID. |
| `-TenantId` | `string` | Config file | Azure tenant ID. |
| `-ResourceGroup` | `string` | Config file | Target resource group. |
| `-Location` | `string` | `eastus` | Azure region. |
| `-Credential` | `PSCredential` | Prompted | Node admin credential. |
| `-PollInterval` | `int` | `60` | Seconds between polls. |
| `-MaxPolls` | `int` | `120` | Maximum poll cycles. |

### `ArcMonitor-VMware.ps1`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-vCenterServer` | `string` | Config file | vCenter Server FQDN. |
| `-vCenterCredential` | `PSCredential` | Prompted | vCenter admin credential. |
| `-GuestCredential` | `PSCredential` | Prompted | Guest OS credential. |
| `-VMFolder` | `string` | — | Filter VMs by vCenter folder. |
| `-VMTag` | `string` | — | Filter VMs by vSphere tag. |
| `-VMNames` | `string[]` | — | Explicit list of VM names. |
| `-PollInterval` | `int` | `60` | Seconds between polls. |
| `-MaxPolls` | `int` | `120` | Maximum poll cycles. |

### `ArcMonitor-OnPrem.ps1`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ServerList` | `string[]` | Config file | Hostnames of target servers. |
| `-WinCredential` | `PSCredential` | Prompted | Windows admin credential. |
| `-SSHUser` | `string` | Config file | SSH username for Linux servers. |
| `-SSHKeyPath` | `string` | Config file | Path to SSH private key. |
| `-PollInterval` | `int` | `60` | Seconds between polls. |
| `-MaxPolls` | `int` | `120` | Maximum poll cycles. |

---

## Network Requirements

All target servers **and** the management station must have outbound HTTPS (TCP 443) access to the following endpoints:

| Endpoint | Purpose |
|----------|---------|
| `management.azure.com` | Azure Resource Manager API |
| `login.microsoftonline.com` | Microsoft Entra ID (Azure AD) authentication |
| `*.his.arc.azure.com` | Azure Arc Hybrid Identity Service |
| `gbl.his.arc.azure.com` | Azure Arc global metadata |
| `*.guestconfiguration.azure.com` | Azure Arc Guest Configuration |
| `aka.ms` | Microsoft download redirect service |
| `packages.microsoft.com` | Linux agent packages (APT/YUM) |
| `download.microsoft.com` | Windows agent MSI download |

**Test connectivity** from the management station:

```powershell
.\ArcMonitor\Start-ArcMonitor.ps1 -Mode Setup
# Then select option [5] — Test Network Connectivity
```

Or manually:

```powershell
Test-NetConnection -ComputerName management.azure.com -Port 443
Test-NetConnection -ComputerName login.microsoftonline.com -Port 443
Test-NetConnection -ComputerName his.arc.azure.com -Port 443
```

If servers sit behind a proxy, set `$ArcConfig.ProxyServer` in the config file.

---

## Service Principal Setup

Azure Arc onboarding at scale requires a Service Principal instead of interactive user authentication.

### Option A: Setup Wizard (recommended)

```powershell
.\ArcMonitor\Start-ArcMonitor.ps1 -Mode Setup
```

The wizard creates the SP, assigns roles, and prints credentials for you.

### Option B: Azure CLI

```bash
az ad sp create-for-rbac \
    --name "sp-arc-onboarding" \
    --role "Azure Connected Machine Onboarding" \
    --scopes /subscriptions/<SUBSCRIPTION_ID>
```

### Option C: Azure PowerShell

```powershell
Connect-AzAccount
$sp = New-AzADServicePrincipal `
    -DisplayName "sp-arc-onboarding" `
    -Role "Contributor" `
    -Scope "/subscriptions/<SUBSCRIPTION_ID>"

# Assign the Arc-specific role
New-AzRoleAssignment `
    -ApplicationId $sp.AppId `
    -RoleDefinitionName "Azure Connected Machine Onboarding" `
    -Scope "/subscriptions/<SUBSCRIPTION_ID>"

# Output credentials
$sp.AppId                          # → ServicePrincipal.AppId
$sp.PasswordCredentials.SecretText # → ServicePrincipal.Secret
(Get-AzContext).Tenant.Id          # → TenantId
```

Paste the App ID, Secret, and Tenant ID into `ArcMonitor-Config.ps1`.

> ⚠️ **Production guidance**: Store the secret in Azure Key Vault. Do not commit secrets to source control.

---

## Logging

When `$MonitorSettings.EnableLogging` is `$true` (the default), every monitor writes structured logs to disk:

| Setting | Default Value |
|---------|---------------|
| Log directory | `.\ArcMonitor\Logs` |
| Log file naming | `ArcMonitor_YYYYMMDD.log` (one file per day) |
| Format | `YYYY-MM-DD HH:MM:SS [LEVEL] Message` |

**Log levels:**

| Level | Usage |
|-------|-------|
| `INFO` | Normal operations — monitor start/stop, poll summaries |
| `WARN` | Non-fatal issues — poll timeouts, transient connection errors |
| `ERROR` | Failures — connection refused, bootstrap/registration failure |

**Example log entries:**

```
2026-03-09 12:15:00 [INFO] Azure Local monitor started for 2 nodes
2026-03-09 12:16:00 [INFO] Poll 1 : Running=2 Succeeded=0 Failed=0
2026-03-09 12:17:00 [WARN] Failed to poll hci-node-02 : WinRM connection timeout
2026-03-09 12:30:00 [INFO] Azure Local monitor completed — 2 succeeded, 0 failed
```

---

## Troubleshooting

### Connection issues

| Symptom | Cause | Resolution |
|---------|-------|------------|
| WinRM: "Access is denied" | Credential or permission issue | Verify the credential has local admin rights on the target. |
| WinRM: "The WinRM client cannot process the request" | WinRM not enabled or firewall blocking | Run `Enable-PSRemoting -Force` on the target. Ensure TCP 5985/5986 is open. |
| SSH: "Connection refused" | SSHD not running or port blocked | Verify `sshd` is running and TCP 22 is open. |
| PowerCLI: "Cannot connect to vCenter" | Credential, network, or certificate issue | Verify vCenter FQDN resolves. The script sets `InvalidCertificateAction Ignore`. |

### Agent issues

| Symptom | Cause | Resolution |
|---------|-------|------------|
| Agent status: `Disconnected` | Network connectivity to Azure Arc endpoints lost | Check firewall/proxy rules. Re-run `azcmagent connect`. |
| Download progress stuck at 0% | Target cannot reach `aka.ms` or `download.microsoft.com` | Verify outbound HTTPS. Check proxy settings. |
| Bootstrap: `Failed` | Module version mismatch or insufficient permissions | Update `AzsHCI.ARCInstaller` to latest. Verify Azure role assignments. |
| `azcmagent connect` error 1 | Invalid Service Principal credentials | Verify AppId, Secret, and TenantId in config. Ensure SP is not expired. |

### General tips

- **Increase poll speed during debugging**: `-PollInterval 15` for faster feedback.
- **Check logs first**: Review `.\ArcMonitor\Logs\ArcMonitor_<today>.log`.
- **Test endpoints before onboarding**: Use the network test (option 5 in the main menu).
- **Re-run is safe**: Both `Invoke-AzStackHciArcInitialization` and `azcmagent connect` are idempotent when the node is already registered.

---

## License

Internal use. Customize and extend for your environment.
