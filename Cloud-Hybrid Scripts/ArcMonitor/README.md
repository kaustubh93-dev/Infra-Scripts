# Azure Arc Onboarding Monitor (ArcMonitor)

A unified PowerShell framework for onboarding and monitoring Azure Arc-enabled servers across **all platforms** — VMware, Azure Local (HCI), Hyper-V, Physical, KVM, Nutanix — from a centralized management server.

> **Design principle**: Azure Arc onboarding doesn't care where a machine is hosted. One unified framework replaces platform-specific scripts. All checks run **remotely on the target**, never on the management server.

---

## Architecture

```
  MANAGEMENT SERVER                              TARGET SERVERS (remote)
  +--------------------------+                   +------------------------+
  | Start-ArcMonitor.ps1     |                   | node1-2k22 (HyperV)   |
  |   |                      |   WinRM/PSSession  | srv-app-01 (VMware)   |
  |   +-- ArcMonitor-Config  | ================> | srv-db-02  (Physical)  |
  |   +-- ArcMonitor-TUI     |   Remote checks    | hci-node-01 (AzLocal) |
  |   +-- PreReqCheck        |   Agent install     +------------------------+
  |   +-- Onboard            |   azcmagent connect
  |   |                      |
  |   +-> MonitorWindow.ps1  |  <-- Separate PS window (live TUI dashboard)
  |       (reads JSON state) |
  +--------------------------+
```

**Two-window design**:
- **Main window** — runs prereqs, installs agent, connects to Arc, shows detailed logs
- **Monitor window** — opens automatically, shows live TUI dashboard reading from a shared JSON state file. No install output pollutes the dashboard.

---

## File Structure

```
ArcMonitor/
  Start-ArcMonitor.ps1          Launcher + Setup Wizard + interactive menu
  ArcMonitor-Config.ps1         Azure identity, server lists, settings
  ArcMonitor-TUI.ps1            Dashboard rendering engine (ASCII-safe)
  ArcMonitor-PreReqCheck.ps1    Remote prerequisite validation + auto-fix
  ArcMonitor-Onboard.ps1        Unified onboarding (all platforms)
  ArcMonitor-MonitorWindow.ps1  Standalone TUI (separate window, reads JSON)
  README.md                     This file
  Logs/                         Auto-created: daily logs + onboard-state.json
```

---

## Quick Start

### 1. Configure Azure Identity

Run the **Setup Wizard** — it creates a Service Principal, picks a region, selects/creates a resource group, and saves everything directly into `ArcMonitor-Config.ps1`:

```powershell
.\Start-ArcMonitor.ps1 -Mode Setup
```

The wizard walks through 6 steps:
1. Install required Az modules (`Az.Accounts`, `Az.Resources`, `Az.ConnectedMachine`)
2. Authenticate to Azure (`Connect-AzAccount`)
3. Create or reuse a Service Principal (lists existing `sp-arc*` SPNs)
4. Select Azure region (popular list + full list)
5. Select or create a resource group
6. Save all values directly into `ArcMonitor-Config.ps1`

### 2. Onboard Servers

```powershell
# Interactive — prompts for target servers
.\Start-ArcMonitor.ps1

# Direct — pass targets on command line
.\Start-ArcMonitor.ps1 -Mode Onboard -Targets "srv01","srv02","srv03"
```

### 3. PreReq Check Only (no onboarding)

```powershell
.\Start-ArcMonitor.ps1 -Mode PreCheck -Targets "srv01","srv02"
```

---

## Onboarding Flow

```
Enter target servers
  |
  v
Quick reachability check (ICMP + WinRM port 5985)
  |
  v
Get admin credentials for remote servers
  |
  v
Validate config (block if placeholders remain)
  |
  v
+-- Monitor window opens (separate PS window, live TUI dashboard)
|
v  (Main window — detailed logs)
For each server:
  [1/4] Remote Prerequisite Checks (13 checks on TARGET)
        |-- PASS --> continue
        |-- FAIL --> Show remediation guidance + Microsoft docs
                     [F] Auto-fix | [S] Skip | [I] Ignore
  [2/4] Download + Install Azure Connected Machine Agent
  [3/4] azcmagent connect (Service Principal auth)
  [4/4] Verify HIMDS service
  |
  v
Monitor window shows final status, auto-closes after 30s
```

---

## Remote Prerequisite Checks

All 13 checks run **on the target server** via `Invoke-Command`, not on the management server:

| # | Check | What | Auto-Fix |
|---|-------|------|:--------:|
| 1 | **Reachability** | WinRM port 5985 TCP (5s timeout) | — |
| 2 | **Remote Session** | WinRM PSSession establishment | — |
| 3 | **Platform Detect** | VMware / HyperV / AzureLocal / Physical / KVM / Nutanix / AWS / GCP / Azure VM | — |
| 4 | **Azure VM Exclusion** | Azure IMDS check — auto-skip native Azure VMs | N/A |
| 5 | **OS Version** | Windows Server 2012+ or supported Linux | No |
| 6 | **PS Version** | PowerShell 5.0+ | Yes |
| 7 | **.NET Framework** | 4.6.2+ (Release >= 394802) | Yes |
| 8 | **TLS 1.2** | Registry + SecurityProtocol | **Yes** |
| 9 | **Admin Rights** | WindowsBuiltInRole::Administrator | No |
| 10 | **Disk Space** | 2 GB+ free on C: | **Yes** (temp cleanup) |
| 11 | **Existing Agent** | Skip if already Connected | — |
| 12 | **Azure Endpoints** | 9 required URLs via TcpClient (5s timeout each) | No |
| 13 | **Required Services** | WinRM, W32Time running | **Yes** |

### Auto-Remediation

When prereqs fail, the script offers `[F] Auto-fix` which can remotely:
- **Enable TLS 1.2** — sets registry keys + .NET strong crypto (reboot needed)
- **Start services** — sets WinRM/W32Time to Automatic and starts them
- **Clean disk space** — removes temp files from `%TEMP%`, `Windows\Temp`, SoftwareDistribution

For non-fixable issues (firewall, OS version, admin rights), detailed **remediation guidance** is shown with exact commands and **Microsoft documentation links**.

---

## Platform Auto-Detection

The framework auto-detects the hosting platform via `Win32_ComputerSystem.Manufacturer`:

| Manufacturer | Detected Platform |
|---|---|
| VMware, Inc. | VMware |
| Microsoft Corporation + Virtual Machine | HyperV |
| Microsoft Corporation + Azure IMDS responds | **Azure Native VM** (excluded) |
| Microsoft Corporation + Azure Stack | Azure Local (HCI) |
| QEMU | KVM |
| Nutanix | Nutanix |
| Amazon EC2 | AWS EC2 |
| Google | GCP |
| *(anything else, no hypervisor)* | Physical |

Azure native VMs are **automatically excluded** — they must not be onboarded to Arc.

---

## TUI Dashboard

The monitor window renders an ASCII-safe dashboard (works on PS 5.1 + all Windows Server versions):

```
  +--------------------------------------------------------------------------+
  |                    ARC ONBOARDING MONITOR /                              |
  +--------------------------------------------------------------------------+
  Live - PreReq | Install | Connect | Verify

  Nodes: 3  |  Elapsed: 00:02:15  |  Poll: 45/720  |  Mode: On-Prem

  +------------------------+--------------+------------+--------------+--------------+
  | Server                 | Platform     | PreReq     | Install      | Agent        |
  +------------------------+--------------+------------+--------------+--------------+
  | node1-2k22             | HyperV       | Succeeded  | Succeeded    | Connected    |
  | srv-app-01             | VMware       | Succeeded  | Downloading  | ----         |
  | srv-db-02              | Physical     | InProgress | ----         | ----         |
  +------------------------+--------------+------------+--------------+--------------+

  +-- DOWNLOAD PROGRESS ------------------------------------------------
  |
  |  node1:    [##############################]  100%    0.00 MB  Succeeded
  |  srv-app:  [###############               ]   50%    0.00 MB  Downloading
  |

  +-- EVENTS -----------------------------------------------------------
  |
  |  [i] node1-2k22: Connected to Azure Arc
  |  [!] srv-db-02: PreReq check in progress
  |

  1 Running  |  1 Succeeded  |  0 Failed
  --------------------------------------------------------------------------

  Last refresh: 08:45:12  |  Next: 3s  |  Ctrl+C to exit
```

---

## Network Requirements

Target servers must reach these endpoints outbound on TCP 443.

Per [Microsoft docs](https://learn.microsoft.com/en-us/azure/azure-arc/servers/network-requirements#urls):

| Endpoint | Purpose | When |
|----------|---------|------|
| `login.microsoftonline.com` | Microsoft Entra ID | Always |
| `*.login.microsoft.com` | Microsoft Entra ID | Always |
| `pas.windows.net` | Microsoft Entra ID | Always |
| `management.azure.com` | Azure Resource Manager | Connect/disconnect |
| `*.his.arc.azure.com` | Hybrid Identity Service | Always |
| `*.guestconfiguration.azure.com` | Guest Configuration | Always |
| `guestnotificationservice.azure.com` | Notification service | Always |
| `*.servicebus.windows.net` | Notification service | Always |
| `download.microsoft.com` | Windows agent download | Install time |
| `packages.microsoft.com` | Linux agent packages | Install time |

Test from the management server:
```powershell
.\Start-ArcMonitor.ps1
# Select option [4] Test Network Connectivity
```

---

## Configuration Reference

`ArcMonitor-Config.ps1` is auto-populated by the Setup Wizard. Key sections:

### Azure Identity (`$ArcConfig`)
| Key | Description |
|-----|-------------|
| `TenantId` | Microsoft Entra ID tenant GUID |
| `SubscriptionId` | Azure subscription GUID |
| `ResourceGroup` | Target resource group for Arc resources |
| `Location` | Azure region (e.g., `eastus`, `centralindia`) |
| `Cloud` | `AzureCloud` / `AzureUSGovernment` / `AzureChinaCloud` |
| `AuthType` | `principal` (recommended for automation) |
| `ServicePrincipal.AppId` | Service Principal application ID |
| `ServicePrincipal.Secret` | Service Principal client secret |
| `ProxyServer` | HTTP proxy URL or `$null` |
| `CorrelationId` | GUID for Azure Arc log tracking |

### Environment Variables (auto-set)
The config module automatically sets `$env:SUBSCRIPTION_ID`, `$env:RESOURCE_GROUP`, `$env:TENANT_ID`, `$env:LOCATION`, `$env:AUTH_TYPE`, `$env:CLOUD` — matching the standard Azure Arc onboarding script format.

---

## Command-Line Parameters

```powershell
.\Start-ArcMonitor.ps1
    [-Mode <Onboard | PreCheck | Setup>]
    [-Targets <string[]>]           # Server names/IPs
    [-PollInterval <int>]           # Seconds (default: 60)
    [-MaxPolls <int>]               # Max cycles (default: 120)
```

| Usage | Command |
|-------|---------|
| Interactive menu | `.\Start-ArcMonitor.ps1` |
| Setup wizard | `.\Start-ArcMonitor.ps1 -Mode Setup` |
| Onboard specific servers | `.\Start-ArcMonitor.ps1 -Mode Onboard -Targets "srv01","srv02"` |
| PreReq check only | `.\Start-ArcMonitor.ps1 -Mode PreCheck -Targets "srv01"` |
| Faster polling | `.\Start-ArcMonitor.ps1 -Mode Onboard -Targets "srv01" -PollInterval 15` |

---

## Prerequisites

| Requirement | Details |
|---|---|
| **PowerShell** | 5.1+ (ships with Server 2016+). PS 7+ also supported. |
| **Management Server** | Windows with WinRM client. Does not need to be the onboarding target. |
| **Target Servers** | WinRM enabled (`Enable-PSRemoting -Force`), admin credentials. |
| **Azure** | Subscription with Contributor + User Access Administrator roles. |
| **Service Principal** | Created by Setup Wizard with Azure Connected Machine Onboarding role. |
| **Network** | Targets must reach Azure Arc endpoints on TCP 443. |

### Supported Target OS

Per [Microsoft docs](https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems):

- Windows Server 2012, 2012 R2, 2016, 2019, 2022, 2025
- Ubuntu 18.04/20.04/22.04/24.04
- RHEL 7/8/9/10, Oracle 7/8/9
- SLES 12 SP5, 15 SP4+
- Debian 11/12, AlmaLinux 8/9, Rocky 8/9
- Amazon Linux 2/2023

---

## Service Principal Setup

The Setup Wizard (option 3) handles this automatically. Manual alternative:

```powershell
# Azure CLI
az ad sp create-for-rbac --name "sp-arc-onboarding" \
    --role "Azure Connected Machine Onboarding" \
    --scopes /subscriptions/<SUBSCRIPTION_ID>

# Azure PowerShell
$sp = New-AzADServicePrincipal -DisplayName "sp-arc-onboarding"
New-AzRoleAssignment -ApplicationId $sp.AppId `
    -RoleDefinitionName "Contributor" `
    -Scope "/subscriptions/<SUBSCRIPTION_ID>"
New-AzRoleAssignment -ApplicationId $sp.AppId `
    -RoleDefinitionName "Azure Connected Machine Onboarding" `
    -Scope "/subscriptions/<SUBSCRIPTION_ID>"
```

---

## Logging

| Setting | Value |
|---------|-------|
| Log directory | `.\ArcMonitor\Logs\` |
| Log file | `ArcMonitor_YYYYMMDD.log` (daily rotation) |
| State file | `Logs\onboard-state.json` (live dashboard IPC) |
| Format | `YYYY-MM-DD HH:MM:SS [LEVEL] Message` |
| Levels | `INFO`, `WARN`, `ERROR` |

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| "WinRM port 5985 not reachable" | WinRM disabled on target | Run `Enable-PSRemoting -Force` on target |
| "Access is denied" on remote session | Credential not admin | Use local admin or domain admin account |
| "Azure endpoints BLOCKED" | Firewall blocking outbound 443 | Allow endpoints listed in Network Requirements |
| "Azure native VM detected" | Target is an Azure VM | Remove from list — Azure VMs must not use Arc |
| Config still shows `<YOUR-TENANT-ID>` | Setup Wizard not run | Run `.\Start-ArcMonitor.ps1 -Mode Setup` first |
| azcmagent connect error code 23 | Invalid GUID in config | Verify TenantId/SubscriptionId are valid GUIDs |
| Monitor window blank | State file not created yet | Wait for onboarding to start writing state |
| TUI shows garbled characters | Console font issue | Use Consolas or Lucida Console font |

---

## Microsoft Documentation

| Topic | URL |
|-------|-----|
| **Arc-enabled servers overview** | https://learn.microsoft.com/en-us/azure/azure-arc/servers/overview |
| **Prerequisites** | https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites |
| **Network requirements** | https://learn.microsoft.com/en-us/azure/azure-arc/servers/network-requirements |
| **Deployment options** | https://learn.microsoft.com/en-us/azure/azure-arc/servers/deployment-options |
| **Manage agent** | https://learn.microsoft.com/en-us/azure/azure-arc/servers/manage-agent |
| **Private Link** | https://learn.microsoft.com/en-us/azure/azure-arc/servers/private-link-security |
| **Arc Gateway** | https://learn.microsoft.com/en-us/azure/azure-arc/servers/arc-gateway |
| **Supported OS list** | https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems |
| **TLS 1.2 requirements** | https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#transport-layer-security-12-protocol |

---

## License

Internal use. Customize for your environment.