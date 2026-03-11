# Azure Arc Onboarding Monitor (ArcMonitor)

A unified PowerShell framework for onboarding and monitoring Azure Arc-enabled servers across **all platforms** — VMware, Azure Local (HCI), Hyper-V, Physical, KVM, Nutanix — from a centralized management server.

> **Design principle**: Azure Arc onboarding doesn't care where a machine is hosted. One unified framework replaces platform-specific scripts. All checks run **remotely on the target**, never on the management server.


## Table of Contents

- [Architecture](#architecture)
- [Screenshots](#screenshots)
- [File Structure](#file-structure)
- [Quick Start](#quick-start)
- [Onboarding Flow](#onboarding-flow)
- [Remote Prerequisite Checks](#remote-prerequisite-checks)
- [Platform Auto-Detection](#platform-auto-detection)
- [TUI Dashboard](#tui-dashboard)
- [Network Requirements](#network-requirements)
- [Configuration Reference](#configuration-reference)
- [Command-Line Parameters](#command-line-parameters)
- [Prerequisites](#prerequisites)
- [Service Principal Setup](#service-principal-setup)
- [Logging](#logging)
- [Security](#security)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Microsoft Documentation](#microsoft-documentation)

---

## Architecture

![Azure Arc Onboarding Architecture](images/Onboarding%20Architecture.png)

The framework follows a **management server → remote targets → Azure Arc** flow:

| Component | Role |
|-----------|------|
| **Start-ArcMonitor.ps1** | Orchestrator — launches all modules, interactive menu, Setup Wizard |
| **ArcMonitor-Config** | Centralized configuration — Azure identity, server lists, credentials (DPAPI-encrypted) |
| **ArcMonitor-TUI** | Dashboard rendering engine — Unicode box-drawing, color-coded status, progress bars |
| **PreReqCheck** | 13 remote prerequisite checks with auto-remediation and Microsoft docs guidance |
| **Onboard** | Unified onboarding pipeline — download, verify signature, install agent, `azcmagent connect` |
| **MonitorWindow.ps1** | Separate PS window — reads shared JSON state file, renders live TUI dashboard |

**Two-window design**:
- **Main window** — runs prereqs, installs agent, connects to Arc, shows detailed logs + transcript
- **Monitor window** — opens automatically, shows live TUI dashboard reading from a shared JSON state file (atomic writes prevent corruption)

**Data flow**: Management server establishes **WinRM/PSSession** connections to each target, runs all operations remotely (`Invoke-Command`), then each target runs `azcmagent connect` to register with **Microsoft Azure Arc** in the cloud.

---

## Screenshots

### Interactive Landing Page

The main menu provides access to all operations — onboard servers, validate prerequisites, configure Azure identity, and test remote network connectivity.

![ArcMonitor Interactive Menu](images/Onboarding%20Landing%20page.png)

### Two-Window Onboarding In Progress

The **left window** (main) shows detailed logs including prerequisite checks, remediation guidance, and agent installation output. The **right window** (monitor) renders the live TUI dashboard with per-server status, download progress bars, and event feed.

![Two-window onboarding in progress](images/onboarding%20in%20progress%20-two%20server.png)

### Single Server — Onboarding Complete

The monitor window after a successful single-server onboarding. All phases complete: PreReq → Install → Arc Registration → Agent Connected.

![Single server onboarding complete](images/ARC%20OnBoarding%20Monitor-Single%20server.png)

### Azure Portal — Arc-Enabled Machines

After onboarding, servers appear in the Azure Arc portal as **Machine - Azure Arc** resources with a **Connected** status, ready for policy, monitoring, and management.

![Azure Arc Machines in portal](images/azure%20arc%20reflect%20the%20same.png)

### Azure Portal — Resource Group

The `rg-arc-onboarding` resource group showing onboarded Arc-enabled servers in the target region.

![Resource group with Arc nodes](images/resource%20group%20hosting%20arc%20nodes.png)

---

## File Structure

```
ArcMonitor/
├── Start-ArcMonitor.ps1          # Launcher + Setup Wizard + interactive menu
├── ArcMonitor-Config.ps1         # Azure identity, server lists, settings
├── ArcMonitor-TUI.ps1            # Dashboard rendering engine (Unicode box-drawing)
├── ArcMonitor-PreReqCheck.ps1    # Remote prerequisite validation + auto-fix
├── ArcMonitor-Onboard.ps1        # Unified onboarding (all platforms)
├── ArcMonitor-MonitorWindow.ps1  # Standalone TUI (separate window, reads JSON)
├── Config/
│   └── defaults.json             # Externalized thresholds, ports, timeouts, URLs
├── Tests/
│   └── ArcMonitor.Tests.ps1      # Pester tests (validation, security baseline)
├── images/                       # Screenshots for documentation
├── Logs/                         # Auto-created: daily logs, transcripts, state JSON
└── README.md                     # This file
```

---

## Quick Start

### 1. Configure Azure Identity

Run the **Setup Wizard** — it creates a Service Principal, picks a region, selects/creates a resource group, and saves everything:

```powershell
.\Start-ArcMonitor.ps1 -Mode Setup
```

The wizard walks through 6 steps:

| Step | Action |
|------|--------|
| 1 | Install required Az modules (`Az.Accounts`, `Az.Resources`, `Az.ConnectedMachine`) |
| 2 | Authenticate to Azure (`Connect-AzAccount`) |
| 3 | Create or reuse a Service Principal (lists existing `sp-arc*` SPNs) |
| 4 | Select Azure region (popular list + full list) |
| 5 | Select or create a resource group |
| 6 | Save all values into `ArcMonitor-Config.ps1` + optionally save SP credentials to **DPAPI-encrypted** `.xml` |

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

![Onboarding Flow Diagram](images/Onboarding%20Flow.png)

The diagram above shows the complete onboarding pipeline. Key decision points:

| Phase | Action | On Failure |
|-------|--------|------------|
| **Input validation** | Validates hostname/IP format, deduplicates entries | Invalid names removed with warning |
| **Reachability check** | ICMP ping + WinRM port 5985 TCP test | Unreachable servers skipped |
| **Config validation** | Blocks if `<YOUR-TENANT-ID>` placeholders remain | Redirects to Setup Wizard |
| **[1/4] PreReq Checks** | 13 remote checks on target via `Invoke-Command` | `[F]` Auto-fix / `[S]` Skip / `[I]` Ignore |
| **[2/4] Agent Install** | Download → Authenticode signature verify → install | Abort server on failure |
| **[3/4] Arc Connect** | `azcmagent connect` with Service Principal auth | Log error, continue next server |
| **[4/4] HIMDS Verify** | Confirm Hybrid Instance Metadata service running | Report status |

> **Monitor window** opens in a separate PowerShell process after config validation and renders the live TUI dashboard throughout all phases.

![Onboarding in progress — two servers](images/onboarding%20in%20progress%20-two%20server.png)

---

## Remote Prerequisite Checks

All 13 checks run **on the target server** via `Invoke-Command`, not on the management server:

| # | Check | What | Auto-Fix |
|---|-------|------|:--------:|
| 1 | **Reachability** | WinRM port 5985 TCP (5s timeout) | — |
| 2 | **Remote Session** | WinRM PSSession establishment (30s timeout) | — |
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

All auto-fix operations support **`-WhatIf`** for dry-run previews and **`-Confirm`** for explicit approval. Remote reboots require double confirmation with explicit warnings.

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

> Azure native VMs are **automatically excluded** — they must not be onboarded to Arc.

---

## TUI Dashboard

The monitor window renders a Unicode box-drawing dashboard (works on PS 5.1 + all Windows Server versions):

![Single server TUI dashboard](images/ARC%20OnBoarding%20Monitor-Single%20server.png)

**Dashboard sections:**

| Section | Description |
|---------|-------------|
| **Header** | Animated title bar with spinner |
| **Stats Bar** | Node count, elapsed time, poll counter, platform mode |
| **Status Table** | Per-server columns: Server, Platform, PreReq, Install, Arc Reg, Agent |
| **Download Progress** | Green progress bars with percentage and size |
| **Events Panel** | Timestamped events with severity coloring (Info, Warning, Error) |
| **Summary** | Running / Succeeded / Failed counts |
| **Footer** | Last refresh time, next refresh countdown, exit hint |

---

## Network Requirements

Target servers must reach these endpoints outbound on **TCP 443**.

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

### Testing Connectivity from Remote Targets

The network connectivity test (menu option **[4]**) runs **remotely on each target server** — not on the management machine:

```powershell
.\Start-ArcMonitor.ps1
# Select option [4] Test Network Connectivity
# Enter target server names → tests run on EACH target via WinRM
```

Each target is tested against all 9 Azure Arc endpoints with a 5-second TCP timeout per endpoint.

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
| `ServicePrincipal.Secret` | Service Principal client secret (see [Security](#security)) |
| `ProxyServer` | HTTP proxy URL or `$null` |
| `CorrelationId` | GUID for Azure Arc log tracking |

### Secure Credential Loading

The config module supports **DPAPI-encrypted credentials**. On startup, it checks for `ArcSPN-Credentials.xml` (created by the Setup Wizard). If found, credentials are decrypted and loaded automatically — the plaintext values in `ArcMonitor-Config.ps1` are overridden.

```
Load order:
1. Read ArcMonitor-Config.ps1 (may contain placeholders)
2. Check for ArcSPN-Credentials.xml (DPAPI-encrypted)
3. If found → decrypt and override SP AppId + Secret
4. Clean up sensitive environment variables after export
```

> **Note**: DPAPI-encrypted files can only be decrypted by the same user on the same machine.
> For cross-machine deployment, use **Azure Key Vault** or pass credentials at runtime via `Get-Credential`.

### Externalized Defaults (`Config/defaults.json`)

Thresholds, timeouts, ports, and URLs that were previously hardcoded are centralized in `Config/defaults.json`:

| Section | Keys | Examples |
|---------|------|----------|
| `network` | `winrmPort`, `winrmHttpsPort`, `tcpConnectTimeoutMs` | `5985`, `5986`, `5000` |
| `prerequisites` | `minDiskSpaceGB`, `minDotNetRelease`, `minPSMajorVersion` | `2`, `394802`, `5` |
| `monitor` | `pollIntervalSeconds`, `maxPolls` | `60`, `120` |
| `agentUrls` | `windowsAgent`, `linuxAgent` | Microsoft download URLs |
| `azureEndpoints` | Array of `{name, host, port}` | 9 required Azure Arc endpoints |

### Environment Variables (auto-set, auto-cleaned)

The config module temporarily sets `$env:SUBSCRIPTION_ID`, `$env:RESOURCE_GROUP`, `$env:TENANT_ID`, `$env:LOCATION`, `$env:AUTH_TYPE`, `$env:CLOUD` for azcmagent compatibility. **Sensitive environment variables are cleaned up after config export** to minimize credential leakage.

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

### Interactive Menu Options

| Option | Mode | Description |
|--------|------|-------------|
| **[1]** | Onboard | Enter targets → PreReq check → Install → Connect. Live TUI dashboard in separate window. |
| **[2]** | PreReq Check | Validate remote servers without onboarding. Shows detailed pass/fail results. |
| **[3]** | Setup Wizard | Create Service Principal, configure Azure identity, save to config. |
| **[4]** | Network Test | Test Azure Arc endpoint reachability from REMOTE target servers via WinRM. |
| **[Q]** | Quit | Exit ArcMonitor. |

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

The Setup Wizard (menu option **[3]**) handles this automatically. Manual alternative:

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
| Log directory | `.\Logs\` (auto-created) |
| Log file | `ArcMonitor_YYYYMMDD.log` (daily rotation) |
| Transcript | `ArcMonitor_Transcript_YYYYMMDD_HHmmss.log` (per-session audit trail) |
| State file | `Logs\onboard-state.json` (live dashboard IPC, atomic writes) |
| Format | `YYYY-MM-DD HH:MM:SS [LEVEL] Message` |
| Levels | `INFO`, `WARN`, `ERROR` |

### Audit Trail

Every session automatically starts a **PowerShell transcript** (`Start-Transcript`) capturing all console output, user input, and remote operations. Transcripts are stored alongside daily logs and provide a complete audit trail for compliance.

---

## Security

The framework implements security hardening measures for enterprise environments:

### Credential Protection

| Feature | Description |
|---------|-------------|
| **DPAPI-encrypted storage** | SP credentials saved via `Export-Clixml` (Windows DPAPI). Only decryptable by the same user on the same machine. |
| **Masked console output** | SP secrets are never displayed in full — only the last 4 characters are shown. |
| **Environment variable cleanup** | Sensitive env vars (`SUBSCRIPTION_ID`, `TENANT_ID`, etc.) are removed from the process after config export. |
| **No plaintext credential files** | The Setup Wizard uses DPAPI-encrypted `.xml` instead of plaintext `.txt` files. |

### Transport & Execution

| Feature | Description |
|---------|-------------|
| **RemoteSigned execution policy** | All child PowerShell windows use `-ExecutionPolicy RemoteSigned` (not `Bypass`). |
| **Authenticode verification** | Downloaded agent install scripts are checked for valid Microsoft Authenticode signatures before execution. |
| **Atomic state file writes** | JSON state file is written to a temp file first, then atomically renamed to prevent partial reads. |
| **PSSession timeouts** | WinRM sessions use 30s open timeout and 60s operation timeout to prevent hanging. |

### Input Validation & Scope

| Feature | Description |
|---------|-------------|
| **Server name validation** | All user-entered server names are validated against hostname (RFC 1123) and IPv4 patterns. Invalid entries are rejected. |
| **No global variable pollution** | All config uses `$script:` scope instead of `$Global:`. No sensitive data leaks to the global scope. |
| **`Set-StrictMode -Version Latest`** | Enabled on all entry points to catch undefined variables and property access. |
| **`-WhatIf` / `-Confirm` support** | Destructive operations (auto-fix, remote reboot) support `ShouldProcess` for dry-run previews. |
| **`[CmdletBinding()]` on all functions** | Public functions use advanced function features with parameter validation attributes. |

### Production Recommendations

- **Use WinRM over HTTPS** (port 5986) instead of HTTP (5985) for encrypted transport
- **Store SP credentials in Azure Key Vault** for multi-machine deployments
- **Sign all scripts** with a code-signing certificate and use `AllSigned` execution policy
- **Implement JEA** (Just Enough Administration) constrained endpoints on target servers
- **Review transcripts** in `Logs/` for compliance auditing

---

## Testing

Pester tests are included in `Tests/ArcMonitor.Tests.ps1`. They validate:

- **Input validation** — hostname/IP format acceptance and rejection
- **Config integrity** — `defaults.json` structure, required fields, Microsoft domain URLs
- **Security baseline** — no `ExecutionPolicy Bypass`, no `$Global:`, no TrustedHosts wildcards, `Set-StrictMode` present

### Running Tests

```powershell
# Install Pester (if not already installed)
Install-Module Pester -Force -Scope CurrentUser

# Run all tests
Invoke-Pester .\Tests\ArcMonitor.Tests.ps1 -Output Detailed
```

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| "WinRM port 5985 not reachable" | WinRM disabled on target | Run `Enable-PSRemoting -Force` on target |
| "Access is denied" on remote session | Credential not admin | Use local admin or domain admin account |
| "Azure endpoints BLOCKED" | Firewall blocking outbound 443 | Allow endpoints listed in [Network Requirements](#network-requirements) |
| "Azure native VM detected" | Target is an Azure VM | Remove from list — Azure VMs must not use Arc |
| Config still shows `<YOUR-TENANT-ID>` | Setup Wizard not run | Run `.\Start-ArcMonitor.ps1 -Mode Setup` first |
| `azcmagent connect` error code 23 | Invalid GUID in config | Verify TenantId/SubscriptionId are valid GUIDs |
| Monitor window blank | State file not created yet | Wait for onboarding to start writing state |
| TUI shows garbled characters | Console font issue | Use Consolas or Lucida Console font |
| "Invalid server name(s) removed" | Server name failed validation | Use valid hostname (RFC 1123) or IPv4 address |
| "Could not load encrypted credentials" | DPAPI file from different user/machine | Re-run Setup Wizard or provide credentials in Config |
| "Script is NOT signed" abort | Downloaded installer not from Microsoft URL | Verify `AgentURLs` in Config point to `*.azure.com` or `aka.ms` |
| Transcript file locked | Previous session didn't close cleanly | Delete old transcript from `Logs/` or restart PowerShell |

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