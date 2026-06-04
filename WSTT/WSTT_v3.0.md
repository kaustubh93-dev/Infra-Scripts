# Windows Server Troubleshooting & Log Collection Tool (WSTT)

## Overview

A comprehensive PowerShell-based interactive diagnostic tool for **Windows Server 2019, 2022, and 2025**. Diagnoses and collects logs for Network, Memory, CPU, Disk, Services, Event Logs, DNS, Security & Authentication, Windows Update, TLS/SSL, IIS, **WSFC Cluster Port Compliance**, and **Cluster/SQL AG environments**.

**Author:** Kaustubh Sharma  
**Version:** 3.0  
**Requires:** Administrator privileges, PowerShell 5.1+  
**Tested On:** Windows Server 2019 (Build 17763), 2022 (Build 20348), 2025 (Build 26100)

> [!NOTE]
> Performance counter names (`Get-Counter`) are locale-dependent and require an English OS installation. External tools (`w32tm`, `net accounts`, `klist`, `secedit`) also produce English-only output. The tool detects non-English locales at startup and warns accordingly.

---

## What's New in v3.0 (from v2.5)

### 🔌 WSFC Cluster Port Compliance Check (NEW — Option 22)

Local-only validator for the network ports required by Windows Server Failover Clusters. Designed for change-control evidence in regulated environments (banking, healthcare, gov).

**Two evidence streams per required port:**

| Stream | Mechanism | Purpose |
|--------|-----------|---------|
| **Live reachability** | TCP via `TcpClient.ConnectAsync` (2s timeout), ICMP via `Test-Connection`, UDP best-effort via `UdpClient` | Proves traffic actually flows from this node to each peer right now |
| **Local firewall audit** | `Get-NetFirewallRule` + `Get-NetFirewallPortFilter` for inbound + outbound | Proves Allow rules exist and surfaces any enabled Block rules |

**Required port matrix (validated):**

| Service | Protocol | Port | Direction | Purpose |
|---------|----------|------|-----------|---------|
| Cluster Service | UDP | 3343 | Bidirectional | Cluster heartbeat / intra-cluster comms (DTLS-encrypted) |
| Cluster Service | TCP | 3343 | Bidirectional | Required during node-join operations |
| Cluster Service | ICMP | Echo | Bidirectional | Add Node Wizard connectivity test |
| Cluster Service | TCP | 445 | Bidirectional | SMB during cluster join, file-share witness, validation |
| RPC Endpoint Mapper | TCP | 135 | Bidirectional | RPC endpoint mapper for cluster management |
| Cluster Admin (NetBIOS) | UDP | 137 | Bidirectional | NetBIOS name service (legacy admin discovery) |
| SMB / NetBIOS Datagram | UDP | 138 | Bidirectional | NetBIOS datagram service (legacy SMB over NetBIOS) |
| SMB / NetBIOS Session | TCP | 139 | Bidirectional | NetBIOS session service (legacy SMB over NetBIOS) |
| WinRM (Cloud Witness) | TCP | 5985 | Bidirectional | WinRM HTTP — required for Azure cloud witness |

**Out of scope by design:**
- Trojan-port overlap analysis (e.g. environment-specific Trojan list comparison) — not in this tool.
- Dynamic RPC range 49152–65535 live testing — testing 16K ports is impractical; cluster picks random ports at runtime.

**How it works:**
- Auto-discovers peer nodes from `$script:ClusterEnv.ClusterNodes` when run on a cluster member.
- Falls back to interactive prompt or `-TargetNode <hostname[],ip[]>` parameter on standalone hosts.
- All hostnames/IPs validated against an RFC 1123 + IPv4 regex before any network I/O.
- UDP results are explicitly reported as `Inconclusive` (UDP is connectionless — silent ports are indistinguishable from open).
- Console summary table + per-port CSV exports + dark-themed HTML report.

**Outputs (under `%TEMP%\ServerDiagnostics\Logs\`):**
- `WSFC_PortReachability_yyyyMMdd_HHmmss.csv`
- `WSFC_FirewallAudit_yyyyMMdd_HHmmss.csv`
- `WSFC_PortCompliance_yyyyMMdd_HHmmss.html`

### 🌐 Network Diagnostics — 15 New Checks
| # | Check | What It Detects |
|---|-------|-----------------|
| 1 | Default Gateway Reachability | Unreachable gateways, high latency |
| 2 | Duplicate IP Detection | ARP table with multiple MACs for same IP |
| 3 | Link Speed & Duplex | Half-duplex mismatches, 100Mbps on physical NIC |
| 4 | TCP Chimney / Task Offload | Deprecated Chimney state, disabled offloads |
| 5 | MTU / Jumbo Frames | Inconsistent MTU across interfaces |
| 6 | DNS Suffix & Search Order | Missing suffixes, devolution config |
| 7 | WINS Configuration | Legacy WINS server settings |
| 8 | Proxy / WinHTTP Settings | System and IE proxy detection |
| 9 | NIC Driver Version & Date | Outdated drivers (>2 years), vmxnet3 version |
| 10 | Network Binding Order | TCP/IPv4 and IPv6 binding status |
| 11 | Firewall Block Rules | Deny rules on common ports (RDP, SMB, etc.) |
| 12 | RDMA / SMB Direct | RDMA adapters, SMB Multichannel, SMB Direct |
| 13 | TCP/IP Stack Parameters | AutoTuning, KeepAlive, Timestamps, Congestion |
| 14 | NIC Error Events | Events 27, 32, 1073, 4198, 4199 (last 7 days) |
| 15 | Routing Table Analysis | Multiple gateways, metric conflicts, static routes |

### 🧠 Memory Diagnostics — 12 New Checks
| # | Check | What It Detects |
|---|-------|-----------------|
| 1 | Page File Config & Usage | Size, % used, peak, system-managed vs fixed |
| 2 | Available MBytes | True available memory (includes reclaimable cache) |
| 3 | Memory Compression | Compression process WS, compression ratio |
| 4 | Handle & Thread Count | Top processes by handles/threads, leak indicators |
| 5 | Paged Pool Usage | Risk of SESSION_POOL_EMPTY bugcheck |
| 6 | System Cache Working Set | Large cache starving user processes |
| 7 | Memory Leak Trend | Private Bytes vs Working Set gap analysis |
| 8 | Standby Cache Breakdown | Core/Normal/Reserve priority split, reclaimability |
| 9 | RAM Hardware Info | DIMM slots, speeds, types, mismatched DIMMs |
| 10 | Resource Exhaustion Events | Event 2004/333/2003 (virtual memory exhaustion) |
| 11 | Working Set Trimming | Transition pages repurposed/sec, cache faults |
| 12 | Detailed Leak Analysis | Processes where Private >> WS by >200MB |

### 💻 CPU Diagnostics — 15 New Checks
| # | Check | What It Detects |
|---|-------|-----------------|
| 1 | Per-Core CPU Usage | Hot cores at >95% (single-threaded bottleneck) |
| 2 | Privileged vs User Time | Kernel (driver) vs application CPU split |
| 3 | Processor Queue Length | Threads waiting for CPU (>2×cores = need more CPU) |
| 4 | Context Switches/sec | Thread contention (>15K/core = thrashing) |
| 5 | Interrupt & DPC Time | NIC/storage driver CPU theft (>15% = critical) |
| 6 | System Uptime | Long uptimes >90d, kernel timer drift risk |
| 7 | Power Throttling | CPU running below full speed (VM host overcommit, thermal) |
| 8 | Antivirus CPU Detection | 12 AV products + fltmc filter driver stack |
| 9 | Hyper-V Hypervisor Overhead | Hypervisor run time, overhead %, guest time |
| 10 | Real-Time CPU (5s sample) | Two-snapshot delta — current vs cumulative CPU |
| 11 | Thread & Process Count | System-wide totals (>5K threads = resource exhaustion) |
| 12 | DPC Queue Rate | Per-core DPCs/sec (>5K/core = driver bottleneck) |
| 13 | NUMA Node Imbalance | Memory imbalance across NUMA nodes (>20%) |
| 14 | CPU Event Log | WHEA hardware errors, thermal throttling events |
| 15 | Process CPU Affinity | Processes locked to subset of cores |

### 💾 Disk/Storage Diagnostics — 15 New Checks
| # | Check | What It Detects |
|---|-------|-----------------|
| 1 | Disk IOPS | Read/Write/Total IOPS per physical disk |
| 2 | Disk Throughput | MB/sec read and write bandwidth |
| 3 | Storage Media Type | SSD vs HDD vs iSCSI LUN identification |
| 4 | SMART / Predictive Failure | Disk health, operational status, WMI SMART |
| 5 | VSS Shadow Copy Usage | Snapshot count, orphaned snapshots, VSS writer health |
| 6 | Storage Spaces / Pool Health | Degraded pools, virtual disk rebuild status |
| 7 | Disk Fragmentation | Optimize-Volume analysis per volume |
| 8 | Pagefile Disk Placement | Pagefile on OS drive I/O contention |
| 9 | Temp/TempDB Location | Windows TEMP + SQL TempDB on C: risk |
| 10 | Filter Driver Stack (fltmc) | Active filter drivers, AV filters flagged |
| 11 | Disk Timeout Settings | I/O timeout value, iSCSI link down time |
| 12 | MPIO Status | Feature installed, path health, degraded paths |
| 13 | ReFS vs NTFS Detection | File system type per volume with guidance |
| 14 | Disk Busy Time % | Sustained >80% = disk is the bottleneck |
| 15 | Storage Tiering | Tier configuration, optimization task status |

### 📋 Task Scheduler Diagnostics — 8 New Checks (Option 19)
| # | Check | What It Detects |
|---|-------|-----------------|
| 1 | Failed Tasks | Non-zero LastTaskResult with error code decoding |
| 2 | Long-Running / Stuck Tasks | Tasks in Running state >4h |
| 3 | Disabled Tasks | Non-Microsoft tasks accidentally turned off |
| 4 | High-Privilege Audit | SYSTEM + Highest RunLevel — security risk |
| 5 | Credential Failures | Expired passwords (0x8007052E), access denied |
| 6 | SDDL Permission Audit | Everyone/Authenticated Users with Full Access |
| 7 | Orphaned Tasks | Actions pointing to non-existent executables |
| 8 | Trigger Health | Expired end boundaries, disabled triggers |

### ✅ Server Baseline Validation — 9 New Checks (Option 20)
| # | Check | Source |
|---|-------|--------|
| 1 | Active Directory OU Path | DirectoryServices searcher |
| 2 | Windows License & Activation | SoftwareLicensingProduct |
| 3 | Crash Dump Configuration | CrashControl registry + space check |
| 4 | Installed Software Inventory | Registry Uninstall keys (non-Microsoft) |
| 5 | NIC Power Save Setting | WMI MSPower_DeviceEnable |
| 6 | Windows Features Installed | Get-WindowsFeature roles + features |
| 7 | NTFS 8.3 Short Name Setting | FileSystem registry key |
| 8 | Clear Page File at Shutdown | Memory Management registry |
| 9 | Critical System Driver Versions | tcpip.sys, afd.sys, storport.sys, ntfs.sys, etc. |

### 📄 HTML Diagnostic Report (Option 21)
- Runs **all 12 diagnostic functions** automatically
- Produces a **dark-themed, collapsible HTML** report
- Color-coded: `[SUCCESS]` green, `[ERROR]` red, `WARNING:` orange
- Section headers are **clickable** to expand/collapse
- **Expand/Collapse All** button
- Opens in default browser on completion
- Uses `System.Net.WebUtility` (compatible with Server 2019/Core)

### 🕒 Recent Server Changes — last 24h (NEW — Option 23)
- New utility `Get-RecentServerChange` that proactively surfaces **what changed on the server within a configurable lookback window** (default 24h, 1-720h) to speed up issue correlation and root-cause triage
- Presents findings as **confidence-rated change signals** (not a guaranteed change log) plus a consolidated, de-duplicated **chronological timeline**
- Detects across 30 categories:
  - OS patch installs/updates (Windows Update events + `Get-HotFix`)
  - Reboot / restart activity (System events + last boot time)
  - Service add / start-type changes (SCM 7045 / 7040)
  - Driver / GPU / firmware updates (Kernel-PnP events + GPU snapshot)
  - Software & VM Tools installs (MsiInstaller events + Uninstall registry)
  - TLS/SSL certificate changes + SChannel/cipher hardening
  - NIC configuration, routing table, environment variables, proxy configuration
  - Disk / storage configuration events
  - Firewall rule, scheduled task, Windows Defender, and RDP/Terminal Server changes
  - Security-audit signals (local accounts/groups, user rights, time changes — when auditing is enabled)
  - **Expanded set:** hosts file & DNS client, Group Policy, Windows roles/features (servicing), local Administrators membership snapshot, Trusted Root/CA store, recently modified driver files (`drivers\*.sys`), SMB shares, power plan / time zone / pagefile, autorun (Run/RunOnce), WinRM / remote management
  - **Environment-gated:** Hyper-V VM config (when `vmms` present), Failover Cluster config (cluster nodes only), BitLocker / encryption state (when `Get-BitLockerVolume` available), and pending-reboot context (CBS / Windows Update / `PendingFileRenameOperations`)
- **Evidence sources:** Windows Event Logs, registry key `LastWriteTime` (via idempotent `RegQueryInfoKey` P/Invoke), and install/validity dates
- Per-category error isolation, save-to-file support, and inclusion in the HTML Diagnostic Report
- Categories without a native change history additionally show a **current-state snapshot** with a clearly-labelled limitation (a registry `LastWriteTime` indicates a key was touched, not which value changed)

### 🔄 Cluster & SQL AG Awareness (NEW)
| Feature | Description |
|---------|-------------|
| **AG Role Detection** | Queries `sys.dm_hadr_availability_replica_states` at startup; caches PRIMARY/SECONDARY role |
| **CSV Path Guard** | Warns before writing large traces to Cluster Shared Volumes |
| **Heartbeat NIC Filter** | Skips cluster-only heartbeat NICs when pinging gateways |
| **AG Listener DNS** | Resolves AG listener names; flags stale DNS post-failover |
| **FailoverClustering Log** | Queries `Microsoft-Windows-FailoverClustering/Operational` (not just System) |
| **Quorum Health** | Validates quorum type, witness, and node states in scorecard |
| **AG Sync Scorecard** | Checks AG synchronization health (HEALTHY/NOT_SYNCHRONIZING) |
| **AG Replication Counters** | Log Send Queue and Redo Queue Size from perf counters |
| **Service Context** | SQLSERVERAGENT stopped on SECONDARY shown as "expected" not error |
| **CAU Guard** | Warns before `net stop wuauserv` on cluster nodes with CAU |
| **Active Owner Warning** | Shows which cluster groups this node owns before heavy diagnostics |
| **Safe ClusterLog Path** | Suggests `$env:TEMP` instead of hardcoded `D:\` for cluster logs |

### 🖥️ OS Compatibility Fixes
| Fix | Target OS |
|-----|-----------|
| LBFO → SET (Switch Embedded Teaming) fallback | Server 2025 |
| TCP Chimney property safe-access (removed on newer OS) | Server 2025 |
| OS Lifecycle check recognizes builds 17763/20348/26100 | 2019/2022/2025 |
| `Get-HotFix` `.InstalledOn` null handling | Server 2019 |
| `Win32_PageFileSetting` empty = system-managed (not disabled) | All |
| `Invoke-Sqlcmd` timeout + SqlClient fallback | All |
| Non-English locale detection and warning at startup | All |

### 🎨 UX Improvements
- **Clean error output**: `[ERROR]` tags in red — no PowerShell stack traces
- **Section dividers**: `--- Section Name ---` in DarkCyan for visual grouping
- **Save-to-file**: All 9 primary diagnostics (options 1-9) prompt to save output as `.txt` and open in Notepad
- **Reusable export**: `Export-DiagnosticSection` function captures any diagnostic to file

### 🐛 Bug Fixes (from v2.5)
- `Get-WmiObject` → `Get-CimInstance` (PowerShell 7+ compat)
- `$wp.WorkingSet` → `$wp.WorkingSet64` (32-bit overflow)
- `klist` null-safe access (non-English locale)
- CBS.log path corrected (`C:\Windows\Logs\CBS\CBS.log`)
- Menu separator `"" * 65` → `"=" * 65`
- Empty catch blocks now log via `Write-Verbose`
- `Get-Volume` cached (3 calls → 1) in disk diagnostics
- Process analysis cache TTL (2-min expiry prevents stale data)
- TSS argument passing via single-string ArgumentList (preserves quoted paths)
- Event 4624 property access bounds-checked
- IIS `$appPools`/`$sites` declared at function scope
- `System.Web.HttpUtility` → `System.Net.WebUtility` (Server 2019/Core compat for HTML report)

---

## Features

### 🔍 Primary Diagnostics (Options 1-10)
| Option | Category | Check Count |
|--------|----------|-------------|
| 1 | Network Issues | 25+ checks |
| 2 | Memory Issues | 19 checks |
| 3 | CPU Issues | 24 checks (per-core, queue, interrupts, AV, Hyper-V, NUMA) |
| 4 | Disk/Storage Issues | 24 checks (IOPS, SMART, VSS, MPIO, tiering) |
| 5 | Windows Services Health | 9 checks (AG-aware) |
| 6 | Event Log Analysis | 8+ checks + FailoverClustering log |
| 7 | DNS Health & Connectivity | 10+ checks + AG Listener DNS |
| 8 | Security & Authentication | 10+ checks |
| 9 | Windows Update Status | 10+ checks (2019/2022/2025 aware) |
| 10 | Cross-Category Health Scorecard | 9 items (includes quorum + AG sync) |

### 🛠️ Additional Scenarios (Option 11)
- Unexpected reboots
- Boot time issues & slow logon
- Server crashes, bugchecks, and hangs
- Application crashes (ProcDump guidance)
- SQL Server issues (AG-aware TSS commands)
- Cluster issues (with active-owner warnings)
- OS patching (with CAU guard)
- Server assessments
- Event log exports

### 🔐 Security & Compliance (Option 13)
- TLS 1.0/1.1/1.2/1.3 protocol validation
- .NET Framework strong crypto settings
- Cipher suite analysis with weak cipher detection
- PowerShell TLS configuration
- Remediation commands and export

### 📊 Utilities (Options 12-23)
| Option | Feature |
|--------|---------|
| 12 | Generate System Report |
| 13 | TLS Configuration Validation |
| 14 | Validator Script Information |
| 15 | Configure TSS Path |
| 16 | Check TSS Status |
| 17 | .NET Framework Version Check |
| 18 | IIS Troubleshooting & Diagnostics |
| 19 | Task Scheduler Diagnostics |
| 20 | Server Baseline Validation |
| **21** | **Generate HTML Diagnostic Report** |
| **22** | **WSFC Cluster Port Compliance Check** |
| **23** | **Recent Server Changes (last 24h)** |

---

## Prerequisites

### Required
- Windows Server 2019, 2022, or 2025
- PowerShell 5.1 or higher
- Administrator privileges
- Sufficient disk space for logs (minimum 5GB recommended)

### Optional
- **TSS (TroubleShootingScript)**: For automated log collection
  - [https://aka.ms/getTSS](https://aka.ms/getTSS)
  - [https://aka.ms/getTSSlite](https://aka.ms/getTSSlite)
- **SqlServer module**: For AG detection via `Invoke-Sqlcmd` (script has SqlClient fallback)
- **Failover Clustering feature**: For cluster-aware diagnostics
- **WebAdministration module**: For IIS diagnostics

---

## Installation & Usage

### Quick Start

```powershell
# 1. Open PowerShell as Administrator
# 2. Set execution policy if needed
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 3. Run the script
.\WSTT_v3.0.ps1

# 4. With session logging
.\WSTT_v3.0.ps1 -EnableLogging
```

### What Happens at Startup

1. Verifies Administrator privileges
2. Creates diagnostic output directories (`%TEMP%\ServerDiagnostics\`)
3. **Detects cluster environment** (ClusSvc, cluster name, nodes, CSV paths, heartbeat NICs)
4. **Detects SQL AG state** (replica role, sync health, listeners)
5. **Checks locale** (warns if non-English)
6. Displays main menu

---

## Menu Options

```
 WINDOWS SERVER TROUBLESHOOTING & LOG COLLECTION TOOL
                      Version 3.0

PRIMARY DIAGNOSTICS:
  1. Network Issues (Packet Loss, Slowness, RSS, MTU, Routing & 15+ checks)
  2. Memory Issues (Usage, Leaks, Page File, Hardware & 19 checks)
  3. CPU Issues (Per-Core, Queue, Interrupts, Throttling & 24 checks)
  4. Disk/Storage Issues (IOPS, Latency, SMART, VSS, MPIO & 24 checks)
  5. Windows Services Health
  6. Event Log Analysis
  7. DNS Health & Connectivity
  8. Security & Authentication
  9. Windows Update Status
 10. Cross-Category Health Scorecard

ADDITIONAL SCENARIOS:
 11. Additional Troubleshooting Scenarios

UTILITIES:
 12. Generate System Report
 13. TLS Configuration Validation
 14. Validator Script Information
 15. Configure TSS Path
 16. Check TSS Status
 17. Check .NET Framework Versions
 18. IIS Troubleshooting & Diagnostics
 19. Task Scheduler Diagnostics
 20. Server Baseline Validation
 21. Generate HTML Diagnostic Report
 23. Recent Server Changes (last 24h)

CLUSTER:
 22. WSFC Cluster Port Compliance Check
     (Live reachability + local firewall-rule audit for cluster ports)

  0. Exit
=================================================================
```

---

## Cluster & AG Safety

### How It Works
The script calls `Get-ClusterEnvironmentInfo` once at startup and caches the result in `$script:ClusterEnv`. All downstream functions reference this cache — no repeated cluster queries.

### What's Detected
| Property | Source |
|----------|--------|
| Cluster membership | `ClusSvc` service status |
| Cluster name & nodes | `Get-Cluster`, `Get-ClusterNode` |
| Heartbeat-only NICs | `Get-ClusterNetwork` Role=1 |
| CSV mount points | `Get-ClusterSharedVolume` |
| Quorum type & witness | `Get-ClusterQuorum` |
| CAU status | `Get-CauRun` |
| AG role (PRIMARY/SECONDARY) | `sys.dm_hadr_availability_replica_states` |
| AG sync health | Same DMV |
| AG listeners | `sys.availability_group_listeners` |

### Safety Measures
- **Gateway pings**: Skip heartbeat-only NICs to avoid false cluster health alerts
- **Trace output paths**: Warn before writing to CSV (prevents I/O storms)
- **Service checks**: SQLSERVERAGENT stopped on SECONDARY = "expected"
- **Patching guidance**: Warn about CAU before suggesting `net stop wuauserv`
- **Cluster logs**: Suggest `$env:TEMP` not shared storage for `Get-ClusterLog`
- **Heavy diagnostics**: Show which cluster groups this node owns

---

## OS Compatibility Matrix

| Feature/Cmdlet | Server 2019 | Server 2022 | Server 2025 |
|----------------|:-----------:|:-----------:|:-----------:|
| Core diagnostics | ✅ | ✅ | ✅ |
| NIC Teaming (LBFO) | ✅ | ✅ | ❌ → SET fallback |
| TCP Chimney property | ⚠️ Deprecated | ⚠️ Deprecated | ❌ Safe-access |
| Get-HotFix .InstalledOn | ⚠️ May be null | ✅ | ✅ |
| Memory Compression counter | ✅ | ✅ | ✅ |
| TLS 1.3 ciphers | ❌ | ✅ | ✅ |
| Invoke-Sqlcmd | Optional | Optional | Optional |
| FailoverClustering log | ✅ | ✅ | ✅ |
| Get-NetSwitchTeam (SET) | ❌ | ✅ Hyper-V only | ✅ |
| OS Lifecycle detection | ✅ Recognized | ✅ Recognized | ✅ Recognized |

---

## Thresholds Reference

### Resource Thresholds (SCOM-aligned)

WARNING tiers match the SCOM Management Pack alert triggers (May 2026) so WSTT triage corroborates SCOM at the same threshold. The in-script CRITICAL tier (95%) acts as a red-flag above SCOM.

```
                       SCOM alert (WARNING)   In-script CRITICAL
CPU                    🟡 85%                 🔴 95%
Memory                 🟡 85%                 🔴 95%
Disk (system drive)    🟡 85%                 🔴 95%
Disk (non-system)      🟡 90%                 🔴 95%
```

### Disk Latency
```
🟢 Very Good:  <10ms
🟢 Acceptable: 10-20ms
🟡 Slow:       20-50ms
🔴 Critical:   >50ms
```

### Memory Pools
```
NonPaged Pool: 🟡 >200MB  🔴 >300MB
Paged Pool:    🟡 >300MB  🔴 >400MB
Page File:     🟡 >70%    🔴 >90%
Available MB:  🟡 <1024MB 🔴 <500MB
```

### Process Thresholds
```
Handles:  🟡 >10,000 per process (potential handle leak)
Threads:  🟡 >500 per process (high thread count)
Private-WS Gap: 🟡 >200MB (potential memory leak)
```

### AG Replication
```
Log Send Queue: 🟡 >10MB (replication lag)
Redo Queue:     🟡 >10MB (secondary applying slowly)
```

### CPU Advanced
```
Per-Core:         🔴 >95% on any single core (hot core)
Privileged Time:  🟡 >15% kernel > user  🔴 >30% kernel
Queue Length:     🟡 >1×cores  🔴 >2×cores
Context Switches: 🟡 >8K/core  🔴 >15K/core
Interrupt/DPC:    🟡 >5%  🔴 >15%
Throttling:       🟡 <95% performance  🔴 <80% performance
DPC Queue:        🔴 >5K/core
NUMA Imbalance:   🟡 >20% memory difference
System Threads:   🟡 >5,000  Processes: 🟡 >500
```

### Disk Advanced
```
Disk Busy:    🟡 >50%  🔴 >80%
Disk Timeout: 🟡 <30s (too aggressive)  🟡 >120s (too long)
VSS Snapshots: 🟡 >10 per volume (orphaned)
Filter Drivers: 🟡 >10 active (latency impact)
```

---

## Output Files

| File Type | Default Location | Format |
|-----------|------------------|--------|
| **HTML Diagnostic Report** | **`%TEMP%\ServerDiagnostics\Logs\`** | **.html** |
| **WSFC Port Compliance HTML** | **`%TEMP%\ServerDiagnostics\Logs\`** | **.html** |
| **WSFC Reachability CSV** | **`%TEMP%\ServerDiagnostics\Logs\`** | **.csv** |
| **WSFC Firewall Audit CSV** | **`%TEMP%\ServerDiagnostics\Logs\`** | **.csv** |
| Diagnostic reports | `%TEMP%\ServerDiagnostics\Logs\` | .txt |
| System reports | `%TEMP%\ServerDiagnostics\Logs\` | .txt |
| TLS reports | `%TEMP%\ServerDiagnostics\Logs\` | .txt |
| .NET version reports | `%TEMP%\ServerDiagnostics\Logs\` | .csv |
| Session transcripts | `%TEMP%\ServerDiagnostics\Logs\` | .log |
| Event log exports | `%TEMP%\ServerDiagnostics\Logs\EventLogs\` | .evtx |
| Service status | `%TEMP%\ServerDiagnostics\Logs\` | .txt |
| Firewall exports | `%TEMP%\ServerDiagnostics\Logs\` | .txt |
| TSS logs | `C:\MS_DATA\` (or user-specified) | Various |

---

## Configuration

### Threshold Customization
Edit the `Set-Variable` constants at the top of the script (lines 103-137). All are declared `-Option ReadOnly` and reflect the SCOM-aligned defaults:

```powershell
# Resource Thresholds (ReadOnly, SCOM-aligned)
Set-Variable -Name MEMORY_CRITICAL_THRESHOLD         -Value 95   # Memory usage % critical
Set-Variable -Name MEMORY_WARNING_THRESHOLD          -Value 85   # Memory usage % warning (SCOM alert)
Set-Variable -Name CPU_CRITICAL_THRESHOLD            -Value 95   # CPU usage % critical
Set-Variable -Name CPU_WARNING_THRESHOLD             -Value 85   # CPU usage % warning (SCOM alert)
Set-Variable -Name DISK_SYSTEM_CRITICAL_THRESHOLD    -Value 95   # System drive % critical
Set-Variable -Name DISK_SYSTEM_WARNING_THRESHOLD     -Value 85   # System drive % warning (SCOM alert)
Set-Variable -Name DISK_NONSYSTEM_CRITICAL_THRESHOLD -Value 95   # Non-system drive % critical
Set-Variable -Name DISK_NONSYSTEM_WARNING_THRESHOLD  -Value 90   # Non-system drive % warning (SCOM alert)
Set-Variable -Name DISK_LATENCY_CRITICAL_MS          -Value 50   # Read/write latency critical (ms)
Set-Variable -Name NONPAGED_POOL_CRITICAL_MB         -Value 300  # NonPaged pool critical (MB)
Set-Variable -Name PAGED_POOL_CRITICAL_MB            -Value 400  # Paged pool critical (MB)
Set-Variable -Name AVAILABLE_MB_CRITICAL             -Value 500  # Available memory critical (MB)
Set-Variable -Name HANDLE_LEAK_WARNING               -Value 10000 # Handle count warning per process
Set-Variable -Name PAGEFILE_USAGE_CRITICAL_PERCENT   -Value 90   # Page file usage critical %
```

> [!NOTE]
> Legacy aliases `DISK_CRITICAL_THRESHOLD` (95) and `DISK_WARNING_THRESHOLD` (90) are retained for external/test consumers that still reference the original names.

### TSS Path
```powershell
$script:TSSPath = "C:\TSS"  # Default — change or use Option 15 at runtime
```

### Log Path
```powershell
$script:TempBasePath = Join-Path $env:TEMP "ServerDiagnostics"
$script:DefaultLogPath = Join-Path $script:TempBasePath "Logs"
```

---

## Troubleshooting the Script

| Issue | Solution |
|-------|----------|
| "Requires Administrator" | Run PowerShell as Administrator |
| "Execution policy" error | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| "TSS not found" | Download TSS, extract to `C:\TSS`, or use Option 15 |
| Locale parsing failures | English-only tools (w32tm, klist); verify manually via GUI |
| LBFO cmdlets missing | Server 2025 — script auto-falls back to SET |
| AG detection fails | Install SqlServer module or ensure SQL is running |
| Chimney error on newer OS | Handled — shows "N/A (removed on this OS)" |

---

## Performance Impact

| Activity | CPU | Memory | Disk I/O |
|----------|-----|--------|----------|
| Diagnostics (options 1-9) | <5% | <100MB | Low |
| Health Scorecard (option 10) | <3% | <50MB | Low |
| TLS Validation (option 13) | <2% | <50MB | Low |
| TSS Trace Collection | 5-15% | 200-500MB | Medium-High |
| Performance Monitor | <2% | 50-200MB | Medium |

**Safe for production servers.** Diagnostics are read-only. TSS traces should be time-limited.

---

## Script Stats

| Metric | Value |
|--------|-------|
| Total lines | ~11,470 |
| Functions | 62 (PowerShell) |
| Total diagnostic checks | 159+ |
| Menu options | 23 (0-22) |
| OS versions supported | 2019, 2022, 2025 |
| Cluster-safe checks | 13 |
| New in v3.0 | 27 network, 24 CPU, 24 disk, 19 memory, 8 task scheduler, 9 baseline, HTML report, cluster/AG awareness, **9 WSFC port-compliance checks** |
| Pester test coverage | 51 tests (33 base + 18 WSFC) — all passing |

---

## License & Support

### Maintainer
**Kaustubh Sharma** — author and maintainer of WSTT v3.0.

### Reporting Issues
When reporting issues, include:
- Windows Server version and build (`$PSVersionTable`, `[environment]::OSVersion`)
- PowerShell version
- Full error message text
- Cluster/AG configuration (if applicable)
- Locale (`(Get-Culture).Name`)
