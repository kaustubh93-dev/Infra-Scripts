# Windows Server Troubleshooting & Log Collection Tool

## Overview

A comprehensive PowerShell-based interactive diagnostic tool for **Windows Server 2019, 2022, and 2025**. Diagnoses and collects logs for Network, Memory, CPU, Disk, Services, Event Logs, DNS, Security & Authentication, Windows Update, TLS/SSL, IIS, and **Cluster/SQL AG environments**.

**Version:** 3.0  
**Requires:** Administrator privileges, PowerShell 5.1+  
**Tested On:** Windows Server 2019 (Build 17763), 2022 (Build 20348), 2025 (Build 26100)

> [!NOTE]
> Performance counter names (`Get-Counter`) are locale-dependent and require an English OS installation. External tools (`w32tm`, `net accounts`, `klist`, `secedit`) also produce English-only output. The tool detects non-English locales at startup and warns accordingly.

---

## What's New in v3.0 (from v2.5)

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

---

## Features

### 🔍 Primary Diagnostics (Options 1-9)
| Option | Category | Check Count |
|--------|----------|-------------|
| 1 | Network Issues | 25+ checks |
| 2 | Memory Issues | 19 checks |
| 3 | CPU Issues | 8+ checks + AG replication counters |
| 4 | Disk/Storage Issues | 9+ checks |
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

### 📊 Utilities (Options 12-18)
| Option | Feature |
|--------|---------|
| 12 | Generate System Report |
| 13 | TLS Configuration Validation |
| 14 | Validator Script Information |
| 15 | Configure TSS Path |
| 16 | Check TSS Status |
| 17 | .NET Framework Version Check |
| 18 | IIS Troubleshooting & Diagnostics |

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
  3. CPU Issues (High Usage, Process Analysis)
  4. Disk/Storage Issues (Latency, Performance)
  5. Windows Services Health
  6. Event Log Analysis
  7. DNS Health & Connectivity
  8. Security & Authentication
  9. Windows Update Status
 10. Cross-Category Health Scorecard

ADDITIONAL SCENARIOS:
 11. Additional Troubleshooting Scenarios

UTILITIES:
 12-18. Reports, TLS, TSS, .NET, IIS

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

### Resource Thresholds
```
Memory:   🟢 <80%  🟡 80-90%  🔴 >90%
CPU:      🟢 <80%  🟡 80-90%  🔴 >90%
Disk:     🟢 <80%  🟡 80-90%  🔴 >90%
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

---

## Output Files

| File Type | Default Location | Format |
|-----------|------------------|--------|
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
Edit constants at the top of the script (lines 33-63):

```powershell
# Resource Thresholds (ReadOnly)
$MEMORY_CRITICAL_THRESHOLD = 90      # Memory usage % critical
$CPU_CRITICAL_THRESHOLD = 90         # CPU usage % critical
$DISK_CRITICAL_THRESHOLD = 90        # Disk usage % critical
$DISK_LATENCY_CRITICAL_MS = 50       # Read/write latency critical (ms)
$NONPAGED_POOL_CRITICAL_MB = 300     # NonPaged pool critical (MB)
$PAGED_POOL_CRITICAL_MB = 400        # Paged pool critical (MB)
$AVAILABLE_MB_CRITICAL = 500         # Available memory critical (MB)
$HANDLE_LEAK_WARNING = 10000         # Handle count warning per process
$PAGEFILE_USAGE_CRITICAL_PERCENT = 90 # Page file usage critical %
```

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
| Total lines | ~6,050 |
| Functions | 52 |
| Diagnostic checks | 80+ |
| OS versions supported | 2019, 2022, 2025 |
| Cluster-safe checks | 12 |
| New in v3.0 | 27 network checks, 19 memory checks, cluster/AG awareness |

---

## License & Support

### Reporting Issues
When reporting issues, include:
- Windows Server version and build (`$PSVersionTable`, `[environment]::OSVersion`)
- PowerShell version
- Full error message text
- Cluster/AG configuration (if applicable)
- Locale (`(Get-Culture).Name`)
