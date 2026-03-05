# Windows Server Troubleshooting & Log Collection Tool

**Version 2.1** | PowerShell 5.1+ | Requires Administrator

An interactive, menu-driven PowerShell script for diagnosing and collecting logs across all major Windows Server subsystems — network, memory, CPU, disk, services, event logs, DNS, security, and Windows Update.

---

## Quick Start

```powershell
# Basic run
.\Windows Server Troubleshooting Tool - Advance Version 2.1.ps1

# With session transcript logging
.\Windows Server Troubleshooting Tool - Advance Version 2.1.ps1 -EnableLogging
```

> **Note:** Must be run as Administrator. The script will check and prompt if not elevated.

---

## Features

### Primary Diagnostics

| Module | Key Checks |
|--------|------------|
| **1. Network** | TCP/IP config, driver info, NIC performance counters, SMB, MTU, RSS/VMQ, offloading, ephemeral ports, connectivity, power plan |
| **2. Memory** | Page file, memory pools, working sets, handle/leak detection (opt-in, ~5 min), NUMA, compression, standby, kernel/driver memory, commit charge, page faults |
| **3. CPU** | Overall usage, per-process analysis, top consumers by CPU and memory |
| **4. Disk/Storage** | Latency, IOPS, space usage, cluster size validation (64KB for databases) |
| **5. Services** | Auto-start service health, critical service status, failure history, recovery actions, service accounts |
| **6. Event Logs** | Log sizes, critical/error analysis, specific Event ID checks (disk, memory, cluster), pattern detection |
| **7. DNS** | Server connectivity, resolution performance, cache stats, suffix config, DNS Server role check, reverse lookup |
| **8. Security** | Certificate validation, Kerberos tickets, account lockouts, failed logins, firewall status, Windows Defender, audit report |
| **9. Windows Update** | Service status, update history, pending/failed updates, reboot status, WSUS config, cache size |

### Additional Scenarios (Menu Option 10)

- Unexpected Reboot analysis
- Slow Boot / Slow Logon traces
- Server Crash / BugCheck / Hang (memory dump guidance)
- Application Crash (ProcDump setup)
- SQL Server diagnostics
- Cluster diagnostics (with Event 1135 monitoring)
- OS Patch troubleshooting (DISM, SFC, component reset)
- Server Assessment (perfmon + validator)
- Event Log export (System, Application, Security)

### Utilities (Menu Options 11–15)

- **System Report** — One-click full system summary (OS, memory, CPU, disk, network, services, power plan)
- **TLS Validation** — Protocol status, .NET config, cipher suite audit, weak cipher detection
- **Validator Info** — ServerScanner HTML output guidance
- **TSS Path Config** — Set/change the TSS tool location
- **TSS Status** — Verify TSS availability

---

## Log Collection & TSS Integration

Each diagnostic module includes a **log collection** submenu with options for:

- **TSS-based collection** — Automated traces using Microsoft's [TroubleShootingScript (TSS)](https://aka.ms/getTSS) tool
- **Manual commands** — `netsh trace`, `logman`, `wevtutil`, `perfmon` commands displayed for copy/paste
- **Export options** — CSV, EVTX, and text report exports to configurable paths

Default log path: `%TEMP%\ServerDiagnostics\Logs`

### Configuring TSS

TSS defaults to `C:\TSS`. Change via Menu Option 14, or ensure `TSS.ps1` is located at the configured path.

---

## Thresholds

| Resource | Warning | Critical |
|----------|---------|----------|
| Memory Usage | 80% | 90% |
| CPU Usage | 80% | 90% |
| Disk Space | 80% | 90% |
| Disk Latency | 20ms | 50ms |
| DNS Resolution | 30ms | 100ms |
| Port Exhaustion | 80% | — |

---

## Script Architecture

```
Script Entry Point
  └── Start-TroubleshootingTool [-EnableLogging]
        ├── Initialize-DiagnosticPaths
        └── Show-MainMenu (interactive loop)
              │
              ├── 1. Network Diagnostics
              │     ├── Test-NetworkConfiguration (main)
              │     │     ├── Test-TCPIPConfiguration
              │     │     ├── Test-NetworkDriverInfo
              │     │     ├── Test-NICPerformance
              │     │     ├── Test-NetworkOffloading
              │     │     ├── Test-SMBConfiguration
              │     │     ├── Test-ConnectivityTests
              │     │     ├── Test-MTUConfiguration
              │     │     ├── Test-AdvancedAdapterSettings
              │     │     ├── Test-TCPIPTuning
              │     │     ├── Test-NetBIOSWINS
              │     │     ├── Test-RSSConfiguration
              │     │     ├── Test-VMQConfiguration
              │     │     ├── Test-EphemeralPorts
              │     │     └── Test-PowerPlan
              │     └── Start-NetworkLogCollection
              │
              ├── 2. Memory Diagnostics
              │     ├── Test-MemoryUsage (main)
              │     │     ├── Test-PageFileConfiguration
              │     │     ├── Test-MemoryPools
              │     │     ├── Test-ProcessWorkingSets
              │     │     ├── Test-HandleCount
              │     │     ├── Test-SystemCache
              │     │     ├── Test-AvailableMemoryBreakdown
              │     │     ├── Test-NUMAMemoryAnalysis
              │     │     ├── Test-MemoryCompression
              │     │     ├── Test-ModifiedPageList
              │     │     ├── Test-StandbyMemory
              │     │     ├── Test-KernelMemory
              │     │     ├── Test-DriverMemoryUsage
              │     │     ├── Test-PrivateVsVirtualBytes
              │     │     ├── Test-MemoryMappedFiles
              │     │     ├── Test-CommitCharge
              │     │     ├── Test-PageFaultAnalysis
              │     │     └── Test-MemoryLeakDetection (opt-in)
              │     └── Start-MemoryLogCollection
              │
              ├── 3. CPU Diagnostics
              │     ├── Test-CPUUsage
              │     └── Start-CPULogCollection
              │
              ├── 4. Disk/Storage Diagnostics
              │     ├── Test-DiskPerformance
              │     └── Start-DiskLogCollection
              │
              ├── 5. Services Health
              │     ├── Test-ServicesHealth
              │     └── Start-ServicesLogCollection
              │
              ├── 6. Event Log Analysis
              │     ├── Test-EventLogHealth
              │     └── Start-EventLogCollection
              │
              ├── 7. DNS Health
              │     ├── Test-DNSHealth
              │     └── Start-DNSLogCollection
              │
              ├── 8. Security & Authentication
              │     ├── Test-SecurityAuthentication
              │     └── Start-SecurityLogCollection
              │
              ├── 9. Windows Update
              │     ├── Test-WindowsUpdateStatus
              │     └── Start-WindowsUpdateLogCollection
              │
              ├── 10. Show-AdditionalScenarios
              ├── 11. Export-SystemReport
              ├── 12. Test-TLSConfiguration / Export-TLSReport
              ├── 13. Show-ValidatorInfo
              ├── 14. Set-TSSPath
              └── 15. Test-TSSAvailable

Helper Functions:
  ├── Write-Header / Write-Info / Write-Success / Write-Warning / Write-Error
  ├── Get-ValidatedChoice
  ├── Test-PathValid
  ├── Get-ProcessAnalysis
  ├── Show-PerfmonCommand / Show-StorPortCommands / Show-NetworkTraceCommand
  ├── Test-TSSAvailable / Invoke-TSSCommand / Invoke-WithTSSCheck
  └── Initialize-DiagnosticPaths / Set-TSSPath
```

---

## Requirements

- **OS:** Windows Server 2012 R2 or later
- **PowerShell:** 5.1 or 7.x
- **Privileges:** Administrator (enforced at startup)
- **Optional:** [TSS Tool](https://aka.ms/getTSS) for advanced log collection

## Output

| Type | Location |
|------|----------|
| Session transcript | `%TEMP%\ServerDiagnostics\Logs\TroubleshootingTool_<timestamp>.log` |
| Diagnostic reports | `%TEMP%\ServerDiagnostics\Logs\<module>\` |
| Event log exports | User-specified or default log path |
| CSV exports | User-specified or default log path |

---

## Monitored Critical Services

`DNS`, `DHCP`, `Spooler`, `W32Time`, `EventLog`, `WinRM`, `RpcSs`, `LanmanServer`, `LanmanWorkstation`, `MSSQLSERVER`, `SQLSERVERAGENT`, `W3SVC`, `IISADMIN`

---

## License

Internal use. For Windows Server troubleshooting and diagnostics.
