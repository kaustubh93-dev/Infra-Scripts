# Server Validator v5.0S

PowerShell script that generates a comprehensive HTML report of Windows Server SOE (Standard Operating Environment) attributes — covering hardware, OS, network, disk, cluster, services, security, and performance.

## Compatibility

| OS | Build | Status |
|---|---|---|
| Windows Server 2016 | 14393 | ✅ Supported |
| Windows Server 2019 | 17763 | ✅ Supported |
| Windows Server 2022 | 20348 | ✅ Supported |
| Windows Server 2025 | 26100 | ✅ Supported |

## Quick Start

```powershell
# Basic run (requires Administrator)
.\Validator_v5.0S.ps1

# With compliance settings and transcript logging
.\Validator_v5.0S.ps1 -SettingsFile "C:\Config\baseline.csv" -EnableLogging

# Custom output path
.\Validator_v5.0S.ps1 -OutputPath "D:\Reports"
```

## Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-SettingsFile` | No | — | CSV file with compliance definitions |
| `-OutputPath` | No | `C:\Windows\ServerScanner` | Report output directory |
| `-EnableLogging` | No | Off | Enables PowerShell transcript |

## Report Sections (23)

| # | Section | # | Section |
|---|---|---|---|
| 1 | General Information | 13 | TCP Chimney / RSS Settings |
| 2 | NIC Configuration | 14 | Clear PageFile at Shutdown |
| 3 | Disk Configuration | 15 | 8.3 Naming Creation |
| 4 | Windows Features | 16 | Pending Reboot Status |
| 5 | Updates & Hotfixes | 17 | Mount Disk / Block Size |
| 6 | Software Inventory | 18 | Stopped Autostart Services |
| 7 | Power Management | 19 | Cluster Report |
| 8 | Firewall Status | 20 | Physical Disk Perf Counters |
| 9 | NIC Power Management | 21 | Processor Perf Counters |
| 10 | Page File Config | 22 | Memory Perf Counters |
| 11 | Memory Dump Settings | 23 | Event Log Export (CSV+EVTX) |
| 12 | System File Versions | | |

## Output

```
C:\Windows\ServerScanner\
  └── HOSTNAME-Report-09-03-2026-11-50\
        ├── HOSTNAME_ServerValidator_Report.html   ← Main report
        ├── HOSTNAME_113000_09-03-2026.log         ← Execution log
        ├── System_EventLog.csv / .evtx            ← Event exports
        ├── Application_EventLog.csv / .evtx
        └── ClusterLog.log                         ← (if cluster node)
  └── HOSTNAME-Report-09-03-2026-11-50.zip         ← Compressed archive
```

## Key Improvements over v3/v4

- **No deprecated WMI** — all `Get-WmiObject` replaced with `Get-CimInstance`
- **Proper error handling** — 48 Try/Catch blocks; no unprotected external calls
- **No undefined variables** — `$Settings` and `$swdefinitions` loaded from `-SettingsFile`
- **No `Invoke-Expression`** — replaced with call operator `&`
- **Structured logging** — `[INFO/WARN/ERROR]` severity levels with timestamps
- **Cluster safety** — checks `ClusSvc` service before calling cluster cmdlets
- **Modern HTML** — collapsible sections, responsive CSS, color-coded status
- **Exit codes** — `0` success, `1` failure (CI/CD friendly)

## Requirements

- **PowerShell 5.1+**
- **Run as Administrator** (enforced via `#Requires -RunAsAdministrator`)
