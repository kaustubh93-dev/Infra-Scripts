# Server Validator v5.0

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows%20Server-2016%20%7C%202019%20%7C%202022%20%7C%202025-0078D4?logo=windows&logoColor=white)
![Version](https://img.shields.io/badge/Version-5.0-green)
![License](https://img.shields.io/badge/License-AS--IS-lightgrey)

A comprehensive PowerShell-based auditing tool that generates a detailed HTML report of Windows Server Standard Operating Environment (SOE) attributes. In a single execution, it inspects 23 configuration areas — from hardware and networking to cluster health and performance counters — and produces a self-contained, color-coded HTML5 report with a ZIP archive ready for review, archival, or handoff.

**v5.0 is a complete rewrite** of the original v3.0 (2018) script, resolving 38 identified issues spanning security vulnerabilities, deprecated cmdlets, undefined variables, missing error handling, and performance bottlenecks.

---

## Table of Contents

- [Features](#features)
- [Compatibility Matrix](#compatibility-matrix)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Parameters](#parameters)
- [Report Sections](#report-sections)
- [Output Structure](#output-structure)
- [Settings File Format](#settings-file-format)
- [What's New in v5.0](#whats-new-in-v50)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Version History](#version-history)

---

## Features

- **23 inspection sections** covering hardware, OS, network, disk, cluster, security, services, and performance
- **Modern HTML5 report** with collapsible sections, responsive CSS, and color-coded status indicators (green / amber / red)
- **ZIP archive** of all output artifacts for easy transfer and archival
- **Compliance checking** via optional CSV settings file for software baselines and version validation
- **Cluster-aware** — safely detects Failover Clustering via `ClusSvc` service before invoking cluster cmdlets
- **48 Try/Catch blocks** — every external call is protected with structured error handling
- **Structured logging** with `[INFO]` / `[WARN]` / `[ERROR]` severity levels and optional transcript support
- **Performance optimized** — OS queries cached at startup, `ArrayList` collections, `foreach` over pipeline
- **CI/CD friendly** — returns exit code `0` on success, `1` on failure
- **Zero dependencies** — runs on native PowerShell 5.1+ with no external modules

---

## Compatibility Matrix

| Operating System       | Build Number | Status         |
|:-----------------------|:-------------|:---------------|
| Windows Server 2016    | 14393        | ✅ Supported   |
| Windows Server 2019    | 17763        | ✅ Supported   |
| Windows Server 2022    | 20348        | ✅ Supported   |
| Windows Server 2025    | 26100+       | ✅ Supported   |

> **Note:** The script uses build-number detection (`Win32_OperatingSystem.BuildNumber`) to adapt behavior per OS version where required.

---

## Prerequisites

| Requirement            | Details                                                        |
|:-----------------------|:---------------------------------------------------------------|
| **PowerShell**         | Version 5.1 or later (ships with Server 2016+)                |
| **Privileges**         | Administrator — enforced via `#Requires -RunAsAdministrator`   |
| **Execution Policy**   | Must allow script execution (`RemoteSigned` or `Bypass`)       |
| **Disk Space**         | ~10–50 MB depending on event log size                          |
| **Network** (optional) | Not required; all checks are local                             |

---

## Installation

1. **Download** or clone the script to the target server:
   ```powershell
   # Example: copy to a local tools directory
   Copy-Item -Path "\\FileServer\Scripts\Validator_v5.0S.ps1" -Destination "C:\Tools\"
   ```
2. **Unblock** the file if downloaded from the internet:
   ```powershell
   Unblock-File -Path "C:\Tools\Validator_v5.0S.ps1"
   ```
3. **Verify** execution policy allows the script to run:
   ```powershell
   Get-ExecutionPolicy
   # If Restricted, run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

No external modules are required. The script is fully self-contained.

---

## Quick Start

Open an **elevated PowerShell prompt** (Run as Administrator) and execute:

```powershell
# 1. Basic run — uses default output path C:\Windows\ServerScanner
.\Validator_v5.0S.ps1
```

```powershell
# 2. With compliance baseline and transcript logging
.\Validator_v5.0S.ps1 -SettingsFile "C:\Config\baseline.csv" -EnableLogging
```

```powershell
# 3. Custom output directory
.\Validator_v5.0S.ps1 -OutputPath "D:\ServerReports" -EnableLogging
```

The script displays real-time progress (`[1/23] Collecting general information...`) and prints the report path on completion.

---

## Parameters

| Parameter        | Type     | Required | Default                      | Description                                                                 |
|:-----------------|:---------|:---------|:-----------------------------|:----------------------------------------------------------------------------|
| `-SettingsFile`  | `String` | No       | —                            | Path to a CSV file containing compliance baseline definitions for software validation and version checks. |
| `-OutputPath`    | `String` | No       | `C:\Windows\ServerScanner`   | Root directory where the report folder and ZIP archive are created.          |
| `-EnableLogging` | `Switch` | No       | Off                          | Enables PowerShell transcript logging to an additional `.log` file for troubleshooting. |

---

## Report Sections

The script collects data across 23 sections, each rendered as a collapsible panel in the HTML report:

| #  | Section                        | What It Checks                                                        |
|:---|:-------------------------------|:----------------------------------------------------------------------|
| 1  | General Information            | Hostname, hardware model, OS, domain, PowerShell version, OU          |
| 2  | NIC Configuration              | Adapter priority, Rx buffers, ring size, TCP offload thresholds       |
| 3  | Disk Configuration             | Drive letters, capacity, free space (10% threshold), file system type |
| 4  | Windows Features               | Installed roles and features                                          |
| 5  | Updates & Hotfixes             | Installed KBs with staleness detection                                |
| 6  | Software Inventory             | Installed software from registry with optional compliance checking    |
| 7  | Power Management               | Active power plan — flags non-"High Performance" plans                |
| 8  | Firewall Status                | Per-profile state: enabled, default inbound/outbound action           |
| 9  | NIC Power Management           | Detects power-saving features that can cause packet loss              |
| 10 | Page File Configuration        | Current size vs. RAM-based multiplier recommendation                  |
| 11 | Memory Dump Settings           | Dump type validation (Kernel, Complete, Automatic)                    |
| 12 | System File Versions           | Versions of critical drivers: `tcpip.sys`, `afd.sys`, and others     |
| 13 | TCP Chimney / RSS Settings     | TCP offload engine and Receive Side Scaling configuration             |
| 14 | Clear PageFile at Shutdown     | Registry setting for secure page file clearing                        |
| 15 | 8.3 Naming Creation            | Whether legacy short-name creation is disabled (recommended)          |
| 16 | Pending Reboot Status          | Checks registry keys for pending restart flags                        |
| 17 | Mount Disk / Block Size        | Volume mount points and allocation unit size                          |
| 18 | Stopped Autostart Services     | Services set to Automatic that are not currently running              |
| 19 | Cluster Report                 | Cluster name, groups, resources, networks, CSVs, exported log         |
| 20 | Physical Disk Perf Counters    | Disk read/write latency, queue length, throughput                     |
| 21 | Processor Perf Counters        | CPU utilization, interrupt rate, DPC rate                             |
| 22 | Memory Perf Counters           | Available MB, pages/sec, committed bytes, pool usage                  |
| 23 | Event Log Export               | Last 7 days of System and Application logs (CSV + EVTX)              |

---

## Output Structure

Each execution produces a timestamped report folder and a compressed archive:

```
C:\Windows\ServerScanner\                              ← Root output directory
│
├── HOSTNAME-Report-DD-MM-YYYY-HH-mm\                 ← Report folder
│   ├── HOSTNAME_ServerValidator_Report.html           ← Main HTML report
│   ├── HOSTNAME_HHMMSS_DD-MM-YYYY.log                ← Execution log
│   ├── System_EventLog.csv                            ← System log (CSV)
│   ├── System_EventLog.evtx                           ← System log (native)
│   ├── Application_EventLog.csv                       ← Application log (CSV)
│   ├── Application_EventLog.evtx                      ← Application log (native)
│   ├── ClusterLog.log                                 ← Cluster log (if node)
│   └── HOSTNAME_Transcript.log                        ← Transcript (if -EnableLogging)
│
└── HOSTNAME-Report-DD-MM-YYYY-HH-mm.zip              ← Compressed archive
```

> **Tip:** The ZIP archive contains all files from the report folder, making it convenient for attaching to support tickets or uploading to a central repository.

---

## Settings File Format

The optional `-SettingsFile` parameter accepts a CSV with the following structure:

```csv
category,Name,Compliant_Value
version,BaselineVersion,2.1
software,Microsoft Visual C++ 2019,14.28.29913
software,.NET Framework,4.8.0
software,CrowdStrike Windows Sensor,7.10
```

| Column             | Description                                                  |
|:-------------------|:-------------------------------------------------------------|
| `category`         | Row type: `version` for baseline version, `software` for application compliance checks |
| `Name`             | Display name of the software (matched against installed software registry entries) |
| `Compliant_Value`  | Expected version or value to validate against                |

When a settings file is provided, the Software Inventory section compares installed software against the defined baselines and highlights discrepancies.

---

## What's New in v5.0

v5.0 is a ground-up rewrite addressing **38 issues** identified in v3.0 and v4.0. Changes are organized by category:

### Security
| ID  | Fix                                                                           |
|:----|:------------------------------------------------------------------------------|
| S1  | Removed all `Invoke-Expression` usage — replaced with call operator `&`       |
| S2  | Added `#Requires -RunAsAdministrator`, `[CmdletBinding()]`, proper `param()` block |

### Code Quality
| ID  | Fix                                                                           |
|:----|:------------------------------------------------------------------------------|
| Q1  | Fixed undefined `$Settings` variable — now loaded from `-SettingsFile` parameter |
| Q2  | Fixed undefined `$swdefinitions` — derived from settings file with null-safe handling |
| Q3  | Replaced all 20+ `Get-WmiObject` calls with `Get-CimInstance` (WMI deprecated) |
| Q4  | Added comprehensive comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.EXAMPLE`) |
| Q5  | Replaced all aliases (`?`, `%`, `gwmi`, `select`) with full cmdlet names      |
| Q6  | Renamed `Parse-LGPO` to `ConvertFrom-LGPO` (approved verb)                    |
| Q7  | Set `$ErrorActionPreference = "Stop"` at script scope                         |
| Q9  | Fixed smart quotes (non-ASCII characters) that caused runtime failures        |
| Q11 | Updated script version constant to 5.0                                        |
| Q12 | Populated firewall Profile column (was previously empty)                      |

### Error Handling
| ID  | Fix                                                                           |
|:----|:------------------------------------------------------------------------------|
| E1–E8 | Added **48 Try/Catch blocks** — every CIM query, registry read, WMI call, and file operation is protected |
| E4  | Implemented exit codes: `0` (success), `1` (failure) for CI/CD integration    |

### Logging
| ID  | Fix                                                                           |
|:----|:------------------------------------------------------------------------------|
| L1  | Created centralized `Write-Log` function with timestamp and severity levels   |
| L2  | All 38 functions emit structured log entries (`[INFO]` / `[WARN]` / `[ERROR]`) |
| L3  | Added optional `-EnableLogging` for PowerShell transcript capture             |
| L4  | Execution log written per run with full audit trail                           |

### Performance
| ID  | Fix                                                                           |
|:----|:------------------------------------------------------------------------------|
| P1  | Cached `Win32_OperatingSystem` and `Win32_ComputerSystem` at startup — queried once, reused everywhere |
| P2  | Replaced `+=` array concatenation with `[System.Collections.ArrayList]` in all loops |
| P3  | Used `foreach` statement over `ForEach-Object` pipeline for tight loops       |

### Compatibility & Safety
| ID  | Fix                                                                           |
|:----|:------------------------------------------------------------------------------|
| W3  | Cluster safety — verifies `ClusSvc` service exists and is running before calling `Get-Cluster*` cmdlets |
| W4  | Fixed brace-nesting issues that caused silent logic errors                    |

---

## Architecture

The script (~2,500 lines) is organized into clearly delimited `#region` blocks:

```
┌─────────────────────────────────────────────────┐
│  Script Header & Parameters                     │  Lines 1–90
│  #Requires, CmdletBinding, param block          │
├─────────────────────────────────────────────────┤
│  Initialization                                 │  Lines 91–228
│  Variables, logging, OS caching, settings load  │
├─────────────────────────────────────────────────┤
│  HTML Helper Functions (6 functions)            │  Lines 230–720
│  New-HTMLReport, Add-HTMLSection, Add-HTMLTable  │
│  Add-HTMLDetail, Add-HTMLNewDetail, Close-HTML   │
├─────────────────────────────────────────────────┤
│  Data Collection Functions (31 functions)        │  Lines 722–1906
│  Get-PSInfo, Get-NICConfiguration,              │
│  Get-DiskConfiguration, Get-ClusterInfo, etc.   │
├─────────────────────────────────────────────────┤
│  Main Execution Block                           │  Lines 1908–2137
│  Sequential [1/23]–[23/23] collection steps     │
├─────────────────────────────────────────────────┤
│  HTML Report Generation                         │  Lines 2138–2447
│  Assembles all collected data into HTML         │
├─────────────────────────────────────────────────┤
│  Finalization                                   │  Lines 2448–2497
│  ZIP compression, transcript stop, summary      │
└─────────────────────────────────────────────────┘
```

**Execution flow:**

1. **Initialize** — Validate parameters, create output directories, start logging
2. **Cache** — Query OS and computer system information once via CIM
3. **Collect** — Execute 23 data-collection steps sequentially with progress output
4. **Render** — Assemble all collected data into a single HTML5 report
5. **Package** — Compress the report folder into a ZIP archive
6. **Exit** — Stop transcript (if enabled), return exit code

Each data-collection function follows the same pattern: log entry → Try/Catch around external calls → return structured data → log result or error.

---

## Troubleshooting

| Symptom | Cause | Resolution |
|:--------|:------|:-----------|
| **"Access Denied"** on launch | Script not running as Administrator | Right-click PowerShell → *Run as Administrator*, or use `#Requires` will enforce this automatically |
| **"Execution policy"** error | Script execution is restricted | Run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` or launch with `-ExecutionPolicy Bypass` |
| **Script hangs on section 19** (Cluster) | `Get-Cluster` cmdlets timeout on non-cluster nodes | Should not occur — v5.0 checks `ClusSvc` first. If it does, verify the service state: `Get-Service ClusSvc` |
| **Empty Software Inventory** | Registry paths inaccessible | Verify Administrator privileges; check HKLM access on hardened systems |
| **HTML report is blank** | An early fatal error aborted execution | Check the `.log` file in the report folder for `[ERROR]` entries |
| **ZIP creation fails** | Insufficient disk space or path too long | Ensure the output drive has free space; try a shorter `-OutputPath` |
| **Event log export is large** | Servers with high event volume | This is expected; the EVTX export captures the last 7 days of logs |
| **Settings file not loaded** | Path incorrect or CSV malformed | Verify the file exists and matches the expected CSV schema (see [Settings File Format](#settings-file-format)) |

> **Debug tip:** Run with `-EnableLogging` and review both the execution `.log` and the `_Transcript.log` for full diagnostic output.

---

## Contributing

Contributions are welcome. To submit an improvement:

1. **Fork** this repository
2. **Create a feature branch**: `git checkout -b feature/your-improvement`
3. **Follow existing conventions**:
   - Use `#region` / `#endregion` blocks for organization
   - Add `[CmdletBinding()]` and `param()` to all functions
   - Wrap external calls in `Try/Catch` with `Write-Log`
   - Use full cmdlet names (no aliases)
   - Use `Get-CimInstance` instead of `Get-WmiObject`
4. **Test** on at least two supported OS versions
5. **Submit a Pull Request** with a clear description of changes

### Coding Standards

- PowerShell 5.1 compatibility (no PowerShell 7-only features)
- Approved verbs only (`Get-Verb` to list)
- Strict mode: `$ErrorActionPreference = "Stop"`
- All strings use straight quotes — no smart/curly quotes

---

## License

```
ALL SCRIPTS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
```

This script is provided for use in enterprise server environments. Use at your own risk. Always test in a non-production environment first.

---

## Version History

| Version | Year | Highlights                                                                                      |
|:--------|:-----|:------------------------------------------------------------------------------------------------|
| **3.0** | 2018 | Initial release — WMI-based collection, basic HTML output, no error handling                    |
| **4.0** | 2020 | Incremental improvements — additional report sections, partial WMI migration                    |
| **5.0** | 2026 | Complete rewrite — 38 issues fixed, `Get-CimInstance` throughout, 48 Try/Catch blocks, structured logging, modern HTML5 report, Server 2025 support, compliance checking, CI/CD exit codes |

---

<p align="center">
  <strong>Server Validator v5.0</strong> — Built for Windows Server teams who need reliable, repeatable SOE auditing.
</p>
