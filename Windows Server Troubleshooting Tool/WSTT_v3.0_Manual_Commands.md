# WSTT v3.0 — Manual Commands Reference & Test Checklist

> All manual commands displayed by the Windows Server Troubleshooting Tool v3.0.
> Reviewed for correctness. Issues flagged with ⚠️.

---

## Table of Contents

1. [Network Trace Commands](#1-network-trace-commands)
2. [StorPort / Disk Trace Commands](#2-storport--disk-trace-commands)
3. [Performance Monitor (Perfmon) Commands](#3-performance-monitor-perfmon-commands)
4. [DNS Diagnostic Commands](#4-dns-diagnostic-commands)
5. [TSS (TroubleShootingScript) Commands](#5-tss-troubleshootingscript-commands)
6. [Additional Scenario Commands](#6-additional-scenario-commands)
7. [TLS/SSL Configuration Commands](#7-tlsssl-configuration-commands)
8. [Windows Update / OS Repair Commands](#8-windows-update--os-repair-commands)
9. [Event Log Export Commands](#9-event-log-export-commands)
10. [Inline Remediation Commands](#10-inline-remediation-commands)

---

## 1. Network Trace Commands

**Source:** `Show-NetworkTraceCommand` (Menu → 1 → 3)

### Start Trace

**CMD (correct as-is):**

```cmd
netsh trace start scenario=netconnection globallevel=5 capture=yes report=no overwrite=yes persistent=yes maxsize=1024 tracefile=C:\temp\casedata\%computername%.etl
```

**PowerShell equivalent:**

```powershell
New-Item -Path "C:\temp\casedata" -ItemType Directory -Force | Out-Null
netsh trace start scenario=netconnection globallevel=5 capture=yes report=no overwrite=yes persistent=yes maxsize=1024 tracefile="C:\temp\casedata\$env:COMPUTERNAME.etl"
```

### Stop Trace

```
netsh trace stop
```

### Review Notes

| Parameter | Value | Verdict |
|---|---|---|
| `scenario=netconnection` | Valid scenario | ✅ Correct |
| `globallevel=5` | Verbose level | ✅ Correct |
| `capture=yes` | Packet capture | ✅ Correct |
| `report=no` | Skip CAB report | ✅ Correct |
| `persistent=yes` | Survives reboot | ✅ Correct (intentional) |
| `overwrite=yes` | Replace existing | ✅ Correct |
| `maxsize=1024` | 1 GB circular | ✅ Correct |
| `tracefile=...%computername%...` | Output path | ⚠️ **CMD only** — `%computername%` does NOT expand in PowerShell. Use `$env:COMPUTERNAME` |

**Pre-requisites:**
- ✅ Must run **elevated** (Administrator)
- ⚠️ Directory `C:\temp\casedata` must exist before running — `netsh trace` does NOT create it

---

## 2. StorPort / Disk Trace Commands

**Source:** `Show-StorPortCommands` (Menu → 4 → 3)

### Start StorPort Trace

```cmd
logman create trace "storport" -ow -o c:\perflogs\storport.etl -p "Microsoft-Windows-StorPort" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
```

### Stop StorPort Trace

```cmd
logman stop "storport" -ets
```

### Filter Driver Check

```cmd
fltmc
fltmc instances
```

### Review Notes

| Item | Verdict |
|---|---|
| Provider GUID `Microsoft-Windows-StorPort` | ✅ Correct (name-based, Windows resolves it) |
| `-ow` (overwrite) | ✅ Correct |
| `-nb 16 16` (min/max buffers) | ✅ Correct |
| `-bs 1024` (buffer size 1KB) | ✅ Correct |
| `-mode Circular -f bincirc` | ✅ Correct (circular binary) |
| `-max 4096` (max 4 GB) | ✅ Correct |
| `-ets` (start immediately) | ✅ Correct |
| Output path `c:\perflogs\` | ⚠️ Directory must exist. Create first: `mkdir c:\perflogs` |
| `fltmc` / `fltmc instances` | ✅ Correct — lists minifilter drivers |

---

## 3. Performance Monitor (Perfmon) Commands

**Source:** `Show-PerfmonCommand` (Menu → 2/3/4 → long-term option)

### Create Perfmon Data Collector

```cmd
Logman.exe create counter PerfLog-%COMPUTERNAME% -o "C:\temp\ServerDiagnostics\Logs\%COMPUTERNAME%_PerfLog-short.blg" -f bincirc -v mmddhhmm -max 500 -c "\LogicalDisk(*)\*" "\Memory\*" "\Cache\*" "\Network Interface(*)\*" "\Paging File(*)\*" "\PhysicalDisk(*)\*" "\Processor(*)\*" "\Processor Information(*)\*" "\Process(*)\*" "\Redirector\*" "\Server\*" "\System\*" "\Server Work Queues(*)\*" "\Terminal Services\*" -si 00:00:05
```

### Start Collection

```cmd
logman start PerfLog-%COMPUTERNAME%
```

### Stop Collection

```cmd
logman stop PerfLog-%COMPUTERNAME%
```

### Interval Guidance

| Duration | Interval (`-si`) |
|---|---|
| 2 hours | `00:00:07` (7 seconds) |
| 4 hours | `00:00:14` (14 seconds) |
| 24 hours | `00:01:16` (1 min 16 sec) |

### Optional: Scheduled Time Window

```cmd
-b MM/DD/YYYY HH:MM:SS AM/PM
-e MM/DD/YYYY HH:MM:SS AM/PM
```

### Review Notes

| Item | Verdict |
|---|---|
| Counter names (all 14 categories) | ✅ All valid Windows perf counter paths |
| `-f bincirc` (binary circular) | ✅ Correct |
| `-v mmddhhmm` (timestamp suffix) | ✅ Correct |
| `-max 500` (500 MB max) | ✅ Correct |
| `-si 00:00:05` (5 second default) | ✅ Correct for short-term |
| `%COMPUTERNAME%` in CMD | ✅ Correct in CMD |
| Output directory | ⚠️ Must exist. The script uses `$env:TEMP\ServerDiagnostics\Logs` |

---

## 4. DNS Diagnostic Commands

**Source:** `Show-DNSDebugCommands` (Menu → 7 → 2)

### Flush and Re-register DNS

```cmd
ipconfig /flushdns
ipconfig /registerdns
```

### Display DNS Cache

```cmd
ipconfig /displaydns
```

### NSLookup Diagnostics

```cmd
nslookup -debug microsoft.com
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
```

### Export DNS Client Events

```cmd
wevtutil epl Microsoft-Windows-DNS-Client/Operational dns-client.evtx
```

### Review Notes

| Command | Verdict |
|---|---|
| `ipconfig /flushdns` | ✅ Correct |
| `ipconfig /registerdns` | ✅ Correct — forces DNS dynamic update |
| `ipconfig /displaydns` | ✅ Correct |
| `nslookup -debug microsoft.com` | ✅ Correct — verbose DNS query |
| `nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>` | ✅ Correct — replace `<domain>` with actual AD domain (e.g., `contoso.com`) |
| `wevtutil epl ...` | ✅ Correct — exports DNS client operational log |

---

## 5. TSS (TroubleShootingScript) Commands

**Source:** Various `Invoke-WithTSSCheck` / `Invoke-TSSCommand` calls throughout.

> All TSS commands are invoked as: `TSS.ps1 <arguments>`
> Download TSS: <https://aka.ms/getTSS>

### Network

| Command | Scenario | Menu Path |
|---|---|---|
| `TSS.ps1 -Scenario NET_AfdTcpFull -NET_NDIS` | Packet drop / network bottleneck (live) | 1 → 1 |
| `TSS.ps1 -SDP Net -AcceptEula` | General network diagnostics | 1 → 2, 7 → 1 |

### Memory

| Command | Scenario | Menu Path |
|---|---|---|
| `TSS.ps1 -Xperf Memory -XperfMaxFileMB 4096 -LogFolderPath '<path>'` | Memory issue happening now (manual stop) | 2 → 1 |
| `TSS.ps1 -Xperf Memory -XperfMaxFileMB 4096 -StopWaitTimeInSec 300 -LogFolderPath '<path>'` | Memory issue now (auto-stop 5 min) | 2 → 2 |
| `TSS.ps1 -Xperf Memory -WaitEvent HighMemory:90 -StopWaitTimeInSec 300 -LogFolderPath '<path>'` | Intermittent (wait for 90% usage) | 2 → 3 |

### CPU

| Command | Scenario | Menu Path |
|---|---|---|
| `TSS.ps1 -Xperf CPU -XperfMaxFileMB 4096 -LogFolderPath '<path>'` | CPU issue happening now (manual stop) | 3 → 1 |
| `TSS.ps1 -Xperf CPU -XperfMaxFileMB 4096 -StopWaitTimeInSec 300 -LogFolderPath '<path>'` | CPU issue now (auto-stop 5 min) | 3 → 2 |
| `TSS.ps1 -Xperf CPU -WaitEvent HighCPU:90 -XperfMaxFileMB 4096 -StopWaitTimeInSec 300` | Intermittent (wait for 90% CPU) | 3 → 3 |
| `TSS.ps1 -UEX_WMIBase -WIN_Kernel -ETWflags 1 -WPR CPU -Perfmon UEX_WMIPrvSE -PerfIntervalSec 1 -noBasicLog` | WMI-specific CPU issue | 3 → 4 |

### Disk / Storage

| Command | Scenario | Menu Path |
|---|---|---|
| `TSS.ps1 -StartNowait -PerfMon General -PerfIntervalSec 1 -SHA_Storport` | StorPort trace (10-15 min) | 4 → 1 |
| `TSS.ps1 -StartNowait -PerfMon General -PerfIntervalSec 1 -SHA_Storport -noSDP` | StorPort + Perfmon (comprehensive) | 4 → 2 |

### Services

| Command | Scenario | Menu Path |
|---|---|---|
| `TSS.ps1 -SDP Perf -AcceptEula` | Performance SDP (includes services) | 5 → 2 |

### Event Logs

| Command | Scenario | Menu Path |
|---|---|---|
| `TSS.ps1 -SDP Setup -AcceptEula` | Setup SDP (includes event logs) | 6 → 2 |

### Security

| Command | Scenario | Menu Path |
|---|---|---|
| `TSS.ps1 -Scenario ADS_Auth -AcceptEula` | Authentication trace | 8 → 2 |

### Windows Update

| Command | Scenario | Menu Path |
|---|---|---|
| `TSS.ps1 -Collectlog DND_SetupReport -AcceptEula` | Setup/Update report collection | 9 → 2 |

### Stop Any Running TSS Trace

```powershell
TSS.ps1 -Stop
```

### Review Notes

| Item | Verdict |
|---|---|
| All `-SDP` commands | ✅ Correct — valid SDP report names |
| All `-Xperf` commands | ✅ Correct — valid Xperf scenarios |
| `-WaitEvent HighCPU:90` | ✅ Correct — TSS threshold trigger |
| `-WaitEvent HighMemory:90` | ✅ Correct — TSS threshold trigger |
| `-WaitEvent Evt:1135:System` | ✅ Correct — TSS event trigger |
| `-Scenario NET_AfdTcpFull` | ✅ Correct — AFD+TCP full packet trace |
| `-Scenario ADS_SBSL` | ✅ Correct — Slow Boot / Slow Logon |
| `-Scenario ADS_Auth` | ✅ Correct — Authentication scenario |
| `-Scenario SHA_MsCluster` | ✅ Correct — Cluster diagnostic scenario |
| `-NET_NDIS` | ✅ Correct — NDIS provider add-on |
| `-SHA_Storport` | ✅ Correct — StorPort tracing |
| `-AcceptEula` | ✅ Correct — suppresses EULA prompt |
| `-noBasicLog` | ✅ Correct — skip baseline collection |
| `-noSDP` | ✅ Correct — skip SDP report |
| `-StartNowait` | ✅ Correct — start and return to prompt |
| `-XperfMaxFileMB 4096` | ✅ Correct — 4 GB max ETL |
| `-StopWaitTimeInSec 300` | ✅ Correct — 5 min auto-stop |
| `-LogFolderPath` | ✅ Correct — custom output folder |

---

## 6. Additional Scenario Commands

**Source:** `Show-AdditionalScenarios` (Menu → 11)

### 6.1 Unexpected Reboot

```powershell
# Collect after reboot:
TSS.ps1 -SDP Perf -AcceptEula
TSS.ps1 -SDP Setup -AcceptEula
TSS.ps1 -Collectlog DND_Setup
```

Also collect:
- `C:\Windows\Memory.dmp`
- `C:\Windows\Minidump\*.dmp`

| Item | Verdict |
|---|---|
| `-Collectlog DND_Setup` | ✅ Correct |
| Memory.dmp path | ✅ Correct (default location) |
| Minidump path | ✅ Correct |

### 6.2 Slow Boot / Slow Logon

```powershell
# Method 1: ADS_SBSL scenario (prompts for reboot)
TSS.ps1 -Start -Scenario ADS_SBSL
# After reboot, stop:
TSS.ps1 -Stop

# Method 2: Boot-time trace (for startup issues)
TSS.ps1 -StartAutoLogger -Procmon -WPR General -Netsh
# Restart (NOT shutdown), then after boot completes:
TSS.ps1 -Stop
```

| Item | Verdict |
|---|---|
| `-Start -Scenario ADS_SBSL` | ✅ Correct |
| `-StartAutoLogger -Procmon -WPR General -Netsh` | ✅ Correct — persists across reboot |
| Must restart, not shutdown | ✅ Important note (shutdown → fast startup may skip autologger) |

### 6.3 Server Crash / BugCheck / Hang

Manual steps only (no automated command):

1. Set **Complete Memory Dump**: Control Panel → System → Advanced → Startup and Recovery
2. Wait for crash to recur
3. Collect `C:\Windows\Memory.dmp`
4. Then run: `TSS.ps1 -SDP Perf -AcceptEula`

| Item | Verdict |
|---|---|
| Dump config path | ✅ Correct |
| Memory.dmp location | ✅ Correct |

### 6.4 Application Crash (ProcDump)

```cmd
REM Download ProcDump from: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump

REM Install as JIT debugger:
procdump -ma -i -accepteula c:\dumps

REM Reproduce the crash (collect 2-3 dumps)

REM Uninstall JIT debugger:
procdump.exe -u
```

Then: `TSS.ps1 -SDP Perf -AcceptEula`

| Item | Verdict |
|---|---|
| `procdump -ma -i -accepteula c:\dumps` | ✅ Correct — `-ma` full dump, `-i` install as JIT |
| `procdump.exe -u` | ✅ Correct — uninstall JIT |
| Output dir `c:\dumps` | ⚠️ Must exist. Create first: `mkdir c:\dumps` |

### 6.5 SQL Issues

```powershell
# Standalone SQL:
TSS.ps1 -SDP SQLBase -noPSR -AcceptEula

# SQL on Failover Cluster:
TSS.ps1 -SDP Cluster,SQLBase -AcceptEula
```

| Item | Verdict |
|---|---|
| `-SDP SQLBase -noPSR` | ✅ Correct — SQL baseline, no PSR recording |
| `-SDP Cluster,SQLBase` | ✅ Correct — comma-separated SDP types |

### 6.6 Cluster Issues

```powershell
# Run on ALL cluster nodes:
TSS.ps1 -SDP Cluster -AcceptEula

# Cluster logs (last 60 minutes):
Get-ClusterLog -TimeSpan 60 -UseLocalTime -Destination $env:TEMP\clusterlog

# Intermittent heartbeat loss (wait for Event 1135):
TSS.ps1 -Scenario SHA_MsCluster -WaitEvent Evt:1135:System -AcceptEula
```

| Item | Verdict |
|---|---|
| `-SDP Cluster` | ✅ Correct |
| `Get-ClusterLog -TimeSpan 60 -UseLocalTime` | ✅ Correct — `-TimeSpan` in minutes |
| `-WaitEvent Evt:1135:System` | ✅ Correct — TSS event-triggered capture |
| ⚠️ Avoid CSV as destination | ✅ Good warning in script |

### 6.7 Server Assessment

```powershell
# TSS full SDP:
TSS.ps1 -sdp ALL -LogFolderPath E:\MS_Data

# psSDP alternative:
Get-psSDP.ps1 Perf -savePath D:\MS_DATA
```

| Item | Verdict |
|---|---|
| `-sdp ALL` | ✅ Correct — collects all SDP categories |
| `Get-psSDP.ps1 Perf` | ✅ Correct — standalone SDP script |

---

## 7. TLS/SSL Configuration Commands

**Source:** `Test-TLSConfiguration` (Menu → 13)

> ⚠️ **IMPORTANT:** All registry commands below require a **system restart** to take effect.
> Review each command before running manually.

### Disable TLS 1.0 (Server)

```powershell
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force
```

### Disable TLS 1.1 (Server)

```powershell
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force
```

### Enable TLS 1.2 (Server)

```powershell
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force
```

### Enable .NET Framework TLS 1.2

```powershell
# 32-bit
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value 1 -Type DWord

# 64-bit (WOW6432Node)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value 1 -Type DWord
```

### Review Notes

| Command | Verdict |
|---|---|
| TLS 1.0 disable registry paths | ✅ Correct |
| TLS 1.1 disable registry paths | ✅ Correct |
| TLS 1.2 enable registry paths | ✅ Correct |
| .NET 4.x `SchUseStrongCrypto` | ✅ Correct |
| .NET 4.x `SystemDefaultTlsVersions` | ✅ Correct |
| WOW6432Node path for 64-bit | ✅ Correct |
| ⚠️ Missing: TLS 1.0/1.1 **Client** disable | ⚠️ Script only disables **Server** side. For full disable, also create `\Client` subkeys with same values |

---

## 8. Windows Update / OS Repair Commands

**Source:** `Show-AdditionalScenarios` → option 7 (Menu → 11 → 7)

### DISM Repair

```cmd
DISM /online /Cleanup-image /RestoreHealth /Source:<ISO_Drive>:\source\sxs
```

⚠️ Replace `<ISO_Drive>` with actual drive letter (e.g., `D:`, `E:`).

### SFC Scan

```cmd
sfc /scannow
```

### Reset Windows Update Components

```cmd
net stop wuauserv
net stop bits
net stop cryptsvc
ren %systemroot%\SoftwareDistribution SoftwareDistribution.old
net start wuauserv
net start bits
net start cryptsvc
```

### Generate WindowsUpdate.log (Server 2016+)

```powershell
Get-WindowsUpdateLog -LogPath "C:\temp\WindowsUpdate.log"
```

### Collect Setup Logs via TSS

```powershell
TSS.ps1 -Collectlog DND_SetupReport -AcceptEula
```

### Review Notes

| Command | Verdict |
|---|---|
| `DISM /online /Cleanup-image /RestoreHealth /Source:` | ✅ Correct syntax |
| `sfc /scannow` | ✅ Correct |
| `net stop wuauserv / bits / cryptsvc` | ✅ Correct |
| `Rename %systemroot%\SoftwareDistribution folder` | ⚠️ **Incomplete** — should be: `ren %systemroot%\SoftwareDistribution SoftwareDistribution.old` (the script just says "Rename ... folder" without the target name) |
| `Get-WindowsUpdateLog` | ✅ Correct — PowerShell cmdlet for Server 2016+ |
| ⚠️ Cluster warning | ✅ Script correctly warns not to stop WU services on cluster nodes with CAU |

---

## 9. Event Log Export Commands

**Source:** `Start-EventLogCollection` (Menu → 6), `Show-AdditionalScenarios` → option 9

### Export via wevtutil

```cmd
wevtutil epl System system.evtx
wevtutil epl Application application.evtx
wevtutil epl Security security.evtx
```

### Export DNS Client Log

```cmd
wevtutil epl Microsoft-Windows-DNS-Client/Operational dns-client.evtx
```

### Review Notes

| Command | Verdict |
|---|---|
| `wevtutil epl System system.evtx` | ✅ Correct |
| `wevtutil epl Application application.evtx` | ✅ Correct |
| `wevtutil epl Security security.evtx` | ✅ Correct — requires admin |
| DNS client log export | ✅ Correct |

---

## 10. Inline Remediation Commands

These are displayed as fix suggestions within diagnostic output.

### Network

| Command | Purpose | Verdict |
|---|---|---|
| `Set-NetAdapterRss -Name '<name>' -Enabled $true` | Enable RSS | ✅ Correct |
| `powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c` | Set High Performance power plan | ✅ Correct (GUID is correct) |
| `Set-NetOffloadGlobalSetting -Chimney Disabled` | Disable deprecated TCP Chimney | ✅ Correct |

### Security

| Command | Purpose | Verdict |
|---|---|---|
| `Test-ComputerSecureChannel -Repair -Credential (Get-Credential)` | Repair broken domain secure channel | ✅ Correct |
| `nltest /sc_query:<domain>` | Check secure channel | ✅ Correct |
| `klist` | Check Kerberos tickets | ✅ Correct |

### Disk / Storage

| Command | Purpose | Verdict |
|---|---|---|
| `chkdsk /R` | Check disk + repair bad sectors | ✅ Correct |
| `vssadmin delete shadows /for=<volume> /oldest` | Clean up old VSS snapshots | ✅ Correct |
| `fsutil behavior set disable8dot3 1` | Disable NTFS 8.3 short names | ✅ Correct |

### Windows Update

| Command | Purpose | Verdict |
|---|---|---|
| `DISM /Online /Cleanup-Image /CheckHealth` | Quick DISM health check | ✅ Correct |
| `slmgr /ato` | Attempt Windows activation | ✅ Correct |

### DNS

| Command | Purpose | Verdict |
|---|---|---|
| `ipconfig /flushdns` | Flush DNS cache | ✅ Correct |
| `ipconfig /registerdns` | Force DNS registration | ✅ Correct |

---

## Summary of Issues Found

| # | Location | Issue | Severity |
|---|---|---|---|
| 1 | Network Trace | `%computername%` does not expand in PowerShell | ⚠️ Medium — CMD works fine |
| 2 | Network Trace | `C:\temp\casedata` not pre-created | ⚠️ Low — will fail with clear error |
| 3 | StorPort Trace | `c:\perflogs` may not exist | ⚠️ Low |
| 4 | Perfmon | Output directory may not exist | ⚠️ Low |
| 5 | ProcDump | `c:\dumps` not pre-created | ⚠️ Low |
| 6 | WU Reset | "Rename ... folder" text is incomplete (missing target name) | ⚠️ Medium — user may not know what to rename to |
| 7 | TLS Commands | Only disables Server-side TLS 1.0/1.1, not Client-side | ⚠️ Low — Server-side is primary concern |

**Overall Verdict:** All commands are **syntactically correct** and use proper Microsoft tooling. The issues are minor (mostly around directory pre-creation and the CMD vs PowerShell variable expansion).

---

## Test Execution Checklist

Use this checklist to verify each command on a test server:

- [ ] **Network Trace:** Start → reproduce → stop → verify `.etl` file created
- [ ] **StorPort Trace:** Start → wait 10-15 min → stop → verify `.etl` file
- [ ] **Perfmon:** Create → start → wait 5 min → stop → verify `.blg` file
- [ ] **DNS:** Flush → re-register → displaydns → verify output
- [ ] **Event Log Export:** Export all 3 logs → verify `.evtx` files open in Event Viewer
- [ ] **fltmc:** Run both `fltmc` and `fltmc instances` → verify output
- [ ] **TLS Registry:** Apply to test server → restart → verify with `Test-TLSConfiguration`
- [ ] **DISM + SFC:** Run CheckHealth → run SFC → verify no errors
- [ ] **TSS (if installed):** Run `-SDP Perf -AcceptEula` → verify data collected → run `-Stop`

> **Note:** Run on a **non-production test server** first. Several commands (TLS, WU reset, DISM) modify system state.
