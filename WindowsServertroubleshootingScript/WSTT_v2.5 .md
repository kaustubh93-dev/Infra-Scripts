# Windows Server Troubleshooting & Log Collection Tool

## Overview

A comprehensive PowerShell-based interactive tool designed for Windows Server administrators to diagnose and collect logs for common server issues including Network, Memory, CPU, Disk performance, Windows Services, Event Logs, DNS, Security & Authentication, Windows Update status, TLS/SSL configuration validation, and cross-category health scoring.

**Version:** 2.5  
**Requires:** Administrator privileges, PowerShell 5.1 or higher

> [!NOTE]
> Performance counter names (`Get-Counter`) are locale-dependent and require an English OS installation. External tools (`w32tm`, `net accounts`, `klist`, `secedit`) also produce English-only output. On non-English Windows installations, some checks may report "Could not…" or display unexpected results.

---

## Features

### 🔍 Primary Diagnostics
- **Network Issues**: Packet loss, network slowness, RSS checks, port exhaustion detection, VMQ status, NIC teaming, packet discards, WAN heartbeat loss
- **Memory Issues**: High usage analysis, top memory consumers, committed bytes tracking, NonPaged Pool usage, Modified Page List, paging activity, known leaky process detection
- **CPU Issues**: High usage detection, process analysis, WMI-specific troubleshooting, svchost breakdown, monitoring agent CPU storms, Java process detection, Split I/O check
- **Disk/Storage Issues**: Latency measurement (read & write), performance analysis, cluster size validation, storage disconnect events (129/153), disk queue length, NTFS corruption detection, VM pause-critical risk
- **Windows Services Health**: Critical service monitoring, stopped auto-services, crash detection (Event 7034), W32Time NTP sync, Task Scheduler health, EventLog service errors, Netlogon events, RDP licensing
- **Event Log Analysis**: 24-hour error scan grouped by EventID/Source, log capacity warnings, cluster events (1135/1672), storage events (129/153), DNS update failures, high-priority known critical event summary
- **DNS Health & Connectivity**: DNS server checks, resolution tests, cache statistics, Bad Key errors, cluster name resolution, reverse DNS lookup, DNS dynamic update failures
- **Security & Authentication**: Account lockout policy, failed logons, Kerberos, firewall status, account lockout events (4740), logon-as-a-service policy, Schannel/TLS errors, NTLM vs Kerberos detection, MachineKeys permissions
- **Windows Update Status**: Recent patches, pending reboot detection, update age warnings, CBS store health, pending.xml check, OS lifecycle check, failed update events
- **Cross-Category Health Scorecard**: Quick consolidated check across cluster/AG stability, storage health, DNS, RDP connectivity, account lockouts, pending reboots, and TLS/Schannel health

### 🛠️ Additional Scenarios
- Unexpected reboots
- Boot time issues & slow logon
- Server crashes, bugchecks, and hangs
- Application crashes
- SQL Server related issues
- Cluster-related problems
- OS patching issues
- Server health assessments
- Event log exports

### 🔐 Security & Compliance
- **TLS Configuration Validation**: Comprehensive TLS/SSL protocol analysis
  - Check enabled TLS versions (1.0, 1.1, 1.2, 1.3)
  - Validate .NET Framework TLS support
  - Analyze cipher suites and identify weak ciphers
  - Verify PowerShell TLS capabilities
  - Export detailed TLS configuration reports
  - Provides remediation commands for security hardening

### 📊 Utilities
- Comprehensive system report generation
- TLS configuration validation and reporting
- TSS (TroubleShootingScript) integration with digital signature verification
- Validator script information
- Transcript logging support

---

## Prerequisites

### Required
- Windows Server (2012 R2 or later recommended)
- PowerShell 5.1 or higher
- Administrator privileges
- Sufficient disk space for logs (minimum 5GB recommended)

### Optional (Highly Recommended)
- **TSS (TroubleShootingScript)**: Required for automated log collection
  - Download from:
    - [https://aka.ms/getTSS](https://aka.ms/getTSS)
    - [https://aka.ms/getTSSlite](https://aka.ms/getTSSlite)
    - [https://cesdiagtools.blob.core.windows.net/windows/TSS.zip](https://cesdiagtools.blob.core.windows.net/windows/TSS.zip)
  - Extract TSS to `C:\TSS` (or update the path in the script)

---

## Installation

1. **Download the script**
   ```powershell
   # Save the script to a location, for example:
   C:\Scripts\WindowsServertroubleshootingtool_v2.5.ps1
   ```

2. **Configure TSS Path (if not using C:\TSS)**
   - Open the script in a text editor
   - Locate line 60: `$script:TSSPath = "C:\TSS"`
   - Update to your TSS installation path
   - Save the file

3. **Set Execution Policy** (if needed)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

---

## Usage

### Basic Usage

1. **Open PowerShell as Administrator**
   - Right-click PowerShell → "Run as Administrator"

2. **Navigate to script location**
   ```powershell
   cd C:\Scripts
   ```

3. **Run the script**
   ```powershell
   .\WindowsServertroubleshootingtool_v2.5.ps1
   ```

### With Transcript Logging

To enable session logging for auditing or documentation:

```powershell
.\WindowsServertroubleshootingtool_v2.5.ps1 -EnableLogging
```

Transcript logs are saved to: `%TEMP%\ServerDiagnostics\Logs\`

---

## Menu Options

### Main Menu

```
 WINDOWS SERVER TROUBLESHOOTING & LOG COLLECTION TOOL
                      Version 2.5

PRIMARY DIAGNOSTICS:
  1. Network Issues (Packet Loss, Slowness, RSS Check)
  2. Memory Issues (High Usage, Top Consumers)
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
     (Reboot, Crash, SQL, Cluster, Patching, etc.)

UTILITIES:
 12. Generate System Report
 13. TLS Configuration Validation
 14. Validator Script Information
 15. Configure TSS Path
 16. Check TSS Status

  0. Exit
```

---

## Diagnostic Details

### 1. Network Diagnostics

**Checks Performed:**
- RSS (Receive Side Scaling) status
- TCP ephemeral port usage and port exhaustion detection
- VMQ (Virtual Machine Queue) settings
- Network adapter buffer settings (Small Rx Buffers, Rx Ring Size)
- Power plan configuration
- Network interface statistics (packets, errors)
- Packet discards with vmxnet3 adapter detection
- Port reachability test (localhost, 2s timeout via TcpClient)
- NIC Teaming / Dual MAC detection (SwitchIndependent + AddressHash risk)
- WAN heartbeat / cluster link flapping (Events 1135, 1129 last 24h)

**Log Collection Options:**
- Packet drop/network bottleneck trace (real-time)
- General network diagnostics
- Manual netsh trace commands

**Recommended When:**
- Experiencing packet loss
- Network slowness or timeouts
- High network latency
- Connection failures

---

### 2. Memory Diagnostics

**Checks Performed:**
- Total, used, and free memory
- Memory usage percentage with threshold alerts
- Top 10 memory-consuming processes
- Committed bytes analysis
- NonPaged Pool usage (critical >300MB, warning >200MB)
- Modified Page List size (file cache pressure, warning >2GB)
- Paging activity (Pages/sec, critical >1000, warning >500)
- Known memory-intensive process detection (java, BMCMainEngine, MonitoringHost, WinCollect, sqlservr)

**Log Collection Options:**
- High memory trace (manual stop after 60s-3min)
- High memory trace (automatic 5-minute capture)
- Intermittent high memory (waits for 90% threshold)
- Long-term Performance Monitor collection

**Recommended When:**
- Memory usage consistently above 80%
- Out of memory errors
- Application performance degradation
- Memory leak suspected

**Thresholds:**
- 🟢 Normal: < 80%
- 🟡 Warning: 80-90%
- 🔴 Critical: > 90%

---

### 3. CPU Diagnostics

**Checks Performed:**
- Current CPU usage percentage
- Processor information (cores, logical processors, multi-socket support)
- Top 10 CPU-consuming processes
- WMI Provider Host (WmiPrvSE) analysis (warning >100s CPU time)
- Top 5 svchost.exe instances with hosted service identification
- Monitoring agent CPU check (MonitoringHost, HealthService, WinCollect, MOMAgent — warning >50s)
- Java process CPU check (warning >100s)
- Split I/O check (storage fragmentation indicator, warning >100/sec)

**Log Collection Options:**
- High CPU trace (manual stop, 60s-3min recommended)
- High CPU trace (automatic 5-minute capture)
- Intermittent high CPU (waits for 90% threshold)
- WMI-specific CPU trace
- Long-term Performance Monitor collection

**Recommended When:**
- CPU usage consistently above 80%
- Server sluggishness
- Application timeouts
- High WMI activity

**Thresholds:**
- 🟢 Normal: < 80%
- 🟡 Warning: 80-90%
- 🔴 Critical: > 90%

---

### 4. Disk/Storage Diagnostics

**Checks Performed:**
- Physical disk information and health status
- Logical disk space usage
- Disk read latency measurements
- Disk write latency measurements
- Cluster size validation (important for databases)
- Storage disconnect events (Events 129, 153 — last 7 days)
- Disk queue length (warning >2)
- NTFS file system corruption errors (Event 55 — last 30 days)
- VM pause-critical risk check (volumes >95% full)

**Log Collection Options:**
- StorPort trace (10-15 minutes)
- StorPort + Performance Monitor (comprehensive)
- Manual StorPort trace commands
- Long-term Performance Monitor collection

**Recommended When:**
- Slow disk performance
- High disk latency
- Database performance issues
- Disk space warnings

**Latency Guidelines:**
- 🟢 Very Good: < 10ms
- 🟢 Acceptable: 10-20ms
- 🟡 Slow: 20-50ms
- 🔴 Critical: > 50ms

**Disk Space Thresholds:**
- 🟢 Normal: < 80% used
- 🟡 Warning: 80-90% used
- 🔴 Critical: > 90% used

---

### 5. Windows Services Health

**Checks Performed:**
- Critical services status (DNS, DHCP, W32Time, EventLog, WinRM, RpcSs, LanmanServer, LanmanWorkstation, MSSQLSERVER, SQLSERVERAGENT, W3SVC, IISADMIN, Netlogon, Schedule, TermServLicensing)
- Stopped automatic services enumeration
- Disabled services audit (first 15 shown)
- Recently crashed/terminated services (Event 7034, last 24 hours)
- W32Time NTP sync status (source, stratum, last sync time)
- Task Scheduler health (last 24h errors from Operational log)
- EventLog service errors (Event 1108, last 7 days)
- Netlogon / domain connectivity events (Events 5719, 7023, 7024 — last 24h)
- RDP licensing status and errors (Events 1128, 1129 — last 7 days)

**Log Collection Options:**
- Export all service status to file
- TSS Performance SDP collection

**Recommended When:**
- Services failing to start
- Application dependencies not running
- Unexplained service crashes
- Post-reboot service health verification

---

### 6. Event Log Analysis

**Checks Performed:**
- System and Application log scan for Critical/Error events (last 24 hours)
- Event grouping by EventID and Source (top 10 most frequent)
- Last 5 critical/error events with timestamps and message snippets
- Log size and capacity monitoring (warns when >90% full)
- Cluster heartbeat/quarantine events (Events 1135, 1672 — last 7 days)
- Storage adapter events (Events 129, 153 — last 7 days)
- DNS update failure events (Events 8018, 8019 — last 7 days)
- High-priority known critical event summary (last 24h) scanning across System, Security, and Application logs for known critical Event IDs

**Known Critical Event IDs Scanned:**
| Log | Event ID | Description |
|-----|----------|-------------|
| System | 1135 | Cluster node removed (heartbeat loss) |
| System | 1672 | Cluster node quarantined |
| System | 129 | Storage adapter reset/timeout |
| System | 153 | Disk write retry (storage path failure) |
| System | 55 | NTFS file system corruption |
| System | 7034 | Service terminated unexpectedly |
| System | 5719 | Netlogon cannot connect to DC |
| System | 36870 | Schannel TLS fatal error |
| System | 6008 | Unexpected shutdown |
| System | 8018/8019 | DNS dynamic update failure |
| Security | 4625 | Failed logon attempt |
| Security | 4740 | Account lockout |
| Application | 1000 | Application crash |
| Application | 1026 | .NET runtime error |

**Log Collection Options:**
- Export System, Application, Security logs (.evtx)
- TSS Setup SDP collection

**Recommended When:**
- Investigating recurring errors
- Post-incident root cause analysis
- Monitoring event log health
- Compliance auditing

---

### 7. DNS Health & Connectivity

**Checks Performed:**
- DNS Client service status
- Configured DNS servers per network adapter
- DNS server reachability (ping test with latency measurement)
- DNS resolution tests (microsoft.com, google.com, domain)
- DNS cache statistics and recent entries
- DNS "Bad Key" errors (cluster CNO/VCO failures — DNS Server log, last 7 days)
- Cluster name resolution (resolves cluster name if Failover Clustering is running)
- AD secure dynamic DNS update failures (Events 8018, 8019 — last 7 days)
- Reverse DNS lookup (PTR records for server IPs)

**Log Collection Options:**
- TSS Network SDP collection
- Manual DNS debug logging commands (ipconfig, nslookup, wevtutil)

**Recommended When:**
- Name resolution failures
- Slow DNS lookups
- Domain join or authentication issues
- Network connectivity problems
- Cluster name objects cannot update DNS

---

### 8. Security & Authentication

**Checks Performed:**
- Account lockout policy (threshold, duration, observation window)
- Recent failed logon attempts (Event 4625, last 24 hours) grouped by target account
- Kerberos ticket status (cached tickets, server targets)
- Domain secure channel health (Test-ComputerSecureChannel)
- Windows Firewall status per profile (Domain, Private, Public)
- Account lockout events (Event 4740, last 24h) grouped by account
- Logon as a Service policy (SeServiceLogonRight — exported via secedit with restricted temp file ACL)
- Schannel TLS errors (Events 36870, 36871, 36874 — last 7 days)
- Authentication protocol usage analysis — NTLM vs Kerberos detection (last 100 logons from Event 4624)
- MachineKeys directory permissions check (SYSTEM and Administrators access)

**Log Collection Options:**
- Export firewall rules and configuration
- TSS Authentication trace
- Export Security event log

**Recommended When:**
- Account lockouts
- Authentication failures
- Kerberos/NTLM issues
- Firewall rule troubleshooting
- Security audit preparation
- Schannel/TLS certificate issues

---

### 9. Windows Update Status

**Checks Performed:**
- Windows Update and BITS service status
- Last 10 installed hotfixes with dates
- Days since last update (warns at 30+, critical at 90+)
- Pending reboot detection (CBS, Windows Update, PendingFileRenameOperations)
- OS version, build, last boot time, and uptime
- CBS store health (ERROR count in last 200 lines of CBS.log)
- Pending.xml check (detects stale pending operations that block role installations)
- OS lifecycle check (alerts for Server 2012/2012 R2 end-of-support, recommends upgrade for Server 2016)
- Failed update events (Setup log, last 7 days)

**Log Collection Options:**
- Collect CBS and DISM logs
- TSS DND_SetupReport collection
- Generate WindowsUpdate.log (Windows 10/Server 2016+)

**Recommended When:**
- Patching issues or failures
- Verifying update compliance
- Pending reboot investigations
- Post-patch troubleshooting

**Update Age Thresholds:**
- 🟢 Normal: Updated within 30 days
- 🟡 Warning: 30-90 days since last update
- 🔴 Critical: Over 90 days since last update

---

### 10. Cross-Category Health Scorecard

**Overview:**
A consolidated quick-check that surfaces the highest-frequency cross-cutting issues across all diagnostic categories in a single pass.

**Checks Performed:**

| # | Category | What It Checks |
|---|----------|----------------|
| 1 | Cluster / AG Stability | Events 1135, 1672 (last 7 days) |
| 2 | Storage Health | Events 129, 153 (last 7 days) |
| 3 | DNS Health | Events 8018, 8019 (last 7 days) |
| 4 | RDP Connectivity | Port 3389 listening + MachineKeys SYSTEM permissions |
| 5 | Account Lockouts | Event 4740 (last 24h) |
| 6 | Pending Reboot | CBS RebootPending + Windows Update RebootRequired |
| 7 | TLS/Schannel Health | Events 36870, 36871 (last 7 days) |

**Output:**
- Per-category OK/ISSUE status
- Final scorecard summary with total issue count
- Directs to individual diagnostics (options 1-9) for deeper analysis

**Recommended When:**
- Quick health check of a server
- Daily monitoring routine
- Pre-deployment validation
- Post-incident triage to identify affected areas

---

## Additional Scenarios (Option 11)

### 1. Unexpected Reboot
- Collects memory dumps and system diagnostics
- Checks System and Application event logs
- Analyzes minidump files

### 2. Boot Time Issues / Slow Logon
- Traces boot process and logon events
- Captures startup performance data
- Requires reboot to collect data

### 3. Server Crash / BugCheck / Hang
- Guides memory dump configuration
- Collects crash dump analysis data
- Post-crash diagnostics

### 4. Application Crash
- Uses ProcDump for crash dump collection
- Captures application crash details
- Multiple dump collection support

### 5. SQL Related Issues
- SQL-specific diagnostics
- Cluster + SQL diagnostics option
- Performance baseline collection

### 6. Cluster Related Issues
- Cluster validation report generation
- Cluster log collection
- Event 1135 troubleshooting
- Multi-node diagnostics

### 7. OS Patch Issues
- Windows Update troubleshooting
- DISM and SFC repair commands
- Component store repair
- Setup log analysis

### 8. Server Assessment
- Comprehensive 4-hour performance capture
- Validator script execution
- Health check report generation

### 9. Export Event Logs
- System, Application, Security logs
- Custom export path support
- .EVTX format preservation

---

## System Report (Option 12)

Generates a comprehensive text report including:

- **System Information**: OS version, manufacturer, model, domain, last boot time
- **Memory Statistics**: Total, used, free memory with usage percentage
- **Processor Details**: CPU name, cores, logical processors
- **Disk Space**: All volumes with usage percentages and free space
- **Network Adapters**: Active adapters with status and link speed
- **Process Analysis**: Top 10 processes by CPU and memory
- **Service Status**: Stopped automatic services
- **Power Plan**: Current power configuration

**Report Location:** `%TEMP%\ServerDiagnostics\Logs\SystemReport_YYYYMMDD_HHMMSS.txt`

---

## TLS Configuration Validation (Option 13)

### Overview
Comprehensive TLS/SSL protocol analysis and security validation tool that helps ensure your server meets modern security standards and compliance requirements.

### Checks Performed

#### Protocol Analysis
- **TLS 1.0 Status**: Client and Server configuration (deprecated, should be disabled)
- **TLS 1.1 Status**: Client and Server configuration (deprecated, should be disabled)
- **TLS 1.2 Status**: Client and Server configuration (minimum requirement)
- **TLS 1.3 Status**: Client and Server configuration (recommended for Windows Server 2022+)

#### .NET Framework Configuration
- SchUseStrongCrypto settings (32-bit and 64-bit)
- SystemDefaultTlsVersions settings (32-bit and 64-bit)
- Validates proper .NET Framework TLS support for applications

#### PowerShell TLS Support
- Current session security protocol configuration
- TLS 1.2 and 1.3 availability check
- Provides commands to enable TLS in PowerShell sessions

#### Cipher Suite Analysis
- Lists all enabled cipher suites in priority order
- Identifies TLS 1.3 cipher suites (most secure)
- Flags strong cipher suites (GCM, ECDHE)
- **Detects weak/deprecated ciphers**: RC4, DES, 3DES, MD5, NULL, EXPORT, anonymous
- Provides security recommendations

### Output Information

The TLS validation provides:

1. **Color-coded status indicators**:
   - 🟢 **Green (SUCCESS)**: Protocol/feature is properly enabled
   - 🟡 **Yellow (WARNING)**: Protocol/feature needs attention or is disabled
   - 🔴 **Red (ERROR)**: Critical security issue detected (weak ciphers, deprecated protocols enabled)
   - ⚪ **White (INFO)**: Informational status

2. **Security recommendations** based on current best practices

3. **Remediation commands** for common TLS configuration tasks

### TLS Report Export

The tool can generate a detailed TLS configuration report including:
- Complete protocol status for all TLS versions
- .NET Framework configuration details
- Full list of enabled cipher suites
- Registry configuration values
- Timestamp and server identification

**Report Location:** `%TEMP%\ServerDiagnostics\Logs\TLSReport_YYYYMMDD_HHMMSS.txt`

### Security Best Practices

#### Recommended Configuration

✅ **ENABLE**:
- TLS 1.2 (minimum requirement)
- TLS 1.3 (if supported by your OS)
- Strong cipher suites (AES-GCM, ChaCha20-Poly1305)
- .NET Framework strong crypto
- System default TLS versions

❌ **DISABLE**:
- TLS 1.0 (deprecated since 2020)
- TLS 1.1 (deprecated since 2020)
- Weak cipher suites (RC4, DES, 3DES, CBC-mode)
- SSL 3.0 and earlier (if not already disabled)

### Quick Fix Commands

The tool provides ready-to-use PowerShell commands for:

#### Disabling TLS 1.0 and 1.1
```powershell
# Disable TLS 1.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force

# Disable TLS 1.1
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force
```

#### Enabling TLS 1.2
```powershell
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force
```

#### Enabling .NET Framework TLS 1.2
```powershell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value 1 -Type DWord
```

**⚠️ IMPORTANT**: A system restart is required after making TLS registry changes!

### Use Cases

**When to use TLS validation:**
- **Security Audits**: Verify server meets security compliance requirements (PCI DSS, HIPAA, SOC 2)
- **Troubleshooting**: Diagnose SSL/TLS connection failures
- **Migration Planning**: Before/after validation when upgrading servers or applications
- **Compliance**: Regular checks to ensure deprecated protocols remain disabled
- **Application Issues**: When applications fail to connect due to TLS version mismatches
- **Vulnerability Remediation**: After applying security patches or hardening configurations

**Common scenarios:**
1. Application connections failing after disabling TLS 1.0/1.1
2. Browser warnings about insecure connections
3. API integration issues related to cipher suites
4. .NET applications unable to establish HTTPS connections
5. Compliance audit preparation (PCI DSS requires TLS 1.2+)

---

## TSS Configuration

### Default TSS Path
The script is hardcoded to use: `C:\TSS`

### Changing TSS Path

**Method 1: Edit Script** (Permanent)
```powershell
# Open script and modify line 60:
$script:TSSPath = "D:\YourPath\TSS"
```

**Method 2: Runtime Update** (Temporary)
1. Run the script
2. Select option 15: "Configure TSS Path"
3. Enter your TSS installation path
4. Press Enter to validate

### TSS Status Check (Option 16)
Verifies:
- TSS directory exists
- TSS.ps1 file is present
- Path configuration is valid

### TSS Digital Signature Verification
When executing TSS commands, the script verifies the `TSS.ps1` digital signature:
- **Valid**: Proceeds with execution, showing signer certificate
- **NotSigned**: Warns user and prompts for confirmation
- **Other**: Shows status/message and prompts for confirmation

---

## Configuration & Customization

### Threshold Customization

Edit the following constants at the top of the script (lines 33-52):

```powershell
# Resource Thresholds
$MEMORY_CRITICAL_THRESHOLD = 90    # Memory usage critical level (%)
$MEMORY_WARNING_THRESHOLD = 80     # Memory usage warning level (%)
$CPU_CRITICAL_THRESHOLD = 90       # CPU usage critical level (%)
$CPU_WARNING_THRESHOLD = 80        # CPU usage warning level (%)
$DISK_CRITICAL_THRESHOLD = 90      # Disk usage critical level (%)
$DISK_WARNING_THRESHOLD = 80       # Disk usage warning level (%)
$DISK_LATENCY_CRITICAL_MS = 50     # Disk latency critical level (ms)
$DISK_LATENCY_WARNING_MS = 20      # Disk latency warning level (ms)
$DISK_LATENCY_ACCEPTABLE_MS = 10   # Disk latency acceptable level (ms)
$PORT_EXHAUSTION_THRESHOLD = 0.8   # Port exhaustion threshold (80%)

# Memory-Specific Thresholds
$NONPAGED_POOL_CRITICAL_MB = 300   # NonPaged Pool critical (MB)
$NONPAGED_POOL_WARNING_MB = 200    # NonPaged Pool warning (MB)
$MODIFIED_PAGE_LIST_WARNING_GB = 2 # Modified Page List warning (GB)
$PAGING_CRITICAL_THRESHOLD = 1000  # Pages/sec critical
$PAGING_WARNING_THRESHOLD = 500    # Pages/sec warning

# CPU-Specific Thresholds
$WMI_CPU_WARNING_SECONDS = 100     # WMI provider CPU warning (seconds)
$MONITORING_AGENT_CPU_WARNING = 50 # Monitoring agent CPU warning (seconds)
$JAVA_CPU_WARNING_SECONDS = 100    # Java process CPU warning (seconds)

# Disk-Specific Thresholds
$SPLIT_IO_WARNING_THRESHOLD = 100  # Split IO/sec warning
$DISK_QUEUE_WARNING_THRESHOLD = 2  # Disk queue length warning
```

### Log Path Customization

Default log location: `%TEMP%\ServerDiagnostics\`

To change, edit lines 55-56:
```powershell
$script:TempBasePath = "D:\CustomPath\ServerDiagnostics"
$script:DefaultLogPath = Join-Path $script:TempBasePath "Logs"
```

### Critical Services List

To customize which services are checked in Service Health diagnostics, edit the `$script:CriticalServices` array (lines 63-68):
```powershell
$script:CriticalServices = @(
    "DNS", "DHCP", "Spooler", "W32Time", "EventLog",
    "WinRM", "RpcSs", "LanmanServer", "LanmanWorkstation",
    "MSSQLSERVER", "SQLSERVERAGENT", "W3SVC", "IISADMIN",
    "Netlogon", "Schedule", "TermServLicensing"
)
```

### Common Ports List

To customize localhost port reachability checks, edit the `$script:CommonPorts` array (lines 71-79):
```powershell
$script:CommonPorts = @(
    @{ Port = 3389; Name = "RDP" },
    @{ Port = 445;  Name = "SMB" },
    @{ Port = 135;  Name = "RPC" },
    @{ Port = 5985; Name = "WinRM" },
    @{ Port = 1433; Name = "SQL Server" },
    @{ Port = 80;   Name = "HTTP" },
    @{ Port = 443;  Name = "HTTPS" }
)
```

---

## Output Files & Locations

### Default Locations

| File Type | Default Location | Description |
|-----------|------------------|-------------|
| System Reports | `%TEMP%\ServerDiagnostics\Logs\` | Comprehensive system reports |
| TLS Reports | `%TEMP%\ServerDiagnostics\Logs\` | TLS configuration reports |
| Transcript Logs | `%TEMP%\ServerDiagnostics\Logs\` | Session transcript logs |
| TSS Logs | `C:\MS_DATA\` | TSS-generated logs (configurable) |
| Event Logs | `%TEMP%\ServerDiagnostics\Logs\EventLogs\` | Exported event logs |
| Performance Logs | User-specified or default | Perfmon .blg files |
| Service Status | `%TEMP%\ServerDiagnostics\Logs\` | Exported service status |
| Firewall Export | `%TEMP%\ServerDiagnostics\Logs\` | Firewall rules and config |
| WU Logs | `%TEMP%\ServerDiagnostics\Logs\` | CBS.log, DISM.log copies |

### TSS Output
When using TSS commands, logs are typically saved to:
- Default: `C:\MS_DATA\`
- Custom: Specified via `-LogFolderPath` parameter

---

## Best Practices

### 📋 General Guidelines

1. **Run as Administrator**: Always execute with elevated privileges
2. **Adequate Disk Space**: Ensure 5-10GB free space for log collection
3. **Reproduce Issues**: Capture logs while the issue is occurring
4. **Multiple Captures**: Collect 2-3 traces for intermittent issues
5. **Document Symptoms**: Note exact time and symptoms when starting traces

### 🎯 Performance Monitoring

1. **Short-term Issues**: Use Xperf traces (1-5 minutes)
2. **Long-term Monitoring**: Use Performance Monitor (2-4 hours)
3. **Baseline Collection**: Capture during normal operations for comparison
4. **Off-peak Hours**: For comprehensive assessments, run during low activity

### 🔐 Security Best Practices

1. **Regular TLS Audits**: Run TLS validation monthly or after system changes
2. **Disable Deprecated Protocols**: Immediately disable TLS 1.0 and 1.1
3. **Enable Strong Cryptography**: Configure .NET Framework for TLS 1.2+
4. **Monitor Cipher Suites**: Regularly check for and remove weak ciphers
5. **Document Changes**: Keep records of all security configuration changes
6. **Test Before Production**: Validate TLS changes in test environment first

### 🔧 Troubleshooting Tips

1. **Start with Scorecard**: Run Cross-Category Health Scorecard (option 10) for a quick overview
2. **Then Diagnostics**: Run specific diagnostic checks for flagged areas
3. **Check Thresholds**: Review warnings/errors from diagnostic output
4. **TSS Integration**: Use TSS for comprehensive automated collection
5. **Manual Fallback**: Use manual commands if TSS is unavailable
6. **Stop Traces Promptly**: Don't let traces run longer than necessary

### 📊 Log Analysis

1. **Review Output**: Check console output for immediate insights
2. **Preserve Logs**: Archive collected logs before analysis
3. **Use Proper Tools**: 
   - Windows Performance Analyzer for ETL files
   - Event Viewer for EVTX files
   - SQL Server Profiler for SQL traces
4. **Compare Baselines**: Use baseline data for trend analysis

---

## Troubleshooting the Script

### Common Issues

#### Issue: "Script requires Administrator privileges"
**Solution:** Run PowerShell as Administrator
```powershell
# Right-click PowerShell → "Run as Administrator"
```

#### Issue: "Execution policy doesn't allow script"
**Solution:** Set execution policy
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Issue: "TSS not found"
**Solution:** 
1. Download TSS from provided links
2. Extract to `C:\TSS` or update path (Option 15)
3. Verify with Option 16

#### Issue: "Cannot create directory"
**Solution:** Check permissions and disk space
```powershell
# Verify write access to temp directory
Test-Path $env:TEMP -PathType Container
```

#### Issue: "Network adapter advanced properties unavailable"
**Solution:** This is normal for some adapters (virtual, legacy)
- Script will skip unavailable properties
- No action required

#### Issue: "Get-TlsCipherSuite cmdlet not found"
**Solution:** Requires Windows Server 2012 R2 or later
- TLS validation will work partially
- Cipher suite analysis will be skipped

#### Issue: "Could not parse lockout policy (non-English locale?)"
**Solution:** The `net accounts` command outputs English text
- On non-English Windows, lockout policy parsing may fail
- Manually verify via `secpol.msc` or Group Policy

---

## Performance Impact

### Resource Usage

| Activity | CPU Impact | Memory Impact | Disk I/O | Network I/O |
|----------|------------|---------------|----------|-------------|
| Diagnostics Only | Minimal (<5%) | Minimal (<100MB) | Low | Low |
| Health Scorecard | Minimal (<3%) | Minimal (<50MB) | Low | None |
| TLS Validation | Minimal (<2%) | Minimal (<50MB) | Low | None |
| TSS Traces | Low-Medium (5-15%) | Medium (200-500MB) | Medium-High | Low-Medium |
| Performance Monitor | Minimal (<2%) | Low (50-200MB) | Medium | Minimal |
| System Report | Minimal (<3%) | Minimal (<50MB) | Low | Minimal |

### Recommendations

- **Production Servers**: Safe to run diagnostics, scorecard, and TLS validation anytime
- **Trace Collection**: Monitor system resources during collection
- **Peak Hours**: Avoid long-term traces during critical operations
- **Resource-Constrained**: Use shorter capture windows or specific traces

---

## Support & Contribution

### Getting Help

1. Review this README thoroughly
2. Check console output for specific error messages
3. Verify prerequisites are met
4. Ensure TSS is properly installed and configured

### Reporting Issues

When reporting issues, include:
- Windows Server version
- PowerShell version (`$PSVersionTable`)
- Error messages (full text)
- Steps to reproduce
- TSS path configuration

### Enhancement Requests

Suggestions for improvements are welcome. Consider:
- Specific diagnostic needs
- Additional log collection scenarios
- Output format preferences
- Integration requirements

---

## Version History

### Version 2.5 (Current)
- ✨ **NEW: Cross-Category Health Scorecard** — Consolidated quick-check across 7 issue areas (cluster, storage, DNS, RDP, lockouts, reboot, TLS)
- ✨ **NEW: Windows Services Health** — Critical service monitoring, stopped auto-service detection, crash analysis (Event 7034), W32Time NTP sync, Task Scheduler health, EventLog errors, Netlogon events, RDP licensing
- ✨ **NEW: Event Log Analysis** — 24-hour error scan, grouped by EventID/Source, log capacity monitoring, cluster/storage/DNS event correlation, known critical event summary
- ✨ **NEW: DNS Health & Connectivity** — DNS server checks, resolution tests, cache statistics, Bad Key errors, cluster name resolution, reverse DNS, DNS dynamic update failures
- ✨ **NEW: Security & Authentication** — Account lockout policy, failed logons (Event 4625), Kerberos tickets, secure channel, firewall status, account lockout events (4740), logon-as-a-service policy, Schannel TLS errors, NTLM vs Kerberos detection, MachineKeys permissions
- ✨ **NEW: Windows Update Status** — Recent hotfixes, pending reboot detection, update age warnings, OS version info, CBS store health, pending.xml check, OS lifecycle check, failed update events
- 🔒 **Enhanced TSS security** — Digital signature verification (Authenticode) before executing TSS.ps1, restricted temp file ACL for secedit export
- 🔧 **Enhanced Memory diagnostics** — NonPaged Pool usage, Modified Page List, paging activity (Pages/sec), known leaky process detection
- 🔧 **Enhanced CPU diagnostics** — Svchost.exe breakdown with hosted services, monitoring agent CPU storm detection, Java CPU check, Split I/O check
- 🔧 **Enhanced Disk diagnostics** — Write latency, disk queue length, storage disconnect events (129/153), NTFS corruption (Event 55), VM pause-critical risk
- 🔧 **Enhanced Network diagnostics** — Packet discard detection with vmxnet3 alert, NIC teaming dual MAC risk, WAN heartbeat/cluster link flapping, port reachability via TcpClient with 2s timeout
- 🛡️ Replaced `Invoke-Expression` with safe `&` call operator (security fix)
- 🛡️ Renamed `Write-Warning`/`Write-Error` overrides to `Write-DiagWarning`/`Write-DiagError` to avoid shadowing built-in cmdlets
- 🐛 Fixed port exhaustion check (now uses scalar `Get-NetTCPSetting -SettingName "Internet"`)
- 🐛 Added division-by-zero guard on disk volume calculations
- 🐛 Fixed `wevtutil` argument parsing (pre-computed `Join-Path` variables)
- 🐛 Replaced `Set-Location` with `Push-Location`/`Pop-Location` for safer directory handling
- 🐛 Fixed `$null` comparison order per PSScriptAnalyzer best practices
- 🐛 Removed unused `$tssAvailable` variables
- 📊 Expanded main menu from 10 to 16 options

### Version 2.0
- ✨ Complete rewrite with enhanced error handling
- ✨ Hardcoded TSS path with runtime update capability
- ✨ Comprehensive input validation
- ✨ Performance optimized (cached process analysis)
- ✨ Configurable thresholds
- ✨ Enhanced documentation and help
- ✨ Transcript logging support
- ✨ Improved user experience with validated inputs
- ✨ **TLS Configuration Validation**
  - Protocol status checking (TLS 1.0, 1.1, 1.2, 1.3)
  - .NET Framework TLS support validation
  - Cipher suite analysis with weak cipher detection
  - PowerShell TLS capability check
  - Detailed TLS configuration reports
  - Security remediation commands
- 🐛 Fixed path handling issues
- 🐛 Resolved TSS execution errors

### Version 1.0
- Initial release
- Basic diagnostic and log collection functionality

---

## License & Disclaimer

### Disclaimer

This tool is provided "as is" without warranty of any kind. Always:
- Test in non-production environments first
- Review commands before execution
- Ensure adequate backups exist
- Monitor system resources during log collection
- **Test TLS changes in development/staging before production**
- **Verify application compatibility after TLS configuration changes**

### Usage Rights

This script is intended for:
- Windows Server administrators
- IT support personnel
- System troubleshooting and diagnostics
- Performance analysis and optimization
- Security compliance and auditing

---

## Quick Reference

### Quick Start Checklist

- [ ] Run PowerShell as Administrator
- [ ] Download and extract TSS to `C:\TSS`
- [ ] Execute script
- [ ] Run Health Scorecard (Option 10) for quick overview
- [ ] Run specific diagnostics (Options 1-9) for flagged areas
- [ ] Run TLS validation (Option 13) for security audit
- [ ] Collect logs if issues found
- [ ] Review output and collected logs

### Common Command Sequences

**Quick Health Check:**
1. Option 10 → Run Cross-Category Health Scorecard
2. Review flagged issue areas
3. Run specific diagnostics for any ISSUE categories

**Network Issue Investigation:**
1. Option 1 → Run network diagnostics
2. Review RSS, VMQ, port usage, packet discards, NIC teaming
3. Option 1 → Choose log collection method
4. Reproduce issue during trace

**Memory Leak Investigation:**
1. Option 2 → Check current memory usage
2. Note top consumers, NonPaged Pool, Modified Page List, paging activity
3. Option 2 → Select intermittent capture (Option 3)
4. Wait for automatic capture at 90% threshold

**Performance Baseline:**
1. Option 12 → Generate system report
2. Option 2, 3, or 4 → Select long-term Perfmon (Option 4/5)
3. Run for 2-4 hours during normal operations
4. Analyze .blg files with Performance Monitor

**Security Audit:**
1. Option 8 → Run Security & Authentication check
2. Option 13 → Run TLS Configuration Validation
3. Review protocol status and cipher suites
4. Export TLS report for documentation
5. Apply remediation commands if needed
6. Restart server
7. Re-run validation to confirm changes

**Services & Update Health Check:**
1. Option 10 → Run Health Scorecard first
2. Option 5 → Check Windows Services Health
3. Option 9 → Check Windows Update Status
4. Option 6 → Review Event Log Analysis
5. Option 7 → Verify DNS Health
6. Option 12 → Generate system report

**Pre-Deployment Security Check:**
1. Option 10 → Run Health Scorecard for baseline
2. Option 13 → Validate current TLS configuration
3. Option 8 → Review Security & Authentication
4. Option 12 → Generate system report
5. Document current state
6. Apply security hardening
7. Option 13 → Verify changes
8. Export reports for compliance documentation

---

## Contact & Resources

### Microsoft Resources
- [TSS Download](https://aka.ms/getTSS)
- [Windows Server Documentation](https://docs.microsoft.com/windows-server/)
- [Performance Tuning Guidelines](https://docs.microsoft.com/windows-server/administration/performance-tuning/)
- [ProcDump Documentation](https://learn.microsoft.com/sysinternals/downloads/procdump)
- [TLS Best Practices](https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings)
- [.NET Framework TLS](https://docs.microsoft.com/dotnet/framework/network-programming/tls)

### Security Resources
- [NIST TLS Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)

### Tools Mentioned
- **TSS (TroubleShootingScript)**: Microsoft's comprehensive data collection tool
- **Windows Performance Analyzer**: ETL file analysis
- **Performance Monitor**: Real-time and historical performance data
- **ProcDump**: Application crash dump utility
- **Netsh**: Network tracing utility
- **IISCrypto**: GUI tool for TLS configuration (third-party)

---

## Appendix

### Perfmon Counter Intervals

| Duration | Interval | Command Parameter |
|----------|----------|-------------------|
| 2 hours | 7 seconds | `-si 00:00:07` |
| 4 hours | 14 seconds | `-si 00:00:14` |
| 24 hours | 76 seconds | `-si 00:01:16` |

### Network Trace File Size
- Default max size: 1024 MB
- Typical 1-hour trace: 200-500 MB
- Adjust with `maxsize` parameter

### Recommended Trace Durations

| Issue Type | Minimum Duration | Optimal Duration |
|------------|------------------|------------------|
| Active High CPU | 60 seconds | 2-3 minutes |
| Active High Memory | 60 seconds | 2-3 minutes |
| Intermittent Issue | 30 minutes | 2-4 hours |
| Baseline Collection | 2 hours | 4 hours |
| Disk Performance | 10 minutes | 15 minutes |
| TLS Validation | Instant | N/A |
| Health Scorecard | Instant | N/A |

### TLS Protocol Support by Windows Version

| Windows Version | TLS 1.0 | TLS 1.1 | TLS 1.2 | TLS 1.3 |
|-----------------|---------|---------|---------|---------|
| Server 2008 R2 | ✅ Default | ✅ Default | ✅ (Update required) | ❌ |
| Server 2012 | ✅ Default | ✅ Default | ✅ Default | ❌ |
| Server 2012 R2 | ✅ Default | ✅ Default | ✅ Default | ❌ |
| Server 2016 | ✅ Default | ✅ Default | ✅ Default | ❌ |
| Server 2019 | ✅ (Disabled) | ✅ (Disabled) | ✅ Default | ❌ |
| Server 2022 | ❌ Disabled | ❌ Disabled | ✅ Default | ✅ Available |

### Script Architecture

The script is organized into the following regions:

| Region | Lines | Description |
|--------|-------|-------------|
| Constants and Configuration | 31-105 | Thresholds, paths, services, ports, critical event IDs |
| Output and Display Functions | 107-167 | Write-Header, Write-Success, Write-DiagWarning, Write-DiagError, Write-Info |
| Event Helpers | 169-234 | Get-EventSnippet, Get-RecentEvents |
| Helper Functions | 236-398 | Path validation, input validation, TSS wrapper, process analysis |
| TSS Functions | 401-567 | Set-TSSPath, Test-TSSAvailable, Invoke-TSSCommand |
| Network Diagnostics | 570-882 | Test-NetworkConfiguration, Start-NetworkLogCollection |
| Memory Diagnostics | 884-1103 | Test-MemoryUsage, Start-MemoryLogCollection |
| CPU Diagnostics | 1105-1331 | Test-CPUUsage, Start-CPULogCollection |
| Disk/Storage Diagnostics | 1333-1649 | Test-DiskPerformance, Start-DiskLogCollection |
| Services Health | 1651-1913 | Test-ServicesHealth, Start-ServicesLogCollection |
| Event Log Analysis | 1916-2125 | Test-EventLogHealth, Start-EventLogCollection |
| DNS Health | 2127-2387 | Test-DNSHealth, Start-DNSLogCollection |
| Security & Authentication | 2389-2731 | Test-SecurityAuthentication, Start-SecurityLogCollection |
| Windows Update Status | 2733-3011 | Test-WindowsUpdateStatus, Start-WindowsUpdateLogCollection |
| Cross-Category Health | 3013-3181 | Test-CrossCategoryHealth |
| Additional Scenarios | 3183-3359 | Show-AdditionalScenarios |
| Report Functions | 3361-3898 | Validator info, TLS validation, TLS report, System report |
| Main Menu and Execution | 3901-4133 | Show-MainMenu, Start-TroubleshootingTool |

---

**Last Updated:** March 2026  
**Script Version:** 2.5  
**Documentation Version:** 2.5