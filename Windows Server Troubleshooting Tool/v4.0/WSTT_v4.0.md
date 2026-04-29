# Windows Server Troubleshooting Tool (WSTT) — v4.0

> **Supersedes** `WSTT_v3.0.md`. All v3.0 menu numbers (1–21) and behaviours are preserved verbatim — see [§ Backwards Compatibility](#backwards-compatibility). This document focuses on what is **new in v4.0**.

| | |
|---|---|
| **Version** | 4.0.0 |
| **Module** | `WSTT` (PowerShell module) |
| **Entry point** | `WSTT.ps1` (thin shim) |
| **Requires** | PowerShell 5.1+ · Administrator |
| **Tested on** | Windows Server 2019 (17763), 2022 (20348), 2025 (26100) |
| **Findings schema** | [`wstt-findings-v1.schema.json`](WSTT/schemas/wstt-findings-v1.schema.json) |

---

## Table of Contents

- [What's new in v4.0](#whats-new-in-v40)
- [Layout](#layout)
- [Quick start](#quick-start)
- [Menu reference (new options 22–32)](#menu-reference-new-options-2232)
- [Unattended mode](#unattended-mode)
- [Export formats](#export-formats)
- [Multi-server remoting](#multi-server-remoting)
- [Findings schema (v1)](#findings-schema-v1)
- [Exit codes](#exit-codes)
- [Build pipeline](#build-pipeline)
- [Backwards compatibility](#backwards-compatibility)
- [Troubleshooting](#troubleshooting)

---

## What's new in v4.0

| Area | v3.0 | v4.0 |
|------|------|------|
| Distribution | Single 7,900-line `.ps1` | PowerShell module (`WSTT.psm1` + 35 region-split sources) + thin shim |
| Modern security posture | TLS + auth events only | Option 25 — VBS/HVCI/CG, LSA-PPL, ASR, WDAC, BitLocker, LAPS, SMB1, SMB signing, NTLM audit, PrintNightmare |
| Server 2025 features | OS-build only | Option 26 — Hotpatch, dMSA, NTLM-deprecation, SMB-over-QUIC, Network ATC, GPU-P, ARM64, OpenSSH, WinRM HTTPS, TLS 1.3, DNSSEC |
| Active Directory | None | Option 22 — `dcdiag`, `repadmin`, FSMO, SYSVOL/DFSR, time hierarchy, Kerberos, LDAP signing, NTLM telemetry, NTDS volume |
| Hyper-V host | None | Option 23 — VM state, integration services, dynamic memory, checkpoint sprawl, Replica, vSwitch, VHDX integrity, Live Migration, GPU-P, VMMS event log |
| Advanced storage | Free space + IOPS | Option 24 — S2D pool/cache, Storage Replica, Dedup, ReFS scrub, Storage QoS, tier rebalance, SHS alerts, NVMe firmware |
| PKI | None | Option 27 — expiring certs (My/IIS/WinRM/LDAPS), root CA freshness, key ACLs, chain build, autoenrollment, NDES |
| Hybrid / Arc | None | Option 28 — Arc agent (`himds`), AMA, AUM, MDC, outbound endpoints, proxy, extension health |
| Patching depth | `Get-HotFix` only | Option 29 — Hotpatch state, latest LCU vs expected KB, SSU, reboot-pending root cause, failed updates, OS lifecycle, .NET/VC++, drivers, WSUS source |
| Multi-server | None | Option 30 — fan-out via PSRemoting (5985/5986), `Start-ThreadJob` parallelism, DPAPI clixml creds, capability probe |
| Output | HTML/TXT | Option 31 — JSON, NDJSON, CSV, SARIF 2.1 + schema-versioned envelope |
| Automation | Interactive only | Option 32 — `-Unattended` parameter set, exit codes, scheduled-task generator |

**Foundation refactors (transparent to operators):**
- `Add-Finding` helper records every check into `$script:Findings` (used by Option 31 + unattended mode).
- `Get-OSCapability` cache replaces scattered `Get-CimInstance` calls — one CIM hit per run.
- 19-test Pester 5 suite; PSScriptAnalyzer green (0 Errors / 0 Warnings).
- [Invoke-Build](.build.ps1) pipeline (`Clean → Analyze → Test → Package`) producing `out/WSTT-4.0.0.zip`.

---

## Layout

```
v4.0/
├── WSTT.ps1                   # Thin shim — parses params, imports module, dispatches
├── WSTT/
│   ├── WSTT.psd1              # Module manifest (75 exported functions, explicit list)
│   ├── WSTT.psm1              # Loader: dot-sources Source/*.ps1 in lexical order
│   ├── Source/                # 35 region-split files (01-Constants … 35-Option32)
│   └── schemas/
│       └── wstt-findings-v1.schema.json
├── Tests/
│   └── WSTT.Tests.ps1         # 19 Pester 5 tests
├── tools/
│   └── Split-Module.ps1       # One-off generator (historical; safe to ignore)
├── .build.ps1                 # Invoke-Build pipeline
└── WSTT_v4.0.md               # This document
```

---

## Quick start

```powershell
# Interactive (replaces v3.0 entry point)
.\WSTT.ps1

# Interactive with on-disk transcript
.\WSTT.ps1 -EnableLogging

# Unattended — JSON only
.\WSTT.ps1 -Unattended -Categories ModernSecurity,Server2025 `
           -Format JSON -OutputPath C:\WSTTReports

# Unattended — all formats, fan out to two servers
.\WSTT.ps1 -Unattended -Categories Security,Patching -Format All `
           -OutputPath C:\WSTTReports `
           -ComputerName SRV01,SRV02 -CredentialPath C:\creds\ops.clixml `
           -ThrottleLimit 4
```

Direct module use (no shim):

```powershell
Import-Module .\WSTT\WSTT.psd1
Start-TroubleshootingTool                # interactive
Invoke-WSTTUnattended -Categories Security -Format JSON -OutputPath C:\Out
Test-ModernSecurityPosture | Out-Null
Get-Findings | Where-Object Severity -eq 'ERROR'
```

---

## Menu reference (new options 22–32)

> Options 1–21 are unchanged from v3.0 (Network, Memory, CPU, Disk, Services, Event Logs, DNS, Security/Auth, Windows Update, TLS, IIS, Task Scheduler, Cluster, SQL AG, Server Baseline, HTML Report, etc.). See [`WSTT_v3.0.md`](../WSTT_v3.0.md) for v3.0 detail.

### 22 — Active Directory Health *(DC role only)*
Auto-skips if `(Get-CimInstance Win32_ComputerSystem).DomainRole < 4`.
Checks: `dcdiag /q` summary, `repadmin /replsummary`, FSMO role holders, SYSVOL/DFSR backlog, w32tm hierarchy, krbtgt password age, LDAP signing & channel binding, NTLM operational events, NTDS volume free space.

### 23 — Hyper-V Host Health *(Hyper-V role only)*
Auto-skips if `Get-WindowsFeature Hyper-V` is not Installed.
Checks: VM state inventory (Critical/Off/Saved), integration services drift, dynamic memory pressure, checkpoint sprawl, `Get-VMReplication` health, vSwitch + SR-IOV, VHDX dynamic full risk, Live Migration config, GPU-P partitions (2025), VMMS event log (24h).

### 24 — Advanced Storage
Checks: S2D pool/virtual disk/storage jobs, S2D cache journal, Storage Replica lag, Data Deduplication status, ReFS file integrity & scrub, Storage QoS policies, tier-rebalance scheduled task, Storage Health Service alerts, persistent-reservation conflicts, NVMe firmware versions.
Gracefully N/A on non-S2D / non-storage hosts.

### 25 — Modern Security Posture
Checks: Secure Boot, TPM 2.0, VBS/HVCI/Credential Guard (`Win32_DeviceGuard`), LSA Protection (`RunAsPPL`), ASR rules, WDAC enforcement, AppLocker, BitLocker volumes, Defender / MDE health, Windows LAPS service, SMB1 feature presence, SMB signing/encryption, NTLM `LmCompatibilityLevel`, Print Spooler on DC + driver-install restriction.

### 26 — Server 2025 Feature Audit
Checks: Hotpatch eligibility (`Get-HotPatchState`), dMSA presence, NTLM deprecation telemetry (events 8001/8002), SMB-over-QUIC server (`Get-SmbServerCertificateMapping`), Network ATC intents (`Get-NetIntentStatus`), GPU partitionable adapters, ARM64 CPU detection, OpenSSH server posture, WinRM HTTPS listener, Schannel TLS 1.3 registry, DNSSEC validation, Wi-Fi/Bluetooth anti-pattern.
Older OS prints `N/A — requires Server 2025` rather than erroring.

### 27 — Certificates & PKI
Checks: expiring `Cert:\LocalMachine\My` (≤30d ERROR, ≤90d WARN), IIS bindings, WinRM listener cert, root CA store size, private key ACL audit, `[X509Chain]::Build()` per cert, autoenrollment GPO + last `certutil -pulse`, NDES SCEP responder, LDAPS bind on 636.

### 28 — Hybrid / Azure Arc
Checks: `himds` agent + `azcmagent show`, Arc agent version vs N-2, Azure Monitor Agent (`AzureMonitorAgent` service), AUM scheduled assessment, Defender for Cloud onboarding registry, outbound 443 reachability to `*.guestconfiguration.azure.com` / `*.his.arc.azure.com`, `azcmagent config list` proxy, extension state.
Auto-skips when `azcmagent` not installed.

### 29 — Patching Depth & Lifecycle
Checks: Hotpatch baseline KB, latest LCU vs current month's expected (embedded KB-by-month list), SSU version, six pending-reboot signals (CBS, WU, PendingFileRename, ComputerName change, etc.) with root cause, `WindowsUpdateClient` failures (last 30d), OS lifecycle dates, .NET / Visual C++ runtime currency, storage/NIC driver age, WSUS vs Microsoft Update.

### 30 — Multi-Server Remoting Mode
A *mode* — wraps any of options 1–29 across an array of `-ComputerName`.
- Credentials: DPAPI `Export-Clixml` only (`-CredentialPath`).
- Parallelism: `Start-ThreadJob` (or `PSThreadJob` polyfill on PS 5.1) gated by `-ThrottleLimit`.
- Pre-flight: WinRM 5985/5986 reachability, TrustedHosts hint for workgroup.
- Capability probe: skips checks whose required cmdlets are missing on the target.
- Per-target output folder + rolled-up summary.
- Resilient: per-check timeouts, partial failures tolerated.
- Audit log (caller, targets, run timestamp) — non-PII.

### 31 — Export Diagnostics
Serialises `$script:Findings` after any run.

| Format | Extension | Use case |
|--------|-----------|----------|
| JSON | `.json` | SIEM ingestion, downstream automation, validates against [findings schema v1](#findings-schema-v1) |
| NDJSON | `.ndjson` | Splunk, Elastic, log shippers (1 finding per line) |
| CSV | `.csv` | Excel triage |
| SARIF 2.1 | `.sarif` | GitHub / Azure DevOps code-scanning surfaces |

Filenames follow `wstt_findings_<yyyyMMdd_HHmmss>.<ext>`.

### 32 — Unattended / Scheduled Mode
- New parameter set: `-Unattended -Categories <id[]> -OutputPath <dir> -Format JSON|NDJSON|CSV|SARIF|All`.
- Zero prompts, no `Read-Host`.
- Exit code reflects worst severity emitted (see [Exit codes](#exit-codes)).
- Optional `-ComputerName` / `-CredentialPath` / `-ThrottleLimit` invokes Option 30 fan-out under the hood.
- Companion helper to register a daily Scheduled Task is exposed in the menu.
- Output rotation by date stamp; old runs may be pruned by external retention.

---

## Unattended mode

```powershell
.\WSTT.ps1 -Unattended `
           -Categories Security,ModernSecurity,Server2025,Patching `
           -Format All `
           -OutputPath C:\WSTTReports
```

| Parameter | Type | Default | Notes |
|-----------|------|---------|-------|
| `-Unattended` | switch | — | Selects the unattended parameter set |
| `-Categories` | string[] | *(required)* | Logical group identifiers — see Category names below |
| `-Format` | enum | `JSON` | `JSON`, `NDJSON`, `CSV`, `SARIF`, `All` |
| `-OutputPath` | string | `$env:TEMP\WSTT` | Created if missing |
| `-ComputerName` | string[] | *(none)* | Triggers Option 30 fan-out |
| `-CredentialPath` | string | *(none)* | Path to DPAPI clixml created by `Get-Credential ⏎ Export-Clixml` |
| `-ThrottleLimit` | int | `4` | Concurrent remote targets |

**Category names** (case-insensitive): `Network`, `Memory`, `CPU`, `Disk`, `Services`, `EventLog`, `DNS`, `Security`, `WindowsUpdate`, `TLS`, `IIS`, `TaskScheduler`, `ActiveDirectory`, `Hyper-V`, `Storage`, `ModernSecurity`, `Server2025`, `PKI`, `AzureArc`, `Patching`.

---

## Export formats

```powershell
# Inside an interactive session, after running checks:
Show-MainMenu          # choose 31, then J/N/C/S/A
```

Programmatic:

```powershell
Import-Module .\WSTT\WSTT.psd1
Test-ModernSecurityPosture
Test-PatchingDepthAndLifecycle
Export-FindingsToFile -Format All -OutputPath C:\WSTTReports
```

Resulting JSON envelope (truncated):

```json
{
  "$schema": "https://github.com/Infra-Scripts/wstt/schemas/wstt-findings-v1.schema.json",
  "schema": "wstt-findings-v1",
  "meta": {
    "Tool": "WSTT", "Version": "4.0",
    "Host": "SRV01", "User": "ops",
    "StartedUtc": "2026-04-29T15:00:00.000Z",
    "PSVersion": "5.1.20348.2849"
  },
  "endedUtc": "2026-04-29T15:01:42.123Z",
  "findings": [
    {
      "TimestampUtc": "2026-04-29T15:00:11.456Z",
      "Severity": "WARN",
      "Category": "ModernSecurity",
      "CheckId": "25.4",
      "Message": "LSA Protection (RunAsPPL) is disabled.",
      "Data": { "RunAsPPL": 0 },
      "Host": "SRV01"
    }
  ]
}
```

---

## Multi-server remoting

```powershell
# 1) One-time: capture credentials encrypted with DPAPI for the current user
Get-Credential | Export-Clixml -Path C:\creds\ops.clixml

# 2) Fan out
.\WSTT.ps1 -Unattended `
           -Categories Security,Patching `
           -Format JSON -OutputPath C:\WSTTReports `
           -ComputerName (Get-Content C:\inv\servers.txt) `
           -CredentialPath C:\creds\ops.clixml `
           -ThrottleLimit 8
```

**Security guarantees:**
- Plain-text passwords are *never* accepted on the command line.
- Credentials are read from DPAPI clixml (only the original user can decrypt).
- Sensitive env vars are wiped in `finally` blocks.
- WinRM transport prefers HTTPS (5986) when available; falls back to HTTP (5985) only with a console warning.

---

## Findings schema (v1)

Authoritative file: [`WSTT/schemas/wstt-findings-v1.schema.json`](WSTT/schemas/wstt-findings-v1.schema.json) (JSON Schema draft 2020-12).

Top-level envelope (JSON only — NDJSON omits the envelope and emits one `finding` object per line):

| Field | Type | Required | Description |
|-------|------|:-------:|-------------|
| `$schema` | string (URI) | ✓ | Self-discoverable schema URL |
| `schema` | const `wstt-findings-v1` | ✓ | Stable identifier for forward compatibility |
| `meta` | object | ✓ | Tool, version, host, user, ISO-8601 start UTC, PS version |
| `endedUtc` | ISO-8601 string | ✓ | Envelope serialisation time |
| `findings` | array | ✓ | Ordered findings |

`finding` shape:

| Field | Type | Required | Description |
|-------|------|:-------:|-------------|
| `TimestampUtc` | ISO-8601 | ✓ | Emit time |
| `Severity` | enum `INFO\|WARN\|ERROR\|FATAL\|NA` | ✓ | `NA` = not applicable on this OS/role |
| `Category` | string | ✓ | Logical group (see [Unattended](#unattended-mode)) |
| `CheckId` | string | — | Stable identifier (e.g. `25.4`, `22.3`); empty when unmapped |
| `Message` | string | ✓ | Human-readable description |
| `Data` | object/array/scalar | — | Optional structured evidence |
| `Host` | string | ✓ | Computer name (may differ from `meta.Host` in remoting mode) |

---

## Exit codes

Used by Option 32 / unattended runs:

| Code | Meaning |
|:----:|---------|
| `0` | All findings ≤ INFO |
| `1` | At least one WARN, no ERROR/FATAL |
| `2` | At least one ERROR, no FATAL |
| `3` | At least one FATAL or unhandled exception |
| `4` | Invalid arguments / pre-flight failure (e.g. not running as Administrator) |

Interactive runs always exit `0` on graceful menu exit.

---

## Build pipeline

The repository ships an [Invoke-Build](https://github.com/nightroman/Invoke-Build) pipeline. Run from `Windows Server Troubleshooting Tool/v4.0/`:

```powershell
Invoke-Build              # Clean → Analyze → Test → Package (default)
Invoke-Build Test         # Pester 5 only
Invoke-Build Analyze      # PSScriptAnalyzer only
Invoke-Build Package      # Stage + zip into out\WSTT-<version>.zip
```

Acceptance gates enforced:

| Gate | Threshold | Current |
|------|-----------|---------|
| PSScriptAnalyzer Errors | 0 | ✅ 0 |
| PSScriptAnalyzer Warnings | ≤5 | ✅ 0 |
| Pester FailedCount | 0 | ✅ 0 (19 passed) |
| Module manifest | `Test-ModuleManifest` clean | ✅ |

Artifacts land in `out/`:
- `out/WSTT-4.0.0/` — staged module ready to copy onto a server.
- `out/WSTT-4.0.0.zip` — distributable archive.
- `out/test-results.xml` — Pester NUnit XML for CI ingestion.

---

## Backwards compatibility

- **Menu numbering 1–21 unchanged.** Existing operator runbooks and screenshots remain accurate.
- **Output folder structure** for HTML / TXT (Option 21) unchanged.
- **Cluster + SQL AG awareness** (v3.0 feature) preserved verbatim.
- **CLI surface:** the v3.0 entry point was `WSTT_v3.0.ps1`; v4.0's entry point is `WSTT.ps1` (or import the `WSTT` module). Wrappers calling the old script must be updated to the new file name.
- **Findings emission** is purely additive — every existing `Write-Success`/`Write-DiagWarning`/`Write-DiagError` now also calls `Add-Finding`. Console output is byte-for-byte equivalent.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Module import fails with `RootModule … not found` | Importing the `.psm1` directly | Import the **manifest**: `Import-Module .\WSTT\WSTT.psd1` |
| `Test-ModuleManifest` warns about wildcard exports | Old manifest cached | Restart PowerShell; v4.0 ships an explicit 75-function `FunctionsToExport` |
| `[INFO] Host is not a Domain Controller — skipping AD health checks.` | Expected on non-DC hosts | Not an error; emits `NA` finding |
| `Get-MpComputerStatus : Cmdlet not found` on Server Core | Defender module absent on minimal SKUs | Option 25 emits `NA` for those checks |
| Unattended run exits with code `4` | Missing `-RunAsAdministrator` privileges | Re-launch elevated |
| `Compress-Archive` hangs in custom build wrappers | PowerShell progress stream stalls | `.build.ps1` already sets `$ProgressPreference='SilentlyContinue'` and uses `[System.IO.Compression.ZipFile]` |
| Multi-server run reports "WinRM not reachable" | Firewall on target / TrustedHosts not set for workgroup | `Set-Item WSMan:\localhost\Client\TrustedHosts -Value SRV01,SRV02` (admin) and ensure 5985/5986 inbound |

---

*WSTT v4.0 release candidate — generated for the v3.0 → v4.0 cutover. Companion roadmap: [`WSTT_v4.0_Roadmap.md`](WSTT_v4.0_Roadmap.md).*
