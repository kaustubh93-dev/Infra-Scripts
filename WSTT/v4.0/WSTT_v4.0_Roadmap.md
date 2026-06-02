# WSTT v4.0 — Future-Ready Roadmap

> Companion to **`WSTT_v3.0.ps1`** / **`WSTT_v3.0.md`**.
> Goal: extend the Windows Server Troubleshooting Tool to remain authoritative for **Windows Server 2019 (17763) → 2022 (20348) → 2025 (26100)** and modern hybrid (Azure Arc) environments.
>
> **Audience:** maintainers planning the v3.x → v4.0 increment.
> **Status of each item:** `📋 Backlog` (proposed). None implemented yet.
> **Effort key:** S = ≤½ day · M = 1–2 days · L = 3–5 days · XL = >1 week.

---

## 1. Gap Analysis vs. Current v3.0

`WSTT_v3.0.ps1` already covers Network, Memory, CPU, Disk, Services, EventLog, DNS, Security/Auth, Windows Update, TLS, IIS, Task Scheduler, Server Baseline, plus cluster/SQL-AG awareness and an HTML report.

The following capability domains are **not yet present** or are **only superficially covered** and are required to remain "future-ready":

| # | Domain | Current v3.0 Coverage | Gap |
|---|--------|-----------------------|-----|
| A | Server 2025-specific features | OS-build detection, LBFO→SET fallback only | No Hotpatch, dMSA, NTLM-deprecation audit, SMB-over-QUIC, Network ATC, GPU-P, ARM64 detection |
| B | Modern security hardening | TLS, basic auth events | No VBS/HVCI/Credential-Guard/LSA-PPL/ASR/WDAC/Secure-Boot/TPM/BitLocker/LAPS posture |
| C | Active Directory role health | None (generic event log only) | No `dcdiag`/`repadmin`/FSMO/SYSVOL/DFSR/time-hierarchy/Kerberos checks |
| D | Hyper-V host health | None | No VM state, integration services, dynamic memory, replica, checkpoint sprawl, vSwitch health |
| E | Advanced storage (S2D / SR / Dedup / ReFS-integrity / Storage-QoS) | Volume free space + IOPS | No S2D pool/jobs, Storage Replica, Dedup status, ReFS scrub, Storage-QoS policies |
| F | Hybrid / Azure Arc | None | No Arc agent health, Azure Update Manager, AMA, MDE/MDC posture |
| G | Certificates & PKI | None | No expiring-cert scan, chain-build validation, autoenrollment, NDES |
| H | Lifecycle & patching depth | Build detection, basic WU status | No Hotpatch state, KB supersedence chain, EoL/EoS, reboot-pending root cause |
| I | Output / integration | HTML, TXT | No JSON/CSV/NDJSON, no SIEM-friendly schema, no scheduled/unattended mode, no multi-server fan-out |

This roadmap closes those gaps.

---

## 2. Proposed v4.0 Menu Structure (Additive)

Existing options 1–21 remain unchanged. New options are appended so existing automation and muscle memory are not broken.

```
NEW OPTIONS (v4.0):
 22. Active Directory Health (DC role only)
 23. Hyper-V Host Health
 24. Advanced Storage (S2D / Dedup / ReFS / Storage Replica / Storage QoS)
 25. Modern Security Posture (VBS/HVCI/CG/LSA-PPL/ASR/WDAC/SecureBoot/TPM/BitLocker/LAPS)
 26. Server 2025 Feature Audit (Hotpatch / dMSA / NTLM-Deprecation / SMB-QUIC / NetATC / GPU-P)
 27. Certificates & PKI Health
 28. Hybrid / Azure Arc Health
 29. Patching Depth & Lifecycle
 30. Multi-Server Remoting Mode
 31. Export Diagnostics (JSON / CSV / NDJSON / SARIF-lite)
 32. Unattended / Scheduled Mode
```

---

## 3. Detailed Feature Backlog

> Each row: **Check · Purpose · Source/cmdlet · OS · Severity output · Notes**.
> "OS" column key — ✅ supported, ⚠️ partial/needs feature install, ❌ N/A.

### 3.1 — Option 22 · Active Directory Health (Domain Controller only)

| # | Check | Purpose | Source / Cmdlet | 2019 | 2022 | 2025 | Default Severity |
|---|-------|---------|-----------------|:----:|:----:|:----:|------------------|
| 22.1 | DC role detection | Skip section if not a DC | `Get-WindowsFeature AD-Domain-Services` + `(Get-CimInstance Win32_ComputerSystem).DomainRole` ≥4 | ✅ | ✅ | ✅ | INFO |
| 22.2 | `dcdiag /v /q` summary | Surface DC test failures | `dcdiag.exe /q` parse | ✅ | ✅ | ✅ | ERROR on failure |
| 22.3 | Replication health | Inbound failures, last sync | `repadmin /replsummary`, `repadmin /showrepl` | ✅ | ✅ | ✅ | ERROR if last >24h |
| 22.4 | FSMO role holders | Map roles → DC, flag if local DC offline | `netdom query fsmo` | ✅ | ✅ | ✅ | INFO / WARN |
| 22.5 | SYSVOL / DFSR state | DFSR backlog, SYSVOL share readable | `Get-DfsrState`, `\\$env:LOGONSERVER\SYSVOL` test | ✅ | ✅ | ✅ | WARN if backlog >100 |
| 22.6 | Time hierarchy | Stratum, source, offset | `w32tm /query /status`, `w32tm /monitor` | ✅ | ✅ | ✅ | WARN if offset >1s |
| 22.7 | Kerberos health | KDC service, krbtgt password age, PKINIT | `Get-ADUser krbtgt -Properties PasswordLastSet`, KDC svc | ✅ | ✅ | ✅ | WARN if krbtgt >180d |
| 22.8 | LDAP signing / channel binding | LDAP hardening posture (ADV190023) | Registry `LDAPServerIntegrity`, `LdapEnforceChannelBinding` | ✅ | ✅ | ✅ | WARN if not enforced |
| 22.9 | NTLM auditing | Inbound NTLM usage (8004/8002 events) | `Microsoft-Windows-NTLM/Operational` | ✅ | ✅ | ✅ | INFO (count) |
| 22.10 | AD database / log free space | NTDS volume free | `Get-Volume` of NTDS path | ✅ | ✅ | ✅ | WARN <15% |

**Effort:** L · **Dependencies:** Optional `ActiveDirectory` RSAT module (graceful fallback to `dsquery`/`netdom`).

---

### 3.2 — Option 23 · Hyper-V Host Health

| # | Check | Purpose | Source / Cmdlet | 2019 | 2022 | 2025 | Severity |
|---|-------|---------|-----------------|:----:|:----:|:----:|----------|
| 23.1 | Hyper-V role detection | Skip if not a host | `Get-WindowsFeature Hyper-V` | ✅ | ✅ | ✅ | INFO |
| 23.2 | VM state inventory | Off / Saved / Paused / Critical | `Get-VM` | ✅ | ✅ | ✅ | ERROR if Critical |
| 23.3 | Integration services version drift | Out-of-date guests | `Get-VM | Select IntegrationServicesVersion` | ✅ | ✅ | ✅ | WARN |
| 23.4 | Dynamic memory pressure | Demand vs Assigned | `Get-VM | Select MemoryDemand,MemoryAssigned` | ✅ | ✅ | ✅ | WARN >80% |
| 23.5 | Checkpoint sprawl | Old/large/production checkpoints | `Get-VMSnapshot` (age, size) | ✅ | ✅ | ✅ | WARN if >7d |
| 23.6 | Hyper-V Replica status | Health=Critical, lag | `Get-VMReplication` | ✅ | ✅ | ✅ | ERROR Critical |
| 23.7 | vSwitch health | External switches up, SR-IOV state | `Get-VMSwitch`, `Get-NetAdapterSriov` | ✅ | ✅ | ✅ | WARN |
| 23.8 | Storage path / VHDX integrity | Pass-through, dynamic full risk | `Get-VHD` (Size vs FileSize) | ✅ | ✅ | ✅ | WARN >85% allocated |
| 23.9 | Live Migration config | Authentication, performance options | `Get-VMHost` LiveMigration props | ✅ | ✅ | ✅ | INFO |
| 23.10 | GPU partitioning (GPU-P) | List partitioned adapters (Server 2025) | `Get-VMHostPartitionableGpu` | ❌ | ⚠️ | ✅ | INFO |
| 23.11 | Event log scrape | `Microsoft-Windows-Hyper-V-VMMS-Admin/Operational` last 24h | `Get-WinEvent` | ✅ | ✅ | ✅ | ERROR/WARN |

**Effort:** L · **Dependencies:** `Hyper-V` PowerShell module.

---

### 3.3 — Option 24 · Advanced Storage

| # | Check | Source / Cmdlet | 2019 | 2022 | 2025 | Severity |
|---|-------|-----------------|:----:|:----:|:----:|----------|
| 24.1 | S2D pool health | `Get-StoragePool`, `Get-VirtualDisk`, `Get-StorageJob` | ⚠️ DC SKU | ✅ DC SKU | ✅ DC SKU | ERROR if `Degraded`/`Repair Needed` |
| 24.2 | S2D cache state | `Get-PhysicalDisk | ? Usage -eq 'Journal'` | ⚠️ | ✅ | ✅ | WARN if missing |
| 24.3 | Storage Replica | Async lag, partnership state | `Get-SRPartnership`, `Get-SRGroup` | ✅ | ✅ | ✅ | WARN if lag >30s |
| 24.4 | Data Deduplication | Volume status, savings, last optimization | `Get-DedupStatus`, `Get-DedupSchedule` | ✅ | ✅ | ✅ | WARN if last >7d |
| 24.5 | ReFS integrity & scrub | `Get-FileIntegrity`, `Get-StorageBusBindingMode`, scrub jobs | ✅ | ✅ | ✅ | WARN on errors |
| 24.6 | Storage QoS policies | `Get-StorageQosPolicy`, `Get-StorageQosFlow` | ⚠️ | ✅ | ✅ | INFO |
| 24.7 | Tier rebalance | Storage Spaces tiering job | `Get-ScheduledTask MicrosoftWindowsStorageTiersManagement` | ✅ | ✅ | ✅ | WARN if disabled |
| 24.8 | Storage Health Service alerts | `Get-StorageSubSystem | Get-StorageHealthReport` | ⚠️ | ✅ | ✅ | ERROR |
| 24.9 | Persistent reservation conflicts | `Get-WinEvent Microsoft-Windows-StorageSpaces-Driver` | ✅ | ✅ | ✅ | WARN |
| 24.10 | NVMe namespace / firmware | `Get-PhysicalDisk | ft FirmwareVersion` + EOL list | ✅ | ✅ | ✅ | INFO |

**Effort:** L · **Dependencies:** Storage role/feature; gracefully skip if not S2D.

---

### 3.4 — Option 25 · Modern Security Posture

| # | Check | Source | 2019 | 2022 | 2025 | Severity |
|---|-------|--------|:----:|:----:|:----:|----------|
| 25.1 | Secure Boot enabled | `Confirm-SecureBootUEFI` | ✅ | ✅ | ✅ | WARN if false |
| 25.2 | TPM 2.0 ready & owned | `Get-Tpm` | ✅ | ✅ | ✅ | WARN if absent on physical |
| 25.3 | VBS / HVCI / Credential Guard running | `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard` (`SecurityServicesRunning`) | ✅ | ✅ | ✅ | WARN if not running |
| 25.4 | LSA Protection (RunAsPPL) | Registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` | ✅ | ✅ | ✅ | WARN if 0 |
| 25.5 | ASR rules state | `Get-MpPreference | Select AttackSurfaceReductionRules_*` | ✅ | ✅ | ✅ | WARN if all Disabled |
| 25.6 | WDAC / Code Integrity policy | `Get-CimInstance Win32_DeviceGuard CodeIntegrityPolicyEnforcementStatus` | ✅ | ✅ | ✅ | INFO |
| 25.7 | AppLocker rules in effect | `Get-AppLockerPolicy -Effective`, mode (Audit/Enforce) | ✅ | ✅ | ✅ | INFO |
| 25.8 | BitLocker volumes | `Get-BitLockerVolume` (system + data drives) | ✅ | ✅ | ✅ | WARN if any decrypted |
| 25.9 | Defender / MDE health | `Get-MpComputerStatus`, `Get-MpPreference`, signature age | ✅ | ✅ | ✅ | ERROR if AMRunningMode≠Normal |
| 25.10 | Defender for Endpoint sensor | `Get-Service Sense`, onboarding state | ✅ | ✅ | ✅ | INFO |
| 25.11 | LAPS (Windows LAPS) | `Get-Service LapsSvc`, policy applied via `Get-LapsAADPassword`/registry | ⚠️ | ✅ | ✅ | INFO |
| 25.12 | SMB1 client/server installed | `Get-WindowsOptionalFeature SMB1Protocol*` | ✅ | ✅ | ✅ | ERROR if installed |
| 25.13 | SMB signing / encryption | `Get-SmbServerConfiguration` (`RequireSecuritySignature`, `EncryptData`) | ✅ | ✅ | ✅ (default true) | WARN if false |
| 25.14 | NTLM audit posture | Registry `LmCompatibilityLevel`, audit policies | ✅ | ✅ | ✅ | WARN if <5 |
| 25.15 | Print Spooler / PrintNightmare | Spooler running on DC, `RestrictDriverInstallationToAdministrators` | ✅ | ✅ | ✅ | ERROR if DC + spooler running |

**Effort:** L · **Dependencies:** Defender module on Server SKUs; graceful skip on Core/SAC.

---

### 3.5 — Option 26 · Server 2025 Feature Audit

| # | Check | Source | 2019 | 2022 | 2025 | Severity |
|---|-------|--------|:----:|:----:|:----:|----------|
| 26.1 | Hotpatch eligibility & state | `Get-HotPatchState` (2025) / Azure-Edition VM tag (2022) / `Get-AutomanageHCRPMachine` | ❌ | ⚠️ Az Ed | ✅ | INFO |
| 26.2 | dMSA (Delegated MSA) presence | `Get-ADServiceAccount -Filter {ObjectClass -eq 'msDS-DelegatedManagedServiceAccount'}` | ❌ | ❌ | ✅ | INFO |
| 26.3 | NTLM deprecation telemetry | `Microsoft-Windows-NTLM/Operational` events 8001/8002 last 7d | ✅ | ✅ | ✅ | WARN if active |
| 26.4 | SMB-over-QUIC server | `Get-SmbServerCertificateMapping`, listener on 443 | ❌ | ✅ Azure Ed | ✅ | INFO |
| 26.5 | Network ATC intents | `Get-NetIntent`, `Get-NetIntentStatus` | ❌ | ✅ Azure Stack HCI | ✅ | WARN if Failed |
| 26.6 | GPU-P partitions | `Get-VMHostPartitionableGpu`, `Get-VMGpuPartitionAdapter` | ❌ | ⚠️ | ✅ | INFO |
| 26.7 | ARM64 architecture | `(Get-CimInstance Win32_Processor).Architecture` | ✅ | ✅ | ✅ (12 = ARM64) | INFO + flags incompatible tools |
| 26.8 | OpenSSH server posture | `Get-Service sshd`, configured KEX/ciphers | ✅ | ✅ | ✅ (in-box) | WARN on weak |
| 26.9 | WinRM HTTPS default | Listener inventory; flag HTTP-only listener | ✅ | ✅ | ✅ | WARN if HTTP only |
| 26.10 | TLS 1.3 enabled (Schannel) | Registry SCHANNEL\Protocols\TLS 1.3 | ❌ | ✅ | ✅ | INFO |
| 26.11 | DNSSEC validation | `Get-DnsServerDnsSecZoneSetting` (DNS role), `Resolve-DnsName -DnssecOk` | ✅ | ✅ | ✅ | INFO |
| 26.12 | Wi-Fi / Bluetooth stack present (anti-pattern on server) | `Get-NetAdapter` filter `MediaType -eq 'Native 802.11'` | ✅ | ✅ | ✅ | WARN if found |

**Effort:** M-L · **Notes:** Several checks are pure detection — they should not error if cmdlets are missing on older OS; they should print "N/A — requires Server 2025".

---

### 3.6 — Option 27 · Certificates & PKI

| # | Check | Source | 2019 | 2022 | 2025 | Severity |
|---|-------|--------|:----:|:----:|:----:|----------|
| 27.1 | Expiring computer / personal certs | `Get-ChildItem Cert:\LocalMachine\My` (≤30d, ≤90d) | ✅ | ✅ | ✅ | ERROR ≤30d |
| 27.2 | Expiring web bindings | `Get-WebBinding` → cert thumbprint → expiry | ✅ | ✅ | ✅ | ERROR ≤30d |
| 27.3 | WinRM listener cert | `winrm enumerate winrm/config/listener` | ✅ | ✅ | ✅ | ERROR if expired |
| 27.4 | Trusted Root CA freshness | Count `LocalMachine\Root` vs Microsoft CTL age | ✅ | ✅ | ✅ | INFO |
| 27.5 | Private key permissions | `(Get-Acl <key>).Access` audit | ✅ | ✅ | ✅ | WARN if Everyone |
| 27.6 | Cert chain build | `[X509Chain]::Build()` per cert; surface revocation/CRL fail | ✅ | ✅ | ✅ | WARN on failure |
| 27.7 | Auto-enrollment status | GPO setting + `certutil -pulse` last result | ✅ | ✅ | ✅ | WARN |
| 27.8 | NDES / SCEP responder reachable | (if NDES role) IIS app pool + endpoint test | ✅ | ✅ | ✅ | ERROR |
| 27.9 | LDAPS cert (DC) | Bind to 636, validate cert | ✅ | ✅ | ✅ | ERROR |

**Effort:** M.

---

### 3.7 — Option 28 · Hybrid / Azure Arc

| # | Check | Source | 2019 | 2022 | 2025 | Severity |
|---|-------|--------|:----:|:----:|:----:|----------|
| 28.1 | Arc agent installed & connected | `Get-Service himds`, `azcmagent show` | ✅ | ✅ | ✅ | WARN if Disconnected |
| 28.2 | Arc agent version vs supported | `azcmagent version` vs N-2 policy | ✅ | ✅ | ✅ | WARN |
| 28.3 | Azure Monitor Agent (AMA) | `Get-Service AzureMonitorAgent`, heartbeat events | ✅ | ✅ | ✅ | WARN |
| 28.4 | Azure Update Manager assessment | `Get-Service WindowsAzureGuestAgent` (Azure VM) or AUM scheduled task | ✅ | ✅ | ✅ | INFO |
| 28.5 | Defender for Cloud onboarding | MDE sensor + Defender plan registry | ✅ | ✅ | ✅ | INFO |
| 28.6 | Outbound endpoint reachability | Test 443 to `*.guestconfiguration.azure.com`, `*.his.arc.azure.com` | ✅ | ✅ | ✅ | ERROR if blocked |
| 28.7 | Proxy configuration for Arc | `azcmagent config list` proxy.url | ✅ | ✅ | ✅ | INFO |
| 28.8 | Extension health | `azcmagent show -j` → extensions[].state | ✅ | ✅ | ✅ | ERROR Failed |

**Effort:** M · **Dependencies:** `azcmagent` CLI optional; gracefully skip on non-Arc machines.

---

### 3.8 — Option 29 · Patching Depth & Lifecycle

| # | Check | Source | 2019 | 2022 | 2025 | Severity |
|---|-------|--------|:----:|:----:|:----:|----------|
| 29.1 | Hotpatch state & baseline KB | `Get-HotPatchState` / registry `HotPatch` | ❌ | ⚠️ Az Ed | ✅ | INFO |
| 29.2 | Latest cumulative installed | `Get-HotFix` newest LCU vs current month's expected KB (offline list) | ✅ | ✅ | ✅ | WARN if >60d behind |
| 29.3 | SSU (Servicing Stack) version | Registry `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Component Based Servicing\Packages` | ✅ | ✅ | ✅ | INFO |
| 29.4 | Reboot pending root cause | Six pending-reboot signals (CBS, WU, PendingFileRename, etc.) — surface which | ✅ | ✅ | ✅ | WARN if pending |
| 29.5 | Failed updates (last 30d) | `Get-WUHistory` / `Get-WinEvent System` source `WindowsUpdateClient` ResultCode≠0 | ✅ | ✅ | ✅ | ERROR |
| 29.6 | OS lifecycle dates | Lookup table (mainstream/extended end) per build | ✅ | ✅ | ✅ | WARN if <12 months left |
| 29.7 | .NET / Visual C++ runtime currency | Installed versions vs latest GA | ✅ | ✅ | ✅ | INFO |
| 29.8 | Driver currency for storage/NIC | `Get-PnpDeviceProperty` → driver date >2y | ✅ | ✅ | ✅ | WARN |
| 29.9 | Microsoft Update vs WSUS source | `Get-WUSettings` UseWUServer, target group | ✅ | ✅ | ✅ | INFO |

**Effort:** M-L · **Notes:** Maintain a small embedded KB-by-month JSON updated per release; allow override path.

---

### 3.9 — Option 30 · Multi-Server Remoting Mode

A *mode*, not a check. Wraps options 1–29 with a server-list iterator using PSRemoting / WinRM.

| Capability | Detail | Effort |
|------------|--------|--------|
| 30.1 | Accept `-ComputerName` array, `-CredentialPath` (DPAPI clixml) | M |
| 30.2 | Parallel execution via `Start-ThreadJob` (PS5 polyfill `PSThreadJob`) | M |
| 30.3 | Per-target output folder, single rolled-up summary | S |
| 30.4 | Capability probe (skip checks needing modules not present on target) | M |
| 30.5 | Pre-flight: WinRM trust, port 5985/5986, TrustedHosts for workgroup | S |
| 30.6 | Resilient: timeouts per check, partial-failure tolerated | S |
| 30.7 | Audit log (who ran, against whom, when) — non-PII | S |

**Effort total:** L · **Security:** never accept plain-text passwords on CLI; always Get-Credential or DPAPI clixml; honour repo CLAUDE.md credential rules.

---

### 3.10 — Option 31 · Export Diagnostics

| Format | Use case | Implementation | Effort |
|--------|----------|----------------|--------|
| 31.1 | **JSON** structured per check | SIEM ingestion, downstream automation | Refactor `Write-Success/Warning/Error` to also emit `[pscustomobject]` into `$script:Findings`; serialise with `ConvertTo-Json -Depth 8` | M |
| 31.2 | **NDJSON** (one finding per line) | Splunk/Elastic, log shippers | Same source; different writer | S |
| 31.3 | **CSV** flat findings | Excel triage | Project `$script:Findings` with `Export-Csv -NoTypeInformation` | S |
| 31.4 | **SARIF-lite** | GitHub/Azure DevOps code-scanning style ingest | Map severity → SARIF level | M |
| 31.5 | Schema version + tool/host metadata header | Forward compatibility | Top-level envelope `{ schema:1, host:{}, run:{}, findings:[] }` | S |

**Effort total:** M · **Prerequisite:** introduce `Add-Finding` helper used by every check (refactor — see §4 phase 1).

---

### 3.11 — Option 32 · Unattended / Scheduled Mode

| Item | Detail |
|------|--------|
| 32.1 | New parameter set `-Unattended -Categories <id[]> -OutputPath <dir> -Format JSON|HTML|Both` |
| 32.2 | No prompts, no `Read-Host`, exit code reflects worst severity (0 OK, 1 WARN, 2 ERROR, 3 fatal) |
| 32.3 | Scheduled Task generator: `Register-WSTTSchedule -Daily 02:00 -Categories Security,Patching` |
| 32.4 | Output rotation (keep N) |
| 32.5 | Optional Event Log channel (`WSTT/Operational`) for run summary |

**Effort:** M · **Dependencies:** §3.10 JSON output.

---

## 4. Phased Implementation Plan

> Strictly additive. Existing menu items 1–21 remain untouched until Phase 5 refactor.
> Each phase is independently shippable (script remains usable after each).

### Phase 0 — Foundation refactors (prerequisite)

| Task | Detail | Effort |
|------|--------|--------|
| 0.1 | Introduce `Add-Finding` helper + `$script:Findings` collection (`List[object]`) | M |
| 0.2 | Wire existing `Write-Success/DiagWarning/DiagError` to also call `Add-Finding` (no behaviour change) | M |
| 0.3 | Add `Get-OSCapability` cache (build, edition Core/Desktop, Azure Edition, ARM64, role inventory) replacing scattered `(Get-CimInstance Win32_OperatingSystem)` calls | M |
| 0.4 | Split `WSTT_v3.0.ps1` into a folder-module (`WSTT/Public`, `WSTT/Private`) per CLAUDE.md (3+ functions rule already exceeded) — *deferred but tracked* | XL |
| 0.5 | Add Pester 5 baseline tests (PSScriptAnalyzer 0-error gate, no `$Global:`, no `ExecutionPolicy Bypass`) | M |

**Phase total:** L

### Phase 1 — Security & Server-2025 audit (highest external value)

Adds **Option 25 (Modern Security Posture)** + **Option 26 (Server 2025 Feature Audit)**.
Effort: L. Risk: low (read-only checks).

### Phase 2 — Role-aware health (DC + Hyper-V + Storage)

Adds **Option 22, 23, 24**. Each guarded by role detection so non-applicable hosts skip gracefully.
Effort: L-XL.

### Phase 3 — PKI + Hybrid + Lifecycle

Adds **Option 27, 28, 29**. Embeds maintained KB / EoL JSON.
Effort: L.

### Phase 4 — Output & Automation

Adds **Option 31 (export)**, **Option 32 (unattended)** — leverages Phase-0 `Add-Finding`.
Effort: M.

### Phase 5 — Multi-server remoting

Adds **Option 30**. Build last so all checks have proven idempotent / remotable.
Effort: L.

### Phase 6 — Module-isation

Convert script to module (Phase 0 task 0.4) once feature surface is stable. Adds `.build.ps1`, platyPS help, manifest, signing.
Effort: XL.

---

## 5. OS Compatibility Matrix Update (post-v4.0)

| Capability | 2019 | 2022 | 2025 |
|------------|:----:|:----:|:----:|
| All v3.0 checks | ✅ | ✅ | ✅ |
| Hotpatch | ❌ | ⚠️ Az Ed | ✅ |
| dMSA | ❌ | ❌ | ✅ |
| Network ATC | ❌ | ⚠️ HCI | ✅ |
| GPU-P | ❌ | ⚠️ | ✅ |
| SMB-over-QUIC server | ❌ | ✅ Az Ed | ✅ |
| TLS 1.3 Schannel | ❌ | ✅ | ✅ |
| Windows LAPS in-box | ⚠️ | ✅ | ✅ |
| Credential Guard / VBS | ✅ | ✅ | ✅ (default-on Std) |
| ARM64 detection | n/a | n/a | ✅ |

---

## 6. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Script size already large (7900 lines) | Phase 0 refactor extracts findings emitter; Phase 6 modularises |
| New cmdlets unavailable on 2019 | Each check wrapped in `if (Get-Command X -EA SilentlyContinue)` and emits N/A finding |
| Performance counter locale dependence | Re-use existing locale warning; new checks favour CIM/registry over `Get-Counter` |
| Remote execution credential exposure | DPAPI clixml only, never `-Password` on CLI, env vars cleaned in `finally` (per CLAUDE.md) |
| KB-by-month list goes stale | External JSON path overrideable; embedded copy with `LastUpdated` field surfaced in output |
| Increased run-time | `-Categories` selector, parallel internal sections via `Start-ThreadJob` |
| Test debt | Phase 0.5 mandates Pester baseline; each new option must ship with at least 1 Pester test |

---

## 7. Acceptance Criteria for v4.0 Release

1. All Phase 0–4 items complete.
2. PSScriptAnalyzer: **0 Error**, ≤5 Warning across the file/module.
3. Pester: 100% of new public functions have ≥1 test.
4. JSON output validates against published `wstt-findings-v1.schema.json`.
5. Non-admin or unsupported-OS run **does not crash**; emits a clean N/A summary.
6. `WSTT_v3.0.md` superseded by `WSTT_v4.0.md` covering new options.
7. Backwards compatibility: every v3.0 menu number unchanged.

---

## 8. Out of Scope (intentionally deferred)

- Containers / AKS edge — deferred to v4.1.
- SDN / DCB / BGP deep-dive — deferred to v4.1.
- Backup (WSB / MARS / ASR) — deferred to v4.1.
- Group Policy / WMI repository deep-dive — deferred to v4.1.
- Non-Windows targets — out of scope permanently.

---

*Generated as a planning artefact for `WSTT_v3.0.ps1` → v4.0. No code changes have been made.*
