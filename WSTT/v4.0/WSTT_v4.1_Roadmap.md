# WSTT v4.1 — Roadmap

> Successor to **`WSTT_v4.0.md`** / **`WSTT_v4.0_Roadmap.md`**.
> v4.0 closed §1–§7 of its roadmap (modular `WSTT` PowerShell module, options 22–32, JSON/SARIF export, multi-server remoting, platyPS help, optional Authenticode signing, 65 Pester tests, 0/0 PSSA, packaged `WSTT-4.0.0.zip`). v4.1 picks up the items v4.0 deferred (§8 of the v4.0 roadmap) plus operational polish surfaced during release validation.
>
> **Audience:** maintainers planning the v4.0 → v4.1 increment.
> **Status of each item:** `📋 Backlog` (proposed). None implemented yet.
> **Effort key:** S = ≤½ day · M = 1–2 days · L = 3–5 days · XL = >1 week.

---

## 1. Goals

1. Close the four operational gaps left open at v4.0 sign-off (signing execution, KB feed, Operational event channel, multi-server audit log).
2. Land the v4.0-§8 deferred domain coverage: **Containers/AKS edge**, **SDN/DCB/BGP**, **Backup (WSB/MARS/ASR)**, **GPO/WMI repository**.
3. Strengthen the foundation: **CI/CD**, **module signing chain**, **CHANGELOG/SemVer policy**, **PowerShell 7.4+ first-class** support (PS 5.1 remains supported).
4. **No breaking changes** to v4.0 menu numbers, exported function names, or findings schema. Schema may be additively extended to `wstt-findings-v1.1`.

---

## 2. Proposed v4.1 Menu Structure (Additive)

```
EXISTING (unchanged): 1–32

NEW IN v4.1:
 33. Container Host Health (Docker / Containerd / Windows Containers / AKS edge)
 34. Software-Defined Networking (SDN / DCB / BGP / RDMA)
 35. Backup Posture (Windows Server Backup / MARS / Azure Site Recovery)
 36. Group Policy & WMI Repository Health
 37. Cluster-Aware Updating (CAU) & Maintenance Mode
 38. Performance Baseline Snapshot (capture/compare counters across runs)
```

---

## 3. Detailed Feature Backlog

### 3.1 — Option 33 · Container Host Health

| # | Check | Source / Cmdlet | 2019 | 2022 | 2025 | Severity |
|---|-------|-----------------|:----:|:----:|:----:|----------|
| 33.1 | Container role detection | `Get-WindowsFeature Containers`, `Get-Service docker`, `Get-Service containerd` | ✅ | ✅ | ✅ | INFO |
| 33.2 | Containerd / Moby version & EoL | `containerd --version`, `docker version` vs supported matrix | ✅ | ✅ | ✅ | WARN if EoL |
| 33.3 | Image age & vulnerability count | `docker images` / `crictl images` → tag age | ✅ | ✅ | ✅ | WARN >180d |
| 33.4 | Disk pressure for image store | `Get-Item C:\ProgramData\containerd`, `C:\ProgramData\docker` | ✅ | ✅ | ✅ | WARN >85% |
| 33.5 | AKS edge / Arc-enabled K8s agent | `Get-Service aks-arc-*`, `azcmagent show` extensions | ⚠️ | ✅ | ✅ | WARN if Disconnected |
| 33.6 | HostProcess / HostNetwork compatibility | OS build vs HostProcess GA matrix | ⚠️ | ✅ | ✅ | INFO |
| 33.7 | Hyper-V isolation availability | `Get-VMHost`, container isolation policy | ✅ | ✅ | ✅ | INFO |
| 33.8 | Pod / container event log | `Microsoft-Windows-Containers-*/Operational` last 24h | ✅ | ✅ | ✅ | WARN/ERROR |

**Effort:** L · **Dependencies:** Containers feature; gracefully skip on bare hosts.

### 3.2 — Option 34 · SDN / DCB / BGP / RDMA

| # | Check | Source / Cmdlet | 2019 | 2022 | 2025 | Severity |
|---|-------|-----------------|:----:|:----:|:----:|----------|
| 34.1 | SDN role inventory | `Get-NetworkController`, `Get-NetworkControllerNode` | ⚠️ | ✅ | ✅ | INFO |
| 34.2 | SLB MUX / HNV gateway state | `Get-SlbMux`, `Get-NetworkControllerLoadBalancer` | ⚠️ | ✅ | ✅ | ERROR if not Healthy |
| 34.3 | DCB / PFC / ETS config | `Get-NetQosPolicy`, `Get-NetAdapterQos`, `Get-NetQosFlowControl` | ✅ | ✅ | ✅ | WARN on misalignment |
| 34.4 | RDMA capability + RoCE/iWARP detection | `Get-NetAdapterRdma`, `Get-SmbClientNetworkInterface` | ✅ | ✅ | ✅ | INFO + flags missing |
| 34.5 | BGP peer state | `Get-BgpPeer`, `Get-BgpRouter`, `Get-BgpRouteInformation` | ✅ | ✅ | ✅ | ERROR if Idle |
| 34.6 | NIC team / SET load balancing | `Get-VMSwitchTeam`, `Get-NetLbfoTeam` (legacy) | ✅ | ✅ | ✅ | WARN on degraded |
| 34.7 | Jumbo frame consistency | `Get-NetAdapterAdvancedProperty` | ✅ | ✅ | ✅ | WARN on mismatch |
| 34.8 | DNS over HTTPS / DoT client posture | `Get-DnsClientDohServerAddress` | ⚠️ | ✅ | ✅ | INFO |

**Effort:** L · **Notes:** SDN/HNV checks must `try/catch` around missing cmdlets and emit NA on non-SDN hosts.

### 3.3 — Option 35 · Backup Posture

| # | Check | Source / Cmdlet | Severity |
|---|-------|-----------------|----------|
| 35.1 | Windows Server Backup last successful job | `Get-WBSummary`, `Get-WBJob -Previous 1` | ERROR if >7d |
| 35.2 | Backup destination free space | `Get-WBBackupTarget` → volume free | WARN <15% |
| 35.3 | MARS (Recovery Services agent) installed + registered | `Get-Service obengine`, `OBRegistration` registry | INFO/WARN |
| 35.4 | MARS last backup status | `Get-OBJob -Previous 1` (if `MSOnlineBackup` module present) | ERROR on Failed |
| 35.5 | ASR (Site Recovery) replication health | `Get-Service Microsoft Azure Site Recovery Provider/Agent` (Hyper-V hosts) | WARN on critical |
| 35.6 | VSS writer health | `vssadmin list writers` parse | ERROR on failed writer |
| 35.7 | System State / SystemImage retention | Backup catalog age | INFO |

**Effort:** M · **Dependencies:** WSB feature; MARS/ASR optional & detected.

### 3.4 — Option 36 · Group Policy & WMI Repository

| # | Check | Source / Cmdlet | Severity |
|---|-------|-----------------|----------|
| 36.1 | Last GPO refresh time + result | Registry `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\State` | WARN >24h |
| 36.2 | `gpresult /h` summary parse — failed extensions | `gpresult.exe /h $tmp /f` | ERROR on extension failure |
| 36.3 | sysvol GPT.ini accessibility per applied GPO | `\\$dc\SYSVOL\<dom>\Policies\{GUID}\GPT.INI` | WARN on inaccessible |
| 36.4 | WMI repository consistency | `winmgmt /verifyrepository` | ERROR if inconsistent |
| 36.5 | WMI provider host churn (`wmiprvse.exe`) | Process count + memory | WARN >300MB sustained |
| 36.6 | Common WMI namespace enumerability | `Get-CimInstance -Namespace root\cimv2 __Namespace` | ERROR on enum failure |
| 36.7 | GPO disk/SYSVOL bloat | `Get-ChildItem \\dc\SYSVOL` size | INFO |

**Effort:** M.

### 3.5 — Option 37 · Cluster-Aware Updating & Maintenance

| # | Check | Source / Cmdlet | Severity |
|---|-------|-----------------|----------|
| 37.1 | CAU role enabled | `Get-CauPlugin`, `Get-CauClusterRole` | INFO |
| 37.2 | Last CAU run result + age | `Get-CauReport -Detailed -Last` | WARN if >60d |
| 37.3 | Cluster node paused / drained state | `Get-ClusterNode` State | WARN if persistent paused |
| 37.4 | Pending maintenance windows | `Get-CauRun` schedule | INFO |
| 37.5 | CAU pre-stage downloads | `Get-WindowsUpdateLog` parse for download readiness | INFO |

**Effort:** S-M · **Dependencies:** Failover Clustering + ClusterAwareUpdating modules.

### 3.6 — Option 38 · Performance Baseline Snapshot

| # | Capability | Detail | Effort |
|---|------------|--------|--------|
| 38.1 | Capture canonical counter set (`\Processor(_Total)\% Processor Time`, `\Memory\Available MBytes`, `\PhysicalDisk(*)\Avg. Disk sec/Transfer`, `\Network Interface(*)\Bytes Total/sec`) over N seconds | `Get-Counter -SampleInterval 1 -MaxSamples N` → JSON snapshot file | M |
| 38.2 | Save to `C:\Windows\WSTT\Baselines\<host>_<utc>.json` | atomic write, retain N copies | S |
| 38.3 | Compare current run vs latest baseline; emit deltas as findings | `Compare-Baseline` helper, percentile-based thresholds | M |
| 38.4 | Optional Excel export of multi-baseline trend | `ImportExcel` module (recommended in CLAUDE.md) | S |

**Effort total:** M · **Notes:** Useful as a leading indicator before/after patching, capacity planning.

---

## 4. v4.0 Carry-Over Items (Operational Polish)

These are the four items left open at v4.0 sign-off. v4.1 finishes them.

| ID | Carry-over | Detail | Effort |
|----|-----------|--------|--------|
| C.1 | Authenticode signing **executed** | Acquire / generate code-signing cert, sign module + `WSTT.ps1` + `.psm1` + `.psd1`, ship `WSTT-4.1.0-signed.zip`. Document cert procurement in `docs/SIGNING.md`. Add `Verify` task to `.build.ps1` that runs `Get-AuthenticodeSignature` and asserts `Valid` for every shipped file. | S (ex-cert procurement) |
| C.2 | KB-by-month feed refresh | Add `tools/Update-KbCatalog.ps1` to fetch the current month's expected LCU per OS build from MSRC release notes RSS / Update Catalog API and write `WSTT/data/kb-catalog.json`. Wire `Test-PatchingDepthAndLifecycle` to prefer external `-CatalogPath` then fall back to embedded JSON with `LastUpdated` surfaced. | M |
| C.3 | Operational Event Log channel `WSTT/Operational` | One-time `New-WinEvent`/wevtutil registration helper (`Register-WSTTEventChannel`); unattended runs emit a single event per run (severity-mapped) with finding counts + worst-severity exit code; documented in `WSTT_v4.1.md`. | S |
| C.4 | Multi-server **audit log** for Option 30 | Append-only `Logs\wstt-remoting-audit.jsonl` (caller `whoami`, target list, timestamp, run id, finding counts per target). DPAPI-encrypted at rest if cred path supplied. No per-finding PII. | S |

---

## 5. Foundation / Tooling Improvements

| # | Item | Detail | Effort |
|---|------|--------|--------|
| F.1 | **CI** in GitHub Actions / Azure Pipelines | Matrix: `windows-2019`, `windows-2022`, `windows-2025`. Steps: Install-Module InvokeBuild/Pester/PSScriptAnalyzer/platyPS → `Invoke-Build` → upload `out/test-results.xml` + `out/WSTT-*.zip`. | M |
| F.2 | **PowerShell 7.4+ first-class** | Pester run-matrix on PS 5.1 + PS 7.4. Replace remaining `Start-ThreadJob` polyfills with `ForEach-Object -Parallel` when on PS 7+. | M |
| F.3 | **CHANGELOG.md** + SemVer policy | Adopt Keep-a-Changelog. Add release-checklist doc. Bump `WSTT.psd1` `ModuleVersion` per release. | S |
| F.4 | **Schema v1.1** (additive) | New optional finding fields: `RemediationUrl`, `Tags[]`, `Confidence`. Add `wstt-findings-v1.1.schema.json`. v1 envelope still accepted. | S |
| F.5 | **`Test-WSTTSchema` helper** | In-process JSON-schema validation of own export (`Test-Json -Schema` on PS 7.3+; minimal validator on PS 5.1). | M |
| F.6 | **Findings de-duplication** | `Add-Finding -Idempotent` mode keyed on `(Category,CheckId,Message,Host)` for safe replays. | S |
| F.7 | **Concurrent-safe findings collection** | Replace `[List[object]]` with `[System.Collections.Concurrent.ConcurrentBag[object]]` for Phase F.2 parallelism. | S |
| F.8 | **PSGallery publishing** | `Publish` task: `Publish-Module -Path stage -NuGetApiKey $env:PSGALLERY_KEY`. | S |
| F.9 | **Telemetry-free metrics** | Local-only `Logs\run-metrics.jsonl` (run duration per check) for self-profiling. | S |

---

## 6. Phased Implementation Plan

| Phase | Scope | Effort |
|-------|-------|--------|
| **Phase 0 — Carry-over close-out** | C.1 – C.4 + F.3 (CHANGELOG) + F.4 (schema v1.1 placeholder) | M-L |
| **Phase 1 — CI + PS 7.4** | F.1, F.2, F.7 | L |
| **Phase 2 — Containers + Backup** | Option 33, Option 35, Option 36 (most-requested coverage) | L |
| **Phase 3 — SDN + CAU** | Option 34, Option 37 | L |
| **Phase 4 — Performance baseline** | Option 38, F.6, F.9 | M |
| **Phase 5 — Schema v1.1 + Publish** | F.4 finalised, F.5, F.8 | M |

Each phase remains independently shippable. Default `Invoke-Build` continues to succeed at every commit.

---

## 7. Acceptance Criteria for v4.1 Release

1. Carry-over items C.1 – C.4 are all closed.
2. CI green on `windows-2022` (and `windows-2019` if available) with matrix PS 5.1 + PS 7.4.
3. PSScriptAnalyzer: **0 Error**, ≤5 Warning (unchanged threshold).
4. Pester: ≥1 test per new public function (Options 33–38) on top of the existing 65.
5. JSON output validates against published `wstt-findings-v1.1.schema.json`; v1 envelopes still parseable.
6. New `WSTT_v4.1.md` supersedes `WSTT_v4.0.md`; `CHANGELOG.md` lists every behavioural change.
7. v4.0 menu numbers (1–32) and exported function names unchanged.
8. Signed `WSTT-4.1.0.zip` published (Authenticode `Valid` for every `.ps1/.psm1/.psd1`).

---

## 8. Out of Scope (deferred again or permanently)

- **Linux / macOS targets** — permanently out of scope (PowerShell-on-Linux works for the module surface but check coverage is Windows-Server-specific).
- **Defender for Identity / Sentinel deep integration** — deferred to v4.2.
- **DSC / Configuration drift** — deferred to v4.2 (overlaps with Microsoft Configuration Manager / OSConfig).
- **Live remediation / auto-fix** — explicitly out of scope; WSTT remains read-only / advisory.
- **Web UI / dashboard** — out of scope; downstream consumers (SIEM, Power BI, GitHub Code Scanning via SARIF) cover this.

---

## 9. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Container/SDN/Backup checks balloon module size | Continue NN-prefixed file split under `WSTT/Source/`; one file per option |
| PS 7 `ForEach-Object -Parallel` runspace state divergence | Concurrent-safe `$script:Findings` (F.7) + per-target merge in fan-out |
| Code-signing cert procurement delay | Use self-signed cert for non-prod build until commercial cert available; CI publishes unsigned + signed artifacts side by side |
| KB catalog API throttling | Cache locally with ETag, run weekly in CI |
| Schema drift breaking SIEM consumers | v1 envelope accepted indefinitely; v1.1 is additive; advertise both `$schema` URIs |

---

## 10. Open Questions

1. Do we want a **single `WSTT-4.1.0-signed.zip`** or separate `…-unsigned.zip` artifacts per release? (Affects CI + release notes.)
2. Should `Test-PatchingDepthAndLifecycle` ship the KB catalog **inside the module** (offline-friendly) or fetch on demand (always fresh)? Default proposed: embed + override.
3. Is **PSGallery publishing** acceptable for this module, or internal-only feed? (F.8 gating.)
4. Target completion date for v4.1 — function of cert procurement (C.1).

---

*Generated as a planning artefact for `WSTT v4.0` → `v4.1`. No code changes have been made.*
