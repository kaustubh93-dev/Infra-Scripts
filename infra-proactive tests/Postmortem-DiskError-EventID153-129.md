# Blameless Postmortem — Cluster Node Failure Due to Storage Disk Errors

> **Template Version:** 1.0  
> **Applies To:** Windows Server Failover Cluster (WSFC) node evictions triggered by disk I/O errors  
> **Key Event IDs:** 153 (I/O retry) · 129 (Storage adapter reset)

---

## Document Control

| Field | Value |
|---|---|
| **Incident ID** | `INC-YYYYMMDD-XXX` |
| **Severity** | Sev-1 / Sev-2 / Sev-3 |
| **Date of Incident** | YYYY-MM-DD |
| **Duration** | HH:MM (detection → full recovery) |
| **Postmortem Author** | _Name_ |
| **Postmortem Date** | YYYY-MM-DD |
| **Review Board** | _Names / Teams_ |
| **Status** | Draft / Reviewed / Final |

---

## 1. Incident Summary

> _Write 2–3 sentences. What happened, which node(s), what was the customer/business impact?_

**Example:**  
On YYYY-MM-DD at HH:MM UTC, cluster node `NODE-NAME` was evicted from the Windows Server Failover Cluster after sustained disk I/O errors (Event ID 153 / 129) on physical disk `PhysicalDrive#`. The node hosted [AG secondary replica / Cluster Shared Volume / File Server role]. [Failover occurred successfully / Client connections were interrupted for X minutes / Data movement was suspended].

---

## 2. Impact Assessment

| Dimension | Detail |
|---|---|
| **Affected node(s)** | |
| **Affected workloads** | SQL AG replica / CSV / Hyper-V VM / File share |
| **Failover triggered?** | Yes — automatic / Yes — manual / No |
| **Client-facing downtime** | X min (or none if secondary) |
| **Data loss** | None / Potential (async replica) / Confirmed |
| **SLA breach** | Yes / No — remaining SLA budget: X min |
| **Blast radius** | Single node / Single site / Multi-site |

---

## 3. Timeline

> _Use UTC. Include every meaningful event from first signal to full recovery. Timestamps from event logs, not memory._

| Time (UTC) | Source | Event |
|---|---|---|
| HH:MM:SS | System Event Log | First Event ID 153 — `The IO operation at logical block address 0x________ for Disk # was retried.` |
| HH:MM:SS | System Event Log | Event ID 129 — `Reset to device, \Device\RaidPortX, was issued.` |
| HH:MM:SS | System Event Log | Event ID 153 count reaches X within Y minutes |
| HH:MM:SS | System Event Log | Event ID 129 recurs — storage adapter reset #2 |
| HH:MM:SS | System Event Log | Event ID 11 (disk) — `The driver detected a controller error on \Device\HarddiskX` |
| HH:MM:SS | FailoverClustering/Operational | Event ID 1135 — `Node NODE-NAME was removed from the active failover cluster membership` |
| HH:MM:SS | SQL Server Error Log | `The availability group database "DB-NAME" is changing roles from "SECONDARY" to "RESOLVING"` |
| HH:MM:SS | Monitoring | Alert fired: [alert name] |
| HH:MM:SS | On-call | Engineer acknowledged, joined bridge |
| HH:MM:SS | On-call | Diagnostics started — identified disk errors as root cause |
| HH:MM:SS | On-call | Node rebooted / disk replaced / node re-joined cluster |
| HH:MM:SS | AG DMV | All replicas returned to `SYNCHRONIZED` |
| HH:MM:SS | On-call | Incident resolved, monitoring confirmed steady state |

---

## 4. Root Cause Analysis

### 4.1 — Event ID Reference

| Event ID | Source | Meaning | Severity |
|---|---|---|---|
| **129** | storahci / storport | **Storage adapter reset issued** — the storage driver timed out waiting for a response from the disk/controller and issued a bus reset. Indicates the disk or HBA did not respond within the timeout window (default 30 s for storport). | 🔴 Critical precursor |
| **153** | disk / iScsi | **I/O operation retried** — a read/write at a specific logical block address failed and was retried by the storage stack. Frequent occurrences indicate degrading media, controller issues, or fabric problems. | 🟠 Warning / escalation |
| **11** | disk | **Controller error** — the driver detected a controller error on the physical disk device. Often follows 129/153 cascades. | 🔴 Error |
| **15** | disk | **Device not ready** — the disk is no longer responding. Final stage before node-level impact. | 🔴 Critical |
| **1135** | FailoverClustering | **Node removed from cluster membership** — the cluster service evicted the node because it could not communicate or maintain health checks. | 🔴 Node eviction |
| **1177** | FailoverClustering | **Quorum lost** (if applicable) — the cluster lost quorum due to insufficient votes. | 🔴 Cluster-wide |

### 4.2 — Root Cause Chain (5 Whys)

> _Fill in the chain working backward from the business impact to the true root cause._

| # | Why? | Answer |
|---|---|---|
| **1** | Why was the node evicted from the cluster? | The cluster health check timed out because the node was unresponsive due to disk I/O stalls. |
| **2** | Why was the node unresponsive? | Pending I/O operations hung for > 30 seconds, causing the storage stack to issue bus resets (Event 129) and the OS to become sluggish/frozen. |
| **3** | Why did I/O operations hang? | The physical disk / controller / SAN path failed to complete I/O within the storport timeout, triggering retries (Event 153) that cascaded into adapter resets. |
| **4** | Why did the disk/controller/SAN path fail? | _Root cause — fill in one of the following:_ |
| | | ☐ **Physical disk degradation** — media errors, bad sectors, SMART warnings |
| | | ☐ **RAID controller failure** — battery/capacitor issue, firmware bug, cache de-staging failure |
| | | ☐ **HBA / FC switch issue** — link flap, port error, zoning misconfiguration |
| | | ☐ **SAN fabric congestion** — ISL saturation, buffer credit starvation |
| | | ☐ **iSCSI / network storage** — NIC failure, VLAN issue, MTU mismatch, multipath failover failure |
| | | ☐ **VMware / Hyper-V virtual disk** — underlying datastore latency, snapshot consolidation |
| | | ☐ **Driver / firmware bug** — known issue in storport / storahci / HBA driver version |
| | | ☐ **Power / environmental** — UPS event, thermal throttling |
| **5** | Why was this not prevented? | _Fill in: missing monitoring / stale firmware / no predictive disk replacement / timeout not tuned, etc._ |

### 4.3 — Disk Error Forensics

> _Fill in from the affected node's logs. Use `Get-WinEvent`, `diskperf`, SMART data, storage vendor tools._

| Diagnostic | Value | Normal Range | Verdict |
|---|---|---|---|
| Event 153 count (24 h before incident) | | 0 | |
| Event 129 count (24 h before incident) | | 0 | |
| Event 11 count | | 0 | |
| Disk model / firmware | | | |
| RAID controller model / firmware | | | |
| HBA driver version | | | |
| Storport miniport driver version | | | |
| `TimeoutValue` (HKLM\SYSTEM\CurrentControlSet\Services\Disk) | | 60 (default) | |
| SMART — Reallocated Sector Count | | 0 | |
| SMART — Current Pending Sector Count | | 0 | |
| SMART — Uncorrectable Sector Count | | 0 | |
| SMART — Power-On Hours | | < manufacturer spec | |
| Avg disk latency (perfmon) at incident time | | < 20 ms | |
| Peak disk queue length at incident time | | < 4 | |
| Multipath status (MPIO) | Active/Active, Active/Passive | | |
| Number of path failovers in 24 h | | 0 | |

### 4.4 — Storage Stack Diagram (Mark Failure Point)

```
┌─────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                        │
│                  (SQL Server / Hyper-V / CSV)                   │
├─────────────────────────────────────────────────────────────────┤
│                        FILESYSTEM LAYER                         │
│                   (NTFS / ReFS / CSVFS)                         │
├─────────────────────────────────────────────────────────────────┤
│                      VOLUME / PARTITION                          │
│               (Basic / Dynamic / Storage Spaces)                │
├─────────────────────────────────────────────────────────────────┤
│                     MULTIPATH I/O (MPIO)                        │
│             (Microsoft DSM / Vendor DSM)                        │
│                                                                 │
│         Path A ──────────┬────────── Path B                     │
│                          │                                      │
├──────────────────────────┼──────────────────────────────────────┤
│                   MINIPORT DRIVER                                │
│          (storahci / storport / vendor HBA)                     │
│                                                                 │
│   ┌─────────────────────────────────────────────┐               │
│   │  ⏱ Storport Timeout (default 30s)           │  ← Event 129 │
│   │  I/O retry logic                             │  ← Event 153 │
│   └─────────────────────────────────────────────┘               │
├─────────────────────────────────────────────────────────────────┤
│                   HARDWARE / TRANSPORT                           │
│                                                                 │
│   Local:  SATA / SAS / NVMe controller → Physical Disk         │
│   FC:     HBA → FC Switch → SAN Controller → LUN               │
│   iSCSI:  NIC → Network → iSCSI Target → LUN                  │
│                                                                 │
│   Mark failure point:  ☐ Controller  ☐ Fabric  ☐ Disk          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Contributing Factors

> _Blameless: focus on system weaknesses, not people. Check all that apply and add detail._

- [ ] **No proactive disk health monitoring** — SMART/predictive failure alerts not configured
- [ ] **Stale firmware** — disk/controller/HBA firmware not on vendor-recommended version
- [ ] **Stale drivers** — storport/storahci/HBA driver outdated; known bugs in current version
- [ ] **Storport timeout too aggressive/lenient** — `TimeoutValue` not tuned for workload
- [ ] **MPIO misconfigured** — single path, no failover, or wrong DSM policy
- [ ] **No disk I/O latency alerting** — monitoring lacked thresholds on Event 153/129 counts or disk latency
- [ ] **Cluster heartbeat timeout too tight** — cross-subnet thresholds caused premature eviction during transient I/O stall
- [ ] **No hardware redundancy** — single controller, no hot spare, no RAID battery backup
- [ ] **Capacity / thermal issue** — disk operating beyond rated conditions
- [ ] **Runbook gap** — no documented response procedure for Event 129/153 escalation
- [ ] **Other:** _describe_

---

## 6. What Went Well

> _Acknowledge what worked. This reinforces good practices._

- [ ] Cluster failover worked as designed — workload moved to healthy node within X seconds
- [ ] Monitoring detected the event within X minutes
- [ ] On-call responded within X minutes of page
- [ ] AG data integrity preserved (zero data loss on sync-commit replicas)
- [ ] Communication to stakeholders was timely and clear
- [ ] _Other:_

---

## 7. What Went Wrong

> _Focus on process/system gaps, not individual actions._

- [ ] Event 153/129 errors were occurring for X hours/days before the eviction but were not alerted on
- [ ] Monitoring lacked correlation between disk events and cluster health
- [ ] Disk replacement process took X hours due to [spare availability / vendor SLA / approval process]
- [ ] Runbook did not cover this specific failure mode
- [ ] Node re-join after disk replacement required manual steps not documented
- [ ] _Other:_

---

## 8. Action Items

### 8.1 — Immediate (Within 48 Hours)

| # | Action | Owner | Status | Ticket |
|---|---|---|---|---|
| I-1 | Replace failed disk / verify RAID rebuild complete | | ☐ Open | |
| I-2 | Verify SMART health on all disks in affected node | | ☐ Open | |
| I-3 | Run `chkdsk /R` or storage vendor diagnostics on affected volumes | | ☐ Open | |
| I-4 | Verify node has re-joined cluster and AG replicas are `SYNCHRONIZED` | | ☐ Open | |
| I-5 | Review Event 153/129 on ALL other cluster nodes (proactive scan) | | ☐ Open | |

### 8.2 — Short-Term (Within 2 Weeks)

| # | Action | Owner | Status | Ticket |
|---|---|---|---|---|
| S-1 | Create monitoring alert: Event 153 count > 5 in 1 hour → P2 page | | ☐ Open | |
| S-2 | Create monitoring alert: Event 129 count > 1 in 1 hour → P1 page | | ☐ Open | |
| S-3 | Create monitoring alert: Avg disk latency > 50 ms for 5 min → P2 | | ☐ Open | |
| S-4 | Audit and update disk/controller/HBA firmware on all cluster nodes | | ☐ Open | |
| S-5 | Audit and update storahci/storport/HBA drivers on all cluster nodes | | ☐ Open | |
| S-6 | Validate MPIO configuration (active paths, failover policy, DSM version) | | ☐ Open | |
| S-7 | Document disk error response runbook (Event 153/129 → escalation → replacement) | | ☐ Open | |

### 8.3 — Medium-Term (Within 30 Days)

| # | Action | Owner | Status | Ticket |
|---|---|---|---|---|
| M-1 | Tune `TimeoutValue` registry key per storage vendor recommendation across all nodes | | ☐ Open | |
| M-2 | Review and tune cluster `SameSubnetThreshold` / `CrossSubnetThreshold` to tolerate transient I/O stalls | | ☐ Open | |
| M-3 | Implement predictive disk failure alerting via SMART / storage vendor API (Dell OMSA, HPE ILO, etc.) | | ☐ Open | |
| M-4 | Establish disk/controller firmware patch cadence (quarterly) | | ☐ Open | |
| M-5 | Run chaos engineering test S-1 (disk I/O saturation) from ChaosEngineering-9NodeWSFC.md to validate detection | | ☐ Open | |

### 8.4 — Long-Term (Within 90 Days)

| # | Action | Owner | Status | Ticket |
|---|---|---|---|---|
| L-1 | Evaluate Storage Spaces Direct (S2D) or SAN refresh for end-of-life hardware | | ☐ Open | |
| L-2 | Implement automated disk health scoring dashboard (SMART + Event 153/129 trend) | | ☐ Open | |
| L-3 | Add storage fault injection to quarterly chaos engineering test cycle | | ☐ Open | |
| L-4 | Evaluate NVMe migration for latency-sensitive workloads | | ☐ Open | |

---

## 9. Detection & Response Metrics

| Metric | Value | Target | Met? |
|---|---|---|---|
| **Time to Detect (TTD)** — first disk error → alert fired | | < 5 min | |
| **Time to Engage (TTE)** — alert fired → engineer on bridge | | < 15 min | |
| **Time to Diagnose (TTDx)** — engineer engaged → root cause identified | | < 30 min | |
| **Time to Mitigate (TTM)** — root cause identified → impact mitigated | | < 60 min | |
| **Time to Recover (TTR)** — mitigation → full steady state | | < 4 h | |
| **Total incident duration** | | | |
| **Client-facing downtime** | | < SLA | |

---

## 10. Diagnostic Commands Reference

> _Commands used (or that should have been used) during the incident._

```powershell
# ─── DISK ERROR FORENSICS ───

# Count Event 153 / 129 in the last 7 days
Get-WinEvent -FilterHashtable @{LogName='System'; Id=153; StartTime=(Get-Date).AddDays(-7)} |
    Group-Object {$_.TimeCreated.ToString('yyyy-MM-dd HH:00')} |
    Sort-Object Name | Select Name, Count

Get-WinEvent -FilterHashtable @{LogName='System'; Id=129; StartTime=(Get-Date).AddDays(-7)} |
    Group-Object {$_.TimeCreated.ToString('yyyy-MM-dd HH:00')} |
    Sort-Object Name | Select Name, Count

# Full disk error event dump (129, 153, 11, 15, 51)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=129,153,11,15,51;
    StartTime=(Get-Date).AddDays(-7)} |
    Select TimeCreated, Id, LevelDisplayName, Message |
    Sort-Object TimeCreated | Format-Table -Wrap -AutoSize

# Check disk timeout registry value
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Disk' -Name TimeoutValue

# Physical disk health (Storage Spaces / S2D)
Get-PhysicalDisk | Select FriendlyName, MediaType, HealthStatus, OperationalStatus, Size,
    @{N='Wear';E={$_.Wear}} | Format-Table

# SMART data via CIM (requires manufacturer support)
Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSStorageDriver_FailurePredictStatus' |
    Select InstanceName, PredictFailure, Reason

# Disk latency (perfmon snapshot)
Get-Counter @(
    '\PhysicalDisk(*)\Avg. Disk sec/Read',
    '\PhysicalDisk(*)\Avg. Disk sec/Write',
    '\PhysicalDisk(*)\Current Disk Queue Length',
    '\PhysicalDisk(*)\Disk Transfers/sec'
) -SampleInterval 5 -MaxSamples 12

# MPIO path status
Get-MSDSMSupportedHW
mpclaim -s -d  # Show all multipath disks and path states

# ─── CLUSTER FORENSICS ───

# Node eviction events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-FailoverClustering/Operational';
    Id=1135,1177; StartTime=(Get-Date).AddDays(-7)} |
    Select TimeCreated, Id, Message | Format-Table -Wrap

# Cluster log (detailed — generates per-node log)
Get-ClusterLog -Destination C:\PostmortemLogs -TimeSpan 60 -UseLocalTime

# Current cluster & AG state
Get-ClusterNode | Select Name, State, StatusInformation, DynamicWeight
Get-ClusterQuorum | Select QuorumResource, QuorumType

# AG replica health
Invoke-Sqlcmd -Query "
SELECT
    ar.replica_server_name,
    ars.role_desc,
    ars.synchronization_health_desc,
    ars.connected_state_desc,
    drs.log_send_queue_size AS log_send_KB,
    drs.redo_queue_size AS redo_KB,
    drs.last_hardened_time,
    drs.last_redone_time
FROM sys.dm_hadr_availability_replica_states ars
JOIN sys.availability_replicas ar ON ars.replica_id = ar.replica_id
LEFT JOIN sys.dm_hadr_database_replica_states drs ON ars.replica_id = drs.replica_id
ORDER BY ar.replica_server_name;
"

# ─── HARDWARE VENDOR TOOLS ───
# Dell:    racadm storage get pdisks -o  (via iDRAC)
# HPE:    ssacli ctrl all show config detail  (SmartArray)
# Lenovo:  storcli /cX/eY/sZ show all  (MegaRAID)
```

---

## 11. Event ID 153/129 — Quick Decision Tree

```
                    Event 153 detected
                          │
                    ┌──────┴──────┐
                    │ Count in    │
                    │ last hour?  │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
          1–5 events   6–20 events   > 20 events
              │            │            │
         🟡 Monitor    🟠 Investigate  🔴 Escalate
         Log ticket    Check SMART     Page on-call
              │        Check paths     Prepare failover
              │            │            │
              │       Event 129?  ──── YES ──→ 🔴 Imminent
              │         NO │                    node loss
              │            │                    │
              │       Continue                Drain node
              │       monitoring              Replace disk
              │            │                    │
              └────────────┼────────────────────┘
                           │
                    Verify steady state
                    Update CMDB
                    Close ticket
```

---

## 12. Approval & Sign-Off

| Role | Name | Date | Signature |
|---|---|---|---|
| Postmortem Author | | | |
| Incident Commander | | | |
| Infrastructure Lead | | | |
| Application/DBA Lead | | | |
| Change Advisory Board | | | |

---

## 13. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | | | Initial postmortem |
| | | | |

---

> **Blameless principles applied in this document:**
> - Focus on system design, process gaps, and tooling — not individual actions
> - "What can we improve?" not "Who made a mistake?"
> - Every finding maps to a concrete, trackable action item
> - Detection gaps are treated as system bugs, not human failures

*Template generated — March 2026*
