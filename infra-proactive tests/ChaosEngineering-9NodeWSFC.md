# Chaos Engineering Test Plan — 9-Node Multi-Site WSFC with SQL Server AG

> **Environment:** Production (controlled faults only; all tests have automated rollback)  
> **OS:** Windows Server 2019  
> **Cluster:** 9-node Windows Server Failover Cluster + SQL Server Availability Group  
> **Topology:** 3 sites × 3 nodes — Site-A (Primary), Site-B (Sync), Site-C (Async)  
> **WAN:** MPLS dedicated links between all 3 sites  
> **Quorum:** Node Majority + File Share Witness on a 4th site / Azure VM

---

## 1. Cluster Topology

```
                        ┌──────────────────────┐
                        │   File Share Witness  │
                        │   (4th site / Azure)  │
                        │      1 vote           │
                        └──────────┬───────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
   MPLS Link (~5 ms)          MPLS Link                 MPLS Link (~25 ms)
        │                          │                          │
┌───────┴────────┐     ┌──────────┴──────────┐     ┌─────────┴───────┐
│    SITE-A      │     │      SITE-B         │     │     SITE-C      │
│   (Primary)    │     │   (Sync-Commit)     │     │  (Async-Commit) │
│                │     │                     │     │                 │
│  SA-SQL-01 ◄──┼─────┼── SB-SQL-01         │     │  SC-SQL-01      │
│  (Primary)     │     │  (Sync Secondary)   │     │ (Async Second.) │
│  SA-SQL-02    │     │  SB-SQL-02          │     │  SC-SQL-02      │
│  (Sync Second.)│     │  (Sync Secondary)   │     │ (Async Second.) │
│  SA-SQL-03    │     │  SB-SQL-03          │     │  SC-SQL-03      │
│  (Sync Second.)│     │  (Sync Secondary)   │     │ (Async Second.) │
│                │     │                     │     │                 │
│  Subnet:       │     │  Subnet:            │     │  Subnet:        │
│  10.10.0.0/24  │     │  10.20.0.0/24       │     │  10.30.0.0/24   │
└────────────────┘     └─────────────────────┘     └─────────────────┘
     3 nodes                  3 nodes                    3 nodes
     3 votes                  3 votes                    3 votes

Total quorum votes: 9 nodes + 1 FSW = 10 → Majority = 6
```

### Node Inventory

| Node | Site | Role | Commit Mode | Subnet |
|---|---|---|---|---|
| SA-SQL-01 | Site-A | **AG Primary** | — | 10.10.0.0/24 |
| SA-SQL-02 | Site-A | Sync Secondary | Synchronous | 10.10.0.0/24 |
| SA-SQL-03 | Site-A | Sync Secondary | Synchronous | 10.10.0.0/24 |
| SB-SQL-01 | Site-B | Sync Secondary | Synchronous | 10.20.0.0/24 |
| SB-SQL-02 | Site-B | Sync Secondary | Synchronous | 10.20.0.0/24 |
| SB-SQL-03 | Site-B | Sync Secondary | Synchronous | 10.20.0.0/24 |
| SC-SQL-01 | Site-C | Async Secondary | Asynchronous | 10.30.0.0/24 |
| SC-SQL-02 | Site-C | Async Secondary | Asynchronous | 10.30.0.0/24 |
| SC-SQL-03 | Site-C | Async Secondary | Asynchronous | 10.30.0.0/24 |

### AG Listener — Multi-Subnet Configuration

```
Listener: ag-listener.contoso.com
  ├── VIP 10.10.0.100 (Site-A subnet — active when primary in Site-A)
  ├── VIP 10.20.0.100 (Site-B subnet — active when primary in Site-B)
  └── VIP 10.30.0.100 (Site-C subnet — active when primary in Site-C)
DNS TTL: 300 s (RegisterAllProvidersIP = 0 for multi-subnet)
```

---

## 2. Steady-State Hypothesis

Before injecting any fault, **all** of the following must hold. Re-verify after every rollback.

| # | Metric | Expected Steady State | Command / Query |
|---|---|---|---|
| SS-1 | Cluster nodes | All 9 nodes `Up` | `Get-ClusterNode` |
| SS-2 | Quorum | 10/10 votes present, majority healthy | `Get-ClusterQuorum` |
| SS-3 | FSW reachable | Witness share accessible | `Test-Path \\fsw-server\witness$` |
| SS-4 | AG primary location | SA-SQL-01 = PRIMARY | `sys.dm_hadr_availability_replica_states` |
| SS-5 | Site-A + Site-B replicas | `SYNCHRONIZED` | Same DMV |
| SS-6 | Site-C replicas | `SYNCHRONIZING` (async) | Same DMV |
| SS-7 | Redo queue (sync) | < 500 KB | `redo_queue_size` in DMV |
| SS-8 | Log send queue (async) | < 50 MB | `log_send_queue_size` in DMV |
| SS-9 | Listener DNS | Resolves to Site-A VIP within 2 s | `Resolve-DnsName ag-listener` |
| SS-10 | Cross-site latency | A↔B < 10 ms, A↔C < 30 ms | `Test-NetConnection` / `ping` |
| SS-11 | MPLS links | All 3 inter-site links UP | Network monitoring / `tracert` |
| SS-12 | Client R/W latency | P99 < workload threshold | App-level metrics |
| SS-13 | Event logs clean | No Critical/Error cluster events in 15 min | `Get-WinEvent` (FailoverClustering) |

---

## 3. Fault Injection Matrix

### 3.1 — Node-Level Faults

| ID | Fault | Target | Method | Blast Radius | Rollback |
|---|---|---|---|---|---|
| **N-1** | Graceful single-node drain | 1 Site-A secondary | `Suspend-ClusterNode -Drain` | 1 node, no failover | `Resume-ClusterNode` |
| **N-2** | Graceful single-node drain | 1 Site-B secondary | `Suspend-ClusterNode -Drain` | 1 cross-site sync replica | `Resume-ClusterNode` |
| **N-3** | Cluster service crash | 1 Site-C node | `Stop-Service ClusSvc -Force` | 1 async replica leaves cluster | `Start-Service ClusSvc` |
| **N-4** | Primary node drain | SA-SQL-01 | `Suspend-ClusterNode -Drain` | **Intra-site AG failover** to SA-02/03 | Resume + failback |
| **N-5** | Two-node drain (same site) | 2 Site-B secondaries | Drain SB-SQL-02 + SB-SQL-03 | Site-B reduced to 1 sync replica | Resume both |
| **N-6** | Two-node drain (cross-site) | 1 Site-A secondary + 1 Site-B secondary | Drain both | 2 sync replicas lost | Resume both |

> **Safety gate (10-vote quorum):** Never take more than 4 voters offline (need ≥ 6 for majority). Since FSW = 1 vote, max node failures = 4 while FSW is healthy.

---

### 3.2 — WAN / Inter-Site Network Faults ⭐ (Multi-Site Specific)

| ID | Fault | Target Link | Method | Blast Radius | Rollback |
|---|---|---|---|---|---|
| **WAN-1** | Latency injection (100 ms added) | Site-A ↔ Site-B | `clumsy` or Windows QoS policy on Site-A gateway NIC | Sync-commit latency spike → commit slowdown | Remove QoS policy |
| **WAN-2** | Latency injection (200 ms added) | Site-A ↔ Site-C | QoS policy on Site-A gateway NIC for 10.30.0.0/24 | Async queue growth | Remove QoS policy |
| **WAN-3** | Packet loss 5% | Site-A ↔ Site-B | `clumsy` on Site-A nodes targeting 10.20.0.0/24 | Sync replica retransmits, potential SYNCHRONIZED → NOT_SYNCHRONIZING | Remove `clumsy` |
| **WAN-4** | Packet loss 15% | Site-A ↔ Site-C | `clumsy` on Site-A nodes targeting 10.30.0.0/24 | Async log send queue growth | Remove `clumsy` |
| **WAN-5** | **Complete Site-A↔Site-B link failure** | Site-A ↔ Site-B MPLS | Firewall DROP all traffic to 10.20.0.0/24 on all 3 Site-A nodes | Site-B replicas = NOT_SYNCHRONIZING; 3 Site-B votes lost from Site-A perspective | Remove firewall rules |
| **WAN-6** | **Complete Site-A↔Site-C link failure** | Site-A ↔ Site-C MPLS | Firewall DROP all traffic to 10.30.0.0/24 on all 3 Site-A nodes | Site-C replicas disconnected; 3 Site-C votes lost | Remove firewall rules |
| **WAN-7** | **Dual WAN failure** (Site-B + Site-C isolated) | Site-A ↔ Site-B **and** Site-A ↔ Site-C | Firewall rules on Site-A blocking both subnets | Site-A (3 nodes) + FSW (1) = 4 votes → **quorum lost if FSW unreachable from Site-A** | Remove firewall rules |
| **WAN-8** | MPLS brownout (high jitter) | All inter-site links | QoS policies adding 10–100 ms random jitter | Cluster heartbeat instability, potential false failovers | Remove QoS policies |
| **WAN-9** | DNS resolution failure for AG listener | Cross-site DNS | Flush DNS + hosts file poison on Site-B app servers | Site-B apps cannot reach listener | Revert hosts file |

> ⚠️ **WAN-7 is the highest-risk network test.** Only execute after WAN-5 and WAN-6 succeed individually.

---

### 3.3 — Full Site Failure ⭐ (Multi-Site Specific)

| ID | Fault | Target | Method | Blast Radius | Rollback |
|---|---|---|---|---|---|
| **SITE-1** | **Site-C loss** (async DR) | All 3 Site-C nodes | Drain all 3 Site-C nodes simultaneously | 3 async replicas offline; quorum = 7/10 ✅ | Resume all 3 |
| **SITE-2** | **Site-B loss** (sync secondary) | All 3 Site-B nodes | Drain all 3 Site-B nodes simultaneously | 3 sync replicas offline; quorum = 7/10 ✅; primary stays in Site-A | Resume all 3 |
| **SITE-3** | **Site-A loss** (primary site) | All 3 Site-A nodes | Drain all 3 Site-A nodes | **AG primary lost** → must failover to Site-B (sync) or Site-C (async); quorum = 7/10 ✅ | Resume all 3 + failback |
| **SITE-4** | **Site-A loss + FSW unreachable** | 3 Site-A nodes + FSW path | Drain Site-A nodes + block FSW | Quorum = 6 Site-B+Site-C nodes / 10 votes = 6 ✅ (barely) | Resume + restore FSW |
| **SITE-5** | **Two-site loss** (Site-A + Site-C) | 6 nodes total | ⛔ **DO NOT EXECUTE IN PRODUCTION** | Quorum lost (Site-B 3 votes + FSW 1 = 4 < 6) | — |

> **SITE-5** is documented for awareness only. Losing 2 of 3 sites in a 3-3-3 topology **will** lose quorum. This is an accepted limitation validated by the test plan.

---

### 3.4 — Quorum & Witness Faults ⭐ (Multi-Site Specific)

| ID | Fault | Target | Method | Blast Radius | Rollback |
|---|---|---|---|---|---|
| **Q-1** | File Share Witness unreachable | FSW server/share | Block SMB port 445 from all nodes to FSW | Quorum recalculates to 9 votes; majority = 5 | Unblock port |
| **Q-2** | FSW loss + 1 node loss | FSW + 1 Site-C node | Block FSW + drain SC-SQL-01 | Quorum = 8 votes, 8 nodes up = OK | Restore both |
| **Q-3** | FSW loss + full Site-C loss | FSW + 3 Site-C nodes | Block FSW + drain all Site-C | Quorum = 6 votes needed, 6 Site-A+Site-B nodes = **exactly at boundary** ✅ | Restore all |
| **Q-4** | FSW loss + 1 additional node beyond Q-3 | FSW + Site-C + 1 Site-B node | ⛔ **DO NOT EXECUTE** | Would lose quorum (5 of 9 < ⌈9/2⌉+1=5... borderline) | — |
| **Q-5** | Dynamic quorum behavior | Kill ClusSvc on 2 nodes rapidly | Observe Windows dynamic quorum adjusting votes | 2 nodes lose vote | Restart ClusSvc |

---

### 3.5 — Cross-Site AG Failover Faults ⭐ (Multi-Site Specific)

| ID | Fault | Target | Method | Blast Radius | Rollback |
|---|---|---|---|---|---|
| **XF-1** | Planned cross-site failover to Site-B | AG primary → SB-SQL-01 | `ALTER AG … FAILOVER` to SB-SQL-01 | Primary moves to Site-B; listener VIP switches to 10.20.0.100 | Failback to Site-A |
| **XF-2** | Forced failover to Site-C (async) | AG primary → SC-SQL-01 | `ALTER AG … FORCE_FAILOVER_ALLOW_DATA_LOSS` | **Data loss window**; listener VIP → 10.30.0.100 | Reseed + failback |
| **XF-3** | Primary crash → auto failover to Site-A peer | `Stop-Service MSSQLSERVER` on SA-SQL-01 | AG auto-failover within Site-A site | Intra-site failover (fast, no cross-site) | Restart SQL + failback |
| **XF-4** | Primary crash + all Site-A down → Site-B takes over | Stop SQL on all 3 Site-A nodes | Simulate full Site-A SQL outage | **Cross-site failover to Site-B**; observe listener TTL / DNS propagation | Restart Site-A SQL + failback |
| **XF-5** | Measure listener DNS propagation | After XF-1 or XF-4 | `Resolve-DnsName` from all 3 sites repeatedly | Measures multi-subnet listener convergence time | — |
| **XF-6** | Application reconnection after cross-site failover | After XF-1 | Monitor app connection pools from all sites | Measures real client-perceived downtime | — |

---

### 3.6 — Node-Local Network Faults

| ID | Fault | Target | Method | Blast Radius | Rollback |
|---|---|---|---|---|---|
| **NET-1** | Single-node firewall isolation | 1 Site-B secondary | `netsh advfirewall` block ports 3343,1433,5022 | 1 node network partition | Remove rules |
| **NET-2** | AG mirroring port blocked | 1 Site-A secondary (port 5022) | `netsh` firewall rule | Replication stops for 1 replica | Remove rule |
| **NET-3** | Cluster heartbeat port blocked | 1 Site-C node (port 3343) | `netsh` firewall rule | Node marked `Down` by cluster after timeout | Remove rule |

---

### 3.7 — Storage / Disk Faults

| ID | Fault | Target | Method | Blast Radius | Rollback |
|---|---|---|---|---|---|
| **S-1** | Data drive I/O saturation | 1 Site-B secondary | `diskspd -w100 -b64K -d120 -t4` on data drive | Redo queue growth on 1 sync replica | Kill `diskspd` |
| **S-2** | TempDB volume full | 1 Site-A secondary | Fill tempdb drive to 95% | TempDB queries fail on 1 node | Delete dummy file |
| **S-3** | Log drive latency spike | 1 Site-C secondary | `diskspd` random I/O on log drive | Async log replay slows | Kill `diskspd` |

> **Production constraint:** Storage faults target **secondaries only**.

---

### 3.8 — SQL Server AG-Specific Faults

| ID | Fault | Target | Method | Blast Radius | Rollback |
|---|---|---|---|---|---|
| **AG-1** | Suspend data movement (sync) | 1 Site-B secondary | `ALTER DATABASE … SET HADR SUSPEND` | 1 sync replica falls behind | `SET HADR RESUME` |
| **AG-2** | Suspend data movement (async) | 1 Site-C secondary | `ALTER DATABASE … SET HADR SUSPEND` | 1 async replica falls behind | `SET HADR RESUME` |
| **AG-3** | Connection flood on listener | Site-A listener VIP | `sqlcmd` loop, 5000 concurrent connections | Connection pool exhaustion | Kill test process |
| **AG-4** | Long-running transaction | SA-SQL-01 primary | `BEGIN TRAN; WAITFOR DELAY '00:05:00'` | Lock contention + redo queue growth on all replicas | `KILL <spid>` |
| **AG-5** | Seeding operation during production | Add temp replica | `ALTER AG … ADD REPLICA` triggering automatic seeding | Bandwidth contention on MPLS links | Remove replica |

---

### 3.9 — Resource Exhaustion

| ID | Fault | Target | Method | Blast Radius | Rollback |
|---|---|---|---|---|---|
| **R-1** | CPU saturation (95%) | 1 Site-A secondary | PowerShell busy loop | 1 node CPU; redo thread starved | Kill process |
| **R-2** | Memory pressure | 1 Site-B secondary | Allocate large memory block | Buffer pool eviction on 1 node | Kill process |
| **R-3** | Worker thread exhaustion | SA-SQL-01 primary | `sp_configure 'max worker threads'` low + load | Scheduler contention; commit latency spike on all sites | Restore config |

---

## 4. Test Execution Protocol

```
┌────────────────────────────────────────────────────────────────────┐
│  PHASE 1: PRE-FLIGHT                                               │
│  • Verify ALL steady-state metrics (Section 2, SS-1 through SS-13)│
│  • Confirm MPLS link health from network team                      │
│  • Verify FSW is reachable from all 3 sites                       │
│  • Test rollback mechanism in isolation first                      │
│  • Notify on-call at ALL 3 sites + network ops                    │
│  • Open incident bridge (precautionary)                            │
│  • Confirm change management window is active                      │
├────────────────────────────────────────────────────────────────────┤
│  PHASE 2: INJECT                                                   │
│  • Execute ONE fault from the matrix                               │
│  • Start stopwatch                                                 │
│  • Monitor from a node NOT in the blast radius                     │
│  • Stream: cluster events, AG DMVs, MPLS link stats, app errors   │
├────────────────────────────────────────────────────────────────────┤
│  PHASE 3: OBSERVE (max duration per test category)                 │
│  • Node/Storage/Resource faults: 10 min                            │
│  • WAN faults: 15 min (allow for heartbeat timeouts)               │
│  • Site-level faults: 20 min (cross-site failover + DNS)           │
│  • Record: detection time, failover time, DNS propagation, data    │
│    loss, redo queue peak, client error rate                        │
│  • Capture logs from ALL 3 sites + FSW                             │
├────────────────────────────────────────────────────────────────────┤
│  PHASE 4: ROLLBACK                                                 │
│  • Execute rollback action from matrix                             │
│  • Wait for AG to re-synchronize across all sites                  │
│  • Re-verify ALL steady-state metrics                              │
│  • Confirm redo_queue_size returns to < 500 KB (sync)              │
│  • Wait 10 min cool-down before next test                          │
├────────────────────────────────────────────────────────────────────┤
│  PHASE 5: ABORT CRITERIA (stop ALL testing immediately if):        │
│  • Quorum lost (< 6 votes of 10)                                  │
│  • AG primary has no synchronized replica in ANY site              │
│  • MPLS link failure not caused by test injection                  │
│  • App error rate > 5% for > 3 min                                │
│  • Any unexpected data loss detected                               │
│  • Rollback fails or takes > 15 min                                │
│  • Real production incident declared                               │
└────────────────────────────────────────────────────────────────────┘
```

---

## 5. Observability Checklist

Capture from **all 3 sites** during every test:

```powershell
# ─── Run from each site's monitoring node ───

# Cluster health (all sites)
Get-ClusterNode | Select Name, State, StatusInformation, Site
Get-ClusterGroup | Select Name, OwnerNode, State
Get-ClusterQuorum | Select QuorumResource, QuorumType
Get-ClusterLog -Destination C:\ChaosLogs -TimeSpan 20

# AG health — cross-site replica states
Invoke-Sqlcmd -Query "
SELECT
    ar.replica_server_name,
    ars.role_desc,
    ars.synchronization_health_desc,
    ar.availability_mode_desc,          -- SYNCHRONOUS vs ASYNCHRONOUS
    ars.connected_state_desc,
    ars.last_hardened_lsn,
    drs.log_send_queue_size,            -- KB pending send
    drs.redo_queue_size,                -- KB pending redo
    drs.last_hardened_time,
    drs.last_redone_time,
    DATEDIFF(SECOND, drs.last_hardened_time, GETDATE()) AS seconds_behind
FROM sys.dm_hadr_availability_replica_states ars
JOIN sys.availability_replicas ar ON ars.replica_id = ar.replica_id
LEFT JOIN sys.dm_hadr_database_replica_states drs ON ars.replica_id = drs.replica_id
ORDER BY ar.replica_server_name;
"

# Cross-site network latency (run from Site-A)
@('10.20.0.1','10.30.0.1') | ForEach-Object {
    Test-NetConnection $_ -Port 1433 | Select ComputerName, TcpTestSucceeded,
    @{N='LatencyMs';E={$_.PingReplyDetails.RoundtripTime}}
}

# Multi-subnet listener resolution (run from each site)
Resolve-DnsName ag-listener.contoso.com | Select Name, IPAddress, TTL

# Perfmon — cross-site replication specific
Get-Counter @(
    '\SQLServer:Availability Replica(*)\Bytes Sent to Replica/sec',
    '\SQLServer:Availability Replica(*)\Bytes Received from Replica/sec',
    '\SQLServer:Database Replica(*)\Redo Bytes Remaining',
    '\SQLServer:Database Replica(*)\Transaction Delay',
    '\Network Interface(*)\Bytes Total/sec'
)

# Windows failover cluster events
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-FailoverClustering/Operational'
    Level=1,2,3  # Critical, Error, Warning
    StartTime=(Get-Date).AddMinutes(-20)
} | Select TimeCreated, LevelDisplayName, Message | Format-Table -Wrap

# FSW accessibility check
Test-Path '\\fsw-server\witness$' -ErrorAction SilentlyContinue
```

---

## 6. Recommended Execution Order (Production-Safe)

Run in ascending risk. **Stop entirely** if any abort criterion triggers.

| Phase | Tests | Risk | Notes |
|---|---|---|---|
| **Week 1** — Single-Node Baseline | N-1, N-2, N-3, AG-1, AG-2 | 🟢 Low | 1 replica at a time; no failover expected |
| **Week 2** — Storage & Resources | S-1, S-2, S-3, R-1, R-2 | 🟢 Low | Secondaries only; observe redo queue impact |
| **Week 3** — WAN Degradation | WAN-1, WAN-2, WAN-3, WAN-4 | 🟡 Medium | Latency + packet loss; measure sync→not_sync thresholds |
| **Week 4** — Intra-Site Failover | N-4, XF-3, NET-2, NET-3 | 🟡 Medium | Primary failover within Site-A |
| **Week 5** — Single WAN Link Failure | WAN-5, WAN-6 | 🟠 High | Full link loss; 1 site at a time disconnected |
| **Week 6** — Quorum Stress | Q-1, Q-2, Q-3, Q-5 | 🟠 High | Test quorum boundaries with FSW combinations |
| **Week 7** — Site-Level Failures | SITE-1, SITE-2 | 🟠 High | Full DR site or sync-secondary site loss |
| **Week 8** — Primary Site Failure | SITE-3, SITE-4, XF-4, XF-5, XF-6 | 🔴 Critical | Full Site-A loss → cross-site failover to Site-B |
| **Week 9** — Forced Failover to Async | XF-2, WAN-7 | 🔴 Critical | Site-C forced failover (data loss risk); dual WAN failure |
| **Week 10** — Compound Faults | N-6 + WAN-1, AG-4 + S-1 | 🔴 Critical | Combined faults — never more than 2 simultaneous |

---

## 7. Success Criteria

### 7.1 — Intra-Site Failover (Site-A → Site-A peer)

| Outcome | Pass Threshold |
|---|---|
| AG automatic failover time | ≤ 15 seconds |
| Client reconnection | ≤ 30 seconds |
| Data loss | Zero (sync-commit within site) |

### 7.2 — Cross-Site Failover to Site-B (Sync)

| Outcome | Pass Threshold |
|---|---|
| AG failover time (manual or auto) | ≤ 30 seconds |
| Listener DNS propagation (all sites) | ≤ 120 seconds |
| Client reconnection (Site-B local apps) | ≤ 60 seconds |
| Client reconnection (Site-C remote apps) | ≤ 120 seconds |
| Data loss | Zero (sync-commit) |

### 7.3 — Cross-Site Failover to Site-C (Async — DR)

| Outcome | Pass Threshold |
|---|---|
| Forced failover time | ≤ 60 seconds |
| Listener DNS propagation | ≤ 180 seconds |
| Data loss window | Documented (RPO measured from `log_send_queue_size` at failure) |
| Reseed time back to steady state | Documented, not gated |

### 7.4 — Infrastructure Resilience

| Outcome | Pass Threshold |
|---|---|
| Quorum survives any single-site loss | ✅ (7/10 votes remain) |
| Quorum survives FSW + 3-node loss | ✅ (6/9 remaining = majority) |
| MPLS single-link failure | AG degrades gracefully, no quorum loss |
| Monitoring detects fault | Alert fires within 2 minutes |
| Full steady-state recovery after rollback | ≤ 15 minutes |

---

## 8. Multi-Site-Specific Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Cross-site failover takes > 60 s due to DNS TTL | High | Client outage | Pre-test: verify `RegisterAllProvidersIP = 0` and TTL = 300 s |
| Async failover to Site-C causes data loss | By design | Data loss | Measure RPO; confirm Site-C `log_send_queue_size` before test |
| MPLS brownout causes cluster heartbeat false positive | Medium | Spurious failover | Tune `SameSubnetDelay`, `CrossSubnetDelay`, `CrossSubnetThreshold` |
| FSW on Azure VM unreachable during WAN test | Medium | Quorum risk | Verify FSW connectivity from all 3 sites before WAN tests |
| Dynamic quorum removes vote from recovering node | Low | Delayed re-join | Monitor `Get-ClusterNode` NodeWeight during recovery |
| Split-brain: 2 partitions both think they have quorum | Very Low | Catastrophic | FSW on 4th site prevents this; verify before SITE tests |

---

## 9. Cluster Tuning Parameters to Validate

These settings critically affect multi-site behavior. **Document current values before any test.**

```powershell
# Heartbeat and timeout tuning (cross-subnet)
(Get-Cluster).CrossSubnetDelay          # Default: 1000 ms — time between heartbeats
(Get-Cluster).CrossSubnetThreshold      # Default: 5 — missed heartbeats before marking down
(Get-Cluster).SameSubnetDelay           # Default: 1000 ms
(Get-Cluster).SameSubnetThreshold       # Default: 5
(Get-Cluster).RouteHistoryLength        # Network route tracking

# Quorum
(Get-Cluster).DynamicQuorum             # Should be 1 (enabled)
Get-ClusterQuorum | Select QuorumResource, QuorumType

# AG timeouts
# Check session_timeout per replica (default 10s):
SELECT replica_server_name, session_timeout
FROM sys.availability_replicas;
```

> **Recommendation:** For MPLS-linked sites, consider `CrossSubnetThreshold = 10` to tolerate transient WAN hiccups without spurious failovers.

---
