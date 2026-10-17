# Arbiter (`arbiter-rs`) — System Architecture & Protocol Specification

This document details the internal architecture of `arbiter-rs`, focusing on how it unifies resource allocation, multi-cluster federation, and high-availability stateful consensus/fencing ("Consensus-as-a-Service" / `CaaS`) without the wire amplification or passive TTL delays of traditional two-cluster stacks.

---

## 1. The Dual-Cluster Pathology in Traditional Stateful HA

In conventional production deployments (such as `PostgreSQL` + `Patroni` + `etcd`, `Redis Sentinel`, or `Kubernetes` `Lease` controllers backed by `etcd`), running a stateful replicated service requires maintaining **two independent distributed consensus/replication planes**:

1. **External Consensus Plane (`etcd` / `Consul` / `ZooKeeper`)**:
   - Exchanges continuous $O(N)$ or $O(N^2)$ Raft/Paxos peer heartbeats (`MsgHeartbeat` / `MsgHeartbeatResp` over TCP + TLS 1.3 + HTTP/2 gRPC).
   - Receives periodic client `LeaseKeepAlive` RPCs from every stateful sidecar across the fleet.
   - Maintains open HTTP/2 `Watch` streams to all $N$ sidecars on `/service/<cluster>/leader`.
2. **Data-Plane Replication (`PostgreSQL` `walsender`/`walreceiver`, `Redis` `PSYNC2`, `Kafka` ISR)**:
   - Exchanges its own continuous replication keep-alive frames (`CopyData` `k`/`r` messages) and node health checks.

When the node hosting the active database Primary (and potentially a co-located `etcd` leader) crashes or experiences an asymmetric network partition:
- The external consensus cluster must first detect leader loss, execute a Raft `PreVote`/`Vote` round, re-establish client gRPC streams, and **wait out the passive client lease TTL** before any standby is permitted to promote.
- When the lease finally expires, `etcd` broadcasts a `Watch` notification to all $N - 1$ surviving sidecars simultaneously, triggering a **thundering-herd Compare-And-Swap (`Txn` CAS) storm** where all standbys race to write `/service/<cluster>/leader`.

---

## 2. The Unified `arbiter-rs` CaaS Architecture

`arbiter-rs` collapses cluster orchestration, liveness detection, lease management, and STONITH fencing into a single protocol-aware control plane (`arbiter-store::election`, `arbiter-store::ha_generic`, `arbiter-agent::caas`):

### 2.1 Single-Wire Multiplexed QUIC Heartbeats
- Every physical or virtual host runs a single `arbiter-agent` supervisor connected to `arbiter-master` over a multiplexed QUIC connection (`arbiter-net::quic`).
- A single periodic `MultiplexedAgentHeartbeat` frame carries the health status of **all** co-located tasks on that host (`healthy_tasks`) and returns renewed `LeaseGrant`s in one compact `rkyv` binary frame.

### 2.2 Zero-Packet Local `AgentCaasLeaseCache` Verification
- Stateful workloads (`PostgreSQL`, `Redis`/`Valkey`, `Kafka`) verify primary leadership and monotonic [`FencingToken`](crates/arbiter-core/src/ids.rs) validity before committing transactions by reading their local Agent's `AgentCaasLeaseCache` over a host-local Unix Domain Socket (`/var/run/arbiter/caas.sock`) or Windows Named Pipe.
- Because the local cache is updated in-band by the Agent's multiplexed heartbeat and invalidated immediately upon local process exit or watchdog expiration, primary verification emits **zero network packets (`0 B` on the wire)**.

### 2.3 Three-Tier Deterministic STONITH Fencing (`FenceVerificationReceipt`)
To address Jepsen-style criticisms regarding unreachable agents or asymmetric network partitions, `arbiter-rs` implements a strict 3-tier fencing hierarchy (`crates/arbiter-store/src/ha_generic.rs`):

```text
+-----------------------------------------------------------------------------+
|                    ARBITER 3-TIER DETERMINISTIC FENCING                     |
+------+----------------------------------+-----------------------------------+
| Tier | Fault Condition                  | Isolation Proof & Mechanism       |
+------+----------------------------------+-----------------------------------+
|  T1  | Process crash (`SIGKILL`), OOM,  | `InBandAgentStonith`:             |
|      | or WAN jitter where local        | Agent synchronously executes      |
|      | `arbiter-agent` is reachable.    | `kill(SIGKILL)` + `zfs unmount`   |
|      |                                  | + VNIC/VNET/eBPF drop in 1 RTT.   |
+------+----------------------------------+-----------------------------------+
|  T2  | Hard node power-off, kernel      | `OutOfBandHardwareOrStorageFence`:|
|      | panic, or asymmetric `iptables`  | Executes IPMI/Redfish BMC chassis |
|      | blackhole (`agent` unreachable). | power-off + SCSI-3 PR / NVMe-oF   |
|      |                                  | storage key preemption + ToR      |
|      |                                  | switch port shutdown.             |
+------+----------------------------------+-----------------------------------+
|  T3  | Total in-band + OOB partition    | `LocalCaasWatchdogSelfFence`:     |
|      | or `SIGSTOP` kernel/VM freeze.   | Local `CLOCK_MONOTONIC_RAW` /     |
|      |                                  | `/dev/watchdog` deadline revokes  |
|      |                                  | local UDS lease cache & demotes   |
|      |                                  | primary before remote promotion.  |
+------+----------------------------------+-----------------------------------+
```

Once the appropriate `FenceVerificationReceipt` is verified, `arbiter-master` deterministically selects the surviving standby with the highest replayed `LogSequenceNumber` (`LSN`), issues a single targeted promotion grant with `FencingToken = T + 1` on `TimelineId = L + 1`, and sends targeted re-parenting notifications to the remaining $N - 2$ standbys — **eliminating thundering-herd watch broadcasts and competing CAS races**.

---

## 3. Multi-Cluster Co-Location & Federation (`arbiter-store::federation`, `arbiter-alloc::federation`)

`arbiter-rs` supports three distinct cluster operating modes evaluated in `arbiter-master::bench`:

1. **`SingleMonolithicCluster`**: A single flat control plane across all $N_{	ext{total}}$ nodes. Suffers $O(N_{	ext{total}}^2)$ state-store CAS contention and scheduler lock contention as fleet size scales.
2. **`SiloedIndependentClusters` (No Multiclustering)**: Statically partitioned hardware silos. Suffers high task rejection rates during regional diurnal spikes and high stranded resource fragmentation (`StrandedMillicores`, `StrandedBytes`).
3. **`ArbiterMulticlusterColocatedAndFederated`**:
   - **Physical Co-Location (`LogicalClusterSlice`)**: Multiple logical clusters share physical bare-metal nodes with guaranteed quotas and `HdrfRanker` revocable idle capacity borrowing (`SpotPreemptible`).
   - **Cross-Cluster Overflow Bursting**: Unmet tasks (`burst_task_to_federation`) and atomic multi-host GPU/TPU gangs (`burst_gang_to_federation`) overflow to healthy federated peer clusters (`FederationTopology`).
   - **Regional Disaster Recovery (`failover_election_group`)**: Automatically fences failed regions, increments monotonic `FencingToken`s in standby regions, and converges federated DNS (`<task>.<service>.<role>.<cluster>.<federation>.arbiter.internal`).
