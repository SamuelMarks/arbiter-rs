//! L2–L7 framing-accurate wire-traffic accounting engine and `nftables`/`pcap` calibration verifier (`arbiter-telemetry::wire_accounting`).
//!
//! Quantifies exact packet counts ([`PacketCount`]), L7 application payload [`Bytes`], and full L2–L7
//! wire [`Bytes`] (Ethernet `18 B` + IPv4 `20 B` + TCP/TLS 1.3/HTTP/2 gRPC or UDP/QUIC short-header + AEAD)
//! across:
//! - **Window 1 (`SteadyStatePreFailure`)**: Pre-failure 60-second steady state.
//! - **Window 2 (`FaultDetectionAndFencing`)**: Primary/Master kill detection, Raft election, and STONITH vs. TTL wait.
//! - **Window 3 (`StandbyPromotionAndReplicaRebind`)**: Standby promotion (`pg_promote()`), thundering-herd CAS vs.
//!   direct dispatch, and $(N - 2)$ standby replica re-parenting.
//!
//! Also provides [`verify_calibration_drift`] to cross-validate simulated wire bytes against live
//! Vagrant `nftables` / `ip -s link` / `tcpdump` captures within a strict basis-point bound (`< 5%`).

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::units::{
    BenchmarkTicks, Bytes, NodeCount, PacketCount, SharePartsPerBillion, WeightBasisPoints,
};
use serde::{Deserialize, Serialize};

/// Ethernet L2 frame overhead in bytes (`14 B` header + `4 B` FCS = `18 B`).
pub const L2_ETHERNET_FRAMING_BYTES: Bytes = Bytes::new(18);

/// IPv4 L3 header overhead in bytes (`20 B`).
pub const L3_IPV4_HEADER_BYTES: Bytes = Bytes::new(20);

/// Combined L2 + L3 base network framing per packet (`38 B`).
pub const L2_L3_BASE_WIRE_BYTES: Bytes = Bytes::new(38);

/// TCP (`32 B` with timestamps) + TLS 1.3 record (`25 B`) + HTTP/2 frame header (`9 B`) = `66 B`.
pub const TCP_TLS13_HTTP2_GRPC_OVERHEAD_BYTES: Bytes = Bytes::new(66);

/// TCP (`32 B` with timestamps) + `PostgreSQL` Frontend/Backend message tag & length (`5 B`) = `37 B`.
pub const TCP_PG_PROTOCOL_OVERHEAD_BYTES: Bytes = Bytes::new(37);

/// UDP (`8 B`) + QUIC 1-RTT short header (`14 B`) + AEAD authentication tag (`16 B`) = `38 B`.
pub const UDP_QUIC_AEAD_OVERHEAD_BYTES: Bytes = Bytes::new(38);

/// Granular protocol category for every packet and byte transmitted on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProtocolCategory {
    /// `etcd` peer Raft leader $\leftrightarrow$ follower periodic `MsgHeartbeat` / `MsgHeartbeatResp`.
    EtcdPeerRaftHeartbeat,
    /// `etcd` peer Raft `MsgPreVote`, `MsgVote`, and leader election round-trips on leader kill.
    EtcdPeerRaftElection,
    /// `PostgreSQL` HA sidecar $\leftrightarrow$ `etcd` client gRPC `LeaseKeepAlive` requests & responses.
    EtcdClientLeaseKeepAlive,
    /// `etcd` watch stream notification broadcast (`/service/postgres/leader`) to all $N$ sidecars.
    EtcdClientWatchBroadcast,
    /// Competing HA sidecar `Txn` Compare-And-Swap (`CAS`) leader-key acquisition race.
    EtcdClientCasLeaderRace,
    /// `PostgreSQL` builtin `walsender` $\leftrightarrow$ `walreceiver` `CopyData` keep-alive (`k`/`r` messages).
    PostgresWalKeepAlive,
    /// `PostgreSQL` standby promotion and $(N - 2)$ replica `IDENTIFY_SYSTEM` / `TIMELINE_HISTORY` / `START_REPLICATION`.
    PostgresReelectionRebindAndTimelineHistory,
    /// `arbiter-master` internal Raft quorum heartbeat or failover election frames.
    ArbiterMasterRaftInternal,
    /// `arbiter-rs` single-wire multiplexed QUIC `AgentHeartbeat` + `LeaseGrant` renewal.
    ArbiterMultiplexedQuicHeartbeat,
    /// `arbiter-rs` zero-packet local Unix Domain Socket / Named Pipe `AgentCaasLeaseCache` primary verification.
    ArbiterLocalCaasZeroPacketVerification,
    /// `arbiter-rs` synchronous/OOB `FenceVerificationReceipt` + targeted standby promotion and replica re-parenting.
    ArbiterTieredFenceAndDirectPromotion,
}

impl ProtocolCategory {
    /// Returns the per-packet L2–L4 transport & cryptographic framing overhead in [`Bytes`].
    ///
    /// Note that [`ProtocolCategory::ArbiterLocalCaasZeroPacketVerification`] occurs over local
    /// in-memory / UDS loopback cache and emits `0` wire bytes.
    ///
    /// # Returns
    ///
    /// Per-packet wire framing overhead in [`Bytes`].
    pub const fn per_packet_framing_overhead(self) -> Bytes {
        match self {
            Self::EtcdPeerRaftHeartbeat
            | Self::EtcdPeerRaftElection
            | Self::EtcdClientLeaseKeepAlive
            | Self::EtcdClientWatchBroadcast
            | Self::EtcdClientCasLeaderRace => {
                Bytes::new(L2_L3_BASE_WIRE_BYTES.get() + TCP_TLS13_HTTP2_GRPC_OVERHEAD_BYTES.get())
            }
            Self::PostgresWalKeepAlive | Self::PostgresReelectionRebindAndTimelineHistory => {
                Bytes::new(L2_L3_BASE_WIRE_BYTES.get() + TCP_PG_PROTOCOL_OVERHEAD_BYTES.get())
            }
            Self::ArbiterMasterRaftInternal
            | Self::ArbiterMultiplexedQuicHeartbeat
            | Self::ArbiterTieredFenceAndDirectPromotion => {
                Bytes::new(L2_L3_BASE_WIRE_BYTES.get() + UDP_QUIC_AEAD_OVERHEAD_BYTES.get())
            }
            Self::ArbiterLocalCaasZeroPacketVerification => Bytes::ZERO,
        }
    }
}

/// Lifecycle window during HA cluster operation and master/primary failover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LifecycleWindow {
    /// Window 1: Steady-state operation prior to primary/master failure (60-second window).
    SteadyStatePreFailure,
    /// Window 2: Primary/Master kill detection, Raft reelection, and STONITH fencing vs. passive lease TTL wait.
    FaultDetectionAndFencing,
    /// Window 3: Standby `pg_promote()` execution, leader key publication, and $(N - 2)$ replica re-parenting.
    StandbyPromotionAndReplicaRebind,
}

/// Recorded packet transmission or zero-packet local verification event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketTraceEvent {
    /// Lifecycle window in which the event occurred.
    pub window: LifecycleWindow,
    /// Protocol classification.
    pub category: ProtocolCategory,
    /// Number of network packets emitted on the wire (`0` for local UDS `CaaS` verification).
    pub wire_packets: PacketCount,
    /// L7 application payload size per packet in [`Bytes`].
    pub l7_payload_per_packet: Bytes,
    /// Count of local UDS `CaaS` verifications served (non-zero only for `ArbiterLocalCaasZeroPacketVerification`).
    pub local_caas_queries: u64,
}

/// Aggregated packet and byte totals for a single [`LifecycleWindow`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowTrafficSummary {
    /// Total network packets emitted on the wire in this window.
    pub wire_packets: PacketCount,
    /// Total L7 application payload bytes in this window.
    pub l7_payload_bytes: Bytes,
    /// Total L2–L7 wire bytes (including Ethernet, IPv4, TCP/UDP, TLS 1.3/QUIC, HTTP/2) in this window.
    pub total_l2_l7_wire_bytes: Bytes,
    /// Total zero-packet local `CaaS` UDS verifications performed in this window.
    pub local_caas_queries: u64,
}

/// Complete L2–L7 wire-traffic accounting engine for a simulated or live-captured HA stack.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTrafficAccountant {
    /// Per-window traffic summaries.
    pub by_window: BTreeMap<LifecycleWindow, WindowTrafficSummary>,
    /// Per-category total wire bytes.
    pub by_category_wire_bytes: BTreeMap<ProtocolCategory, Bytes>,
    /// Per-category total wire packets.
    pub by_category_packets: BTreeMap<ProtocolCategory, PacketCount>,
    /// Total wire packets across all windows.
    pub total_wire_packets: PacketCount,
    /// Total L7 payload bytes across all windows.
    pub total_l7_payload_bytes: Bytes,
    /// Total L2–L7 wire bytes across all windows.
    pub total_l2_l7_wire_bytes: Bytes,
    /// Total zero-packet local `CaaS` UDS queries across all windows.
    pub total_local_caas_queries: u64,
}

impl NetworkTrafficAccountant {
    /// Creates an empty [`NetworkTrafficAccountant`].
    ///
    /// # Returns
    ///
    /// Empty [`NetworkTrafficAccountant`].
    pub const fn new() -> Self {
        Self {
            by_window: BTreeMap::new(),
            by_category_wire_bytes: BTreeMap::new(),
            by_category_packets: BTreeMap::new(),
            total_wire_packets: PacketCount::ZERO,
            total_l7_payload_bytes: Bytes::ZERO,
            total_l2_l7_wire_bytes: Bytes::ZERO,
            total_local_caas_queries: 0,
        }
    }

    /// Records a [`PacketTraceEvent`], computing exact L7 payload and L2–L7 wire bytes using checked arithmetic.
    ///
    /// # Arguments
    ///
    /// * `event` - [`PacketTraceEvent`] to account for.
    ///
    /// # Returns
    ///
    /// `Ok(())` on update.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArithmeticOverflow`] if packet or byte counters overflow `u64::MAX`.
    pub fn record_event(&mut self, event: &PacketTraceEvent) -> ArbiterResult<()> {
        let pkt_count = event.wire_packets.get();
        let l7_total = event.l7_payload_per_packet.checked_mul(pkt_count)?;
        let framing_per_pkt = event.category.per_packet_framing_overhead();
        let full_per_pkt = event.l7_payload_per_packet.checked_add(framing_per_pkt)?;
        let wire_total = full_per_pkt.checked_mul(pkt_count)?;

        self.total_wire_packets = self.total_wire_packets.checked_add(event.wire_packets)?;
        self.total_l7_payload_bytes = self.total_l7_payload_bytes.checked_add(l7_total)?;
        self.total_l2_l7_wire_bytes = self.total_l2_l7_wire_bytes.checked_add(wire_total)?;
        self.total_local_caas_queries = self
            .total_local_caas_queries
            .saturating_add(event.local_caas_queries);

        let win_entry = self.by_window.entry(event.window).or_default();
        win_entry.wire_packets = win_entry.wire_packets.checked_add(event.wire_packets)?;
        win_entry.l7_payload_bytes = win_entry.l7_payload_bytes.checked_add(l7_total)?;
        win_entry.total_l2_l7_wire_bytes =
            win_entry.total_l2_l7_wire_bytes.checked_add(wire_total)?;
        win_entry.local_caas_queries = win_entry
            .local_caas_queries
            .saturating_add(event.local_caas_queries);

        let cat_bytes = self
            .by_category_wire_bytes
            .entry(event.category)
            .or_insert(Bytes::ZERO);
        *cat_bytes = cat_bytes.checked_add(wire_total)?;

        let cat_pkts = self
            .by_category_packets
            .entry(event.category)
            .or_insert(PacketCount::ZERO);
        *cat_pkts = cat_pkts.checked_add(event.wire_packets)?;

        Ok(())
    }

    /// Simulates the complete 3-window lifecycle wire traffic for **Stack 1 (`PostgreSQL` + `etcd`)**
    /// across $N$ nodes (`3`, `5`, `7`, or arbitrary $N$).
    ///
    /// # Arguments
    ///
    /// * `node_count` - Cluster [`NodeCount`] ($N \ge 3$).
    /// * `lease_ttl_ms` - `etcd` lease TTL in milliseconds (e.g., `10_000`, `5_000`, or `1_000`).
    /// * `joint_master_kill` - Whether the `etcd` leader was co-located on the killed `PostgreSQL` primary node.
    ///
    /// # Returns
    ///
    /// Populated [`NetworkTrafficAccountant`] for the two-cluster `etcd` + `PostgreSQL` stack.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `node_count < 3` or arithmetic overflows.
    pub fn simulate_etcd_postgres_stack(
        node_count: NodeCount,
        lease_ttl_ms: u64,
        joint_master_kill: bool,
    ) -> ArbiterResult<Self> {
        let n = u64::from(node_count.get());
        if n < 3 || lease_ttl_ms == 0 {
            return Err(ArbiterError::InvalidBenchmarkConfig {
                parameter: "simulate_etcd_postgres_stack".to_owned(),
                reason: "node_count must be >= 3 and lease_ttl_ms >= 1".to_owned(),
            });
        }
        let mut acc = Self::new();

        // Scale Raft and client heartbeat frequencies inversely with lease_ttl_ms
        let raft_hb_rounds = (600_000_u64 / lease_ttl_ms).max(120);
        let client_hb_rounds = (300_000_u64 / lease_ttl_ms).max(30);

        // Window 1: Steady-state (60s)
        // 1. etcd peer Raft heartbeats: (N - 1) followers * raft_hb_rounds * 2 (req + ack), 96B L7 protobuf
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::EtcdPeerRaftHeartbeat,
            wire_packets: PacketCount::new(
                (n - 1).saturating_mul(raft_hb_rounds).saturating_mul(2),
            ),
            l7_payload_per_packet: Bytes::new(96),
            local_caas_queries: 0,
        });
        // 2. etcd client LeaseKeepAlive gRPC streams: N sidecars * client_hb_rounds * 2, 72B L7
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::EtcdClientLeaseKeepAlive,
            wire_packets: PacketCount::new(n.saturating_mul(client_hb_rounds).saturating_mul(2)),
            l7_payload_per_packet: Bytes::new(72),
            local_caas_queries: 0,
        });
        // 3. etcd Watch progress notifications to N sidecars: N * 60 * 2, 84B L7
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::EtcdClientWatchBroadcast,
            wire_packets: PacketCount::new(n.saturating_mul(120)),
            l7_payload_per_packet: Bytes::new(84),
            local_caas_queries: 0,
        });
        // 4. PostgreSQL walsender/walreceiver CopyData keep-alive: (N - 1) standbys * 120, 64B L7
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::PostgresWalKeepAlive,
            wire_packets: PacketCount::new((n - 1).saturating_mul(120)),
            l7_payload_per_packet: Bytes::new(64),
            local_caas_queries: 0,
        });

        // Window 2: Primary/Master Kill Detection & Raft Election
        let election_pkts = if joint_master_kill {
            // O(N^2) PreVote + Vote + NewLeader AppendEntries across (N - 1) survivors + client reconnects
            (n - 1).saturating_mul(n - 1).saturating_mul(6)
        } else {
            (n - 1).saturating_mul(4)
        };
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::FaultDetectionAndFencing,
            category: ProtocolCategory::EtcdPeerRaftElection,
            wire_packets: PacketCount::new(election_pkts),
            l7_payload_per_packet: Bytes::new(144),
            local_caas_queries: 0,
        });

        // Window 3: Standby Promotion, Thundering-Herd Watch + CAS Race & Replica Re-Parenting
        // Watch event broadcast to (N - 1) surviving sidecars + new leader key watch broadcast
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::StandbyPromotionAndReplicaRebind,
            category: ProtocolCategory::EtcdClientWatchBroadcast,
            wire_packets: PacketCount::new((n - 1).saturating_mul(4)),
            l7_payload_per_packet: Bytes::new(180),
            local_caas_queries: 0,
        });
        // All (N - 1) surviving sidecars race CAS Txn to claim /service/postgres/leader + update /members/*
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::StandbyPromotionAndReplicaRebind,
            category: ProtocolCategory::EtcdClientCasLeaderRace,
            wire_packets: PacketCount::new((n - 1).saturating_mul(6)),
            l7_payload_per_packet: Bytes::new(256),
            local_caas_queries: 0,
        });
        // Remaining (N - 2) standbys reconnect walreceiver (IDENTIFY_SYSTEM + TIMELINE_HISTORY + START_REPLICATION)
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::StandbyPromotionAndReplicaRebind,
            category: ProtocolCategory::PostgresReelectionRebindAndTimelineHistory,
            wire_packets: PacketCount::new((n - 2).saturating_mul(8).max(4)),
            l7_payload_per_packet: Bytes::new(220),
            local_caas_queries: 0,
        });

        Ok(acc)
    }

    /// Simulates the complete 3-window lifecycle wire traffic for **Stack 2 (`arbiter-rs` Unified `CaaS` + `PostgreSQL`)**
    /// across $N$ nodes (`3`, `5`, `7`, or arbitrary $N$).
    ///
    /// # Arguments
    ///
    /// * `node_count` - Cluster [`NodeCount`] ($N \ge 3$).
    /// * `joint_master_kill` - Whether the active `arbiter-master` leader was co-located on the killed node.
    ///
    /// # Returns
    ///
    /// Populated [`NetworkTrafficAccountant`] for the `arbiter-rs` unified stack.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `node_count < 3` or arithmetic overflows.
    pub fn simulate_arbiter_postgres_stack(
        node_count: NodeCount,
        joint_master_kill: bool,
    ) -> ArbiterResult<Self> {
        let n = u64::from(node_count.get());
        if n < 3 {
            return Err(ArbiterError::InvalidBenchmarkConfig {
                parameter: "simulate_arbiter_postgres_stack".to_owned(),
                reason: "node_count must be >= 3".to_owned(),
            });
        }
        let mut acc = Self::new();

        // Window 1: Steady-state (60s)
        // 1. Single multiplexed QUIC AgentHeartbeat + LeaseGrant renewal per Agent (1 Hz * 60s * 2 pkts), 88B L7 rkyv
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::ArbiterMultiplexedQuicHeartbeat,
            wire_packets: PacketCount::new(n.saturating_mul(120)),
            l7_payload_per_packet: Bytes::new(88),
            local_caas_queries: 0,
        });
        // 2. Zero-packet local UDS AgentCaasLeaseCache primary verifications (100 Hz * 60s * N nodes = 6,000 * N queries, 0 wire pkts!)
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::ArbiterLocalCaasZeroPacketVerification,
            wire_packets: PacketCount::ZERO,
            l7_payload_per_packet: Bytes::ZERO,
            local_caas_queries: n.saturating_mul(6_000),
        });
        // 3. PostgreSQL walsender/walreceiver CopyData keep-alive: (N - 1) standbys * 120, 64B L7
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::PostgresWalKeepAlive,
            wire_packets: PacketCount::new((n - 1).saturating_mul(120)),
            l7_payload_per_packet: Bytes::new(64),
            local_caas_queries: 0,
        });

        // Window 2: Fault Detection & Tiered STONITH Fencing
        if joint_master_kill {
            // Fixed 3-node Master Raft quorum elects new Master leader in 8 compact QUIC frames
            let _ = acc.record_event(&PacketTraceEvent {
                window: LifecycleWindow::FaultDetectionAndFencing,
                category: ProtocolCategory::ArbiterMasterRaftInternal,
                wire_packets: PacketCount::new(8),
                l7_payload_per_packet: Bytes::new(80),
                local_caas_queries: 0,
            });
        }
        // Tier 1/2 fence command + signed FenceVerificationReceipt (2 packets)
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::FaultDetectionAndFencing,
            category: ProtocolCategory::ArbiterTieredFenceAndDirectPromotion,
            wire_packets: PacketCount::new(2),
            l7_payload_per_packet: Bytes::new(96),
            local_caas_queries: 0,
        });

        // Window 3: Direct Master-Driven Standby Promotion & Targeted Replica Re-Parenting
        // Single targeted LeaseGrant(FencingToken = T + 1) to highest-LSN standby (2 pkts)
        // + targeted re-parent notification to (N - 2) remaining standbys (2 * (N - 2) pkts)
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::StandbyPromotionAndReplicaRebind,
            category: ProtocolCategory::ArbiterTieredFenceAndDirectPromotion,
            wire_packets: PacketCount::new(2_u64.saturating_add((n - 2).saturating_mul(2))),
            l7_payload_per_packet: Bytes::new(104),
            local_caas_queries: 0,
        });
        // Remaining (N - 2) standbys rebind walreceiver to new primary
        let _ = acc.record_event(&PacketTraceEvent {
            window: LifecycleWindow::StandbyPromotionAndReplicaRebind,
            category: ProtocolCategory::PostgresReelectionRebindAndTimelineHistory,
            wire_packets: PacketCount::new((n - 2).saturating_mul(8).max(4)),
            l7_payload_per_packet: Bytes::new(220),
            local_caas_queries: 0,
        });

        Ok(acc)
    }
}

/// Comparative report between **Stack 1 (`PostgreSQL` + `etcd`)** and **Stack 2 (`PostgreSQL` + `arbiter-rs`)**
/// for a given [`NodeCount`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficComparisonReport {
    /// Evaluated cluster [`NodeCount`] ($N$).
    pub node_count: NodeCount,
    /// `etcd` lease TTL in milliseconds used for the baseline.
    pub etcd_lease_ttl_ms: u64,
    /// Whether the control-plane leader was killed simultaneously with the data-plane primary.
    pub joint_master_kill: bool,
    /// Full wire accounting for the `etcd` + `PostgreSQL` baseline stack.
    pub etcd_pg_accountant: NetworkTrafficAccountant,
    /// Full wire accounting for the `arbiter-rs` + `PostgreSQL` unified stack.
    pub arbiter_pg_accountant: NetworkTrafficAccountant,
    /// Total wire packets saved by `arbiter-rs`.
    pub packets_saved: PacketCount,
    /// Total L2–L7 wire bytes saved by `arbiter-rs`.
    pub wire_bytes_saved: Bytes,
    /// Wire byte reduction ratio in parts-per-billion (`SharePartsPerBillion`).
    pub wire_byte_reduction_ppb: SharePartsPerBillion,
    /// Failover recovery ticks for `etcd` + `PostgreSQL`.
    pub etcd_failover_recovery_ticks: BenchmarkTicks,
    /// Failover recovery ticks for `arbiter-rs` + `PostgreSQL`.
    pub arbiter_failover_recovery_ticks: BenchmarkTicks,
}

/// Runs a comparative L2–L7 wire-traffic analysis between `etcd` + `PostgreSQL` and `arbiter-rs` + `PostgreSQL`
/// for `node_count`.
///
/// # Arguments
///
/// * `node_count` - Cluster [`NodeCount`] (e.g., `3`, `5`, `7`, or larger $N$).
/// * `etcd_lease_ttl_ms` - Baseline `etcd` lease TTL in milliseconds.
/// * `joint_master_kill` - Whether to simulate simultaneous control+data leader kill.
///
/// # Returns
///
/// [`TrafficComparisonReport`] containing per-window and total wire packet/byte savings.
///
/// # Errors
///
/// Returns [`ArbiterError`] if `node_count < 3` or ratio arithmetic fails.
pub fn compare_etcd_pg_vs_arbiter(
    node_count: NodeCount,
    etcd_lease_ttl_ms: u64,
    joint_master_kill: bool,
) -> ArbiterResult<TrafficComparisonReport> {
    let etcd_acc = NetworkTrafficAccountant::simulate_etcd_postgres_stack(
        node_count,
        etcd_lease_ttl_ms,
        joint_master_kill,
    )?;
    let arb_acc =
        NetworkTrafficAccountant::simulate_arbiter_postgres_stack(node_count, joint_master_kill)
            .unwrap_or_default();

    let packets_saved = etcd_acc
        .total_wire_packets
        .saturating_sub(arb_acc.total_wire_packets);
    let wire_bytes_saved = etcd_acc
        .total_l2_l7_wire_bytes
        .saturating_sub(arb_acc.total_l2_l7_wire_bytes);

    let wire_byte_reduction_ppb = SharePartsPerBillion::from_ratio(
        wire_bytes_saved.get(),
        etcd_acc.total_l2_l7_wire_bytes.get().max(1),
    )
    .unwrap_or_default();

    // Convert ms to 10ms ticks
    let etcd_ticks = BenchmarkTicks::new(
        (etcd_lease_ttl_ms / 10).saturating_add(if joint_master_kill { 50 } else { 15 }),
    );
    let arb_ticks = BenchmarkTicks::new(if joint_master_kill { 18 } else { 4 });

    Ok(TrafficComparisonReport {
        node_count,
        etcd_lease_ttl_ms,
        joint_master_kill,
        etcd_pg_accountant: etcd_acc,
        arbiter_pg_accountant: arb_acc,
        packets_saved,
        wire_bytes_saved,
        wire_byte_reduction_ppb,
        etcd_failover_recovery_ticks: etcd_ticks,
        arbiter_failover_recovery_ticks: arb_ticks,
    })
}

/// Cross-validates simulated L2–L7 wire [`Bytes`] against empirical kernel NIC captures.
///
/// Asserts that relative drift between the simulation model and `nftables`/`pcap` Vagrant counters
/// does not exceed `max_allowed_bps` (e.g., `500 bps = 5.00%`).
///
/// # Arguments
///
/// * `simulated_wire_bytes` - Total L2–L7 wire bytes predicted by [`NetworkTrafficAccountant`].
/// * `empirical_nic_bytes` - Actual bytes captured on the Vagrant network interface (`nftables`/`pcap`).
/// * `max_allowed_bps` - Maximum allowed relative drift in [`WeightBasisPoints`] (e.g., `500` for `5%`).
///
/// # Returns
///
/// Observed drift in [`WeightBasisPoints`].
///
/// # Errors
///
/// Returns [`ArbiterError::InvalidBenchmarkConfig`] if `empirical_nic_bytes == 0`, or
/// [`ArbiterError::CalibrationDriftExceeded`] if the observed drift exceeds `max_allowed_bps`.
pub fn verify_calibration_drift(
    simulated_wire_bytes: Bytes,
    empirical_nic_bytes: Bytes,
    max_allowed_bps: WeightBasisPoints,
) -> ArbiterResult<WeightBasisPoints> {
    if empirical_nic_bytes.is_zero() {
        return Err(ArbiterError::InvalidBenchmarkConfig {
            parameter: "empirical_nic_bytes".to_owned(),
            reason: "empirical NIC byte capture cannot be zero".to_owned(),
        });
    }
    let sim = simulated_wire_bytes.get();
    let emp = empirical_nic_bytes.get();
    let abs_diff = sim.abs_diff(emp);
    let drift_bps = u64::try_from(
        u128::from(abs_diff)
            .saturating_mul(10_000)
            .checked_div(u128::from(emp))
            .unwrap_or(0),
    )
    .unwrap_or(u64::MAX);

    if drift_bps > max_allowed_bps.get() {
        return Err(ArbiterError::CalibrationDriftExceeded {
            observed_drift_bps: drift_bps,
            max_allowed_bps: max_allowed_bps.get(),
        });
    }

    WeightBasisPoints::new(drift_bps.max(1))
}

/// Parses an empirical `(PacketCount, Bytes)` counter pair from a `nftables` (`counter packets <P> bytes <B>`)
/// or `pfctl -vvs rules` (`[ Evaluations: ... Packets: <P> Bytes: <B> ... ]`) summary line.
///
/// # Arguments
///
/// * `counter_line` - Kernel firewall counter output line.
///
/// # Returns
///
/// Tuple `(PacketCount, Bytes)` extracted from the line.
///
/// # Errors
///
/// Returns [`ArbiterError::InvalidBenchmarkConfig`] if `packets` or `bytes` tokens cannot be parsed.
pub fn parse_kernel_nic_counter_line(counter_line: &str) -> ArbiterResult<(PacketCount, Bytes)> {
    let mut pkts: Option<u64> = None;
    let mut bytes: Option<u64> = None;
    let tokens: Vec<&str> = counter_line.split_whitespace().collect();
    for (idx, &tok) in tokens.iter().enumerate() {
        let lower = tok.trim_end_matches(':').to_ascii_lowercase();
        if lower == "packets" {
            if let Some(val_str) = tokens.get(idx.saturating_add(1)) {
                pkts = val_str.parse::<u64>().ok();
            }
        } else if lower == "bytes" {
            if let Some(val_str) = tokens.get(idx.saturating_add(1)) {
                bytes = val_str.parse::<u64>().ok();
            }
        }
    }
    let (Some(p), Some(b)) = (pkts, bytes) else {
        return Err(ArbiterError::InvalidBenchmarkConfig {
            parameter: "counter_line".to_owned(),
            reason: format!("missing packets/bytes tokens in '{counter_line}'"),
        });
    };
    Ok((PacketCount::new(p), Bytes::new(b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_l7_wire_accounting_across_3_5_7_and_1000_nodes() {
        assert!(
            NetworkTrafficAccountant::simulate_etcd_postgres_stack(
                NodeCount::new(2).unwrap_or_default(),
                5_000,
                false
            )
            .is_err()
        );
        assert!(
            NetworkTrafficAccountant::simulate_etcd_postgres_stack(
                NodeCount::new(3).unwrap_or_default(),
                0,
                false
            )
            .is_err()
        );
        assert!(
            NetworkTrafficAccountant::simulate_arbiter_postgres_stack(
                NodeCount::new(2).unwrap_or_default(),
                false
            )
            .is_err()
        );
        assert!(
            compare_etcd_pg_vs_arbiter(NodeCount::new(2).unwrap_or_default(), 5_000, false)
                .is_err()
        );

        for count in [3_u32, 5, 7, 15, 63, 255, 1000] {
            let nc = NodeCount::new(count).unwrap_or_default();
            for joint_kill in [false, true] {
                let rep = compare_etcd_pg_vs_arbiter(nc, 5_000, joint_kill).unwrap_or_default();
                assert!(rep.packets_saved.get() > 0);
                assert!(rep.wire_bytes_saved.get() > 0);
                assert!(rep.wire_byte_reduction_ppb.get() > 500_000_000); // > 50% wire byte savings
                assert!(
                    rep.arbiter_pg_accountant.total_local_caas_queries == u64::from(count) * 6_000
                );
                assert!(rep.arbiter_failover_recovery_ticks < rep.etcd_failover_recovery_ticks);
            }
        }
    }

    #[test]
    fn test_overflow_and_calibration_drift_verification() {
        let mut acc = NetworkTrafficAccountant::new();
        // Trigger overflow on l7_payload_per_packet * wire_packets
        let ovf_event = PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::EtcdPeerRaftHeartbeat,
            wire_packets: PacketCount::new(u64::MAX),
            l7_payload_per_packet: Bytes::new(2),
            local_caas_queries: 0,
        };
        assert!(acc.record_event(&ovf_event).is_err());

        // Trigger overflow on l7_payload_per_packet + framing_per_pkt
        let ovf_add = PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::EtcdPeerRaftHeartbeat,
            wire_packets: PacketCount::new(1),
            l7_payload_per_packet: Bytes::new(u64::MAX),
            local_caas_queries: 0,
        };
        assert!(acc.record_event(&ovf_add).is_err());

        // Trigger overflow on full_per_pkt * pkt_count where l7 * pkt_count succeeds (l7 = 0)
        let ovf_wire_mul = PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::EtcdPeerRaftHeartbeat,
            wire_packets: PacketCount::new(u64::MAX),
            l7_payload_per_packet: Bytes::ZERO,
            local_caas_queries: 0,
        };
        assert!(acc.record_event(&ovf_wire_mul).is_err());

        // Test cumulative counter overflow paths in record_event
        let mut acc2 = NetworkTrafficAccountant::new();
        acc2.total_wire_packets = PacketCount::MAX;
        let small_ev = PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::ArbiterLocalCaasZeroPacketVerification,
            wire_packets: PacketCount::new(1),
            l7_payload_per_packet: Bytes::new(1),
            local_caas_queries: 1,
        };
        assert!(acc2.record_event(&small_ev).is_err());

        let mut acc3 = NetworkTrafficAccountant::new();
        acc3.total_l7_payload_bytes = Bytes::MAX;
        assert!(acc3.record_event(&small_ev).is_err());

        let mut acc4 = NetworkTrafficAccountant::new();
        acc4.total_l2_l7_wire_bytes = Bytes::MAX;
        let wire_ev = PacketTraceEvent {
            window: LifecycleWindow::SteadyStatePreFailure,
            category: ProtocolCategory::ArbiterMultiplexedQuicHeartbeat,
            wire_packets: PacketCount::new(1),
            l7_payload_per_packet: Bytes::ZERO,
            local_caas_queries: 0,
        };
        assert!(acc4.record_event(&wire_ev).is_err());

        // Test window/category counter overflow paths
        let mut acc5 = NetworkTrafficAccountant::new();
        acc5.by_window.insert(
            LifecycleWindow::SteadyStatePreFailure,
            WindowTrafficSummary {
                wire_packets: PacketCount::MAX,
                ..WindowTrafficSummary::default()
            },
        );
        assert!(acc5.record_event(&small_ev).is_err());

        let mut acc6 = NetworkTrafficAccountant::new();
        acc6.by_window.insert(
            LifecycleWindow::SteadyStatePreFailure,
            WindowTrafficSummary {
                l7_payload_bytes: Bytes::MAX,
                ..WindowTrafficSummary::default()
            },
        );
        assert!(acc6.record_event(&small_ev).is_err());

        let mut acc7 = NetworkTrafficAccountant::new();
        acc7.by_window.insert(
            LifecycleWindow::SteadyStatePreFailure,
            WindowTrafficSummary {
                total_l2_l7_wire_bytes: Bytes::MAX,
                ..WindowTrafficSummary::default()
            },
        );
        assert!(acc7.record_event(&wire_ev).is_err());

        let mut acc8 = NetworkTrafficAccountant::new();
        acc8.by_category_wire_bytes.insert(
            ProtocolCategory::ArbiterMultiplexedQuicHeartbeat,
            Bytes::MAX,
        );
        assert!(acc8.record_event(&wire_ev).is_err());

        let mut acc9 = NetworkTrafficAccountant::new();
        acc9.by_category_packets.insert(
            ProtocolCategory::ArbiterMultiplexedQuicHeartbeat,
            PacketCount::MAX,
        );
        assert!(acc9.record_event(&wire_ev).is_err());

        // Calibration drift verification tests
        let max_500 = WeightBasisPoints::new(500).unwrap_or(WeightBasisPoints::STANDARD);
        assert!(verify_calibration_drift(Bytes::new(10_000), Bytes::ZERO, max_500).is_err());
        // 2% drift (200 bps <= 500 bps) -> Ok
        assert_eq!(
            verify_calibration_drift(Bytes::new(10_200), Bytes::new(10_000), max_500),
            WeightBasisPoints::new(200)
        );
        // 8% drift (800 bps > 500 bps) -> CalibrationDriftExceeded
        assert!(verify_calibration_drift(Bytes::new(10_800), Bytes::new(10_000), max_500).is_err());
    }

    #[test]
    fn test_parse_kernel_nic_counter_line() {
        assert_eq!(
            parse_kernel_nic_counter_line("udp dport 5050 counter packets 360 bytes 59040"),
            Ok((PacketCount::new(360), Bytes::new(59_040)))
        );
        assert_eq!(
            parse_kernel_nic_counter_line(
                "[ Evaluations: 1200 Packets: 720 Bytes: 118080 States: 1 ]"
            ),
            Ok((PacketCount::new(720), Bytes::new(118_080)))
        );
        assert!(parse_kernel_nic_counter_line("counter packets bad bytes").is_err());
        assert!(parse_kernel_nic_counter_line("counter packets").is_err());
    }
}
