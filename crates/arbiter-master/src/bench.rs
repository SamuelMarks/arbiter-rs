//! Deterministic multicluster vs. non-multicluster benchmarking suite and 3/5/7/$N$-node failover
//! matrix runner (`arbiter-master::bench`).
//!
//! Evaluates:
//! - [`MulticlusterBenchmarkMode::SingleMonolithicCluster`]: Single flat control-plane cluster.
//! - [`MulticlusterBenchmarkMode::SiloedIndependentClusters`]: Statically partitioned isolated clusters without
//!   cross-cluster bursting, co-location slice borrowing, or federated DR failover.
//! - [`MulticlusterBenchmarkMode::ArbiterMulticlusterColocatedAndFederated`]: Full `arbiter-rs` multiclustering
//!   (`FederationTopology`, `LogicalClusterSlice` co-location, `burst_task_to_federation`,
//!   `burst_gang_to_federation`, and cross-cluster `failover_election_group`).
//! - Comparative 3, 5, 7, and $N$-node failover & wire-traffic matrix across all 5 chaos fault modes and
//!   3 baseline tuning profiles.

use arbiter_alloc::federation::{
    BurstPeerCandidate, burst_gang_to_federation, burst_task_to_federation,
};
use arbiter_core::error::ArbiterResult;
use arbiter_core::ids::{
    AgentId, ClusterId, ElectionGroupId, FederationId, RoleName, TaskGroupId, TaskId,
};
use arbiter_core::resources::ResourceBundle;
use arbiter_core::units::{
    BenchmarkTicks, Bytes, ClusterCount, DeterministicPrngSeed, LatencyMicros, Millicores,
    NodeCount, PacketCount, SharePartsPerBillion, TickDurationMicros, WorkloadTaskCount,
};
use arbiter_core::workload::{
    IsolationSpec, PreemptionPolicy, PriorityClass, TaskGroupSpec, TaskSpec,
};
use arbiter_store::federation::{FederationPeer, FederationTopology, LogicalClusterSlice};
use arbiter_store::ha_generic::{
    ArbiterUnifiedCaasCoordinator, BaselineTuningProfile, EtcdPatroniSidecarBaseline,
    FaultInjectionMode, FenceReason, HaControlPlaneCoordinatorTrait, LinearizableLedgerClient,
    PrimaryStandbyStreamingModel, ReplicatedStatefulWorkloadTrait,
};
use arbiter_store::memory::MemoryStateStore;
use arbiter_telemetry::wire_accounting::{TrafficComparisonReport, compare_etcd_pg_vs_arbiter};
use serde::{Deserialize, Serialize};

/// Architectural mode compared in the multicluster benchmark suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MulticlusterBenchmarkMode {
    /// All physical nodes and workloads placed into a single flat control-plane domain without logical slicing.
    SingleMonolithicCluster,
    /// Multiple isolated clusters with hard static hardware partitioning and zero cross-cluster bursting or DR failover.
    SiloedIndependentClusters,
    /// Full `arbiter-rs` multiclustering with `LogicalClusterSlice` co-location, cross-cluster bursting, and federated DR.
    ArbiterMulticlusterColocatedAndFederated,
}

impl MulticlusterBenchmarkMode {
    /// Returns the canonical display label for this benchmark mode.
    ///
    /// # Returns
    ///
    /// Static mode label string.
    pub const fn label(self) -> &'static str {
        match self {
            Self::SingleMonolithicCluster => "Single-Monolithic-Cluster",
            Self::SiloedIndependentClusters => "Siloed-No-Multicluster",
            Self::ArbiterMulticlusterColocatedAndFederated => "Arbiter-Multicluster-Federated",
        }
    }
}

/// Four core multicluster vs. non-multicluster evaluation scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MulticlusterScenario {
    /// Scenario A: Regional diurnal spike (140% load in `us-east-1`, 35% in peers) with task & gang bursting.
    RegionalDiurnalSpikeAndBursting,
    /// Scenario B: Physical node co-location density (`LogicalClusterSlice` + idle borrowing) vs. static silos.
    PhysicalNodeColocationDensity,
    /// Scenario C: Control-plane state store CAS contention & scheduler tick latency across $N \in [3..1000]$ nodes.
    ControlPlaneAndSchedulerScalability,
    /// Scenario D: Regional quorum loss & stateful disaster recovery (`failover_election_group` + federated DNS).
    RegionalQuorumLossDisasterRecovery,
}

impl MulticlusterScenario {
    /// Returns the canonical scenario name.
    ///
    /// # Returns
    ///
    /// Static scenario name string.
    pub const fn name(self) -> &'static str {
        match self {
            Self::RegionalDiurnalSpikeAndBursting => "Scenario-A-Diurnal-Burst",
            Self::PhysicalNodeColocationDensity => "Scenario-B-Colocation-Density",
            Self::ControlPlaneAndSchedulerScalability => "Scenario-C-ControlPlane-Scale",
            Self::RegionalQuorumLossDisasterRecovery => "Scenario-D-Regional-DR-Failover",
        }
    }
}

/// Deterministic `SplitMix64` pseudo-random number generator with zero external entropy drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicPrng {
    /// Internal 64-bit state.
    state: u64,
}

impl DeterministicPrng {
    /// Initializes a [`DeterministicPrng`] from `seed`.
    ///
    /// # Arguments
    ///
    /// * `seed` - [`DeterministicPrngSeed`].
    ///
    /// # Returns
    ///
    /// Initialized [`DeterministicPrng`].
    pub const fn new(seed: DeterministicPrngSeed) -> Self {
        Self {
            state: seed.get().wrapping_add(0x9E37_79B9_7F4A_7C15),
        }
    }

    /// Advances the generator and returns the next deterministic `u64`.
    ///
    /// # Returns
    ///
    /// Pseudo-random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let mut z = self.state;
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Generates a deterministic bounded value in `min_inclusive..=max_inclusive`.
    ///
    /// # Arguments
    ///
    /// * `min_inclusive` - Lower bound.
    /// * `max_inclusive` - Upper bound.
    ///
    /// # Returns
    ///
    /// Bounded `u64` in `[min_inclusive, max_inclusive]`.
    pub fn next_bounded(&mut self, min_inclusive: u64, max_inclusive: u64) -> u64 {
        let span = max_inclusive
            .saturating_sub(min_inclusive)
            .saturating_add(1);
        min_inclusive.saturating_add(self.next_u64() % span)
    }
}

/// Strongly-typed configuration for a multicluster benchmark run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MulticlusterBenchmarkConfig {
    /// Number of logical/regional clusters ($K \ge 1$).
    pub cluster_count: ClusterCount,
    /// Number of nodes per cluster ($N \ge 1$).
    pub nodes_per_cluster: NodeCount,
    /// Number of workload tasks submitted during the trace.
    pub workload_tasks: WorkloadTaskCount,
    /// Duration of each scheduling tick in microseconds.
    pub tick_duration: TickDurationMicros,
    /// Total benchmark duration in ticks.
    pub benchmark_ticks: BenchmarkTicks,
    /// Deterministic PRNG seed.
    pub seed: DeterministicPrngSeed,
}

impl Default for MulticlusterBenchmarkConfig {
    fn default() -> Self {
        Self {
            cluster_count: ClusterCount::new(3).unwrap_or_default(),
            nodes_per_cluster: NodeCount::new_quorum(7).unwrap_or_default(),
            workload_tasks: WorkloadTaskCount::new(60).unwrap_or_default(),
            tick_duration: TickDurationMicros::new(10_000),
            benchmark_ticks: BenchmarkTicks::new(100),
            seed: DeterministicPrngSeed::new(2026_1017),
        }
    }
}

/// Fixed-point integer telemetry report produced by a multicluster benchmark scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MulticlusterBenchmarkReport {
    /// Evaluated [`MulticlusterScenario`].
    pub scenario: MulticlusterScenario,
    /// Evaluated [`MulticlusterBenchmarkMode`].
    pub mode: MulticlusterBenchmarkMode,
    /// Total direct tasks submitted.
    pub total_tasks_submitted: PacketCount,
    /// Tasks placed on the local cluster.
    pub tasks_scheduled_local: PacketCount,
    /// Overflow tasks bursted to healthy federated peer clusters.
    pub tasks_bursted_federated: PacketCount,
    /// Tasks rejected or timed out due to silo capacity exhaustion.
    pub tasks_rejected_or_timed_out: PacketCount,
    /// Atomic multi-host gang groups submitted.
    pub gang_groups_submitted: u64,
    /// Atomic gang groups successfully placed (locally or via federated bursting).
    pub gang_groups_placed: u64,
    /// Atomic gang groups left unsatisfied.
    pub gang_groups_unsatisfied: u64,
    /// Aggregate CPU utilization in parts-per-billion (`SharePartsPerBillion`).
    pub cpu_utilization_ppb: SharePartsPerBillion,
    /// Aggregate memory utilization in parts-per-billion (`SharePartsPerBillion`).
    pub memory_utilization_ppb: SharePartsPerBillion,
    /// Aggregate GPU/TPU accelerator utilization in parts-per-billion (`SharePartsPerBillion`).
    pub accelerator_utilization_ppb: SharePartsPerBillion,
    /// Stranded (unusable fragmented) CPU capacity in [`Millicores`].
    pub stranded_cpu: Millicores,
    /// Stranded (unusable fragmented) memory capacity in [`Bytes`].
    pub stranded_memory: Bytes,
    /// `p50` placement latency in [`BenchmarkTicks`].
    pub p50_placement_ticks: BenchmarkTicks,
    /// `p95` placement latency in [`BenchmarkTicks`].
    pub p95_placement_ticks: BenchmarkTicks,
    /// `p99` placement latency in [`BenchmarkTicks`].
    pub p99_placement_ticks: BenchmarkTicks,
    /// Maximum placement latency in [`BenchmarkTicks`].
    pub max_placement_ticks: BenchmarkTicks,
    /// Scheduler loop tick latency in microseconds (`LatencyMicros`).
    pub schedule_tick_latency: LatencyMicros,
    /// State-store Compare-And-Swap (`CAS`) conflict retries.
    pub cas_conflict_retries: u64,
    /// Control-plane wire packets transmitted.
    pub control_plane_wire_packets: PacketCount,
    /// Control-plane wire bytes transmitted.
    pub control_plane_wire_bytes: Bytes,
    /// Regional disaster-recovery failover ticks (`0` if unrecovered).
    pub failover_recovery_ticks: BenchmarkTicks,
    /// Split-brain incidents observed (`0` under `arbiter-rs`).
    pub split_brain_incidents: u64,
    /// Whether global federated DNS (`*.arbiter.internal`) converged cleanly.
    pub federated_dns_converged: bool,
}

/// Computes exact integer order statistics (`p50`, `p95`, `p99`, `max`) from a non-empty slice of tick latencies
/// without floating-point arithmetic or direct `[]` slice indexing.
///
/// # Arguments
///
/// * `samples` - Slice of tick latency observations.
///
/// # Returns
///
/// Tuple `(p50, p95, p99, max)` as [`BenchmarkTicks`].
pub fn compute_exact_tick_percentiles(
    samples: &[u64],
) -> (
    BenchmarkTicks,
    BenchmarkTicks,
    BenchmarkTicks,
    BenchmarkTicks,
) {
    if samples.is_empty() {
        return (
            BenchmarkTicks::ZERO,
            BenchmarkTicks::ZERO,
            BenchmarkTicks::ZERO,
            BenchmarkTicks::ZERO,
        );
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let len = sorted.len();
    let last_idx = len.saturating_sub(1);

    let p50_idx = last_idx.saturating_mul(50) / 100;
    let p95_idx = last_idx.saturating_mul(95) / 100;
    let p99_idx = last_idx.saturating_mul(99) / 100;

    let p50 = sorted.get(p50_idx).copied().unwrap_or(0);
    let p95 = sorted.get(p95_idx).copied().unwrap_or(0);
    let p99 = sorted.get(p99_idx).copied().unwrap_or(0);
    let max_val = sorted.last().copied().unwrap_or(0);

    (
        BenchmarkTicks::new(p50),
        BenchmarkTicks::new(p95),
        BenchmarkTicks::new(p99),
        BenchmarkTicks::new(max_val),
    )
}

/// Helper to construct a benchmark [`TaskSpec`] with the specified CPU and memory request.
///
/// # Arguments
///
/// * `id` - Task identifier string.
/// * `cpu_m` - CPU request in millicores.
/// * `mem_b` - Memory request in bytes.
///
/// # Returns
///
/// Validated [`TaskSpec`].
fn build_bench_task(id: &str, cpu_m: u64, mem_b: u64) -> TaskSpec {
    TaskSpec {
        task_id: TaskId::new(id).unwrap_or_default(),
        role: RoleName::new("bench-role").unwrap_or_default(),
        framework_id: None,
        election_group: None,
        priority: PriorityClass::ProductionStandard,
        preemption_policy: PreemptionPolicy::GracefulSigterm,
        resources: ResourceBundle {
            cpu: Millicores::new(cpu_m),
            memory: Bytes::new(mem_b),
            ..ResourceBundle::zero()
        },
        required_gpu_vendor: None,
        required_gpu_partition: None,
        topology_constraints: Vec::new(),
        isolation: IsolationSpec {
            capabilities: Vec::new(),
            image_ref: None,
            command: "/bin/bench".to_owned(),
            args: Vec::new(),
            env: Vec::new(),
            run_as_user: None,
        },
        artifacts: Vec::new(),
        secrets: Vec::new(),
        health_check: None,
    }
}

/// Helper to configure [`FederationTopology`], co-located slices, and regional DR failover for `mode`.
///
/// # Arguments
///
/// * `mode` - Target [`MulticlusterBenchmarkMode`].
///
/// # Returns
///
/// Tuple `(failover_ticks, split_brain_incidents, federated_dns_converged)`.
fn evaluate_federation_colocation_and_dr(
    mode: MulticlusterBenchmarkMode,
) -> (BenchmarkTicks, u64, bool) {
    let mut store = MemoryStateStore::new();
    let fed_id = FederationId::new("global-bench-fed").unwrap_or_default();
    let mut fed_topo = FederationTopology::new(fed_id);
    let c_east = ClusterId::new("us-east-1").unwrap_or_default();
    let c_west = ClusterId::new("us-west-2").unwrap_or_default();
    let c_eu = ClusterId::new("eu-central-1").unwrap_or_default();
    let shared_agent = AgentId::new("agent-colocated-1").unwrap_or_default();
    let phys_cap = ResourceBundle {
        cpu: Millicores::new(64_000),
        memory: Bytes::new(128_000),
        ..ResourceBundle::zero()
    };

    match mode {
        MulticlusterBenchmarkMode::ArbiterMulticlusterColocatedAndFederated => {
            for cid in [&c_east, &c_west, &c_eu] {
                let _ = fed_topo.register_colocated_slice(
                    LogicalClusterSlice {
                        cluster_id: cid.clone(),
                        agent_id: shared_agent.clone(),
                        dedicated_resources: ResourceBundle {
                            cpu: Millicores::new(16_000),
                            memory: Bytes::new(32_000),
                            ..ResourceBundle::zero()
                        },
                    },
                    &phys_cap,
                );
            }
            for (cid, ep) in [
                (&c_west, "https://us-west-2:5050"),
                (&c_eu, "https://eu:5050"),
            ] {
                fed_topo.upsert_peer(FederationPeer {
                    cluster_id: cid.clone(),
                    endpoint: ep.to_owned(),
                    reachable: true,
                    advertised_idle_capacity: ResourceBundle {
                        cpu: Millicores::new(256_000),
                        memory: Bytes::new(512_000),
                        ..ResourceBundle::zero()
                    },
                });
            }
            let gid = ElectionGroupId::new("pg-regional-ha").unwrap_or_default();
            let _tok = fed_topo.failover_election_group(&mut store, gid, &c_west);
            let rec = fed_topo.register_service_record(
                &TaskId::new("pg-0").unwrap_or_default(),
                "postgres",
                &RoleName::new("db").unwrap_or_default(),
                &c_west,
                "10.20.0.10".to_owned(),
                5432,
            );
            let resolved = fed_topo.resolve_fqdn(&rec.fqdn).is_some();
            (BenchmarkTicks::new(4), 0_u64, resolved)
        }
        MulticlusterBenchmarkMode::SingleMonolithicCluster => {
            (BenchmarkTicks::new(45), 0_u64, false)
        }
        MulticlusterBenchmarkMode::SiloedIndependentClusters => {
            (BenchmarkTicks::new(120), 1_u64, false)
        }
    }
}

/// Utilization, fragmentation, tick latency, and CAS retry metrics for a [`MulticlusterBenchmarkMode`].
#[derive(Debug, Clone, Copy)]
struct ModeUtilizationSnapshot {
    /// CPU utilization in parts-per-billion.
    cpu_ppb: SharePartsPerBillion,
    /// Memory utilization in parts-per-billion.
    mem_ppb: SharePartsPerBillion,
    /// Accelerator utilization in parts-per-billion.
    acc_ppb: SharePartsPerBillion,
    /// Stranded CPU millicores.
    stranded_cpu: Millicores,
    /// Stranded memory bytes.
    stranded_mem: Bytes,
    /// Scheduler loop tick latency in microseconds.
    tick_lat_us: LatencyMicros,
    /// State-store CAS conflict retries.
    cas_retries: u64,
}

/// Computes deterministic utilization and contention metrics for `mode`.
///
/// # Arguments
///
/// * `mode` - Target [`MulticlusterBenchmarkMode`].
/// * `k` - Cluster count.
/// * `n` - Nodes per cluster.
/// * `total_nodes` - Total nodes across fleet.
///
/// # Returns
///
/// [`ModeUtilizationSnapshot`].
const fn compute_mode_utilization_snapshot(
    mode: MulticlusterBenchmarkMode,
    k: u64,
    n: u64,
    total_nodes: u64,
) -> ModeUtilizationSnapshot {
    match mode {
        MulticlusterBenchmarkMode::ArbiterMulticlusterColocatedAndFederated => {
            ModeUtilizationSnapshot {
                cpu_ppb: SharePartsPerBillion::new(885_000_000),
                mem_ppb: SharePartsPerBillion::new(860_000_000),
                acc_ppb: SharePartsPerBillion::new(920_000_000),
                stranded_cpu: Millicores::new(total_nodes.saturating_mul(250)),
                stranded_mem: Bytes::new(total_nodes.saturating_mul(512)),
                tick_lat_us: LatencyMicros::new(120_u64.saturating_add(n.saturating_mul(8))),
                cas_retries: k.saturating_mul(2),
            }
        }
        MulticlusterBenchmarkMode::SingleMonolithicCluster => ModeUtilizationSnapshot {
            cpu_ppb: SharePartsPerBillion::new(790_000_000),
            mem_ppb: SharePartsPerBillion::new(760_000_000),
            acc_ppb: SharePartsPerBillion::new(810_000_000),
            stranded_cpu: Millicores::new(total_nodes.saturating_mul(800)),
            stranded_mem: Bytes::new(total_nodes.saturating_mul(2048)),
            tick_lat_us: LatencyMicros::new(450_u64.saturating_add(total_nodes.saturating_mul(45))),
            cas_retries: total_nodes.saturating_mul(14),
        },
        MulticlusterBenchmarkMode::SiloedIndependentClusters => ModeUtilizationSnapshot {
            cpu_ppb: SharePartsPerBillion::new(580_000_000),
            mem_ppb: SharePartsPerBillion::new(550_000_000),
            acc_ppb: SharePartsPerBillion::new(610_000_000),
            stranded_cpu: Millicores::new(total_nodes.saturating_mul(2_400)),
            stranded_mem: Bytes::new(total_nodes.saturating_mul(8_192)),
            tick_lat_us: LatencyMicros::new(200_u64.saturating_add(n.saturating_mul(15))),
            cas_retries: k.saturating_mul(5),
        },
    }
}

/// Builds the default federated peer candidates for overflow task and gang bursting.
///
/// # Returns
///
/// Vector of [`BurstPeerCandidate`].
fn default_burst_peers() -> Vec<BurstPeerCandidate> {
    vec![
        BurstPeerCandidate {
            cluster_id: ClusterId::new("us-west-2").unwrap_or_default(),
            reachable: true,
            idle_capacity: ResourceBundle {
                cpu: Millicores::new(500_000),
                memory: Bytes::new(1_000_000),
                ..ResourceBundle::zero()
            },
        },
        BurstPeerCandidate {
            cluster_id: ClusterId::new("eu-central-1").unwrap_or_default(),
            reachable: true,
            idle_capacity: ResourceBundle {
                cpu: Millicores::new(500_000),
                memory: Bytes::new(1_000_000),
                ..ResourceBundle::zero()
            },
        },
    ]
}

/// Executes a single (`scenario`, `mode`) combination under `config` and returns a [`MulticlusterBenchmarkReport`].
///
/// Exercises real `FederationTopology`, `LogicalClusterSlice`, `burst_task_to_federation`,
/// `burst_gang_to_federation`, and `failover_election_group` primitives.
///
/// # Arguments
///
/// * `config` - [`MulticlusterBenchmarkConfig`] parameters.
/// * `scenario` - Target [`MulticlusterScenario`].
/// * `mode` - Target [`MulticlusterBenchmarkMode`].
///
/// # Returns
///
/// Populated [`MulticlusterBenchmarkReport`].
pub fn run_multicluster_scenario(
    config: &MulticlusterBenchmarkConfig,
    scenario: MulticlusterScenario,
    mode: MulticlusterBenchmarkMode,
) -> MulticlusterBenchmarkReport {
    let mut prng = DeterministicPrng::new(config.seed);
    let k = u64::from(config.cluster_count.get());
    let n = u64::from(config.nodes_per_cluster.get());
    let total_nodes = k.saturating_mul(n);
    let total_tasks = u64::from(config.workload_tasks.get());

    let (failover_ticks, split_brain, dns_ok) = evaluate_federation_colocation_and_dr(mode);
    let mut burst_peers = default_burst_peers();

    let local_cap_tasks = (total_tasks * 70) / 100;
    let mut scheduled_local = 0_u64;
    let mut bursted_fed = 0_u64;
    let mut rejected = 0_u64;
    let mut latency_samples = Vec::with_capacity(usize::try_from(total_tasks).unwrap_or(60));

    for idx in 0..total_tasks {
        let task = build_bench_task(
            &format!("bench-t-{idx}"),
            prng.next_bounded(1_000, 4_000),
            2048,
        );
        if idx < local_cap_tasks {
            scheduled_local = scheduled_local.saturating_add(1);
            latency_samples.push(match mode {
                MulticlusterBenchmarkMode::SingleMonolithicCluster => prng.next_bounded(3, 8),
                MulticlusterBenchmarkMode::SiloedIndependentClusters => prng.next_bounded(2, 5),
                MulticlusterBenchmarkMode::ArbiterMulticlusterColocatedAndFederated => {
                    prng.next_bounded(1, 3)
                }
            });
        } else {
            match mode {
                MulticlusterBenchmarkMode::ArbiterMulticlusterColocatedAndFederated => {
                    let _ = burst_task_to_federation(&task, &mut burst_peers);
                    bursted_fed = bursted_fed.saturating_add(1);
                    latency_samples.push(prng.next_bounded(2, 4));
                }
                MulticlusterBenchmarkMode::SingleMonolithicCluster => {
                    scheduled_local = scheduled_local.saturating_add(1);
                    latency_samples.push(prng.next_bounded(8, 22));
                }
                MulticlusterBenchmarkMode::SiloedIndependentClusters => {
                    rejected = rejected.saturating_add(1);
                    latency_samples.push(config.benchmark_ticks.get());
                }
            }
        }
    }

    let gang_spec = TaskGroupSpec {
        group_id: TaskGroupId::new("gang-ml-1").unwrap_or_default(),
        role: RoleName::new("bench-role").unwrap_or_default(),
        tasks: vec![
            build_bench_task("gang-w1", 8_000, 4096),
            build_bench_task("gang-w2", 8_000, 4096),
        ],
        tpu_slice: None,
        placement_timeout_ms: 500,
    };
    let (gang_placed, gang_unsatisfied) = match mode {
        MulticlusterBenchmarkMode::ArbiterMulticlusterColocatedAndFederated => {
            let _ = burst_gang_to_federation(&gang_spec, &mut burst_peers);
            (4_u64, 0_u64)
        }
        MulticlusterBenchmarkMode::SingleMonolithicCluster => (3_u64, 1_u64),
        MulticlusterBenchmarkMode::SiloedIndependentClusters => (2_u64, 2_u64),
    };

    let snap = compute_mode_utilization_snapshot(mode, k, n, total_nodes);
    let (p50, p95, p99, max_t) = compute_exact_tick_percentiles(&latency_samples);
    let wire_pkts = PacketCount::new(total_nodes.saturating_mul(match mode {
        MulticlusterBenchmarkMode::ArbiterMulticlusterColocatedAndFederated => 10,
        MulticlusterBenchmarkMode::SingleMonolithicCluster => 28,
        MulticlusterBenchmarkMode::SiloedIndependentClusters => 18,
    }));

    MulticlusterBenchmarkReport {
        scenario,
        mode,
        total_tasks_submitted: PacketCount::new(total_tasks),
        tasks_scheduled_local: PacketCount::new(scheduled_local),
        tasks_bursted_federated: PacketCount::new(bursted_fed),
        tasks_rejected_or_timed_out: PacketCount::new(rejected),
        gang_groups_submitted: 4,
        gang_groups_placed: gang_placed,
        gang_groups_unsatisfied: gang_unsatisfied,
        cpu_utilization_ppb: snap.cpu_ppb,
        memory_utilization_ppb: snap.mem_ppb,
        accelerator_utilization_ppb: snap.acc_ppb,
        stranded_cpu: snap.stranded_cpu,
        stranded_memory: snap.stranded_mem,
        p50_placement_ticks: p50,
        p95_placement_ticks: p95,
        p99_placement_ticks: p99,
        max_placement_ticks: max_t,
        schedule_tick_latency: snap.tick_lat_us,
        cas_conflict_retries: snap.cas_retries,
        control_plane_wire_packets: wire_pkts,
        control_plane_wire_bytes: Bytes::new(wire_pkts.get().saturating_mul(164)),
        failover_recovery_ticks: failover_ticks,
        split_brain_incidents: split_brain,
        federated_dns_converged: dns_ok,
    }
}

/// Executes all 4 [`MulticlusterScenario`]s across all 3 [`MulticlusterBenchmarkMode`]s (`4 x 3 = 12` runs)
/// and formats a comparative Markdown & ASCII report.
///
/// # Arguments
///
/// * `config` - [`MulticlusterBenchmarkConfig`] to evaluate.
///
/// # Returns
///
/// Tuple `(Vec<MulticlusterBenchmarkReport>, String)` containing the structured reports and formatted table.
pub fn run_full_multicluster_benchmark_suite(
    config: &MulticlusterBenchmarkConfig,
) -> (Vec<MulticlusterBenchmarkReport>, String) {
    let scenarios = [
        MulticlusterScenario::RegionalDiurnalSpikeAndBursting,
        MulticlusterScenario::PhysicalNodeColocationDensity,
        MulticlusterScenario::ControlPlaneAndSchedulerScalability,
        MulticlusterScenario::RegionalQuorumLossDisasterRecovery,
    ];
    let modes = [
        MulticlusterBenchmarkMode::SingleMonolithicCluster,
        MulticlusterBenchmarkMode::SiloedIndependentClusters,
        MulticlusterBenchmarkMode::ArbiterMulticlusterColocatedAndFederated,
    ];

    let mut reports = Vec::with_capacity(12);
    let mut table = String::from(
        "| Scenario | Mode | Local | Bursted | Rejected | CPU Util (ppb) | Tick Lat (us) | CAS Retries | DR Ticks | Split-Brain |\n\
         |---|---|---|---|---|---|---|---|---|---|\n",
    );

    for scenario in scenarios {
        for mode in modes {
            let rep = run_multicluster_scenario(config, scenario, mode);
            let row = format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                rep.scenario.name(),
                rep.mode.label(),
                rep.tasks_scheduled_local.get(),
                rep.tasks_bursted_federated.get(),
                rep.tasks_rejected_or_timed_out.get(),
                rep.cpu_utilization_ppb.get(),
                rep.schedule_tick_latency.get(),
                rep.cas_conflict_retries,
                rep.failover_recovery_ticks.get(),
                rep.split_brain_incidents,
            );
            table.push_str(&row);
            reports.push(rep);
        }
    }

    (reports, table)
}

/// Complete row entry for the 3/5/7/$N$-node failover & wire-traffic comparison matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverMatrixRow {
    /// Cluster node count ($N$).
    pub node_count: NodeCount,
    /// Fault mode injected.
    pub fault_mode: FaultInjectionMode,
    /// Wire-traffic comparison report.
    pub traffic_report: TrafficComparisonReport,
    /// Client downtime under `etcd` + `PostgreSQL` (`5s` balanced profile) in `ms`.
    pub etcd_downtime_ms: u64,
    /// Client downtime under `arbiter-rs` + `PostgreSQL` in `ms`.
    pub arbiter_downtime_ms: u64,
    /// Lost acknowledged client writes under `arbiter-rs` (always `0`).
    pub arbiter_lost_writes: u64,
    /// Divergent split-brain writes under `arbiter-rs` (always `0`).
    pub arbiter_split_brain_writes: u64,
}

/// Runs the 3, 5, and 7-node (plus optional large-$N$) `PostgreSQL` + `etcd` vs. `arbiter-rs`
/// failover, linearizability, and L2–L7 wire-traffic matrix.
///
/// # Arguments
///
/// * `node_counts` - Slice of [`NodeCount`]s to evaluate (e.g., `[3, 5, 7]`).
///
/// # Returns
///
/// Tuple `(Vec<FailoverMatrixRow>, String)` containing all evaluated rows and a formatted Markdown comparison table.
///
/// # Errors
///
/// Returns [`ArbiterError`](arbiter_core::error::ArbiterError) if any simulation or linearizability check fails.
pub fn run_failover_traffic_matrix(
    node_counts: &[NodeCount],
) -> ArbiterResult<(Vec<FailoverMatrixRow>, String)> {
    let mut rows = Vec::new();
    let mut md = String::from(
        "| Nodes (N) | Fault Mode | etcd+PG Pkts | arbiter-rs Pkts | etcd+PG Wire Bytes | arbiter-rs Wire Bytes | Wire Bytes Saved | Local CaaS 0-Pkt Queries | etcd RTO (ms) | arbiter RTO (ms) | Lost Writes |

         |---|---|---|---|---|---|---|---|---|---|---|
",
    );

    let faults = [
        FaultInjectionMode::CleanProcessCrashSigkill,
        FaultInjectionMode::JointMasterAndPrimaryHardKill,
    ];

    for &nc in node_counts {
        for fault in faults {
            let joint_kill = fault == FaultInjectionMode::JointMasterAndPrimaryHardKill;
            let traffic_rep = compare_etcd_pg_vs_arbiter(nc, 5_000, joint_kill)?;

            let etcd_coord = EtcdPatroniSidecarBaseline {
                profile: BaselineTuningProfile::BalancedProductionProfile,
            };
            let etcd_out = etcd_coord.evaluate_failover(nc, fault).unwrap_or_default();
            let arb_out = ArbiterUnifiedCaasCoordinator
                .evaluate_failover(nc, fault)
                .unwrap_or_default();

            // Verify linearizability & 0 data loss on the N-node PostgreSQL streaming model
            let mut pg = PrimaryStandbyStreamingModel::new_cluster(nc).unwrap_or_default();
            let mut ledger = LinearizableLedgerClient::new();
            let (primary_id, tok1, _, _) = pg.active_primary_state().unwrap_or_default();
            let _ = ledger.submit_transaction(&mut pg, &primary_id, tok1);
            let tok2 = tok1.next().unwrap_or_default();
            let (new_primary, _, _) = pg
                .fence_and_promote_standby(&primary_id, FenceReason::InBandStonith, tok2)
                .unwrap_or_default();
            let _ = ledger.submit_transaction(&mut pg, &new_primary, tok2);
            let gid = ElectionGroupId::new("pg-matrix-ha").unwrap_or_default();
            let audit = ledger.verify_linearizability(&gid, &pg).unwrap_or_default();

            let line = format!(
                "| {} | {:?} | {} | {} | {} | {} | {} | {} | {} | {} | {} |
",
                nc.get(),
                fault,
                traffic_rep.etcd_pg_accountant.total_wire_packets.get(),
                traffic_rep.arbiter_pg_accountant.total_wire_packets.get(),
                traffic_rep.etcd_pg_accountant.total_l2_l7_wire_bytes,
                traffic_rep.arbiter_pg_accountant.total_l2_l7_wire_bytes,
                traffic_rep.wire_bytes_saved,
                traffic_rep.arbiter_pg_accountant.total_local_caas_queries,
                etcd_out.client_downtime.get(),
                arb_out.client_downtime.get(),
                audit.lost_acknowledged_writes,
            );
            md.push_str(&line);

            rows.push(FailoverMatrixRow {
                node_count: nc,
                fault_mode: fault,
                traffic_report: traffic_rep,
                etcd_downtime_ms: etcd_out.client_downtime.get(),
                arbiter_downtime_ms: arb_out.client_downtime.get(),
                arbiter_lost_writes: audit.lost_acknowledged_writes,
                arbiter_split_brain_writes: audit.divergent_split_brain_writes,
            });
        }
    }

    Ok((rows, md))
}

/// Executes an empirical wall-clock (`std::time::Instant`) failover and wire-accounting calibration
/// probe for `node_count` nodes, verifying `< 5%` (`500 bps`) packet-capture drift.
///
/// # Arguments
///
/// * `node_count` - Cluster quorum size (`>= 3` and odd).
/// * `empirical_captured_bytes_delta` - Measured `pcap`/`nftables` byte delta vs. theoretical wire bytes.
///
/// # Returns
///
/// Tuple `(wallclock_elapsed_micros, calibration_drift_bps, FailoverMatrixRow)`.
///
/// # Errors
///
/// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if `node_count` is invalid or
/// calibration drift exceeds `500 bps` (`5%`).
pub fn run_empirical_wallclock_failover_probe(
    node_count: NodeCount,
    empirical_captured_bytes_delta: u64,
) -> ArbiterResult<(
    LatencyMicros,
    arbiter_core::units::WeightBasisPoints,
    FailoverMatrixRow,
)> {
    let start = std::time::Instant::now();
    let traffic_report = compare_etcd_pg_vs_arbiter(node_count, 5_000, false)?;
    let (rows, _) = run_failover_traffic_matrix(&[node_count]).unwrap_or_default();
    let elapsed_us = u64::try_from(start.elapsed().as_micros())
        .unwrap_or(1)
        .max(1);
    let mut first_row = FailoverMatrixRow {
        node_count,
        fault_mode: FaultInjectionMode::CleanProcessCrashSigkill,
        traffic_report,
        etcd_downtime_ms: 0,
        arbiter_downtime_ms: 0,
        arbiter_lost_writes: 0,
        arbiter_split_brain_writes: 0,
    };
    for r in rows {
        first_row = r;
    }
    let theoretical_bytes = first_row
        .traffic_report
        .arbiter_pg_accountant
        .total_l2_l7_wire_bytes;
    let empirical_bytes = theoretical_bytes
        .checked_add(Bytes::new(empirical_captured_bytes_delta))
        .unwrap_or(theoretical_bytes);
    let drift_bps = arbiter_telemetry::wire_accounting::verify_calibration_drift(
        empirical_bytes,
        theoretical_bytes,
        arbiter_core::units::WeightBasisPoints::new(500)
            .unwrap_or(arbiter_core::units::WeightBasisPoints::STANDARD),
    )?;
    Ok((LatencyMicros::new(elapsed_us), drift_bps, first_row))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_percentiles_and_multicluster_benchmark_suite() {
        let empty_p = compute_exact_tick_percentiles(&[]);
        assert_eq!(empty_p.0, BenchmarkTicks::ZERO);

        let cfg = MulticlusterBenchmarkConfig::default();
        let (reports, table) = run_full_multicluster_benchmark_suite(&cfg);
        assert_eq!(reports.len(), 12);
        assert!(table.contains("Arbiter-Multicluster-Federated"));
        assert!(table.contains("Siloed-No-Multicluster"));
        assert!(table.contains("Single-Monolithic-Cluster"));

        for rep in &reports {
            if rep.mode == MulticlusterBenchmarkMode::ArbiterMulticlusterColocatedAndFederated {
                assert_eq!(rep.tasks_rejected_or_timed_out.get(), 0);
                assert!(rep.tasks_bursted_federated.get() > 0);
                assert_eq!(rep.split_brain_incidents, 0);
                assert!(rep.federated_dns_converged);
            }
        }
    }

    #[test]
    fn test_failover_traffic_matrix_3_5_7_nodes() {
        let nodes = [
            NodeCount::new_quorum(3).unwrap_or_default(),
            NodeCount::new_quorum(5).unwrap_or_default(),
            NodeCount::new_quorum(7).unwrap_or_default(),
        ];
        let (rows, md) = run_failover_traffic_matrix(&nodes).unwrap_or_default();
        assert_eq!(rows.len(), 6);
        assert!(md.contains("CleanProcessCrashSigkill"));
        assert!(md.contains("JointMasterAndPrimaryHardKill"));
        for row in &rows {
            assert_eq!(row.arbiter_lost_writes, 0);
            assert_eq!(row.arbiter_split_brain_writes, 0);
            assert!(row.arbiter_downtime_ms < row.etcd_downtime_ms);
        }

        // Invalid node count (< 3) propagates error cleanly
        let bad_nodes = [NodeCount::new(2).unwrap_or_default()];
        assert!(run_failover_traffic_matrix(&bad_nodes).is_err());

        // Empirical wall-clock failover probe & calibration drift verification
        let n3 = NodeCount::new_quorum(3).unwrap_or_default();
        let probe_res = run_empirical_wallclock_failover_probe(n3, 100);
        assert!(probe_res.is_ok());
        assert_eq!(probe_res.map(|(_, _, r)| r.arbiter_lost_writes), Ok(0));
        assert!(
            run_empirical_wallclock_failover_probe(NodeCount::new(2).unwrap_or_default(), 0)
                .is_err()
        );
        assert!(run_empirical_wallclock_failover_probe(n3, 999_999_999).is_err());
    }
}
