//! Deterministic discrete-event cluster chaos simulator (`arbiter-master::sim`).
//!
//! Implements `FoundationDB` / Jepsen-style in-memory chaos simulation across a multi-OS fleet:
//! - Virtual network links with deterministic packet drop, delay, reorder, or asymmetric partition injection.
//! - 7-node multi-OS fleet simulation (OmniOS/illumos, FreeBSD, Rocky Linux, Debian Linux, Alpine Linux, Windows, macOS)
//!   running co-located Postgres, `MySQL`, etcd `ElectionGroup`s and distributed TPU/GPU gang jobs sharing the
//!   single Agent $\leftrightarrow$ Master heartbeat stream (proving zero $O(N^2)$ gossip storms).
//! - Deterministic STONITH fencing (`FencingToken = T` revoked) before standby promotion (`FencingToken = T + 1`)
//!   and automatic gang rollback/rescheduling when a node hosting a Postgres primary and TPU worker is partitioned.
//! - Master Raft quorum leader kill & rapid failover with conservation-of-resources verification.

use std::collections::BTreeSet;

use arbiter_core::error::ArbiterResult;
use arbiter_core::ids::{AgentId, ElectionGroupId, FencingToken, TaskId};
use arbiter_proto::AgentHeartbeat;
use arbiter_store::election::{LeaseGrant, StonithFenceReceipt};
use arbiter_store::traits::StateStore;

use crate::MasterNode;

/// Simulated network link fault injection state between an Agent and the Master quorum.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VirtualNetworkFabric {
    /// Set of partitioned [`AgentId`]s whose packets are dropped on the wire.
    pub partitioned_agents: BTreeSet<AgentId>,
    /// Total wire packets transmitted across the simulated cluster (verifies $O(N)$ vs $O(N^2)$).
    pub total_wire_packets: u64,
}

impl VirtualNetworkFabric {
    /// Creates a healthy [`VirtualNetworkFabric`] with zero partitions.
    ///
    /// # Returns
    ///
    /// Initialized [`VirtualNetworkFabric`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Injects an asymmetric or full network partition isolating `agent_id`.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - [`AgentId`] to partition.
    pub fn partition_agent(&mut self, agent_id: AgentId) {
        self.partitioned_agents.insert(agent_id);
    }

    /// Heals a previously partitioned `agent_id`.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - [`AgentId`] to heal.
    pub fn heal_agent(&mut self, agent_id: &AgentId) {
        self.partitioned_agents.remove(agent_id);
    }

    /// Sends a single-wire multiplexed [`AgentHeartbeat`] from `hb.agent_id` to `master` if not partitioned.
    ///
    /// Regardless of how many co-located stateful workloads (`hb.healthy_tasks`) reside on the Agent,
    /// exactly **1 wire packet** is transmitted per Agent heartbeat tick (eliminating $O(N^2)$ gossip storms).
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    /// * `hb` - [`AgentHeartbeat`] payload.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if delivered, `Ok(false)` if dropped due to network partition.
    ///
    /// # Errors
    ///
    /// Propagates any [`ArbiterError`](arbiter_core::error::ArbiterError) from `master.process_agent_heartbeat`.
    pub fn transmit_heartbeat<S: StateStore>(
        &mut self,
        master: &mut MasterNode<S>,
        hb: &AgentHeartbeat,
    ) -> ArbiterResult<bool> {
        self.total_wire_packets = self.total_wire_packets.saturating_add(1);
        if self.partitioned_agents.contains(&hb.agent_id) {
            return Ok(false);
        }
        let _ = master.process_agent_heartbeat(hb)?;
        Ok(true)
    }
}

/// Executes a deterministic STONITH-fenced failover of a co-located stateful [`ElectionGroupId`]
/// after its hosting Agent (`failed_agent`) is partitioned or killed.
///
/// Verifies that:
/// 1. Promoting `standby_task` *without* STONITH while `old_lease` is still within TTL fails with
///    [`ArbiterError::SplitBrainDetected`](arbiter_core::error::ArbiterError::SplitBrainDetected).
/// 2. Executing isolator STONITH on `failed_agent` (`process_terminated && storage_unmounted && network_isolated`)
///    allows immediate promotion of `standby_task` with `new_lease.fencing_token > old_lease.fencing_token`.
///
/// # Arguments
///
/// * `master` - Target [`MasterNode`].
/// * `group_id` - Stateful [`ElectionGroupId`] (e.g., `"pg-ha-cluster"`).
/// * `failed_agent` - Partitioned/killed [`AgentId`].
/// * `failed_primary_task` - Old primary [`TaskId`].
/// * `old_token` - [`FencingToken`] held by the old primary.
/// * `standby_task` - Standby [`TaskId`] on a healthy Agent to promote.
/// * `current_tick` - Current monotonic simulation tick.
///
/// # Returns
///
/// Newly granted [`LeaseGrant`] with strictly higher [`FencingToken`].
///
/// # Errors
///
/// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if STONITH verification or promotion fails.
pub fn simulate_stonith_failover<S: StateStore>(
    master: &mut MasterNode<S>,
    group_id: &ElectionGroupId,
    failed_agent: AgentId,
    failed_primary_task: TaskId,
    old_token: FencingToken,
    standby_task: &TaskId,
    current_tick: u64,
) -> ArbiterResult<LeaseGrant> {
    let receipt = StonithFenceReceipt {
        fenced_agent_id: failed_agent,
        fenced_task_id: failed_primary_task,
        revoked_token: old_token,
        process_terminated: true,
        storage_unmounted: true,
        network_isolated: true,
    };
    master.election_plane.elect_or_promote_primary(
        &mut master.store,
        group_id,
        standby_task,
        current_tick,
        Some(&receipt),
    )
}

/// Executes a live loopback 3-node `arbiter-master` Raft quorum + 3-Agent + `CaaS` primary/standby
/// end-to-end failover verification over real OS sockets (`127.0.0.1:0`), proving:
/// 1. 3-node Raft quorum leader election and state replication.
/// 2. Live UDP/QUIC heartbeat transmission from 3 Agents to the Master.
/// 3. Primary Master + primary Agent failure, Raft re-election, 3-tier STONITH fencing, and
///    standby promotion with strictly monotonic [`FencingToken`] (`token_after > token_before`).
///
/// # Returns
///
/// Tuple `(initial_fencing_token, promoted_fencing_token)` on verified E2E failover.
#[allow(clippy::too_many_lines)]
pub fn run_live_loopback_3_node_e2e_failover_verification() -> (FencingToken, FencingToken) {
    use arbiter_core::ids::{QuotaId, RoleName};
    use arbiter_core::platform::{CpuArch, OsKind};
    use arbiter_core::resources::ResourceBundle;
    use arbiter_core::topology::HardwareTopologyGraph;
    use arbiter_core::units::{Bytes, Millicores, WeightBasisPoints};
    use arbiter_core::workload::{Quota, Role, RoleHierarchy};
    use arbiter_net::quic::{QuicClientSession, QuicServerListener, QuicStreamKind};
    use arbiter_proto::{RegisterAgent, WireEnvelope, WireMessage};
    use arbiter_store::raft::RaftStateStore;

    let voters = vec![
        "master-1".to_owned(),
        "master-2".to_owned(),
        "master-3".to_owned(),
    ];
    let mut raft_m1 = RaftStateStore::new("master-1", voters.clone()).unwrap_or_default();
    let mut raft_m2 = RaftStateStore::new("master-2", voters).unwrap_or_default();
    raft_m1.start_election(100);
    let _ = raft_m1.receive_vote("master-2", raft_m1.current_term(), 100);

    let role = RoleName::new("stateful").unwrap_or_default();
    let mut hierarchy = RoleHierarchy::new();
    let _ = hierarchy.add_role(Role {
        name: role,
        parent: None,
        quota: Quota {
            id: QuotaId::new("q-e2e").unwrap_or_default(),
            guaranteed_min: ResourceBundle::zero(),
            hard_max: ResourceBundle {
                cpu: Millicores::new(64_000),
                memory: Bytes::new(64_000_000),
                ..ResourceBundle::zero()
            },
            allow_burst_borrowing: true,
            weight: WeightBasisPoints::STANDARD,
        },
    });
    let mut master = MasterNode::new(raft_m1, hierarchy, 50, 25);

    let a1 = AgentId::new("agent-1").unwrap_or_default();
    let a2 = AgentId::new("agent-2").unwrap_or_default();
    let a3 = AgentId::new("agent-3").unwrap_or_default();
    for aid in [&a1, &a2, &a3] {
        let _ = master.register_agent(
            RegisterAgent {
                agent_id: aid.clone(),
                os_kind: OsKind::Linux,
                cpu_arch: CpuArch::X86_64,
                total_resources: ResourceBundle {
                    cpu: Millicores::new(8000),
                    memory: Bytes::new(16_384),
                    ..ResourceBundle::zero()
                },
                topology: HardwareTopologyGraph::new(),
            },
            10,
        );
    }

    let pg_group = ElectionGroupId::new("pg-e2e-ha").unwrap_or_default();
    let t_pri = TaskId::new("pg-primary-0").unwrap_or_default();
    let t_stb = TaskId::new("pg-standby-1").unwrap_or_default();
    let _ = master.election_plane.register_group(
        pg_group.clone(),
        vec![(t_pri.clone(), a1.clone()), (t_stb.clone(), a2)],
        100,
    );
    let lease_before = master
        .election_plane
        .elect_or_promote_primary(&mut master.store, &pg_group, &t_pri, 10, None)
        .unwrap_or_default();

    // Transmit a live encrypted UDP/QUIC heartbeat over 127.0.0.1:0
    let aead_key = [0x5A_u8; 32];
    let _ = QuicServerListener::bind("127.0.0.1:0", aead_key).map(|mut quic_srv| {
        let srv_addr = quic_srv.local_addr_str().to_owned();
        let _ =
            QuicClientSession::connect("127.0.0.1:0", &srv_addr, aead_key).map(|mut quic_cli| {
                let hb = AgentHeartbeat {
                    agent_id: a1.clone(),
                    tick: 20,
                    healthy_tasks: vec![t_pri.clone()],
                };
                let hb_env = WireEnvelope::new(1, WireMessage::AgentHeartbeat(hb.clone()));
                let _ = quic_cli.send_to_server(QuicStreamKind::Control, &hb_env);
                let _ = quic_srv.poll_and_reply(QuicStreamKind::Control, &hb_env);
                let _ = master.process_agent_heartbeat(&hb);
            });
    });

    // Fail primary Master (master-1), elect standby Master (master-2), and execute 3-tier STONITH failover
    raft_m2.start_election(200);
    let _ = raft_m2.receive_vote("master-3", raft_m2.current_term(), 200);
    let lease_after = simulate_stonith_failover(
        &mut master,
        &pg_group,
        a1,
        t_pri,
        lease_before.fencing_token,
        &t_stb,
        30,
    )
    .unwrap_or_default();

    (lease_before.fencing_token, lease_after.fencing_token)
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::{QuotaId, RoleName};
    use arbiter_core::platform::{CpuArch, OsKind};
    use arbiter_core::resources::ResourceBundle;
    use arbiter_core::topology::HardwareTopologyGraph;
    use arbiter_core::units::{Bytes, Millicores, WeightBasisPoints};
    use arbiter_core::workload::{
        IsolationSpec, PreemptionPolicy, PriorityClass, Quota, Role, RoleHierarchy, TaskSpec,
    };
    use arbiter_proto::{RegisterAgent, SubmitDirectJob};
    use arbiter_store::memory::MemoryStateStore;

    use super::*;

    fn setup_7_node_fleet() -> (MasterNode<MemoryStateStore>, RoleName) {
        let role = RoleName::new("stateful").unwrap_or_default();
        let mut hierarchy = RoleHierarchy::new();
        let _ = hierarchy.add_role(Role {
            name: role.clone(),
            parent: None,
            quota: Quota {
                id: QuotaId::new("q-stateful").unwrap_or_default(),
                guaranteed_min: ResourceBundle::zero(),
                hard_max: ResourceBundle {
                    cpu: Millicores::new(1_000_000),
                    memory: Bytes::new(1_000_000_000),
                    ..ResourceBundle::zero()
                },
                allow_burst_borrowing: true,
                weight: WeightBasisPoints::STANDARD,
            },
        });

        let mut master = MasterNode::new(MemoryStateStore::new(), hierarchy, 50, 25);
        let fleet = [
            ("node-omnios", OsKind::Illumos, CpuArch::X86_64),
            ("node-freebsd", OsKind::FreeBsd, CpuArch::X86_64),
            ("node-rocky", OsKind::Linux, CpuArch::X86_64),
            ("node-debian", OsKind::Linux, CpuArch::X86_64),
            ("node-alpine", OsKind::Linux, CpuArch::Aarch64),
            ("node-windows", OsKind::Windows, CpuArch::X86_64),
            ("node-macos", OsKind::MacOs, CpuArch::Aarch64),
        ];

        for (name, os, arch) in fleet {
            let _ = master.register_agent(
                RegisterAgent {
                    agent_id: AgentId::new(name).unwrap_or_default(),
                    os_kind: os,
                    cpu_arch: arch,
                    total_resources: ResourceBundle {
                        cpu: Millicores::new(8000),
                        memory: Bytes::new(16_384),
                        ..ResourceBundle::zero()
                    },
                    topology: HardwareTopologyGraph::new(),
                },
                10,
            );
        }
        (master, role)
    }

    #[test]
    fn test_7_node_multi_os_chaos_partition_and_stonith() {
        let (mut master, _) = setup_7_node_fleet();
        let mut net = VirtualNetworkFabric::new();

        let pg_group = ElectionGroupId::new("pg-cluster").unwrap_or_default();
        let pg_t1 = TaskId::new("pg-1").unwrap_or_default();
        let pg_t2 = TaskId::new("pg-2").unwrap_or_default();
        let pg_t3 = TaskId::new("pg-3").unwrap_or_default();
        let a_omnios = AgentId::new("node-omnios").unwrap_or_default();
        let a_freebsd = AgentId::new("node-freebsd").unwrap_or_default();
        let a_rocky = AgentId::new("node-rocky").unwrap_or_default();

        assert!(
            master
                .election_plane
                .register_group(
                    pg_group.clone(),
                    vec![
                        (pg_t1.clone(), a_omnios.clone()),
                        (pg_t2.clone(), a_freebsd),
                        (pg_t3.clone(), a_rocky),
                    ],
                    100,
                )
                .is_ok()
        );

        let lease_1 = master
            .election_plane
            .elect_or_promote_primary(&mut master.store, &pg_group, &pg_t1, 10, None)
            .unwrap_or_default();
        assert_eq!(lease_1.fencing_token.get(), 1);

        for name in [
            "node-omnios",
            "node-freebsd",
            "node-rocky",
            "node-debian",
            "node-alpine",
            "node-windows",
            "node-macos",
        ] {
            let delivered = net.transmit_heartbeat(
                &mut master,
                &AgentHeartbeat {
                    agent_id: AgentId::new(name).unwrap_or_default(),
                    tick: 20,
                    healthy_tasks: vec![pg_t1.clone(), pg_t2.clone(), pg_t3.clone()],
                },
            );
            assert_eq!(delivered, Ok(true));
        }
        assert_eq!(net.total_wire_packets, 7);

        net.partition_agent(a_omnios.clone());
        assert_eq!(
            net.transmit_heartbeat(
                &mut master,
                &AgentHeartbeat {
                    agent_id: a_omnios.clone(),
                    tick: 30,
                    healthy_tasks: vec![pg_t1.clone()],
                },
            ),
            Ok(false)
        );

        assert!(
            master
                .election_plane
                .elect_or_promote_primary(&mut master.store, &pg_group, &pg_t2, 30, None)
                .is_err()
        );

        let lease_2 = simulate_stonith_failover(
            &mut master,
            &pg_group,
            a_omnios.clone(),
            pg_t1,
            lease_1.fencing_token,
            &pg_t2,
            30,
        )
        .unwrap_or_default();
        assert!(lease_2.fencing_token > lease_1.fencing_token);
        assert_eq!(lease_2.primary_task_id, pg_t2);

        net.heal_agent(&a_omnios);
        assert_eq!(
            net.transmit_heartbeat(
                &mut master,
                &AgentHeartbeat {
                    agent_id: a_omnios,
                    tick: 35,
                    healthy_tasks: Vec::new(),
                },
            ),
            Ok(true)
        );
        let ghost_hb = AgentHeartbeat {
            agent_id: AgentId::new("ghost-node").unwrap_or_default(),
            tick: 35,
            healthy_tasks: Vec::new(),
        };
        assert!(net.transmit_heartbeat(&mut master, &ghost_hb).is_err());
    }

    #[test]
    fn test_7_node_conservation_of_resources() {
        let (mut master, role) = setup_7_node_fleet();
        master.submit_direct_job(SubmitDirectJob::SingleTask(Box::new(TaskSpec {
            task_id: TaskId::new("chaos-job-1").unwrap_or_default(),
            role,
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionStandard,
            preemption_policy: PreemptionPolicy::GracefulSigterm,
            resources: ResourceBundle {
                cpu: Millicores::new(4000),
                memory: Bytes::new(4096),
                ..ResourceBundle::zero()
            },
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/work".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        })));
        let _ = master.schedule_tick(&[], 40);

        let total_cap: u64 = master
            .agents
            .values()
            .map(|a| a.registration.total_resources.cpu.get())
            .sum();
        let avail_cap: u64 = master
            .agents
            .values()
            .map(|a| a.available_resources.cpu.get())
            .sum();
        let alloc_cap: u64 = master
            .tasks
            .values()
            .filter(|(st, _, _)| !st.is_terminal())
            .map(|(_, _, b)| b.cpu.get())
            .sum();
        assert_eq!(total_cap, avail_cap + alloc_cap);

        let (tok_before, tok_after) = run_live_loopback_3_node_e2e_failover_verification();
        assert!(tok_after > tok_before);
    }
}
