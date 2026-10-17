//! Multi-host gang scheduler and TPU Pod co-scheduler (`arbiter-alloc::gang`).
//!
//! Implements atomic all-or-nothing gang placement for [`TaskGroupSpec`] workloads across
//! multiple Agents:
//! - Supports homogeneous and heterogeneous gang members (e.g., Parameter Servers + Workers, MPI ranks).
//! - Matches multi-host Google Cloud TPU Pod slices (e.g., finding a healthy contiguous 2D/3D torus
//!   of TPU v4/v5e/v5p/v6e chips with intact ICI links across multiple hosts).
//! - Enforces deadlock prevention via strict global lexicographical [`AgentId`] lock/reservation
//!   ordering and TTL lease expiration with automatic rollback on partial failure.

use std::collections::{BTreeMap, BTreeSet};

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, DeviceId, TaskGroupId, TaskId};
use arbiter_core::resources::{TorusCoordinate, TpuDevice, TpuTopologySlice};
use arbiter_core::workload::{TaskGroupSpec, TopologyConstraint};
use serde::{Deserialize, Serialize};

use crate::topology_packer::{AgentHardwareInventory, TopologyPlacementPlan, pack_task_on_agent};

/// Extended Agent inventory including available TPU chips for gang/Pod co-scheduling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GangAgentCandidate {
    /// Standard CPU/Memory/GPU/RDMA inventory for this Agent.
    pub hardware: AgentHardwareInventory,
    /// Available physical TPU chips on this Agent.
    pub tpu_devices: Vec<TpuDevice>,
}

/// Optimistic two-phase reservation lease produced during gang scheduling.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GangReservation {
    /// Task group identifier owning this reservation.
    pub group_id: TaskGroupId,
    /// Per-task placement plans ordered deterministically by task index.
    pub member_placements: Vec<(TaskId, TopologyPlacementPlan)>,
    /// Assigned TPU chip device IDs and torus coordinates if a [`TpuTopologySlice`] was requested.
    pub assigned_tpu_torus: Vec<(AgentId, DeviceId, TorusCoordinate)>,
    /// Sorted list of locked [`AgentId`]s (strict global ordering for deadlock prevention).
    pub locked_agents_ordered: Vec<AgentId>,
    /// Monotonic tick at which this optimistic reservation expires if not committed.
    pub lease_expires_at_tick: u64,
}

impl GangReservation {
    /// Checks whether this optimistic reservation has expired at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic scheduler tick.
    ///
    /// # Returns
    ///
    /// `true` if `current_tick >= self.lease_expires_at_tick`.
    pub const fn is_expired(&self, current_tick: u64) -> bool {
        current_tick >= self.lease_expires_at_tick
    }
}

/// Matches a contiguous 3D torus of healthy [`TpuDevice`]s of dimensions `(dim_x, dim_y, dim_z)`
/// starting at origin `(0, 0, 0)` across the candidate Agents.
///
/// # Arguments
///
/// * `slice_req` - Required [`TpuTopologySlice`] specification.
/// * `candidates` - Sorted slice of [`GangAgentCandidate`]s.
///
/// # Returns
///
/// Vector of `(AgentId, DeviceId, TorusCoordinate)` for all `dim_x * dim_y * dim_z` chips.
///
/// # Errors
///
/// Returns [`ArbiterError::InvalidTpuTopologySlice`] if any torus coordinate is missing, unhealthy,
/// wrong generation, or lacks required wrap-around ICI links.
pub fn match_contiguous_tpu_torus(
    slice_req: &TpuTopologySlice,
    candidates: &[GangAgentCandidate],
) -> ArbiterResult<Vec<(AgentId, DeviceId, TorusCoordinate)>> {
    let mut coord_map: BTreeMap<TorusCoordinate, (AgentId, DeviceId)> = BTreeMap::new();
    for agent in candidates {
        for chip in &agent.tpu_devices {
            if chip.generation == slice_req.generation
                && chip.ici_links_healthy
                && (!slice_req.require_wrap_around || chip.wrap_around_links)
            {
                coord_map.insert(
                    chip.coordinate,
                    (agent.hardware.agent_id.clone(), chip.device_id.clone()),
                );
            }
        }
    }

    let mut matched = Vec::new();
    for x in 0..slice_req.dim_x {
        for y in 0..slice_req.dim_y {
            for z in 0..slice_req.dim_z {
                let target_coord = TorusCoordinate { x, y, z };
                let Some((agent_id, dev_id)) = coord_map.get(&target_coord) else {
                    return Err(ArbiterError::InvalidTpuTopologySlice {
                        slice: slice_req.slice_id.to_string(),
                        reason: format!(
                            "missing or unhealthy TPU chip at torus coordinate ({x}, {y}, {z})"
                        ),
                    });
                };
                matched.push((agent_id.clone(), dev_id.clone(), target_coord));
            }
        }
    }

    Ok(matched)
}

/// Atomically places all tasks in a [`TaskGroupSpec`] across `candidates` using optimistic
/// two-phase reservation and strict global [`AgentId`] ordering.
///
/// If any task member or TPU torus constraint cannot be satisfied, all tentative allocations
/// are rolled back (the original `candidates` remain untouched) and an [`ArbiterError`] is returned.
///
/// # Arguments
///
/// * `group` - The [`TaskGroupSpec`] to co-schedule.
/// * `candidates` - Available [`GangAgentCandidate`]s in the cluster.
/// * `current_tick` - Current monotonic scheduler tick for TTL computation.
///
/// # Returns
///
/// Tuple `(GangReservation, Vec<GangAgentCandidate>)` containing the atomic reservation and the
/// updated post-deduction agent inventories.
///
/// # Errors
///
/// Returns:
/// - [`ArbiterError::GangConstraintUnsatisfied`] if fewer than `group.tasks.len()` members can be placed.
/// - [`ArbiterError::InvalidTpuTopologySlice`] if `group.tpu_slice` cannot be formed.
pub fn schedule_gang_atomic(
    group: &TaskGroupSpec,
    candidates: &[GangAgentCandidate],
    current_tick: u64,
) -> ArbiterResult<(GangReservation, Vec<GangAgentCandidate>)> {
    // Sort candidates deterministically by AgentId to guarantee deadlock-free global acquisition order.
    let mut working_pool: Vec<GangAgentCandidate> = candidates.to_vec();
    working_pool.sort_by(|a, b| a.hardware.agent_id.cmp(&b.hardware.agent_id));

    // 1. If a Pod-level TPU torus slice is requested, verify and match it first.
    let assigned_tpu_torus = if let Some(ref slice_req) = group.tpu_slice {
        match_contiguous_tpu_torus(slice_req, &working_pool)?
    } else {
        Vec::new()
    };

    // 2. Place each member task sequentially onto the working pool, respecting AntiAffinityHost.
    let mut member_placements: Vec<(TaskId, TopologyPlacementPlan)> =
        Vec::with_capacity(group.tasks.len());
    let mut used_hosts: BTreeSet<AgentId> = BTreeSet::new();

    for task in &group.tasks {
        let require_anti_affinity = task
            .topology_constraints
            .iter()
            .any(|c| matches!(c, TopologyConstraint::AntiAffinityHost));

        let mut placed_on_idx: Option<(usize, TopologyPlacementPlan)> = None;
        for (idx, candidate) in working_pool.iter().enumerate() {
            if require_anti_affinity && used_hosts.contains(&candidate.hardware.agent_id) {
                continue;
            }
            if let Ok(plan) = pack_task_on_agent(task, &candidate.hardware) {
                placed_on_idx = Some((idx, plan));
                break;
            }
        }

        let Some((chosen_idx, plan)) = placed_on_idx else {
            // Rollback happens automatically by dropping `working_pool` and `member_placements`.
            return Err(ArbiterError::GangConstraintUnsatisfied {
                group_id: group.group_id.to_string(),
                placed: member_placements.len(),
                required: group.tasks.len(),
            });
        };

        // Deduct allocated bundle from the chosen candidate in working_pool.
        for (idx, candidate) in working_pool.iter_mut().enumerate() {
            if idx == chosen_idx {
                candidate.hardware.available_bundle = candidate
                    .hardware
                    .available_bundle
                    .try_sub(&task.resources)
                    .unwrap_or_default();
            }
        }

        used_hosts.insert(plan.agent_id.clone());
        member_placements.push((task.task_id.clone(), plan));
    }

    for (agent_id, _, _) in &assigned_tpu_torus {
        used_hosts.insert(agent_id.clone());
    }

    // BTreeSet iteration yields strictly sorted AgentIds for deadlock-free lock acquisition.
    let locked_agents_ordered: Vec<AgentId> = used_hosts.into_iter().collect();
    let lease_expires_at_tick = current_tick.saturating_add(group.placement_timeout_ms);

    let reservation = GangReservation {
        group_id: group.group_id.clone(),
        member_placements,
        assigned_tpu_torus,
        locked_agents_ordered,
        lease_expires_at_tick,
    };

    Ok((reservation, working_pool))
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::{RoleName, SliceId};
    use arbiter_core::resources::{ResourceBundle, TpuGeneration};
    use arbiter_core::topology::HardwareTopologyGraph;
    use arbiter_core::units::{Bytes, GpuMillicores, Millicores, TpuChips};
    use arbiter_core::workload::{IsolationSpec, PreemptionPolicy, PriorityClass, TaskSpec};

    use super::*;

    fn make_task(id_str: &str, cpu_m: u64, anti_affinity: bool) -> TaskSpec {
        let mut constraints = Vec::new();
        if anti_affinity {
            constraints.push(TopologyConstraint::AntiAffinityHost);
        }
        TaskSpec {
            task_id: TaskId::new(id_str).unwrap_or_default(),
            role: RoleName::new("ml-gang").unwrap_or_default(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionHigh,
            preemption_policy: PreemptionPolicy::CheckpointAndSuspend,
            resources: ResourceBundle {
                cpu: Millicores::new(cpu_m),
                memory: Bytes::new(1024),
                ..ResourceBundle::zero()
            },
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: constraints,
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/worker".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        }
    }

    fn make_candidate(agent_name: &str, cpu_m: u64, tpus: Vec<TpuDevice>) -> GangAgentCandidate {
        GangAgentCandidate {
            hardware: AgentHardwareInventory {
                agent_id: AgentId::new(agent_name).unwrap_or_default(),
                available_bundle: ResourceBundle {
                    cpu: Millicores::new(cpu_m),
                    memory: Bytes::new(1_000_000),
                    gpu_compute: GpuMillicores::ZERO,
                    tpu_chips: TpuChips::new(tpus.len() as u64),
                    ..ResourceBundle::zero()
                },
                numa_domains: Vec::new(),
                gpus: Vec::new(),
                rdma_nics: Vec::new(),
                topology: HardwareTopologyGraph::new(),
            },
            tpu_devices: tpus,
        }
    }

    #[test]
    fn test_gang_placement_anti_affinity_deadlock_order_and_rollback() {
        // Provide candidates in reverse order; agent-01 has 8_000m (too small for rank-0 needing 10_000m),
        // agent-02 and agent-03 have 16_000m.
        let c3 = make_candidate("agent-03", 16_000, Vec::new());
        let c2 = make_candidate("agent-02", 16_000, Vec::new());
        let c1 = make_candidate("agent-01", 8_000, Vec::new());
        let candidates = vec![c3, c2, c1];

        let group = TaskGroupSpec {
            group_id: TaskGroupId::new("gang-mpi-1").unwrap_or_default(),
            role: RoleName::new("ml-gang").unwrap_or_default(),
            tasks: vec![
                make_task("rank-0", 10_000, true),
                make_task("rank-1", 10_000, true),
            ],
            tpu_slice: None,
            placement_timeout_ms: 500,
        };

        let (reservation, updated_pool) =
            schedule_gang_atomic(&group, &candidates, 100).unwrap_or_default();
        assert_eq!(reservation.member_placements.len(), 2);
        assert_eq!(
            reservation.locked_agents_ordered,
            vec![
                AgentId::new("agent-02").unwrap_or_default(),
                AgentId::new("agent-03").unwrap_or_default()
            ]
        );
        assert!(!reservation.is_expired(599));
        assert!(reservation.is_expired(600));
        assert_eq!(
            updated_pool.get(1).map(|c| c.hardware.available_bundle.cpu),
            Some(Millicores::new(6_000))
        );

        // Partial failure rollback: 3 anti-affinity ranks needing 10_000m when only 2 agents have >= 10_000m
        let mut group_fail = group;
        group_fail.tasks.push(make_task("rank-2", 10_000, true));
        assert_eq!(
            schedule_gang_atomic(&group_fail, &candidates, 100),
            Err(ArbiterError::GangConstraintUnsatisfied {
                group_id: "gang-mpi-1".to_owned(),
                placed: 2,
                required: 3,
            })
        );
    }

    #[test]
    fn test_tpu_torus_contiguity_matching() {
        let slice_id = SliceId::new("slice-v5p-2x2x1").unwrap_or_default();
        let mut chips = Vec::new();
        for x in 0..2 {
            for y in 0..2 {
                chips.push(TpuDevice {
                    device_id: DeviceId::new(&format!("tpu-{x}-{y}")).unwrap_or_default(),
                    generation: TpuGeneration::CloudTpuV5p,
                    chip_index: x * 2 + y,
                    hbm_bytes: Bytes::new(96 * 1024 * 1024 * 1024),
                    coordinate: TorusCoordinate { x, y, z: 0 },
                    ici_links_healthy: true,
                    wrap_around_links: true,
                    slice_id: slice_id.clone(),
                });
            }
        }

        let agent = make_candidate("agent-tpu-1", 32_000, chips);
        let slice_req = TpuTopologySlice {
            slice_id,
            generation: TpuGeneration::CloudTpuV5p,
            dim_x: 2,
            dim_y: 2,
            dim_z: 1,
            require_wrap_around: true,
        };

        let group = TaskGroupSpec {
            group_id: TaskGroupId::new("tpu-pod-job").unwrap_or_default(),
            role: RoleName::new("ml-gang").unwrap_or_default(),
            tasks: vec![make_task("tpu-worker-0", 8_000, false)],
            tpu_slice: Some(slice_req.clone()),
            placement_timeout_ms: 1000,
        };

        let scheduled = schedule_gang_atomic(&group, &[agent.clone()], 10);
        assert!(scheduled.is_ok());

        // Break ICI link health on one chip -> must reject slice via schedule_gang_atomic too
        let mut broken_agent = agent;
        for (idx, chip) in broken_agent.tpu_devices.iter_mut().enumerate() {
            if idx == 0 {
                chip.ici_links_healthy = false;
            } else if idx == 1 {
                chip.wrap_around_links = false;
            } else if idx == 2 {
                chip.generation = TpuGeneration::CloudTpuV4;
            }
        }
        assert!(schedule_gang_atomic(&group, &[broken_agent.clone()], 10).is_err());

        // Also test require_wrap_around == false branch
        let mut relaxed_slice = slice_req;
        relaxed_slice.require_wrap_around = false;
        assert!(match_contiguous_tpu_torus(&relaxed_slice, &[broken_agent]).is_err());
    }
}
