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

use crate::topology_packer::{
    AgentHardwareInventory, AgentSchedulingProfile, TopologyPlacementPlan,
    pack_task_on_agent_with_profile,
};

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

/// Gang co-scheduling barrier constraint (`GangConstraint`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GangConstraint {
    /// Gang group identifier.
    pub group_id: TaskGroupId,
    /// Minimum number of placed members required to launch (`min_members <= total_members`).
    pub min_members: usize,
    /// Total desired members in the gang.
    pub total_members: usize,
    /// Maximum duration in ticks to hold partial gang claims before atomic rollback.
    pub holding_timeout_ticks: u64,
}

/// Active partial gang reservation hold state supporting short-task backfilling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GangBarrierHoldState {
    /// Governing [`GangConstraint`].
    pub constraint: GangConstraint,
    /// Partial placements currently held across agents.
    pub held_placements: Vec<(TaskId, TopologyPlacementPlan)>,
    /// Monotonic tick when the barrier hold expires (`started_at_tick + holding_timeout_ticks`).
    pub barrier_expires_at_tick: u64,
}

impl GangBarrierHoldState {
    /// Checks whether a short single-node backfill task with `estimated_runtime_ticks` can run on
    /// resources held by this gang barrier before `barrier_expires_at_tick`.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic scheduler tick.
    /// * `estimated_runtime_ticks` - Estimated execution duration of the backfill task (`> 0`).
    ///
    /// # Returns
    ///
    /// `true` if `estimated_runtime_ticks > 0` and `current_tick + estimated_runtime_ticks < self.barrier_expires_at_tick`.
    pub const fn admits_backfill_task(
        &self,
        current_tick: u64,
        estimated_runtime_ticks: u64,
    ) -> bool {
        estimated_runtime_ticks > 0
            && current_tick.saturating_add(estimated_runtime_ticks) < self.barrier_expires_at_tick
    }

    /// Checks whether the partial gang hold has satisfied `min_members` or expired at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic scheduler tick.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if `held_placements.len() >= constraint.min_members`, `Ok(false)` if still waiting
    /// before timeout, or `Err(ArbiterError::GangConstraintUnsatisfied)` if the barrier timeout expired
    /// before `min_members` could be assembled (triggering atomic release of held claims).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::GangConstraintUnsatisfied`] when `current_tick >= self.barrier_expires_at_tick`
    /// and `self.held_placements.len() < self.constraint.min_members`.
    pub fn evaluate_barrier_or_release(&self, current_tick: u64) -> ArbiterResult<bool> {
        if self.held_placements.len() >= self.constraint.min_members {
            return Ok(true);
        }
        if current_tick >= self.barrier_expires_at_tick {
            return Err(ArbiterError::GangConstraintUnsatisfied {
                group_id: self.constraint.group_id.to_string(),
                placed: self.held_placements.len(),
                required: self.constraint.min_members,
            });
        }
        Ok(false)
    }
}

/// Matches a contiguous 3D torus of healthy [`TpuDevice`]s of dimensions `(dim_x, dim_y, dim_z)`.
///
/// Searches origin `(0, 0, 0)` first and then any shifted sub-torus origin `(x0, y0, z0)`
/// present in `candidates`.
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

    let mut candidate_origins = vec![TorusCoordinate { x: 0, y: 0, z: 0 }];
    for &coord in coord_map.keys() {
        if coord != (TorusCoordinate { x: 0, y: 0, z: 0 }) {
            candidate_origins.push(coord);
        }
    }

    let mut first_missing: Option<TorusCoordinate> = None;
    for origin in candidate_origins {
        let mut matched = Vec::new();
        let mut missing_coord: Option<TorusCoordinate> = None;
        for dx in 0..slice_req.dim_x {
            for dy in 0..slice_req.dim_y {
                for dz in 0..slice_req.dim_z {
                    let target_coord = TorusCoordinate {
                        x: origin.x.saturating_add(dx),
                        y: origin.y.saturating_add(dy),
                        z: origin.z.saturating_add(dz),
                    };
                    if let Some((agent_id, dev_id)) = coord_map.get(&target_coord) {
                        matched.push((agent_id.clone(), dev_id.clone(), target_coord));
                    } else {
                        missing_coord = Some(target_coord);
                        break;
                    }
                }
                if missing_coord.is_some() {
                    break;
                }
            }
            if missing_coord.is_some() {
                break;
            }
        }
        if missing_coord.is_none() {
            return Ok(matched);
        }
        if first_missing.is_none() {
            first_missing = missing_coord;
        }
    }

    let miss = first_missing.unwrap_or(TorusCoordinate { x: 0, y: 0, z: 0 });
    Err(ArbiterError::InvalidTpuTopologySlice {
        slice: slice_req.slice_id.to_string(),
        reason: format!(
            "missing or unhealthy TPU chip at torus coordinate ({}, {}, {})",
            miss.x, miss.y, miss.z
        ),
    })
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
    schedule_gang_atomic_with_profiles(group, candidates, &BTreeMap::new(), current_tick)
}

/// Atomically places all tasks in a [`TaskGroupSpec`] across `candidates` while enforcing `profiles`.
///
/// # Arguments
///
/// * `group` - The [`TaskGroupSpec`] to co-schedule.
/// * `candidates` - Available [`GangAgentCandidate`]s in the cluster.
/// * `profiles` - Optional map of per-Agent [`AgentSchedulingProfile`]s.
/// * `current_tick` - Current monotonic scheduler tick for TTL computation.
///
/// # Returns
///
/// Tuple `(GangReservation, Vec<GangAgentCandidate>)`.
///
/// # Errors
///
/// Returns [`ArbiterError::GangConstraintUnsatisfied`] or [`ArbiterError::InvalidTpuTopologySlice`] on failure.
pub fn schedule_gang_atomic_with_profiles(
    group: &TaskGroupSpec,
    candidates: &[GangAgentCandidate],
    profiles: &BTreeMap<AgentId, AgentSchedulingProfile>,
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

    // 2. Place each member task sequentially onto the working pool, respecting AntiAffinityHost and PlacementConstraint counts.
    let mut member_placements: Vec<(TaskId, TopologyPlacementPlan)> =
        Vec::with_capacity(group.tasks.len());
    let mut used_hosts: BTreeSet<AgentId> = BTreeSet::new();
    let mut host_task_counts: BTreeMap<AgentId, u32> = BTreeMap::new();
    let mut zone_task_counts: BTreeMap<String, u32> = BTreeMap::new();

    for task in &group.tasks {
        let require_anti_affinity = task
            .topology_constraints
            .iter()
            .any(|c| matches!(c, TopologyConstraint::AntiAffinityHost));

        let mut placed_on_idx: Option<(usize, TopologyPlacementPlan)> = None;
        for (idx, candidate) in working_pool.iter().enumerate() {
            let aid = &candidate.hardware.agent_id;
            if require_anti_affinity && used_hosts.contains(aid) {
                continue;
            }
            let mut effective_profile = profiles.get(aid).cloned().unwrap_or_default();
            let added_host = host_task_counts.get(aid).copied().unwrap_or(0);
            effective_profile.existing_tasks_on_host = effective_profile
                .existing_tasks_on_host
                .saturating_add(added_host);
            let zone_key = effective_profile
                .domain_info
                .as_ref()
                .map_or_else(String::new, |d| d.fault_domain.zone.as_str().to_owned());
            let added_zone = zone_task_counts.get(&zone_key).copied().unwrap_or(0);
            effective_profile.existing_tasks_in_zone = effective_profile
                .existing_tasks_in_zone
                .saturating_add(added_zone);

            if let Ok(plan) =
                pack_task_on_agent_with_profile(task, &candidate.hardware, &effective_profile)
            {
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

        // Deduct allocated bundle, NUMA capacity, and per-GPU capacity from the chosen candidate.
        for (idx, candidate) in working_pool.iter_mut().enumerate() {
            if idx == chosen_idx {
                candidate.hardware.apply_placement_deduction(task, &plan);
            }
        }

        let zone_key = profiles
            .get(&plan.agent_id)
            .and_then(|p| p.domain_info.as_ref())
            .map_or_else(String::new, |d| d.fault_domain.zone.as_str().to_owned());
        *host_task_counts.entry(plan.agent_id.clone()).or_insert(0) += 1;
        *zone_task_counts.entry(zone_key).or_insert(0) += 1;
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

/// Computes the aggregate communication hop cost across all placed gang members in `reservation`.
///
/// Pairs of tasks placed on:
/// - The **same Agent host** incur `0` inter-host fabric penalty (or `10` if no `NVLink` / `PCIe` switch affinity).
/// - The **same availability zone / rack** (`DomainInfo.fault_domain.zone` matches) incur `100` cost units.
/// - The **same geographic region** (`DomainInfo.fault_domain.region` matches, different zone) incur `500` cost units.
/// - **Different geographic regions** incur `5_000` cost units.
///
/// # Arguments
///
/// * `reservation` - Completed [`GangReservation`].
/// * `profiles` - Map of per-Agent [`AgentSchedulingProfile`]s containing [`arbiter_core::workload::DomainInfo`].
///
/// # Returns
///
/// Total pairwise communication cost in deterministic integer units (lower means tighter fabric locality).
pub fn compute_gang_fabric_communication_cost(
    reservation: &GangReservation,
    profiles: &BTreeMap<AgentId, AgentSchedulingProfile>,
) -> u64 {
    let mut total_cost = 0_u64;
    for (i, (_, plan_a)) in reservation.member_placements.iter().enumerate() {
        for (_, plan_b) in reservation.member_placements.iter().skip(i + 1) {
            let pair_cost = if plan_a.agent_id == plan_b.agent_id {
                if plan_a.affinity_score.min(plan_b.affinity_score) >= 900 {
                    0
                } else {
                    10
                }
            } else {
                let dom_a = profiles
                    .get(&plan_a.agent_id)
                    .and_then(|p| p.domain_info.as_ref());
                let dom_b = profiles
                    .get(&plan_b.agent_id)
                    .and_then(|p| p.domain_info.as_ref());
                match (dom_a, dom_b) {
                    (Some(da), Some(db)) if da.fault_domain.zone == db.fault_domain.zone => 100,
                    (Some(da), Some(db)) if !da.is_remote_region(db) => 500,
                    _ => 5_000,
                }
            };
            total_cost = total_cost.saturating_add(pair_cost);
        }
    }
    total_cost
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

        // Shifted non-origin 2x2x1 sub-torus at origin (2, 2, 0) also matches!
        let mut shifted_chips = Vec::new();
        for x in 2..4 {
            for y in 2..4 {
                shifted_chips.push(TpuDevice {
                    device_id: DeviceId::new(&format!("tpu-shift-{x}-{y}")).unwrap_or_default(),
                    generation: TpuGeneration::CloudTpuV5p,
                    chip_index: x * 4 + y,
                    hbm_bytes: Bytes::new(96 * 1024 * 1024 * 1024),
                    coordinate: TorusCoordinate { x, y, z: 0 },
                    ici_links_healthy: true,
                    wrap_around_links: true,
                    slice_id: slice_req.slice_id.clone(),
                });
            }
        }
        let shifted_agent = make_candidate("agent-tpu-shifted", 32_000, shifted_chips);
        let shifted_matched =
            match_contiguous_tpu_torus(&slice_req, &[shifted_agent]).unwrap_or_default();
        assert_eq!(shifted_matched.len(), 4);
        assert_eq!(
            shifted_matched.first().map(|(_, _, c)| *c),
            Some(TorusCoordinate { x: 2, y: 2, z: 0 })
        );

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

    #[test]
    fn test_gang_with_profiles_and_fault_domain_spread() {
        use arbiter_core::ids::{RegionName, ZoneName};
        use arbiter_core::workload::{DomainInfo, PlacementConstraint};

        use crate::topology_packer::TaskSchedulingRequirements;

        let c1 = make_candidate("agent-01", 32_000, Vec::new());
        let c2 = make_candidate("agent-02", 32_000, Vec::new());
        let mut profiles = BTreeMap::new();
        profiles.insert(
            c1.hardware.agent_id.clone(),
            AgentSchedulingProfile {
                domain_info: Some(DomainInfo::new(
                    RegionName::new("us-east-1").unwrap_or_default(),
                    ZoneName::new("zone-a").unwrap_or_default(),
                )),
                ..AgentSchedulingProfile::default()
            },
        );
        profiles.insert(
            c2.hardware.agent_id.clone(),
            AgentSchedulingProfile {
                domain_info: Some(DomainInfo::new(
                    RegionName::new("us-east-1").unwrap_or_default(),
                    ZoneName::new("zone-b").unwrap_or_default(),
                )),
                ..AgentSchedulingProfile::default()
            },
        );

        let mut t0 = make_task("rank-0", 4_000, false);
        let mut t1 = make_task("rank-1", 4_000, false);
        let reqs = TaskSchedulingRequirements {
            placement_constraints: vec![PlacementConstraint::MaxPerFaultDomain(1)],
            ..TaskSchedulingRequirements::default()
        };
        reqs.attach_to_task(&mut t0);
        reqs.attach_to_task(&mut t1);

        let group = TaskGroupSpec {
            group_id: TaskGroupId::new("gang-zone-spread").unwrap_or_default(),
            role: RoleName::new("ml-gang").unwrap_or_default(),
            tasks: vec![t0, t1],
            tpu_slice: None,
            placement_timeout_ms: 500,
        };
        let (gang_reservation, _) =
            schedule_gang_atomic_with_profiles(&group, &[c1, c2], &profiles, 10)
                .unwrap_or_default();
        assert_eq!(gang_reservation.locked_agents_ordered.len(), 2);
        // Same region ("us-east-1"), different zones ("zone-a" vs "zone-b") -> 500 cost units
        assert_eq!(
            compute_gang_fabric_communication_cost(&gang_reservation, &profiles),
            500
        );
    }

    #[test]
    fn test_compute_gang_fabric_communication_cost() {
        use arbiter_core::ids::{RegionName, ZoneName};
        use arbiter_core::workload::DomainInfo;

        let mut profiles = BTreeMap::new();
        let a1 = AgentId::new("agent-01").unwrap_or_default();
        let a2 = AgentId::new("agent-02").unwrap_or_default();
        let a3 = AgentId::new("agent-03").unwrap_or_default();
        let a4 = AgentId::new("agent-04").unwrap_or_default();
        for (aid, reg, zone) in [
            (&a1, "us-east-1", "zone-a"),
            (&a2, "us-east-1", "zone-b"),
            (&a3, "us-east-1", "zone-a"),
            (&a4, "eu-west-1", "zone-eu"),
        ] {
            profiles.insert(
                aid.clone(),
                AgentSchedulingProfile {
                    domain_info: Some(DomainInfo::new(
                        RegionName::new(reg).unwrap_or_default(),
                        ZoneName::new(zone).unwrap_or_default(),
                    )),
                    ..AgentSchedulingProfile::default()
                },
            );
        }
        let member_placements = [
            ("t1", &a1, 1000_u64),
            ("t2", &a1, 950),
            ("t3", &a1, 500),
            ("t4", &a3, 1000),
            ("t5", &a2, 1000),
            ("t6", &a4, 1000),
        ]
        .into_iter()
        .map(|(tid, aid, score)| {
            (
                TaskId::new(tid).unwrap_or_default(),
                TopologyPlacementPlan {
                    agent_id: aid.clone(),
                    selected_numa_node: 0,
                    assigned_gpus: Vec::new(),
                    paired_rdma_nic: None,
                    affinity_score: score,
                },
            )
        })
        .collect();
        let custom_res = GangReservation {
            group_id: TaskGroupId::new("g-cost").unwrap_or_default(),
            member_placements,
            assigned_tpu_torus: Vec::new(),
            locked_agents_ordered: Vec::new(),
            lease_expires_at_tick: 100,
        };
        assert!(compute_gang_fabric_communication_cost(&custom_res, &profiles) > 5_000);

        let mut hold = GangBarrierHoldState {
            constraint: GangConstraint {
                group_id: TaskGroupId::new("g-hold").unwrap_or_default(),
                min_members: 2,
                total_members: 4,
                holding_timeout_ticks: 100,
            },
            held_placements: vec![(
                TaskId::new("t-hold-1").unwrap_or_default(),
                TopologyPlacementPlan::default(),
            )],
            barrier_expires_at_tick: 200,
        };
        assert!(!hold.admits_backfill_task(100, 0));
        assert!(hold.admits_backfill_task(100, 50));
        assert!(!hold.admits_backfill_task(100, 100));
        assert_eq!(hold.evaluate_barrier_or_release(150), Ok(false));
        assert!(hold.evaluate_barrier_or_release(200).is_err());
        hold.held_placements.push((
            TaskId::new("t-hold-2").unwrap_or_default(),
            TopologyPlacementPlan::default(),
        ));
        assert_eq!(hold.evaluate_barrier_or_release(250), Ok(true));
    }
}
