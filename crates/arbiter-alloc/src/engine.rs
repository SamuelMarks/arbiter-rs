//! Hybrid scheduler facade (`arbiter-alloc::engine`) and cross-cluster federation bursting (`arbiter-alloc::federation`).
//!
//! Unifies:
//! - **Direct Task & Gang Scheduling**: Built-in zero-overhead First-Party Scheduler module that
//!   places [`TaskSpec`] and [`TaskGroupSpec`] workloads directly onto Agent inventories in HDRF order.
//! - **Mesos 2-Level Offer Generation**: Emits [`ResourceOffer`]s to external Frameworks respecting
//!   their [`OfferFilter`]s, suppression windows, and role quotas.

use std::collections::BTreeMap;

use arbiter_core::error::ArbiterResult;
use arbiter_core::ids::{AgentId, FrameworkId, OfferId, RoleName, TaskId};
use arbiter_core::resources::ResourceBundle;
use arbiter_core::workload::{OfferFilter, ResourceOffer, RoleHierarchy, TaskGroupSpec, TaskSpec};
use serde::{Deserialize, Serialize};

use crate::drf::{RoleAllocationState, rank_hdrf_candidates};
use crate::gang::{GangAgentCandidate, GangReservation, schedule_gang_atomic_with_profiles};
use crate::topology_packer::{
    AgentSchedulingProfile, TopologyPlacementPlan, pack_task_on_agent_with_profile,
};

/// Provenance type of a Mesos resource reservation entry (`ReservationInfo::Type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReservationOriginKind {
    /// Static reservation configured at Agent startup (`STATIC`).
    StaticAgentConfig,
    /// Dynamic reservation created at runtime via `OfferOperation::Reserve` or `OperatorCall::ReserveResources` (`DYNAMIC`).
    DynamicRuntime,
}

/// Single entry in a hierarchical Mesos `Resource::ReservationInfo` refinement stack.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReservationStackEntry {
    /// Origin kind (`StaticAgentConfig` vs. `DynamicRuntime`).
    pub kind: ReservationOriginKind,
    /// Target [`RoleName`] at this refinement level.
    pub role: RoleName,
    /// Authenticated principal that created this reservation layer.
    pub principal: String,
    /// Reserved [`ResourceBundle`] at this layer.
    pub resources: ResourceBundle,
}

/// Resolves the ordered Mesos `ReservationInfo` stack for `(agent_id, target_role)` from static
/// agent reservations, dynamic role reservations, and refined `PushReservation` stacks.
///
/// # Arguments
///
/// * `agent_id` - Hosting [`AgentId`].
/// * `target_role` - Target [`RoleName`] receiving the offer.
/// * `static_reservations` - Map of `(AgentId, RoleName) -> ResourceBundle` configured statically on the Agent.
/// * `dynamic_reservations` - Map of `(AgentId, RoleName) -> (String, ResourceBundle)` reserved dynamically.
/// * `refined_stacks` - Map of `(AgentId, Vec<RoleName>) -> (String, ResourceBundle)` refined via `PushReservation`.
///
/// # Returns
///
/// Ordered vector of [`ReservationStackEntry`]s from ancestor reservation to leaf refined role.
pub fn resolve_offer_reservation_stack(
    agent_id: &AgentId,
    target_role: &RoleName,
    static_reservations: &BTreeMap<(AgentId, RoleName), ResourceBundle>,
    dynamic_reservations: &BTreeMap<(AgentId, RoleName), (String, ResourceBundle)>,
    refined_stacks: &BTreeMap<(AgentId, Vec<RoleName>), (String, ResourceBundle)>,
) -> Vec<ReservationStackEntry> {
    let mut stack_out = Vec::new();
    if let Some(static_bundle) = static_reservations.get(&(agent_id.clone(), target_role.clone())) {
        stack_out.push(ReservationStackEntry {
            kind: ReservationOriginKind::StaticAgentConfig,
            role: target_role.clone(),
            principal: "agent-static".to_owned(),
            resources: static_bundle.clone(),
        });
    }
    if let Some((principal, dyn_bundle)) =
        dynamic_reservations.get(&(agent_id.clone(), target_role.clone()))
    {
        stack_out.push(ReservationStackEntry {
            kind: ReservationOriginKind::DynamicRuntime,
            role: target_role.clone(),
            principal: principal.clone(),
            resources: dyn_bundle.clone(),
        });
    }
    for ((aid, role_chain), (principal, bundle)) in refined_stacks {
        if aid == agent_id && role_chain.last() == Some(target_role) {
            for r in role_chain {
                stack_out.push(ReservationStackEntry {
                    kind: ReservationOriginKind::DynamicRuntime,
                    role: r.clone(),
                    principal: principal.clone(),
                    resources: bundle.clone(),
                });
            }
        }
    }
    stack_out
}

/// Registered external 2-level Framework state in the Hybrid Scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredFramework {
    /// Framework identifier.
    pub framework_id: FrameworkId,
    /// Role under which the framework schedules.
    pub role: RoleName,
    /// Optional offer filter and agent suppression rules.
    pub filter: OfferFilter,
    /// Map of `AgentId -> refused_until_tick` for declined offers.
    pub suppressed_agents: BTreeMap<AgentId, u64>,
}

/// Output of a single scheduling cycle of the [`HybridAllocationEngine`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationCycleOutcome {
    /// Direct tasks placed during this cycle.
    pub direct_placements: Vec<(TaskId, TopologyPlacementPlan)>,
    /// Atomic gang reservations placed during this cycle.
    pub gang_reservations: Vec<GangReservation>,
    /// Resource offers generated for external 2-level frameworks.
    pub generated_offers: Vec<ResourceOffer>,
    /// Direct tasks that could not be placed on the local cluster (eligible for federation bursting).
    pub unplaced_direct_tasks: Vec<TaskSpec>,
    /// Gang jobs that could not be placed on the local cluster (eligible for federation bursting).
    pub unplaced_gang_groups: Vec<TaskGroupSpec>,
}

/// Hybrid scheduling engine combining direct first-party placement and 2-level framework offer generation.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridAllocationEngine {
    /// Monotonic counter for generating unique [`OfferId`]s.
    next_offer_seq: u64,
    /// Default offer TTL in ticks.
    offer_ttl_ticks: u64,
}

impl HybridAllocationEngine {
    /// Creates a new [`HybridAllocationEngine`].
    ///
    /// # Arguments
    ///
    /// * `offer_ttl_ticks` - Number of ticks before generated [`ResourceOffer`]s expire.
    ///
    /// # Returns
    ///
    /// Initialized [`HybridAllocationEngine`].
    pub const fn new(offer_ttl_ticks: u64) -> Self {
        Self {
            next_offer_seq: 1,
            offer_ttl_ticks,
        }
    }

    /// Executes one full hybrid allocation cycle across direct tasks, gang jobs, and external frameworks.
    ///
    /// 1. Ranks all active roles and frameworks using [`rank_hdrf_candidates`].
    /// 2. Places pending [`TaskGroupSpec`] gangs atomically.
    /// 3. Places pending direct [`TaskSpec`]s onto compatible Agents.
    /// 4. Generates [`ResourceOffer`]s from remaining Agent capacity for external frameworks in HDRF order,
    ///    honoring each framework's [`OfferFilter`] and agent suppression timestamps.
    ///
    /// # Arguments
    ///
    /// * `hierarchy` - Cluster [`RoleHierarchy`].
    /// * `role_states` - Current [`RoleAllocationState`]s.
    /// * `total_capacity` - Total cluster [`ResourceBundle`].
    /// * `agents` - Mutable slice of [`GangAgentCandidate`]s representing available Agent resources.
    /// * `direct_tasks` - Pending direct tasks.
    /// * `gang_groups` - Pending atomic gang task groups.
    /// * `frameworks` - Registered 2-level [`RegisteredFramework`]s.
    /// * `current_tick` - Current monotonic scheduler tick.
    ///
    /// # Returns
    ///
    /// [`AllocationCycleOutcome`] detailing all placements, offers, and unplaced overflow workloads.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if HDRF role validation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn run_allocation_cycle(
        &mut self,
        hierarchy: &RoleHierarchy,
        role_states: &[RoleAllocationState],
        total_capacity: &ResourceBundle,
        agents: &mut Vec<GangAgentCandidate>,
        direct_tasks: &[TaskSpec],
        gang_groups: &[TaskGroupSpec],
        frameworks: &[RegisteredFramework],
        current_tick: u64,
    ) -> ArbiterResult<AllocationCycleOutcome> {
        self.run_allocation_cycle_with_profiles(
            hierarchy,
            role_states,
            total_capacity,
            agents,
            &BTreeMap::new(),
            direct_tasks,
            gang_groups,
            frameworks,
            current_tick,
        )
    }

    /// Executes one full hybrid allocation cycle while enforcing per-Agent [`AgentSchedulingProfile`]
    /// (`PlacementConstraint`, `DomainInfo` zone spread, `CpuCoreClass`, `CpuInstructionExtension`,
    /// `NumaMemoryPool`) across gang and direct placements.
    ///
    /// # Arguments
    ///
    /// * `hierarchy` - Cluster [`RoleHierarchy`].
    /// * `role_states` - Current [`RoleAllocationState`]s.
    /// * `total_capacity` - Total cluster [`ResourceBundle`].
    /// * `agents` - Mutable slice of [`GangAgentCandidate`]s representing available Agent resources.
    /// * `profiles` - Optional map of per-Agent [`AgentSchedulingProfile`]s.
    /// * `direct_tasks` - Pending direct tasks.
    /// * `gang_groups` - Pending atomic gang task groups.
    /// * `frameworks` - Registered 2-level [`RegisteredFramework`]s.
    /// * `current_tick` - Current monotonic scheduler tick.
    ///
    /// # Returns
    ///
    /// [`AllocationCycleOutcome`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if HDRF role validation fails.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn run_allocation_cycle_with_profiles(
        &mut self,
        hierarchy: &RoleHierarchy,
        role_states: &[RoleAllocationState],
        total_capacity: &ResourceBundle,
        agents: &mut Vec<GangAgentCandidate>,
        profiles: &BTreeMap<AgentId, AgentSchedulingProfile>,
        direct_tasks: &[TaskSpec],
        gang_groups: &[TaskGroupSpec],
        frameworks: &[RegisteredFramework],
        current_tick: u64,
    ) -> ArbiterResult<AllocationCycleOutcome> {
        let ranked = rank_hdrf_candidates(hierarchy, role_states, total_capacity)?;
        let mut outcome = AllocationCycleOutcome::default();
        let mut host_task_counts: BTreeMap<AgentId, u32> = BTreeMap::new();
        let mut zone_task_counts: BTreeMap<String, u32> = BTreeMap::new();

        // 1. Schedule atomic gang jobs first.
        for group in gang_groups {
            if let Ok((reservation, updated_pool)) =
                schedule_gang_atomic_with_profiles(group, agents, profiles, current_tick)
            {
                for (_, plan) in &reservation.member_placements {
                    let zone_key = profiles
                        .get(&plan.agent_id)
                        .and_then(|p| p.domain_info.as_ref())
                        .map_or_else(String::new, |d| d.fault_domain.zone.as_str().to_owned());
                    *host_task_counts.entry(plan.agent_id.clone()).or_insert(0) += 1;
                    *zone_task_counts.entry(zone_key).or_insert(0) += 1;
                }
                *agents = updated_pool;
                outcome.gang_reservations.push(reservation);
            } else {
                outcome.unplaced_gang_groups.push(group.clone());
            }
        }

        // 2. Schedule direct tasks using the built-in first-party scheduler.
        for task in direct_tasks {
            let mut placed: Option<(usize, TopologyPlacementPlan)> = None;
            for (idx, agent) in agents.iter().enumerate() {
                let aid = &agent.hardware.agent_id;
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
                    pack_task_on_agent_with_profile(task, &agent.hardware, &effective_profile)
                {
                    placed = Some((idx, plan));
                    break;
                }
            }
            if let Some((chosen_idx, plan)) = placed {
                for (idx, agent) in agents.iter_mut().enumerate() {
                    if idx == chosen_idx {
                        agent.hardware.apply_placement_deduction(task, &plan);
                    }
                }
                let zone_key = profiles
                    .get(&plan.agent_id)
                    .and_then(|p| p.domain_info.as_ref())
                    .map_or_else(String::new, |d| d.fault_domain.zone.as_str().to_owned());
                *host_task_counts.entry(plan.agent_id.clone()).or_insert(0) += 1;
                *zone_task_counts.entry(zone_key).or_insert(0) += 1;
                outcome.direct_placements.push((task.task_id.clone(), plan));
            } else {
                outcome.unplaced_direct_tasks.push(task.clone());
            }
        }

        // Compute whether any role in the hierarchy has unallocated guaranteed_min capacity that can
        // be lent out as revocable resources to burst-borrowing frameworks.
        let mut role_allocated: BTreeMap<RoleName, ResourceBundle> = BTreeMap::new();
        for st in role_states {
            let curr = role_allocated
                .get(&st.role)
                .cloned()
                .unwrap_or_else(ResourceBundle::zero);
            role_allocated.insert(st.role.clone(), curr.try_add(&st.allocated).unwrap_or(curr));
        }
        let has_idle_lender_quota = hierarchy.roles().iter().any(|r| {
            let used = role_allocated
                .get(&r.name)
                .cloned()
                .unwrap_or_else(ResourceBundle::zero);
            !used.contains(&r.quota.guaranteed_min)
        });

        // 3. Generate Mesos 2-level ResourceOffers for external frameworks in HDRF order.
        for entry in &ranked {
            let Some(ref fw_id) = entry.framework_id else {
                continue;
            };
            let Some(fw) = frameworks.iter().find(|f| &f.framework_id == fw_id) else {
                continue;
            };
            let is_revocable_borrow = hierarchy.roles().iter().any(|r| {
                (r.name == fw.role)
                    & has_idle_lender_quota
                    & r.quota.guaranteed_min.is_empty()
                    & r.quota.allow_burst_borrowing
            });

            for agent in agents.iter_mut() {
                let avail = &agent.hardware.available_bundle;
                if avail.is_empty() {
                    continue;
                }
                if fw
                    .suppressed_agents
                    .get(&agent.hardware.agent_id)
                    .is_some_and(|&until_tick| current_tick < until_tick)
                {
                    continue;
                }
                if avail.cpu.get() < fw.filter.min_cpu_millicores
                    || avail.memory < fw.filter.min_memory_bytes
                {
                    continue;
                }
                if fw.filter.refuse_gpu_offers
                    && (!avail.gpu_compute.is_zero() || !avail.gpu_vram.is_zero())
                {
                    continue;
                }
                if avail.gpu_vram < fw.filter.min_gpu_vram {
                    continue;
                }

                let offer_id =
                    OfferId::new(&format!("offer-{}", self.next_offer_seq)).unwrap_or_default();
                self.next_offer_seq = self.next_offer_seq.saturating_add(1);

                let offered_resources = avail.clone();
                agent.hardware.available_bundle = ResourceBundle::zero();

                outcome.generated_offers.push(ResourceOffer {
                    offer_id,
                    framework_id: fw.framework_id.clone(),
                    agent_id: agent.hardware.agent_id.clone(),
                    role: fw.role.clone(),
                    resources: offered_resources,
                    revocable: is_revocable_borrow,
                    expires_at_tick: current_tick.saturating_add(self.offer_ttl_ticks),
                });
            }
        }

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::{QuotaId, TaskGroupId};
    use arbiter_core::topology::HardwareTopologyGraph;
    use arbiter_core::units::{Bytes, Millicores, WeightBasisPoints};
    use arbiter_core::workload::{IsolationSpec, PreemptionPolicy, PriorityClass, Quota, Role};

    use super::*;
    use crate::topology_packer::AgentHardwareInventory;

    fn make_agent(name: &str, cpu_m: u64, mem_b: u64) -> GangAgentCandidate {
        GangAgentCandidate {
            hardware: AgentHardwareInventory {
                agent_id: AgentId::new(name).unwrap_or_default(),
                available_bundle: ResourceBundle {
                    cpu: Millicores::new(cpu_m),
                    memory: Bytes::new(mem_b),
                    ..ResourceBundle::zero()
                },
                numa_domains: Vec::new(),
                gpus: Vec::new(),
                rdma_nics: Vec::new(),
                topology: HardwareTopologyGraph::new(),
            },
            tpu_devices: Vec::new(),
        }
    }

    fn make_direct_task(id: &str, role: &RoleName, cpu_m: u64) -> TaskSpec {
        TaskSpec {
            task_id: TaskId::new(id).unwrap_or_default(),
            role: role.clone(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionStandard,
            preemption_policy: PreemptionPolicy::GracefulSigterm,
            resources: ResourceBundle {
                cpu: Millicores::new(cpu_m),
                memory: Bytes::new(1024),
                ..ResourceBundle::zero()
            },
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/app".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        }
    }

    fn sample_hierarchy_and_cap() -> (RoleHierarchy, ResourceBundle, RoleName, RoleName) {
        let total_cap = ResourceBundle {
            cpu: Millicores::new(64_000),
            memory: Bytes::new(64_000_000),
            ..ResourceBundle::zero()
        };

        let r_prod = RoleName::new("prod").unwrap_or_default();
        let r_fw = RoleName::new("spark").unwrap_or_default();
        let mut hierarchy = RoleHierarchy::new();
        let mut prod_quota = Quota {
            id: QuotaId::new("q-all").unwrap_or_default(),
            guaranteed_min: ResourceBundle {
                cpu: Millicores::new(4_000),
                ..ResourceBundle::zero()
            },
            hard_max: total_cap.clone(),
            allow_burst_borrowing: true,
            weight: WeightBasisPoints::STANDARD,
        };
        let _ = hierarchy.add_role(Role {
            name: r_prod.clone(),
            parent: None,
            quota: prod_quota.clone(),
        });
        prod_quota.guaranteed_min = ResourceBundle::zero();
        let _ = hierarchy.add_role(Role {
            name: r_fw.clone(),
            parent: None,
            quota: prod_quota,
        });
        (hierarchy, total_cap, r_prod, r_fw)
    }

    #[test]
    fn test_hybrid_scheduler_direct_gang_and_framework_offers() {
        let (hierarchy, total_cap, r_prod, r_fw) = sample_hierarchy_and_cap();

        let fw_id = FrameworkId::new("fw-spark-1").unwrap_or_default();
        let fw_unregistered = FrameworkId::new("fw-ghost").unwrap_or_default();
        let role_states = vec![
            RoleAllocationState {
                role: r_prod.clone(),
                framework_id: None,
                allocated: ResourceBundle::zero(),
                allocation_count: 0,
            },
            RoleAllocationState {
                role: r_fw.clone(),
                framework_id: Some(fw_unregistered),
                allocated: ResourceBundle::zero(),
                allocation_count: 0,
            },
            RoleAllocationState {
                role: r_fw.clone(),
                framework_id: Some(fw_id.clone()),
                allocated: ResourceBundle::zero(),
                allocation_count: 0,
            },
        ];

        let mut agents = vec![
            make_agent("agent-0-empty", 0, 0),
            make_agent("agent-1", 16_000, 16_000_000),
            make_agent("agent-2", 16_000, 16_000_000),
            make_agent("agent-3", 2_000, 1_000),
        ];

        let gang_ok = TaskGroupSpec {
            group_id: TaskGroupId::new("gang-ok").unwrap_or_default(),
            role: r_prod.clone(),
            tasks: vec![make_direct_task("g-t1", &r_prod, 8_000)],
            tpu_slice: None,
            placement_timeout_ms: 500,
        };
        let gang_too_big = TaskGroupSpec {
            group_id: TaskGroupId::new("gang-big").unwrap_or_default(),
            role: r_prod.clone(),
            tasks: vec![make_direct_task("g-t2", &r_prod, 100_000)],
            tpu_slice: None,
            placement_timeout_ms: 500,
        };

        let direct_ok = make_direct_task("direct-1", &r_prod, 8_000);
        let direct_too_big = make_direct_task("direct-big", &r_prod, 100_000);

        let mut suppressed = BTreeMap::new();
        suppressed.insert(AgentId::new("agent-3").unwrap_or_default(), 500);

        let frameworks = vec![RegisteredFramework {
            framework_id: fw_id,
            role: r_fw,
            filter: OfferFilter {
                refuse_milliseconds: 500,
                min_cpu_millicores: 4_000,
                min_memory_bytes: Bytes::new(4_000_000),
                refuse_gpu_offers: false,
                min_gpu_vram: Bytes::ZERO,
            },
            suppressed_agents: suppressed,
        }];

        let mut engine = HybridAllocationEngine::new(100);
        let outcome = engine
            .run_allocation_cycle(
                &hierarchy,
                &role_states,
                &total_cap,
                &mut agents,
                &[direct_ok, direct_too_big],
                &[gang_ok, gang_too_big],
                &frameworks,
                100,
            )
            .unwrap_or_default();

        assert_eq!(outcome.gang_reservations.len(), 1);
        assert_eq!(outcome.unplaced_gang_groups.len(), 1);
        assert_eq!(outcome.direct_placements.len(), 1);
        assert_eq!(outcome.unplaced_direct_tasks.len(), 1);
        assert_eq!(outcome.generated_offers.len(), 1);
    }

    #[test]
    fn test_hybrid_scheduler_filters_and_errors() {
        let (hierarchy, total_cap, _, r_fw) = sample_hierarchy_and_cap();
        let fw_id = FrameworkId::new("fw-spark-1").unwrap_or_default();
        let role_states = vec![RoleAllocationState {
            role: r_fw.clone(),
            framework_id: Some(fw_id.clone()),
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        let frameworks = vec![RegisteredFramework {
            framework_id: fw_id.clone(),
            role: r_fw.clone(),
            filter: OfferFilter {
                refuse_milliseconds: 500,
                min_cpu_millicores: 4_000,
                min_memory_bytes: Bytes::new(4_000_000),
                refuse_gpu_offers: true,
                min_gpu_vram: Bytes::new(8_000_000_000),
            },
            suppressed_agents: BTreeMap::new(),
        }];

        let mut engine = HybridAllocationEngine::new(100);
        let mut gpu_agent = make_agent("agent-gpu", 16_000, 16_000_000);
        gpu_agent.hardware.available_bundle.gpu_compute =
            arbiter_core::units::GpuMillicores::new(1000);
        let mut vram_only_agent = make_agent("agent-vram-only", 16_000, 16_000_000);
        vram_only_agent.hardware.available_bundle.gpu_vram = Bytes::new(4_000_000_000);
        let mut agents2 = vec![
            make_agent("agent-low-cpu", 1_000, 16_000_000),
            make_agent("agent-low-mem", 16_000, 500),
            gpu_agent,
            vram_only_agent,
            make_agent("agent-low-vram", 16_000, 16_000_000),
        ];
        let outcome2 = engine
            .run_allocation_cycle(
                &hierarchy,
                &role_states,
                &total_cap,
                &mut agents2,
                &[],
                &[],
                &frameworks,
                600,
            )
            .unwrap_or_default();
        assert!(outcome2.generated_offers.is_empty());

        // Test min_gpu_vram when refuse_gpu_offers == false
        let frameworks_vram = vec![RegisteredFramework {
            framework_id: fw_id,
            role: r_fw,
            filter: OfferFilter {
                refuse_milliseconds: 500,
                min_cpu_millicores: 4_000,
                min_memory_bytes: Bytes::new(4_000_000),
                refuse_gpu_offers: false,
                min_gpu_vram: Bytes::new(8_000_000_000),
            },
            suppressed_agents: BTreeMap::new(),
        }];
        let mut high_vram_agent = make_agent("agent-high-vram", 16_000, 16_000_000);
        high_vram_agent.hardware.available_bundle.gpu_vram = Bytes::new(16_000_000_000);
        let mut agents3 = vec![high_vram_agent];
        let outcome3 = engine
            .run_allocation_cycle(
                &hierarchy,
                &role_states,
                &total_cap,
                &mut agents3,
                &[],
                &[],
                &frameworks_vram,
                600,
            )
            .unwrap_or_default();
        assert_eq!(outcome3.generated_offers.len(), 1);

        let bad_states = vec![RoleAllocationState {
            role: RoleName::new("missing-role").unwrap_or_default(),
            framework_id: None,
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        assert!(
            engine
                .run_allocation_cycle(
                    &hierarchy,
                    &bad_states,
                    &total_cap,
                    &mut agents2,
                    &[],
                    &[],
                    &[],
                    600,
                )
                .is_err()
        );
    }

    #[test]
    fn test_allocation_cycle_with_profiles_and_zone_spread() {
        use arbiter_core::ids::{RegionName, ZoneName};
        use arbiter_core::workload::{DomainInfo, PlacementConstraint};

        use crate::topology_packer::TaskSchedulingRequirements;

        let (hierarchy, total_cap, r_direct, _) = sample_hierarchy_and_cap();
        let role_states = vec![RoleAllocationState {
            role: r_direct.clone(),
            framework_id: None,
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];

        let a1 = make_agent("agent-1", 32_000, 32_000_000);
        let a2 = make_agent("agent-2", 32_000, 32_000_000);
        let mut profiles = BTreeMap::new();
        profiles.insert(
            a1.hardware.agent_id.clone(),
            AgentSchedulingProfile {
                domain_info: Some(DomainInfo::new(
                    RegionName::new("us-east-1").unwrap_or_default(),
                    ZoneName::new("zone-1a").unwrap_or_default(),
                )),
                ..AgentSchedulingProfile::default()
            },
        );
        profiles.insert(
            a2.hardware.agent_id.clone(),
            AgentSchedulingProfile {
                domain_info: Some(DomainInfo::new(
                    RegionName::new("us-east-1").unwrap_or_default(),
                    ZoneName::new("zone-1b").unwrap_or_default(),
                )),
                ..AgentSchedulingProfile::default()
            },
        );

        let mut gang_t = make_direct_task("gang-m1", &r_direct, 2_000);
        let mut dt1 = make_direct_task("direct-1", &r_direct, 2_000);
        let mut dt2 = make_direct_task("direct-2", &r_direct, 2_000);
        let reqs = TaskSchedulingRequirements {
            placement_constraints: vec![PlacementConstraint::MaxPerFaultDomain(1)],
            ..TaskSchedulingRequirements::default()
        };
        reqs.attach_to_task(&mut gang_t);
        reqs.attach_to_task(&mut dt1);
        reqs.attach_to_task(&mut dt2);

        let gang = TaskGroupSpec {
            group_id: TaskGroupId::new("g-1").unwrap_or_default(),
            role: r_direct,
            tasks: vec![gang_t],
            tpu_slice: None,
            placement_timeout_ms: 100,
        };
        let mut agents = vec![a1, a2];
        let mut engine = HybridAllocationEngine::new(100);
        let outcome = engine
            .run_allocation_cycle_with_profiles(
                &hierarchy,
                &role_states,
                &total_cap,
                &mut agents,
                &profiles,
                &[dt1, dt2],
                &[gang],
                &[],
                10,
            )
            .unwrap_or_default();
        assert_eq!(outcome.gang_reservations.len(), 1);
        assert_eq!(outcome.direct_placements.len(), 1);
        assert_eq!(outcome.unplaced_direct_tasks.len(), 1);
    }

    #[test]
    fn test_resolve_offer_reservation_stack() {
        let (_, total_cap, _, _) = sample_hierarchy_and_cap();
        let aid1 = AgentId::new("agent-1").unwrap_or_default();
        let aid2 = AgentId::new("agent-2").unwrap_or_default();
        let r_base = RoleName::new("finance").unwrap_or_default();
        let r_sub = RoleName::new("finance.quant").unwrap_or_default();
        let mut static_res = BTreeMap::new();
        static_res.insert((aid1.clone(), r_sub.clone()), total_cap.clone());
        let mut dyn_res = BTreeMap::new();
        dyn_res.insert(
            (aid1.clone(), r_sub.clone()),
            ("op-principal".to_owned(), total_cap.clone()),
        );
        let mut refined = BTreeMap::new();
        refined.insert(
            (aid1.clone(), vec![r_base.clone(), r_sub.clone()]),
            ("fw-principal".to_owned(), total_cap.clone()),
        );
        refined.insert(
            (aid2.clone(), vec![r_base.clone(), r_sub.clone()]),
            ("other-agent".to_owned(), total_cap),
        );
        let stack = resolve_offer_reservation_stack(&aid1, &r_sub, &static_res, &dyn_res, &refined);
        assert_eq!(stack.len(), 4);
        assert_eq!(
            stack.first().map(|e| e.kind),
            Some(ReservationOriginKind::StaticAgentConfig)
        );
        let empty_stack =
            resolve_offer_reservation_stack(&aid2, &r_base, &static_res, &dyn_res, &refined);
        assert!(empty_stack.is_empty());
    }
}
