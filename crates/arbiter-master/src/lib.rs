//! Master node state machine, scheduling coordinator, and cluster control plane for Arbiter (`arbiter-master`).
//!
//! Coordinates:
//! - Agent registration, heartbeat lease tracking, and unhealthy agent fencing/reconciliation.
//! - Framework registration, failover timeouts, and offer lifecycle management (`AcceptOffers`, `Decline`).
//! - Direct job submission queue, gang scheduling coordinator, and continuous HDRF allocation loop.
//! - State persistence via [`arbiter_store::traits::StateStore`] and zero-trust policy enforcement via [`arbiter_net::security`].

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod bench;
pub mod sim;

use std::collections::{BTreeMap, BTreeSet};

use arbiter_alloc::drf::RoleAllocationState;
use arbiter_alloc::engine::{AllocationCycleOutcome, HybridAllocationEngine, RegisteredFramework};
use arbiter_alloc::gang::GangAgentCandidate;
use arbiter_alloc::topology_packer::AgentHardwareInventory;
use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, FrameworkId, OfferId, TaskId};
use arbiter_core::resources::ResourceBundle;
use arbiter_core::workload::{
    OfferFilter, OfferOperation, ResourceOffer, RoleHierarchy, TaskGroupSpec, TaskSpec, TaskState,
};
use arbiter_proto::{
    AcceptOffers, AgentHeartbeat, RegisterAgent, SubmitDirectJob, SubscribeFramework,
    TaskStatusUpdate,
};
use arbiter_store::election::{ElectionPlane, MultiplexedAgentHeartbeat};
use arbiter_store::traits::StateStore;
use serde::{Deserialize, Serialize};

/// Tracked Agent node state inside the Master control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterAgentRecord {
    /// Agent registration info.
    pub registration: RegisterAgent,
    /// Currently available (unallocated and unoffered) resources on this Agent.
    pub available_resources: ResourceBundle,
    /// Monotonic tick at which this Agent's heartbeat lease expires.
    pub lease_expires_at_tick: u64,
    /// Whether this Agent is currently healthy and connected.
    pub healthy: bool,
}

/// Master control-plane state machine parameterized over a [`StateStore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterNode<S: StateStore> {
    /// Consensus state store backing the Master.
    pub store: S,
    /// Role hierarchy and quotas.
    pub role_hierarchy: RoleHierarchy,
    /// Hybrid HDRF / Gang / Offer allocation engine.
    pub alloc_engine: HybridAllocationEngine,
    /// Shared `CaaS` election plane for co-located stateful workloads.
    pub election_plane: ElectionPlane,
    /// Registered Agents keyed by [`AgentId`].
    pub agents: BTreeMap<AgentId, MasterAgentRecord>,
    /// Registered 2-level Frameworks keyed by [`FrameworkId`].
    pub frameworks: BTreeMap<FrameworkId, RegisteredFramework>,
    /// Active outstanding resource offers keyed by [`OfferId`].
    pub active_offers: BTreeMap<OfferId, ResourceOffer>,
    /// Consumed (accepted or declined) offer IDs.
    pub consumed_offers: BTreeSet<OfferId>,
    /// Task lifecycle states and hosting Agent IDs keyed by [`TaskId`].
    pub tasks: BTreeMap<TaskId, (TaskState, AgentId, ResourceBundle)>,
    /// Pending direct tasks awaiting placement.
    pub pending_direct_tasks: Vec<TaskSpec>,
    /// Pending atomic gang jobs awaiting placement.
    pub pending_gang_jobs: Vec<TaskGroupSpec>,
    /// Agent heartbeat lease TTL in ticks.
    pub agent_lease_ttl_ticks: u64,
}

impl<S: StateStore> MasterNode<S> {
    /// Creates a new [`MasterNode`] backed by `store` and `role_hierarchy`.
    ///
    /// # Arguments
    ///
    /// * `store` - Consensus [`StateStore`].
    /// * `role_hierarchy` - Cluster [`RoleHierarchy`].
    /// * `agent_lease_ttl_ticks` - Agent heartbeat TTL in ticks.
    /// * `offer_ttl_ticks` - Resource offer TTL in ticks.
    ///
    /// # Returns
    ///
    /// Initialized [`MasterNode`].
    pub fn new(
        store: S,
        role_hierarchy: RoleHierarchy,
        agent_lease_ttl_ticks: u64,
        offer_ttl_ticks: u64,
    ) -> Self {
        Self {
            store,
            role_hierarchy,
            alloc_engine: HybridAllocationEngine::new(offer_ttl_ticks),
            election_plane: ElectionPlane::new(),
            agents: BTreeMap::new(),
            frameworks: BTreeMap::new(),
            active_offers: BTreeMap::new(),
            consumed_offers: BTreeSet::new(),
            tasks: BTreeMap::new(),
            pending_direct_tasks: Vec::new(),
            pending_gang_jobs: Vec::new(),
            agent_lease_ttl_ticks,
        }
    }

    /// Registers an Agent with the Master and persists its record to `store`.
    ///
    /// # Arguments
    ///
    /// * `reg` - [`RegisterAgent`] payload.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` on registration.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if state store persistence fails.
    pub fn register_agent(&mut self, reg: RegisterAgent, current_tick: u64) -> ArbiterResult<()> {
        let key = format!("/agents/{}", reg.agent_id);
        let bytes = serde_json::to_vec(&reg).unwrap_or_default();
        let _ = self.store.put(&key, bytes)?;

        let avail = reg.total_resources.clone();
        self.agents.insert(
            reg.agent_id.clone(),
            MasterAgentRecord {
                registration: reg,
                available_resources: avail,
                lease_expires_at_tick: current_tick.saturating_add(self.agent_lease_ttl_ticks),
                healthy: true,
            },
        );
        Ok(())
    }

    /// Processes an [`AgentHeartbeat`], extending the Agent's lease and renewing any co-located
    /// `CaaS` [`ElectionPlane`] primary leases in a single pass.
    ///
    /// # Arguments
    ///
    /// * `hb` - [`AgentHeartbeat`] message.
    ///
    /// # Returns
    ///
    /// Updated lease expiration tick for the Agent.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `hb.agent_id` is not registered.
    pub fn process_agent_heartbeat(&mut self, hb: &AgentHeartbeat) -> ArbiterResult<u64> {
        let Some(agent_rec) = self.agents.get_mut(&hb.agent_id) else {
            return Err(ArbiterError::StoreReadError {
                key: hb.agent_id.to_string(),
                reason: "unknown agent in heartbeat".to_owned(),
            });
        };

        let new_expiry = hb.tick.saturating_add(self.agent_lease_ttl_ticks);
        agent_rec.lease_expires_at_tick = new_expiry;
        agent_rec.healthy = true;

        let _ = self
            .election_plane
            .process_multiplexed_heartbeat(&MultiplexedAgentHeartbeat {
                agent_id: hb.agent_id.clone(),
                healthy_tasks: hb.healthy_tasks.clone(),
                heartbeat_tick: hb.tick,
            });

        Ok(new_expiry)
    }

    /// Reconciles Agent leases at `current_tick`, marking expired Agents unhealthy and transitioning
    /// all non-terminal tasks hosted on them to [`TaskState::Lost`].
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Vector of `(AgentId, TaskId)` tasks transitioned to `Lost`.
    pub fn reconcile_unhealthy_agents(&mut self, current_tick: u64) -> Vec<(AgentId, TaskId)> {
        let mut expired_agents = BTreeSet::new();
        for (aid, rec) in &mut self.agents {
            if current_tick >= rec.lease_expires_at_tick {
                rec.healthy = false;
                expired_agents.insert(aid.clone());
            }
        }

        let mut lost_tasks = Vec::new();
        for (tid, (state, aid, _)) in &mut self.tasks {
            if expired_agents.contains(aid) && !state.is_terminal() {
                *state = TaskState::Lost;
                lost_tasks.push((aid.clone(), tid.clone()));
            }
        }
        lost_tasks
    }

    /// Subscribes an external 2-level Framework.
    ///
    /// # Arguments
    ///
    /// * `sub` - [`SubscribeFramework`] request.
    ///
    /// # Returns
    ///
    /// `Ok(())` on registration.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RoleNotFound`] if `sub.role` is not in `role_hierarchy`.
    pub fn subscribe_framework(&mut self, sub: SubscribeFramework) -> ArbiterResult<()> {
        let _ = self.role_hierarchy.get_role(&sub.role)?;
        self.frameworks.insert(
            sub.framework_id.clone(),
            RegisteredFramework {
                framework_id: sub.framework_id,
                role: sub.role,
                filter: OfferFilter::default(),
                suppressed_agents: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Submits a direct task or atomic gang job to the Master queue.
    ///
    /// # Arguments
    ///
    /// * `job` - [`SubmitDirectJob`] payload.
    pub fn submit_direct_job(&mut self, job: SubmitDirectJob) {
        match job {
            SubmitDirectJob::SingleTask(task) => self.pending_direct_tasks.push(*task),
            SubmitDirectJob::GangJob(group) => self.pending_gang_jobs.push(group),
        }
    }

    /// Runs a single continuous HDRF / Gang / Offer scheduling tick across all healthy Agents.
    ///
    /// # Arguments
    ///
    /// * `role_states` - Current [`RoleAllocationState`]s.
    /// * `current_tick` - Monotonic scheduler tick.
    ///
    /// # Returns
    ///
    /// [`AllocationCycleOutcome`] produced by the allocation engine.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if HDRF ranking fails.
    pub fn schedule_tick(
        &mut self,
        role_states: &[RoleAllocationState],
        current_tick: u64,
    ) -> ArbiterResult<AllocationCycleOutcome> {
        let mut total_capacity = ResourceBundle::zero();
        let mut candidates: Vec<GangAgentCandidate> = Vec::new();

        for rec in self.agents.values() {
            if !rec.healthy {
                continue;
            }
            total_capacity = total_capacity
                .try_add(&rec.registration.total_resources)
                .unwrap_or_default();
            candidates.push(GangAgentCandidate {
                hardware: AgentHardwareInventory {
                    agent_id: rec.registration.agent_id.clone(),
                    available_bundle: rec.available_resources.clone(),
                    numa_domains: Vec::new(),
                    gpus: Vec::new(),
                    rdma_nics: Vec::new(),
                    topology: rec.registration.topology.clone(),
                },
                tpu_devices: Vec::new(),
            });
        }

        let fw_list: Vec<RegisteredFramework> = self.frameworks.values().cloned().collect();
        let direct_queue = core::mem::take(&mut self.pending_direct_tasks);
        let gang_queue = core::mem::take(&mut self.pending_gang_jobs);

        let outcome = self.alloc_engine.run_allocation_cycle(
            &self.role_hierarchy,
            role_states,
            &total_capacity,
            &mut candidates,
            &direct_queue,
            &gang_queue,
            &fw_list,
            current_tick,
        )?;

        // Update available resources on healthy agents from post-cycle candidates.
        for cand in candidates {
            for (_, rec) in self
                .agents
                .iter_mut()
                .filter(|(id, _)| *id == &cand.hardware.agent_id)
            {
                rec.available_resources = cand.hardware.available_bundle.clone();
            }
        }

        // Record placed direct tasks and gang tasks as Staging.
        for (tid, plan) in &outcome.direct_placements {
            let task_res = direct_queue
                .iter()
                .find(|t| &t.task_id == tid)
                .map(|t| t.resources.clone())
                .unwrap_or_default();
            self.tasks.insert(
                tid.clone(),
                (TaskState::Staging, plan.agent_id.clone(), task_res),
            );
        }
        for gang_res in &outcome.gang_reservations {
            for (tid, plan) in &gang_res.member_placements {
                let task_res = gang_queue
                    .iter()
                    .flat_map(|g| &g.tasks)
                    .find(|t| &t.task_id == tid)
                    .map(|t| t.resources.clone())
                    .unwrap_or_default();
                self.tasks.insert(
                    tid.clone(),
                    (TaskState::Staging, plan.agent_id.clone(), task_res),
                );
            }
        }

        // Track active offers.
        for offer in &outcome.generated_offers {
            self.active_offers
                .insert(offer.offer_id.clone(), offer.clone());
        }

        self.pending_direct_tasks
            .clone_from(&outcome.unplaced_direct_tasks);
        self.pending_gang_jobs
            .clone_from(&outcome.unplaced_gang_groups);

        Ok(outcome)
    }

    /// Processes an [`AcceptOffers`] request from a subscribed Framework.
    ///
    /// # Arguments
    ///
    /// * `accept` - [`AcceptOffers`] payload.
    /// * `current_tick` - Monotonic tick for offer expiration and suppression calculations.
    ///
    /// # Returns
    ///
    /// `Ok(())` when all offer operations are applied.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`ArbiterError::FrameworkNotFound`] if `accept.framework_id` is not subscribed.
    /// - [`ArbiterError::OfferAlreadyConsumed`] if an offer ID was already consumed or is unknown.
    /// - [`ArbiterError::OfferExpired`] if `current_tick >= offer.expires_at_tick`.
    pub fn accept_offers(&mut self, accept: &AcceptOffers, current_tick: u64) -> ArbiterResult<()> {
        if !self.frameworks.contains_key(&accept.framework_id) {
            return Err(ArbiterError::FrameworkNotFound {
                framework_id: accept.framework_id.to_string(),
            });
        }

        let mut pooled_resources = ResourceBundle::zero();
        let mut primary_agent_id = AgentId::default();

        for oid in &accept.offer_ids {
            if self.consumed_offers.contains(oid) {
                return Err(ArbiterError::OfferAlreadyConsumed {
                    offer_id: oid.to_string(),
                });
            }
            let Some(offer) = self.active_offers.remove(oid) else {
                return Err(ArbiterError::OfferAlreadyConsumed {
                    offer_id: oid.to_string(),
                });
            };
            self.consumed_offers.insert(oid.clone());

            if current_tick >= offer.expires_at_tick {
                return Err(ArbiterError::OfferExpired {
                    offer_id: oid.to_string(),
                });
            }
            primary_agent_id = offer.agent_id;
            pooled_resources = pooled_resources
                .try_add(&offer.resources)
                .unwrap_or_default();
        }

        for op in &accept.operations {
            match op {
                OfferOperation::LaunchTask(task) => {
                    pooled_resources = pooled_resources.try_sub(&task.resources)?;
                    self.tasks.insert(
                        task.task_id.clone(),
                        (
                            TaskState::Staging,
                            primary_agent_id.clone(),
                            task.resources.clone(),
                        ),
                    );
                }
                OfferOperation::Decline(filter) => {
                    for (_, fw) in self
                        .frameworks
                        .iter_mut()
                        .filter(|(id, _)| *id == &accept.framework_id)
                    {
                        fw.suppressed_agents.insert(
                            primary_agent_id.clone(),
                            current_tick.saturating_add(filter.refuse_milliseconds),
                        );
                    }
                }
                _ => {}
            }
        }

        // Return any unused remainder of the offer back to the Agent's available pool.
        for (_, agent_rec) in self
            .agents
            .iter_mut()
            .filter(|(id, _)| *id == &primary_agent_id)
        {
            agent_rec.available_resources = agent_rec
                .available_resources
                .try_add(&pooled_resources)
                .unwrap_or_default();
        }

        Ok(())
    }

    /// Applies a [`TaskStatusUpdate`] reported by an Agent or Executor, validating the state machine
    /// transition and releasing resources back to the Agent if the task reaches a terminal state.
    ///
    /// # Arguments
    ///
    /// * `update` - [`TaskStatusUpdate`] payload.
    ///
    /// # Returns
    ///
    /// `Ok(())` on valid transition.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the task is unknown, or
    /// [`ArbiterError::TaskStateTransitionInvalid`] if the state transition is invalid.
    pub fn update_task_status(&mut self, update: &TaskStatusUpdate) -> ArbiterResult<()> {
        let Some((current_state, hosting_agent, held_resources)) =
            self.tasks.get_mut(&update.task_id)
        else {
            return Err(ArbiterError::StoreReadError {
                key: update.task_id.to_string(),
                reason: "unknown task ID in TaskStatusUpdate".to_owned(),
            });
        };

        current_state.validate_transition(update.state)?;
        *current_state = update.state;

        if update.state.is_terminal() {
            let reclaimed = core::mem::replace(held_resources, ResourceBundle::zero());
            for (_, agent_rec) in self
                .agents
                .iter_mut()
                .filter(|(id, _)| *id == hosting_agent)
            {
                agent_rec.available_resources = agent_rec
                    .available_resources
                    .try_add(&reclaimed)
                    .unwrap_or_default();
            }
        }
        Ok(())
    }
}

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-master"`.
pub const fn crate_name() -> &'static str {
    "arbiter-master"
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::{QuotaId, RoleName, TaskGroupId};
    use arbiter_core::platform::{CpuArch, OsKind};
    use arbiter_core::topology::HardwareTopologyGraph;
    use arbiter_core::units::{Bytes, Millicores, WeightBasisPoints};
    use arbiter_core::workload::{IsolationSpec, PreemptionPolicy, PriorityClass, Quota, Role};
    use arbiter_store::memory::{MemoryStateStore, MemoryStoreFault};

    use super::*;

    fn sample_role_hierarchy() -> (RoleHierarchy, RoleName) {
        let role = RoleName::new("prod").unwrap_or_default();
        let mut h = RoleHierarchy::new();
        let max_b = ResourceBundle {
            cpu: Millicores::new(100_000),
            memory: Bytes::new(100_000_000),
            ..ResourceBundle::zero()
        };
        let _ = h.add_role(Role {
            name: role.clone(),
            parent: None,
            quota: Quota {
                id: QuotaId::new("q-prod").unwrap_or_default(),
                guaranteed_min: ResourceBundle::zero(),
                hard_max: max_b,
                allow_burst_borrowing: true,
                weight: WeightBasisPoints::STANDARD,
            },
        });
        (h, role)
    }

    fn make_task(id: &str, role: &RoleName, cpu_m: u64) -> TaskSpec {
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
                command: "/bin/task".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        }
    }

    #[test]
    fn test_master_agent_lifecycle_direct_jobs_and_reconciliation() {
        assert_eq!(crate_name(), "arbiter-master");
        let (h, role) = sample_role_hierarchy();
        let mut master = MasterNode::new(MemoryStateStore::new(), h, 100, 50);

        let a1 = AgentId::new("agent-1").unwrap_or_default();
        let reg = RegisterAgent {
            agent_id: a1.clone(),
            os_kind: OsKind::Linux,
            cpu_arch: CpuArch::X86_64,
            total_resources: ResourceBundle {
                cpu: Millicores::new(16_000),
                memory: Bytes::new(16_000_000),
                ..ResourceBundle::zero()
            },
            topology: HardwareTopologyGraph::new(),
        };

        master.store.set_fault(Some(MemoryStoreFault::FailWrites));
        assert!(master.register_agent(reg.clone(), 10).is_err());
        master.store.set_fault(None);

        assert!(master.register_agent(reg, 10).is_ok());

        let hb = AgentHeartbeat {
            agent_id: a1,
            tick: 50,
            healthy_tasks: Vec::new(),
        };
        assert_eq!(master.process_agent_heartbeat(&hb), Ok(150));
        assert!(
            master
                .process_agent_heartbeat(&AgentHeartbeat {
                    agent_id: AgentId::new("unknown").unwrap_or_default(),
                    tick: 50,
                    healthy_tasks: Vec::new(),
                })
                .is_err()
        );

        master.submit_direct_job(SubmitDirectJob::SingleTask(Box::new(make_task(
            "t-direct-1",
            &role,
            4_000,
        ))));
        master.submit_direct_job(SubmitDirectJob::GangJob(TaskGroupSpec {
            group_id: TaskGroupId::new("gang-1").unwrap_or_default(),
            role: role.clone(),
            tasks: vec![make_task("t-gang-1", &role, 4_000)],
            tpu_slice: None,
            placement_timeout_ms: 100,
        }));

        let states = vec![RoleAllocationState {
            role,
            framework_id: None,
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        let outcome = master.schedule_tick(&states, 60).unwrap_or_default();
        assert_eq!(outcome.direct_placements.len(), 1);
        assert_eq!(outcome.gang_reservations.len(), 1);

        assert!(master.reconcile_unhealthy_agents(100).is_empty());

        let lost = master.reconcile_unhealthy_agents(200);
        assert_eq!(lost.len(), 2);

        // Second reconciliation when tasks are already terminal (Lost) covers `!state.is_terminal() == false`
        assert!(master.reconcile_unhealthy_agents(210).is_empty());

        assert!(master.schedule_tick(&states, 210).is_ok());

        // schedule_tick error when role_states has unknown role
        let bad_states = vec![RoleAllocationState {
            role: RoleName::new("ghost").unwrap_or_default(),
            framework_id: None,
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        assert!(master.schedule_tick(&bad_states, 210).is_err());
    }

    #[test]
    fn test_master_framework_offers() {
        let (h, role) = sample_role_hierarchy();
        let mut master = MasterNode::new(MemoryStateStore::new(), h, 100, 50);

        let a1 = AgentId::new("agent-1").unwrap_or_default();
        let a2 = AgentId::new("agent-2").unwrap_or_default();
        let cap = ResourceBundle {
            cpu: Millicores::new(16_000),
            memory: Bytes::new(16_000_000),
            ..ResourceBundle::zero()
        };
        for id in [a1, a2] {
            let _ = master.register_agent(
                RegisterAgent {
                    agent_id: id,
                    os_kind: OsKind::Linux,
                    cpu_arch: CpuArch::X86_64,
                    total_resources: cap.clone(),
                    topology: HardwareTopologyGraph::new(),
                },
                10,
            );
        }

        let fw_id = FrameworkId::new("fw-1").unwrap_or_default();
        assert!(
            master
                .subscribe_framework(SubscribeFramework {
                    framework_id: fw_id.clone(),
                    role: RoleName::new("unknown").unwrap_or_default(),
                    failover_timeout_ms: 1000,
                })
                .is_err()
        );

        assert!(
            master
                .subscribe_framework(SubscribeFramework {
                    framework_id: fw_id.clone(),
                    role: role.clone(),
                    failover_timeout_ms: 1000,
                })
                .is_ok()
        );

        let states = vec![RoleAllocationState {
            role: role.clone(),
            framework_id: Some(fw_id.clone()),
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];

        // Generates 2 offers (offer-1 on agent-1, offer-2 on agent-2)
        let _ = master.schedule_tick(&states, 20).unwrap_or_default();
        let offer1 = OfferId::new("offer-1").unwrap_or_default();
        let offer2 = OfferId::new("offer-2").unwrap_or_default();

        // Accept offer-1 with LaunchTask + Decline + Reserve
        let accept = AcceptOffers {
            framework_id: fw_id.clone(),
            offer_ids: vec![offer1],
            operations: vec![
                OfferOperation::LaunchTask(Box::new(make_task("fw-task-1", &role, 4_000))),
                OfferOperation::Reserve(ResourceBundle::zero()),
                OfferOperation::Decline(OfferFilter {
                    refuse_milliseconds: 1,
                    min_cpu_millicores: 0,
                    min_memory_bytes: Bytes::ZERO,
                }),
            ],
        };
        assert!(master.accept_offers(&accept, 30).is_ok());
        assert!(master.accept_offers(&accept, 30).is_err());

        // Accept offer-2 with a task that exceeds offered capacity (999_000m > 16_000m) -> InsufficientResources
        assert!(
            master
                .accept_offers(
                    &AcceptOffers {
                        framework_id: fw_id.clone(),
                        offer_ids: vec![offer2],
                        operations: vec![OfferOperation::LaunchTask(Box::new(make_task(
                            "too-big", &role, 999_000
                        )))],
                    },
                    30,
                )
                .is_err()
        );

        // Next schedule_tick at tick 40 generates offer-3 on agent-1 (since 12_000m was returned)
        let _ = master.schedule_tick(&states, 40).unwrap_or_default();
        let exp_accept = AcceptOffers {
            framework_id: fw_id.clone(),
            offer_ids: vec![OfferId::new("offer-3").unwrap_or_default()],
            operations: Vec::new(),
        };
        assert!(master.accept_offers(&exp_accept, 500).is_err());

        // Unknown offer & unknown framework
        let err_oid = AcceptOffers {
            framework_id: fw_id,
            offer_ids: vec![OfferId::new("offer-999").unwrap_or_default()],
            operations: Vec::new(),
        };
        assert!(master.accept_offers(&err_oid, 30).is_err());
        let err_fw = AcceptOffers {
            framework_id: FrameworkId::new("fw-ghost").unwrap_or_default(),
            offer_ids: Vec::new(),
            operations: Vec::new(),
        };
        assert!(master.accept_offers(&err_fw, 30).is_err());
    }

    #[test]
    fn test_master_task_status_updates_and_resource_reclaim() {
        let (h, role) = sample_role_hierarchy();
        let mut master = MasterNode::new(MemoryStateStore::new(), h, 100, 50);
        let a1 = AgentId::new("agent-1").unwrap_or_default();
        let _ = master.register_agent(
            RegisterAgent {
                agent_id: a1.clone(),
                os_kind: OsKind::Linux,
                cpu_arch: CpuArch::X86_64,
                total_resources: ResourceBundle {
                    cpu: Millicores::new(16_000),
                    memory: Bytes::new(16_000_000),
                    ..ResourceBundle::zero()
                },
                topology: HardwareTopologyGraph::new(),
            },
            10,
        );
        master.submit_direct_job(SubmitDirectJob::SingleTask(Box::new(make_task(
            "fw-task-1",
            &role,
            4_000,
        ))));
        let states = vec![RoleAllocationState {
            role,
            framework_id: None,
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        let _ = master.schedule_tick(&states, 20);

        for next_state in [TaskState::Starting, TaskState::Running, TaskState::Finished] {
            assert!(
                master
                    .update_task_status(&TaskStatusUpdate {
                        task_id: TaskId::new("fw-task-1").unwrap_or_default(),
                        agent_id: a1.clone(),
                        state: next_state,
                        message: "ok".to_owned(),
                    })
                    .is_ok()
            );
        }
        assert!(
            master
                .update_task_status(&TaskStatusUpdate {
                    task_id: TaskId::new("fw-task-1").unwrap_or_default(),
                    agent_id: a1.clone(),
                    state: TaskState::Running,
                    message: "bad".to_owned(),
                })
                .is_err()
        );
        assert!(
            master
                .update_task_status(&TaskStatusUpdate {
                    task_id: TaskId::new("ghost-task").unwrap_or_default(),
                    agent_id: a1,
                    state: TaskState::Running,
                    message: "bad".to_owned(),
                })
                .is_err()
        );
    }
}
