//! Master node state machine, scheduling coordinator, and cluster control plane for Arbiter (`arbiter-master`).
//!
//! Coordinates:
//! - Agent registration, heartbeat lease tracking, and unhealthy agent fencing/reconciliation.
//! - Framework registration, failover timeouts, and offer lifecycle management (`AcceptOffers`, `Decline`).
//! - Direct job submission queue, gang scheduling coordinator, and continuous HDRF allocation loop.
//! - State persistence via [`arbiter_store::traits::StateStore`] and zero-trust policy enforcement (`arbiter-net::security`).

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod bench;
pub mod sim;

use std::collections::{BTreeMap, BTreeSet};

use arbiter_alloc::drf::RoleAllocationState;
use arbiter_alloc::engine::{AllocationCycleOutcome, HybridAllocationEngine, RegisteredFramework};
use arbiter_alloc::federation::{
    BurstPeerCandidate, burst_gang_to_federation, burst_task_to_federation,
};
use arbiter_alloc::gang::GangAgentCandidate;
use arbiter_alloc::preemption::{
    PreemptionPlan, RunningTaskInstance, solve_minimum_disruption_preemption,
};
use arbiter_alloc::topology_packer::AgentHardwareInventory;
use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{
    AgentId, ClusterId, ExecutorId, FrameworkId, OfferId, OperationId, ResourceProviderId,
    RoleName, SpiffeId, StatusUpdateUuid, TaskGroupId, TaskId, VolumeId,
};
use arbiter_core::resources::ResourceBundle;
use arbiter_core::units::{BenchmarkTicks, Bytes, WeightBasisPoints};
use arbiter_core::workload::{
    AgentLossReason, AgentMaintenanceState, DrainCompletionMode, DynamicReservationSpec,
    ExecutorInfo, InverseOffer, MaintenanceSchedule, MasterInfo, OfferFilter, OfferOperation,
    OfferRescindReason, OperationState, Quota, ResourceOffer, ResourceProviderInfo, RoleHierarchy,
    TaskGroupSpec, TaskSpec, TaskState, VolumeReservationSpec,
};
use arbiter_net::security::{Decision, MesosAclAction, PolicyEngine};
use arbiter_proto::{
    AcceptOffers, AgentHeartbeat, OperatorCall, OperatorEvent, OperatorResponse, RegisterAgent,
    ResourceProviderCall, ResourceProviderEvent, SchedulerCall, SchedulerEvent, SubmitDirectJob,
    SubscribeFramework, TaskStatusUpdate, WIRE_SCHEMA_VERSION,
};
use arbiter_store::election::{ElectionPlane, LeaseGrant, MultiplexedAgentHeartbeat};
use arbiter_store::traits::{StateStore, StoreTransaction, TransactionOp};
use serde::{Deserialize, Serialize};

/// Connection and failover state for a subscribed 2-level Framework.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkConnectionRecord {
    /// Whether the Framework is currently connected over QUIC or SSE.
    pub connected: bool,
    /// Failover timeout in ticks before an un-reconnected Framework is torn down.
    pub failover_timeout_ticks: u64,
    /// Monotonic tick at which the Framework disconnected (`0` when connected).
    pub disconnected_at_tick: u64,
    /// Whether roles are currently suppressed by [`SchedulerCall::Suppress`].
    pub suppressed: bool,
    /// Set of suppressed [`RoleName`]s for per-role offer suppression (`Suppress` / `Revive`).
    #[serde(default)]
    pub suppressed_roles: BTreeSet<RoleName>,
}

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
    /// Per-Agent maintenance and draining state keyed by [`AgentId`].
    pub agent_maintenance: BTreeMap<AgentId, AgentMaintenanceState>,
    /// Per-Agent dynamically reserved capacity keyed by `(AgentId, RoleName)`.
    pub dynamic_reservations: BTreeMap<(AgentId, RoleName), ResourceBundle>,
    /// Hierarchical reservation refinement stacks keyed by `(AgentId, Vec<RoleName>)`.
    #[serde(default)]
    pub reservation_stacks: BTreeMap<(AgentId, Vec<RoleName>), ResourceBundle>,
    /// Registered Mesos CSI / External [`ResourceProviderInfo`]s keyed by [`ResourceProviderId`].
    #[serde(default)]
    pub resource_providers: BTreeMap<ResourceProviderId, ResourceProviderInfo>,
    ///Per-Agent persistent volumes keyed by `(AgentId, VolumeId)`.
    pub persistent_volumes: BTreeMap<(AgentId, VolumeId), (RoleName, VolumeReservationSpec)>,
    /// Shared persistent volume mount modes and active task reference counts keyed by `(AgentId, VolumeId)`.
    #[serde(default)]
    pub shared_volume_mounts:
        BTreeMap<(AgentId, VolumeId), (arbiter_core::workload::SharedVolumeMode, u32)>,
    /// Outbound wire messages (`LaunchExecutorTask`, `KillRunningTask`, `PreemptTaskCommand`, `FenceAgentRequest`)
    /// queued for dispatch to each [`AgentId`].
    #[serde(default)]
    pub outbound_agent_messages: BTreeMap<AgentId, Vec<arbiter_proto::WireMessage>>,
    /// Cluster maintenance schedule.
    pub maintenance_schedule: MaintenanceSchedule,
    /// Registered 2-level Frameworks keyed by [`FrameworkId`].
    pub frameworks: BTreeMap<FrameworkId, RegisteredFramework>,
    /// Framework connection and failover metadata keyed by [`FrameworkId`].
    pub framework_connections: BTreeMap<FrameworkId, FrameworkConnectionRecord>,
    /// Mapping from [`TaskId`] to owning [`FrameworkId`] for framework-launched tasks.
    pub task_owners: BTreeMap<TaskId, FrameworkId>,
    /// Active outstanding resource offers keyed by [`OfferId`].
    pub active_offers: BTreeMap<OfferId, ResourceOffer>,
    /// Active outstanding [`InverseOffer`]s keyed by [`OfferId`].
    pub active_inverse_offers: BTreeMap<OfferId, InverseOffer>,
    /// Consumed (accepted, declined, or rescinded) offer IDs.
    pub consumed_offers: BTreeSet<OfferId>,
    /// Unacknowledged [`TaskStatusUpdate`]s awaiting [`SchedulerCall::Acknowledge`].
    pub unacknowledged_updates: BTreeMap<StatusUpdateUuid, (FrameworkId, TaskStatusUpdate)>,
    /// Tracked offer operation states keyed by [`OperationId`].
    pub tracked_operations: BTreeMap<OperationId, (FrameworkId, Option<AgentId>, OperationState)>,
    /// Active custom Executors across the cluster.
    pub active_executors: BTreeMap<(AgentId, ExecutorId), FrameworkId>,
    /// Task lifecycle states and hosting Agent IDs keyed by [`TaskId`].
    pub tasks: BTreeMap<TaskId, (TaskState, AgentId, ResourceBundle)>,
    /// Pending direct tasks awaiting placement.
    pub pending_direct_tasks: Vec<TaskSpec>,
    /// Pending atomic gang jobs awaiting placement.
    pub pending_gang_jobs: Vec<TaskGroupSpec>,
    /// Streaming [`OperatorEvent`] log emitted for subscribed Operators.
    pub operator_event_log: Vec<OperatorEvent>,
    /// Whether the cluster defaults to partition-aware `TaskState::Unreachable` on transient Agent timeouts.
    pub partition_aware_tasks: bool,
    /// Active Master logging verbosity level (`0..=3`, default `1`).
    #[serde(default = "default_logging_level")]
    pub logging_level: u8,
    /// Virtual/persisted sandbox files keyed by file path for `LIST_FILES` and `READ_FILE` Operator calls.
    #[serde(default)]
    pub sandbox_files: BTreeMap<String, String>,
    /// Agent heartbeat lease TTL in ticks.
    pub agent_lease_ttl_ticks: u64,
}

/// Returns the default logging level (`1` = `INFO`).
///
/// # Returns
///
/// `1`.
const fn default_logging_level() -> u8 {
    1
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
            agent_maintenance: BTreeMap::new(),
            dynamic_reservations: BTreeMap::new(),
            reservation_stacks: BTreeMap::new(),
            resource_providers: BTreeMap::new(),
            persistent_volumes: BTreeMap::new(),
            shared_volume_mounts: BTreeMap::new(),
            outbound_agent_messages: BTreeMap::new(),
            maintenance_schedule: MaintenanceSchedule::default(),
            frameworks: BTreeMap::new(),
            framework_connections: BTreeMap::new(),
            task_owners: BTreeMap::new(),
            active_offers: BTreeMap::new(),
            active_inverse_offers: BTreeMap::new(),
            consumed_offers: BTreeSet::new(),
            unacknowledged_updates: BTreeMap::new(),
            tracked_operations: BTreeMap::new(),
            active_executors: BTreeMap::new(),
            tasks: BTreeMap::new(),
            pending_direct_tasks: Vec::new(),
            pending_gang_jobs: Vec::new(),
            operator_event_log: Vec::new(),
            partition_aware_tasks: false,
            logging_level: default_logging_level(),
            sandbox_files: BTreeMap::new(),
            agent_lease_ttl_ticks,
        }
    }

    /// Commits a batch of `(key, value)` puts and `delete_keys` to `self.store` via an atomic [`StoreTransaction`].
    ///
    /// # Arguments
    ///
    /// * `puts` - Slice of `(key, serialized_bytes)` pairs to write.
    /// * `deletes` - Slice of keys to delete.
    fn commit_store_puts_and_deletes(&mut self, puts: &[(String, Vec<u8>)], deletes: &[String]) {
        let mut ops = Vec::with_capacity(puts.len().saturating_add(deletes.len()));
        for (key, value) in puts {
            ops.push(TransactionOp::Put {
                key: key.clone(),
                value: value.clone(),
            });
        }
        for key in deletes {
            ops.push(TransactionOp::Delete { key: key.clone() });
        }
        if !ops.is_empty() {
            let _ = self
                .store
                .commit_transaction(&StoreTransaction { operations: ops });
        }
    }

    /// Registers an Agent with the Master (or re-registers a partitioned Agent), persisting its record to `store`.
    ///
    /// If the Agent had tasks in [`TaskState::Unreachable`], they are smoothly transitioned back to [`TaskState::Running`].
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
    #[inline(never)]
    pub fn register_agent(&mut self, reg: RegisterAgent, current_tick: u64) -> ArbiterResult<()> {
        let key = format!("/agents/{}", reg.agent_id);
        let bytes = serde_json::to_vec(&reg).unwrap_or_default();
        let _ = self.store.put(&key, bytes)?;

        let aid = reg.agent_id.clone();
        for (state, task_agent, _) in self.tasks.values_mut() {
            if task_agent == &aid {
                *state = TaskState::Running;
            }
        }
        let avail = reg.total_resources.clone();
        self.agent_maintenance
            .entry(aid.clone())
            .or_insert(AgentMaintenanceState::Normal);
        self.agents.insert(
            aid.clone(),
            MasterAgentRecord {
                registration: reg,
                available_resources: avail,
                lease_expires_at_tick: current_tick.saturating_add(self.agent_lease_ttl_ticks),
                healthy: true,
            },
        );
        self.operator_event_log.push(OperatorEvent::AgentAdded(aid));
        Ok(())
    }

    /// Reconstructs all 12 Master control-plane state maps (`/agents/*`, `/frameworks/*`, `/tasks/*`,
    /// `/offers/*`, `/reservations/*`, `/reservation_stacks/*`, `/resource_providers/*`, `/volumes/*`,
    /// `/quotas/*`, `/weights/*`, `/maintenance/*`, `/operations/*`, and `/caas_leases/*`) from `store`
    /// upon Raft leadership failover, enforcing the Mesos re-registration grace window
    /// (`current_tick + agent_lease_ttl_ticks`) before un-reregistered Agents can be marked `Unreachable`.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Monotonic tick of leader promotion.
    ///
    /// # Returns
    ///
    /// Number of Agent records recovered from the state store.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if reading from `store` fails.
    #[allow(clippy::too_many_lines)]
    pub fn recover_from_state_store(&mut self, current_tick: u64) -> ArbiterResult<usize> {
        let agent_entries = self.store.scan_prefix("/agents/")?;
        let mut recovered = 0_usize;
        for reg in agent_entries
            .into_iter()
            .filter_map(|e| serde_json::from_slice::<RegisterAgent>(&e.value).ok())
        {
            let avail = reg.total_resources.clone();
            let aid = reg.agent_id.clone();
            self.agent_maintenance
                .entry(aid.clone())
                .or_insert(AgentMaintenanceState::Normal);
            self.agents.insert(
                aid,
                MasterAgentRecord {
                    registration: reg,
                    available_resources: avail,
                    lease_expires_at_tick: current_tick.saturating_add(self.agent_lease_ttl_ticks),
                    healthy: true,
                },
            );
            recovered = recovered.saturating_add(1);
        }

        for (fw, conn) in self
            .store
            .scan_prefix("/frameworks/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                serde_json::from_slice::<(RegisteredFramework, FrameworkConnectionRecord)>(&e.value)
                    .ok()
            })
        {
            let fw_id = fw.framework_id.clone();
            self.frameworks.insert(fw_id.clone(), fw);
            self.framework_connections.insert(fw_id, conn);
        }

        for (tid, state, aid, res, owner) in self
            .store
            .scan_prefix("/tasks/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                serde_json::from_slice::<(
                    TaskId,
                    TaskState,
                    AgentId,
                    ResourceBundle,
                    Option<FrameworkId>,
                )>(&e.value)
                .ok()
            })
        {
            if let Some(fw_id) = owner {
                self.task_owners.insert(tid.clone(), fw_id);
            }
            self.tasks.insert(tid, (state, aid, res));
        }

        for offer in self
            .store
            .scan_prefix("/offers/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| serde_json::from_slice::<ResourceOffer>(&e.value).ok())
        {
            self.active_offers.insert(offer.offer_id.clone(), offer);
        }

        for (aid, role, bundle) in self
            .store
            .scan_prefix("/reservations/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                serde_json::from_slice::<(AgentId, RoleName, ResourceBundle)>(&e.value).ok()
            })
        {
            self.dynamic_reservations.insert((aid, role), bundle);
        }

        for (aid, stack, bundle) in self
            .store
            .scan_prefix("/reservation_stacks/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                serde_json::from_slice::<(AgentId, Vec<RoleName>, ResourceBundle)>(&e.value).ok()
            })
        {
            self.reservation_stacks.insert((aid, stack), bundle);
        }

        for rp in self
            .store
            .scan_prefix("/resource_providers/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| serde_json::from_slice::<ResourceProviderInfo>(&e.value).ok())
        {
            self.resource_providers.insert(rp.provider_id.clone(), rp);
        }

        for (aid, role, vol) in self
            .store
            .scan_prefix("/volumes/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                serde_json::from_slice::<(AgentId, RoleName, VolumeReservationSpec)>(&e.value).ok()
            })
        {
            self.persistent_volumes
                .insert((aid, vol.volume_id.clone()), (role, vol));
        }

        for (role, quota) in self
            .store
            .scan_prefix("/quotas/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| serde_json::from_slice::<(RoleName, Quota)>(&e.value).ok())
        {
            let _ = self.role_hierarchy.set_role_quota(&role, quota);
        }

        for (role, weight) in self
            .store
            .scan_prefix("/weights/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| serde_json::from_slice::<(RoleName, WeightBasisPoints)>(&e.value).ok())
        {
            let _ = self.role_hierarchy.update_role_weight(&role, weight);
        }

        for entry in self.store.scan_prefix("/maintenance/").unwrap_or_default() {
            if entry.key == "/maintenance/schedule" {
                self.maintenance_schedule =
                    serde_json::from_slice::<MaintenanceSchedule>(&entry.value).unwrap_or_default();
            }
        }
        for (aid, st) in self
            .store
            .scan_prefix("/maintenance/")
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.key != "/maintenance/schedule")
            .filter_map(|e| {
                serde_json::from_slice::<(AgentId, AgentMaintenanceState)>(&e.value).ok()
            })
        {
            self.agent_maintenance.insert(aid, st);
        }

        for (op_id, fw_id, aid, st) in self
            .store
            .scan_prefix("/operations/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                serde_json::from_slice::<(
                    OperationId,
                    FrameworkId,
                    Option<AgentId>,
                    OperationState,
                )>(&e.value)
                .ok()
            })
        {
            self.tracked_operations.insert(op_id, (fw_id, aid, st));
        }

        for grant in self
            .store
            .scan_prefix("/caas_leases/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| serde_json::from_slice::<LeaseGrant>(&e.value).ok())
        {
            self.election_plane.restore_lease(grant);
        }

        Ok(recovered)
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

        let renewed =
            self.election_plane
                .process_multiplexed_heartbeat(&MultiplexedAgentHeartbeat {
                    agent_id: hb.agent_id.clone(),
                    healthy_tasks: hb.healthy_tasks.clone(),
                    heartbeat_tick: hb.tick,
                });
        let mut puts = Vec::with_capacity(renewed.len());
        for grant in &renewed {
            puts.push((
                format!("/caas_leases/{}", grant.group_id),
                serde_json::to_vec(grant).unwrap_or_default(),
            ));
        }
        self.commit_store_puts_and_deletes(&puts, &[]);

        Ok(new_expiry)
    }

    /// Rescinds all active [`ResourceOffer`]s hosted on `agent_id` and returns their resources to the Agent's pool.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Target [`AgentId`].
    /// * `reason` - [`OfferRescindReason`] for the revocation.
    ///
    /// # Returns
    ///
    /// Vector of [`SchedulerEvent::Rescind`] events generated.
    pub fn rescind_offers_for_agent(
        &mut self,
        agent_id: &AgentId,
        reason: OfferRescindReason,
    ) -> Vec<SchedulerEvent> {
        let mut to_rescind = Vec::new();
        for (oid, offer) in &self.active_offers {
            if &offer.agent_id == agent_id {
                to_rescind.push((oid.clone(), offer.resources.clone()));
            }
        }
        let mut events = Vec::new();
        let mut deletes = Vec::with_capacity(to_rescind.len());
        for (oid, res) in to_rescind {
            self.active_offers.remove(&oid);
            self.consumed_offers.insert(oid.clone());
            deletes.push(format!("/offers/{oid}"));
            for (_, rec) in self.agents.iter_mut().filter(|(id, _)| *id == agent_id) {
                rec.available_resources = rec.available_resources.try_add(&res).unwrap_or_default();
            }
            events.push(SchedulerEvent::Rescind(oid, reason));
        }
        self.commit_store_puts_and_deletes(&[], &deletes);
        events
    }

    /// Reconciles Agent leases at `current_tick`, marking expired Agents unhealthy, rescinding their
    /// outstanding offers, and transitioning non-terminal tasks hosted on them to [`TaskState::Unreachable`]
    /// (when `partition_aware_tasks == true`) or [`TaskState::Lost`].
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Vector of `(AgentId, TaskId)` tasks transitioned to `Lost` or `Unreachable`.
    pub fn reconcile_unhealthy_agents(&mut self, current_tick: u64) -> Vec<(AgentId, TaskId)> {
        let mut expired_agents = BTreeSet::new();
        for (aid, rec) in &mut self.agents {
            if current_tick >= rec.lease_expires_at_tick {
                rec.healthy = false;
                expired_agents.insert(aid.clone());
            }
        }

        for aid in &expired_agents {
            let _ = self.rescind_offers_for_agent(aid, OfferRescindReason::AgentDisconnected);
        }

        let target_state = if self.partition_aware_tasks {
            TaskState::Unreachable
        } else {
            TaskState::Lost
        };

        let mut affected_tasks = Vec::new();
        for (tid, (state, aid, _)) in &mut self.tasks {
            if expired_agents.contains(aid)
                && !state.is_terminal()
                && *state != TaskState::Unreachable
            {
                *state = target_state;
                affected_tasks.push((aid.clone(), tid.clone()));
            }
        }
        affected_tasks
    }

    /// Expires and rescinds any active [`ResourceOffer`] whose `expires_at_tick <= current_tick`,
    /// returning its resources to the hosting Agent's available pool and emitting
    /// `(FrameworkId, SchedulerEvent::Rescind(offer_id, OfferRescindReason::OfferTtlExpired))`.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Vector of `(FrameworkId, SchedulerEvent)` rescind notifications.
    pub fn expire_and_rescind_stale_offers(
        &mut self,
        current_tick: u64,
    ) -> Vec<(FrameworkId, SchedulerEvent)> {
        let expired: Vec<(OfferId, FrameworkId, AgentId, ResourceBundle)> = self
            .active_offers
            .iter()
            .filter(|(_, o)| current_tick >= o.expires_at_tick)
            .map(|(oid, o)| {
                (
                    oid.clone(),
                    o.framework_id.clone(),
                    o.agent_id.clone(),
                    o.resources.clone(),
                )
            })
            .collect();
        let mut events = Vec::with_capacity(expired.len());
        let mut deletes = Vec::with_capacity(expired.len());
        for (oid, fw_id, aid, res) in expired {
            self.active_offers.remove(&oid);
            self.consumed_offers.insert(oid.clone());
            deletes.push(format!("/offers/{oid}"));
            for (_, rec) in self.agents.iter_mut().filter(|(id, _)| *id == &aid) {
                rec.available_resources = rec.available_resources.try_add(&res).unwrap_or_default();
            }
            events.push((
                fw_id,
                SchedulerEvent::Rescind(oid, OfferRescindReason::OfferTtlExpired),
            ));
        }
        self.commit_store_puts_and_deletes(&[], &deletes);
        events
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
    #[inline(never)]
    pub fn subscribe_framework(&mut self, sub: SubscribeFramework) -> ArbiterResult<()> {
        let _ = self.role_hierarchy.get_role(&sub.role)?;
        let SubscribeFramework {
            framework_id: fw_id,
            role,
            failover_timeout_ms: timeout,
        } = sub;
        let is_reconnection = self.frameworks.contains_key(&fw_id);

        let fw_rec = RegisteredFramework {
            framework_id: fw_id.clone(),
            role: role.clone(),
            filter: OfferFilter::default(),
            suppressed_agents: BTreeMap::new(),
        };
        let conn_rec = FrameworkConnectionRecord {
            connected: true,
            failover_timeout_ticks: timeout,
            disconnected_at_tick: 0,
            suppressed: false,
            suppressed_roles: BTreeSet::new(),
        };
        self.commit_store_puts_and_deletes(
            &[(
                format!("/frameworks/{fw_id}"),
                serde_json::to_vec(&(&fw_rec, &conn_rec)).unwrap_or_default(),
            )],
            &[],
        );
        self.frameworks.insert(fw_id.clone(), fw_rec);
        self.framework_connections.insert(fw_id.clone(), conn_rec);
        if is_reconnection {
            self.operator_event_log
                .push(OperatorEvent::FrameworkUpdated(fw_id));
        } else {
            self.operator_event_log
                .push(OperatorEvent::FrameworkAdded(fw_id, role));
        }
        Ok(())
    }

    /// Marks a subscribed Framework as disconnected at `current_tick` so its `failover_timeout_ticks` timer starts.
    ///
    /// # Arguments
    ///
    /// * `framework_id` - Disconnected [`FrameworkId`].
    /// * `current_tick` - Tick of disconnection.
    ///
    /// # Returns
    ///
    /// `Ok(())` when marked disconnected.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FrameworkNotFound`] if `framework_id` is not registered.
    pub fn mark_framework_disconnected(
        &mut self,
        framework_id: &FrameworkId,
        current_tick: u64,
    ) -> ArbiterResult<()> {
        let Some(conn) = self.framework_connections.get_mut(framework_id) else {
            return Err(ArbiterError::FrameworkNotFound {
                framework_id: framework_id.to_string(),
            });
        };
        conn.connected = false;
        conn.disconnected_at_tick = current_tick;
        Ok(())
    }

    /// Evaluates disconnected Frameworks against their `failover_timeout_ticks`, tearing down any expired Frameworks.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Vector of torn-down [`FrameworkId`]s.
    pub fn evaluate_framework_failover_timeouts(&mut self, current_tick: u64) -> Vec<FrameworkId> {
        let mut expired = Vec::new();
        for (fw_id, conn) in &self.framework_connections {
            if !conn.connected
                && current_tick
                    >= conn
                        .disconnected_at_tick
                        .saturating_add(conn.failover_timeout_ticks)
            {
                expired.push(fw_id.clone());
            }
        }
        for fw_id in &expired {
            let _ = self.teardown_framework(fw_id);
        }
        expired
    }

    /// Tears down a Framework, killing all its active tasks, rescinding its offers, and removing its registration.
    ///
    /// # Arguments
    ///
    /// * `framework_id` - [`FrameworkId`] to tear down.
    ///
    /// # Returns
    ///
    /// Number of active tasks terminated by the teardown.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FrameworkNotFound`] if `framework_id` is not registered.
    pub fn teardown_framework(&mut self, framework_id: &FrameworkId) -> ArbiterResult<usize> {
        if self.frameworks.remove(framework_id).is_none() {
            return Err(ArbiterError::FrameworkNotFound {
                framework_id: framework_id.to_string(),
            });
        }
        self.framework_connections.remove(framework_id);
        let mut deletes = vec![format!("/frameworks/{framework_id}")];
        let mut puts = Vec::new();

        // Rescind all active offers belonging to this framework
        let fw_offers: Vec<(OfferId, AgentId, ResourceBundle)> = self
            .active_offers
            .iter()
            .filter(|(_, o)| &o.framework_id == framework_id)
            .map(|(id, o)| (id.clone(), o.agent_id.clone(), o.resources.clone()))
            .collect();
        for (oid, aid, res) in fw_offers {
            self.active_offers.remove(&oid);
            self.consumed_offers.insert(oid.clone());
            deletes.push(format!("/offers/{oid}"));
            for (_, rec) in self.agents.iter_mut().filter(|(id, _)| *id == &aid) {
                rec.available_resources = rec.available_resources.try_add(&res).unwrap_or_default();
            }
        }

        // Kill all tasks owned by this framework
        let owned_tasks: Vec<TaskId> = self
            .task_owners
            .iter()
            .filter(|(_, fw)| *fw == framework_id)
            .map(|(tid, _)| tid.clone())
            .collect();
        let mut killed_count = 0_usize;
        for tid in owned_tasks {
            self.task_owners.remove(&tid);
            for (_, (state, aid, held)) in self.tasks.iter_mut().filter(|(id, _)| *id == &tid) {
                if !state.is_terminal() {
                    *state = TaskState::Killed;
                    let reclaimed = core::mem::replace(held, ResourceBundle::zero());
                    puts.push((
                        format!("/tasks/{tid}"),
                        serde_json::to_vec(&(
                            tid.clone(),
                            TaskState::Killed,
                            aid.clone(),
                            ResourceBundle::zero(),
                            None::<FrameworkId>,
                        ))
                        .unwrap_or_default(),
                    ));
                    for (_, rec) in self.agents.iter_mut().filter(|(id, _)| *id == aid) {
                        rec.available_resources = rec
                            .available_resources
                            .try_add(&reclaimed)
                            .unwrap_or_default();
                    }
                    killed_count = killed_count.saturating_add(1);
                }
            }
        }

        self.commit_store_puts_and_deletes(&puts, &deletes);
        self.active_executors.retain(|_, fw| fw != framework_id);
        self.operator_event_log
            .push(OperatorEvent::FrameworkRemoved(framework_id.clone()));
        Ok(killed_count)
    }

    /// Processes a Mesos v1 [`SchedulerCall`] and returns any resulting [`SchedulerEvent`]s.
    ///
    /// # Arguments
    ///
    /// * `call` - [`SchedulerCall`] from a Framework.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// Vector of [`SchedulerEvent`]s emitted in response.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if the Framework is unknown or an operation fails validation.
    #[allow(clippy::too_many_lines)]
    pub fn handle_scheduler_call(
        &mut self,
        call: SchedulerCall,
        current_tick: u64,
    ) -> ArbiterResult<Vec<SchedulerEvent>> {
        match call {
            SchedulerCall::Subscribe(sub, _, autoregister_roles, suppressed_roles) => {
                for r in &autoregister_roles {
                    let _ = self.role_hierarchy.get_role(r)?;
                }
                let fw_id = sub.framework_id.clone();
                let primary_role = sub.role.clone();
                self.subscribe_framework(sub)?;
                if !suppressed_roles.is_empty() {
                    for (_, conn) in self
                        .framework_connections
                        .iter_mut()
                        .filter(|(id, _)| *id == &fw_id)
                    {
                        for r in &suppressed_roles {
                            conn.suppressed_roles.insert(r.clone());
                        }
                        if conn.suppressed_roles.contains(&primary_role) {
                            conn.suppressed = true;
                        }
                    }
                }
                Ok(vec![SchedulerEvent::Subscribed(
                    fw_id,
                    MasterInfo {
                        leader_id: "master-1".to_owned(),
                        version: "0.1.0".to_owned(),
                        elected_term: 1,
                    },
                    BenchmarkTicks::new(self.agent_lease_ttl_ticks),
                )])
            }
            SchedulerCall::Teardown(framework_id) => {
                let _ = self.teardown_framework(&framework_id)?;
                Ok(Vec::new())
            }
            SchedulerCall::Accept(accept, operation_id, filter) => {
                let fw_id = accept.framework_id.clone();
                self.accept_offers(&accept, current_tick)?;
                let has_filter = (filter.refuse_milliseconds > 0)
                    | (filter.min_cpu_millicores > 0)
                    | (filter.min_memory_bytes > Bytes::ZERO)
                    | (filter.min_gpu_vram > Bytes::ZERO)
                    | filter.refuse_gpu_offers;
                if has_filter {
                    for (_, fw) in self.frameworks.iter_mut().filter(|(id, _)| *id == &fw_id) {
                        fw.filter = filter;
                    }
                }
                let mut events = Vec::new();
                if let Some(op_id) = operation_id {
                    self.tracked_operations.insert(
                        op_id.clone(),
                        (fw_id.clone(), None, OperationState::Finished),
                    );
                    self.commit_store_puts_and_deletes(
                        &[(
                            format!("/operations/{op_id}"),
                            serde_json::to_vec(&(
                                op_id.clone(),
                                fw_id,
                                None::<AgentId>,
                                OperationState::Finished,
                            ))
                            .unwrap_or_default(),
                        )],
                        &[],
                    );
                    events.push(SchedulerEvent::OperationUpdate(
                        op_id,
                        OperationState::Finished,
                        "offer operation committed".to_owned(),
                        None,
                    ));
                }
                Ok(events)
            }
            SchedulerCall::Decline(framework_id, offer_ids, filter) => {
                let accept = AcceptOffers {
                    framework_id,
                    offer_ids,
                    operations: vec![OfferOperation::Decline(filter)],
                };
                self.accept_offers(&accept, current_tick)?;
                Ok(Vec::new())
            }
            SchedulerCall::RespondInverseOffer(framework_id, inverse_offer_ids, _) => {
                if !self.frameworks.contains_key(&framework_id) {
                    return Err(ArbiterError::FrameworkNotFound {
                        framework_id: framework_id.to_string(),
                    });
                }
                for ioid in inverse_offer_ids {
                    self.active_inverse_offers.remove(&ioid);
                    self.consumed_offers.insert(ioid);
                }
                Ok(Vec::new())
            }
            SchedulerCall::Revive(framework_id, roles) => {
                let Some(fw) = self.frameworks.get_mut(&framework_id) else {
                    return Err(ArbiterError::FrameworkNotFound {
                        framework_id: framework_id.to_string(),
                    });
                };
                let primary_role = fw.role.clone();
                fw.filter = OfferFilter::default();
                fw.suppressed_agents.clear();
                for (_, conn) in self
                    .framework_connections
                    .iter_mut()
                    .filter(|(id, _)| *id == &framework_id)
                {
                    if roles.is_empty() {
                        conn.suppressed_roles.clear();
                        conn.suppressed = false;
                    } else {
                        for r in &roles {
                            conn.suppressed_roles.remove(r);
                        }
                        conn.suppressed = conn.suppressed_roles.contains(&primary_role);
                    }
                }
                Ok(Vec::new())
            }
            SchedulerCall::Suppress(framework_id, roles) => {
                let Some(primary_role) = self.frameworks.get(&framework_id).map(|f| f.role.clone())
                else {
                    return Err(ArbiterError::FrameworkNotFound {
                        framework_id: framework_id.to_string(),
                    });
                };
                for (_, conn) in self
                    .framework_connections
                    .iter_mut()
                    .filter(|(id, _)| *id == &framework_id)
                {
                    if roles.is_empty() {
                        conn.suppressed_roles.insert(primary_role.clone());
                        conn.suppressed = true;
                    } else {
                        for r in &roles {
                            conn.suppressed_roles.insert(r.clone());
                        }
                        conn.suppressed = conn.suppressed_roles.contains(&primary_role);
                    }
                }
                Ok(Vec::new())
            }
            SchedulerCall::Kill(framework_id, task_id, _, _) => {
                if !self.frameworks.contains_key(&framework_id) {
                    return Err(ArbiterError::FrameworkNotFound {
                        framework_id: framework_id.to_string(),
                    });
                }
                let Some((_, aid, _)) = self.tasks.get(&task_id).cloned() else {
                    return Err(ArbiterError::StoreReadError {
                        key: task_id.to_string(),
                        reason: "unknown task in Kill call".to_owned(),
                    });
                };
                let update = TaskStatusUpdate {
                    task_id,
                    agent_id: aid,
                    state: TaskState::Killed,
                    message: "killed by framework".to_owned(),
                };
                let _ = self.update_task_status(&update);
                let uuid =
                    StatusUpdateUuid::new(&format!("uuid-kill-{current_tick}")).unwrap_or_default();
                self.unacknowledged_updates
                    .insert(uuid.clone(), (framework_id, update.clone()));
                Ok(vec![SchedulerEvent::Update(update, Some(uuid))])
            }
            SchedulerCall::Shutdown(framework_id, executor_id, agent_id) => {
                if !self.frameworks.contains_key(&framework_id) {
                    return Err(ArbiterError::FrameworkNotFound {
                        framework_id: framework_id.to_string(),
                    });
                }
                self.active_executors
                    .remove(&(agent_id.clone(), executor_id.clone()));
                Ok(vec![SchedulerEvent::FailureExecutorLost(
                    agent_id,
                    executor_id,
                    0,
                )])
            }
            SchedulerCall::Acknowledge(framework_id, _, _, status_uuid)
            | SchedulerCall::AcknowledgeOperationStatus(framework_id, _, _, status_uuid) => {
                if !self.frameworks.contains_key(&framework_id) {
                    return Err(ArbiterError::FrameworkNotFound {
                        framework_id: framework_id.to_string(),
                    });
                }
                self.unacknowledged_updates.remove(&status_uuid);
                Ok(Vec::new())
            }
            SchedulerCall::ReconcileTasks(framework_id, tasks) => {
                if !self.frameworks.contains_key(&framework_id) {
                    return Err(ArbiterError::FrameworkNotFound {
                        framework_id: framework_id.to_string(),
                    });
                }
                let mut events = Vec::new();
                if tasks.is_empty() {
                    for (tid, (state, aid, _)) in &self.tasks {
                        if !state.is_terminal() {
                            events.push(SchedulerEvent::Update(
                                TaskStatusUpdate {
                                    task_id: tid.clone(),
                                    agent_id: aid.clone(),
                                    state: *state,
                                    message: "implicit reconciliation".to_owned(),
                                },
                                None,
                            ));
                        }
                    }
                } else {
                    for (tid, maybe_agent) in tasks {
                        if let Some((state, aid, _)) = self.tasks.get(&tid) {
                            events.push(SchedulerEvent::Update(
                                TaskStatusUpdate {
                                    task_id: tid,
                                    agent_id: aid.clone(),
                                    state: *state,
                                    message: "explicit reconciliation".to_owned(),
                                },
                                None,
                            ));
                        } else {
                            let fallback_agent = maybe_agent.unwrap_or_else(|| {
                                AgentId::new("unknown-agent").unwrap_or_default()
                            });
                            events.push(SchedulerEvent::Update(
                                TaskStatusUpdate {
                                    task_id: tid,
                                    agent_id: fallback_agent,
                                    state: TaskState::Unknown,
                                    message: "task unknown to master".to_owned(),
                                },
                                None,
                            ));
                        }
                    }
                }
                Ok(events)
            }
            SchedulerCall::ReconcileOperations(framework_id, operations) => {
                if !self.frameworks.contains_key(&framework_id) {
                    return Err(ArbiterError::FrameworkNotFound {
                        framework_id: framework_id.to_string(),
                    });
                }
                let mut events = Vec::new();
                for (op_id, _, _) in operations {
                    let state = self
                        .tracked_operations
                        .get(&op_id)
                        .map_or(OperationState::Unknown, |(_, _, st)| *st);
                    events.push(SchedulerEvent::OperationUpdate(
                        op_id,
                        state,
                        "reconciled operation".to_owned(),
                        None,
                    ));
                }
                Ok(events)
            }
            SchedulerCall::Message(framework_id, agent_id, executor_id, payload) => {
                if !self.frameworks.contains_key(&framework_id) {
                    return Err(ArbiterError::FrameworkNotFound {
                        framework_id: framework_id.to_string(),
                    });
                }
                self.active_executors.insert(
                    (agent_id.clone(), executor_id.clone()),
                    framework_id.clone(),
                );
                Ok(vec![SchedulerEvent::Message(
                    agent_id,
                    framework_id,
                    executor_id,
                    payload,
                )])
            }
            SchedulerCall::Request(framework_id, _) => {
                if !self.frameworks.contains_key(&framework_id) {
                    return Err(ArbiterError::FrameworkNotFound {
                        framework_id: framework_id.to_string(),
                    });
                }
                Ok(vec![SchedulerEvent::Heartbeat])
            }
        }
    }

    /// Processes a Mesos v1 [`ResourceProviderCall`] (`/api/v1/resource_provider`) from a local CSI
    /// or external fabric Resource Provider, updating advertised storage inventory and operation states.
    ///
    /// # Arguments
    ///
    /// * `call` - [`ResourceProviderCall`] message.
    ///
    /// # Returns
    ///
    /// Vector of [`ResourceProviderEvent`]s emitted to the Resource Provider.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the Resource Provider or hosting Agent is unknown.
    pub fn handle_resource_provider_call(
        &mut self,
        call: ResourceProviderCall,
    ) -> ArbiterResult<Vec<ResourceProviderEvent>> {
        match call {
            ResourceProviderCall::Subscribe(info) => {
                if let Some(ref aid) = info.agent_id {
                    if !self.agents.contains_key(aid) {
                        return Err(ArbiterError::StoreReadError {
                            key: aid.to_string(),
                            reason: "unknown hosting agent in ResourceProviderCall::Subscribe"
                                .to_owned(),
                        });
                    }
                }
                let pid = info.provider_id.clone();
                self.commit_store_puts_and_deletes(
                    &[(
                        format!("/resource_providers/{pid}"),
                        serde_json::to_vec(&info).unwrap_or_default(),
                    )],
                    &[],
                );
                self.resource_providers.insert(pid.clone(), info);
                Ok(vec![ResourceProviderEvent::Subscribed(pid)])
            }
            ResourceProviderCall::UpdateOperationStatus(
                provider_id,
                operation_id,
                state,
                status_uuid,
                converted_disk,
            ) => {
                let Some(rp) = self.resource_providers.get_mut(&provider_id) else {
                    return Err(ArbiterError::StoreReadError {
                        key: provider_id.to_string(),
                        reason: "unknown resource provider in UpdateOperationStatus".to_owned(),
                    });
                };
                if let Some(disk_spec) = converted_disk {
                    rp.advertised_disks
                        .push((disk_spec.source, disk_spec.capacity));
                }
                let rp_clone = rp.clone();
                for (_, (_, _, st)) in self
                    .tracked_operations
                    .iter_mut()
                    .filter(|(id, _)| *id == &operation_id)
                {
                    *st = state;
                }
                self.commit_store_puts_and_deletes(
                    &[(
                        format!("/resource_providers/{provider_id}"),
                        serde_json::to_vec(&rp_clone).unwrap_or_default(),
                    )],
                    &[],
                );
                Ok(vec![ResourceProviderEvent::AcknowledgeOperationStatus(
                    operation_id,
                    status_uuid,
                )])
            }
            ResourceProviderCall::UpdateState(provider_id, _, advertised_disks) => {
                let Some(rp) = self.resource_providers.get_mut(&provider_id) else {
                    return Err(ArbiterError::StoreReadError {
                        key: provider_id.to_string(),
                        reason: "unknown resource provider in UpdateState".to_owned(),
                    });
                };
                rp.advertised_disks = advertised_disks;
                let rp_clone = rp.clone();
                self.commit_store_puts_and_deletes(
                    &[(
                        format!("/resource_providers/{provider_id}"),
                        serde_json::to_vec(&rp_clone).unwrap_or_default(),
                    )],
                    &[],
                );
                Ok(Vec::new())
            }
            ResourceProviderCall::UpdatePublishResourcesStatus(provider_id, _, ok) => {
                if !self.resource_providers.contains_key(&provider_id) {
                    return Err(ArbiterError::StoreReadError {
                        key: provider_id.to_string(),
                        reason: "unknown resource provider in UpdatePublishResourcesStatus"
                            .to_owned(),
                    });
                }
                if !ok {
                    return Err(ArbiterError::CsiRpcError {
                        method: "PublishResources".to_owned(),
                        volume_id: provider_id.to_string(),
                        reason: format!("resource provider '{provider_id}' failed to publish"),
                    });
                }
                Ok(Vec::new())
            }
        }
    }

    /// Processes a Mesos v1 [`OperatorCall`] against the Master state machine.
    ///
    /// # Arguments
    ///
    /// * `call` - [`OperatorCall`] administrative request.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// [`OperatorResponse`] result.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if a referenced Agent, Role, Quota, Reservation, or Volume is invalid.
    #[allow(clippy::too_many_lines)]
    pub fn handle_operator_call(
        &mut self,
        call: OperatorCall,
        current_tick: u64,
    ) -> ArbiterResult<OperatorResponse> {
        match call {
            OperatorCall::GetHealth => Ok(OperatorResponse::Health(true)),
            OperatorCall::GetVersion => Ok(OperatorResponse::Version(
                "0.1.0".to_owned(),
                WIRE_SCHEMA_VERSION,
            )),
            OperatorCall::GetMetrics => Ok(OperatorResponse::Metrics(
                self.agents.len() as u64,
                self.tasks.len() as u64,
                self.active_offers.len() as u64,
            )),
            OperatorCall::GetFlags => Ok(OperatorResponse::Flags(
                self.agent_lease_ttl_ticks,
                self.agent_lease_ttl_ticks / 2,
            )),
            OperatorCall::GetMaster => Ok(OperatorResponse::Master(MasterInfo {
                leader_id: "master-1".to_owned(),
                version: "0.1.0".to_owned(),
                elected_term: 1,
            })),
            OperatorCall::GetAgents | OperatorCall::GetState => {
                let mut list = Vec::new();
                for (aid, rec) in &self.agents {
                    let maint = self.agent_maintenance.get(aid).cloned().unwrap_or_default();
                    list.push((
                        aid.clone(),
                        rec.healthy,
                        maint,
                        rec.available_resources.clone(),
                    ));
                }
                Ok(OperatorResponse::Agents(list))
            }
            OperatorCall::GetFrameworks => {
                let mut list = Vec::new();
                for (fw_id, fw) in &self.frameworks {
                    let conn = self
                        .framework_connections
                        .get(fw_id)
                        .is_none_or(|c| c.connected);
                    list.push((fw_id.clone(), fw.role.clone(), conn));
                }
                Ok(OperatorResponse::Frameworks(list))
            }
            OperatorCall::GetExecutors => {
                let mut list = Vec::new();
                for (aid, eid) in self.active_executors.keys() {
                    list.push(ExecutorInfo {
                        executor_id: eid.clone(),
                        agent_id: aid.clone(),
                    });
                }
                Ok(OperatorResponse::Executors(list))
            }
            OperatorCall::GetTasks => {
                let list = self
                    .tasks
                    .iter()
                    .map(|(tid, (st, aid, res))| (tid.clone(), *st, aid.clone(), res.clone()))
                    .collect();
                Ok(OperatorResponse::Tasks(list))
            }
            OperatorCall::GetRoles | OperatorCall::GetQuota => Ok(OperatorResponse::Roles(
                self.role_hierarchy.roles().to_vec(),
            )),
            OperatorCall::GetWeights => {
                let weights = self
                    .role_hierarchy
                    .roles()
                    .iter()
                    .map(|r| (r.name.clone(), r.quota.weight))
                    .collect();
                Ok(OperatorResponse::Weights(weights))
            }
            OperatorCall::UpdateWeights(weight_infos) => {
                let mut puts = Vec::with_capacity(weight_infos.len());
                for (role, weight) in weight_infos {
                    self.role_hierarchy.update_role_weight(&role, weight)?;
                    puts.push((
                        format!("/weights/{role}"),
                        serde_json::to_vec(&(&role, weight)).unwrap_or_default(),
                    ));
                }
                self.commit_store_puts_and_deletes(&puts, &[]);
                Ok(OperatorResponse::Ok("weights updated".to_owned()))
            }
            OperatorCall::SetQuota(role, quota) => {
                self.role_hierarchy.set_role_quota(&role, quota.clone())?;
                self.commit_store_puts_and_deletes(
                    &[(
                        format!("/quotas/{role}"),
                        serde_json::to_vec(&(&role, &quota)).unwrap_or_default(),
                    )],
                    &[],
                );
                Ok(OperatorResponse::Ok("quota set".to_owned()))
            }
            OperatorCall::RemoveQuota(role) => {
                self.role_hierarchy.remove_role_quota(&role)?;
                self.commit_store_puts_and_deletes(&[], &[format!("/quotas/{role}")]);
                Ok(OperatorResponse::Ok("quota removed".to_owned()))
            }
            OperatorCall::ReserveResources(reservation) => {
                self.apply_dynamic_reservation(&reservation)?;
                Ok(OperatorResponse::Ok("resources reserved".to_owned()))
            }
            OperatorCall::UnreserveResources(reservation) => {
                self.release_dynamic_reservation(&reservation)?;
                Ok(OperatorResponse::Ok("resources unreserved".to_owned()))
            }
            OperatorCall::CreateVolumes(agent_id, role, volumes) => {
                for vol in volumes {
                    self.create_persistent_volume(&agent_id, &role, vol)?;
                }
                Ok(OperatorResponse::Ok("volumes created".to_owned()))
            }
            OperatorCall::DestroyVolumes(agent_id, volume_ids) => {
                for vid in volume_ids {
                    self.destroy_persistent_volume(&agent_id, &vid)?;
                }
                Ok(OperatorResponse::Ok("volumes destroyed".to_owned()))
            }
            OperatorCall::GrowVolume(agent_id, volume_id, additional_bytes) => {
                let _ = self.grow_persistent_volume(&agent_id, &volume_id, additional_bytes)?;
                Ok(OperatorResponse::Ok("volume grown".to_owned()))
            }
            OperatorCall::ShrinkVolume(agent_id, volume_id, subtract_bytes) => {
                let _ = self.shrink_persistent_volume(&agent_id, &volume_id, subtract_bytes)?;
                Ok(OperatorResponse::Ok("volume shrunk".to_owned()))
            }
            OperatorCall::GetLoggingLevel => Ok(OperatorResponse::LoggingLevel(self.logging_level)),
            OperatorCall::SetLoggingLevel(level, _) => {
                let parsed = arbiter_core::units::LoggingLevel::from_u8(level)?;
                self.logging_level = parsed.as_u8();
                Ok(OperatorResponse::Ok("logging level updated".to_owned()))
            }
            OperatorCall::ListFiles(prefix) => {
                let matches = self
                    .sandbox_files
                    .keys()
                    .filter(|p| p.starts_with(&prefix))
                    .cloned()
                    .collect();
                Ok(OperatorResponse::FileList(matches))
            }
            OperatorCall::ReadFile(path, offset, length) => {
                let Some(content) = self.sandbox_files.get(&path) else {
                    return Err(ArbiterError::StoreReadError {
                        key: path,
                        reason: "sandbox file not found in ReadFile".to_owned(),
                    });
                };
                let start = usize::try_from(offset).unwrap_or(0).min(content.len());
                let end = start
                    .saturating_add(usize::try_from(length).unwrap_or(0))
                    .min(content.len());
                let chunk = content.get(start..end).unwrap_or("").to_owned();
                Ok(OperatorResponse::FileChunk(offset, chunk))
            }
            OperatorCall::GetMaintenanceSchedule => Ok(OperatorResponse::MaintenanceSchedule(
                self.maintenance_schedule.clone(),
            )),
            OperatorCall::UpdateMaintenanceSchedule(schedule) => {
                self.update_maintenance_schedule(schedule, current_tick)?;
                Ok(OperatorResponse::Ok(
                    "maintenance schedule updated".to_owned(),
                ))
            }
            OperatorCall::GetMaintenanceStatus => {
                let statuses = self
                    .agent_maintenance
                    .iter()
                    .map(|(aid, st)| (aid.clone(), st.clone()))
                    .collect();
                Ok(OperatorResponse::MaintenanceStatus(statuses))
            }
            OperatorCall::StartMaintenance(agents) => {
                let mut puts = Vec::with_capacity(agents.len());
                for aid in agents {
                    if !self.agents.contains_key(&aid) {
                        return Err(ArbiterError::StoreReadError {
                            key: aid.to_string(),
                            reason: "unknown agent in StartMaintenance".to_owned(),
                        });
                    }
                    let _ = self.rescind_offers_for_agent(
                        &aid,
                        OfferRescindReason::AgentEnteredMaintenance,
                    );
                    puts.push((
                        format!("/maintenance/{aid}"),
                        serde_json::to_vec(&(&aid, AgentMaintenanceState::Deactivated))
                            .unwrap_or_default(),
                    ));
                    self.agent_maintenance
                        .insert(aid, AgentMaintenanceState::Deactivated);
                }
                self.commit_store_puts_and_deletes(&puts, &[]);
                Ok(OperatorResponse::Ok("maintenance started".to_owned()))
            }
            OperatorCall::StopMaintenance(agents) => {
                let mut puts = Vec::with_capacity(agents.len());
                for aid in agents {
                    if !self.agents.contains_key(&aid) {
                        return Err(ArbiterError::StoreReadError {
                            key: aid.to_string(),
                            reason: "unknown agent in StopMaintenance".to_owned(),
                        });
                    }
                    puts.push((
                        format!("/maintenance/{aid}"),
                        serde_json::to_vec(&(&aid, AgentMaintenanceState::Normal))
                            .unwrap_or_default(),
                    ));
                    self.agent_maintenance
                        .insert(aid, AgentMaintenanceState::Normal);
                }
                self.commit_store_puts_and_deletes(&puts, &[]);
                Ok(OperatorResponse::Ok("maintenance stopped".to_owned()))
            }
            OperatorCall::DrainAgent(agent_id, max_grace_period_ticks, completion_mode) => {
                self.drain_agent(&agent_id, max_grace_period_ticks, completion_mode)?;
                Ok(OperatorResponse::Ok("agent draining".to_owned()))
            }
            OperatorCall::DeactivateAgent(agent_id) => {
                if !self.agents.contains_key(&agent_id) {
                    return Err(ArbiterError::StoreReadError {
                        key: agent_id.to_string(),
                        reason: "unknown agent in DeactivateAgent".to_owned(),
                    });
                }
                let _ = self.rescind_offers_for_agent(
                    &agent_id,
                    OfferRescindReason::AgentEnteredMaintenance,
                );
                self.commit_store_puts_and_deletes(
                    &[(
                        format!("/maintenance/{agent_id}"),
                        serde_json::to_vec(&(&agent_id, AgentMaintenanceState::Deactivated))
                            .unwrap_or_default(),
                    )],
                    &[],
                );
                self.agent_maintenance
                    .insert(agent_id, AgentMaintenanceState::Deactivated);
                Ok(OperatorResponse::Ok("agent deactivated".to_owned()))
            }
            OperatorCall::ReactivateAgent(agent_id) => {
                if !self.agents.contains_key(&agent_id) {
                    return Err(ArbiterError::StoreReadError {
                        key: agent_id.to_string(),
                        reason: "unknown agent in ReactivateAgent".to_owned(),
                    });
                }
                self.commit_store_puts_and_deletes(
                    &[(
                        format!("/maintenance/{agent_id}"),
                        serde_json::to_vec(&(&agent_id, AgentMaintenanceState::Normal))
                            .unwrap_or_default(),
                    )],
                    &[],
                );
                self.agent_maintenance
                    .insert(agent_id, AgentMaintenanceState::Normal);
                Ok(OperatorResponse::Ok("agent reactivated".to_owned()))
            }
            OperatorCall::MarkAgentGone(agent_id) => {
                self.mark_agent_gone(&agent_id)?;
                Ok(OperatorResponse::Ok("agent marked gone".to_owned()))
            }
            OperatorCall::SubscribeOperatorEvents => Ok(OperatorResponse::Ok(format!(
                "subscribed ({} buffered events)",
                self.operator_event_log.len()
            ))),
        }
    }

    /// Dynamically reserves `spec.resources` on `spec.agent_id` for `spec.role` and persists to `store`.
    ///
    /// # Arguments
    ///
    /// * `spec` - [`DynamicReservationSpec`] to apply.
    ///
    /// # Returns
    ///
    /// `Ok(())` when reserved.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RoleNotFound`], [`ArbiterError::StoreReadError`] (unknown agent),
    /// or [`ArbiterError::InsufficientResources`].
    pub fn apply_dynamic_reservation(
        &mut self,
        spec: &DynamicReservationSpec,
    ) -> ArbiterResult<()> {
        let _ = self.role_hierarchy.get_role(&spec.role)?;
        let Some(agent_rec) = self.agents.get_mut(&spec.agent_id) else {
            return Err(ArbiterError::StoreReadError {
                key: spec.agent_id.to_string(),
                reason: "unknown agent in apply_dynamic_reservation".to_owned(),
            });
        };
        agent_rec.available_resources = agent_rec.available_resources.try_sub(&spec.resources)?;
        let current = self
            .dynamic_reservations
            .get(&(spec.agent_id.clone(), spec.role.clone()))
            .cloned()
            .unwrap_or_default();
        let updated = current.try_add(&spec.resources).unwrap_or_default();
        let key = format!("/reservations/{}/{}", spec.agent_id, spec.role);
        let _ = self.store.put(
            &key,
            serde_json::to_vec(&(&spec.agent_id, &spec.role, &updated)).unwrap_or_default(),
        );
        self.dynamic_reservations
            .insert((spec.agent_id.clone(), spec.role.clone()), updated);
        Ok(())
    }

    /// Releases previously dynamically reserved resources back to `spec.agent_id`'s unreserved pool.
    ///
    /// # Arguments
    ///
    /// * `spec` - [`DynamicReservationSpec`] to release.
    ///
    /// # Returns
    ///
    /// `Ok(())` when unreserved.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the reservation or Agent does not exist,
    /// or [`ArbiterError::InsufficientResources`] if releasing more than reserved.
    pub fn release_dynamic_reservation(
        &mut self,
        spec: &DynamicReservationSpec,
    ) -> ArbiterResult<()> {
        let Some(current) = self
            .dynamic_reservations
            .get(&(spec.agent_id.clone(), spec.role.clone()))
            .cloned()
        else {
            return Err(ArbiterError::StoreReadError {
                key: format!("{}/{}", spec.agent_id, spec.role),
                reason: "no active dynamic reservation for agent and role".to_owned(),
            });
        };
        let remaining = current.try_sub(&spec.resources)?;
        for (_, agent_rec) in self
            .agents
            .iter_mut()
            .filter(|(id, _)| *id == &spec.agent_id)
        {
            agent_rec.available_resources = agent_rec
                .available_resources
                .try_add(&spec.resources)
                .unwrap_or_default();
        }
        let key = format!("/reservations/{}/{}", spec.agent_id, spec.role);
        let _ = self.store.put(
            &key,
            serde_json::to_vec(&(&spec.agent_id, &spec.role, &remaining)).unwrap_or_default(),
        );
        self.dynamic_reservations
            .insert((spec.agent_id.clone(), spec.role.clone()), remaining);
        Ok(())
    }

    /// Creates a persistent volume on `agent_id` bound to `role`.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Hosting [`AgentId`].
    /// * `role` - Owning [`RoleName`].
    /// * `vol` - [`VolumeReservationSpec`].
    ///
    /// # Returns
    ///
    /// `Ok(())` when created.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `agent_id` is unknown, or
    /// [`ArbiterError::StoreWriteError`] if `vol.volume_id` already exists on `agent_id`.
    pub fn create_persistent_volume(
        &mut self,
        agent_id: &AgentId,
        role: &RoleName,
        vol: VolumeReservationSpec,
    ) -> ArbiterResult<()> {
        if !self.agents.contains_key(agent_id) {
            return Err(ArbiterError::StoreReadError {
                key: agent_id.to_string(),
                reason: "unknown agent in create_persistent_volume".to_owned(),
            });
        }
        let tuple_key = (agent_id.clone(), vol.volume_id.clone());
        if self.persistent_volumes.contains_key(&tuple_key) {
            return Err(ArbiterError::StoreWriteError {
                key: vol.volume_id.to_string(),
                reason: "persistent volume already exists on agent".to_owned(),
            });
        }
        let store_key = format!("/volumes/{}/{}", agent_id, vol.volume_id);
        let _ = self.store.put(
            &store_key,
            serde_json::to_vec(&(agent_id, role, &vol)).unwrap_or_default(),
        );
        self.persistent_volumes
            .insert(tuple_key, (role.clone(), vol));
        Ok(())
    }

    /// Destroys a persistent volume on `agent_id`.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Hosting [`AgentId`].
    /// * `volume_id` - [`VolumeId`] to destroy.
    ///
    /// # Returns
    ///
    /// `Ok(())` when destroyed.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the volume does not exist on `agent_id`, or
    /// [`ArbiterError::StoreWriteError`] if the volume is currently mounted by active tasks.
    pub fn destroy_persistent_volume(
        &mut self,
        agent_id: &AgentId,
        volume_id: &VolumeId,
    ) -> ArbiterResult<()> {
        let tuple_key = (agent_id.clone(), volume_id.clone());
        let active_refs = self
            .shared_volume_mounts
            .get(&tuple_key)
            .map_or(0, |(_, refs)| *refs);
        if active_refs > 0 {
            return Err(ArbiterError::StoreWriteError {
                key: volume_id.to_string(),
                reason: format!(
                    "cannot destroy persistent volume while mounted by {active_refs} active tasks"
                ),
            });
        }
        if self.persistent_volumes.remove(&tuple_key).is_none() {
            return Err(ArbiterError::StoreReadError {
                key: volume_id.to_string(),
                reason: "persistent volume not found on agent".to_owned(),
            });
        }
        let store_key = format!("/volumes/{agent_id}/{volume_id}");
        let _ = self.store.delete(&store_key);
        Ok(())
    }

    /// Mounts a persistent volume on `agent_id` with `mode` ([`arbiter_core::workload::SharedVolumeMode`]),
    /// enforcing exclusive vs. shared (`SharedReadOnly` / `SharedReadWrite`) reference counting.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Hosting [`AgentId`].
    /// * `volume_id` - Target [`VolumeId`].
    /// * `mode` - Requested [`arbiter_core::workload::SharedVolumeMode`].
    ///
    /// # Returns
    ///
    /// Updated active mount reference count (`>= 1`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the volume does not exist on `agent_id`, or
    /// [`ArbiterError::StoreWriteError`] if an `Exclusive` volume is already mounted or a shared
    /// volume is requested with a conflicting mode.
    pub fn mount_shared_persistent_volume(
        &mut self,
        agent_id: &AgentId,
        volume_id: &VolumeId,
        mode: arbiter_core::workload::SharedVolumeMode,
    ) -> ArbiterResult<u32> {
        let tuple_key = (agent_id.clone(), volume_id.clone());
        if !self.persistent_volumes.contains_key(&tuple_key) {
            return Err(ArbiterError::StoreReadError {
                key: volume_id.to_string(),
                reason: "persistent volume not found on agent in mount_shared_persistent_volume"
                    .to_owned(),
            });
        }
        let (existing_mode, current_refs) = self
            .shared_volume_mounts
            .get(&tuple_key)
            .copied()
            .unwrap_or((mode, 0));
        if current_refs > 0
            && (existing_mode == arbiter_core::workload::SharedVolumeMode::Exclusive
                || mode == arbiter_core::workload::SharedVolumeMode::Exclusive
                || existing_mode != mode)
        {
            return Err(ArbiterError::StoreWriteError {
                key: volume_id.to_string(),
                reason: "conflicting or exclusive persistent volume mount already active"
                    .to_owned(),
            });
        }
        let next_refs = current_refs.saturating_add(1);
        self.shared_volume_mounts
            .insert(tuple_key, (mode, next_refs));
        Ok(next_refs)
    }

    /// Unmounts a persistent volume on `agent_id`, decrementing its active reference count.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Hosting [`AgentId`].
    /// * `volume_id` - Target [`VolumeId`].
    ///
    /// # Returns
    ///
    /// Remaining active mount reference count.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the volume has no active mounts on `agent_id`.
    pub fn unmount_shared_persistent_volume(
        &mut self,
        agent_id: &AgentId,
        volume_id: &VolumeId,
    ) -> ArbiterResult<u32> {
        let tuple_key = (agent_id.clone(), volume_id.clone());
        let Some((mode, current_refs)) = self.shared_volume_mounts.get(&tuple_key).copied() else {
            return Err(ArbiterError::StoreReadError {
                key: volume_id.to_string(),
                reason: "persistent volume is not currently mounted on agent".to_owned(),
            });
        };
        let next_refs = current_refs.saturating_sub(1);
        if next_refs == 0 {
            self.shared_volume_mounts.remove(&tuple_key);
        } else {
            self.shared_volume_mounts
                .insert(tuple_key, (mode, next_refs));
        }
        Ok(next_refs)
    }

    /// Enqueues a [`arbiter_proto::WireMessage`] for outbound network dispatch to `agent_id`.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Target [`AgentId`].
    /// * `message` - Outbound [`arbiter_proto::WireMessage`].
    pub fn queue_agent_wire_message(
        &mut self,
        agent_id: &AgentId,
        message: arbiter_proto::WireMessage,
    ) {
        self.outbound_agent_messages
            .entry(agent_id.clone())
            .or_default()
            .push(message);
    }

    /// Drains and returns all queued outbound [`arbiter_proto::WireMessage`]s for `agent_id`.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Target [`AgentId`].
    ///
    /// # Returns
    ///
    /// Vector of queued [`arbiter_proto::WireMessage`]s in FIFO order.
    pub fn drain_outbound_agent_messages(
        &mut self,
        agent_id: &AgentId,
    ) -> Vec<arbiter_proto::WireMessage> {
        self.outbound_agent_messages
            .remove(agent_id)
            .unwrap_or_default()
    }

    /// Expands an existing persistent volume on `agent_id` by `additional_bytes` (`GROW_VOLUME`),
    /// deducting `additional_bytes` from the Agent's available disk pool.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Hosting [`AgentId`].
    /// * `volume_id` - Target [`VolumeId`].
    /// * `additional_bytes` - Additional [`Bytes`] to add (`> 0`).
    ///
    /// # Returns
    ///
    /// Updated volume capacity in [`Bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the volume or Agent is unknown, or
    /// [`ArbiterError::InsufficientResources`] if the Agent lacks sufficient free disk space.
    pub fn grow_persistent_volume(
        &mut self,
        agent_id: &AgentId,
        volume_id: &VolumeId,
        additional_bytes: Bytes,
    ) -> ArbiterResult<Bytes> {
        let tuple_key = (agent_id.clone(), volume_id.clone());
        let Some((role, mut vol)) = self.persistent_volumes.get(&tuple_key).cloned() else {
            return Err(ArbiterError::StoreReadError {
                key: volume_id.to_string(),
                reason: "persistent volume not found on agent in grow_persistent_volume".to_owned(),
            });
        };
        let mut disk_req = ResourceBundle::zero();
        disk_req.disk = additional_bytes;
        for (_, rec) in self.agents.iter_mut().filter(|(id, _)| *id == agent_id) {
            rec.available_resources = rec.available_resources.try_sub(&disk_req)?;
        }
        vol.capacity = vol
            .capacity
            .checked_add(additional_bytes)
            .unwrap_or_default();
        let new_cap = vol.capacity;
        let store_key = format!("/volumes/{agent_id}/{volume_id}");
        let _ = self.store.put(
            &store_key,
            serde_json::to_vec(&(agent_id, &role, &vol)).unwrap_or_default(),
        );
        self.persistent_volumes.insert(tuple_key, (role, vol));
        Ok(new_cap)
    }

    /// Shrinks an existing persistent volume on `agent_id` by `subtract_bytes` (`SHRINK_VOLUME`),
    /// returning `subtract_bytes` to the Agent's available disk pool.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Hosting [`AgentId`].
    /// * `volume_id` - Target [`VolumeId`].
    /// * `subtract_bytes` - [`Bytes`] to reclaim (`< vol.capacity`).
    ///
    /// # Returns
    ///
    /// Updated volume capacity in [`Bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the volume is unknown, or
    /// [`ArbiterError::InvalidResourceQuantity`] if `subtract_bytes >= vol.capacity`.
    pub fn shrink_persistent_volume(
        &mut self,
        agent_id: &AgentId,
        volume_id: &VolumeId,
        subtract_bytes: Bytes,
    ) -> ArbiterResult<Bytes> {
        let tuple_key = (agent_id.clone(), volume_id.clone());
        let Some((role, mut vol)) = self.persistent_volumes.get(&tuple_key).cloned() else {
            return Err(ArbiterError::StoreReadError {
                key: volume_id.to_string(),
                reason: "persistent volume not found on agent in shrink_persistent_volume"
                    .to_owned(),
            });
        };
        if subtract_bytes >= vol.capacity {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "ShrinkVolume".to_owned(),
                quantity: subtract_bytes.get(),
                reason: "cannot shrink persistent volume to zero or negative capacity".to_owned(),
            });
        }
        vol.capacity = vol.capacity.checked_sub(subtract_bytes).unwrap_or_default();
        let new_cap = vol.capacity;
        let mut disk_reclaim = ResourceBundle::zero();
        disk_reclaim.disk = subtract_bytes;
        for (_, rec) in self.agents.iter_mut().filter(|(id, _)| *id == agent_id) {
            rec.available_resources = rec
                .available_resources
                .try_add(&disk_reclaim)
                .unwrap_or_default();
        }
        let store_key = format!("/volumes/{agent_id}/{volume_id}");
        let _ = self.store.put(
            &store_key,
            serde_json::to_vec(&(agent_id, &role, &vol)).unwrap_or_default(),
        );
        self.persistent_volumes.insert(tuple_key, (role, vol));
        Ok(new_cap)
    }

    /// Re-emits all unacknowledged [`TaskStatusUpdate`]s queued in `self.unacknowledged_updates`
    /// for at-least-once delivery until the owning Framework sends [`SchedulerCall::Acknowledge`].
    ///
    /// # Returns
    ///
    /// Vector of `(FrameworkId, SchedulerEvent::Update)` pairs for connected Frameworks.
    pub fn retry_unacknowledged_status_updates(&self) -> Vec<(FrameworkId, SchedulerEvent)> {
        self.unacknowledged_updates
            .iter()
            .map(|(uuid, (fw_id, update))| {
                (
                    fw_id.clone(),
                    SchedulerEvent::Update(update.clone(), Some(uuid.clone())),
                )
            })
            .collect()
    }

    /// Updates the cluster [`MaintenanceSchedule`], rescinding offers on scheduled Agents and
    /// generating [`InverseOffer`]s for all registered Frameworks.
    ///
    /// # Arguments
    ///
    /// * `schedule` - New [`MaintenanceSchedule`].
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Vector of generated [`InverseOffer`]s.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if any Agent in `schedule` is not registered.
    pub fn update_maintenance_schedule(
        &mut self,
        schedule: MaintenanceSchedule,
        current_tick: u64,
    ) -> ArbiterResult<Vec<InverseOffer>> {
        for win in &schedule.windows {
            for aid in &win.agent_ids {
                if !self.agents.contains_key(aid) {
                    return Err(ArbiterError::StoreReadError {
                        key: aid.to_string(),
                        reason: "unknown agent in maintenance schedule".to_owned(),
                    });
                }
            }
        }
        let mut generated = Vec::new();
        let mut seq = current_tick.saturating_add(1);
        let mut puts = vec![(
            "/maintenance/schedule".to_owned(),
            serde_json::to_vec(&schedule).unwrap_or_default(),
        )];
        for win in &schedule.windows {
            for aid in &win.agent_ids {
                let _ =
                    self.rescind_offers_for_agent(aid, OfferRescindReason::AgentEnteredMaintenance);
                let maint_st =
                    AgentMaintenanceState::ScheduledForMaintenance(win.window_id.clone());
                puts.push((
                    format!("/maintenance/{aid}"),
                    serde_json::to_vec(&(aid, &maint_st)).unwrap_or_default(),
                ));
                self.agent_maintenance.insert(aid.clone(), maint_st);
                for fw_id in self.frameworks.keys() {
                    let ioid = OfferId::new(&format!("inv-offer-{seq}")).unwrap_or_default();
                    seq = seq.saturating_add(1);
                    let inv = InverseOffer {
                        inverse_offer_id: ioid.clone(),
                        framework_id: fw_id.clone(),
                        agent_id: aid.clone(),
                        maintenance_window_id: win.window_id.clone(),
                        resources: ResourceBundle::zero(),
                        unavailability_start_tick: win.unavailability_start_tick,
                    };
                    self.active_inverse_offers.insert(ioid, inv.clone());
                    generated.push(inv);
                }
            }
        }
        self.commit_store_puts_and_deletes(&puts, &[]);
        self.maintenance_schedule = schedule;
        Ok(generated)
    }

    /// Drains an Agent, rescinding all offers on it, terminating its running tasks, and transitioning it to
    /// [`AgentMaintenanceState::Drained`] (or marking it gone if `completion_mode == DrainCompletionMode::MarkGoneOnComplete`).
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Target [`AgentId`] to drain.
    /// * `grace_period_ticks` - Grace period for task termination.
    /// * `completion_mode` - Post-drain completion behavior.
    ///
    /// # Returns
    ///
    /// Number of tasks evicted during draining.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `agent_id` is not registered.
    pub fn drain_agent(
        &mut self,
        agent_id: &AgentId,
        grace_period_ticks: BenchmarkTicks,
        completion_mode: DrainCompletionMode,
    ) -> ArbiterResult<usize> {
        if !self.agents.contains_key(agent_id) {
            return Err(ArbiterError::StoreReadError {
                key: agent_id.to_string(),
                reason: "unknown agent in drain_agent".to_owned(),
            });
        }
        let _ =
            self.rescind_offers_for_agent(agent_id, OfferRescindReason::AgentEnteredMaintenance);
        self.agent_maintenance.insert(
            agent_id.clone(),
            AgentMaintenanceState::Draining(arbiter_core::workload::DrainingSpec {
                completion_mode,
                grace_period_ticks,
            }),
        );

        let mut evicted = 0_usize;
        for (state, aid, held) in self.tasks.values_mut() {
            if aid == agent_id && !state.is_terminal() {
                *state = TaskState::Killed;
                let reclaimed = core::mem::replace(held, ResourceBundle::zero());
                for (_, rec) in self.agents.iter_mut().filter(|(id, _)| *id == agent_id) {
                    rec.available_resources = rec
                        .available_resources
                        .try_add(&reclaimed)
                        .unwrap_or_default();
                }
                evicted = evicted.saturating_add(1);
            }
        }

        if completion_mode == DrainCompletionMode::MarkGoneOnComplete {
            let _ = self.mark_agent_gone(agent_id);
        } else {
            self.commit_store_puts_and_deletes(
                &[(
                    format!("/maintenance/{agent_id}"),
                    serde_json::to_vec(&(agent_id, AgentMaintenanceState::Drained))
                        .unwrap_or_default(),
                )],
                &[],
            );
            self.agent_maintenance
                .insert(agent_id.clone(), AgentMaintenanceState::Drained);
        }
        Ok(evicted)
    }

    /// Permanently marks an Agent gone (`TASK_GONE_BY_OPERATOR`), removing it from active scheduling
    /// and transitioning all its non-terminal tasks to [`TaskState::GoneByOperator`].
    ///
    /// # Arguments
    ///
    /// * `agent_id` - [`AgentId`] to mark gone.
    ///
    /// # Returns
    ///
    /// Number of tasks transitioned to `GoneByOperator`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `agent_id` is not registered.
    pub fn mark_agent_gone(&mut self, agent_id: &AgentId) -> ArbiterResult<usize> {
        if self.agents.remove(agent_id).is_none() {
            return Err(ArbiterError::StoreReadError {
                key: agent_id.to_string(),
                reason: "unknown agent in mark_agent_gone".to_owned(),
            });
        }
        self.commit_store_puts_and_deletes(
            &[(
                format!("/maintenance/{agent_id}"),
                serde_json::to_vec(&(agent_id, AgentMaintenanceState::Deactivated))
                    .unwrap_or_default(),
            )],
            &[],
        );
        self.agent_maintenance
            .insert(agent_id.clone(), AgentMaintenanceState::Deactivated);
        let _ = self.rescind_offers_for_agent(agent_id, OfferRescindReason::AgentDisconnected);

        let mut gone_count = 0_usize;
        for (state, aid, _) in self.tasks.values_mut() {
            if aid == agent_id && !state.is_terminal() {
                *state = TaskState::GoneByOperator;
                gone_count = gone_count.saturating_add(1);
            }
        }
        self.operator_event_log.push(OperatorEvent::AgentRemoved(
            agent_id.clone(),
            AgentLossReason::MarkedGoneByOperator,
        ));
        Ok(gone_count)
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

    /// Runs a single continuous HDRF / Gang / Offer scheduling tick across all healthy, non-drained Agents.
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
    #[inline(never)]
    #[allow(clippy::too_many_lines)]
    pub fn schedule_tick(
        &mut self,
        role_states: &[RoleAllocationState],
        current_tick: u64,
    ) -> ArbiterResult<AllocationCycleOutcome> {
        let mut total_capacity = ResourceBundle::zero();
        let mut candidates: Vec<GangAgentCandidate> = Vec::new();

        for (aid, rec) in &self.agents {
            let maint = self.agent_maintenance.get(aid).cloned().unwrap_or_default();
            let is_schedulable = matches!(
                maint,
                AgentMaintenanceState::Normal | AgentMaintenanceState::ScheduledForMaintenance(_)
            );
            if !rec.healthy || !is_schedulable {
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

        let mut fw_list: Vec<RegisteredFramework> = Vec::new();
        for fw in self.frameworks.values() {
            let active = self
                .framework_connections
                .get(&fw.framework_id)
                .is_none_or(|c| {
                    c.connected && !c.suppressed && !c.suppressed_roles.contains(&fw.role)
                });
            if active {
                fw_list.push(fw.clone());
            }
        }
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

        let mut puts = Vec::new();
        // Record placed direct tasks and gang tasks as Staging.
        for (tid, plan) in &outcome.direct_placements {
            let task_res = direct_queue
                .iter()
                .find(|t| &t.task_id == tid)
                .map(|t| t.resources.clone())
                .unwrap_or_default();
            puts.push((
                format!("/tasks/{tid}"),
                serde_json::to_vec(&(
                    tid,
                    TaskState::Staging,
                    &plan.agent_id,
                    &task_res,
                    None::<FrameworkId>,
                ))
                .unwrap_or_default(),
            ));
            self.tasks.insert(
                tid.clone(),
                (TaskState::Staging, plan.agent_id.clone(), task_res),
            );
            self.operator_event_log
                .push(OperatorEvent::TaskAdded(tid.clone(), plan.agent_id.clone()));
        }
        for gang_res in &outcome.gang_reservations {
            for (tid, plan) in &gang_res.member_placements {
                let task_res = gang_queue
                    .iter()
                    .flat_map(|g| &g.tasks)
                    .find(|t| &t.task_id == tid)
                    .map(|t| t.resources.clone())
                    .unwrap_or_default();
                puts.push((
                    format!("/tasks/{tid}"),
                    serde_json::to_vec(&(
                        tid,
                        TaskState::Staging,
                        &plan.agent_id,
                        &task_res,
                        None::<FrameworkId>,
                    ))
                    .unwrap_or_default(),
                ));
                self.tasks.insert(
                    tid.clone(),
                    (TaskState::Staging, plan.agent_id.clone(), task_res),
                );
                self.operator_event_log
                    .push(OperatorEvent::TaskAdded(tid.clone(), plan.agent_id.clone()));
            }
        }

        // Track active offers.
        for offer in &outcome.generated_offers {
            puts.push((
                format!("/offers/{}", offer.offer_id),
                serde_json::to_vec(offer).unwrap_or_default(),
            ));
            self.active_offers
                .insert(offer.offer_id.clone(), offer.clone());
        }
        self.commit_store_puts_and_deletes(&puts, &[]);

        self.pending_direct_tasks
            .clone_from(&outcome.unplaced_direct_tasks);
        self.pending_gang_jobs
            .clone_from(&outcome.unplaced_gang_groups);

        Ok(outcome)
    }

    /// Evaluates a Mesos v1 [`MesosAclAction`] against `policy_engine` for `principal`, `resource`,
    /// and `role`, returning [`ArbiterError::AuthorizationDenied`] if the RBAC/ABAC policy rejects it.
    ///
    /// # Arguments
    ///
    /// * `policy_engine` - Zero-trust [`PolicyEngine`] holding RBAC/ABAC rules.
    /// * `principal` - Authenticated [`SpiffeId`] of the caller.
    /// * `acl_action` - Specific [`MesosAclAction`] being requested.
    /// * `resource` - Target resource URI/prefix (e.g., `"role:team-a"`).
    /// * `role` - Target [`RoleName`].
    /// * `env_attributes` - Contextual ABAC attributes.
    ///
    /// # Returns
    ///
    /// `Ok(Decision::Allow)` when authorized.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::AuthorizationDenied`] if `policy_engine.evaluate` rejects the action.
    pub fn enforce_mesos_acl_with_policy(
        &self,
        policy_engine: &PolicyEngine,
        principal: &SpiffeId,
        acl_action: MesosAclAction,
        resource: &str,
        role: &RoleName,
        env_attributes: &BTreeMap<String, String>,
    ) -> ArbiterResult<Decision> {
        policy_engine.evaluate(
            principal.as_str(),
            acl_action.as_str(),
            resource,
            role,
            env_attributes,
        )
    }

    /// Solves minimum-disruption preemption on `agent_id` for `incoming_task` against `running_victims`,
    /// transitioning evicted tasks to [`TaskState::Preempting`] and reclaiming their resources so
    /// `incoming_task` can be staged immediately on `agent_id`.
    ///
    /// # Arguments
    ///
    /// * `incoming_task` - High-priority [`TaskSpec`] requiring placement.
    /// * `agent_id` - Target [`AgentId`].
    /// * `running_victims` - Candidate lower-priority [`RunningTaskInstance`]s on `agent_id`.
    ///
    /// # Returns
    ///
    /// [`PreemptionPlan`] listing evicted victim tasks and reclaimed resources.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `agent_id` is unknown, or
    /// [`ArbiterError::InsufficientResources`] if preemption cannot free enough capacity.
    pub fn preempt_for_high_priority_task(
        &mut self,
        incoming_task: &TaskSpec,
        agent_id: &AgentId,
        running_victims: &[RunningTaskInstance],
    ) -> ArbiterResult<PreemptionPlan> {
        let Some(current_free) = self
            .agents
            .get(agent_id)
            .map(|r| r.available_resources.clone())
        else {
            return Err(ArbiterError::StoreReadError {
                key: agent_id.to_string(),
                reason: "unknown agent in preempt_for_high_priority_task".to_owned(),
            });
        };
        let decision = solve_minimum_disruption_preemption(
            incoming_task,
            agent_id,
            &current_free,
            running_victims,
            true,
        )?;
        for (victim_tid, _) in &decision.victims {
            let _ = self.update_task_status(&TaskStatusUpdate {
                task_id: victim_tid.clone(),
                agent_id: agent_id.clone(),
                state: TaskState::Preempting,
                message: "preempted by higher-priority workload".to_owned(),
            });
            let _ = self.update_task_status(&TaskStatusUpdate {
                task_id: victim_tid.clone(),
                agent_id: agent_id.clone(),
                state: TaskState::Killed,
                message: "evicted after preemption".to_owned(),
            });
        }
        for (_, rec) in self.agents.iter_mut().filter(|(id, _)| *id == agent_id) {
            rec.available_resources = rec
                .available_resources
                .try_sub(&incoming_task.resources)
                .unwrap_or(ResourceBundle::zero());
        }
        self.tasks.insert(
            incoming_task.task_id.clone(),
            (
                TaskState::Staging,
                agent_id.clone(),
                incoming_task.resources.clone(),
            ),
        );
        Ok(decision)
    }

    /// Forwards unplaced `pending_direct_tasks` and `pending_gang_jobs` to healthy federated peer
    /// clusters in `peers`, returning the `(TaskId, ClusterId)` and `(TaskGroupId, ClusterId)` burst
    /// assignments and retaining any workloads that could not be burst.
    ///
    /// # Arguments
    ///
    /// * `peers` - Mutable slice of federated peer clusters (`BurstPeerCandidate`).
    ///
    /// # Returns
    ///
    /// Tuple `(Vec<(TaskId, ClusterId)>, Vec<(TaskGroupId, ClusterId)>)` of burst tasks and gangs.
    pub fn burst_overflow_to_federation(
        &mut self,
        peers: &mut [BurstPeerCandidate],
    ) -> (Vec<(TaskId, ClusterId)>, Vec<(TaskGroupId, ClusterId)>) {
        let mut burst_tasks = Vec::new();
        let mut remaining_tasks = Vec::new();
        for task in core::mem::take(&mut self.pending_direct_tasks) {
            if let Ok(dec) = burst_task_to_federation(&task, peers) {
                burst_tasks.push((task.task_id, dec.target_cluster));
            } else {
                remaining_tasks.push(task);
            }
        }
        self.pending_direct_tasks = remaining_tasks;

        let mut burst_gangs = Vec::new();
        let mut remaining_gangs = Vec::new();
        for gang in core::mem::take(&mut self.pending_gang_jobs) {
            if let Ok(dec) = burst_gang_to_federation(&gang, peers) {
                burst_gangs.push((gang.group_id, dec.target_cluster));
            } else {
                remaining_gangs.push(gang);
            }
        }
        self.pending_gang_jobs = remaining_gangs;
        (burst_tasks, burst_gangs)
    }

    /// Processes an [`AcceptOffers`] request from a subscribed Framework, executing all Mesos v1
    /// [`OfferOperation`]s (`LaunchTask`, `LaunchTaskGroup`, `Reserve`, `Unreserve`, `PushReservation`,
    /// `PopReservation`, `CreateVolume`, `DestroyVolume`, `CreateDisk`, `DestroyDisk`, `Decline`).
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
    #[inline(never)]
    #[allow(clippy::too_many_lines)]
    pub fn accept_offers(&mut self, accept: &AcceptOffers, current_tick: u64) -> ArbiterResult<()> {
        let Some(fw_role) = self
            .frameworks
            .get(&accept.framework_id)
            .map(|f| f.role.clone())
        else {
            return Err(ArbiterError::FrameworkNotFound {
                framework_id: accept.framework_id.to_string(),
            });
        };

        let mut pooled_resources = ResourceBundle::zero();
        let mut primary_agent_id = AgentId::default();
        let mut deletes = Vec::with_capacity(accept.offer_ids.len());
        let mut puts = Vec::new();

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
            deletes.push(format!("/offers/{oid}"));

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
                    self.task_owners
                        .insert(task.task_id.clone(), accept.framework_id.clone());
                    puts.push((
                        format!("/tasks/{}", task.task_id),
                        serde_json::to_vec(&(
                            &task.task_id,
                            TaskState::Staging,
                            &primary_agent_id,
                            &task.resources,
                            Some(&accept.framework_id),
                        ))
                        .unwrap_or_default(),
                    ));
                    self.tasks.insert(
                        task.task_id.clone(),
                        (
                            TaskState::Staging,
                            primary_agent_id.clone(),
                            task.resources.clone(),
                        ),
                    );
                    self.queue_agent_wire_message(
                        &primary_agent_id,
                        arbiter_proto::WireMessage::LaunchTaskCommand(Box::new(
                            arbiter_proto::LaunchTaskCommand {
                                agent_id: primary_agent_id.clone(),
                                task: (**task).clone(),
                            },
                        )),
                    );
                }
                OfferOperation::LaunchTaskGroup(group) => {
                    for task in &group.tasks {
                        pooled_resources = pooled_resources.try_sub(&task.resources)?;
                        self.task_owners
                            .insert(task.task_id.clone(), accept.framework_id.clone());
                        puts.push((
                            format!("/tasks/{}", task.task_id),
                            serde_json::to_vec(&(
                                &task.task_id,
                                TaskState::Staging,
                                &primary_agent_id,
                                &task.resources,
                                Some(&accept.framework_id),
                            ))
                            .unwrap_or_default(),
                        ));
                        self.tasks.insert(
                            task.task_id.clone(),
                            (
                                TaskState::Staging,
                                primary_agent_id.clone(),
                                task.resources.clone(),
                            ),
                        );
                        self.queue_agent_wire_message(
                            &primary_agent_id,
                            arbiter_proto::WireMessage::LaunchTaskCommand(Box::new(
                                arbiter_proto::LaunchTaskCommand {
                                    agent_id: primary_agent_id.clone(),
                                    task: task.clone(),
                                },
                            )),
                        );
                    }
                }
                OfferOperation::Reserve(bundle) => {
                    pooled_resources = pooled_resources.try_sub(bundle)?;
                    let current = self
                        .dynamic_reservations
                        .get(&(primary_agent_id.clone(), fw_role.clone()))
                        .cloned()
                        .unwrap_or_default();
                    let updated = current.try_add(bundle).unwrap_or_default();
                    puts.push((
                        format!("/reservations/{primary_agent_id}/{fw_role}"),
                        serde_json::to_vec(&(&primary_agent_id, &fw_role, &updated))
                            .unwrap_or_default(),
                    ));
                    self.dynamic_reservations
                        .insert((primary_agent_id.clone(), fw_role.clone()), updated);
                }
                OfferOperation::Unreserve(bundle) => {
                    let current = self
                        .dynamic_reservations
                        .get(&(primary_agent_id.clone(), fw_role.clone()))
                        .cloned()
                        .unwrap_or_default();
                    let remaining = current.try_sub(bundle)?;
                    puts.push((
                        format!("/reservations/{primary_agent_id}/{fw_role}"),
                        serde_json::to_vec(&(&primary_agent_id, &fw_role, &remaining))
                            .unwrap_or_default(),
                    ));
                    self.dynamic_reservations
                        .insert((primary_agent_id.clone(), fw_role.clone()), remaining);
                    pooled_resources = pooled_resources.try_add(bundle).unwrap_or_default();
                }
                OfferOperation::PushReservation(child_role, bundle) => {
                    let role_info = self.role_hierarchy.get_role(child_role)?;
                    if role_info.parent.as_ref() != Some(&fw_role) {
                        return Err(ArbiterError::InvalidQuotaBounds {
                            role: child_role.to_string(),
                            reason: format!(
                                "child role '{child_role}' is not a direct descendant of '{fw_role}'"
                            ),
                        });
                    }
                    let base = self
                        .dynamic_reservations
                        .get(&(primary_agent_id.clone(), fw_role.clone()))
                        .cloned()
                        .unwrap_or_default();
                    let remaining_base = base.try_sub(bundle)?;
                    self.dynamic_reservations
                        .insert((primary_agent_id.clone(), fw_role.clone()), remaining_base);
                    let stack = vec![fw_role.clone(), child_role.clone()];
                    let current_stack = self
                        .reservation_stacks
                        .get(&(primary_agent_id.clone(), stack.clone()))
                        .cloned()
                        .unwrap_or_default();
                    let updated_stack = current_stack.try_add(bundle).unwrap_or_default();
                    puts.push((
                        format!("/reservation_stacks/{primary_agent_id}/{fw_role}/{child_role}"),
                        serde_json::to_vec(&(&primary_agent_id, &stack, &updated_stack))
                            .unwrap_or_default(),
                    ));
                    self.reservation_stacks
                        .insert((primary_agent_id.clone(), stack), updated_stack);
                }
                OfferOperation::PopReservation(bundle) => {
                    let matching_key = self
                        .reservation_stacks
                        .keys()
                        .find(|(aid, stack)| {
                            aid == &primary_agent_id && stack.first() == Some(&fw_role)
                        })
                        .cloned();
                    let Some((aid, stack)) = matching_key else {
                        return Err(ArbiterError::StoreReadError {
                            key: format!("{primary_agent_id}/{fw_role}"),
                            reason: "no active refined reservation stack to pop".to_owned(),
                        });
                    };
                    let current_stack = self
                        .reservation_stacks
                        .get(&(aid.clone(), stack.clone()))
                        .cloned()
                        .unwrap_or_default();
                    let remaining_stack = current_stack.try_sub(bundle)?;
                    let child_role = stack.last().cloned().unwrap_or_default();
                    puts.push((
                        format!("/reservation_stacks/{primary_agent_id}/{fw_role}/{child_role}"),
                        serde_json::to_vec(&(&aid, &stack, &remaining_stack)).unwrap_or_default(),
                    ));
                    self.reservation_stacks
                        .insert((aid, stack), remaining_stack);
                    let base = self
                        .dynamic_reservations
                        .get(&(primary_agent_id.clone(), fw_role.clone()))
                        .cloned()
                        .unwrap_or_default();
                    let restored_base = base.try_add(bundle).unwrap_or_default();
                    self.dynamic_reservations
                        .insert((primary_agent_id.clone(), fw_role.clone()), restored_base);
                }
                OfferOperation::CreateVolume(vol) => {
                    let mut disk_req = ResourceBundle::zero();
                    disk_req.disk = vol.capacity;
                    pooled_resources = pooled_resources.try_sub(&disk_req)?;
                    self.create_persistent_volume(&primary_agent_id, &fw_role, vol.clone())?;
                }
                OfferOperation::DestroyVolume(vid) => {
                    if let Some((_, vol)) = self
                        .persistent_volumes
                        .get(&(primary_agent_id.clone(), vid.clone()))
                        .cloned()
                    {
                        let _ = self.destroy_persistent_volume(&primary_agent_id, vid);
                        let mut reclaimed = ResourceBundle::zero();
                        reclaimed.disk = vol.capacity;
                        pooled_resources = pooled_resources.try_add(&reclaimed).unwrap_or_default();
                    } else {
                        return Err(ArbiterError::StoreReadError {
                            key: vid.to_string(),
                            reason: "unknown persistent volume in OfferOperation::DestroyVolume"
                                .to_owned(),
                        });
                    }
                }
                OfferOperation::GrowVolume(vid, add_bytes) => {
                    let mut disk_req = ResourceBundle::zero();
                    disk_req.disk = *add_bytes;
                    pooled_resources = pooled_resources.try_sub(&disk_req)?;
                    let tuple_key = (primary_agent_id.clone(), vid.clone());
                    let Some((role, mut vol)) = self.persistent_volumes.get(&tuple_key).cloned()
                    else {
                        return Err(ArbiterError::StoreReadError {
                            key: vid.to_string(),
                            reason: "unknown persistent volume in OfferOperation::GrowVolume"
                                .to_owned(),
                        });
                    };
                    vol.capacity = vol.capacity.checked_add(*add_bytes).unwrap_or_default();
                    puts.push((
                        format!("/volumes/{primary_agent_id}/{vid}"),
                        serde_json::to_vec(&(&primary_agent_id, &role, &vol)).unwrap_or_default(),
                    ));
                    self.persistent_volumes.insert(tuple_key, (role, vol));
                }
                OfferOperation::ShrinkVolume(vid, sub_bytes) => {
                    let tuple_key = (primary_agent_id.clone(), vid.clone());
                    let Some((role, mut vol)) = self.persistent_volumes.get(&tuple_key).cloned()
                    else {
                        return Err(ArbiterError::StoreReadError {
                            key: vid.to_string(),
                            reason: "unknown persistent volume in OfferOperation::ShrinkVolume"
                                .to_owned(),
                        });
                    };
                    if *sub_bytes >= vol.capacity {
                        return Err(ArbiterError::InvalidResourceQuantity {
                            resource: "ShrinkVolume".to_owned(),
                            quantity: sub_bytes.get(),
                            reason: "cannot shrink volume to zero or negative capacity".to_owned(),
                        });
                    }
                    vol.capacity = vol.capacity.checked_sub(*sub_bytes).unwrap_or_default();
                    let mut reclaimed = ResourceBundle::zero();
                    reclaimed.disk = *sub_bytes;
                    pooled_resources = pooled_resources.try_add(&reclaimed).unwrap_or_default();
                    puts.push((
                        format!("/volumes/{primary_agent_id}/{vid}"),
                        serde_json::to_vec(&(&primary_agent_id, &role, &vol)).unwrap_or_default(),
                    ));
                    self.persistent_volumes.insert(tuple_key, (role, vol));
                }
                OfferOperation::CreateDisk(disk_spec) => {
                    let Some(rp) = self.resource_providers.get_mut(&disk_spec.provider_id) else {
                        return Err(ArbiterError::StoreReadError {
                            key: disk_spec.provider_id.to_string(),
                            reason: "unknown resource provider in OfferOperation::CreateDisk"
                                .to_owned(),
                        });
                    };
                    let mut disk_req = ResourceBundle::zero();
                    disk_req.disk = disk_spec.capacity;
                    pooled_resources = pooled_resources.try_sub(&disk_req)?;
                    rp.advertised_disks
                        .push((disk_spec.source.clone(), disk_spec.capacity));
                    let rp_clone = rp.clone();
                    puts.push((
                        format!("/resource_providers/{}", disk_spec.provider_id),
                        serde_json::to_vec(&rp_clone).unwrap_or_default(),
                    ));
                }
                OfferOperation::DestroyDisk(disk_spec) => {
                    let Some(rp) = self.resource_providers.get_mut(&disk_spec.provider_id) else {
                        return Err(ArbiterError::StoreReadError {
                            key: disk_spec.provider_id.to_string(),
                            reason: "unknown resource provider in OfferOperation::DestroyDisk"
                                .to_owned(),
                        });
                    };
                    rp.advertised_disks
                        .retain(|(src, _)| src != &disk_spec.source);
                    let rp_clone = rp.clone();
                    puts.push((
                        format!("/resource_providers/{}", disk_spec.provider_id),
                        serde_json::to_vec(&rp_clone).unwrap_or_default(),
                    ));
                    let mut reclaimed = ResourceBundle::zero();
                    reclaimed.disk = disk_spec.capacity;
                    pooled_resources = pooled_resources.try_add(&reclaimed).unwrap_or_default();
                }
                OfferOperation::Decline(filter) => {
                    for (_, fw) in self
                        .frameworks
                        .iter_mut()
                        .filter(|(id, _)| *id == &accept.framework_id)
                    {
                        fw.filter = *filter;
                        fw.suppressed_agents.insert(
                            primary_agent_id.clone(),
                            current_tick.saturating_add(filter.refuse_milliseconds),
                        );
                    }
                }
            }
        }

        self.commit_store_puts_and_deletes(&puts, &deletes);

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
        let aid_clone = hosting_agent.clone();
        self.operator_event_log.push(OperatorEvent::TaskUpdated(
            update.task_id.clone(),
            update.state,
        ));

        if update.state.is_terminal() {
            let reclaimed = core::mem::replace(held_resources, ResourceBundle::zero());
            for (_, agent_rec) in self.agents.iter_mut().filter(|(id, _)| *id == &aid_clone) {
                agent_rec.available_resources = agent_rec
                    .available_resources
                    .try_add(&reclaimed)
                    .unwrap_or_default();
            }
        }
        let persisted_res = self
            .tasks
            .get(&update.task_id)
            .map(|(_, _, r)| r.clone())
            .unwrap_or_default();
        let owner = self.task_owners.get(&update.task_id).cloned();
        self.commit_store_puts_and_deletes(
            &[(
                format!("/tasks/{}", update.task_id),
                serde_json::to_vec(&(
                    &update.task_id,
                    update.state,
                    &aid_clone,
                    &persisted_res,
                    &owner,
                ))
                .unwrap_or_default(),
            )],
            &[],
        );
        Ok(())
    }
}

/// Thread-safe shared Master coordinator (`SharedMasterCoordinator`) wrapping [`MasterNode`].
///
/// Maintains per-Framework, per-Executor, and per-ResourceProvider outbound `RecordIO`
/// event queues so concurrent QUIC streams, HTTP/REST requests, SSE streams, and background
/// Raft/Scheduler ticker threads operate cohesively on live cluster state.
#[derive(Debug)]
pub struct SharedMasterCoordinator<S: StateStore> {
    /// Synchronized inner [`MasterNode`].
    inner: std::sync::Mutex<MasterNode<S>>,
    /// Per-Framework outbound [`SchedulerEvent`] queues keyed by [`FrameworkId`].
    framework_queues: std::sync::Mutex<BTreeMap<FrameworkId, Vec<SchedulerEvent>>>,
}

impl<S: StateStore> SharedMasterCoordinator<S> {
    /// Creates a new [`SharedMasterCoordinator`] wrapping `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Initialized [`MasterNode`].
    ///
    /// # Returns
    ///
    /// Thread-safe [`SharedMasterCoordinator`].
    pub const fn new(master: MasterNode<S>) -> Self {
        Self {
            inner: std::sync::Mutex::new(master),
            framework_queues: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Executes a [`SchedulerCall`] against the synchronized [`MasterNode`] and queues all emitted
    /// [`SchedulerEvent`]s into the Framework's outbound `RecordIO` event buffer.
    ///
    /// # Arguments
    ///
    /// * `framework_id` - Calling [`FrameworkId`].
    /// * `call` - [`SchedulerCall`] to process.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// Vector of emitted [`SchedulerEvent`]s.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if `handle_scheduler_call` fails.
    pub fn dispatch_scheduler_call(
        &self,
        framework_id: &FrameworkId,
        call: SchedulerCall,
        current_tick: u64,
    ) -> ArbiterResult<Vec<SchedulerEvent>> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let events = guard.handle_scheduler_call(call, current_tick)?;
        drop(guard);
        self.framework_queues
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(framework_id.clone())
            .or_default()
            .extend(events.iter().cloned());
        Ok(events)
    }

    /// Runs a background maintenance and allocation tick on the synchronized [`MasterNode`]:
    /// 1. Expires stale offers (`expire_and_rescind_stale_offers`) and queues `Rescind` events.
    /// 2. Reconciles unhealthy agents (`reconcile_unhealthy_agents`).
    /// 3. Runs `schedule_tick` and queues generated [`ResourceOffer`]s into each Framework's outbound queue.
    ///
    /// # Arguments
    ///
    /// * `role_states` - Current [`RoleAllocationState`]s.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// [`AllocationCycleOutcome`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if `schedule_tick` fails.
    pub fn run_background_tick(
        &self,
        role_states: &[RoleAllocationState],
        current_tick: u64,
    ) -> ArbiterResult<AllocationCycleOutcome> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rescinded = guard.expire_and_rescind_stale_offers(current_tick);
        let _ = guard.reconcile_unhealthy_agents(current_tick);
        let outcome = guard.schedule_tick(role_states, current_tick)?;
        drop(guard);

        let mut q_guard = self
            .framework_queues
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (fw_id, ev) in rescinded {
            q_guard.entry(fw_id).or_default().push(ev);
        }
        for offer in &outcome.generated_offers {
            q_guard
                .entry(offer.framework_id.clone())
                .or_default()
                .push(SchedulerEvent::Offers(vec![offer.clone()]));
        }
        drop(q_guard);
        Ok(outcome)
    }

    /// Drains all queued [`SchedulerEvent`]s for `framework_id`.
    ///
    /// # Arguments
    ///
    /// * `framework_id` - Subscribed [`FrameworkId`].
    ///
    /// # Returns
    ///
    /// Queued [`SchedulerEvent`]s in FIFO order.
    pub fn drain_framework_events(&self, framework_id: &FrameworkId) -> Vec<SchedulerEvent> {
        self.framework_queues
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(framework_id)
            .unwrap_or_default()
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
            disk: Bytes::new(100_000_000),
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
    #[allow(clippy::too_many_lines)]
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
                    min_gpu_vram: Bytes::ZERO,
                    refuse_gpu_offers: false,
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
        // Test expire_and_rescind_stale_offers and SharedMasterCoordinator
        let _ = master.register_agent(
            RegisterAgent {
                agent_id: AgentId::new("agent-3").unwrap_or_default(),
                os_kind: OsKind::Linux,
                cpu_arch: CpuArch::X86_64,
                total_resources: cap,
                topology: HardwareTopologyGraph::new(),
            },
            15,
        );
        let shared = SharedMasterCoordinator::new(master);
        let fw_s = FrameworkId::new("fw-shared-1").unwrap_or_default();
        assert!(
            shared
                .dispatch_scheduler_call(
                    &fw_s,
                    SchedulerCall::Subscribe(
                        SubscribeFramework {
                            framework_id: fw_s.clone(),
                            role: role.clone(),
                            failover_timeout_ms: 100,
                        },
                        arbiter_core::workload::CheckpointMode::Enabled,
                        Vec::new(),
                        Vec::new(),
                    ),
                    15,
                )
                .is_ok()
        );
        let shared_states = vec![RoleAllocationState {
            role,
            framework_id: Some(fw_s.clone()),
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        assert!(shared.run_background_tick(&shared_states, 20).is_ok());
        // At tick 80 (past offer_ttl 50, before agent lease expiry 115), expire_and_rescind_stale_offers rescinds the offer
        assert!(shared.run_background_tick(&shared_states, 80).is_ok());
        let drained = shared.drain_framework_events(&fw_s);
        assert!(drained.len() >= 2);
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

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_mesos_v1_scheduler_calls_reconcile_suppress_revive_and_failover() {
        use arbiter_core::ids::MaintenanceWindowId;
        use arbiter_core::workload::{CheckpointMode, KillPolicy, MaintenanceWindow};

        let (h, role) = sample_role_hierarchy();
        let mut master = MasterNode::new(MemoryStateStore::new(), h, 100, 50);
        master.partition_aware_tasks = true;

        let a1 = AgentId::new("agent-1").unwrap_or_default();
        let cap = ResourceBundle {
            cpu: Millicores::new(16_000),
            memory: Bytes::new(16_000_000),
            disk: Bytes::new(50_000_000),
            ..ResourceBundle::zero()
        };
        assert!(
            master
                .register_agent(
                    RegisterAgent {
                        agent_id: a1.clone(),
                        os_kind: OsKind::Linux,
                        cpu_arch: CpuArch::X86_64,
                        total_resources: cap,
                        topology: HardwareTopologyGraph::new(),
                    },
                    10,
                )
                .is_ok()
        );

        let fw_id = FrameworkId::new("fw-mesos-1").unwrap_or_default();
        let bad_fw = FrameworkId::new("fw-ghost").unwrap_or_default();

        // Subscribe with bad autoregister_roles fails
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Subscribe(
                        SubscribeFramework {
                            framework_id: fw_id.clone(),
                            role: role.clone(),
                            failover_timeout_ms: 50,
                        },
                        CheckpointMode::Enabled,
                        vec![RoleName::new("nonexistent").unwrap_or_default()],
                        Vec::new(),
                    ),
                    10,
                )
                .is_err()
        );

        // Subscribe with suppressed_roles
        let sub_ev = master
            .handle_scheduler_call(
                SchedulerCall::Subscribe(
                    SubscribeFramework {
                        framework_id: fw_id.clone(),
                        role: role.clone(),
                        failover_timeout_ms: 50,
                    },
                    CheckpointMode::Enabled,
                    vec![role.clone()],
                    vec![role.clone()],
                ),
                10,
            )
            .unwrap_or_default();
        assert_eq!(sub_ev.len(), 1);

        // Re-subscribe updates existing framework
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Subscribe(
                        SubscribeFramework {
                            framework_id: fw_id.clone(),
                            role: role.clone(),
                            failover_timeout_ms: 50,
                        },
                        CheckpointMode::Enabled,
                        Vec::new(),
                        Vec::new(),
                    ),
                    12,
                )
                .is_ok()
        );

        // Suppress and Revive
        assert!(
            master
                .handle_scheduler_call(SchedulerCall::Suppress(bad_fw.clone(), Vec::new()), 15)
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Suppress(fw_id.clone(), vec![role.clone()]),
                    15
                )
                .is_ok()
        );
        let states = vec![RoleAllocationState {
            role: role.clone(),
            framework_id: Some(fw_id.clone()),
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        // While suppressed, 0 offers generated
        let out_supp = master.schedule_tick(&states, 16).unwrap_or_default();
        assert!(out_supp.generated_offers.is_empty());

        assert!(
            master
                .handle_scheduler_call(SchedulerCall::Revive(bad_fw.clone(), Vec::new()), 17)
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(SchedulerCall::Revive(fw_id.clone(), vec![role.clone()]), 17)
                .is_ok()
        );

        // Generate offer and test Accept with LaunchTaskGroup, Reserve, Unreserve, CreateVolume, DestroyVolume
        let out_rev = master.schedule_tick(&states, 18).unwrap_or_default();
        assert_eq!(out_rev.generated_offers.len(), 1);
        let oid = out_rev
            .generated_offers
            .first()
            .map(|o| o.offer_id.clone())
            .unwrap_or_default();

        let vol_id = VolumeId::new("vol-1").unwrap_or_default();
        let res_bundle = ResourceBundle {
            cpu: Millicores::new(1_000),
            ..ResourceBundle::zero()
        };
        let op_id = OperationId::new("op-1").unwrap_or_default();
        let acc_events = master
            .handle_scheduler_call(
                SchedulerCall::Accept(
                    AcceptOffers {
                        framework_id: fw_id.clone(),
                        offer_ids: vec![oid],
                        operations: vec![
                            OfferOperation::LaunchTaskGroup(TaskGroupSpec {
                                group_id: TaskGroupId::new("pod-1").unwrap_or_default(),
                                role: role.clone(),
                                tasks: vec![make_task("pod-task-1", &role, 1_000)],
                                tpu_slice: None,
                                placement_timeout_ms: 100,
                            }),
                            OfferOperation::Reserve(res_bundle.clone()),
                            OfferOperation::Unreserve(res_bundle),
                            OfferOperation::CreateVolume(VolumeReservationSpec {
                                volume_id: vol_id.clone(),
                                capacity: Bytes::new(1_024),
                                container_path: "/data".to_owned(),
                            }),
                            OfferOperation::DestroyVolume(vol_id),
                        ],
                    },
                    Some(op_id.clone()),
                    OfferFilter {
                        refuse_milliseconds: 5,
                        min_cpu_millicores: 0,
                        min_memory_bytes: Bytes::ZERO,
                        min_gpu_vram: Bytes::ZERO,
                        refuse_gpu_offers: false,
                    },
                ),
                20,
            )
            .unwrap_or_default();
        assert_eq!(acc_events.len(), 1);

        // Decline via SchedulerCall (and error branch with unknown framework)
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Decline(bad_fw.clone(), Vec::new(), OfferFilter::default()),
                    21,
                )
                .is_err()
        );
        // Accept with operation_id = None and filter.refuse_milliseconds = 0
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Accept(
                        AcceptOffers {
                            framework_id: fw_id.clone(),
                            offer_ids: Vec::new(),
                            operations: Vec::new(),
                        },
                        None,
                        OfferFilter::default(),
                    ),
                    21,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Accept(
                        AcceptOffers {
                            framework_id: bad_fw.clone(),
                            offer_ids: Vec::new(),
                            operations: Vec::new(),
                        },
                        None,
                        OfferFilter::default(),
                    ),
                    21,
                )
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Subscribe(
                        SubscribeFramework {
                            framework_id: fw_id.clone(),
                            role: RoleName::new("missing-role").unwrap_or_default(),
                            failover_timeout_ms: 50,
                        },
                        CheckpointMode::Enabled,
                        Vec::new(),
                        Vec::new(),
                    ),
                    21,
                )
                .is_err()
        );
        let _ = master
            .handle_scheduler_call(SchedulerCall::Revive(fw_id.clone(), Vec::new()), 21)
            .unwrap_or_default();
        let out2 = master.schedule_tick(&states, 22).unwrap_or_default();
        let oid2 = out2
            .generated_offers
            .first()
            .map(|o| o.offer_id.clone())
            .unwrap_or_default();
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Decline(fw_id.clone(), vec![oid2], OfferFilter::default()),
                    23,
                )
                .is_ok()
        );

        // Destroy unknown volume in AcceptOffers fails
        let out3 = master.schedule_tick(&states, 24).unwrap_or_default();
        let oid3 = out3
            .generated_offers
            .first()
            .map(|o| o.offer_id.clone())
            .unwrap_or_default();
        assert!(
            master
                .accept_offers(
                    &AcceptOffers {
                        framework_id: fw_id.clone(),
                        offer_ids: vec![oid3],
                        operations: vec![OfferOperation::DestroyVolume(
                            VolumeId::new("vol-ghost").unwrap_or_default()
                        )],
                    },
                    25,
                )
                .is_err()
        );

        // ReconcileTasks (implicit & explicit) and ReconcileOperations
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::ReconcileTasks(bad_fw.clone(), Vec::new()),
                    25
                )
                .is_err()
        );
        let imp_rec = master
            .handle_scheduler_call(SchedulerCall::ReconcileTasks(fw_id.clone(), Vec::new()), 25)
            .unwrap_or_default();
        assert_eq!(imp_rec.len(), 1);

        let exp_rec = master
            .handle_scheduler_call(
                SchedulerCall::ReconcileTasks(
                    fw_id.clone(),
                    vec![
                        (
                            TaskId::new("pod-task-1").unwrap_or_default(),
                            Some(a1.clone()),
                        ),
                        (TaskId::new("unknown-t").unwrap_or_default(), None),
                    ],
                ),
                25,
            )
            .unwrap_or_default();
        assert_eq!(exp_rec.len(), 2);

        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::ReconcileOperations(bad_fw.clone(), Vec::new()),
                    25,
                )
                .is_err()
        );
        let op_rec = master
            .handle_scheduler_call(
                SchedulerCall::ReconcileOperations(
                    fw_id.clone(),
                    vec![
                        (op_id, None, None),
                        (
                            OperationId::new("op-unknown").unwrap_or_default(),
                            None,
                            None,
                        ),
                    ],
                ),
                25,
            )
            .unwrap_or_default();
        assert_eq!(op_rec.len(), 2);

        // Message, Request, Shutdown, Acknowledge, AcknowledgeOperationStatus, RespondInverseOffer, Kill
        let exec_id = ExecutorId::new("exec-1").unwrap_or_default();
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Message(
                        bad_fw.clone(),
                        a1.clone(),
                        exec_id.clone(),
                        vec![1, 2],
                    ),
                    26,
                )
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Message(fw_id.clone(), a1.clone(), exec_id.clone(), vec![1, 2],),
                    26,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_scheduler_call(SchedulerCall::Request(bad_fw.clone(), Vec::new()), 26)
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(SchedulerCall::Request(fw_id.clone(), Vec::new()), 26)
                .is_ok()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Shutdown(bad_fw.clone(), exec_id.clone(), a1.clone()),
                    26,
                )
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Shutdown(fw_id.clone(), exec_id, a1.clone()),
                    26,
                )
                .is_ok()
        );

        // Maintenance schedule generates InverseOffer, RespondInverseOffer consumes it
        let inv_offers = master
            .update_maintenance_schedule(
                MaintenanceSchedule {
                    windows: vec![MaintenanceWindow {
                        window_id: MaintenanceWindowId::new("mw-1").unwrap_or_default(),
                        agent_ids: vec![a1.clone()],
                        unavailability_start_tick: BenchmarkTicks::new(100),
                        duration_ticks: BenchmarkTicks::new(50),
                    }],
                },
                27,
            )
            .unwrap_or_default();
        assert_eq!(inv_offers.len(), 1);
        let ioid = inv_offers
            .first()
            .map(|i| i.inverse_offer_id.clone())
            .unwrap_or_default();
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::RespondInverseOffer(bad_fw.clone(), vec![ioid.clone()], true),
                    28,
                )
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::RespondInverseOffer(fw_id.clone(), vec![ioid], true),
                    28,
                )
                .is_ok()
        );

        //Partition-aware reconciliation transitions pod-task-1 to Unreachable, then re-registration restores Running
        let unr = master.reconcile_unhealthy_agents(200);
        assert_eq!(unr.len(), 1);
        assert!(master.reconcile_unhealthy_agents(205).is_empty());
        // Insert a task on another agent so register_agent sees both `task_agent == &aid` true and false
        master.tasks.insert(
            TaskId::new("other-agent-task").unwrap_or_default(),
            (
                TaskState::Running,
                AgentId::new("agent-other").unwrap_or_default(),
                ResourceBundle::zero(),
            ),
        );
        let reg_again = RegisterAgent {
            agent_id: a1.clone(),
            os_kind: OsKind::Linux,
            cpu_arch: CpuArch::X86_64,
            total_resources: ResourceBundle {
                cpu: Millicores::new(16_000),
                memory: Bytes::new(16_000_000),
                disk: Bytes::new(50_000_000),
                ..ResourceBundle::zero()
            },
            topology: HardwareTopologyGraph::new(),
        };
        assert!(master.register_agent(reg_again, 210).is_ok());
        master
            .tasks
            .remove(&TaskId::new("other-agent-task").unwrap_or_default());
        // Evaluate failover timeouts while fw_id is still connected -> covers `!conn.connected == false`
        assert!(master.evaluate_framework_failover_timeouts(210).is_empty());

        // Kill call & Acknowledge
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Kill(
                        bad_fw.clone(),
                        TaskId::new("pod-task-1").unwrap_or_default(),
                        None,
                        None,
                    ),
                    215,
                )
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Kill(
                        fw_id.clone(),
                        TaskId::new("ghost").unwrap_or_default(),
                        None,
                        None,
                    ),
                    215,
                )
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Kill(
                        fw_id.clone(),
                        TaskId::new("pod-task-1").unwrap_or_default(),
                        Some(a1.clone()),
                        Some(KillPolicy {
                            grace_period_ticks: BenchmarkTicks::new(5),
                        }),
                    ),
                    215,
                )
                .is_ok()
        );
        // Reconcile when task is terminal covers `!state.is_terminal() == false` in implicit reconciliation
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::ReconcileTasks(fw_id.clone(), Vec::new()),
                    216,
                )
                .unwrap_or_default()
                .is_empty()
        );

        let uuid = StatusUpdateUuid::new("uuid-kill-215").unwrap_or_default();
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Acknowledge(
                        bad_fw.clone(),
                        a1.clone(),
                        TaskId::new("pod-task-1").unwrap_or_default(),
                        uuid.clone(),
                    ),
                    216,
                )
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Acknowledge(
                        fw_id.clone(),
                        a1.clone(),
                        TaskId::new("pod-task-1").unwrap_or_default(),
                        uuid.clone(),
                    ),
                    216,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::AcknowledgeOperationStatus(
                        bad_fw.clone(),
                        Some(a1.clone()),
                        OperationId::new("op-1").unwrap_or_default(),
                        uuid.clone(),
                    ),
                    216,
                )
                .is_err()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::AcknowledgeOperationStatus(
                        fw_id.clone(),
                        Some(a1),
                        OperationId::new("op-1").unwrap_or_default(),
                        uuid,
                    ),
                    216,
                )
                .is_ok()
        );

        // Framework disconnect & failover timeout evaluation
        assert!(master.mark_framework_disconnected(&bad_fw, 220).is_err());
        assert!(master.mark_framework_disconnected(&fw_id, 220).is_ok());
        // Calling schedule_tick while disconnected covers `c.connected == false` in schedule_tick
        let _ = master.schedule_tick(&states, 225);
        assert!(master.evaluate_framework_failover_timeouts(240).is_empty());
        let timed_out = master.evaluate_framework_failover_timeouts(300);
        assert_eq!(timed_out, vec![fw_id]);
        assert!(
            master
                .handle_scheduler_call(SchedulerCall::Teardown(bad_fw), 305)
                .is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_mesos_v1_operator_api_maintenance_draining_and_state_recovery() {
        use arbiter_core::ids::MaintenanceWindowId;
        use arbiter_core::workload::MaintenanceWindow;

        let (h, role) = sample_role_hierarchy();
        let mut master = MasterNode::new(MemoryStateStore::new(), h, 100, 50);

        let a1 = AgentId::new("agent-1").unwrap_or_default();
        let a2 = AgentId::new("agent-2").unwrap_or_default();
        let cap = ResourceBundle {
            cpu: Millicores::new(16_000),
            memory: Bytes::new(16_000_000),
            disk: Bytes::new(50_000_000),
            ..ResourceBundle::zero()
        };
        for id in [a1.clone(), a2.clone()] {
            assert!(
                master
                    .register_agent(
                        RegisterAgent {
                            agent_id: id,
                            os_kind: OsKind::Linux,
                            cpu_arch: CpuArch::X86_64,
                            total_resources: cap.clone(),
                            topology: HardwareTopologyGraph::new(),
                        },
                        10,
                    )
                    .is_ok()
            );
        }

        // Subscribe a framework and launch a task so teardown_framework covers active offers & active tasks
        let fw_id = FrameworkId::new("fw-op-1").unwrap_or_default();
        assert!(
            master
                .subscribe_framework(SubscribeFramework {
                    framework_id: fw_id.clone(),
                    role: role.clone(),
                    failover_timeout_ms: 100,
                })
                .is_ok()
        );
        let states = vec![RoleAllocationState {
            role: role.clone(),
            framework_id: Some(fw_id.clone()),
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        let out = master.schedule_tick(&states, 15).unwrap_or_default();
        let oid_a1 = out
            .generated_offers
            .first()
            .map(|o| o.offer_id.clone())
            .unwrap_or_default();
        assert!(
            master
                .accept_offers(
                    &AcceptOffers {
                        framework_id: fw_id.clone(),
                        offer_ids: vec![oid_a1],
                        operations: vec![OfferOperation::LaunchTask(Box::new(make_task(
                            "op-t-1", &role, 2_000
                        )))],
                    },
                    16,
                )
                .is_ok()
        );

        master.active_executors.insert(
            (a1.clone(), ExecutorId::new("ex-1").unwrap_or_default()),
            fw_id.clone(),
        );
        // Read-only operator calls
        for call in [
            OperatorCall::GetHealth,
            OperatorCall::GetVersion,
            OperatorCall::GetMetrics,
            OperatorCall::GetFlags,
            OperatorCall::GetMaster,
            OperatorCall::GetAgents,
            OperatorCall::GetState,
            OperatorCall::GetFrameworks,
            OperatorCall::GetExecutors,
            OperatorCall::GetTasks,
            OperatorCall::GetRoles,
            OperatorCall::GetQuota,
            OperatorCall::GetWeights,
            OperatorCall::GetMaintenanceSchedule,
            OperatorCall::GetMaintenanceStatus,
            OperatorCall::SubscribeOperatorEvents,
        ] {
            assert!(master.handle_operator_call(call, 20).is_ok());
        }

        // UpdateWeights, SetQuota, RemoveQuota (including error branches through handle_operator_call)
        let bad_role = RoleName::new("ghost-role").unwrap_or_default();
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::UpdateWeights(vec![(
                        bad_role.clone(),
                        WeightBasisPoints::STANDARD
                    )]),
                    20,
                )
                .is_err()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::UpdateWeights(vec![(role.clone(), WeightBasisPoints::STANDARD)]),
                    20,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::SetQuota(
                        role.clone(),
                        Quota {
                            id: QuotaId::new("q-bad").unwrap_or_default(),
                            guaranteed_min: cap.clone(),
                            hard_max: ResourceBundle::zero(),
                            allow_burst_borrowing: true,
                            weight: WeightBasisPoints::STANDARD,
                        },
                    ),
                    20,
                )
                .is_err()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::SetQuota(
                        role.clone(),
                        Quota {
                            id: QuotaId::new("q-op").unwrap_or_default(),
                            guaranteed_min: ResourceBundle::zero(),
                            hard_max: cap,
                            allow_burst_borrowing: true,
                            weight: WeightBasisPoints::STANDARD,
                        },
                    ),
                    20,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(OperatorCall::RemoveQuota(bad_role.clone()), 20)
                .is_err()
        );
        assert!(
            master
                .handle_operator_call(OperatorCall::RemoveQuota(role.clone()), 20)
                .is_ok()
        );

        // ReserveResources & UnreserveResources via OperatorCall (both Ok and Err)
        let res_spec = DynamicReservationSpec {
            operation_id: OperationId::new("op-res-1").unwrap_or_default(),
            agent_id: a1.clone(),
            role: role.clone(),
            principal: "admin".to_owned(),
            resources: ResourceBundle {
                cpu: Millicores::new(1_000),
                ..ResourceBundle::zero()
            },
        };
        assert!(
            master
                .handle_operator_call(OperatorCall::ReserveResources(res_spec.clone()), 21)
                .is_ok()
        );
        // Reserve with unknown role, unknown agent, or insufficient resources via OperatorCall
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::ReserveResources(DynamicReservationSpec {
                        role: bad_role,
                        ..res_spec.clone()
                    }),
                    21,
                )
                .is_err()
        );
        let bad_agent = AgentId::new("agent-ghost").unwrap_or_default();
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::ReserveResources(DynamicReservationSpec {
                        agent_id: bad_agent.clone(),
                        ..res_spec.clone()
                    }),
                    21,
                )
                .is_err()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::ReserveResources(DynamicReservationSpec {
                        resources: ResourceBundle {
                            cpu: Millicores::new(999_999_000),
                            ..ResourceBundle::zero()
                        },
                        ..res_spec.clone()
                    }),
                    21,
                )
                .is_err()
        );
        // Unreserve more than reserved -> Err
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::UnreserveResources(DynamicReservationSpec {
                        resources: ResourceBundle {
                            cpu: Millicores::new(999_000),
                            ..ResourceBundle::zero()
                        },
                        ..res_spec.clone()
                    }),
                    22,
                )
                .is_err()
        );
        assert!(
            master
                .handle_operator_call(OperatorCall::UnreserveResources(res_spec.clone()), 22)
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::UnreserveResources(DynamicReservationSpec {
                        agent_id: bad_agent.clone(),
                        ..res_spec
                    }),
                    22,
                )
                .is_err()
        );

        // CreateVolumes & DestroyVolumes via OperatorCall (Ok and Err)
        let v_spec = VolumeReservationSpec {
            volume_id: VolumeId::new("vol-op-1").unwrap_or_default(),
            capacity: Bytes::new(4_096),
            container_path: "/mnt/pg".to_owned(),
        };
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::CreateVolumes(a1.clone(), role.clone(), vec![v_spec.clone()]),
                    23,
                )
                .is_ok()
        );
        // Test shared persistent volume mounting, conflict detection, and reference-counted destruction guard
        assert_eq!(
            master.mount_shared_persistent_volume(
                &a1,
                &v_spec.volume_id,
                arbiter_core::workload::SharedVolumeMode::SharedReadOnly,
            ),
            Ok(1)
        );
        assert_eq!(
            master.mount_shared_persistent_volume(
                &a1,
                &v_spec.volume_id,
                arbiter_core::workload::SharedVolumeMode::SharedReadOnly,
            ),
            Ok(2)
        );
        // Conflicting mode (`Exclusive` or `SharedReadWrite`) rejected while `SharedReadOnly` is mounted
        assert!(
            master
                .mount_shared_persistent_volume(
                    &a1,
                    &v_spec.volume_id,
                    arbiter_core::workload::SharedVolumeMode::Exclusive,
                )
                .is_err()
        );
        assert!(
            master
                .mount_shared_persistent_volume(
                    &a1,
                    &v_spec.volume_id,
                    arbiter_core::workload::SharedVolumeMode::SharedReadWrite,
                )
                .is_err()
        );
        // Cannot destroy while ref_count > 0
        assert!(
            master
                .destroy_persistent_volume(&a1, &v_spec.volume_id)
                .is_err()
        );
        assert_eq!(
            master.unmount_shared_persistent_volume(&a1, &v_spec.volume_id),
            Ok(1)
        );
        assert_eq!(
            master.unmount_shared_persistent_volume(&a1, &v_spec.volume_id),
            Ok(0)
        );
        // Unmounting when not mounted -> Err
        assert!(
            master
                .unmount_shared_persistent_volume(&a1, &v_spec.volume_id)
                .is_err()
        );
        // Exclusive mount blocks second exclusive mount
        assert_eq!(
            master.mount_shared_persistent_volume(
                &a1,
                &v_spec.volume_id,
                arbiter_core::workload::SharedVolumeMode::Exclusive,
            ),
            Ok(1)
        );
        assert!(
            master
                .mount_shared_persistent_volume(
                    &a1,
                    &v_spec.volume_id,
                    arbiter_core::workload::SharedVolumeMode::Exclusive,
                )
                .is_err()
        );
        let _ = master.unmount_shared_persistent_volume(&a1, &v_spec.volume_id);
        assert!(
            master
                .mount_shared_persistent_volume(
                    &bad_agent,
                    &v_spec.volume_id,
                    arbiter_core::workload::SharedVolumeMode::Exclusive,
                )
                .is_err()
        );
        // Verify outbound agent message queue populated by LaunchTask
        assert!(!master.drain_outbound_agent_messages(&a1).is_empty());
        assert!(master.drain_outbound_agent_messages(&a1).is_empty());
        // Duplicate volume via OperatorCall -> Err
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::CreateVolumes(a1.clone(), role.clone(), vec![v_spec.clone()]),
                    23,
                )
                .is_err()
        );
        assert!(
            master
                .create_persistent_volume(&bad_agent, &role, v_spec.clone())
                .is_err()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::DestroyVolumes(a1.clone(), vec![v_spec.volume_id.clone()]),
                    24,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::DestroyVolumes(a1.clone(), vec![v_spec.volume_id]),
                    24,
                )
                .is_err()
        );

        // Maintenance schedule, StartMaintenance, StopMaintenance, Deactivate, Reactivate, Drain, MarkAgentGone
        let out_resc = master.schedule_tick(&states, 24).unwrap_or_default();
        assert!(!out_resc.generated_offers.is_empty());
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::UpdateMaintenanceSchedule(MaintenanceSchedule {
                        windows: vec![MaintenanceWindow {
                            window_id: MaintenanceWindowId::new("mw-op").unwrap_or_default(),
                            agent_ids: vec![a1.clone()],
                            unavailability_start_tick: BenchmarkTicks::new(50),
                            duration_ticks: BenchmarkTicks::new(20),
                        }],
                    }),
                    25,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::UpdateMaintenanceSchedule(MaintenanceSchedule {
                        windows: vec![MaintenanceWindow {
                            window_id: MaintenanceWindowId::new("mw-bad").unwrap_or_default(),
                            agent_ids: vec![bad_agent.clone()],
                            unavailability_start_tick: BenchmarkTicks::new(50),
                            duration_ticks: BenchmarkTicks::new(20),
                        }],
                    }),
                    25,
                )
                .is_err()
        );

        assert!(
            master
                .handle_operator_call(OperatorCall::StartMaintenance(vec![a1.clone()]), 26)
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(OperatorCall::StartMaintenance(vec![bad_agent.clone()]), 26)
                .is_err()
        );
        assert!(
            master
                .handle_operator_call(OperatorCall::StopMaintenance(vec![a1.clone()]), 27)
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(OperatorCall::StopMaintenance(vec![bad_agent.clone()]), 27)
                .is_err()
        );

        assert!(
            master
                .handle_operator_call(OperatorCall::DeactivateAgent(a1.clone()), 28)
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(OperatorCall::DeactivateAgent(bad_agent.clone()), 28)
                .is_err()
        );
        // Schedule tick skips deactivated a1
        let _ = master.schedule_tick(&states, 29).unwrap_or_default();
        assert!(
            master
                .handle_operator_call(OperatorCall::ReactivateAgent(a1.clone()), 30)
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(OperatorCall::ReactivateAgent(bad_agent.clone()), 30)
                .is_err()
        );

        // Drain a1 with RemainDrained & bad_agent error via OperatorCall
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::DrainAgent(
                        a1.clone(),
                        BenchmarkTicks::new(10),
                        DrainCompletionMode::RemainDrained,
                    ),
                    31,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::DrainAgent(
                        bad_agent.clone(),
                        BenchmarkTicks::new(10),
                        DrainCompletionMode::RemainDrained,
                    ),
                    31,
                )
                .is_err()
        );

        // Reactivate a1 and Revive fw_id so schedule_tick generates valid offers on a1 and a2
        let _ = master.handle_operator_call(OperatorCall::ReactivateAgent(a1.clone()), 31);
        let _ = master.handle_scheduler_call(SchedulerCall::Revive(fw_id.clone(), Vec::new()), 31);
        // Test accept_offers error branches for LaunchTaskGroup, Reserve, Unreserve, CreateVolume
        let huge_bundle = ResourceBundle {
            cpu: Millicores::new(999_999_000),
            disk: Bytes::new(999_999_000),
            ..ResourceBundle::zero()
        };
        for bad_op in [
            OfferOperation::LaunchTaskGroup(TaskGroupSpec {
                group_id: TaskGroupId::new("g-big").unwrap_or_default(),
                role: role.clone(),
                tasks: vec![make_task("t-big", &role, 999_999_000)],
                tpu_slice: None,
                placement_timeout_ms: 10,
            }),
            OfferOperation::Reserve(huge_bundle.clone()),
            OfferOperation::Unreserve(huge_bundle),
            OfferOperation::CreateVolume(VolumeReservationSpec {
                volume_id: VolumeId::new("v-big").unwrap_or_default(),
                capacity: Bytes::new(999_999_000),
                container_path: "/big".to_owned(),
            }),
        ] {
            let synth_oid = OfferId::new("offer-synth-err").unwrap_or_default();
            master.consumed_offers.remove(&synth_oid);
            master.active_offers.insert(
                synth_oid.clone(),
                ResourceOffer {
                    offer_id: synth_oid.clone(),
                    framework_id: fw_id.clone(),
                    agent_id: a1.clone(),
                    role: role.clone(),
                    resources: ResourceBundle {
                        cpu: Millicores::new(100),
                        disk: Bytes::new(100),
                        ..ResourceBundle::zero()
                    },
                    revocable: false,
                    expires_at_tick: 500,
                },
            );
            assert!(
                master
                    .accept_offers(
                        &AcceptOffers {
                            framework_id: fw_id.clone(),
                            offer_ids: vec![synth_oid],
                            operations: vec![bad_op],
                        },
                        32,
                    )
                    .is_err()
            );
        }

        // Duplicate volume error in OfferOperation::CreateVolume
        let dup_vol = VolumeReservationSpec {
            volume_id: VolumeId::new("v-dup").unwrap_or_default(),
            capacity: Bytes::new(100),
            container_path: "/dup".to_owned(),
        };
        let _ = master.create_persistent_volume(&a1, &role, dup_vol.clone());
        let oid_dup = OfferId::new("offer-synth-dup").unwrap_or_default();
        master.active_offers.insert(
            oid_dup.clone(),
            ResourceOffer {
                offer_id: oid_dup.clone(),
                framework_id: fw_id.clone(),
                agent_id: a1.clone(),
                role: role.clone(),
                resources: ResourceBundle {
                    cpu: Millicores::new(1_000),
                    disk: Bytes::new(1_000),
                    ..ResourceBundle::zero()
                },
                revocable: false,
                expires_at_tick: 500,
            },
        );
        assert!(
            master
                .accept_offers(
                    &AcceptOffers {
                        framework_id: fw_id.clone(),
                        offer_ids: vec![oid_dup],
                        operations: vec![OfferOperation::CreateVolume(dup_vol)],
                    },
                    33,
                )
                .is_err()
        );

        // Insert an active offer and an owned task directly so teardown_framework exercises both loops
        let td_oid = OfferId::new("offer-td-1").unwrap_or_default();
        master.active_offers.insert(
            td_oid,
            ResourceOffer {
                offer_id: OfferId::new("offer-td-1").unwrap_or_default(),
                framework_id: fw_id.clone(),
                agent_id: a2.clone(),
                role: role.clone(),
                resources: ResourceBundle {
                    cpu: Millicores::new(500),
                    ..ResourceBundle::zero()
                },
                revocable: false,
                expires_at_tick: 500,
            },
        );
        let teardown_task_id = TaskId::new("op-t-td").unwrap_or_default();
        master
            .task_owners
            .insert(teardown_task_id.clone(), fw_id.clone());
        master.tasks.insert(
            teardown_task_id,
            (
                TaskState::Running,
                a2.clone(),
                ResourceBundle {
                    cpu: Millicores::new(500),
                    ..ResourceBundle::zero()
                },
            ),
        );
        assert!(
            master
                .handle_scheduler_call(SchedulerCall::Teardown(fw_id), 35)
                .is_ok()
        );

        // Drain a1 with MarkGoneOnComplete and MarkAgentGone on a2 (with a running task on a2)
        assert!(
            master
                .drain_agent(
                    &a1,
                    BenchmarkTicks::new(5),
                    DrainCompletionMode::MarkGoneOnComplete
                )
                .is_ok()
        );
        master.tasks.insert(
            TaskId::new("running-on-a2").unwrap_or_default(),
            (TaskState::Running, a2.clone(), ResourceBundle::zero()),
        );
        assert!(
            master
                .handle_operator_call(OperatorCall::MarkAgentGone(a2), 37)
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(OperatorCall::MarkAgentGone(bad_agent), 37)
                .is_err()
        );

        // Test recover_from_state_store
        let _ = master.store.put("/agents/corrupt", b"{bad".to_vec());
        let recovered = master.recover_from_state_store(100).unwrap_or_default();
        assert_eq!(recovered, 2);
        master.store.set_fault(Some(MemoryStoreFault::FailReads));
        assert!(master.recover_from_state_store(100).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_phase5_reservation_refinement_resource_providers_role_suppression_and_full_recovery() {
        use arbiter_core::ids::{ElectionGroupId, MaintenanceWindowId, ResourceProviderId};
        use arbiter_core::workload::{
            CheckpointMode, DiskSource, MaintenanceWindow, ResourceProviderDiskSpec,
            ResourceProviderInfo,
        };

        let (mut h, parent_role) = sample_role_hierarchy();
        let child_role = RoleName::new("prod/ml").unwrap_or_default();
        let other_role = RoleName::new("analytics").unwrap_or_default();
        let max_b = ResourceBundle {
            cpu: Millicores::new(100_000),
            memory: Bytes::new(100_000_000),
            disk: Bytes::new(100_000_000),
            ..ResourceBundle::zero()
        };
        let _ = h.add_role(Role {
            name: child_role.clone(),
            parent: Some(parent_role.clone()),
            quota: Quota {
                id: QuotaId::new("q-child").unwrap_or_default(),
                guaranteed_min: ResourceBundle::zero(),
                hard_max: max_b.clone(),
                allow_burst_borrowing: true,
                weight: WeightBasisPoints::STANDARD,
            },
        });
        let _ = h.add_role(Role {
            name: other_role.clone(),
            parent: None,
            quota: Quota {
                id: QuotaId::new("q-other").unwrap_or_default(),
                guaranteed_min: ResourceBundle::zero(),
                hard_max: max_b,
                allow_burst_borrowing: true,
                weight: WeightBasisPoints::STANDARD,
            },
        });

        let mut master = MasterNode::new(MemoryStateStore::new(), h.clone(), 100, 50);
        let a1 = AgentId::new("agent-p5-1").unwrap_or_default();
        let cap = ResourceBundle {
            cpu: Millicores::new(16_000),
            memory: Bytes::new(16_000_000),
            disk: Bytes::new(50_000_000),
            ..ResourceBundle::zero()
        };
        assert!(
            master
                .register_agent(
                    RegisterAgent {
                        agent_id: a1.clone(),
                        os_kind: OsKind::Linux,
                        cpu_arch: CpuArch::X86_64,
                        total_resources: cap,
                        topology: HardwareTopologyGraph::new(),
                    },
                    10,
                )
                .is_ok()
        );

        let fw_id = FrameworkId::new("fw-p5-1").unwrap_or_default();
        // Subscribe with non-primary suppressed role so `conn.suppressed_roles.contains(&primary_role)` is false
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Subscribe(
                        SubscribeFramework {
                            framework_id: fw_id.clone(),
                            role: parent_role.clone(),
                            failover_timeout_ms: 100,
                        },
                        CheckpointMode::Enabled,
                        Vec::new(),
                        vec![other_role.clone()],
                    ),
                    10,
                )
                .is_ok()
        );
        // Suppress with empty roles vs non-primary role vs primary role
        assert!(
            master
                .handle_scheduler_call(SchedulerCall::Suppress(fw_id.clone(), Vec::new()), 11)
                .is_ok()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Revive(fw_id.clone(), vec![other_role.clone()]),
                    11,
                )
                .is_ok()
        );
        // Primary role is still suppressed after reviving only `other_role`
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Revive(fw_id.clone(), vec![parent_role.clone()]),
                    11,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Suppress(fw_id.clone(), vec![other_role.clone()]),
                    11,
                )
                .is_ok()
        );

        // ResourceProviderCall lifecycle & error branches
        let rp_id = ResourceProviderId::new("rp-csi-1").unwrap_or_default();
        let bad_rp_id = ResourceProviderId::new("rp-ghost").unwrap_or_default();
        assert!(
            master
                .handle_resource_provider_call(ResourceProviderCall::Subscribe(
                    ResourceProviderInfo {
                        provider_id: rp_id.clone(),
                        agent_id: Some(AgentId::new("unknown-agent").unwrap_or_default()),
                        provider_type: "org.apache.mesos.rp.local.storage".to_owned(),
                        provider_name: "csi-zfs".to_owned(),
                        default_role: parent_role.clone(),
                        advertised_disks: Vec::new(),
                    },
                ))
                .is_err()
        );
        // External resource provider (`agent_id: None`) and local resource provider (`agent_id: Some(a1)`)
        let ext_rp_id = ResourceProviderId::new("rp-ext-1").unwrap_or_default();
        assert!(
            master
                .handle_resource_provider_call(ResourceProviderCall::Subscribe(
                    ResourceProviderInfo {
                        provider_id: ext_rp_id,
                        agent_id: None,
                        provider_type: "org.apache.mesos.rp.external".to_owned(),
                        provider_name: "ext-san".to_owned(),
                        default_role: parent_role.clone(),
                        advertised_disks: Vec::new(),
                    },
                ))
                .is_ok()
        );
        let sub_rp = master
            .handle_resource_provider_call(ResourceProviderCall::Subscribe(ResourceProviderInfo {
                provider_id: rp_id.clone(),
                agent_id: Some(a1.clone()),
                provider_type: "org.apache.mesos.rp.local.storage".to_owned(),
                provider_name: "csi-zfs".to_owned(),
                default_role: parent_role.clone(),
                advertised_disks: vec![(
                    DiskSource::Raw("fast-nvme".to_owned()),
                    Bytes::new(10_000_000),
                )],
            }))
            .unwrap_or_default();
        assert_eq!(
            sub_rp,
            vec![ResourceProviderEvent::Subscribed(rp_id.clone())]
        );

        let op_id = OperationId::new("op-rp-1").unwrap_or_default();
        master.tracked_operations.insert(
            op_id.clone(),
            (fw_id.clone(), Some(a1.clone()), OperationState::Pending),
        );
        let uuid = StatusUpdateUuid::new("uuid-rp-1").unwrap_or_default();
        assert!(
            master
                .handle_resource_provider_call(ResourceProviderCall::UpdateOperationStatus(
                    bad_rp_id.clone(),
                    op_id.clone(),
                    OperationState::Finished,
                    uuid.clone(),
                    None,
                ))
                .is_err()
        );
        let converted_spec = ResourceProviderDiskSpec {
            provider_id: rp_id.clone(),
            volume_id: VolumeId::new("csi-vol-1").unwrap_or_default(),
            source: DiskSource::Mount("/mnt/csi-vol-1".to_owned()),
            capacity: Bytes::new(4_096),
        };
        assert!(
            master
                .handle_resource_provider_call(ResourceProviderCall::UpdateOperationStatus(
                    rp_id.clone(),
                    op_id,
                    OperationState::Finished,
                    uuid.clone(),
                    Some(converted_spec.clone()),
                ))
                .is_ok()
        );
        assert!(
            master
                .handle_resource_provider_call(ResourceProviderCall::UpdateOperationStatus(
                    rp_id.clone(),
                    OperationId::new("untracked-op").unwrap_or_default(),
                    OperationState::Finished,
                    uuid.clone(),
                    None,
                ))
                .is_ok()
        );
        assert!(
            master
                .handle_resource_provider_call(ResourceProviderCall::UpdateState(
                    bad_rp_id.clone(),
                    uuid.clone(),
                    Vec::new(),
                ))
                .is_err()
        );
        assert!(
            master
                .handle_resource_provider_call(ResourceProviderCall::UpdateState(
                    rp_id.clone(),
                    uuid.clone(),
                    vec![(converted_spec.source.clone(), converted_spec.capacity)],
                ))
                .is_ok()
        );
        assert!(
            master
                .handle_resource_provider_call(ResourceProviderCall::UpdatePublishResourcesStatus(
                    bad_rp_id.clone(),
                    uuid.clone(),
                    true,
                ))
                .is_err()
        );
        assert!(
            master
                .handle_resource_provider_call(ResourceProviderCall::UpdatePublishResourcesStatus(
                    rp_id.clone(),
                    uuid.clone(),
                    false,
                ))
                .is_err()
        );
        assert!(
            master
                .handle_resource_provider_call(ResourceProviderCall::UpdatePublishResourcesStatus(
                    rp_id, uuid, true,
                ))
                .is_ok()
        );

        // Reservation refinement (PushReservation / PopReservation) and CreateDisk / DestroyDisk in AcceptOffers
        let res_bundle = ResourceBundle {
            cpu: Millicores::new(2_000),
            disk: Bytes::new(8_192),
            ..ResourceBundle::zero()
        };
        let oid1 = OfferId::new("offer-p5-1").unwrap_or_default();
        master.active_offers.insert(
            oid1.clone(),
            ResourceOffer {
                offer_id: oid1.clone(),
                framework_id: fw_id.clone(),
                agent_id: a1.clone(),
                role: parent_role.clone(),
                resources: ResourceBundle {
                    cpu: Millicores::new(4_000),
                    disk: Bytes::new(20_000),
                    ..ResourceBundle::zero()
                },
                revocable: false,
                expires_at_tick: 500,
            },
        );
        assert!(
            master
                .handle_scheduler_call(
                    SchedulerCall::Accept(
                        AcceptOffers {
                            framework_id: fw_id.clone(),
                            offer_ids: vec![oid1],
                            operations: vec![
                                OfferOperation::Reserve(res_bundle.clone()),
                                OfferOperation::PushReservation(
                                    child_role.clone(),
                                    res_bundle.clone(),
                                ),
                                OfferOperation::PopReservation(res_bundle.clone()),
                                OfferOperation::PushReservation(
                                    child_role.clone(),
                                    res_bundle.clone(),
                                ),
                                OfferOperation::CreateDisk(converted_spec.clone()),
                                OfferOperation::DestroyDisk(converted_spec.clone()),
                                OfferOperation::CreateDisk(converted_spec.clone()),
                            ],
                        },
                        Some(OperationId::new("op-commit-p5").unwrap_or_default()),
                        OfferFilter {
                            refuse_milliseconds: 0,
                            min_cpu_millicores: 100,
                            min_memory_bytes: Bytes::new(1024),
                            min_gpu_vram: Bytes::new(1024),
                            refuse_gpu_offers: true,
                        },
                    ),
                    20,
                )
                .is_ok()
        );

        // Test error branches for PushReservation, PopReservation, CreateDisk, DestroyDisk
        let bad_ops = vec![
            // PushReservation to unknown role
            OfferOperation::PushReservation(
                RoleName::new("ghost-child").unwrap_or_default(),
                res_bundle.clone(),
            ),
            // PushReservation to role that is not a child of `parent_role`
            OfferOperation::PushReservation(other_role, res_bundle.clone()),
            // PushReservation exceeding base reservation
            OfferOperation::PushReservation(
                child_role,
                ResourceBundle {
                    cpu: Millicores::new(999_000),
                    ..ResourceBundle::zero()
                },
            ),
            // PopReservation exceeding stacked reservation
            OfferOperation::PopReservation(ResourceBundle {
                cpu: Millicores::new(999_000),
                ..ResourceBundle::zero()
            }),
            // CreateDisk with unknown provider
            OfferOperation::CreateDisk(ResourceProviderDiskSpec {
                provider_id: bad_rp_id.clone(),
                ..converted_spec.clone()
            }),
            // CreateDisk exceeding offered disk capacity
            OfferOperation::CreateDisk(ResourceProviderDiskSpec {
                capacity: Bytes::new(999_999_999),
                ..converted_spec.clone()
            }),
            // DestroyDisk with unknown provider
            OfferOperation::DestroyDisk(ResourceProviderDiskSpec {
                provider_id: bad_rp_id,
                ..converted_spec
            }),
        ];
        for bad_op in bad_ops {
            let oid_err = OfferId::new("offer-p5-err").unwrap_or_default();
            master.consumed_offers.remove(&oid_err);
            master.active_offers.insert(
                oid_err.clone(),
                ResourceOffer {
                    offer_id: oid_err.clone(),
                    framework_id: fw_id.clone(),
                    agent_id: a1.clone(),
                    role: parent_role.clone(),
                    resources: ResourceBundle {
                        cpu: Millicores::new(1_000),
                        disk: Bytes::new(1_000),
                        ..ResourceBundle::zero()
                    },
                    revocable: false,
                    expires_at_tick: 500,
                },
            );
            assert!(
                master
                    .accept_offers(
                        &AcceptOffers {
                            framework_id: fw_id.clone(),
                            offer_ids: vec![oid_err],
                            operations: vec![bad_op],
                        },
                        25,
                    )
                    .is_err()
            );
        }

        // PopReservation when no stack exists for agent
        let a_no_stack = AgentId::new("agent-nostack").unwrap_or_default();
        let oid_ns = OfferId::new("offer-p5-ns").unwrap_or_default();
        master.active_offers.insert(
            oid_ns.clone(),
            ResourceOffer {
                offer_id: oid_ns.clone(),
                framework_id: fw_id.clone(),
                agent_id: a_no_stack,
                role: parent_role.clone(),
                resources: ResourceBundle::zero(),
                revocable: false,
                expires_at_tick: 500,
            },
        );
        assert!(
            master
                .accept_offers(
                    &AcceptOffers {
                        framework_id: fw_id.clone(),
                        offer_ids: vec![oid_ns],
                        operations: vec![OfferOperation::PopReservation(res_bundle)],
                    },
                    25,
                )
                .is_err()
        );

        // Populate all remaining persisted prefixes (`/quotas/*`, `/weights/*`, `/volumes/*`, `/caas_leases/*`, `/offers/*`, `/tasks/*`)
        // and verify `recover_from_state_store` on a fresh MasterNode sharing the store.
        let _ = master.handle_operator_call(
            OperatorCall::SetQuota(
                parent_role.clone(),
                Quota {
                    id: QuotaId::new("q-p5").unwrap_or_default(),
                    guaranteed_min: ResourceBundle::zero(),
                    hard_max: ResourceBundle {
                        cpu: Millicores::new(50_000),
                        ..ResourceBundle::zero()
                    },
                    allow_burst_borrowing: true,
                    weight: WeightBasisPoints::STANDARD,
                },
            ),
            26,
        );
        let _ = master.handle_operator_call(
            OperatorCall::UpdateWeights(vec![(parent_role.clone(), WeightBasisPoints::STANDARD)]),
            26,
        );
        let vid_p5 = VolumeId::new("vol-p5").unwrap_or_default();
        let _ = master.create_persistent_volume(
            &a1,
            &parent_role,
            VolumeReservationSpec {
                volume_id: vid_p5.clone(),
                capacity: Bytes::new(512),
                container_path: "/var/lib/p5".to_owned(),
            },
        );
        // Test OperatorCall::GrowVolume & ShrinkVolume and error branches
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::GrowVolume(a1.clone(), vid_p5.clone(), Bytes::new(256)),
                    26,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::ShrinkVolume(a1.clone(), vid_p5.clone(), Bytes::new(128)),
                    26,
                )
                .is_ok()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::ShrinkVolume(a1.clone(), vid_p5.clone(), Bytes::new(999_999)),
                    26,
                )
                .is_err()
        );
        let ghost_vid = VolumeId::new("vol-ghost").unwrap_or_default();
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::GrowVolume(a1.clone(), ghost_vid.clone(), Bytes::new(10)),
                    26,
                )
                .is_err()
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::ShrinkVolume(a1.clone(), ghost_vid.clone(), Bytes::new(10)),
                    26,
                )
                .is_err()
        );
        assert!(
            master
                .grow_persistent_volume(&a1, &vid_p5, Bytes::new(999_999_999_999))
                .is_err()
        );

        // Test OfferOperation::GrowVolume and OfferOperation::ShrinkVolume + error branches
        let oid_vol_ops = OfferId::new("offer-vol-ops").unwrap_or_default();
        master.active_offers.insert(
            oid_vol_ops.clone(),
            ResourceOffer {
                offer_id: oid_vol_ops.clone(),
                framework_id: fw_id.clone(),
                agent_id: a1.clone(),
                role: parent_role.clone(),
                resources: ResourceBundle {
                    disk: Bytes::new(1_000),
                    ..ResourceBundle::zero()
                },
                revocable: false,
                expires_at_tick: 500,
            },
        );
        assert!(
            master
                .accept_offers(
                    &AcceptOffers {
                        framework_id: fw_id.clone(),
                        offer_ids: vec![oid_vol_ops],
                        operations: vec![
                            OfferOperation::GrowVolume(vid_p5.clone(), Bytes::new(200)),
                            OfferOperation::ShrinkVolume(vid_p5.clone(), Bytes::new(100)),
                        ],
                    },
                    26,
                )
                .is_ok()
        );
        for (idx, bad_vol_op) in [
            OfferOperation::GrowVolume(vid_p5.clone(), Bytes::new(999_999)),
            OfferOperation::GrowVolume(ghost_vid.clone(), Bytes::new(10)),
            OfferOperation::ShrinkVolume(ghost_vid, Bytes::new(10)),
            OfferOperation::ShrinkVolume(vid_p5, Bytes::new(999_999)),
        ]
        .into_iter()
        .enumerate()
        {
            let oid_bv = OfferId::new(&format!("offer-bv-{idx}")).unwrap_or_default();
            master.active_offers.insert(
                oid_bv.clone(),
                ResourceOffer {
                    offer_id: oid_bv.clone(),
                    framework_id: fw_id.clone(),
                    agent_id: a1.clone(),
                    role: parent_role.clone(),
                    resources: ResourceBundle {
                        disk: Bytes::new(1_000),
                        ..ResourceBundle::zero()
                    },
                    revocable: false,
                    expires_at_tick: 500,
                },
            );
            assert!(
                master
                    .accept_offers(
                        &AcceptOffers {
                            framework_id: fw_id.clone(),
                            offer_ids: vec![oid_bv],
                            operations: vec![bad_vol_op],
                        },
                        26,
                    )
                    .is_err()
            );
        }

        // Test GetLoggingLevel, SetLoggingLevel, ListFiles, ReadFile, and retry_unacknowledged_status_updates
        assert_eq!(
            master.handle_operator_call(OperatorCall::GetLoggingLevel, 26),
            Ok(OperatorResponse::LoggingLevel(1))
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::SetLoggingLevel(2, BenchmarkTicks::new(10)),
                    26
                )
                .is_ok()
        );
        assert_eq!(
            master.handle_operator_call(OperatorCall::GetLoggingLevel, 26),
            Ok(OperatorResponse::LoggingLevel(2))
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::SetLoggingLevel(9, BenchmarkTicks::new(10)),
                    26
                )
                .is_err()
        );
        master.sandbox_files.insert(
            "/var/lib/arbiter/task-1/stdout".to_owned(),
            "hello world\n".to_owned(),
        );
        assert_eq!(
            master.handle_operator_call(OperatorCall::ListFiles("/var/lib/arbiter".to_owned()), 26),
            Ok(OperatorResponse::FileList(vec![
                "/var/lib/arbiter/task-1/stdout".to_owned()
            ]))
        );
        assert_eq!(
            master.handle_operator_call(
                OperatorCall::ReadFile("/var/lib/arbiter/task-1/stdout".to_owned(), 0, 5),
                26
            ),
            Ok(OperatorResponse::FileChunk(0, "hello".to_owned()))
        );
        assert!(
            master
                .handle_operator_call(
                    OperatorCall::ReadFile("/var/lib/arbiter/missing".to_owned(), 0, 5),
                    26
                )
                .is_err()
        );
        master.unacknowledged_updates.insert(
            StatusUpdateUuid::new("uuid-retry-1").unwrap_or_default(),
            (
                fw_id.clone(),
                TaskStatusUpdate {
                    task_id: TaskId::new("t-retry-1").unwrap_or_default(),
                    agent_id: a1.clone(),
                    state: TaskState::Running,
                    message: "running".to_owned(),
                },
            ),
        );
        assert_eq!(master.retry_unacknowledged_status_updates().len(), 1);
        let _ = master.update_maintenance_schedule(
            MaintenanceSchedule {
                windows: vec![MaintenanceWindow {
                    window_id: MaintenanceWindowId::new("win-p5").unwrap_or_default(),
                    agent_ids: vec![a1.clone()],
                    unavailability_start_tick: BenchmarkTicks::new(900),
                    duration_ticks: BenchmarkTicks::new(100),
                }],
            },
            26,
        );
        let group_id_p5 = ElectionGroupId::new("pg-p5").unwrap_or_default();
        let primary_task_p5 = TaskId::new("caas-primary-1").unwrap_or_default();
        let _ = master.election_plane.register_group(
            group_id_p5.clone(),
            vec![(primary_task_p5.clone(), a1.clone())],
            100,
        );
        let _ = master.election_plane.elect_or_promote_primary(
            &mut master.store,
            &group_id_p5,
            &primary_task_p5,
            26,
            None,
        );
        let _ = master.process_agent_heartbeat(&AgentHeartbeat {
            agent_id: a1.clone(),
            tick: 27,
            healthy_tasks: vec![primary_task_p5],
        });
        // Reset filter & suppression on fw_id so schedule_tick generates an offer into `/offers/*`
        let _ = master.handle_scheduler_call(SchedulerCall::Revive(fw_id.clone(), Vec::new()), 27);
        // Also launch a framework-owned task so `/tasks/*` has both `Some(fw_id)` and `None` owners
        let oid_fw = OfferId::new("offer-p5-fw-task").unwrap_or_default();
        master.active_offers.insert(
            oid_fw.clone(),
            ResourceOffer {
                offer_id: oid_fw.clone(),
                framework_id: fw_id.clone(),
                agent_id: a1.clone(),
                role: parent_role.clone(),
                resources: ResourceBundle {
                    cpu: Millicores::new(1_000),
                    memory: Bytes::new(10_000),
                    ..ResourceBundle::zero()
                },
                revocable: false,
                expires_at_tick: 500,
            },
        );
        let _ = master.accept_offers(
            &AcceptOffers {
                framework_id: fw_id.clone(),
                offer_ids: vec![oid_fw],
                operations: vec![OfferOperation::LaunchTask(Box::new(make_task(
                    "fw-owned-p5",
                    &parent_role,
                    500,
                )))],
            },
            27,
        );
        master.submit_direct_job(SubmitDirectJob::SingleTask(Box::new(make_task(
            "direct-p5",
            &parent_role,
            500,
        ))));
        let states = vec![RoleAllocationState {
            role: parent_role,
            framework_id: Some(fw_id),
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        let _ = master.schedule_tick(&states, 28);

        let mut recovered_master = MasterNode::new(master.store.clone(), h, 100, 50);
        assert_eq!(recovered_master.recover_from_state_store(30), Ok(1));
        assert!(!recovered_master.frameworks.is_empty());
        assert!(!recovered_master.tasks.is_empty());
        assert!(!recovered_master.task_owners.is_empty());
        assert!(!recovered_master.active_offers.is_empty());
        assert!(!recovered_master.reservation_stacks.is_empty());
        assert!(!recovered_master.resource_providers.is_empty());
        assert!(!recovered_master.persistent_volumes.is_empty());
        assert!(!recovered_master.tracked_operations.is_empty());

        // Test enforce_mesos_acl_with_policy, preempt_for_high_priority_task, and burst_overflow_to_federation
        let mut policy = PolicyEngine::new();
        let spiffe_op =
            SpiffeId::new("spiffe://arbiter.internal/operator/admin").unwrap_or_default();
        let role_root = RoleName::new("team-a").unwrap_or_default();
        let env_attrs = BTreeMap::new();
        policy.add_rule(arbiter_net::security::PolicyRule {
            principal: spiffe_op.as_str().to_owned(),
            action: MesosAclAction::RunTask.as_str().to_owned(),
            resource_prefix: "role:team-a".to_owned(),
            role: role_root.clone(),
            required_attributes: BTreeMap::new(),
        });
        assert!(
            recovered_master
                .enforce_mesos_acl_with_policy(
                    &policy,
                    &spiffe_op,
                    MesosAclAction::RunTask,
                    "role:team-a/task-1",
                    &role_root,
                    &env_attrs,
                )
                .is_ok()
        );
        assert!(
            recovered_master
                .enforce_mesos_acl_with_policy(
                    &policy,
                    &spiffe_op,
                    MesosAclAction::KillTask,
                    "role:team-a/task-1",
                    &role_root,
                    &env_attrs,
                )
                .is_err()
        );

        // Preemption on a1 (set a1's free CPU to 1_000m so victim_tid holding 15_500m must be evicted!)
        for rec in recovered_master.agents.values_mut() {
            rec.available_resources.cpu = Millicores::new(1_000);
        }
        let victim_tid = TaskId::new("fw-owned-p5").unwrap_or_default();
        for (st, _, held) in recovered_master.tasks.values_mut() {
            *st = TaskState::Running;
            held.cpu = Millicores::new(15_500);
        }
        let victims = vec![RunningTaskInstance {
            task_id: victim_tid,
            group_id: None,
            agent_id: a1.clone(),
            role: role_root.clone(),
            priority: PriorityClass::SpotPreemptible,
            preemption_policy: PreemptionPolicy::GracefulSigterm,
            allocated_resources: ResourceBundle {
                cpu: Millicores::new(15_500),
                memory: Bytes::new(1_024),
                ..ResourceBundle::zero()
            },
            is_revocable: true,
        }];
        let mut high_prio_task = make_task("urgent-preempt-1", &role_root, 15_000);
        high_prio_task.priority = PriorityClass::SystemCritical;
        let p_plan = recovered_master
            .preempt_for_high_priority_task(&high_prio_task, &a1, &victims)
            .unwrap_or_default();
        assert_eq!(p_plan.victims.len(), 1);
        let ghost_agent = AgentId::new("agent-ghost").unwrap_or_default();
        assert!(
            recovered_master
                .preempt_for_high_priority_task(&high_prio_task, &ghost_agent, &victims)
                .is_err()
        );
        let huge_prio_task = make_task("urgent-too-huge", &role_root, 999_000);
        assert!(
            recovered_master
                .preempt_for_high_priority_task(&huge_prio_task, &a1, &[])
                .is_err()
        );

        // Federation bursting for unplaced direct tasks and gang jobs
        recovered_master.submit_direct_job(SubmitDirectJob::SingleTask(Box::new(make_task(
            "burst-t1", &role_root, 4_000,
        ))));
        recovered_master.submit_direct_job(SubmitDirectJob::SingleTask(Box::new(make_task(
            "burst-t2-too-big",
            &role_root,
            99_000,
        ))));
        recovered_master.submit_direct_job(SubmitDirectJob::GangJob(TaskGroupSpec {
            group_id: TaskGroupId::new("burst-g1").unwrap_or_default(),
            role: role_root.clone(),
            tasks: vec![make_task("burst-gt1", &role_root, 4_000)],
            tpu_slice: None,
            placement_timeout_ms: 100,
        }));
        recovered_master.submit_direct_job(SubmitDirectJob::GangJob(TaskGroupSpec {
            group_id: TaskGroupId::new("burst-g2-too-big").unwrap_or_default(),
            role: role_root.clone(),
            tasks: vec![make_task("burst-gt2", &role_root, 99_000)],
            tpu_slice: None,
            placement_timeout_ms: 100,
        }));
        let mut peers = vec![BurstPeerCandidate {
            cluster_id: ClusterId::new("eu-central-1").unwrap_or_default(),
            reachable: true,
            idle_capacity: ResourceBundle {
                cpu: Millicores::new(16_000),
                memory: Bytes::new(16_000_000),
                ..ResourceBundle::zero()
            },
        }];
        let (b_tasks, b_gangs) = recovered_master.burst_overflow_to_federation(&mut peers);
        assert_eq!(b_tasks.len(), 1);
        assert_eq!(b_gangs.len(), 1);
        assert_eq!(recovered_master.pending_direct_tasks.len(), 1);
        assert_eq!(recovered_master.pending_gang_jobs.len(), 1);
    }
}
