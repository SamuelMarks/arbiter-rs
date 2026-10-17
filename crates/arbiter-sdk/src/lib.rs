//! Ergonomic, strongly-typed Rust Framework and Direct Job Client SDK for Arbiter (`arbiter-sdk`).
//!
//! Provides:
//! - [`FrameworkScheduler`] trait for implementing custom 2-level Mesos-style Frameworks (`on_offers_received`, `on_task_status_update`).
//! - [`FrameworkRunner`] for subscribing a [`FrameworkScheduler`] to a [`MasterNode`] and driving offer acceptance/decline cycles.
//! - [`ArbiterClient`] for submitting direct tasks, atomic gang jobs, and TPU/GPU topology workloads to a Master control plane.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{FrameworkId, OfferId, RoleName, TaskGroupId, TaskId};
use arbiter_core::resources::{GpuPartition, GpuVendor, ResourceBundle, TpuTopologySlice};
use arbiter_core::workload::{
    IsolationSpec, OfferFilter, OfferOperation, PreemptionPolicy, PriorityClass, ResourceOffer,
    TaskGroupSpec, TaskSpec, TopologyConstraint,
};
use arbiter_master::MasterNode;
use arbiter_proto::{AcceptOffers, SubmitDirectJob, SubscribeFramework, TaskStatusUpdate};
use arbiter_store::traits::StateStore;

/// Trait implemented by custom 2-level Mesos-style Frameworks consuming [`ResourceOffer`]s.
pub trait FrameworkScheduler {
    /// Returns the Framework's unique [`FrameworkId`].
    ///
    /// # Returns
    ///
    /// [`FrameworkId`].
    fn framework_id(&self) -> FrameworkId;

    /// Returns the [`RoleName`] under which this Framework subscribes.
    ///
    /// # Returns
    ///
    /// [`RoleName`].
    fn role(&self) -> RoleName;

    /// Returns the failover timeout in milliseconds for this Framework.
    ///
    /// # Returns
    ///
    /// Failover timeout in milliseconds.
    fn failover_timeout_ms(&self) -> u64;

    /// Invoked when the Master dispatches a batch of [`ResourceOffer`]s to this Framework.
    ///
    /// The Framework returns a vector of [`AcceptOffers`] responses (either launching tasks,
    /// reserving resources, or declining offers).
    ///
    /// # Arguments
    ///
    /// * `offers` - Slice of [`ResourceOffer`]s allocated to this Framework.
    ///
    /// # Returns
    ///
    /// Vector of [`AcceptOffers`] decisions.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if the Framework scheduler encounters a domain error.
    fn on_offers_received(&mut self, offers: &[ResourceOffer]) -> ArbiterResult<Vec<AcceptOffers>>;

    /// Invoked when a task launched by this Framework transitions state on an Agent.
    ///
    /// # Arguments
    ///
    /// * `update` - [`TaskStatusUpdate`] notification.
    ///
    /// # Returns
    ///
    /// `Ok(())` on acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if status handling fails.
    fn on_task_status_update(&mut self, update: &TaskStatusUpdate) -> ArbiterResult<()>;
}

/// Driver that connects a [`FrameworkScheduler`] implementation to a [`MasterNode`].
pub struct FrameworkRunner<F: FrameworkScheduler> {
    /// Underlying [`FrameworkScheduler`] implementation.
    pub scheduler: F,
    /// Whether the Framework has subscribed to the Master.
    pub is_subscribed: bool,
}

impl<F: FrameworkScheduler> FrameworkRunner<F> {
    /// Creates a new [`FrameworkRunner`] wrapping `scheduler`.
    ///
    /// # Arguments
    ///
    /// * `scheduler` - [`FrameworkScheduler`] implementation.
    ///
    /// # Returns
    ///
    /// Unsubscribed [`FrameworkRunner`].
    pub const fn new(scheduler: F) -> Self {
        Self {
            scheduler,
            is_subscribed: false,
        }
    }

    /// Subscribes the Framework with `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    ///
    /// # Returns
    ///
    /// `Ok(())` when subscribed.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if the Framework's role does not exist on the Master.
    pub fn subscribe<S: StateStore>(&mut self, master: &mut MasterNode<S>) -> ArbiterResult<()> {
        master.subscribe_framework(SubscribeFramework {
            framework_id: self.scheduler.framework_id(),
            role: self.scheduler.role(),
            failover_timeout_ms: self.scheduler.failover_timeout_ms(),
        })?;
        self.is_subscribed = true;
        Ok(())
    }

    /// Dispatches all active offers belonging to this Framework from `master` to `scheduler.on_offers_received`
    /// and applies the resulting [`AcceptOffers`] operations back onto `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Number of [`AcceptOffers`] batches processed.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FrameworkNotFound`] if not subscribed, or any error from the scheduler or Master.
    pub fn poll_and_process_offers<S: StateStore>(
        &mut self,
        master: &mut MasterNode<S>,
        current_tick: u64,
    ) -> ArbiterResult<usize> {
        if !self.is_subscribed {
            return Err(ArbiterError::FrameworkNotFound {
                framework_id: self.scheduler.framework_id().to_string(),
            });
        }

        let fw_id = self.scheduler.framework_id();
        let my_offers: Vec<ResourceOffer> = master
            .active_offers
            .values()
            .filter(|o| o.framework_id == fw_id)
            .cloned()
            .collect();

        if my_offers.is_empty() {
            return Ok(0);
        }

        let decisions = self.scheduler.on_offers_received(&my_offers)?;
        let count = decisions.len();
        for accept in &decisions {
            master.accept_offers(accept, current_tick)?;
        }
        Ok(count)
    }

    /// Delivers a [`TaskStatusUpdate`] to the wrapped [`FrameworkScheduler`].
    ///
    /// # Arguments
    ///
    /// * `update` - [`TaskStatusUpdate`] notification.
    ///
    /// # Returns
    ///
    /// `Ok(())` on acknowledgement.
    ///
    /// # Errors
    ///
    /// Propagates any [`ArbiterError`] from `scheduler.on_task_status_update`.
    pub fn deliver_status_update(&mut self, update: &TaskStatusUpdate) -> ArbiterResult<()> {
        self.scheduler.on_task_status_update(update)
    }
}

/// High-level client SDK for submitting direct tasks, gang jobs, and GPU/TPU topology workloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArbiterClient {
    /// Default role used by this client when submitting workloads.
    pub default_role: RoleName,
}

impl ArbiterClient {
    /// Creates a new [`ArbiterClient`] bound to `default_role`.
    ///
    /// # Arguments
    ///
    /// * `default_role` - Default [`RoleName`] for submitted jobs.
    ///
    /// # Returns
    ///
    /// Initialized [`ArbiterClient`].
    pub const fn new(default_role: RoleName) -> Self {
        Self { default_role }
    }

    /// Submits a single direct [`TaskSpec`] to `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    /// * `task` - [`TaskSpec`] to enqueue.
    ///
    /// # Returns
    ///
    /// The submitted [`TaskId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RoleNotFound`] if `task.role` is not registered in `master`.
    pub fn submit_task<S: StateStore>(
        &self,
        master: &mut MasterNode<S>,
        task: TaskSpec,
    ) -> ArbiterResult<TaskId> {
        let _ = master.role_hierarchy.get_role(&task.role)?;
        let tid = task.task_id.clone();
        master.submit_direct_job(SubmitDirectJob::SingleTask(Box::new(task)));
        Ok(tid)
    }

    /// Builds and submits a GPU topology-aware direct task to `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    /// * `task_id` - Unique [`TaskId`].
    /// * `resources` - Requested [`ResourceBundle`].
    /// * `vendor` - Required [`GpuVendor`].
    /// * `partition` - Required [`GpuPartition`].
    /// * `constraints` - Hardware [`TopologyConstraint`]s (e.g., `NvLinkConnected`, `SameNuma`).
    /// * `command` - Executable command path.
    ///
    /// # Returns
    ///
    /// Submitted [`TaskId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RoleNotFound`] if `self.default_role` is unknown.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_gpu_workload<S: StateStore>(
        &self,
        master: &mut MasterNode<S>,
        task_id: TaskId,
        resources: ResourceBundle,
        vendor: GpuVendor,
        partition: GpuPartition,
        constraints: Vec<TopologyConstraint>,
        command: &str,
    ) -> ArbiterResult<TaskId> {
        let spec = TaskSpec {
            task_id,
            role: self.default_role.clone(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionHigh,
            preemption_policy: PreemptionPolicy::CheckpointAndSuspend,
            resources,
            required_gpu_vendor: Some(vendor),
            required_gpu_partition: Some(partition),
            topology_constraints: constraints,
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: command.to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        };
        self.submit_task(master, spec)
    }

    /// Submits an atomic multi-host gang job or TPU Pod slice workload to `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    /// * `group_id` - Unique [`TaskGroupId`].
    /// * `tasks` - Member [`TaskSpec`]s of the gang.
    /// * `tpu_slice` - Optional [`TpuTopologySlice`] torus requirement.
    /// * `placement_timeout_ms` - All-or-nothing placement timeout in milliseconds.
    ///
    /// # Returns
    ///
    /// Submitted [`TaskGroupId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `tasks` is empty, or
    /// [`ArbiterError::RoleNotFound`] if `self.default_role` is unknown.
    pub fn submit_gang_or_tpu_job<S: StateStore>(
        &self,
        master: &mut MasterNode<S>,
        group_id: TaskGroupId,
        tasks: Vec<TaskSpec>,
        tpu_slice: Option<TpuTopologySlice>,
        placement_timeout_ms: u64,
    ) -> ArbiterResult<TaskGroupId> {
        if tasks.is_empty() {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "gang.tasks".to_owned(),
                quantity: 0,
                reason: "gang job must contain at least one member task".to_owned(),
            });
        }
        let _ = master.role_hierarchy.get_role(&self.default_role)?;
        master.submit_direct_job(SubmitDirectJob::GangJob(TaskGroupSpec {
            group_id: group_id.clone(),
            role: self.default_role.clone(),
            tasks,
            tpu_slice,
            placement_timeout_ms,
        }));
        Ok(group_id)
    }

    /// Helper to build a decline [`AcceptOffers`] response for a set of unwanted [`OfferId`]s.
    ///
    /// # Arguments
    ///
    /// * `framework_id` - [`FrameworkId`] declining the offers.
    /// * `offer_ids` - Vector of [`OfferId`]s to decline.
    /// * `refuse_milliseconds` - Duration to suppress offers from the agent.
    ///
    /// # Returns
    ///
    /// [`AcceptOffers`] containing a single `OfferOperation::Decline`.
    pub fn build_decline_offers(
        framework_id: FrameworkId,
        offer_ids: Vec<OfferId>,
        refuse_milliseconds: u64,
    ) -> AcceptOffers {
        AcceptOffers {
            framework_id,
            offer_ids,
            operations: vec![OfferOperation::Decline(OfferFilter {
                refuse_milliseconds,
                min_cpu_millicores: 0,
                min_memory_bytes: arbiter_core::units::Bytes::ZERO,
            })],
        }
    }
}

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-sdk"`.
pub const fn crate_name() -> &'static str {
    "arbiter-sdk"
}

#[cfg(test)]
mod tests {
    use arbiter_alloc::drf::RoleAllocationState;
    use arbiter_core::ids::{AgentId, QuotaId};
    use arbiter_core::platform::{CpuArch, OsKind};
    use arbiter_core::topology::HardwareTopologyGraph;
    use arbiter_core::units::{Bytes, Millicores, WeightBasisPoints};
    use arbiter_core::workload::{Quota, Role, RoleHierarchy, TaskState};
    use arbiter_proto::RegisterAgent;
    use arbiter_store::memory::MemoryStateStore;

    use super::*;

    struct GreedyTestFramework {
        fw_id: FrameworkId,
        role: RoleName,
        launch_on_offer: bool,
        fail_on_offer: bool,
        observed_updates: usize,
    }

    impl FrameworkScheduler for GreedyTestFramework {
        fn framework_id(&self) -> FrameworkId {
            self.fw_id.clone()
        }

        fn role(&self) -> RoleName {
            self.role.clone()
        }

        fn failover_timeout_ms(&self) -> u64 {
            5000
        }

        fn on_offers_received(
            &mut self,
            offers: &[ResourceOffer],
        ) -> ArbiterResult<Vec<AcceptOffers>> {
            if self.fail_on_offer {
                return Err(ArbiterError::InvalidResourceQuantity {
                    resource: "simulated".to_owned(),
                    quantity: 0,
                    reason: "scheduler error".to_owned(),
                });
            }
            let mut out = Vec::new();
            for offer in offers {
                if self.launch_on_offer {
                    let task = TaskSpec {
                        task_id: TaskId::new("sdk-fw-task").unwrap_or_default(),
                        role: self.role.clone(),
                        framework_id: Some(self.fw_id.clone()),
                        election_group: None,
                        priority: PriorityClass::ProductionStandard,
                        preemption_policy: PreemptionPolicy::GracefulSigterm,
                        resources: ResourceBundle {
                            cpu: Millicores::new(1000),
                            memory: Bytes::new(1024),
                            ..ResourceBundle::zero()
                        },
                        required_gpu_vendor: None,
                        required_gpu_partition: None,
                        topology_constraints: Vec::new(),
                        isolation: IsolationSpec {
                            capabilities: Vec::new(),
                            image_ref: None,
                            command: "/bin/fw".to_owned(),
                            args: Vec::new(),
                            env: Vec::new(),
                            run_as_user: None,
                        },
                        artifacts: Vec::new(),
                        secrets: Vec::new(),
                        health_check: None,
                    };
                    out.push(AcceptOffers {
                        framework_id: self.fw_id.clone(),
                        offer_ids: vec![offer.offer_id.clone()],
                        operations: vec![OfferOperation::LaunchTask(Box::new(task))],
                    });
                } else {
                    out.push(ArbiterClient::build_decline_offers(
                        self.fw_id.clone(),
                        vec![offer.offer_id.clone()],
                        10,
                    ));
                }
            }
            Ok(out)
        }

        fn on_task_status_update(&mut self, _update: &TaskStatusUpdate) -> ArbiterResult<()> {
            self.observed_updates = self.observed_updates.saturating_add(1);
            Ok(())
        }
    }

    fn setup_master() -> (MasterNode<MemoryStateStore>, RoleName) {
        let role = RoleName::new("ml").unwrap_or_default();
        let mut h = RoleHierarchy::new();
        let _ = h.add_role(Role {
            name: role.clone(),
            parent: None,
            quota: Quota {
                id: QuotaId::new("q-ml").unwrap_or_default(),
                guaranteed_min: ResourceBundle::zero(),
                hard_max: ResourceBundle {
                    cpu: Millicores::new(100_000),
                    memory: Bytes::new(100_000_000),
                    ..ResourceBundle::zero()
                },
                allow_burst_borrowing: true,
                weight: WeightBasisPoints::STANDARD,
            },
        });
        let mut master = MasterNode::new(MemoryStateStore::new(), h, 100, 50);
        let _ = master.register_agent(
            RegisterAgent {
                agent_id: AgentId::new("agent-1").unwrap_or_default(),
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
        (master, role)
    }

    #[test]
    fn test_sdk_framework_runner() {
        assert_eq!(crate_name(), "arbiter-sdk");
        let (mut master, role) = setup_master();

        let fw_id = FrameworkId::new("spark-fw").unwrap_or_default();
        let mut runner = FrameworkRunner::new(GreedyTestFramework {
            fw_id: fw_id.clone(),
            role: role.clone(),
            launch_on_offer: true,
            fail_on_offer: false,
            observed_updates: 0,
        });

        // Poll before subscribe -> Err
        assert!(runner.poll_and_process_offers(&mut master, 20).is_err());

        // Subscribe with bad role -> Err
        let mut bad_runner = FrameworkRunner::new(GreedyTestFramework {
            fw_id: fw_id.clone(),
            role: RoleName::new("ghost").unwrap_or_default(),
            launch_on_offer: true,
            fail_on_offer: false,
            observed_updates: 0,
        });
        assert!(bad_runner.subscribe(&mut master).is_err());

        // Subscribe valid
        assert!(runner.subscribe(&mut master).is_ok());

        // Poll when no offers exist -> Ok(0)
        assert_eq!(runner.poll_and_process_offers(&mut master, 20), Ok(0));

        // Generate offer via schedule_tick
        let states = vec![RoleAllocationState {
            role,
            framework_id: Some(fw_id),
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        let _ = master.schedule_tick(&states, 20);

        // Scheduler error propagation during offer callback
        runner.scheduler.fail_on_offer = true;
        assert!(runner.poll_and_process_offers(&mut master, 25).is_err());
        runner.scheduler.fail_on_offer = false;

        // Poll and launch task on offer
        assert_eq!(runner.poll_and_process_offers(&mut master, 25), Ok(1));

        // Generate another offer and test decline path + expired offer error path
        let _ = master.schedule_tick(&states, 30);
        runner.scheduler.launch_on_offer = false;
        assert_eq!(runner.poll_and_process_offers(&mut master, 35), Ok(1));

        let _ = master.schedule_tick(&states, 50);
        assert!(runner.poll_and_process_offers(&mut master, 500).is_err()); // expired at tick 500

        // Deliver status update
        assert!(
            runner
                .deliver_status_update(&TaskStatusUpdate {
                    task_id: TaskId::new("sdk-fw-task").unwrap_or_default(),
                    agent_id: AgentId::new("agent-1").unwrap_or_default(),
                    state: TaskState::Running,
                    message: "ok".to_owned(),
                })
                .is_ok()
        );
        assert_eq!(runner.scheduler.observed_updates, 1);
    }

    #[test]
    fn test_sdk_client_submissions() {
        let (mut master, role) = setup_master();

        // ArbiterClient direct task, GPU workload, and gang/TPU job submissions
        let client = ArbiterClient::new(role);
        let t_gpu = client.submit_gpu_workload(
            &mut master,
            TaskId::new("gpu-job-1").unwrap_or_default(),
            ResourceBundle {
                cpu: Millicores::new(4000),
                memory: Bytes::new(8192),
                ..ResourceBundle::zero()
            },
            GpuVendor::Nvidia,
            GpuPartition::WholeDevice,
            vec![TopologyConstraint::SameNuma],
            "/bin/cuda-train",
        );
        assert!(t_gpu.is_ok());

        // Gang job empty tasks -> Err
        let gid = TaskGroupId::new("tpu-gang-1").unwrap_or_default();
        assert!(
            client
                .submit_gang_or_tpu_job(&mut master, gid.clone(), Vec::new(), None, 1000)
                .is_err()
        );

        // Valid gang job
        let member = TaskSpec {
            task_id: TaskId::new("gang-member-1").unwrap_or_default(),
            role: client.default_role.clone(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::Batch,
            preemption_policy: PreemptionPolicy::ImmediateKill,
            resources: ResourceBundle::zero(),
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/true".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        };
        assert!(
            client
                .submit_gang_or_tpu_job(&mut master, gid.clone(), vec![member], None, 1000)
                .is_ok()
        );

        // Client with unknown role -> Err
        let bad_client = ArbiterClient::new(RoleName::new("unknown-role").unwrap_or_default());
        assert!(
            bad_client
                .submit_gpu_workload(
                    &mut master,
                    TaskId::new("gpu-bad").unwrap_or_default(),
                    ResourceBundle::zero(),
                    GpuVendor::Nvidia,
                    GpuPartition::WholeDevice,
                    Vec::new(),
                    "/bin/false",
                )
                .is_err()
        );
        let popped_tasks = master
            .pending_gang_jobs
            .pop()
            .map(|g| g.tasks)
            .unwrap_or_default();
        assert!(
            bad_client
                .submit_gang_or_tpu_job(&mut master, gid, popped_tasks, None, 1000)
                .is_err()
        );
    }
}
