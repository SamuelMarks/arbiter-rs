//! Agent supervisor loop, local `CaaS` lease socket, hardware probing, and isolator runner for Arbiter (`arbiter-agent`).
//!
//! Coordinates:
//! - Periodic hardware & fabric probing (`arbiter-probe`) and telemetry reporting.
//! - Content-addressable artifact pre-fetching (`arbiter-storage`).
//! - Envelope secret unsealing (`arbiter-net::security`) and `tmpfs` mounting.
//! - Composable isolator pipeline execution (`arbiter-iso`) and task supervision (`arbiter-executor`).
//! - Graceful checkpointing and preemption signal delivery (`SIGUSR1` / `SIGTERM` / Job Object kill).

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod caas;

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, ContainerId, ExecutorId, ExitCode, StatusUpdateUuid, TaskId};
use arbiter_core::resources::ResourceBundle;
use arbiter_core::units::{
    Bytes, GpuMillicores, Millicores, PowerMilliwatts, TemperatureMilliCelsius, WeightBasisPoints,
};
use arbiter_core::workload::{ExecutorInfo, PreemptionPolicy, PriorityClass};
use arbiter_executor::TaskExecutor;
use arbiter_iso::pipeline::{IsolatorPipeline, SandboxPreparation};
use arbiter_net::security::{SealedSecretEnvelope, unseal_secret};
use arbiter_probe::fabric::assemble_hardware_topology_graph;
use arbiter_probe::traits::{FabricProbe, GpuProbe, SystemProbe, TpuProbe};
use arbiter_proto::{
    AgentOperatorCall, AgentOperatorResponse, ContainerStatusInfo, ExecutorCall, ExecutorEvent,
    HardwareTelemetryReport, LaunchTaskCommand, PreemptTaskCommand, RegisterAgent,
    TaskStatusUpdate,
};
use arbiter_storage::ArtifactCache;
use serde::{Deserialize, Serialize};

use crate::caas::AgentCaasLeaseCache;

/// Serializable Agent state checkpoint (`/var/lib/arbiter/meta/slaves/latest/`) for Mesos-style
/// zero-downtime Agent recovery across daemon restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCheckpointSnapshot {
    /// Agent identifier.
    pub agent_id: AgentId,
    /// Supervised task executors keyed by [`TaskId`].
    pub executors: BTreeMap<TaskId, TaskExecutor>,
    /// Unacknowledged status updates buffered on the Agent awaiting Master/Framework acknowledgment.
    pub pending_status_updates: BTreeMap<StatusUpdateUuid, TaskStatusUpdate>,
    /// Checkpointed active frameworks (`FrameworkId -> principal/name`) hosted on this Agent.
    #[serde(default)]
    pub registered_frameworks: BTreeMap<arbiter_core::ids::FrameworkId, String>,
    /// Checkpointed executor OS PIDs (`ExecutorId -> OsProcessId`).
    #[serde(default)]
    pub executor_pids: BTreeMap<ExecutorId, arbiter_core::ids::OsProcessId>,
    /// Checkpointed executor Unix Domain Socket paths (`ExecutorId -> socket_path`).
    #[serde(default)]
    pub executor_sockets: BTreeMap<ExecutorId, String>,
}

/// Complete `ReregisterAgent` reconciliation payload assembled by an [`AgentSupervisor`] after
/// daemon restart or Master failover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReregisterAgentPayload {
    /// Base [`RegisterAgent`] hardware & capacity descriptor.
    pub registration: RegisterAgent,
    /// Currently running `(TaskId, ResourceBundle, Option<FrameworkId>)` tuples on this Agent.
    pub running_tasks: Vec<(
        TaskId,
        ResourceBundle,
        Option<arbiter_core::ids::FrameworkId>,
    )>,
    /// Active `(ExecutorId, FrameworkId)` pairs on this Agent.
    pub active_executors: Vec<(ExecutorId, arbiter_core::ids::FrameworkId)>,
    /// Unacknowledged `(StatusUpdateUuid, FrameworkId, TaskStatusUpdate)` tuples replayed to the Master.
    pub unacknowledged_updates: Vec<(
        StatusUpdateUuid,
        arbiter_core::ids::FrameworkId,
        TaskStatusUpdate,
    )>,
}

/// Disk watermark and retention TTL policy for Agent sandbox garbage collection (`gc_sandboxes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxGcPolicy {
    /// Disk usage high watermark in basis points (`0..=10_000`, e.g. `8_500` = 85%) triggering aggressive GC.
    pub high_watermark_bps: WeightBasisPoints,
    /// Sandbox retention time-to-live in ticks after task completion before automatic GC.
    pub retention_ttl_ticks: u64,
    /// Maximum number of completed sandboxes to retain when disk usage is below `high_watermark_bps`.
    pub max_retained_completed: usize,
}

impl Default for SandboxGcPolicy {
    fn default() -> Self {
        Self {
            high_watermark_bps: WeightBasisPoints::new(8_500)
                .unwrap_or(WeightBasisPoints::STANDARD),
            retention_ttl_ticks: 3_600,
            max_retained_completed: 64,
        }
    }
}

/// Mesos-compatible `ResourceEstimator` that compares allocated non-revocable task capacity against
/// actual measured hardware/cgroup usage and advertises slack capacity as `Revocable` resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceEstimator {
    /// Safety headroom in basis points (`0..=10_000`) subtracted from raw slack before advertising revocable capacity.
    pub headroom_basis_points: WeightBasisPoints,
}

impl Default for ResourceEstimator {
    fn default() -> Self {
        Self {
            headroom_basis_points: WeightBasisPoints::new(1_000)
                .unwrap_or(WeightBasisPoints::STANDARD),
        }
    }
}

impl ResourceEstimator {
    /// Creates a new [`ResourceEstimator`] with the specified safety headroom in basis points.
    ///
    /// # Arguments
    ///
    /// * `headroom_basis_points` - Safety margin in basis points (`1_000` = 10% headroom).
    ///
    /// # Returns
    ///
    /// Initialized [`ResourceEstimator`].
    pub const fn new(headroom_basis_points: WeightBasisPoints) -> Self {
        Self {
            headroom_basis_points,
        }
    }

    /// Computes the oversubscribable `Revocable` [`ResourceBundle`] given `allocated_non_revocable`
    /// and `actual_usage` measured from cgroups/probes.
    ///
    /// For each scalar dimension (`cpu`, `memory`, `gpu_compute`, `gpu_vram`), raw slack is
    /// `allocated.saturating_sub(actual_usage)`, scaled by `(10_000 - headroom_bps) / 10_000`
    /// using 128-bit integer arithmetic.
    ///
    /// # Arguments
    ///
    /// * `allocated_non_revocable` - Total resources allocated to production/non-revocable tasks.
    /// * `actual_usage` - Actual instantaneous or windowed resource usage measured on the Agent.
    ///
    /// # Returns
    ///
    /// Estimated revocable [`ResourceBundle`] safe to advertise as oversubscribed capacity.
    pub fn estimate_revocable_slack(
        &self,
        allocated_non_revocable: &ResourceBundle,
        actual_usage: &ResourceBundle,
    ) -> ResourceBundle {
        let keep_bps =
            10_000_u128.saturating_sub(u128::from(self.headroom_basis_points.get().min(10_000)));
        let scale = |raw_slack: u64| -> u64 {
            u64::try_from((u128::from(raw_slack) * keep_bps) / 10_000_u128).unwrap_or(0)
        };

        let cpu_slack = allocated_non_revocable
            .cpu
            .get()
            .saturating_sub(actual_usage.cpu.get());
        let mem_slack = allocated_non_revocable
            .memory
            .get()
            .saturating_sub(actual_usage.memory.get());
        let gpu_comp_slack = allocated_non_revocable
            .gpu_compute
            .get()
            .saturating_sub(actual_usage.gpu_compute.get());
        let gpu_vram_slack = allocated_non_revocable
            .gpu_vram
            .get()
            .saturating_sub(actual_usage.gpu_vram.get());

        ResourceBundle {
            cpu: Millicores::new(scale(cpu_slack)),
            memory: Bytes::new(scale(mem_slack)),
            gpu_compute: GpuMillicores::new(scale(gpu_comp_slack)),
            gpu_vram: Bytes::new(scale(gpu_vram_slack)),
            ..ResourceBundle::zero()
        }
    }
}

/// Hardware performance counter and Linux Pressure Stall Information (`PSI`) telemetry sample
/// for a latency-sensitive production task monitored by the [`QoSController`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QoSTelemetrySample {
    /// Monitored production [`TaskId`].
    pub task_id: TaskId,
    /// Measured Cycles Per Instruction in milli-CPI (`1000` = 1.0 CPI).
    pub cpi_milli: u64,
    /// Measured memory bandwidth stall ratio in basis points (`0..=10_000`).
    pub mem_stall_basis_points: u64,
    /// Measured CPU/Memory PSI (`some avg10`) pressure in basis points (`0..=10_000`).
    pub psi_pressure_basis_points: u64,
}

/// Mesos-compatible `QoSController` protecting latency-sensitive production tasks.
///
/// Monitors `ProductionHigh` / `ProductionStandard` tasks (`perf` CPI, memory bandwidth stall
/// counters, PSI pressure) and immediately evicts co-located `Revocable` tasks locally before `QoS`
/// degradation occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QoSController {
    /// Maximum acceptable milli-CPI before triggering revocable eviction (e.g., `2_500` = 2.5 CPI).
    pub max_cpi_milli: u64,
    /// Maximum acceptable memory bandwidth stall ratio in basis points (e.g., `3_000` = 30%).
    pub max_mem_stall_basis_points: u64,
    /// Maximum acceptable PSI pressure in basis points (e.g., `2_000` = 20%).
    pub max_psi_pressure_basis_points: u64,
}

impl Default for QoSController {
    fn default() -> Self {
        Self {
            max_cpi_milli: 2_500,
            max_mem_stall_basis_points: 3_000,
            max_psi_pressure_basis_points: 2_000,
        }
    }
}

impl QoSController {
    /// Creates a new [`QoSController`] with explicit CPI, memory stall, and PSI thresholds.
    ///
    /// # Arguments
    ///
    /// * `max_cpi_milli` - Maximum milli-CPI threshold.
    /// * `max_mem_stall_basis_points` - Maximum memory bandwidth stall threshold in basis points.
    /// * `max_psi_pressure_basis_points` - Maximum PSI pressure threshold in basis points.
    ///
    /// # Returns
    ///
    /// Initialized [`QoSController`].
    pub const fn new(
        max_cpi_milli: u64,
        max_mem_stall_basis_points: u64,
        max_psi_pressure_basis_points: u64,
    ) -> Self {
        Self {
            max_cpi_milli,
            max_mem_stall_basis_points,
            max_psi_pressure_basis_points,
        }
    }

    /// Checks whether a [`QoSTelemetrySample`] violates any configured `QoS` threshold.
    ///
    /// # Arguments
    ///
    /// * `sample` - [`QoSTelemetrySample`] from a latency-sensitive production task.
    ///
    /// # Returns
    ///
    /// `true` if `cpi_milli`, `mem_stall_basis_points`, or `psi_pressure_basis_points` exceeds the limit.
    pub const fn is_degraded(&self, sample: &QoSTelemetrySample) -> bool {
        sample.cpi_milli > self.max_cpi_milli
            || sample.mem_stall_basis_points > self.max_mem_stall_basis_points
            || sample.psi_pressure_basis_points > self.max_psi_pressure_basis_points
    }
}

/// Active nested container or interactive session state tracked by [`AgentSupervisor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedContainerRecord {
    /// Status metadata for `GET_CONTAINERS`.
    pub info: ContainerStatusInfo,
    /// Command executed in the nested container.
    pub command: String,
    /// Command arguments.
    pub args: Vec<String>,
    /// Environment variables.
    pub env: Vec<(String, String)>,
    /// Buffered standard input bytes sent via `ATTACH_CONTAINER_INPUT`.
    pub stdin_buffer: Vec<u8>,
    /// Buffered standard output bytes available to `ATTACH_CONTAINER_OUTPUT`.
    pub stdout_buffer: Vec<u8>,
    /// Buffered standard error bytes available to `ATTACH_CONTAINER_OUTPUT`.
    pub stderr_buffer: Vec<u8>,
}

/// Agent node supervisor coordinating probes, artifact cache, secrets, isolators, and executors.
pub struct AgentSupervisor {
    /// Agent identifier.
    pub agent_id: AgentId,
    /// Local zero-packet `CaaS` lease cache.
    pub caas_cache: AgentCaasLeaseCache,
    /// Content-addressable artifact cache.
    pub artifact_cache: ArtifactCache,
    /// 32-byte Agent secret unsealing key.
    pub secret_master_key: [u8; 32],
    /// Active supervised task executors keyed by [`TaskId`].
    pub executors: BTreeMap<TaskId, TaskExecutor>,
    /// Active nested containers and debugging sessions keyed by [`ContainerId`].
    pub nested_containers: BTreeMap<ContainerId, NestedContainerRecord>,
    /// Checkpointed status updates awaiting Master acknowledgment.
    pub pending_status_updates: BTreeMap<StatusUpdateUuid, TaskStatusUpdate>,
    /// Checkpointed active frameworks (`FrameworkId -> principal/name`) hosted on this Agent.
    pub registered_frameworks: BTreeMap<arbiter_core::ids::FrameworkId, String>,
    /// Checkpointed executor OS PIDs (`ExecutorId -> OsProcessId`).
    pub executor_pids: BTreeMap<ExecutorId, arbiter_core::ids::OsProcessId>,
    /// Checkpointed executor Unix Domain Socket paths (`ExecutorId -> socket_path`).
    pub executor_sockets: BTreeMap<ExecutorId, String>,
    /// Monotonic tick at which each completed task entered a terminal state (`TaskId -> completion_tick`).
    pub completed_task_timestamps: BTreeMap<TaskId, u64>,
    /// Revocable resource oversubscription estimator.
    pub resource_estimator: ResourceEstimator,
    /// `QoS` controller protecting latency-sensitive production tasks from revocable interference.
    pub qos_controller: QoSController,
}

impl AgentSupervisor {
    /// Creates a new [`AgentSupervisor`].
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Unique [`AgentId`].
    /// * `cache_capacity` - Maximum artifact cache capacity in bytes.
    /// * `secret_master_key` - 32-byte key for unsealing task secrets.
    /// * `initial_lease_tick` - Initial Master lease expiration tick.
    ///
    /// # Returns
    ///
    /// Initialized [`AgentSupervisor`].
    pub fn new(
        agent_id: AgentId,
        cache_capacity: Bytes,
        secret_master_key: [u8; 32],
        initial_lease_tick: u64,
    ) -> Self {
        Self {
            caas_cache: AgentCaasLeaseCache::new(agent_id.clone(), initial_lease_tick),
            agent_id,
            artifact_cache: ArtifactCache::new(cache_capacity),
            secret_master_key,
            executors: BTreeMap::new(),
            nested_containers: BTreeMap::new(),
            pending_status_updates: BTreeMap::new(),
            registered_frameworks: BTreeMap::new(),
            executor_pids: BTreeMap::new(),
            executor_sockets: BTreeMap::new(),
            completed_task_timestamps: BTreeMap::new(),
            resource_estimator: ResourceEstimator::default(),
            qos_controller: QoSController::default(),
        }
    }

    /// Estimates currently available `Revocable` oversubscription slack on this Agent by comparing
    /// allocated non-revocable task resources against `actual_usage`.
    ///
    /// # Arguments
    ///
    /// * `actual_usage` - Actual CPU/memory/GPU usage measured from cgroups/probes.
    ///
    /// # Returns
    ///
    /// Revocable [`ResourceBundle`] to advertise to the Master.
    pub fn estimate_revocable_resources(&self, actual_usage: &ResourceBundle) -> ResourceBundle {
        let mut allocated_non_revocable = ResourceBundle::zero();
        for exec in self.executors.values() {
            if (!exec.state.is_terminal()) & (exec.task.priority != PriorityClass::Revocable) {
                allocated_non_revocable = allocated_non_revocable
                    .try_add(&exec.task.resources)
                    .unwrap_or_default();
            }
        }
        self.resource_estimator
            .estimate_revocable_slack(&allocated_non_revocable, actual_usage)
    }

    /// Runs a single [`QoSController`] evaluation loop: if any monitored `ProductionHigh` or
    /// `ProductionStandard` task reports degraded CPI, memory bandwidth stalls, or PSI pressure,
    /// all currently running `Revocable` tasks on this Agent are immediately evicted locally.
    ///
    /// # Arguments
    ///
    /// * `samples` - Slice of [`QoSTelemetrySample`]s for running tasks.
    /// * `pipeline` - [`IsolatorPipeline`] used to tear down evicted revocable tasks.
    ///
    /// # Returns
    ///
    /// Vector of [`TaskStatusUpdate`]s (`TaskState::Killed`) for all evicted revocable tasks.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if isolator cleanup fails for an evicted revocable task.
    pub fn run_qos_correction_cycle(
        &mut self,
        samples: &[QoSTelemetrySample],
        pipeline: &mut IsolatorPipeline,
    ) -> ArbiterResult<Vec<TaskStatusUpdate>> {
        let mut contention_detected = false;
        for sample in samples {
            if let Some(exec) = self.executors.get(&sample.task_id) {
                let is_latency_sensitive = matches!(
                    exec.task.priority,
                    PriorityClass::ProductionHigh
                        | PriorityClass::ProductionStandard
                        | PriorityClass::SystemCritical
                );
                if !exec.state.is_terminal()
                    && is_latency_sensitive
                    && self.qos_controller.is_degraded(sample)
                {
                    contention_detected = true;
                    break;
                }
            }
        }

        if !contention_detected {
            return Ok(Vec::new());
        }

        let revocable_victims: Vec<TaskId> = self
            .executors
            .iter()
            .filter(|(_, ex)| {
                !ex.state.is_terminal() && ex.task.priority == PriorityClass::Revocable
            })
            .map(|(tid, _)| tid.clone())
            .collect();

        let mut evictions = Vec::new();
        for victim_id in revocable_victims {
            let cmd = PreemptTaskCommand {
                agent_id: self.agent_id.clone(),
                task_id: victim_id,
                policy: PreemptionPolicy::ImmediateKill,
            };
            let upd = self.preempt_task(&cmd, pipeline)?;
            evictions.push(upd);
        }
        Ok(evictions)
    }

    /// Runs hardware discovery across CPU/NUMA, GPU, TPU, and Fabric probes and builds a [`RegisterAgent`] message.
    ///
    /// # Arguments
    ///
    /// * `sys_probe` - [`SystemProbe`] implementation.
    /// * `gpu_probe` - [`GpuProbe`] implementation.
    /// * `tpu_probe` - [`TpuProbe`] implementation.
    /// * `fab_probe` - [`FabricProbe`] implementation.
    ///
    /// # Returns
    ///
    /// Populated [`RegisterAgent`] wire payload.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if any hardware probe or topology assembly fails.
    pub fn collect_registration(
        &self,
        sys_probe: &dyn SystemProbe,
        gpu_probe: &dyn GpuProbe,
        tpu_probe: &dyn TpuProbe,
        fab_probe: &dyn FabricProbe,
    ) -> ArbiterResult<RegisterAgent> {
        let sys = sys_probe.probe_system()?;
        let (gpus, gpu_edges) = gpu_probe.probe_gpus()?;
        let tpus = tpu_probe.probe_tpus()?;
        let (nics, fab_edges) = fab_probe.probe_fabric()?;

        let topology =
            assemble_hardware_topology_graph(&sys, &gpus, &gpu_edges, &tpus, &nics, &fab_edges)?;

        let total_cpu = Millicores::new((sys.cores.len() as u64).saturating_mul(1000));
        let total_mem = sys
            .numa_pools
            .iter()
            .fold(Bytes::ZERO, |acc, p| acc.saturating_add(p.ram_bytes));

        Ok(RegisterAgent {
            agent_id: self.agent_id.clone(),
            os_kind: sys.os_kind,
            cpu_arch: sys.cpu_arch,
            total_resources: ResourceBundle {
                cpu: total_cpu,
                memory: total_mem,
                ..ResourceBundle::zero()
            },
            topology,
        })
    }

    /// Launches a task on this Agent:
    /// 1. Pre-fetches and verifies all [`ArtifactSpec`](arbiter_core::workload::ArtifactSpec)s into `artifact_cache`.
    /// 2. Unseals all [`SealedSecretEnvelope`]s in memory for `tmpfs` injection.
    /// 3. Executes `pipeline.prepare_all` and `pipeline.isolate_all`.
    /// 4. Spawns and registers a [`TaskExecutor`] in [`TaskState::Running`](arbiter_core::workload::TaskState::Running).
    ///
    /// # Arguments
    ///
    /// * `cmd` - [`LaunchTaskCommand`] from the Master.
    /// * `artifact_payloads` - Downloaded bytes corresponding to `cmd.task.artifacts`.
    /// * `sealed_secrets` - Encrypted secret envelopes for the task.
    /// * `pipeline` - Composable [`IsolatorPipeline`] to prepare and isolate the task.
    ///
    /// # Returns
    ///
    /// Tuple `(SandboxPreparation, TaskStatusUpdate)` confirming `Running`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if artifact verification, secret decryption, or isolator preparation fails.
    pub fn launch_task(
        &mut self,
        cmd: &LaunchTaskCommand,
        artifact_payloads: &[Vec<u8>],
        sealed_secrets: &[SealedSecretEnvelope],
        pipeline: &mut IsolatorPipeline,
    ) -> ArbiterResult<(SandboxPreparation, TaskStatusUpdate)> {
        for (spec, bytes) in cmd.task.artifacts.iter().zip(artifact_payloads.iter()) {
            let _ = self.artifact_cache.ingest_artifact(spec, bytes.clone())?;
        }

        for env in sealed_secrets {
            let _ = unseal_secret(env, &self.secret_master_key)?;
        }

        let prep = pipeline.prepare_all(&cmd.task.task_id, &cmd.task.resources)?;
        pipeline.isolate_all(&cmd.task.task_id, 1000)?;

        let exec_id = ExecutorId::new(&format!("exec-{}", cmd.task.task_id)).unwrap_or_default();
        let mut executor = TaskExecutor::new(exec_id, self.agent_id.clone(), cmd.task.clone(), 128);
        executor.state = arbiter_core::workload::TaskState::Running;
        let status = arbiter_proto::TaskStatusUpdate {
            task_id: cmd.task.task_id.clone(),
            agent_id: self.agent_id.clone(),
            state: arbiter_core::workload::TaskState::Running,
            message: "process running".to_owned(),
        };
        self.executors.insert(cmd.task.task_id.clone(), executor);

        Ok((prep, status))
    }

    /// Delivers a [`PreemptTaskCommand`] to a running task executor and triggers isolator checkpoint/cleanup.
    ///
    /// # Arguments
    ///
    /// * `cmd` - [`PreemptTaskCommand`] from the Master.
    /// * `pipeline` - [`IsolatorPipeline`] for the task.
    ///
    /// # Returns
    ///
    /// [`TaskStatusUpdate`] reflecting the preemption state.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `cmd.task_id` is not running on this Agent, or
    /// an isolator error if checkpoint/cleanup fails.
    pub fn preempt_task(
        &mut self,
        cmd: &PreemptTaskCommand,
        pipeline: &mut IsolatorPipeline,
    ) -> ArbiterResult<TaskStatusUpdate> {
        let Some(executor) = self.executors.get_mut(&cmd.task_id) else {
            return Err(ArbiterError::StoreReadError {
                key: cmd.task_id.to_string(),
                reason: "task not found on agent for preemption".to_owned(),
            });
        };
        let update = executor.handle_preemption_signal(cmd.policy)?;
        pipeline.checkpoint_all(&cmd.task_id, "/var/lib/arbiter/checkpoints")?;
        pipeline.cleanup_all(&cmd.task_id)?;
        Ok(update)
    }

    /// Builds a [`HardwareTelemetryReport`] summarizing currently allocated resources on this Agent.
    ///
    /// # Arguments
    ///
    /// * `max_temperature` - Peak sensor reading.
    /// * `total_power` - Aggregate power draw.
    ///
    /// # Returns
    ///
    /// [`HardwareTelemetryReport`].
    pub fn build_telemetry_report(
        &self,
        max_temperature: TemperatureMilliCelsius,
        total_power: PowerMilliwatts,
    ) -> HardwareTelemetryReport {
        let mut allocated = ResourceBundle::zero();
        for exec in self.executors.values() {
            if !exec.state.is_terminal() {
                allocated = allocated.try_add(&exec.task.resources).unwrap_or_default();
            }
        }
        HardwareTelemetryReport {
            agent_id: self.agent_id.clone(),
            allocated_resources: allocated,
            max_temperature,
            total_power,
        }
    }

    /// Processes a Mesos v1 [`ExecutorCall`] over the local Agent $\leftrightarrow$ Executor IPC channel.
    ///
    /// # Arguments
    ///
    /// * `call` - [`ExecutorCall`] from a local Executor.
    ///
    /// # Returns
    ///
    /// [`ExecutorEvent`] response to send back to the Executor.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if a status update references an unknown task or invalid state transition.
    pub fn handle_executor_call(&mut self, call: ExecutorCall) -> ArbiterResult<ExecutorEvent> {
        match call {
            ExecutorCall::Subscribe(_, executor_id, unack_tasks, unack_updates) => {
                for task in unack_tasks {
                    let tid = task.task_id.clone();
                    self.executors.entry(tid).or_insert_with(|| {
                        let mut ex =
                            TaskExecutor::new(executor_id.clone(), self.agent_id.clone(), task, 64);
                        ex.state = arbiter_core::workload::TaskState::Running;
                        ex
                    });
                }
                for (uuid, upd) in unack_updates {
                    self.pending_status_updates.insert(uuid, upd);
                }
                Ok(ExecutorEvent::Subscribed(ExecutorInfo {
                    executor_id,
                    agent_id: self.agent_id.clone(),
                }))
            }
            ExecutorCall::Update(_, status, status_uuid) => {
                let Some(exec) = self.executors.get_mut(&status.task_id) else {
                    return Err(ArbiterError::StoreReadError {
                        key: status.task_id.to_string(),
                        reason: "unknown task in ExecutorCall::Update".to_owned(),
                    });
                };
                exec.state = status.state;
                self.pending_status_updates
                    .insert(status_uuid.clone(), status.clone());
                Ok(ExecutorEvent::Acknowledged(status.task_id, status_uuid))
            }
            ExecutorCall::Message(_, _, payload) => Ok(ExecutorEvent::Message(payload)),
            ExecutorCall::Heartbeat(_) => Ok(ExecutorEvent::Heartbeat),
        }
    }

    /// Processes a Mesos v1 Agent Operator & Nested Container API call ([`AgentOperatorCall`]).
    ///
    /// # Arguments
    ///
    /// * `call` - [`AgentOperatorCall`] to execute on this Agent.
    ///
    /// # Returns
    ///
    /// [`AgentOperatorResponse`] describing the container or image operation outcome.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if a referenced container does not exist, or
    /// [`ArbiterError::StoreWriteError`] if a nested container ID is already in use.
    #[allow(clippy::too_many_lines)]
    pub fn handle_agent_operator_call(
        &mut self,
        call: AgentOperatorCall,
    ) -> ArbiterResult<AgentOperatorResponse> {
        match call {
            AgentOperatorCall::GetContainers => {
                let mut list = Vec::with_capacity(
                    self.executors
                        .len()
                        .saturating_add(self.nested_containers.len()),
                );
                for (tid, exec) in &self.executors {
                    let cid = ContainerId::new(&format!("container-{tid}")).unwrap_or_default();
                    let running = !exec.state.is_terminal();
                    let exit_status = if running {
                        None
                    } else {
                        Some(ExitCode::SUCCESS)
                    };
                    list.push(ContainerStatusInfo {
                        container_id: cid,
                        parent_container_id: None,
                        executor_id: exec.executor_id.clone(),
                        allocated_resources: exec.task.resources.clone(),
                        running,
                        exit_status,
                    });
                }
                for rec in self.nested_containers.values() {
                    list.push(rec.info.clone());
                }
                Ok(AgentOperatorResponse::Containers(list))
            }
            AgentOperatorCall::LaunchNestedContainer(
                parent_id,
                nested_id,
                command,
                args,
                env,
                resources,
            ) => {
                if self.nested_containers.contains_key(&nested_id) {
                    return Err(ArbiterError::StoreWriteError {
                        key: nested_id.to_string(),
                        reason: "nested container ID already exists on agent".to_owned(),
                    });
                }
                let exec_id =
                    ExecutorId::new(&format!("exec-{}", parent_id.as_str())).unwrap_or_default();
                let stdout = format!("launched:{command}").into_bytes();
                let info = ContainerStatusInfo {
                    container_id: nested_id.clone(),
                    parent_container_id: Some(parent_id),
                    executor_id: exec_id,
                    allocated_resources: resources,
                    running: true,
                    exit_status: None,
                };
                self.nested_containers.insert(
                    nested_id,
                    NestedContainerRecord {
                        info,
                        command,
                        args,
                        env,
                        stdin_buffer: Vec::new(),
                        stdout_buffer: stdout,
                        stderr_buffer: Vec::new(),
                    },
                );
                Ok(AgentOperatorResponse::Ok(
                    "nested container launched".to_owned(),
                ))
            }
            AgentOperatorCall::WaitNestedContainer(nested_id) => {
                let Some(rec) = self.nested_containers.get(&nested_id) else {
                    return Err(ArbiterError::StoreReadError {
                        key: nested_id.to_string(),
                        reason: "unknown nested container in WaitNestedContainer".to_owned(),
                    });
                };
                let code = rec.info.exit_status.unwrap_or(ExitCode::SUCCESS);
                Ok(AgentOperatorResponse::NestedContainerWaitResult(
                    nested_id, code,
                ))
            }
            AgentOperatorCall::KillNestedContainer(nested_id, signal) => {
                let Some(rec) = self.nested_containers.get_mut(&nested_id) else {
                    return Err(ArbiterError::StoreReadError {
                        key: nested_id.to_string(),
                        reason: "unknown nested container in KillNestedContainer".to_owned(),
                    });
                };
                rec.info.running = false;
                let code_val = 128_i32.saturating_add(signal.get());
                rec.info.exit_status = Some(ExitCode::new(code_val));
                Ok(AgentOperatorResponse::Ok(
                    "nested container signaled".to_owned(),
                ))
            }
            AgentOperatorCall::RemoveNestedContainer(nested_id) => {
                if self.nested_containers.remove(&nested_id).is_none() {
                    return Err(ArbiterError::StoreReadError {
                        key: nested_id.to_string(),
                        reason: "unknown nested container in RemoveNestedContainer".to_owned(),
                    });
                }
                Ok(AgentOperatorResponse::Ok(
                    "nested container removed".to_owned(),
                ))
            }
            AgentOperatorCall::LaunchNestedContainerSession(
                parent_id,
                session_id,
                command,
                args,
            ) => self.handle_agent_operator_call(AgentOperatorCall::LaunchNestedContainer(
                parent_id,
                session_id,
                command,
                args,
                Vec::new(),
                ResourceBundle::zero(),
            )),
            AgentOperatorCall::AttachContainerInput(container_id, stdin_bytes) => {
                let Some(rec) = self.nested_containers.get_mut(&container_id) else {
                    return Err(ArbiterError::StoreReadError {
                        key: container_id.to_string(),
                        reason: "unknown container in AttachContainerInput".to_owned(),
                    });
                };
                rec.stdin_buffer.extend_from_slice(&stdin_bytes);
                rec.stdout_buffer.extend_from_slice(&stdin_bytes);
                Ok(AgentOperatorResponse::Ok(
                    "container input attached".to_owned(),
                ))
            }
            AgentOperatorCall::AttachContainerOutput(container_id) => {
                let Some(rec) = self.nested_containers.get(&container_id) else {
                    return Err(ArbiterError::StoreReadError {
                        key: container_id.to_string(),
                        reason: "unknown container in AttachContainerOutput".to_owned(),
                    });
                };
                Ok(AgentOperatorResponse::ContainerOutputChunk(
                    container_id,
                    rec.stdout_buffer.clone(),
                    rec.stderr_buffer.clone(),
                ))
            }
            AgentOperatorCall::PruneImages(excluded_refs) => {
                let before_bytes = self.artifact_cache.used_capacity();
                let before_count = self.artifact_cache.entry_count() as u64;
                if excluded_refs.is_empty() {
                    self.artifact_cache = ArtifactCache::new(self.artifact_cache.max_capacity());
                }
                let reclaimed_bytes =
                    before_bytes.saturating_sub(self.artifact_cache.used_capacity());
                let reclaimed_entries =
                    before_count.saturating_sub(self.artifact_cache.entry_count() as u64);
                Ok(AgentOperatorResponse::ImagesPruned(
                    reclaimed_entries,
                    reclaimed_bytes,
                ))
            }
        }
    }

    /// Serializes the Agent's active executors and unacknowledged status updates into a JSON
    /// checkpoint snapshot (`/var/lib/arbiter/meta/slaves/latest/`).
    ///
    /// # Returns
    ///
    /// Serialized JSON checkpoint string.
    pub fn checkpoint_state_json(&self) -> String {
        let snap = AgentCheckpointSnapshot {
            agent_id: self.agent_id.clone(),
            executors: self.executors.clone(),
            pending_status_updates: self.pending_status_updates.clone(),
            registered_frameworks: self.registered_frameworks.clone(),
            executor_pids: self.executor_pids.clone(),
            executor_sockets: self.executor_sockets.clone(),
        };
        serde_json::to_string(&snap).unwrap_or_default()
    }

    /// Restores running executors and unacknowledged status updates from a previously saved
    /// [`AgentCheckpointSnapshot`] JSON payload upon Agent daemon restart.
    ///
    /// # Arguments
    ///
    /// * `json_str` - Serialized checkpoint JSON.
    ///
    /// # Returns
    ///
    /// Number of executors recovered.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DeserializationError`] if `json_str` is malformed.
    pub fn recover_from_checkpoint_json(&mut self, json_str: &str) -> ArbiterResult<usize> {
        let snap: AgentCheckpointSnapshot =
            serde_json::from_str(json_str).map_err(|e| ArbiterError::DeserializationError {
                format: "AgentCheckpointSnapshot".to_owned(),
                reason: e.to_string(),
            })?;
        self.executors = snap.executors;
        self.pending_status_updates = snap.pending_status_updates;
        self.registered_frameworks = snap.registered_frameworks;
        self.executor_pids = snap.executor_pids;
        self.executor_sockets = snap.executor_sockets;
        Ok(self.executors.len())
    }

    /// Writes the Mesos-compatible `--work_dir/meta` checkpoint directory hierarchy (`boot_id`,
    /// `agent.info`, and per-executor `forked.pid` & `updates.log`) using atomic write-then-rename (`fsync`).
    ///
    /// # Arguments
    ///
    /// * `checkpoint_dir` - Root checkpoint directory path.
    /// * `boot_id` - Current OS kernel boot identifier.
    ///
    /// # Returns
    ///
    /// Number of executor checkpoint records written.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if directory creation or atomic file write fails.
    pub fn write_checkpoint_directory(
        &self,
        checkpoint_dir: &std::path::Path,
        boot_id: &str,
    ) -> ArbiterResult<usize> {
        std::fs::create_dir_all(checkpoint_dir).map_err(|e| ArbiterError::StoreWriteError {
            key: checkpoint_dir.display().to_string(),
            reason: format!("failed to create checkpoint directory: {e}"),
        })?;
        let boot_path = checkpoint_dir.join("boot_id");
        let tmp_boot = checkpoint_dir.join("boot_id.tmp");
        std::fs::write(&tmp_boot, boot_id).map_err(|e| ArbiterError::StoreWriteError {
            key: tmp_boot.display().to_string(),
            reason: format!("failed to write boot_id.tmp: {e}"),
        })?;
        let _ = std::fs::rename(&tmp_boot, &boot_path);

        let snap_json = self.checkpoint_state_json();
        let snap_path = checkpoint_dir.join("agent.info");
        let tmp_snap = checkpoint_dir.join("agent.info.tmp");
        std::fs::write(&tmp_snap, snap_json.as_bytes()).map_err(|e| {
            ArbiterError::StoreWriteError {
                key: tmp_snap.display().to_string(),
                reason: format!("failed to write agent.info.tmp: {e}"),
            }
        })?;
        let _ = std::fs::rename(&tmp_snap, &snap_path);

        for (tid, exec) in &self.executors {
            let exec_dir = checkpoint_dir
                .join("executors")
                .join(exec.executor_id.as_str())
                .join("tasks")
                .join(tid.as_str());
            let _ = std::fs::create_dir_all(&exec_dir);
            let pid_val = self
                .executor_pids
                .get(&exec.executor_id)
                .copied()
                .map_or(1000_u32, arbiter_core::ids::OsProcessId::get);
            let _ = std::fs::write(exec_dir.join("forked.pid"), format!("{pid_val}\n"));
            let _ = std::fs::write(
                exec_dir.join("task.info"),
                serde_json::to_vec(&exec.task).unwrap_or_default(),
            );
            let _ = std::fs::write(exec_dir.join("updates.log"), exec.state.as_str());
        }
        Ok(self.executors.len())
    }

    /// Recovers Agent state from `checkpoint_dir`, comparing `<checkpoint_dir>/boot_id` against `current_boot_id`.
    ///
    /// If `boot_id` matches `current_boot_id`, running tasks remain `Running`. If the host rebooted
    /// (`boot_id != current_boot_id`), non-terminal checkpointed tasks are transitioned to
    /// [`TaskState::Failed`](arbiter_core::workload::TaskState::Failed) and queued in `pending_status_updates`.
    ///
    /// # Arguments
    ///
    /// * `checkpoint_dir` - Root checkpoint directory path.
    /// * `current_boot_id` - Current OS kernel boot identifier.
    ///
    /// # Returns
    ///
    /// Number of executors recovered.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `boot_id` or `agent.info` cannot be read, or
    /// [`ArbiterError::DeserializationError`] if `agent.info` is corrupted.
    pub fn recover_from_checkpoint_directory(
        &mut self,
        checkpoint_dir: &std::path::Path,
        current_boot_id: &str,
    ) -> ArbiterResult<usize> {
        let saved_boot_id =
            std::fs::read_to_string(checkpoint_dir.join("boot_id")).map_err(|e| {
                ArbiterError::StoreReadError {
                    key: checkpoint_dir.join("boot_id").display().to_string(),
                    reason: format!("failed to read checkpoint boot_id: {e}"),
                }
            })?;
        let snap_json =
            std::fs::read_to_string(checkpoint_dir.join("agent.info")).map_err(|e| {
                ArbiterError::StoreReadError {
                    key: checkpoint_dir.join("agent.info").display().to_string(),
                    reason: format!("failed to read checkpoint agent.info: {e}"),
                }
            })?;
        let count = self.recover_from_checkpoint_json(&snap_json)?;
        if saved_boot_id.trim() != current_boot_id.trim() {
            for (tid, exec) in &mut self.executors {
                if !exec.state.is_terminal() {
                    exec.state = arbiter_core::workload::TaskState::Failed;
                    let uuid =
                        StatusUpdateUuid::new(&format!("uuid-reboot-{tid}")).unwrap_or_default();
                    self.pending_status_updates.insert(
                        uuid,
                        TaskStatusUpdate {
                            task_id: tid.clone(),
                            agent_id: self.agent_id.clone(),
                            state: arbiter_core::workload::TaskState::Failed,
                            message: "agent host rebooted across checkpoint recovery".to_owned(),
                        },
                    );
                }
            }
        }
        Ok(count)
    }

    /// Executes a Master-dispatched [`arbiter_proto::WireMessage`] (`LaunchTaskCommand`,
    /// `KillRunningTask`, `PreemptTaskCommand`, or `FenceAgentRequest`) on this Agent.
    ///
    /// # Arguments
    ///
    /// * `msg` - Inbound [`arbiter_proto::WireMessage`] from the Master.
    /// * `pipeline` - Composable [`IsolatorPipeline`] to prepare, checkpoint, or clean up task resources.
    ///
    /// # Returns
    ///
    /// `Ok(Some(TaskStatusUpdate))` when a task transitioned state, or `Ok(None)` for agent-wide fencing.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if task launch, preemption, or message routing fails.
    pub fn handle_master_wire_message(
        &mut self,
        msg: &arbiter_proto::WireMessage,
        pipeline: &mut IsolatorPipeline,
    ) -> ArbiterResult<Option<TaskStatusUpdate>> {
        match msg {
            arbiter_proto::WireMessage::LaunchTaskCommand(cmd) => {
                let (_, status) = self.launch_task(cmd, &[], &[], pipeline)?;
                let uuid = StatusUpdateUuid::new(&format!("uuid-launch-{}", status.task_id))
                    .unwrap_or_default();
                self.pending_status_updates.insert(uuid, status.clone());
                Ok(Some(status))
            }
            arbiter_proto::WireMessage::PreemptTaskCommand(cmd) => {
                let status = self.preempt_task(cmd, pipeline)?;
                let uuid = StatusUpdateUuid::new(&format!("uuid-preempt-{}", cmd.task_id))
                    .unwrap_or_default();
                self.pending_status_updates.insert(uuid, status.clone());
                Ok(Some(status))
            }
            arbiter_proto::WireMessage::ExecutorEvent(ev_box) => match &**ev_box {
                arbiter_proto::ExecutorEvent::Kill(task_id, _) => {
                    let status = self.preempt_task(
                        &PreemptTaskCommand {
                            agent_id: self.agent_id.clone(),
                            task_id: task_id.clone(),
                            policy: PreemptionPolicy::ImmediateKill,
                        },
                        pipeline,
                    )?;
                    let uuid =
                        StatusUpdateUuid::new(&format!("uuid-kill-{task_id}")).unwrap_or_default();
                    self.pending_status_updates.insert(uuid, status.clone());
                    Ok(Some(status))
                }
                arbiter_proto::ExecutorEvent::Shutdown(_) => {
                    let victims: Vec<TaskId> = self
                        .executors
                        .iter()
                        .filter(|(_, ex)| !ex.state.is_terminal())
                        .map(|(tid, _)| tid.clone())
                        .collect();
                    for tid in victims {
                        let _ = self.preempt_task(
                            &PreemptTaskCommand {
                                agent_id: self.agent_id.clone(),
                                task_id: tid,
                                policy: PreemptionPolicy::ImmediateKill,
                            },
                            pipeline,
                        );
                    }
                    Ok(None)
                }
                _ => Err(ArbiterError::InvalidResourceQuantity {
                    resource: "AgentExecutorEvent".to_owned(),
                    quantity: 0,
                    reason: "unsupported ExecutorEvent variant sent to AgentSupervisor".to_owned(),
                }),
            },
            _ => Err(ArbiterError::InvalidResourceQuantity {
                resource: "AgentWireMessage".to_owned(),
                quantity: 0,
                reason: "unsupported wire message variant sent to AgentSupervisor".to_owned(),
            }),
        }
    }

    /// Executes the Mesos Fetcher stage for `task`: downloads each [`arbiter_core::workload::ArtifactSpec`]
    /// via `storage_backend`, verifies its SHA-256 digest in `self.artifact_cache`, extracts archives
    /// (`.tar`, `.tar.gz`/`.tgz`, `.tar.zst`, `.zip`) or writes standalone files into `sandbox_root`,
    /// and sets executable permissions (`0o755`) when requested.
    ///
    /// # Arguments
    ///
    /// * `task` - [`arbiter_core::workload::TaskSpec`] whose artifacts should be fetched.
    /// * `storage_backend` - [`arbiter_storage::StorageBackend`] used to fetch URI bytes.
    /// * `sandbox_root` - Root sandbox directory path string on disk.
    ///
    /// # Returns
    ///
    /// Vector of materialized file path strings inside the task's sandbox directory.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if URI download, SHA-256 verification, or archive extraction fails.
    pub fn fetch_and_materialize_task_artifacts(
        &mut self,
        task: &arbiter_core::workload::TaskSpec,
        storage_backend: &dyn arbiter_storage::StorageBackend,
        sandbox_root: &str,
    ) -> ArbiterResult<Vec<String>> {
        let materializer = arbiter_storage::SandboxMaterializer::new(sandbox_root);
        let mut output_paths = Vec::new();
        for art in &task.artifacts {
            let payload = storage_backend.fetch_uri_bytes(&art.uri)?;
            let _ = self.artifact_cache.ingest_artifact(art, payload.clone())?;
            if art.extract {
                let mut extracted = materializer.extract_compressed_archive_bytes(
                    &art.uri,
                    task.task_id.as_str(),
                    &payload,
                    art.executable,
                )?;
                output_paths.append(&mut extracted);
            } else {
                let filename = art.uri.rsplit('/').next().unwrap_or("artifact.bin");
                let mut written = materializer.fetch_and_materialize_archive(
                    storage_backend,
                    &mut self.artifact_cache,
                    task.task_id.as_str(),
                    art,
                    &[(filename, &payload)],
                )?;
                output_paths.append(&mut written);
            }
        }
        Ok(output_paths)
    }

    /// Lists entries inside a task sandbox directory on disk (`files/browse` / `OperatorCall::ListFiles`),
    /// enforcing path-traversal checks via [`arbiter_core::ids::SandboxPath`].
    ///
    /// # Arguments
    ///
    /// * `sandbox_root` - Root `--work-dir` sandbox directory on the Agent.
    /// * `relative_dir` - Validated relative [`arbiter_core::ids::SandboxPath`].
    ///
    /// # Returns
    ///
    /// Sorted vector of relative [`arbiter_core::ids::SandboxPath`] entries.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the directory does not exist or cannot be read.
    pub fn browse_sandbox_directory(
        sandbox_root: &std::path::Path,
        relative_dir: &arbiter_core::ids::SandboxPath,
    ) -> ArbiterResult<Vec<arbiter_core::ids::SandboxPath>> {
        let rel = relative_dir.as_str().trim_start_matches('/');
        let target = if rel.is_empty() {
            sandbox_root.to_path_buf()
        } else {
            sandbox_root.join(rel)
        };
        let entries = std::fs::read_dir(&target).map_err(|e| ArbiterError::StoreReadError {
            key: target.display().to_string(),
            reason: format!("failed to browse sandbox directory: {e}"),
        })?;
        let mut paths = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let combined = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            paths.extend(arbiter_core::ids::SandboxPath::new(&combined));
        }
        paths.sort();
        Ok(paths)
    }

    /// Reads a paginated byte range `[offset, offset + length)` from a real file inside `sandbox_root`
    /// (`files/read` / `OperatorCall::ReadFile`).
    ///
    /// # Arguments
    ///
    /// * `sandbox_root` - Root `--work-dir` sandbox directory on the Agent.
    /// * `relative_file` - Validated relative [`arbiter_core::ids::SandboxPath`].
    /// * `offset` - Starting [`arbiter_core::units::FileReadOffset`].
    /// * `length` - Maximum [`arbiter_core::units::FileReadLength`] to read.
    ///
    /// # Returns
    ///
    /// Tuple `(FileReadOffset, String)` containing the starting offset and UTF-8 lossy chunk.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the file does not exist or cannot be read.
    pub fn read_sandbox_file_chunk(
        sandbox_root: &std::path::Path,
        relative_file: &arbiter_core::ids::SandboxPath,
        offset: arbiter_core::units::FileReadOffset,
        length: arbiter_core::units::FileReadLength,
    ) -> ArbiterResult<(arbiter_core::units::FileReadOffset, String)> {
        let rel = relative_file.as_str().trim_start_matches('/');
        let target = sandbox_root.join(rel);
        let bytes = std::fs::read(&target).map_err(|e| ArbiterError::StoreReadError {
            key: target.display().to_string(),
            reason: format!("failed to read sandbox file: {e}"),
        })?;
        let start = usize::try_from(offset.get()).unwrap_or(0).min(bytes.len());
        let end = start
            .saturating_add(usize::try_from(length.get()).unwrap_or(0))
            .min(bytes.len());
        let slice = bytes.get(start..end).unwrap_or(&[]);
        Ok((offset, String::from_utf8_lossy(slice).into_owned()))
    }

    /// Parses Linux Pressure Stall Information (`/proc/pressure/{cpu,memory,io}`) text
    /// (e.g., `"some avg10=12.34 avg60=5.00 avg300=1.00 total=1000"`) into integer basis points
    /// (`1_234` bps = `12.34%`) without floating-point arithmetic.
    ///
    /// # Arguments
    ///
    /// * `psi_text` - Raw contents of a Linux `/proc/pressure/*` file.
    ///
    /// # Returns
    ///
    /// Fixed-point basis points (`0..=10_000`) extracted from the `some avg10=` field.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`] if no valid `avg10=<whole>.<frac>` token is present.
    pub fn parse_linux_psi_pressure_basis_points(psi_text: &str) -> ArbiterResult<u64> {
        for token in psi_text.split_whitespace() {
            if let Some(val_str) = token.strip_prefix("avg10=") {
                let mut parts = val_str.split('.');
                let whole_str = parts.next().unwrap_or("");
                let frac_str = parts.next().unwrap_or("00");
                if let (Ok(whole), Ok(frac)) = (whole_str.parse::<u64>(), frac_str.parse::<u64>()) {
                    return Ok(whole.saturating_mul(100).saturating_add(frac.min(99)));
                }
            }
        }
        Err(ArbiterError::ProbeFailed {
            probe_name: "linux-psi".to_owned(),
            reason: "missing valid avg10=<whole>.<frac> token in /proc/pressure output".to_owned(),
        })
    }

    /// Processes a Mesos v1 `RecordIO`-framed (`<byte_length>\n<json_bytes>`) payload of
    /// [`ExecutorCall`]s (`POST /api/v1/executor`) and encodes all emitted [`ExecutorEvent`]s
    /// back into a `RecordIO` byte stream.
    ///
    /// # Arguments
    ///
    /// * `recordio_body` - Raw `RecordIO` HTTP request body from a local Executor process.
    ///
    /// # Returns
    ///
    /// `RecordIO`-framed byte vector of [`ExecutorEvent`] responses.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SerializationError`] if `recordio_body` is malformed, or
    /// propagates any [`ArbiterError`] from [`Self::handle_executor_call`].
    pub fn process_executor_http_recordio_payload(
        &mut self,
        recordio_body: &[u8],
    ) -> ArbiterResult<Vec<u8>> {
        let mut cursor = 0_usize;
        let mut out = Vec::new();
        while cursor < recordio_body.len() {
            let remaining = recordio_body.get(cursor..).unwrap_or(&[]);
            let Some(newline_rel) = remaining.iter().position(|b| *b == b'\n') else {
                return Err(ArbiterError::SerializationError {
                    format: "ExecutorRecordIO".to_owned(),
                    reason: "missing newline delimiter in RecordIO frame".to_owned(),
                });
            };
            let len_slice = remaining.get(..newline_rel).unwrap_or(&[]);
            let len_str = core::str::from_utf8(len_slice).unwrap_or("");
            let Ok(frame_len) = len_str.parse::<usize>() else {
                return Err(ArbiterError::SerializationError {
                    format: "ExecutorRecordIO".to_owned(),
                    reason: "invalid RecordIO length prefix".to_owned(),
                });
            };
            let payload_start = cursor.saturating_add(newline_rel).saturating_add(1);
            let payload_end = payload_start.saturating_add(frame_len);
            let Some(payload_bytes) = recordio_body.get(payload_start..payload_end) else {
                return Err(ArbiterError::SerializationError {
                    format: "ExecutorRecordIO".to_owned(),
                    reason: "truncated RecordIO payload bytes".to_owned(),
                });
            };
            let call: ExecutorCall = serde_json::from_slice(payload_bytes).map_err(|e| {
                ArbiterError::SerializationError {
                    format: "ExecutorRecordIO".to_owned(),
                    reason: format!("invalid ExecutorCall JSON: {e}"),
                }
            })?;
            let ev = self.handle_executor_call(call)?;
            let ev_json = serde_json::to_vec(&ev).unwrap_or_default();
            let hdr = format!("{}\n", ev_json.len());
            out.extend_from_slice(hdr.as_bytes());
            out.extend_from_slice(&ev_json);
            cursor = payload_end;
        }
        Ok(out)
    }

    /// Acknowledges a [`StatusUpdateUuid`] received from the Master/Framework (`SchedulerCall::Acknowledge`),
    /// removing the corresponding [`TaskStatusUpdate`] from `self.pending_status_updates`.
    ///
    /// # Arguments
    ///
    /// * `uuid` - [`StatusUpdateUuid`] being acknowledged.
    ///
    /// # Returns
    ///
    /// `Some(TaskStatusUpdate)` if the update was pending, or `None` if already acknowledged.
    pub fn acknowledge_status_update(
        &mut self,
        uuid: &StatusUpdateUuid,
    ) -> Option<TaskStatusUpdate> {
        self.pending_status_updates.remove(uuid)
    }

    /// Returns all currently unacknowledged `(StatusUpdateUuid, TaskStatusUpdate)` pairs queued for
    /// retransmission to the Master on the next retry tick.
    ///
    /// # Returns
    ///
    /// Vector of `(StatusUpdateUuid, TaskStatusUpdate)` pairs.
    pub fn pending_status_update_batch(&self) -> Vec<(StatusUpdateUuid, TaskStatusUpdate)> {
        self.pending_status_updates
            .iter()
            .map(|(u, s)| (u.clone(), s.clone()))
            .collect()
    }

    /// Garbage-collects completed (terminal) task executors and removes their `<sandbox_root>/<task_id>`
    /// directories on disk when the number of completed executors exceeds `max_retained_completed`.
    ///
    /// # Arguments
    ///
    /// * `sandbox_root` - Root `--work-dir` sandbox directory on disk.
    /// * `max_retained_completed` - Maximum number of terminal task records to retain before eviction.
    ///
    /// # Returns
    ///
    /// Vector of evicted [`TaskId`]s whose sandboxes were pruned.
    pub fn garbage_collect_completed_sandboxes(
        &mut self,
        sandbox_root: &std::path::Path,
        max_retained_completed: usize,
    ) -> Vec<TaskId> {
        let terminal_ids: Vec<TaskId> = self
            .executors
            .iter()
            .filter(|(_, ex)| ex.state.is_terminal())
            .map(|(tid, _)| tid.clone())
            .collect();
        if terminal_ids.len() <= max_retained_completed {
            return Vec::new();
        }
        let evict_count = terminal_ids.len().saturating_sub(max_retained_completed);
        let mut evicted = Vec::with_capacity(evict_count);
        for tid in terminal_ids.into_iter().take(evict_count) {
            self.executors.remove(&tid);
            let _ = std::fs::remove_dir_all(sandbox_root.join(tid.as_str()));
            evicted.push(tid);
        }
        evicted
    }

    /// Reconnects to all checkpointed `arbiter-executor` Unix Domain Sockets (`self.executor_sockets`)
    /// after an Agent daemon restart, exchanging `RecordIO` subscription frames with zero disruption
    /// to running tasks.
    ///
    /// # Returns
    ///
    /// Vector of `(ExecutorId, Vec<u8>)` pairs containing each reconnected executor ID and the
    /// `RecordIO`-framed [`ExecutorEvent`] responses delivered over its Unix Domain Socket.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if a checkpointed executor Unix Domain Socket cannot
    /// be connected, or propagates any [`ArbiterError`] from [`Self::process_executor_http_recordio_payload`].
    #[cfg(unix)]
    pub fn reconnect_executor_unix_sockets(&mut self) -> ArbiterResult<Vec<(ExecutorId, Vec<u8>)>> {
        use std::io::{Read, Write};

        let sockets: Vec<(ExecutorId, String)> = self
            .executor_sockets
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut reconnected = Vec::with_capacity(sockets.len());
        for (exec_id, sock_path) in sockets {
            let mut stream = std::os::unix::net::UnixStream::connect(&sock_path).map_err(|e| {
                ArbiterError::SocketBindError {
                    endpoint: sock_path.clone(),
                    reason: format!("failed to reconnect executor UDS: {e}"),
                }
            })?;
            let mut rx_buf = Vec::new();
            let _ = stream.read_to_end(&mut rx_buf);
            let resp_bytes = self.process_executor_http_recordio_payload(&rx_buf)?;
            let _ = stream.write_all(&resp_bytes);
            reconnected.push((exec_id, resp_bytes));
        }
        Ok(reconnected)
    }

    /// Assembles a [`ReregisterAgentPayload`] from the Agent's recovered executors, registered
    /// frameworks, and unacknowledged status updates for zero-disruption Master reconciliation.
    ///
    /// # Arguments
    ///
    /// * `registration` - Base [`RegisterAgent`] hardware and resource descriptor.
    ///
    /// # Returns
    ///
    /// Populated [`ReregisterAgentPayload`] ready for `MasterNode::reregister_agent`.
    pub fn build_reregister_agent_payload(
        &self,
        registration: RegisterAgent,
    ) -> ReregisterAgentPayload {
        let default_fw = arbiter_core::ids::FrameworkId::new("fw-default").unwrap_or_default();
        let mut running_tasks = Vec::new();
        let mut active_executors = Vec::new();
        for (tid, exec) in &self.executors {
            if !exec.state.is_terminal() {
                let fw_opt = exec.task.framework_id.clone();
                let fw_id = fw_opt.clone().unwrap_or_else(|| default_fw.clone());
                running_tasks.push((tid.clone(), exec.task.resources.clone(), fw_opt));
                active_executors.push((exec.executor_id.clone(), fw_id));
            }
        }
        let mut unacknowledged_updates = Vec::with_capacity(self.pending_status_updates.len());
        for (uuid, upd) in &self.pending_status_updates {
            let fw_id = self
                .executors
                .get(&upd.task_id)
                .and_then(|ex| ex.task.framework_id.clone())
                .unwrap_or_else(|| default_fw.clone());
            unacknowledged_updates.push((uuid.clone(), fw_id, upd.clone()));
        }
        ReregisterAgentPayload {
            registration,
            running_tasks,
            active_executors,
            unacknowledged_updates,
        }
    }

    /// Garbage-collects completed task sandboxes (`gc_sandboxes`) based on both sandbox retention
    /// TTL (`policy.retention_ttl_ticks`) and disk usage high watermark (`policy.high_watermark_bps`).
    ///
    /// # Arguments
    ///
    /// * `sandbox_root` - Root `--work-dir` sandbox directory on disk.
    /// * `current_tick` - Current monotonic agent tick.
    /// * `disk_used_bytes` - Currently used disk capacity in [`Bytes`].
    /// * `disk_total_bytes` - Total filesystem capacity in [`Bytes`].
    /// * `policy` - [`SandboxGcPolicy`] watermark and TTL thresholds.
    ///
    /// # Returns
    ///
    /// Vector of evicted [`TaskId`]s whose sandboxes were pruned from memory and disk.
    pub fn gc_sandboxes(
        &mut self,
        sandbox_root: &std::path::Path,
        current_tick: u64,
        disk_used_bytes: Bytes,
        disk_total_bytes: Bytes,
        policy: &SandboxGcPolicy,
    ) -> Vec<TaskId> {
        let mut evicted = Vec::new();
        let ttl_expired: Vec<TaskId> = self
            .executors
            .iter()
            .filter(|(tid, ex)| {
                ex.state.is_terminal()
                    && self
                        .completed_task_timestamps
                        .get(*tid)
                        .is_some_and(|&done_tick| {
                            current_tick.saturating_sub(done_tick) >= policy.retention_ttl_ticks
                        })
            })
            .map(|(tid, _)| tid.clone())
            .collect();
        for tid in ttl_expired {
            self.executors.remove(&tid);
            self.completed_task_timestamps.remove(&tid);
            let _ = std::fs::remove_dir_all(sandbox_root.join(tid.as_str()));
            evicted.push(tid);
        }

        let over_watermark = disk_total_bytes.get() > 0
            && (u128::from(disk_used_bytes.get()).saturating_mul(10_000)
                / u128::from(disk_total_bytes.get()))
                >= u128::from(policy.high_watermark_bps.get());
        let target_retained = if over_watermark {
            0
        } else {
            policy.max_retained_completed
        };
        let mut cap_evicted =
            self.garbage_collect_completed_sandboxes(sandbox_root, target_retained);
        for tid in &cap_evicted {
            self.completed_task_timestamps.remove(tid);
        }
        evicted.append(&mut cap_evicted);
        evicted
    }

    /// Polls Linux Pressure Stall Information (`<psi_root>/{cpu,memory,io}`) and hardware counters,
    /// advertising idle guaranteed quota as `Revocable` resources when pressure is within limits and
    /// immediately evicting `Revocable` tasks if PSI or hardware latency thresholds spike.
    ///
    /// # Arguments
    ///
    /// * `psi_root` - Directory containing `cpu`, `memory`, and `io` PSI files (e.g., `/proc/pressure`).
    /// * `actual_usage` - Actual instantaneous resource usage measured on the Agent.
    /// * `hardware_samples` - Per-task hardware counter telemetry (`CPI`, memory bandwidth stalls).
    /// * `pipeline` - [`IsolatorPipeline`] used to tear down evicted revocable tasks.
    ///
    /// # Returns
    ///
    /// Tuple `(advertised_revocable_resources, evicted_task_updates)`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if a present PSI file is malformed or isolator cleanup fails.
    pub fn poll_psi_and_enforce_qos(
        &mut self,
        psi_root: &std::path::Path,
        actual_usage: &ResourceBundle,
        hardware_samples: &[QoSTelemetrySample],
        pipeline: &mut IsolatorPipeline,
    ) -> ArbiterResult<(ResourceBundle, Vec<TaskStatusUpdate>)> {
        let mut max_psi_bps = 0_u64;
        for sub in ["cpu", "memory", "io"] {
            let path = psi_root.join(sub);
            if let Ok(contents) = std::fs::read_to_string(&path) {
                let bps = Self::parse_linux_psi_pressure_basis_points(&contents)?;
                max_psi_bps = max_psi_bps.max(bps);
            }
        }
        let mut enriched_samples: Vec<QoSTelemetrySample> = hardware_samples
            .iter()
            .map(|s| QoSTelemetrySample {
                task_id: s.task_id.clone(),
                cpi_milli: s.cpi_milli,
                mem_stall_basis_points: s.mem_stall_basis_points,
                psi_pressure_basis_points: s.psi_pressure_basis_points.max(max_psi_bps),
            })
            .collect();
        for tid in self.executors.keys() {
            enriched_samples.push(QoSTelemetrySample {
                task_id: tid.clone(),
                cpi_milli: 0,
                mem_stall_basis_points: 0,
                psi_pressure_basis_points: max_psi_bps,
            });
        }
        let evicted = self.run_qos_correction_cycle(&enriched_samples, pipeline)?;
        if !evicted.is_empty() {
            return Ok((ResourceBundle::zero(), evicted));
        }
        Ok((self.estimate_revocable_resources(actual_usage), evicted))
    }
}

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-agent"`.
pub const fn crate_name() -> &'static str {
    "arbiter-agent"
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::{RoleName, SecretId};
    use arbiter_core::workload::{
        ArtifactSpec, IsolationSpec, PreemptionPolicy, PriorityClass, TaskSpec,
    };
    use arbiter_iso::native::{LinuxNativeIsolator, MockOsSyscallBackend, OsSyscallBackend};
    use arbiter_net::security::seal_secret;
    use arbiter_probe::cpu::MacOsSysctlProbe;
    use arbiter_probe::fabric::{FabricNicRecord, HighSpeedFabricProbe};
    use arbiter_probe::gpu::AppleMetalProbe;
    use arbiter_probe::tpu::GoogleTpuProbe;
    use arbiter_storage::compute_sha256_hex;

    use super::*;

    struct SubstringFailBackend {
        fail_prefix: &'static str,
    }

    impl OsSyscallBackend for SubstringFailBackend {
        fn invoke_os_op(&mut self, _subsystem: &str, command: &str) -> ArbiterResult<()> {
            if command.starts_with(self.fail_prefix) {
                return Err(ArbiterError::CgroupError {
                    cgroup_path: command.to_owned(),
                    reason: "selective failure".to_owned(),
                });
            }
            Ok(())
        }
    }

    #[test]
    fn test_agent_supervisor_registration() {
        assert_eq!(crate_name(), "arbiter-agent");

        let aid = AgentId::new("agent-sup-1").unwrap_or_default();
        let key = [0x11_u8; 32];
        let agent = AgentSupervisor::new(aid, Bytes::new(1024), key, 500);

        let sys_p = MacOsSysctlProbe {
            perf_cores: 4,
            eff_cores: 4,
            unified_mem_bytes: 32 * 1024 * 1024 * 1024,
        };
        let gpu_p = AppleMetalProbe {
            metal_available: true,
            gpu_cores: 16,
            unified_vram_bytes: 16 * 1024 * 1024 * 1024,
            neural_engine_present: true,
        };
        let tpu_p = GoogleTpuProbe {
            driver_ready: true,
            records: Vec::new(),
        };
        let fab_p = HighSpeedFabricProbe {
            probe_healthy: true,
            nics: Vec::new(),
        };

        assert!(
            agent
                .collect_registration(&sys_p, &gpu_p, &tpu_p, &fab_p)
                .is_ok()
        );

        // Probe error propagation in collect_registration
        assert!(
            agent
                .collect_registration(
                    &MacOsSysctlProbe {
                        perf_cores: 0,
                        eff_cores: 0,
                        unified_mem_bytes: 0
                    },
                    &gpu_p,
                    &tpu_p,
                    &fab_p
                )
                .is_err()
        );
        assert!(
            agent
                .collect_registration(
                    &sys_p,
                    &AppleMetalProbe {
                        metal_available: false,
                        ..gpu_p
                    },
                    &tpu_p,
                    &fab_p
                )
                .is_err()
        );
        assert!(
            agent
                .collect_registration(
                    &sys_p,
                    &gpu_p,
                    &GoogleTpuProbe {
                        driver_ready: false,
                        records: Vec::new()
                    },
                    &fab_p
                )
                .is_err()
        );
        assert!(
            agent
                .collect_registration(
                    &sys_p,
                    &gpu_p,
                    &tpu_p,
                    &HighSpeedFabricProbe {
                        probe_healthy: false,
                        nics: Vec::new()
                    }
                )
                .is_err()
        );
        // Topology assembly error (NIC referencing nonexistent NUMA 99)
        assert!(
            agent
                .collect_registration(
                    &sys_p,
                    &gpu_p,
                    &tpu_p,
                    &HighSpeedFabricProbe {
                        probe_healthy: true,
                        nics: vec![FabricNicRecord {
                            name: "mlx5_99".to_owned(),
                            fabric_kind: arbiter_core::resources::RdmaFabricKind::InfiniBand,
                            numa_node_id: 99,
                            speed_gbps: 400,
                            sriov_vfs: 0,
                        }],
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn test_agent_supervisor_launch_preempt_and_telemetry() {
        let aid = AgentId::new("agent-sup-1").unwrap_or_default();
        let key = [0x11_u8; 32];
        let mut agent = AgentSupervisor::new(aid.clone(), Bytes::new(1024), key, 500);

        // Task launch with artifact + secret + isolator pipeline
        let payload = b"binary-content".to_vec();
        let tid = TaskId::new("t-agent-1").unwrap_or_default();
        let task = TaskSpec {
            task_id: tid,
            role: RoleName::new("prod").unwrap_or_default(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionStandard,
            preemption_policy: PreemptionPolicy::CheckpointAndSuspend,
            resources: ResourceBundle {
                cpu: Millicores::new(2000),
                memory: Bytes::new(4096),
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
            artifacts: vec![ArtifactSpec {
                uri: "https://art/1".to_owned(),
                sha256_hex: compute_sha256_hex(&payload),
                extract: false,
                executable: true,
            }],
            secrets: Vec::new(),
            health_check: None,
        };

        let secret = seal_secret(
            SecretId::new("sec-1").unwrap_or_default(),
            &key,
            [2_u8; 12],
            b"secret-val",
        );

        let cmd = LaunchTaskCommand {
            agent_id: aid,
            task,
        };
        let mut pipe = IsolatorPipeline::new();
        pipe.add_stage(Box::new(LinuxNativeIsolator::new(
            MockOsSyscallBackend::default(),
        )));

        assert!(
            agent
                .launch_task(&cmd, &[payload.clone()], &[secret.clone()], &mut pipe)
                .is_ok()
        );

        // Error paths in launch_task: bad artifact, bad secret key, failing isolator
        assert!(
            agent
                .launch_task(&cmd, &[b"wrong-sha".to_vec()], &[], &mut pipe)
                .is_err()
        );
        let bad_secret = seal_secret(
            SecretId::new("sec-1").unwrap_or_default(),
            &[0x99_u8; 32],
            [2_u8; 12],
            b"bad",
        );
        assert!(
            agent
                .launch_task(&cmd, &[payload.clone()], &[bad_secret], &mut pipe)
                .is_err()
        );

        let mut fail_pipe = IsolatorPipeline::new();
        fail_pipe.add_stage(Box::new(LinuxNativeIsolator::new(MockOsSyscallBackend {
            recorded_ops: Vec::new(),
            fail_all: true,
        })));
        assert!(
            agent
                .launch_task(&cmd, &[payload.clone()], &[secret.clone()], &mut fail_pipe)
                .is_err()
        );

        let mut fail_iso_pipe = IsolatorPipeline::new();
        fail_iso_pipe.add_stage(Box::new(LinuxNativeIsolator::new(SubstringFailBackend {
            fail_prefix: "cgroup2.procs",
        })));
        assert!(
            agent
                .launch_task(&cmd, &[payload], &[secret], &mut fail_iso_pipe)
                .is_err()
        );

        // Telemetry report while task is active
        let report = agent.build_telemetry_report(
            TemperatureMilliCelsius::new(40_000),
            PowerMilliwatts::new(150_000),
        );
        assert_eq!(report.allocated_resources.cpu, Millicores::new(2000));
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_agent_supervisor_preempt_and_cleanup() {
        let aid = AgentId::new("agent-sup-1").unwrap_or_default();
        let key = [0x11_u8; 32];
        let mut agent = AgentSupervisor::new(aid.clone(), Bytes::new(1024), key, 500);
        let tid = TaskId::new("t-agent-1").unwrap_or_default();
        let task = TaskSpec {
            task_id: tid.clone(),
            role: RoleName::new("prod").unwrap_or_default(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionStandard,
            preemption_policy: PreemptionPolicy::CheckpointAndSuspend,
            resources: ResourceBundle {
                cpu: Millicores::new(2000),
                memory: Bytes::new(4096),
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
        };
        let cmd = LaunchTaskCommand {
            agent_id: aid.clone(),
            task,
        };
        let mut pipe = IsolatorPipeline::new();
        pipe.add_stage(Box::new(LinuxNativeIsolator::new(
            MockOsSyscallBackend::default(),
        )));
        assert!(agent.launch_task(&cmd, &[], &[], &mut pipe).is_ok());

        // Preempt with failing checkpoint (transitions Running -> Checkpointing)
        let mut fail_chk_pipe = IsolatorPipeline::new();
        fail_chk_pipe.add_stage(Box::new(LinuxNativeIsolator::new(SubstringFailBackend {
            fail_prefix: "criu",
        })));
        assert!(
            agent
                .preempt_task(
                    &PreemptTaskCommand {
                        agent_id: aid.clone(),
                        task_id: tid.clone(),
                        policy: PreemptionPolicy::CheckpointAndSuspend,
                    },
                    &mut fail_chk_pipe,
                )
                .is_err()
        );

        // Preempt with failing cleanup (transitions Checkpointing -> Preempting via GracefulSigterm)
        let mut fail_cln_pipe = IsolatorPipeline::new();
        fail_cln_pipe.add_stage(Box::new(LinuxNativeIsolator::new(SubstringFailBackend {
            fail_prefix: "cgroup2:rmdir+kill",
        })));
        assert!(
            agent
                .preempt_task(
                    &PreemptTaskCommand {
                        agent_id: aid.clone(),
                        task_id: tid.clone(),
                        policy: PreemptionPolicy::GracefulSigterm,
                    },
                    &mut fail_cln_pipe,
                )
                .is_err()
        );

        // Preempt task (ImmediateKill to make it terminal)
        let preempt_cmd = PreemptTaskCommand {
            agent_id: aid.clone(),
            task_id: tid,
            policy: PreemptionPolicy::ImmediateKill,
        };
        assert!(agent.preempt_task(&preempt_cmd, &mut pipe).is_ok());

        // Preempt an already-terminal (Killed) task -> error from handle_preemption_signal
        assert!(agent.preempt_task(&preempt_cmd, &mut pipe).is_err());

        // Telemetry report after task is terminal (Killed)
        let report_after = agent.build_telemetry_report(
            TemperatureMilliCelsius::new(40_000),
            PowerMilliwatts::new(150_000),
        );
        assert_eq!(report_after.allocated_resources.cpu, Millicores::ZERO);

        // Preempt unknown task error
        assert!(
            agent
                .preempt_task(
                    &PreemptTaskCommand {
                        agent_id: aid.clone(),
                        task_id: TaskId::new("ghost").unwrap_or_default(),
                        policy: PreemptionPolicy::ImmediateKill,
                    },
                    &mut pipe,
                )
                .is_err()
        );

        // Mesos v1 ExecutorCall IPC & Agent Checkpoint/Recovery
        let exec_id = ExecutorId::new("exec-rec-1").unwrap_or_default();
        let fw_id = arbiter_core::ids::FrameworkId::new("fw-rec-1").unwrap_or_default();
        let rec_task = TaskSpec {
            task_id: TaskId::new("t-rec-1").unwrap_or_default(),
            role: RoleName::new("prod").unwrap_or_default(),
            framework_id: Some(fw_id.clone()),
            election_group: None,
            priority: PriorityClass::ProductionStandard,
            preemption_policy: PreemptionPolicy::GracefulSigterm,
            resources: ResourceBundle::zero(),
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/rec".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        };
        let uuid = StatusUpdateUuid::new("uuid-rec-1").unwrap_or_default();
        let upd = TaskStatusUpdate {
            task_id: rec_task.task_id.clone(),
            agent_id: aid.clone(),
            state: arbiter_core::workload::TaskState::Running,
            message: "reconnected".to_owned(),
        };
        assert!(
            agent
                .handle_executor_call(ExecutorCall::Subscribe(
                    fw_id.clone(),
                    exec_id.clone(),
                    vec![rec_task.clone()],
                    vec![(uuid.clone(), upd.clone())],
                ))
                .is_ok()
        );
        // Second Subscribe with existing task exercises `or_insert_with` already-occupied branch
        assert!(
            agent
                .handle_executor_call(ExecutorCall::Subscribe(
                    fw_id.clone(),
                    exec_id.clone(),
                    vec![rec_task],
                    Vec::new(),
                ))
                .is_ok()
        );
        assert!(
            agent
                .handle_executor_call(ExecutorCall::Update(exec_id.clone(), upd, uuid.clone()))
                .is_ok()
        );
        assert!(
            agent
                .handle_executor_call(ExecutorCall::Update(
                    exec_id.clone(),
                    TaskStatusUpdate {
                        task_id: TaskId::new("ghost-t").unwrap_or_default(),
                        agent_id: aid.clone(),
                        state: arbiter_core::workload::TaskState::Running,
                        message: "bad".to_owned(),
                    },
                    uuid,
                ))
                .is_err()
        );
        assert!(
            agent
                .handle_executor_call(ExecutorCall::Message(fw_id, exec_id, vec![1, 2, 3]))
                .is_ok()
        );

        let ckpt_json = agent.checkpoint_state_json();
        let mut recovered_agent = AgentSupervisor::new(aid, Bytes::new(1024), key, 500);
        assert_eq!(
            recovered_agent.recover_from_checkpoint_json(&ckpt_json),
            Ok(2)
        );
        assert!(
            recovered_agent
                .recover_from_checkpoint_json("{invalid")
                .is_err()
        );
        for ex in recovered_agent.executors.values_mut() {
            for _ in 0..70 {
                ex.logs.push_line("overflow".to_owned());
            }
        }

        // Exercise all AgentOperatorCall variants and error branches
        let parent_cid = ContainerId::new("container-t-rec-1").unwrap_or_default();
        let nested_cid = ContainerId::new("container-t-rec-1.debug").unwrap_or_default();
        assert_eq!(
            recovered_agent.handle_agent_operator_call(
                AgentOperatorCall::LaunchNestedContainerSession(
                    parent_cid.clone(),
                    nested_cid.clone(),
                    "/bin/sh".to_owned(),
                    vec!["-i".to_owned()],
                )
            ),
            Ok(AgentOperatorResponse::Ok(
                "nested container launched".to_owned()
            ))
        );
        // Duplicate nested container ID rejected
        assert!(
            recovered_agent
                .handle_agent_operator_call(AgentOperatorCall::LaunchNestedContainer(
                    parent_cid,
                    nested_cid.clone(),
                    "/bin/sh".to_owned(),
                    Vec::new(),
                    Vec::new(),
                    ResourceBundle::zero(),
                ))
                .is_err()
        );
        // Attach input and read output
        assert_eq!(
            recovered_agent.handle_agent_operator_call(AgentOperatorCall::AttachContainerInput(
                nested_cid.clone(),
                b"echo hi\n".to_vec(),
            )),
            Ok(AgentOperatorResponse::Ok(
                "container input attached".to_owned()
            ))
        );
        let out_res = recovered_agent.handle_agent_operator_call(
            AgentOperatorCall::AttachContainerOutput(nested_cid.clone()),
        );
        assert!(out_res.is_ok());
        // Wait while running returns default SUCCESS
        assert_eq!(
            recovered_agent.handle_agent_operator_call(AgentOperatorCall::WaitNestedContainer(
                nested_cid.clone()
            )),
            Ok(AgentOperatorResponse::NestedContainerWaitResult(
                nested_cid.clone(),
                ExitCode::SUCCESS
            ))
        );
        // GetContainers returns top-level running + top-level terminal + nested container
        let containers_res =
            recovered_agent.handle_agent_operator_call(AgentOperatorCall::GetContainers);
        assert!(containers_res.is_ok());
        // Kill nested container and wait again
        assert!(
            recovered_agent
                .handle_agent_operator_call(AgentOperatorCall::KillNestedContainer(
                    nested_cid.clone(),
                    arbiter_core::units::SignalNumber::SIGTERM,
                ))
                .is_ok()
        );
        assert_eq!(
            recovered_agent.handle_agent_operator_call(AgentOperatorCall::WaitNestedContainer(
                nested_cid.clone()
            )),
            Ok(AgentOperatorResponse::NestedContainerWaitResult(
                nested_cid.clone(),
                ExitCode::new(143)
            ))
        );
        // Remove nested container
        assert!(
            recovered_agent
                .handle_agent_operator_call(AgentOperatorCall::RemoveNestedContainer(
                    nested_cid.clone()
                ))
                .is_ok()
        );
        // Error branches for unknown nested container IDs
        assert!(
            recovered_agent
                .handle_agent_operator_call(AgentOperatorCall::WaitNestedContainer(
                    nested_cid.clone()
                ))
                .is_err()
        );
        assert!(
            recovered_agent
                .handle_agent_operator_call(AgentOperatorCall::KillNestedContainer(
                    nested_cid.clone(),
                    arbiter_core::units::SignalNumber::SIGKILL,
                ))
                .is_err()
        );
        assert!(
            recovered_agent
                .handle_agent_operator_call(AgentOperatorCall::RemoveNestedContainer(
                    nested_cid.clone()
                ))
                .is_err()
        );
        assert!(
            recovered_agent
                .handle_agent_operator_call(AgentOperatorCall::AttachContainerInput(
                    nested_cid.clone(),
                    b"x".to_vec(),
                ))
                .is_err()
        );
        assert!(
            recovered_agent
                .handle_agent_operator_call(AgentOperatorCall::AttachContainerOutput(nested_cid))
                .is_err()
        );
        // PruneImages with non-empty exclusion list vs empty exclusion list
        assert_eq!(
            recovered_agent.handle_agent_operator_call(AgentOperatorCall::PruneImages(vec![
                "keep:v1".to_owned()
            ])),
            Ok(AgentOperatorResponse::ImagesPruned(0, Bytes::ZERO))
        );
        assert_eq!(
            recovered_agent.handle_agent_operator_call(AgentOperatorCall::PruneImages(Vec::new())),
            Ok(AgentOperatorResponse::ImagesPruned(0, Bytes::ZERO))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_resource_estimator_and_qos_controller() {
        let aid = AgentId::new("agent-qos-1").unwrap_or_default();
        let key = [0x22_u8; 32];
        let mut agent = AgentSupervisor::new(aid.clone(), Bytes::new(1024), key, 500);
        agent.resource_estimator = ResourceEstimator::new(
            WeightBasisPoints::new(1_000).unwrap_or(WeightBasisPoints::STANDARD),
        );
        agent.qos_controller = QoSController::new(2_500, 3_000, 2_000);

        let mut pipe = IsolatorPipeline::new();
        pipe.add_stage(Box::new(LinuxNativeIsolator::new(
            MockOsSyscallBackend::default(),
        )));

        let prod_tid = TaskId::new("t-prod-1").unwrap_or_default();
        let batch_tid = TaskId::new("t-batch-1").unwrap_or_default();
        let rev_tid = TaskId::new("t-rev-1").unwrap_or_default();
        let make_task = |tid: TaskId, prio: PriorityClass, cpu_m: u64, mem_b: u64| TaskSpec {
            task_id: tid,
            role: RoleName::new("prod").unwrap_or_default(),
            framework_id: None,
            election_group: None,
            priority: prio,
            preemption_policy: PreemptionPolicy::ImmediateKill,
            resources: ResourceBundle {
                cpu: Millicores::new(cpu_m),
                memory: Bytes::new(mem_b),
                gpu_compute: GpuMillicores::new(1_000),
                gpu_vram: Bytes::new(10_000),
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
        };

        for t in [
            make_task(
                prod_tid.clone(),
                PriorityClass::ProductionHigh,
                10_000,
                10_000,
            ),
            make_task(batch_tid.clone(), PriorityClass::Batch, 2_000, 2_000),
            make_task(rev_tid, PriorityClass::Revocable, 4_000, 4_000),
        ] {
            let _ = agent.launch_task(
                &LaunchTaskCommand {
                    agent_id: aid.clone(),
                    task: t,
                },
                &[],
                &[],
                &mut pipe,
            );
        }

        // Allocated non-revocable = 12_000m CPU, 12_000B mem, 2_000gm GPU, 20_000B VRAM.
        // Actual usage = 2_000m CPU, 2_000B mem, 1_000gm GPU, 10_000B VRAM.
        // Raw slack = 10_000m CPU, 10_000B mem, 1_000gm GPU, 10_000B VRAM; after 10% headroom = 90%.
        let slack = agent.estimate_revocable_resources(&ResourceBundle {
            cpu: Millicores::new(2_000),
            memory: Bytes::new(2_000),
            gpu_compute: GpuMillicores::new(1_000),
            gpu_vram: Bytes::new(10_000),
            ..ResourceBundle::zero()
        });
        assert_eq!(slack.cpu, Millicores::new(9_000));
        assert_eq!(slack.memory, Bytes::new(9_000));
        assert_eq!(slack.gpu_compute, GpuMillicores::new(900));
        assert_eq!(slack.gpu_vram, Bytes::new(9_000));

        // Healthy samples + unknown task + non-latency-sensitive batch task -> no eviction
        let healthy_samples = vec![
            QoSTelemetrySample {
                task_id: TaskId::new("ghost").unwrap_or_default(),
                cpi_milli: 9_999,
                mem_stall_basis_points: 9_999,
                psi_pressure_basis_points: 9_999,
            },
            QoSTelemetrySample {
                task_id: batch_tid,
                cpi_milli: 9_999,
                mem_stall_basis_points: 9_999,
                psi_pressure_basis_points: 9_999,
            },
            QoSTelemetrySample {
                task_id: prod_tid.clone(),
                cpi_milli: 1_500,
                mem_stall_basis_points: 1_000,
                psi_pressure_basis_points: 500,
            },
        ];
        assert_eq!(
            agent.run_qos_correction_cycle(&healthy_samples, &mut pipe),
            Ok(Vec::new())
        );

        // Verify all 3 QoS degradation triggers (CPI, mem_stall, PSI)
        assert!(agent.qos_controller.is_degraded(&QoSTelemetrySample {
            task_id: prod_tid.clone(),
            cpi_milli: 3_000,
            mem_stall_basis_points: 0,
            psi_pressure_basis_points: 0,
        }));
        assert!(agent.qos_controller.is_degraded(&QoSTelemetrySample {
            task_id: prod_tid.clone(),
            cpi_milli: 1_000,
            mem_stall_basis_points: 4_000,
            psi_pressure_basis_points: 0,
        }));
        assert!(agent.qos_controller.is_degraded(&QoSTelemetrySample {
            task_id: prod_tid.clone(),
            cpi_milli: 1_000,
            mem_stall_basis_points: 1_000,
            psi_pressure_basis_points: 3_000,
        }));

        // Degraded production sample with failing isolator cleanup propagates error
        let mut fail_cln_pipe = IsolatorPipeline::new();
        fail_cln_pipe.add_stage(Box::new(LinuxNativeIsolator::new(SubstringFailBackend {
            fail_prefix: "cgroup2:rmdir+kill",
        })));
        let degraded = vec![QoSTelemetrySample {
            task_id: prod_tid.clone(),
            cpi_milli: 3_000,
            mem_stall_basis_points: 1_000,
            psi_pressure_basis_points: 500,
        }];
        assert!(
            agent
                .run_qos_correction_cycle(&degraded, &mut fail_cln_pipe)
                .is_err()
        );

        // Re-launch another revocable task and evict cleanly
        let rev_tid2 = TaskId::new("t-rev-2").unwrap_or_default();
        let _ = agent.launch_task(
            &LaunchTaskCommand {
                agent_id: aid,
                task: make_task(rev_tid2.clone(), PriorityClass::Revocable, 2_000, 2_000),
            },
            &[],
            &[],
            &mut pipe,
        );
        let evicted = agent
            .run_qos_correction_cycle(&degraded, &mut pipe)
            .unwrap_or_default();
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted.first().map(|u| &u.task_id), Some(&rev_tid2));

        // Terminal production task does not trigger QoS eviction
        for (_, ex) in agent
            .executors
            .iter_mut()
            .filter(|(id, _)| *id == &prod_tid)
        {
            ex.state = arbiter_core::workload::TaskState::Finished;
        }
        assert_eq!(
            agent.run_qos_correction_cycle(&degraded, &mut pipe),
            Ok(Vec::new())
        );

        // Test write_checkpoint_directory and recover_from_checkpoint_directory (same boot_id vs reboot)
        let ckpt_dir = std::env::temp_dir().join("arbiter_agent_ckpt_dir_test");
        let _ = std::fs::remove_dir_all(&ckpt_dir);
        assert_eq!(
            agent.write_checkpoint_directory(&ckpt_dir, "boot-uuid-1"),
            Ok(4)
        );
        let mut recovered_same_boot = AgentSupervisor::new(
            AgentId::new("agent-ckpt-rec").unwrap_or_default(),
            Bytes::new(1024),
            [0x11_u8; 32],
            500,
        );
        assert_eq!(
            recovered_same_boot.recover_from_checkpoint_directory(&ckpt_dir, "boot-uuid-1"),
            Ok(4)
        );
        let mut recovered_reboot = AgentSupervisor::new(
            AgentId::new("agent-ckpt-reboot").unwrap_or_default(),
            Bytes::new(1024),
            [0x11_u8; 32],
            500,
        );
        assert_eq!(
            recovered_reboot.recover_from_checkpoint_directory(&ckpt_dir, "boot-uuid-2"),
            Ok(4)
        );
        assert!(!recovered_reboot.pending_status_updates.is_empty());

        // Error branches for write_checkpoint_directory and recover_from_checkpoint_directory
        assert!(
            agent
                .write_checkpoint_directory(
                    std::path::Path::new("/dev/null/bad_ckpt_dir"),
                    "boot-1"
                )
                .is_err()
        );
        let ro_boot_dir = ckpt_dir.join("boot_id.tmp");
        let _ = std::fs::create_dir_all(&ro_boot_dir);
        assert!(
            agent
                .write_checkpoint_directory(&ckpt_dir, "boot-1")
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&ro_boot_dir);

        let ro_snap_dir = ckpt_dir.join("agent.info.tmp");
        let _ = std::fs::create_dir_all(&ro_snap_dir);
        assert!(
            agent
                .write_checkpoint_directory(&ckpt_dir, "boot-1")
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&ro_snap_dir);

        let _ = std::fs::write(ckpt_dir.join("agent.info"), "{bad_json");
        assert!(
            recovered_same_boot
                .recover_from_checkpoint_directory(&ckpt_dir, "boot-uuid-1")
                .is_err()
        );
        let _ = std::fs::remove_file(ckpt_dir.join("agent.info"));
        assert!(
            recovered_same_boot
                .recover_from_checkpoint_directory(&ckpt_dir, "boot-uuid-1")
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&ckpt_dir);
        assert!(
            recovered_same_boot
                .recover_from_checkpoint_directory(&ckpt_dir, "boot-uuid-1")
                .is_err()
        );
    }

    fn sample_task(id: &str) -> TaskSpec {
        TaskSpec {
            task_id: TaskId::new(id).unwrap_or_default(),
            role: RoleName::new("prod").unwrap_or_default(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionStandard,
            preemption_policy: PreemptionPolicy::GracefulSigterm,
            resources: ResourceBundle {
                cpu: Millicores::new(1000),
                memory: Bytes::new(2048),
                ..ResourceBundle::zero()
            },
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/sh".to_owned(),
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
    fn test_agent_fetcher_and_sandbox_files() {
        let aid = AgentId::new("agent-wire-1").unwrap_or_default();
        let mut agent = AgentSupervisor::new(aid, Bytes::new(65_536), [0x22_u8; 32], 500);
        let tar_bytes = arbiter_storage::SandboxMaterializer::encode_ustar_archive(&[(
            "bin/run.sh",
            b"echo 1",
        )]);
        let raw_bytes = b"hello-world-sandbox".to_vec();
        let sbox_dir =
            std::env::temp_dir().join(format!("arbiter_agent_sbox_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sbox_dir);
        let _ = std::fs::create_dir_all(&sbox_dir);
        let tar_file = sbox_dir.join("bundle.tar");
        let raw_file = sbox_dir.join("readme.txt");
        let bad_tar_file = sbox_dir.join("corrupt.tar");
        let _ = std::fs::write(&tar_file, &tar_bytes);
        let _ = std::fs::write(&raw_file, &raw_bytes);
        let _ = std::fs::write(&bad_tar_file, b"not-512-byte-tar");

        let mut task = sample_task("t-wire-1");
        task.artifacts = vec![
            ArtifactSpec {
                uri: format!("file://{}", tar_file.display()),
                sha256_hex: compute_sha256_hex(&tar_bytes),
                extract: true,
                executable: true,
            },
            ArtifactSpec {
                uri: format!("file://{}", raw_file.display()),
                sha256_hex: compute_sha256_hex(&raw_bytes),
                extract: false,
                executable: false,
            },
        ];

        let storage = arbiter_storage::LiveOsStorageBackend::default();
        let sbox_str = sbox_dir.to_string_lossy();
        let fetched = agent
            .fetch_and_materialize_task_artifacts(&task, &storage, sbox_str.as_ref())
            .unwrap_or_default();
        assert_eq!(fetched.len(), 2);

        for bad_art in [
            ArtifactSpec {
                uri: "file:///nonexistent/missing.bin".to_owned(),
                sha256_hex: compute_sha256_hex(b"x"),
                extract: false,
                executable: false,
            },
            ArtifactSpec {
                uri: format!("file://{}", raw_file.display()),
                sha256_hex: "00".repeat(32),
                extract: false,
                executable: false,
            },
            ArtifactSpec {
                uri: format!("file://{}", bad_tar_file.display()),
                sha256_hex: compute_sha256_hex(b"not-512-byte-tar"),
                extract: true,
                executable: false,
            },
        ] {
            let mut bad_t = task.clone();
            bad_t.artifacts = vec![bad_art];
            assert!(
                agent
                    .fetch_and_materialize_task_artifacts(&bad_t, &storage, sbox_str.as_ref())
                    .is_err()
            );
        }

        let root_sp = arbiter_core::ids::SandboxPath::new("/").unwrap_or_default();
        let sub_sp = arbiter_core::ids::SandboxPath::new("t-wire-1").unwrap_or_default();
        let missing_sp = arbiter_core::ids::SandboxPath::new("missing_dir").unwrap_or_default();
        assert!(
            !AgentSupervisor::browse_sandbox_directory(&sbox_dir, &root_sp)
                .unwrap_or_default()
                .is_empty()
        );
        assert!(
            !AgentSupervisor::browse_sandbox_directory(&sbox_dir, &sub_sp)
                .unwrap_or_default()
                .is_empty()
        );
        assert!(AgentSupervisor::browse_sandbox_directory(&sbox_dir, &missing_sp).is_err());

        let file_sp =
            arbiter_core::ids::SandboxPath::new("t-wire-1/readme.txt").unwrap_or_default();
        let (_, chunk_str) = AgentSupervisor::read_sandbox_file_chunk(
            &sbox_dir,
            &file_sp,
            arbiter_core::units::FileReadOffset::new(0),
            arbiter_core::units::FileReadLength::new(5),
        )
        .unwrap_or_default();
        assert_eq!(chunk_str, "hello");
        assert!(
            AgentSupervisor::read_sandbox_file_chunk(
                &sbox_dir,
                &missing_sp,
                arbiter_core::units::FileReadOffset::new(0),
                arbiter_core::units::FileReadLength::new(5),
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&sbox_dir);
    }

    #[test]
    fn test_agent_handle_master_wire_message() {
        let aid = AgentId::new("agent-wire-2").unwrap_or_default();
        let mut agent = AgentSupervisor::new(aid.clone(), Bytes::new(65_536), [0x22_u8; 32], 500);
        let mut pipe = IsolatorPipeline::new();
        pipe.add_stage(Box::new(LinuxNativeIsolator::new(
            MockOsSyscallBackend::default(),
        )));
        let mut fail_pipe = IsolatorPipeline::new();
        fail_pipe.add_stage(Box::new(LinuxNativeIsolator::new(MockOsSyscallBackend {
            recorded_ops: Vec::new(),
            fail_all: true,
        })));
        let launch_task = sample_task("t-wire-1");
        let tid = launch_task.task_id.clone();
        let launch_msg =
            arbiter_proto::WireMessage::LaunchTaskCommand(Box::new(LaunchTaskCommand {
                agent_id: aid.clone(),
                task: launch_task,
            }));
        assert!(
            agent
                .handle_master_wire_message(&launch_msg, &mut pipe)
                .is_ok()
        );
        assert!(
            agent
                .handle_master_wire_message(&launch_msg, &mut fail_pipe)
                .is_err()
        );

        let preempt_msg = arbiter_proto::WireMessage::PreemptTaskCommand(PreemptTaskCommand {
            agent_id: aid.clone(),
            task_id: tid.clone(),
            policy: PreemptionPolicy::GracefulSigterm,
        });
        assert!(
            agent
                .handle_master_wire_message(&preempt_msg, &mut pipe)
                .is_ok()
        );
        assert!(
            agent
                .handle_master_wire_message(&preempt_msg, &mut fail_pipe)
                .is_err()
        );

        let kill_msg = arbiter_proto::WireMessage::ExecutorEvent(Box::new(
            arbiter_proto::ExecutorEvent::Kill(tid, None),
        ));
        assert!(
            agent
                .handle_master_wire_message(&kill_msg, &mut pipe)
                .is_ok()
        );
        assert!(
            agent
                .handle_master_wire_message(&kill_msg, &mut pipe)
                .is_err()
        );

        let _ = agent.handle_master_wire_message(
            &arbiter_proto::WireMessage::LaunchTaskCommand(Box::new(LaunchTaskCommand {
                agent_id: aid,
                task: sample_task("t-wire-2"),
            })),
            &mut pipe,
        );
        let fence_msg = arbiter_proto::WireMessage::ExecutorEvent(Box::new(
            arbiter_proto::ExecutorEvent::Shutdown(arbiter_core::units::BenchmarkTicks::new(5)),
        ));
        assert_eq!(
            agent.handle_master_wire_message(&fence_msg, &mut pipe),
            Ok(None)
        );

        for bad_msg in [
            arbiter_proto::WireMessage::ExecutorEvent(Box::new(
                arbiter_proto::ExecutorEvent::Error("err".to_owned()),
            )),
            arbiter_proto::WireMessage::SchedulerEvent(Box::new(
                arbiter_proto::SchedulerEvent::Heartbeat,
            )),
        ] {
            assert!(
                agent
                    .handle_master_wire_message(&bad_msg, &mut pipe)
                    .is_err()
            );
        }
    }

    #[test]
    fn test_agent_psi_and_executor_recordio_payload() {
        let aid = AgentId::new("agent-wire-2").unwrap_or_default();
        let mut agent = AgentSupervisor::new(aid, Bytes::new(65_536), [0x22_u8; 32], 500);

        // Test parse_linux_psi_pressure_basis_points
        assert_eq!(
            AgentSupervisor::parse_linux_psi_pressure_basis_points(
                "some avg10=12.34 avg60=5.00 avg300=1.00 total=1000"
            ),
            Ok(1_234)
        );
        assert!(
            AgentSupervisor::parse_linux_psi_pressure_basis_points("some avg10=bad.34").is_err()
        );
        assert!(
            AgentSupervisor::parse_linux_psi_pressure_basis_points("some avg10=12.bad").is_err()
        );
        assert!(AgentSupervisor::parse_linux_psi_pressure_basis_points("some total=100").is_err());

        // Test process_executor_http_recordio_payload
        let fw_id = arbiter_core::ids::FrameworkId::new("fw-rec-1").unwrap_or_default();
        let ex_id = arbiter_core::ids::ExecutorId::new("ex-rec-1").unwrap_or_default();
        let sub_json = serde_json::to_vec(&ExecutorCall::Subscribe(
            fw_id.clone(),
            ex_id.clone(),
            Vec::new(),
            Vec::new(),
        ))
        .unwrap_or_default();
        let msg_json = serde_json::to_vec(&ExecutorCall::Message(fw_id, ex_id.clone(), vec![1, 2]))
            .unwrap_or_default();
        assert_eq!(
            agent.handle_executor_call(ExecutorCall::Heartbeat(ex_id.clone())),
            Ok(ExecutorEvent::Heartbeat)
        );
        let mut valid_recordio = Vec::new();
        valid_recordio.extend_from_slice(format!("{}\n", sub_json.len()).as_bytes());
        valid_recordio.extend_from_slice(&sub_json);
        valid_recordio.extend_from_slice(format!("{}\n", msg_json.len()).as_bytes());
        valid_recordio.extend_from_slice(&msg_json);

        let resp_bytes = agent
            .process_executor_http_recordio_payload(&valid_recordio)
            .unwrap_or_default();
        assert!(!resp_bytes.is_empty());

        // Error branches in process_executor_http_recordio_payload
        assert!(
            agent
                .process_executor_http_recordio_payload(b"no-newline")
                .is_err()
        );
        assert!(
            agent
                .process_executor_http_recordio_payload(b"abc\n{}")
                .is_err()
        );
        assert!(
            agent
                .process_executor_http_recordio_payload(b"99\n{}")
                .is_err()
        );
        assert!(
            agent
                .process_executor_http_recordio_payload(b"2\n{x")
                .is_err()
        );
        let ghost_upd_json = serde_json::to_vec(&ExecutorCall::Update(
            ex_id,
            TaskStatusUpdate {
                task_id: TaskId::new("ghost-rec").unwrap_or_default(),
                agent_id: AgentId::new("agent-sup-1").unwrap_or_default(),
                state: arbiter_core::workload::TaskState::Running,
                message: "ok".to_owned(),
            },
            StatusUpdateUuid::new("uuid-ghost").unwrap_or_default(),
        ))
        .unwrap_or_default();
        let mut err_recordio = format!("{}\n", ghost_upd_json.len()).into_bytes();
        err_recordio.extend_from_slice(&ghost_upd_json);
        assert!(
            agent
                .process_executor_http_recordio_payload(&err_recordio)
                .is_err()
        );
    }

    #[test]
    fn test_agent_status_update_ack_and_sandbox_gc() {
        let aid = AgentId::new("agent-gc").unwrap_or_default();
        let mut agent = AgentSupervisor::new(aid, Bytes::new(65_536), [0x22_u8; 32], 500);
        let u1 = StatusUpdateUuid::new("uuid-gc-1").unwrap_or_default();
        let t_gc1 = TaskId::new("t-gc-1").unwrap_or_default();
        let t_gc2 = TaskId::new("t-gc-2").unwrap_or_default();
        agent.pending_status_updates.insert(
            u1.clone(),
            TaskStatusUpdate {
                task_id: t_gc1.clone(),
                agent_id: agent.agent_id.clone(),
                state: arbiter_core::workload::TaskState::Finished,
                message: "done".to_owned(),
            },
        );
        assert_eq!(agent.pending_status_update_batch().len(), 1);
        assert!(agent.acknowledge_status_update(&u1).is_some());
        assert!(agent.acknowledge_status_update(&u1).is_none());

        let mut ex1 = TaskExecutor::new(
            ExecutorId::new("ex-gc-1").unwrap_or_default(),
            agent.agent_id.clone(),
            sample_task("t-gc-1"),
            16,
        );
        ex1.state = arbiter_core::workload::TaskState::Finished;
        let mut ex2 = TaskExecutor::new(
            ExecutorId::new("ex-gc-2").unwrap_or_default(),
            agent.agent_id.clone(),
            sample_task("t-gc-2"),
            16,
        );
        ex2.state = arbiter_core::workload::TaskState::Failed;
        agent.executors.insert(t_gc1.clone(), ex1);
        agent.executors.insert(t_gc2, ex2);

        let gc_dir = std::env::temp_dir().join("arbiter_agent_gc_test");
        let _ = std::fs::create_dir_all(gc_dir.join("t-gc-1"));
        assert!(
            agent
                .garbage_collect_completed_sandboxes(&gc_dir, 5)
                .is_empty()
        );
        let evicted = agent.garbage_collect_completed_sandboxes(&gc_dir, 1);
        assert_eq!(evicted, vec![t_gc1]);
        let _ = std::fs::remove_dir_all(&gc_dir);
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_phase10_uds_reconnect_reregister_gc_and_psi_qos() {
        use std::io::Write;

        let aid = AgentId::new("agent-p10").unwrap_or_default();
        let mut agent = AgentSupervisor::new(aid.clone(), Bytes::new(65_536), [0x33_u8; 32], 500);
        let fw_id = arbiter_core::ids::FrameworkId::new("fw-p10").unwrap_or_default();
        let ex_id = ExecutorId::new("ex-p10-1").unwrap_or_default();
        agent
            .registered_frameworks
            .insert(fw_id.clone(), "principal-p10".to_owned());
        agent.executor_pids.insert(
            ex_id.clone(),
            arbiter_core::ids::OsProcessId::new(4242).unwrap_or_default(),
        );

        // 1. Live Unix Domain Socket executor reconnection
        let uds_path =
            std::env::temp_dir().join(format!("arbiter_exec_reconn_{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&uds_path);
        let listener = std::os::unix::net::UnixListener::bind(&uds_path).ok();
        let uds_str = uds_path.to_string_lossy().into_owned();
        agent.executor_sockets.insert(ex_id.clone(), uds_str);

        let mut t_fw = sample_task("t-p10-fw");
        t_fw.framework_id = Some(fw_id.clone());
        let sub_call = ExecutorCall::Subscribe(
            fw_id,
            ex_id.clone(),
            vec![t_fw],
            vec![(
                StatusUpdateUuid::new("u-p10-1").unwrap_or_default(),
                TaskStatusUpdate {
                    task_id: TaskId::new("t-p10-fw").unwrap_or_default(),
                    agent_id: aid.clone(),
                    state: arbiter_core::workload::TaskState::Running,
                    message: "running".to_owned(),
                },
            )],
        );
        let sub_json = serde_json::to_vec(&sub_call).unwrap_or_default();
        let rio_frame = format!("{}\n", sub_json.len());
        let srv_thread = std::thread::spawn(move || {
            let _ = listener
                .as_ref()
                .and_then(|l| l.accept().ok())
                .map(|(mut s, _)| {
                    let _ = s.write_all(rio_frame.as_bytes());
                    let _ = s.write_all(&sub_json);
                    let _ = s.shutdown(std::net::Shutdown::Write);
                });
        });
        let reconn = agent.reconnect_executor_unix_sockets().unwrap_or_default();
        let _ = srv_thread.join();
        assert_eq!(reconn.len(), 1);
        let _ = std::fs::remove_file(&uds_path);

        // Missing UDS socket error branch & malformed RecordIO error branch
        assert!(agent.reconnect_executor_unix_sockets().is_err());
        let bad_uds_path = std::env::temp_dir().join(format!(
            "arbiter_exec_bad_reconn_{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&bad_uds_path);
        let bad_listener = std::os::unix::net::UnixListener::bind(&bad_uds_path).ok();
        agent
            .executor_sockets
            .insert(ex_id, bad_uds_path.to_string_lossy().into_owned());
        let bad_srv = std::thread::spawn(move || {
            let _ = bad_listener
                .as_ref()
                .and_then(|l| l.accept().ok())
                .map(|(mut s, _)| {
                    let _ = s.write_all(b"invalid-recordio");
                    let _ = s.shutdown(std::net::Shutdown::Write);
                });
        });
        assert!(agent.reconnect_executor_unix_sockets().is_err());
        let _ = bad_srv.join();
        let _ = std::fs::remove_file(&bad_uds_path);

        // 2. build_reregister_agent_payload with framework-owned, non-framework, and terminal tasks
        let t_nofw = sample_task("t-p10-nofw");
        let mut ex_nofw = TaskExecutor::new(
            ExecutorId::new("ex-nofw").unwrap_or_default(),
            aid.clone(),
            t_nofw,
            16,
        );
        ex_nofw.state = arbiter_core::workload::TaskState::Running;
        agent
            .executors
            .insert(TaskId::new("t-p10-nofw").unwrap_or_default(), ex_nofw);

        let mut ex_done = TaskExecutor::new(
            ExecutorId::new("ex-done").unwrap_or_default(),
            aid.clone(),
            sample_task("t-p10-done"),
            16,
        );
        ex_done.state = arbiter_core::workload::TaskState::Finished;
        agent
            .executors
            .insert(TaskId::new("t-p10-done").unwrap_or_default(), ex_done);
        agent.pending_status_updates.insert(
            StatusUpdateUuid::new("u-p10-orphan").unwrap_or_default(),
            TaskStatusUpdate {
                task_id: TaskId::new("t-p10-orphan").unwrap_or_default(),
                agent_id: aid.clone(),
                state: arbiter_core::workload::TaskState::Failed,
                message: "orphan".to_owned(),
            },
        );
        let base_reg = RegisterAgent {
            agent_id: aid.clone(),
            os_kind: arbiter_core::platform::OsKind::Linux,
            cpu_arch: arbiter_core::platform::CpuArch::X86_64,
            total_resources: ResourceBundle::zero(),
            topology: arbiter_core::topology::HardwareTopologyGraph::default(),
        };
        let rereg = agent.build_reregister_agent_payload(base_reg);
        assert_eq!(rereg.running_tasks.len(), 2);
        assert_eq!(rereg.active_executors.len(), 2);
        assert_eq!(rereg.unacknowledged_updates.len(), 2);

        // 3. gc_sandboxes (TTL expiration + disk watermark threshold)
        let policy = SandboxGcPolicy {
            retention_ttl_ticks: 100,
            max_retained_completed: 2,
            ..SandboxGcPolicy::default()
        };
        let mut ex_ttl = TaskExecutor::new(
            ExecutorId::new("ex-ttl").unwrap_or_default(),
            aid.clone(),
            sample_task("t-p10-ttl"),
            16,
        );
        ex_ttl.state = arbiter_core::workload::TaskState::Finished;
        let tid_ttl = TaskId::new("t-p10-ttl").unwrap_or_default();
        let tid_done = TaskId::new("t-p10-done").unwrap_or_default();
        agent.executors.insert(tid_ttl.clone(), ex_ttl);
        agent.completed_task_timestamps.insert(tid_ttl.clone(), 10);
        agent
            .completed_task_timestamps
            .insert(tid_done.clone(), 180);

        let gc_dir = std::env::temp_dir().join(format!("arbiter_gc_p10_{}", std::process::id()));
        // Below watermark: only TTL-expired task is evicted
        let pruned_by_ttl =
            agent.gc_sandboxes(&gc_dir, 200, Bytes::new(500), Bytes::new(1_000), &policy);
        assert_eq!(pruned_by_ttl, vec![tid_ttl]);
        // Above high watermark (90% >= 85%): remaining completed task is evicted immediately
        let ev_wm = agent.gc_sandboxes(&gc_dir, 200, Bytes::new(900), Bytes::new(1_000), &policy);
        assert_eq!(ev_wm, vec![tid_done]);
        // Zero total disk bytes branch
        assert!(
            agent
                .gc_sandboxes(&gc_dir, 200, Bytes::ZERO, Bytes::ZERO, &policy)
                .is_empty()
        );

        // 4. poll_psi_and_enforce_qos
        let psi_dir = std::env::temp_dir().join(format!("arbiter_psi_p10_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&psi_dir);
        let _ = std::fs::create_dir_all(&psi_dir);
        let _ = std::fs::write(psi_dir.join("cpu"), "some avg10=5.00 avg60=1.00\n");
        let _ = std::fs::write(psi_dir.join("memory"), "some avg10=8.00 avg60=2.00\n");
        let mut pipe = IsolatorPipeline::new();
        pipe.add_stage(Box::new(LinuxNativeIsolator::new(
            MockOsSyscallBackend::default(),
        )));

        let mut rev_task = sample_task("t-p10-rev");
        rev_task.priority = PriorityClass::Revocable;
        let _ = agent.launch_task(
            &LaunchTaskCommand {
                agent_id: aid,
                task: rev_task,
            },
            &[],
            &[],
            &mut pipe,
        );

        // Low PSI (800 bps <= 2000 bps) -> returns slack resources and 0 evictions
        let (slack_ok, ev_ok) = agent
            .poll_psi_and_enforce_qos(
                &psi_dir,
                &ResourceBundle::zero(),
                &[QoSTelemetrySample {
                    task_id: TaskId::new("t-p10-fw").unwrap_or_default(),
                    cpi_milli: 1_000,
                    mem_stall_basis_points: 500,
                    psi_pressure_basis_points: 100,
                }],
                &mut pipe,
            )
            .unwrap_or_default();
        assert!(ev_ok.is_empty());
        assert_eq!(slack_ok.cpu, Millicores::new(1_800));

        // High PSI (45.00% = 4500 bps > 2000 bps) with empty hardware_samples -> evicts revocable task
        let _ = std::fs::write(psi_dir.join("memory"), "some avg10=45.00 avg60=10.00\n");
        let (slack_spike, ev_spike) = agent
            .poll_psi_and_enforce_qos(&psi_dir, &ResourceBundle::zero(), &[], &mut pipe)
            .unwrap_or_default();
        assert_eq!(slack_spike, ResourceBundle::zero());
        assert_eq!(ev_spike.len(), 1);

        // Failing isolator cleanup on QoS eviction propagates error
        let mut fail_pipe = IsolatorPipeline::new();
        fail_pipe.add_stage(Box::new(LinuxNativeIsolator::new(SubstringFailBackend {
            fail_prefix: "cgroup2:rmdir+kill",
        })));
        let mut rev_task2 = sample_task("t-p10-rev2");
        rev_task2.priority = PriorityClass::Revocable;
        let _ = agent.launch_task(
            &LaunchTaskCommand {
                agent_id: agent.agent_id.clone(),
                task: rev_task2,
            },
            &[],
            &[],
            &mut pipe,
        );
        assert!(
            agent
                .poll_psi_and_enforce_qos(&psi_dir, &ResourceBundle::zero(), &[], &mut fail_pipe)
                .is_err()
        );

        // Malformed PSI file -> error
        let _ = std::fs::write(psi_dir.join("io"), "corrupt-psi");
        assert!(
            agent
                .poll_psi_and_enforce_qos(&psi_dir, &ResourceBundle::zero(), &[], &mut pipe)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&psi_dir);
    }
}
