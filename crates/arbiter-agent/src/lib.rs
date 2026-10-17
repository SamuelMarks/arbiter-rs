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
use arbiter_core::ids::{AgentId, ExecutorId, TaskId};
use arbiter_core::resources::ResourceBundle;
use arbiter_core::units::{Bytes, Millicores, PowerMilliwatts, TemperatureMilliCelsius};
use arbiter_executor::TaskExecutor;
use arbiter_iso::pipeline::{IsolatorPipeline, SandboxPreparation};
use arbiter_net::security::{SealedSecretEnvelope, unseal_secret};
use arbiter_probe::fabric::assemble_hardware_topology_graph;
use arbiter_probe::traits::{FabricProbe, GpuProbe, SystemProbe, TpuProbe};
use arbiter_proto::{
    HardwareTelemetryReport, LaunchTaskCommand, PreemptTaskCommand, RegisterAgent, TaskStatusUpdate,
};
use arbiter_storage::ArtifactCache;

use crate::caas::AgentCaasLeaseCache;

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
        }
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
                        agent_id: aid,
                        task_id: TaskId::new("ghost").unwrap_or_default(),
                        policy: PreemptionPolicy::ImmediateKill,
                    },
                    &mut pipe,
                )
                .is_err()
        );
    }
}
