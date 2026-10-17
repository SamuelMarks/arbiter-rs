//! Task process supervisor, ring-buffer log streamer, and local health probe runner for Arbiter (`arbiter-executor`).
//!
//! Manages:
//! - Bounded stdout/stderr ring-buffer log capture and streaming (`LogRingBuffer`).
//! - Task process lifecycle transitions (`Starting` -> `Running` -> `Finished`/`Failed`/`Killed`).
//! - Active local readiness/liveness probe execution via [`arbiter_telemetry::discovery::HealthProbeTracker`].

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use std::collections::VecDeque;

use arbiter_core::error::ArbiterResult;
use arbiter_core::ids::{AgentId, ExecutorId};
use arbiter_core::workload::{PreemptionPolicy, TaskSpec, TaskState};
use arbiter_proto::TaskStatusUpdate;
use arbiter_telemetry::discovery::{HealthProbeTracker, TaskHealthStatus};
use serde::{Deserialize, Serialize};

/// Bounded ring-buffer capturing stdout and stderr log lines from a supervised task process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRingBuffer {
    /// Maximum number of lines retained in the ring buffer.
    capacity_lines: usize,
    /// Buffered log lines (`front` = oldest, `back` = newest).
    lines: VecDeque<String>,
}

impl LogRingBuffer {
    /// Creates a new [`LogRingBuffer`] with `capacity_lines` (clamped to at least `1`).
    ///
    /// # Arguments
    ///
    /// * `capacity_lines` - Maximum number of log lines to retain.
    ///
    /// # Returns
    ///
    /// Empty [`LogRingBuffer`].
    pub const fn new(capacity_lines: usize) -> Self {
        let cap = if capacity_lines == 0 {
            1
        } else {
            capacity_lines
        };
        Self {
            capacity_lines: cap,
            lines: VecDeque::new(),
        }
    }

    /// Appends a log line, evicting the oldest line if the ring buffer is at capacity.
    ///
    /// # Arguments
    ///
    /// * `line` - Log line to append.
    pub fn push_line(&mut self, line: String) {
        if self.lines.len() >= self.capacity_lines {
            let _ = self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    /// Returns a snapshot of all buffered log lines in chronological order.
    ///
    /// # Returns
    ///
    /// Vector of log lines.
    pub fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }
}

/// Task process supervisor and local health runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskExecutor {
    /// Executor identifier.
    pub executor_id: ExecutorId,
    /// Hosting Agent identifier.
    pub agent_id: AgentId,
    /// Supervised task specification.
    pub task: TaskSpec,
    /// Current lifecycle state of the task.
    pub state: TaskState,
    /// Stdout/stderr ring buffer.
    pub logs: LogRingBuffer,
    /// Optional active health probe tracker.
    pub health_tracker: Option<HealthProbeTracker>,
}

impl TaskExecutor {
    /// Creates a new [`TaskExecutor`] in [`TaskState::Starting`].
    ///
    /// # Arguments
    ///
    /// * `executor_id` - Unique [`ExecutorId`].
    /// * `agent_id` - Hosting [`AgentId`].
    /// * `task` - [`TaskSpec`] to supervise.
    /// * `log_ring_capacity` - Max log lines in the ring buffer.
    ///
    /// # Returns
    ///
    /// Initialized [`TaskExecutor`].
    pub fn new(
        executor_id: ExecutorId,
        agent_id: AgentId,
        task: TaskSpec,
        log_ring_capacity: usize,
    ) -> Self {
        let health_tracker = task
            .health_check
            .clone()
            .map(|spec| HealthProbeTracker::new(task.task_id.clone(), spec));
        Self {
            executor_id,
            agent_id,
            task,
            state: TaskState::Starting,
            logs: LogRingBuffer::new(log_ring_capacity),
            health_tracker,
        }
    }

    /// Transitions the supervised task to [`TaskState::Running`] and emits a [`TaskStatusUpdate`].
    ///
    /// # Returns
    ///
    /// [`TaskStatusUpdate`] reporting `Running`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::TaskStateTransitionInvalid`](arbiter_core::error::ArbiterError::TaskStateTransitionInvalid) if not in a state that can transition to `Running`.
    pub fn mark_running(&mut self) -> ArbiterResult<TaskStatusUpdate> {
        self.state.validate_transition(TaskState::Running)?;
        self.state = TaskState::Running;
        self.logs.push_line("process started".to_owned());
        Ok(self.build_status_update("process running"))
    }

    /// Evaluates a local health probe tick on the running task.
    ///
    /// If the health probe exceeds `unhealthy_threshold`, automatically transitions the task to
    /// [`TaskState::Failed`].
    ///
    /// # Arguments
    ///
    /// * `probe_passed` - Whether the local TCP/HTTP/QUIC probe succeeded.
    ///
    /// # Returns
    ///
    /// [`TaskHealthStatus`] if still healthy or degraded.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HealthCheckFailed`](arbiter_core::error::ArbiterError::HealthCheckFailed) after transitioning `self.state` to `Failed`.
    pub fn evaluate_health_tick(&mut self, probe_passed: bool) -> ArbiterResult<TaskHealthStatus> {
        let Some(ref mut tracker) = self.health_tracker else {
            return Ok(TaskHealthStatus::Healthy);
        };
        match tracker.record_probe_outcome(probe_passed, "health probe failed") {
            Ok(status) => Ok(status),
            Err(err) => {
                self.state = TaskState::Failed;
                self.logs.push_line(format!("health check failed: {err}"));
                Err(err)
            }
        }
    }

    /// Delivers a preemption signal (`SIGUSR1` checkpoint, `SIGTERM` graceful, or `SIGKILL` / Job Object kill)
    /// to the supervised task.
    ///
    /// # Arguments
    ///
    /// * `policy` - [`PreemptionPolicy`] to execute.
    ///
    /// # Returns
    ///
    /// Resulting [`TaskStatusUpdate`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if the state transition is invalid.
    pub fn handle_preemption_signal(
        &mut self,
        policy: PreemptionPolicy,
    ) -> ArbiterResult<TaskStatusUpdate> {
        match policy {
            PreemptionPolicy::CheckpointAndSuspend => {
                self.state.validate_transition(TaskState::Checkpointing)?;
                self.state = TaskState::Checkpointing;
                self.logs
                    .push_line("SIGUSR1 checkpoint signal delivered".to_owned());
                Ok(self.build_status_update("checkpointing before suspension"))
            }
            PreemptionPolicy::GracefulSigterm => {
                self.state.validate_transition(TaskState::Preempting)?;
                self.state = TaskState::Preempting;
                self.logs
                    .push_line("SIGTERM graceful preemption delivered".to_owned());
                Ok(self.build_status_update("graceful sigterm preemption"))
            }
            PreemptionPolicy::ImmediateKill | PreemptionPolicy::NonPreemptible => {
                self.state.validate_transition(TaskState::Killed)?;
                self.state = TaskState::Killed;
                self.logs
                    .push_line("SIGKILL / TerminateJobObject executed".to_owned());
                Ok(self.build_status_update("terminated immediately"))
            }
        }
    }

    /// Completes the task cleanly with exit code `0`, transitioning to [`TaskState::Finished`].
    ///
    /// # Returns
    ///
    /// [`TaskStatusUpdate`] reporting `Finished`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if the state transition is invalid.
    pub fn mark_finished(&mut self) -> ArbiterResult<TaskStatusUpdate> {
        self.state.validate_transition(TaskState::Finished)?;
        self.state = TaskState::Finished;
        self.logs.push_line("process exited 0".to_owned());
        Ok(self.build_status_update("exited 0"))
    }

    /// Builds a [`TaskStatusUpdate`] for the current task state.
    ///
    /// # Arguments
    ///
    /// * `msg` - Diagnostic message.
    ///
    /// # Returns
    ///
    /// [`TaskStatusUpdate`].
    fn build_status_update(&self, msg: &str) -> TaskStatusUpdate {
        TaskStatusUpdate {
            task_id: self.task.task_id.clone(),
            agent_id: self.agent_id.clone(),
            state: self.state,
            message: msg.to_owned(),
        }
    }
}

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-executor"`.
pub const fn crate_name() -> &'static str {
    "arbiter-executor"
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::{RoleName, TaskId};
    use arbiter_core::resources::ResourceBundle;
    use arbiter_core::units::PortNumber;
    use arbiter_core::workload::{
        HealthCheckProtocol, HealthCheckSpec, IsolationSpec, PriorityClass,
    };

    use super::*;

    fn sample_task(with_health: bool) -> TaskSpec {
        let hc = if with_health {
            Some(HealthCheckSpec {
                protocol: HealthCheckProtocol::Tcp,
                port: PortNumber::default(),
                interval_ms: 500,
                timeout_ms: 100,
                unhealthy_threshold: 2,
            })
        } else {
            None
        };
        TaskSpec {
            task_id: TaskId::new("exec-task-1").unwrap_or_default(),
            role: RoleName::new("prod").unwrap_or_default(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionStandard,
            preemption_policy: PreemptionPolicy::CheckpointAndSuspend,
            resources: ResourceBundle::zero(),
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/run".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: hc,
        }
    }

    #[test]
    fn test_executor_ring_buffer_health_and_preemption() {
        assert_eq!(crate_name(), "arbiter-executor");

        // Ring buffer clamping 0 -> 1 and eviction
        let mut ring = LogRingBuffer::new(0);
        ring.push_line("line1".to_owned());
        ring.push_line("line2".to_owned());
        assert_eq!(ring.snapshot(), vec!["line2".to_owned()]);

        let exec_id = ExecutorId::new("exec-1").unwrap_or_default();
        let agent_id = AgentId::new("agent-1").unwrap_or_default();

        // Task without health check
        let mut exec_no_hc =
            TaskExecutor::new(exec_id.clone(), agent_id.clone(), sample_task(false), 10);
        assert!(exec_no_hc.mark_running().is_ok());
        assert_eq!(
            exec_no_hc.evaluate_health_tick(false),
            Ok(TaskHealthStatus::Healthy)
        );
        assert!(
            exec_no_hc
                .handle_preemption_signal(PreemptionPolicy::CheckpointAndSuspend)
                .is_ok()
        );
        assert!(exec_no_hc.mark_finished().is_ok());
        // Already finished -> cannot mark_running or mark_finished or preempt
        assert!(exec_no_hc.mark_running().is_err());
        assert!(exec_no_hc.mark_finished().is_err());
        assert!(
            exec_no_hc
                .handle_preemption_signal(PreemptionPolicy::CheckpointAndSuspend)
                .is_err()
        );
        assert!(
            exec_no_hc
                .handle_preemption_signal(PreemptionPolicy::GracefulSigterm)
                .is_err()
        );
        assert!(
            exec_no_hc
                .handle_preemption_signal(PreemptionPolicy::ImmediateKill)
                .is_err()
        );

        // Task with GracefulSigterm and ImmediateKill
        let mut exec_sigterm =
            TaskExecutor::new(exec_id.clone(), agent_id.clone(), sample_task(false), 10);
        let _ = exec_sigterm.mark_running();
        assert!(
            exec_sigterm
                .handle_preemption_signal(PreemptionPolicy::GracefulSigterm)
                .is_ok()
        );
        assert!(
            exec_sigterm
                .handle_preemption_signal(PreemptionPolicy::ImmediateKill)
                .is_ok()
        );

        // Task with health check failing beyond threshold -> transitions to Failed
        let mut exec_hc = TaskExecutor::new(exec_id, agent_id, sample_task(true), 10);
        let _ = exec_hc.mark_running();
        assert!(exec_hc.evaluate_health_tick(false).is_ok()); // 1/2 degraded
        assert!(exec_hc.evaluate_health_tick(false).is_err()); // 2/2 -> Failed!
        assert_eq!(exec_hc.state, TaskState::Failed);
    }
}
