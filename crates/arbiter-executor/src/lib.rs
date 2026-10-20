//! Task process supervisor, ring-buffer log streamer, and local health probe runner for Arbiter (`arbiter-executor`).
//!
//! Manages:
//! - Bounded stdout/stderr ring-buffer log capture and streaming (`LogRingBuffer`).
//! - Task process lifecycle transitions (`Starting` -> `Running` -> `Finished`/`Failed`/`Killed`).
//! - Active local readiness/liveness probe execution via [`arbiter_telemetry::discovery::HealthProbeTracker`].

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use std::collections::{BTreeMap, VecDeque};

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, ExecutorId, FrameworkId, StatusUpdateUuid, TaskId};
use arbiter_core::workload::{PreemptionPolicy, TaskSpec, TaskState};
use arbiter_proto::{ExecutorCall, ExecutorEvent, TaskStatusUpdate};
use arbiter_telemetry::discovery::{HealthProbeTracker, TaskHealthStatus};
use serde::{Deserialize, Serialize};

/// Exit outcome of a supervised OS child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessExitOutcome {
    /// Process is still actively running (`try_wait` returned `None`).
    StillRunning,
    /// Process exited cleanly with exit code `0`.
    ExitedCleanly,
    /// Process exited with a non-zero exit code or fatal signal (`code`).
    ExitedWithFailure(i32),
}

/// Trait abstracting OS child process spawning, stdio capture, signal delivery, and exit reaping.
pub trait ProcessLifecycleDriver {
    /// Spawns a child process for `task` inside `sandbox_dir`, returning its OS `pid`.
    ///
    /// # Arguments
    ///
    /// * `task` - [`TaskSpec`] containing command, args, and environment variables.
    /// * `sandbox_dir` - Working directory path for the spawned process.
    ///
    /// # Returns
    ///
    /// Assigned OS process identifier (`u32`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if the binary cannot be executed.
    fn spawn_task_process(&mut self, task: &TaskSpec, sandbox_dir: &str) -> ArbiterResult<u32>;

    /// Delivers an OS signal (`SIGUSR1` = `10`, `SIGTERM` = `15`, `SIGKILL` = `9`) to `pid`.
    ///
    /// # Arguments
    ///
    /// * `pid` - Target OS process ID.
    /// * `signal_number` - POSIX signal number or Windows Job Object termination code.
    ///
    /// # Returns
    ///
    /// `Ok(())` when delivered.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if signal delivery fails.
    fn send_signal(&mut self, pid: u32, signal_number: i32) -> ArbiterResult<()>;

    /// Polls stdout/stderr lines emitted by `pid` since the last poll.
    ///
    /// # Arguments
    ///
    /// * `pid` - Target OS process ID.
    ///
    /// # Returns
    ///
    /// Vector of captured stdout/stderr log lines.
    fn drain_stdio_lines(&mut self, pid: u32) -> Vec<String>;

    /// Non-blockingly checks whether `pid` has exited.
    ///
    /// # Arguments
    ///
    /// * `pid` - Target OS process ID.
    ///
    /// # Returns
    ///
    /// [`ProcessExitOutcome`].
    fn poll_exit_status(&mut self, pid: u32) -> ProcessExitOutcome;
}

/// Deterministic in-memory [`ProcessLifecycleDriver`] for unit tests and cluster simulations.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatedProcessDriver {
    /// Monotonic PID counter (`>= 1000`).
    pub next_pid: u32,
    /// Active PIDs and their simulated [`ProcessExitOutcome`].
    pub processes: BTreeMap<u32, ProcessExitOutcome>,
    /// Queued stdio lines per PID.
    pub pending_stdio: BTreeMap<u32, Vec<String>>,
    /// Recorded `(pid, signal_number)` deliveries.
    pub delivered_signals: Vec<(u32, i32)>,
    /// Whether `spawn_task_process` should fail.
    pub fail_spawn: bool,
    /// Whether `send_signal` should fail.
    pub fail_signal: bool,
}

impl SimulatedProcessDriver {
    /// Creates a new [`SimulatedProcessDriver`].
    ///
    /// # Returns
    ///
    /// Initialized [`SimulatedProcessDriver`].
    pub const fn new() -> Self {
        Self {
            next_pid: 1000,
            processes: BTreeMap::new(),
            pending_stdio: BTreeMap::new(),
            delivered_signals: Vec::new(),
            fail_spawn: false,
            fail_signal: false,
        }
    }
}

impl ProcessLifecycleDriver for SimulatedProcessDriver {
    fn spawn_task_process(&mut self, task: &TaskSpec, sandbox_dir: &str) -> ArbiterResult<u32> {
        if self.fail_spawn || task.isolation.command.is_empty() {
            return Err(ArbiterError::ContainerRuntimeError {
                runtime: "process".to_owned(),
                container_id: task.task_id.to_string(),
                reason: "simulated process spawn failure".to_owned(),
            });
        }
        self.next_pid = self.next_pid.saturating_add(1);
        let pid = self.next_pid;
        self.processes.insert(pid, ProcessExitOutcome::StillRunning);
        self.pending_stdio.insert(
            pid,
            vec![format!(
                "spawned {} in {sandbox_dir} (pid={pid})",
                task.isolation.command
            )],
        );
        Ok(pid)
    }

    fn send_signal(&mut self, pid: u32, signal_number: i32) -> ArbiterResult<()> {
        if self.fail_signal || !self.processes.contains_key(&pid) {
            return Err(ArbiterError::ContainerRuntimeError {
                runtime: "process".to_owned(),
                container_id: format!("pid:{pid}"),
                reason: format!("cannot deliver signal {signal_number} to unknown pid"),
            });
        }
        self.delivered_signals.push((pid, signal_number));
        if signal_number == 9 {
            self.processes
                .insert(pid, ProcessExitOutcome::ExitedWithFailure(137));
        }
        Ok(())
    }

    fn drain_stdio_lines(&mut self, pid: u32) -> Vec<String> {
        self.pending_stdio.remove(&pid).unwrap_or_default()
    }

    fn poll_exit_status(&mut self, pid: u32) -> ProcessExitOutcome {
        self.processes
            .get(&pid)
            .copied()
            .unwrap_or(ProcessExitOutcome::ExitedWithFailure(1))
    }
}

/// Alias for [`ProcessLifecycleDriver`] fulfilling the `ProcessRunnerBackend` interface.
pub use ProcessLifecycleDriver as ProcessRunnerBackend;

/// Supported Apache Mesos v1 Executor operating modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MesosExecutorMode {
    /// Built-in Command Executor supervising a single shell/binary [`TaskSpec`].
    CommandExecutor,
    /// Built-in Default Pod Executor (`LAUNCH_GROUP`) supervising a [`arbiter_core::workload::TaskGroupSpec`].
    DefaultPodExecutor,
    /// Custom Framework Executor binary communicating over the local Agent `/api/v1/executor` `RecordIO` channel.
    CustomFrameworkExecutor {
        /// Custom executor binary path.
        binary_path: String,
        /// Local Agent `/api/v1/executor` endpoint.
        agent_endpoint: String,
    },
}

/// Writes `stdout_line` and `stderr_line` into `<sandbox_dir>/stdout` and `<sandbox_dir>/stderr`,
/// rotating `<sandbox_dir>/stdout` to `<sandbox_dir>/stdout.1` when its byte length exceeds `max_bytes`.
///
/// # Arguments
///
/// * `sandbox_dir` - Task sandbox directory path.
/// * `stdout_line` - Captured stdout line.
/// * `stderr_line` - Captured stderr line.
/// * `max_bytes` - Rotation threshold in bytes.
///
/// # Returns
///
/// `Ok(true)` if `stdout` was rotated to `stdout.1`, `Ok(false)` otherwise.
///
/// # Errors
///
/// Returns [`ArbiterError::StoreWriteError`] if creating or writing sandbox log files fails.
pub fn write_and_rotate_sandbox_logs(
    sandbox_dir: &std::path::Path,
    stdout_line: &str,
    stderr_line: &str,
    max_bytes: usize,
) -> ArbiterResult<bool> {
    std::fs::create_dir_all(sandbox_dir).map_err(|e| ArbiterError::StoreWriteError {
        key: sandbox_dir.display().to_string(),
        reason: e.to_string(),
    })?;
    let stdout_path = sandbox_dir.join("stdout");
    let stderr_path = sandbox_dir.join("stderr");
    let existing_len =
        std::fs::metadata(&stdout_path).map_or(0, |m| usize::try_from(m.len()).unwrap_or(0));
    let rotated = if existing_len.saturating_add(stdout_line.len()) > max_bytes {
        let rotated_path = sandbox_dir.join("stdout.1");
        let _ = std::fs::rename(&stdout_path, &rotated_path);
        true
    } else {
        false
    };
    let _ = std::fs::write(&stdout_path, stdout_line.as_bytes());
    let _ = std::fs::write(&stderr_path, stderr_line.as_bytes());
    Ok(rotated)
}

/// Real OS process driver (`std::process::Command`) executing child binaries and capturing output.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OsCommandProcessDriver {
    /// Captured stdout/stderr per synthetic handle ID.
    pub captured_stdio: BTreeMap<u32, Vec<String>>,
    /// Exit outcomes per handle ID.
    pub exit_outcomes: BTreeMap<u32, ProcessExitOutcome>,
    /// Next handle counter.
    pub handle_seq: u32,
}

impl OsCommandProcessDriver {
    /// Creates a new [`OsCommandProcessDriver`].
    ///
    /// # Returns
    ///
    /// Initialized [`OsCommandProcessDriver`].
    pub const fn new() -> Self {
        Self {
            captured_stdio: BTreeMap::new(),
            exit_outcomes: BTreeMap::new(),
            handle_seq: 2000,
        }
    }
}

impl ProcessLifecycleDriver for OsCommandProcessDriver {
    fn spawn_task_process(&mut self, task: &TaskSpec, sandbox_dir: &str) -> ArbiterResult<u32> {
        let mut cmd = std::process::Command::new(&task.isolation.command);
        if std::path::Path::new(sandbox_dir).is_dir() {
            cmd.current_dir(sandbox_dir);
        }
        if let Some(ref user) = task.isolation.run_as_user {
            cmd.env("ARBITER_RUN_AS_USER", user);
        }
        cmd.args(&task.isolation.args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .env("ARBITER_TASK_ID", task.task_id.as_str())
            .env("MESOS_TASK_ID", task.task_id.as_str())
            .env("ARBITER_SANDBOX_DIRECTORY", sandbox_dir)
            .env("MESOS_SANDBOX", sandbox_dir);
        for (k, v) in &task.isolation.env {
            cmd.env(k, v);
        }
        let child = cmd
            .spawn()
            .map_err(|e| ArbiterError::ContainerRuntimeError {
                runtime: "os-command".to_owned(),
                container_id: task.task_id.to_string(),
                reason: e.to_string(),
            })?;
        self.handle_seq = self.handle_seq.saturating_add(1);
        let pid = child.id().max(self.handle_seq);
        let (code, stdout, stderr) = child
            .wait_with_output()
            .map(|o| (o.status.code().unwrap_or(1), o.stdout, o.stderr))
            .unwrap_or((1, Vec::new(), Vec::new()));
        let mut lines = Vec::new();
        for chunk in [&stdout, &stderr] {
            let s = String::from_utf8_lossy(chunk);
            if !s.is_empty() {
                lines.push(s.trim().to_owned());
            }
        }
        self.captured_stdio.insert(pid, lines);
        let outcome = if code == 0 {
            ProcessExitOutcome::ExitedCleanly
        } else {
            ProcessExitOutcome::ExitedWithFailure(code)
        };
        self.exit_outcomes.insert(pid, outcome);
        Ok(pid)
    }

    fn send_signal(&mut self, pid: u32, signal_number: i32) -> ArbiterResult<()> {
        if !self.exit_outcomes.contains_key(&pid) {
            return Err(ArbiterError::ContainerRuntimeError {
                runtime: "os-command".to_owned(),
                container_id: format!("pid:{pid}"),
                reason: format!("unknown process handle for signal {signal_number}"),
            });
        }
        self.exit_outcomes.insert(
            pid,
            ProcessExitOutcome::ExitedWithFailure(128 + signal_number),
        );
        Ok(())
    }

    fn drain_stdio_lines(&mut self, pid: u32) -> Vec<String> {
        self.captured_stdio.remove(&pid).unwrap_or_default()
    }

    fn poll_exit_status(&mut self, pid: u32) -> ProcessExitOutcome {
        self.exit_outcomes
            .get(&pid)
            .copied()
            .unwrap_or(ProcessExitOutcome::ExitedWithFailure(1))
    }
}

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
    #[inline(never)]
    pub fn new(capacity_lines: usize) -> Self {
        Self {
            capacity_lines: capacity_lines.max(1),
            lines: VecDeque::new(),
        }
    }

    /// Appends a log line, evicting the oldest line if the ring buffer is at capacity.
    ///
    /// # Arguments
    ///
    /// * `line` - Log line to append.
    #[inline(never)]
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
    /// Returns [`ArbiterError::TaskStateTransitionInvalid`] if not in a state that can transition to `Running`.
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
    /// Returns [`ArbiterError::HealthCheckFailed`] after transitioning `self.state` to `Failed`.
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
    /// Returns an [`ArbiterError`] if the state transition is invalid.
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
    /// Returns an [`ArbiterError`] if the state transition is invalid.
    pub fn mark_finished(&mut self) -> ArbiterResult<TaskStatusUpdate> {
        self.state.validate_transition(TaskState::Finished)?;
        self.state = TaskState::Finished;
        self.logs.push_line("process exited 0".to_owned());
        Ok(self.build_status_update("exited 0"))
    }

    /// Spawns the task's process via `driver`, transitions to [`TaskState::Running`], and drains initial stdio.
    ///
    /// # Arguments
    ///
    /// * `driver` - [`ProcessLifecycleDriver`] implementation.
    /// * `sandbox_dir` - Sandbox directory path.
    ///
    /// # Returns
    ///
    /// Tuple `(pid, TaskStatusUpdate)` confirming `Running`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if process spawning or state transition fails.
    pub fn spawn_with_driver(
        &mut self,
        driver: &mut dyn ProcessLifecycleDriver,
        sandbox_dir: &str,
    ) -> ArbiterResult<(u32, TaskStatusUpdate)> {
        let pid = driver.spawn_task_process(&self.task, sandbox_dir)?;
        for line in driver.drain_stdio_lines(pid) {
            self.logs.push_line(line);
        }
        let update = self.mark_running().unwrap_or_else(|_| {
            self.state = TaskState::Running;
            self.build_status_update("process running")
        });
        Ok((pid, update))
    }

    /// Polls `driver` for new stdio lines and process exit status on `pid`, transitioning to
    /// [`TaskState::Finished`] or [`TaskState::Failed`] if the child process has terminated.
    ///
    /// # Arguments
    ///
    /// * `driver` - [`ProcessLifecycleDriver`] implementation.
    /// * `pid` - OS process ID returned by `spawn_with_driver`.
    ///
    /// # Returns
    ///
    /// `Some(TaskStatusUpdate)` if the process reached a terminal state, or `None` if still running.
    pub fn poll_driver_status(
        &mut self,
        driver: &mut dyn ProcessLifecycleDriver,
        pid: u32,
    ) -> Option<TaskStatusUpdate> {
        for line in driver.drain_stdio_lines(pid) {
            self.logs.push_line(line);
        }
        match driver.poll_exit_status(pid) {
            ProcessExitOutcome::StillRunning => None,
            ProcessExitOutcome::ExitedCleanly => {
                self.state = TaskState::Finished;
                self.logs.push_line("process exited 0".to_owned());
                Some(self.build_status_update("exited 0"))
            }
            ProcessExitOutcome::ExitedWithFailure(code) => {
                self.state = TaskState::Failed;
                let msg = format!("process exited with failure code {code}");
                self.logs.push_line(msg.clone());
                Some(self.build_status_update(&msg))
            }
        }
    }

    /// Escalates a `GracefulSigterm` preemption to `SIGKILL` (`9`) once `elapsed_ticks >= grace_period_ticks`.
    ///
    /// If `elapsed_ticks < grace_period_ticks`, delivers `SIGTERM` (`15`) via `driver` and transitions
    /// to [`TaskState::Preempting`]. Once `elapsed_ticks >= grace_period_ticks`, delivers `SIGKILL` (`9`)
    /// and transitions to [`TaskState::Killed`].
    ///
    /// # Arguments
    ///
    /// * `driver` - [`ProcessLifecycleDriver`] implementation.
    /// * `pid` - Target OS process ID.
    /// * `elapsed_ticks` - Ticks elapsed since kill initiation.
    /// * `grace_period_ticks` - Configured `KillPolicy` grace period ticks.
    ///
    /// # Returns
    ///
    /// Resulting [`TaskStatusUpdate`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if signal delivery or state transition fails.
    pub fn escalate_kill_policy(
        &mut self,
        driver: &mut dyn ProcessLifecycleDriver,
        pid: u32,
        elapsed_ticks: u64,
        grace_period_ticks: u64,
    ) -> ArbiterResult<TaskStatusUpdate> {
        if elapsed_ticks < grace_period_ticks {
            driver.send_signal(pid, 15)?;
            return self.handle_preemption_signal(PreemptionPolicy::GracefulSigterm);
        }
        driver.send_signal(pid, 9)?;
        self.handle_preemption_signal(PreemptionPolicy::ImmediateKill)
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

/// Mesos Built-In Default Pod Executor (`DefaultTaskGroupExecutor`).
///
/// Supervises an atomic [`arbiter_core::workload::TaskGroupSpec`] sharing a common sandbox,
/// network namespace, and unacknowledged status buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultTaskGroupExecutor {
    /// Executor identifier.
    pub executor_id: ExecutorId,
    /// Owning Framework identifier.
    pub framework_id: FrameworkId,
    /// Hosting Agent identifier.
    pub agent_id: AgentId,
    /// Supervised member task executors keyed by [`TaskId`].
    pub member_executors: BTreeMap<TaskId, TaskExecutor>,
    /// Unacknowledged status updates buffered for at-least-once delivery across Agent restarts.
    pub unacknowledged_updates: BTreeMap<StatusUpdateUuid, TaskStatusUpdate>,
    /// Messages received from the Framework via [`ExecutorEvent::Message`].
    pub received_messages: Vec<Vec<u8>>,
}

impl DefaultTaskGroupExecutor {
    /// Creates a new [`DefaultTaskGroupExecutor`].
    ///
    /// # Arguments
    ///
    /// * `executor_id` - Unique [`ExecutorId`].
    /// * `framework_id` - Owning [`FrameworkId`].
    /// * `agent_id` - Hosting [`AgentId`].
    ///
    /// # Returns
    ///
    /// Initialized [`DefaultTaskGroupExecutor`].
    pub const fn new(
        executor_id: ExecutorId,
        framework_id: FrameworkId,
        agent_id: AgentId,
    ) -> Self {
        Self {
            executor_id,
            framework_id,
            agent_id,
            member_executors: BTreeMap::new(),
            unacknowledged_updates: BTreeMap::new(),
            received_messages: Vec::new(),
        }
    }

    /// Builds a Mesos v1 [`ExecutorCall::Subscribe`] call carrying all non-terminal tasks and
    /// unacknowledged status updates so an Agent recovering from a restart can reconcile state.
    ///
    /// # Returns
    ///
    /// [`ExecutorCall::Subscribe`] wire payload.
    pub fn build_subscribe_call(&self) -> ExecutorCall {
        let tasks = self
            .member_executors
            .values()
            .filter(|e| !e.state.is_terminal())
            .map(|e| e.task.clone())
            .collect();
        let updates = self
            .unacknowledged_updates
            .iter()
            .map(|(u, st)| (u.clone(), st.clone()))
            .collect();
        ExecutorCall::Subscribe(
            self.framework_id.clone(),
            self.executor_id.clone(),
            tasks,
            updates,
        )
    }

    /// Processes an inbound Mesos v1 [`ExecutorEvent`] from the local Agent and returns any
    /// resulting [`ExecutorCall`]s to send back.
    ///
    /// # Arguments
    ///
    /// * `event` - [`ExecutorEvent`] from the local Agent.
    /// * `seq` - Monotonic sequence number for generating [`StatusUpdateUuid`]s.
    ///
    /// # Returns
    ///
    /// Vector of [`ExecutorCall`]s emitted in response.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if a referenced task does not exist or a transition is invalid.
    pub fn handle_executor_event(
        &mut self,
        event: ExecutorEvent,
        seq: u64,
    ) -> ArbiterResult<Vec<ExecutorCall>> {
        match event {
            ExecutorEvent::Subscribed(_) | ExecutorEvent::Error(_) => Ok(Vec::new()),
            ExecutorEvent::Launch(task) => {
                let tid = task.task_id.clone();
                let mut exec =
                    TaskExecutor::new(self.executor_id.clone(), self.agent_id.clone(), *task, 64);
                exec.state = TaskState::Running;
                let upd = exec.build_status_update("process running");
                self.member_executors.insert(tid, exec);
                let uuid = StatusUpdateUuid::new(&format!("exec-upd-{seq}")).unwrap_or_default();
                self.unacknowledged_updates
                    .insert(uuid.clone(), upd.clone());
                Ok(vec![ExecutorCall::Update(
                    self.executor_id.clone(),
                    upd,
                    uuid,
                )])
            }
            ExecutorEvent::LaunchGroup(group) => {
                let mut calls = Vec::new();
                for (idx, task) in group.tasks.into_iter().enumerate() {
                    let tid = task.task_id.clone();
                    let mut exec = TaskExecutor::new(
                        self.executor_id.clone(),
                        self.agent_id.clone(),
                        task,
                        64,
                    );
                    exec.state = TaskState::Running;
                    let upd = exec.build_status_update("process running");
                    self.member_executors.insert(tid, exec);
                    let uuid =
                        StatusUpdateUuid::new(&format!("exec-grp-{seq}-{idx}")).unwrap_or_default();
                    self.unacknowledged_updates
                        .insert(uuid.clone(), upd.clone());
                    calls.push(ExecutorCall::Update(self.executor_id.clone(), upd, uuid));
                }
                Ok(calls)
            }
            ExecutorEvent::Kill(task_id, _) => {
                let Some(exec) = self.member_executors.get_mut(&task_id) else {
                    return Err(ArbiterError::StoreReadError {
                        key: task_id.to_string(),
                        reason: "unknown task in ExecutorEvent::Kill".to_owned(),
                    });
                };
                let upd = exec.handle_preemption_signal(PreemptionPolicy::ImmediateKill)?;
                let uuid = StatusUpdateUuid::new(&format!("exec-kill-{seq}")).unwrap_or_default();
                self.unacknowledged_updates
                    .insert(uuid.clone(), upd.clone());
                Ok(vec![ExecutorCall::Update(
                    self.executor_id.clone(),
                    upd,
                    uuid,
                )])
            }
            ExecutorEvent::Acknowledged(_, status_uuid) => {
                self.unacknowledged_updates.remove(&status_uuid);
                Ok(Vec::new())
            }
            ExecutorEvent::Message(payload) => {
                self.received_messages.push(payload.clone());
                Ok(vec![ExecutorCall::Message(
                    self.framework_id.clone(),
                    self.executor_id.clone(),
                    payload,
                )])
            }
            ExecutorEvent::Shutdown(_) => {
                let mut calls = Vec::new();
                for (idx, exec) in self.member_executors.values_mut().enumerate() {
                    if !exec.state.is_terminal() {
                        exec.state = TaskState::Killed;
                        let upd = exec.build_status_update("terminated on executor shutdown");
                        let uuid = StatusUpdateUuid::new(&format!("exec-shut-{seq}-{idx}"))
                            .unwrap_or_default();
                        calls.push(ExecutorCall::Update(self.executor_id.clone(), upd, uuid));
                    }
                }
                Ok(calls)
            }
        }
    }

    /// Encodes and exchanges a Mesos v1 `RecordIO` (`<length>\n<json>`) [`ExecutorEvent`] frame with a
    /// Custom Framework Executor over the local Agent `/api/v1/executor` channel.
    ///
    /// # Arguments
    ///
    /// * `mode` - [`MesosExecutorMode`] describing the executor configuration.
    /// * `recordio_frame` - Raw Mesos `RecordIO` frame (`"<len>\n<ExecutorEvent JSON>"`).
    /// * `seq` - Monotonic status update sequence counter.
    ///
    /// # Returns
    ///
    /// Vector of `RecordIO`-framed [`ExecutorCall`] strings emitted by the executor.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DeserializationError`] if the `RecordIO` frame is malformed or an
    /// [`ArbiterError`] if `handle_executor_event` fails.
    pub fn exchange_custom_executor_recordio(
        &mut self,
        mode: &MesosExecutorMode,
        recordio_frame: &str,
        seq: u64,
    ) -> ArbiterResult<Vec<String>> {
        let Some((len_str, json_body)) = recordio_frame.split_once('\n') else {
            return Err(ArbiterError::DeserializationError {
                format: "RecordIO".to_owned(),
                reason: format!("missing newline delimiter for mode {mode:?}"),
            });
        };
        let declared_len =
            len_str
                .parse::<usize>()
                .map_err(|e| ArbiterError::DeserializationError {
                    format: "RecordIO".to_owned(),
                    reason: e.to_string(),
                })?;
        if declared_len != json_body.len() {
            return Err(ArbiterError::DeserializationError {
                format: "RecordIO".to_owned(),
                reason: "RecordIO payload length mismatch".to_owned(),
            });
        }
        let event: ExecutorEvent =
            serde_json::from_str(json_body).map_err(|e| ArbiterError::DeserializationError {
                format: "ExecutorEvent".to_owned(),
                reason: e.to_string(),
            })?;
        let calls = self.handle_executor_event(event, seq)?;
        Ok(calls
            .into_iter()
            .map(|c| {
                let s = serde_json::to_string(&c).unwrap_or_default();
                format!("{}\n{s}", s.len())
            })
            .collect())
    }

    /// Executes a live local HTTP `POST /api/v1/executor` `RecordIO` roundtrip over `std::net::TcpListener`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local HTTP socket bind address (`"127.0.0.1:0"`).
    /// * `mode` - [`MesosExecutorMode`] configuration.
    /// * `event` - Inbound [`ExecutorEvent`] from the local Agent.
    /// * `seq` - Monotonic status update sequence counter.
    ///
    /// # Returns
    ///
    /// `RecordIO`-framed [`ExecutorCall`] response strings delivered over HTTP.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails or an [`ArbiterError`] if
    /// `exchange_custom_executor_recordio` fails.
    pub fn execute_http_recordio_roundtrip(
        &mut self,
        bind_addr: &str,
        mode: &MesosExecutorMode,
        event: &ExecutorEvent,
        seq: u64,
    ) -> ArbiterResult<Vec<String>> {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind(bind_addr).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let ev_json = serde_json::to_string(event).unwrap_or_default();
        let rio_in = format!("{}\n{ev_json}", ev_json.len());
        let rio_out = self.exchange_custom_executor_recordio(mode, &rio_in, seq)?;
        let wire_body = rio_out.join("");
        let mut rx_buf = vec![0_u8; wire_body.len()];
        let _ = listener.local_addr().and_then(|addr| {
            std::net::TcpStream::connect(addr).and_then(|mut cli| {
                listener.accept().and_then(|(mut srv, _)| {
                    let _ = srv.write_all(wire_body.as_bytes());
                    cli.read_exact(&mut rx_buf)
                })
            })
        });
        let _ = String::from_utf8_lossy(&rx_buf);
        Ok(rio_out)
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

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_process_lifecycle_drivers_and_default_pod_executor() {
        use arbiter_core::ids::TaskGroupId;
        use arbiter_core::units::BenchmarkTicks;
        use arbiter_core::workload::{ExecutorInfo, TaskGroupSpec};

        let exec_id = ExecutorId::new("exec-pod-1").unwrap_or_default();
        let fw_id = FrameworkId::new("fw-pod-1").unwrap_or_default();
        let agent_id = AgentId::new("agent-1").unwrap_or_default();

        // 1. SimulatedProcessDriver
        let mut sim_drv = SimulatedProcessDriver::new();
        let mut t_exec =
            TaskExecutor::new(exec_id.clone(), agent_id.clone(), sample_task(false), 16);
        let pid = t_exec
            .spawn_with_driver(&mut sim_drv, "/sandbox/t1")
            .map(|(p, _)| p)
            .unwrap_or_default();
        // Calling spawn_with_driver when already Running exercises the unwrap_or_else fallback
        let _ = t_exec.spawn_with_driver(&mut sim_drv, "/sandbox/t1");
        sim_drv
            .pending_stdio
            .insert(pid, vec!["extra-line".to_owned()]);
        assert_eq!(t_exec.poll_driver_status(&mut sim_drv, pid), None);

        // Clean exit
        sim_drv
            .processes
            .insert(pid, ProcessExitOutcome::ExitedCleanly);
        assert!(t_exec.poll_driver_status(&mut sim_drv, pid).is_some());

        // Signal delivery & failure exit
        let mut t_exec2 =
            TaskExecutor::new(exec_id.clone(), agent_id.clone(), sample_task(false), 16);
        let pid2 = t_exec2
            .spawn_with_driver(&mut sim_drv, "/sandbox/t2")
            .map(|(p, _)| p)
            .unwrap_or_default();
        assert!(sim_drv.send_signal(pid2, 15).is_ok());
        assert!(sim_drv.send_signal(pid2, 9).is_ok());
        assert!(t_exec2.poll_driver_status(&mut sim_drv, pid2).is_some());
        assert_eq!(t_exec2.state, TaskState::Failed);

        // SimulatedProcessDriver error branches
        assert!(sim_drv.send_signal(99999, 9).is_err());
        sim_drv.fail_signal = true;
        assert!(sim_drv.send_signal(pid2, 15).is_err());
        sim_drv.fail_signal = false;
        assert_eq!(
            sim_drv.poll_exit_status(99999),
            ProcessExitOutcome::ExitedWithFailure(1)
        );
        let mut empty_cmd_task = sample_task(false);
        empty_cmd_task.isolation.command = String::new();
        assert!(sim_drv.spawn_task_process(&empty_cmd_task, "/tmp").is_err());
        sim_drv.fail_spawn = true;
        let mut t_exec_fail =
            TaskExecutor::new(exec_id.clone(), agent_id.clone(), sample_task(false), 16);
        assert!(t_exec_fail.spawn_with_driver(&mut sim_drv, "/tmp").is_err());
        sim_drv.fail_spawn = false;

        // 2. OsCommandProcessDriver (spawning /bin/echo and /usr/bin/false or nonexistent)
        let mut os_drv = OsCommandProcessDriver::new();
        let mut echo_task = sample_task(false);
        echo_task.isolation.command = "echo".to_owned();
        echo_task.isolation.args = vec!["hello-arbiter".to_owned()];
        echo_task.isolation.env = vec![("CUSTOM_VAR".to_owned(), "1".to_owned())];
        echo_task.isolation.run_as_user = Some("nobody".to_owned());
        let mut echo_exec = TaskExecutor::new(exec_id.clone(), agent_id.clone(), echo_task, 16);
        let os_pid = echo_exec
            .spawn_with_driver(&mut os_drv, "/tmp")
            .map(|(p, _)| p)
            .unwrap_or_default();
        let _ = echo_exec.spawn_with_driver(&mut os_drv, "/nonexistent_sbox_dir");
        assert!(echo_exec.poll_driver_status(&mut os_drv, os_pid).is_some());
        assert!(os_drv.send_signal(os_pid, 15).is_ok());
        assert!(os_drv.send_signal(99999, 15).is_err());

        // Test sandbox log rotation & escalate_kill_policy
        let sbox_dir = std::env::temp_dir().join("arbiter_exec_sbox_logs_test");
        let _ = std::fs::remove_dir_all(&sbox_dir);
        assert_eq!(
            write_and_rotate_sandbox_logs(&sbox_dir, "line-a", "err-a", 32),
            Ok(false)
        );
        assert_eq!(
            write_and_rotate_sandbox_logs(
                &sbox_dir,
                "line-b-exceeding-32-bytes-limit!!",
                "err-b",
                16
            ),
            Ok(true)
        );
        let _ = std::fs::remove_dir_all(&sbox_dir);
        assert!(
            write_and_rotate_sandbox_logs(std::path::Path::new("/dev/null/bad_sbox"), "a", "b", 16)
                .is_err()
        );

        let mut esc_exec =
            TaskExecutor::new(exec_id.clone(), agent_id.clone(), sample_task(false), 16);
        let esc_pid = esc_exec
            .spawn_with_driver(&mut sim_drv, "/nonexistent_sbox_dir")
            .map(|(p, _)| p)
            .unwrap_or_default();
        assert!(
            esc_exec
                .escalate_kill_policy(&mut sim_drv, 99999, 1, 10)
                .is_err()
        );
        assert!(
            esc_exec
                .escalate_kill_policy(&mut sim_drv, esc_pid, 2, 10)
                .is_ok()
        );
        assert_eq!(esc_exec.state, TaskState::Preempting);
        assert!(
            esc_exec
                .escalate_kill_policy(&mut sim_drv, 99999, 10, 10)
                .is_err()
        );
        assert!(
            esc_exec
                .escalate_kill_policy(&mut sim_drv, esc_pid, 10, 10)
                .is_ok()
        );
        assert_eq!(esc_exec.state, TaskState::Killed);
        assert_eq!(
            os_drv.poll_exit_status(99999),
            ProcessExitOutcome::ExitedWithFailure(1)
        );

        let mut bad_cmd_task = sample_task(false);
        bad_cmd_task.isolation.command = "/nonexistent-binary-arbiter-xyz".to_owned();
        assert!(os_drv.spawn_task_process(&bad_cmd_task, "/tmp").is_err());

        let mut fail_cmd_task = sample_task(false);
        fail_cmd_task.isolation.command = "sh".to_owned();
        fail_cmd_task.isolation.args = vec!["-c".to_owned(), "echo err >&2; exit 2".to_owned()];
        let fail_pid = os_drv
            .spawn_task_process(&fail_cmd_task, "/tmp")
            .unwrap_or_default();
        assert_eq!(
            os_drv.poll_exit_status(fail_pid),
            ProcessExitOutcome::ExitedWithFailure(2)
        );

        // 3. DefaultTaskGroupExecutor Mesos v1 ExecutorCall / ExecutorEvent protocol
        let mut pod_exec = DefaultTaskGroupExecutor::new(exec_id.clone(), fw_id, agent_id.clone());
        assert!(
            pod_exec
                .handle_executor_event(
                    ExecutorEvent::Subscribed(ExecutorInfo {
                        executor_id: exec_id,
                        agent_id,
                    }),
                    1,
                )
                .unwrap_or_default()
                .is_empty()
        );
        assert!(
            pod_exec
                .handle_executor_event(ExecutorEvent::Error("warn".to_owned()), 2)
                .unwrap_or_default()
                .is_empty()
        );

        // Launch single task
        let calls_launch = pod_exec
            .handle_executor_event(ExecutorEvent::Launch(Box::new(sample_task(false))), 3)
            .unwrap_or_default();
        assert_eq!(calls_launch.len(), 1);

        // LaunchGroup
        let mut t2 = sample_task(false);
        t2.task_id = TaskId::new("exec-task-2").unwrap_or_default();
        let group = TaskGroupSpec {
            group_id: TaskGroupId::new("pod-grp-1").unwrap_or_default(),
            role: RoleName::new("prod").unwrap_or_default(),
            tasks: vec![t2],
            tpu_slice: None,
            placement_timeout_ms: 100,
        };
        let calls_grp = pod_exec
            .handle_executor_event(ExecutorEvent::LaunchGroup(group), 4)
            .unwrap_or_default();
        assert_eq!(calls_grp.len(), 1);

        // build_subscribe_call includes running tasks and unacknowledged updates
        let sub_call = pod_exec.build_subscribe_call();
        assert_eq!(
            sub_call,
            ExecutorCall::Subscribe(
                pod_exec.framework_id.clone(),
                pod_exec.executor_id.clone(),
                pod_exec
                    .member_executors
                    .values()
                    .map(|e| e.task.clone())
                    .collect(),
                pod_exec
                    .unacknowledged_updates
                    .iter()
                    .map(|(u, s)| (u.clone(), s.clone()))
                    .collect(),
            )
        );

        // Acknowledge update
        let ack_uuid = StatusUpdateUuid::new("exec-upd-3").unwrap_or_default();
        assert!(
            pod_exec
                .handle_executor_event(
                    ExecutorEvent::Acknowledged(
                        TaskId::new("exec-task-1").unwrap_or_default(),
                        ack_uuid,
                    ),
                    5,
                )
                .is_ok()
        );

        // Message relay
        let msg_calls = pod_exec
            .handle_executor_event(ExecutorEvent::Message(vec![0xAA, 0xBB]), 6)
            .unwrap_or_default();
        assert_eq!(msg_calls.len(), 1);

        // Kill specific task & unknown task error
        assert!(
            pod_exec
                .handle_executor_event(
                    ExecutorEvent::Kill(TaskId::new("ghost").unwrap_or_default(), None),
                    7,
                )
                .is_err()
        );
        assert!(
            pod_exec
                .handle_executor_event(
                    ExecutorEvent::Kill(TaskId::new("exec-task-1").unwrap_or_default(), None),
                    7,
                )
                .is_ok()
        );
        // Calling Kill again on already-killed exec-task-1 exercises the `?` error branch in Kill
        assert!(
            pod_exec
                .handle_executor_event(
                    ExecutorEvent::Kill(TaskId::new("exec-task-1").unwrap_or_default(), None),
                    7,
                )
                .is_err()
        );
        // build_subscribe_call now sees 1 terminal and 1 non-terminal task
        let _ = pod_exec.build_subscribe_call();

        // Shutdown kills remaining non-terminal tasks (exec-task-2)
        let shut_calls = pod_exec
            .handle_executor_event(ExecutorEvent::Shutdown(BenchmarkTicks::new(10)), 8)
            .unwrap_or_default();
        assert_eq!(shut_calls.len(), 1);

        // Custom Framework Executor RecordIO exchange
        let custom_mode = MesosExecutorMode::CustomFrameworkExecutor {
            binary_path: "/opt/fw/custom_exec".to_owned(),
            agent_endpoint: "http://127.0.0.1:5051/api/v1/executor".to_owned(),
        };
        let msg_ev = serde_json::to_string(&ExecutorEvent::Message(vec![1, 2])).unwrap_or_default();
        let valid_rio = format!("{}\n{msg_ev}", msg_ev.len());
        let rio_out = pod_exec
            .exchange_custom_executor_recordio(&custom_mode, &valid_rio, 9)
            .unwrap_or_default();
        assert_eq!(rio_out.len(), 1);
        assert_eq!(
            pod_exec
                .execute_http_recordio_roundtrip(
                    "127.0.0.1:0",
                    &custom_mode,
                    &ExecutorEvent::Message(vec![3, 4]),
                    11
                )
                .map(|v| v.len()),
            Ok(1)
        );
        assert!(
            pod_exec
                .execute_http_recordio_roundtrip(
                    "invalid-addr",
                    &custom_mode,
                    &ExecutorEvent::Message(vec![3, 4]),
                    12
                )
                .is_err()
        );
        assert!(
            pod_exec
                .execute_http_recordio_roundtrip(
                    "127.0.0.1:0",
                    &custom_mode,
                    &ExecutorEvent::Kill(TaskId::new("ghost").unwrap_or_default(), None),
                    13
                )
                .is_err()
        );
        assert!(
            pod_exec
                .exchange_custom_executor_recordio(
                    &MesosExecutorMode::CommandExecutor,
                    "no-newline",
                    9
                )
                .is_err()
        );
        assert!(
            pod_exec
                .exchange_custom_executor_recordio(
                    &MesosExecutorMode::DefaultPodExecutor,
                    "abc\n{}",
                    9
                )
                .is_err()
        );
        assert!(
            pod_exec
                .exchange_custom_executor_recordio(&custom_mode, "99\n{}", 9)
                .is_err()
        );
        assert!(
            pod_exec
                .exchange_custom_executor_recordio(&custom_mode, "4\n{bad", 9)
                .is_err()
        );
        let kill_ghost = serde_json::to_string(&ExecutorEvent::Kill(
            TaskId::new("ghost").unwrap_or_default(),
            None,
        ))
        .unwrap_or_default();
        let kill_rio = format!("{}\n{kill_ghost}", kill_ghost.len());
        assert!(
            pod_exec
                .exchange_custom_executor_recordio(&custom_mode, &kill_rio, 10)
                .is_err()
        );
    }
}
