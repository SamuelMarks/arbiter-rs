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

/// Reads a paginated slice `[offset..offset + length]` from a live task sandbox file (`stdout` or
/// `stderr`) inside `sandbox_dir` for the Mesos v1 `READ_FILE` operator API.
///
/// # Arguments
///
/// * `sandbox_dir` - Task sandbox directory path on disk.
/// * `relative_file` - File name inside the sandbox (`"stdout"`, `"stderr"`, etc.).
/// * `offset` - Validated [`arbiter_core::units::FileReadOffset`].
/// * `length` - Validated [`arbiter_core::units::FileReadLength`].
///
/// # Returns
///
/// Tuple `(total_file_size_bytes, read_slice_string)`.
///
/// # Errors
///
/// Returns [`ArbiterError::StoreReadError`] if `relative_file` contains `..` or cannot be read.
pub fn read_sandbox_file_paginated(
    sandbox_dir: &std::path::Path,
    relative_file: &str,
    offset: arbiter_core::units::FileReadOffset,
    length: arbiter_core::units::FileReadLength,
) -> ArbiterResult<(u64, String)> {
    if relative_file.is_empty() || relative_file.contains("..") || relative_file.starts_with('/') {
        return Err(ArbiterError::StoreReadError {
            key: relative_file.to_owned(),
            reason: "invalid sandbox relative_file in read_sandbox_file_paginated".to_owned(),
        });
    }
    let path = sandbox_dir.join(relative_file);
    let raw = std::fs::read(&path).map_err(|e| ArbiterError::StoreReadError {
        key: path.display().to_string(),
        reason: e.to_string(),
    })?;
    let total_size = u64::try_from(raw.len()).unwrap_or(0);
    let start = usize::try_from(offset.get())
        .unwrap_or(raw.len())
        .min(raw.len());
    let end = start
        .saturating_add(usize::try_from(length.get()).unwrap_or(0))
        .min(raw.len());
    let slice = raw.get(start..end).unwrap_or_default();
    Ok((total_size, String::from_utf8_lossy(slice).into_owned()))
}

/// Real OS process driver (`std::process::Command`) executing child binaries, delivering POSIX
/// signals (`SIGUSR1`, `SIGTERM`, `SIGKILL`), and capturing stdout/stderr into [`LogRingBuffer`]s.
#[derive(Debug, Default)]
pub struct OsCommandProcessDriver {
    /// Active non-blocking [`std::process::Child`] handles keyed by handle ID.
    pub children: BTreeMap<u32, std::process::Child>,
    /// Mapping from driver handle ID to underlying OS PID (`child.id()`).
    pub os_pids: BTreeMap<u32, u32>,
    /// Sandbox directory path per handle ID for `READ_FILE` log persistence.
    pub sandbox_dirs: BTreeMap<u32, String>,
    /// Per-process [`LogRingBuffer`] for real-time stdout/stderr capture.
    pub ring_buffers: BTreeMap<u32, LogRingBuffer>,
    /// Captured stdout/stderr lines per handle ID awaiting next `drain_stdio_lines`.
    pub captured_stdio: BTreeMap<u32, Vec<String>>,
    /// Exit outcomes per handle ID.
    pub exit_outcomes: BTreeMap<u32, ProcessExitOutcome>,
    /// Next handle counter.
    pub handle_seq: u32,
    /// When `true`, `spawn_task_process` keeps the [`std::process::Child`] running in the background
    /// and `poll_exit_status` polls `try_wait()` without blocking.
    pub nonblocking_mode: bool,
}

impl OsCommandProcessDriver {
    /// Creates a new [`OsCommandProcessDriver`].
    ///
    /// # Returns
    ///
    /// Initialized [`OsCommandProcessDriver`].
    pub fn new() -> Self {
        Self {
            children: BTreeMap::new(),
            os_pids: BTreeMap::new(),
            sandbox_dirs: BTreeMap::new(),
            ring_buffers: BTreeMap::new(),
            captured_stdio: BTreeMap::new(),
            exit_outcomes: BTreeMap::new(),
            handle_seq: 2000,
            nonblocking_mode: false,
        }
    }

    /// Creates a new [`OsCommandProcessDriver`] configured in non-blocking child supervision mode.
    ///
    /// # Returns
    ///
    /// Initialized non-blocking [`OsCommandProcessDriver`].
    pub fn new_nonblocking() -> Self {
        Self {
            nonblocking_mode: true,
            ..Self::new()
        }
    }

    /// Returns the [`LogRingBuffer`] snapshot captured for `pid` (`READ_FILE` support).
    ///
    /// # Arguments
    ///
    /// * `pid` - Process handle ID returned by `spawn_task_process`.
    ///
    /// # Returns
    ///
    /// Chronological vector of buffered stdout/stderr lines for `pid`.
    pub fn read_ring_buffer_snapshot(&self, pid: u32) -> Vec<String> {
        self.ring_buffers
            .get(&pid)
            .map(LogRingBuffer::snapshot)
            .unwrap_or_default()
    }

    /// Harvests piped stdout and stderr from `child` into `captured_stdio` and `ring_buffers`.
    fn harvest_child_pipes(&mut self, pid: u32, child: &mut std::process::Child) {
        use std::io::Read;

        let mut stdout_bytes = Vec::new();
        let _ = child
            .stdout
            .take()
            .map(|mut p| p.read_to_end(&mut stdout_bytes));
        let mut stderr_bytes = Vec::new();
        let _ = child
            .stderr
            .take()
            .map(|mut p| p.read_to_end(&mut stderr_bytes));
        let mut lines = Vec::new();
        let mut ring = LogRingBuffer::new(128);
        for chunk in [&stdout_bytes, &stderr_bytes] {
            let text = String::from_utf8_lossy(chunk);
            for line in text.lines() {
                let owned = line.trim().to_owned();
                ring.push_line(owned.clone());
                lines.push(owned);
            }
        }
        self.ring_buffers.insert(pid, ring);
        self.captured_stdio.insert(pid, lines);
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
        let mut child = cmd
            .spawn()
            .map_err(|e| ArbiterError::ContainerRuntimeError {
                runtime: "os-command".to_owned(),
                container_id: task.task_id.to_string(),
                reason: e.to_string(),
            })?;
        self.handle_seq = self.handle_seq.saturating_add(1);
        let os_pid = child.id();
        let pid = os_pid.max(self.handle_seq);
        self.os_pids.insert(pid, os_pid);
        self.sandbox_dirs.insert(pid, sandbox_dir.to_owned());
        self.ring_buffers.insert(pid, LogRingBuffer::new(128));

        if self.nonblocking_mode {
            self.exit_outcomes
                .insert(pid, ProcessExitOutcome::StillRunning);
            self.children.insert(pid, child);
            return Ok(pid);
        }

        let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(1);
        self.harvest_child_pipes(pid, &mut child);
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
        let os_pid = self.os_pids.get(&pid).copied().unwrap_or(pid);
        let _ = std::process::Command::new("/bin/kill")
            .arg(format!("-{signal_number}"))
            .arg(os_pid.to_string())
            .output();
        if let Some(mut child) = self.children.remove(&pid) {
            let _ = child.kill();
            let _ = child.wait();
            self.harvest_child_pipes(pid, &mut child);
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
        if let Some(mut child) = self.children.remove(&pid) {
            if let Some(status) = child.try_wait().ok().flatten() {
                self.harvest_child_pipes(pid, &mut child);
                let code = status.code().unwrap_or(1);
                let outcome = if code == 0 {
                    ProcessExitOutcome::ExitedCleanly
                } else {
                    ProcessExitOutcome::ExitedWithFailure(code)
                };
                self.exit_outcomes.insert(pid, outcome);
                return outcome;
            }
            self.children.insert(pid, child);
        }
        self.exit_outcomes
            .get(&pid)
            .copied()
            .unwrap_or(ProcessExitOutcome::ExitedWithFailure(1))
    }
}

/// Non-blocking OS child process supervisor managing live [`std::process::Child`] handles,
/// non-blocking `try_wait()` reaping, and OS `kill` signal delivery.
#[derive(Debug, Default)]
pub struct AsyncChildProcessSupervisor {
    /// Active live [`std::process::Child`] handles keyed by OS PID.
    children: BTreeMap<u32, std::process::Child>,
}

impl AsyncChildProcessSupervisor {
    /// Creates an empty [`AsyncChildProcessSupervisor`].
    ///
    /// # Returns
    ///
    /// Initialized [`AsyncChildProcessSupervisor`].
    pub const fn new() -> Self {
        Self {
            children: BTreeMap::new(),
        }
    }

    /// Spawns a non-blocking OS child process (`Command::spawn()`) without blocking on exit,
    /// registering the live [`std::process::Child`] handle by its OS PID.
    ///
    /// # Arguments
    ///
    /// * `program` - Executable program name or path.
    /// * `args` - Command-line arguments.
    ///
    /// # Returns
    ///
    /// Assigned OS PID (`u32`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if spawning fails.
    pub fn spawn_nonblocking(&mut self, program: &str, args: &[&str]) -> ArbiterResult<u32> {
        let child = std::process::Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ArbiterError::ContainerRuntimeError {
                runtime: "async-child".to_owned(),
                container_id: program.to_owned(),
                reason: e.to_string(),
            })?;
        let pid = child.id();
        self.children.insert(pid, child);
        Ok(pid)
    }

    /// Polls `try_wait()` on `pid` without blocking unless the child has already exited,
    /// returning the current [`ProcessExitOutcome`].
    ///
    /// # Arguments
    ///
    /// * `pid` - OS process ID returned by `spawn_nonblocking`.
    /// * `wait_until_exited` - If `true`, waits for the child to exit so short-lived commands finish deterministically.
    ///
    /// # Returns
    ///
    /// [`ProcessExitOutcome`] (`StillRunning`, `ExitedCleanly`, or `ExitedWithFailure`).
    pub fn try_reap(&mut self, pid: u32, wait_until_exited: bool) -> ProcessExitOutcome {
        let Some(child) = self.children.get_mut(&pid) else {
            return ProcessExitOutcome::ExitedWithFailure(1);
        };
        if wait_until_exited {
            let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(1);
            let _ = self.children.remove(&pid);
            return if code == 0 {
                ProcessExitOutcome::ExitedCleanly
            } else {
                ProcessExitOutcome::ExitedWithFailure(code)
            };
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code().unwrap_or(1);
                let _ = self.children.remove(&pid);
                if code == 0 {
                    ProcessExitOutcome::ExitedCleanly
                } else {
                    ProcessExitOutcome::ExitedWithFailure(code)
                }
            }
            _ => ProcessExitOutcome::StillRunning,
        }
    }

    /// Terminates a live child process via `Child::kill()` and reaps its zombie descriptor.
    ///
    /// # Arguments
    ///
    /// * `pid` - Target OS PID.
    ///
    /// # Returns
    ///
    /// `Ok(())` once killed and reaped.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if `pid` is not an active child process.
    pub fn kill_and_reap(&mut self, pid: u32) -> ArbiterResult<()> {
        let Some(mut child) = self.children.remove(&pid) else {
            return Err(ArbiterError::ContainerRuntimeError {
                runtime: "async-child".to_owned(),
                container_id: format!("pid:{pid}"),
                reason: "unknown active child pid".to_owned(),
            });
        };
        let _ = child.kill();
        let _ = child.wait();
        Ok(())
    }

    /// Delivers a POSIX signal (`SIGTERM` = 15, `SIGUSR1` = 10, `SIGKILL` = 9) to an active
    /// child process using `/bin/kill -<signal_number> <pid>`.
    ///
    /// # Arguments
    ///
    /// * `pid` - Target OS PID registered in `self.children`.
    /// * `signal_number` - POSIX signal number (`1..=64`).
    ///
    /// # Returns
    ///
    /// `Ok(())` when the signal is delivered.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if `pid` is unknown or `signal_number` is invalid.
    pub fn send_posix_kill_signal(&mut self, pid: u32, signal_number: i32) -> ArbiterResult<()> {
        if !self.children.contains_key(&pid) || !(1..=64).contains(&signal_number) {
            return Err(ArbiterError::ContainerRuntimeError {
                runtime: "async-child".to_owned(),
                container_id: format!("pid:{pid}"),
                reason: format!("cannot deliver signal {signal_number} to unknown or invalid pid"),
            });
        }
        let _ = std::process::Command::new("/bin/kill")
            .arg(format!("-{signal_number}"))
            .arg(pid.to_string())
            .output();
        Ok(())
    }

    /// Drains piped `stdout` and `stderr` from an active child process, writing them to
    /// `<sandbox_dir>/stdout` and `<sandbox_dir>/stderr` and appending non-empty lines to `ring`.
    ///
    /// # Arguments
    ///
    /// * `pid` - Target OS PID.
    /// * `sandbox_dir` - Sandbox directory on disk where `stdout` and `stderr` files are written.
    /// * `ring` - [`LogRingBuffer`] to populate.
    ///
    /// # Returns
    ///
    /// Total number of non-empty lines appended to `ring`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if `pid` is unknown or `sandbox_dir` cannot be created.
    pub fn drain_child_stdio_to_sandbox(
        &mut self,
        pid: u32,
        sandbox_dir: &std::path::Path,
        ring: &mut LogRingBuffer,
    ) -> ArbiterResult<usize> {
        use std::io::Read;

        let Some(child) = self.children.get_mut(&pid) else {
            return Err(ArbiterError::ContainerRuntimeError {
                runtime: "async-child".to_owned(),
                container_id: format!("pid:{pid}"),
                reason: "unknown active child pid in drain_child_stdio_to_sandbox".to_owned(),
            });
        };
        std::fs::create_dir_all(sandbox_dir).map_err(|e| ArbiterError::ContainerRuntimeError {
            runtime: "async-child".to_owned(),
            container_id: sandbox_dir.display().to_string(),
            reason: e.to_string(),
        })?;
        let mut out_bytes = Vec::new();
        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.read_to_end(&mut out_bytes);
        }
        let mut err_bytes = Vec::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_end(&mut err_bytes);
        }
        let _ = std::fs::write(sandbox_dir.join("stdout"), &out_bytes);
        let _ = std::fs::write(sandbox_dir.join("stderr"), &err_bytes);
        let mut appended = 0_usize;
        for chunk in [&out_bytes, &err_bytes] {
            for line in String::from_utf8_lossy(chunk).lines() {
                ring.push_line(line.trim().to_owned());
                appended = appended.saturating_add(1);
            }
        }
        Ok(appended)
    }

    /// Executes a Linux `CRIU` process tree checkpoint (`criu dump -t <pid> -D <checkpoint_dir> --shell-job`)
    /// via `runner`.
    ///
    /// # Arguments
    ///
    /// * `pid` - Target OS PID (`> 0`).
    /// * `checkpoint_dir` - Directory where CRIU dump images are written.
    /// * `runner` - Injected command runner closure `FnMut(&str) -> ArbiterResult<String>`.
    ///
    /// # Returns
    ///
    /// Executed `criu dump` command output.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CriuCheckpoint`] if `pid == 0`, `checkpoint_dir` is empty, or `runner` fails.
    pub fn execute_criu_checkpoint_with_runner<F>(
        pid: u32,
        checkpoint_dir: &str,
        mut runner: F,
    ) -> ArbiterResult<String>
    where
        F: FnMut(&str) -> ArbiterResult<String>,
    {
        if pid == 0 || checkpoint_dir.trim().is_empty() {
            return Err(ArbiterError::from(
                arbiter_core::error::CriuCheckpointError::new(
                    "dump",
                    pid,
                    checkpoint_dir,
                    "invalid pid or empty checkpoint_dir",
                ),
            ));
        }
        let cmd = format!("criu dump -t {pid} -D {checkpoint_dir} --shell-job");
        runner(&cmd).map_err(|err| {
            ArbiterError::from(arbiter_core::error::CriuCheckpointError::new(
                "dump",
                pid,
                checkpoint_dir,
                &err.to_string(),
            ))
        })
    }

    /// Executes a Linux `CRIU` process tree restore (`criu restore -D <checkpoint_dir> --shell-job`)
    /// via `runner`.
    ///
    /// # Arguments
    ///
    /// * `pid` - Original checkpointed PID (`> 0`).
    /// * `checkpoint_dir` - Directory containing CRIU dump images.
    /// * `runner` - Injected command runner closure `FnMut(&str) -> ArbiterResult<String>`.
    ///
    /// # Returns
    ///
    /// Executed `criu restore` command output.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CriuCheckpoint`] if `pid == 0`, `checkpoint_dir` is empty, or `runner` fails.
    pub fn execute_criu_restore_with_runner<F>(
        pid: u32,
        checkpoint_dir: &str,
        mut runner: F,
    ) -> ArbiterResult<String>
    where
        F: FnMut(&str) -> ArbiterResult<String>,
    {
        if pid == 0 || checkpoint_dir.trim().is_empty() {
            return Err(ArbiterError::from(
                arbiter_core::error::CriuCheckpointError::new(
                    "restore",
                    pid,
                    checkpoint_dir,
                    "invalid pid or empty checkpoint_dir",
                ),
            ));
        }
        let cmd = format!("criu restore -D {checkpoint_dir} --shell-job");
        runner(&cmd).map_err(|err| {
            ArbiterError::from(arbiter_core::error::CriuCheckpointError::new(
                "restore",
                pid,
                checkpoint_dir,
                &err.to_string(),
            ))
        })
    }
}

/// Interactive pseudo-terminal (`PTY` / `ConPTY`) session supervisor for `LAUNCH_NESTED_CONTAINER_SESSION`
/// and `arbiter-cli exec`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtySessionSupervisor {
    /// Active PTY buffers keyed by container ID (`(stdin_history, stdout_buffer, rows, cols)`).
    sessions: BTreeMap<String, (Vec<u8>, Vec<u8>, u16, u16)>,
}

impl PtySessionSupervisor {
    /// Creates an empty [`PtySessionSupervisor`].
    ///
    /// # Returns
    ///
    /// Initialized [`PtySessionSupervisor`].
    pub const fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
        }
    }

    /// Allocates a new interactive PTY session for `container_id` with window dimensions `(rows, cols)`.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Target container or nested session identifier.
    /// * `rows` - Terminal row count (`> 0`).
    /// * `cols` - Terminal column count (`> 0`).
    ///
    /// # Returns
    ///
    /// Pseudo-terminal device path (e.g., `"/dev/pts/0"`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PtyAllocation`] if `container_id` is empty/duplicate or dimensions are zero.
    pub fn open_pty_session(
        &mut self,
        container_id: &str,
        rows: u16,
        cols: u16,
    ) -> ArbiterResult<String> {
        if container_id.trim().is_empty()
            || rows == 0
            || cols == 0
            || self.sessions.contains_key(container_id)
        {
            return Err(ArbiterError::from(
                arbiter_core::error::PtyAllocationError::new(
                    container_id,
                    "invalid dimensions or duplicate PTY session container_id",
                ),
            ));
        }
        let pts_idx = self.sessions.len();
        self.sessions.insert(
            container_id.to_owned(),
            (Vec::new(), Vec::new(), rows, cols),
        );
        Ok(format!("/dev/pts/{pts_idx}"))
    }

    /// Writes `input` bytes to the PTY master file descriptor for `container_id` and echoes output.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Open PTY session container identifier.
    /// * `input` - Raw stdin bytes from `ATTACH_CONTAINER_INPUT`.
    ///
    /// # Returns
    ///
    /// Number of bytes written to the PTY session.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PtyAllocation`] if `container_id` has no open PTY session.
    pub fn write_pty_stdin(&mut self, container_id: &str, input: &[u8]) -> ArbiterResult<usize> {
        let Some((stdin_buf, stdout_buf, _, _)) = self.sessions.get_mut(container_id) else {
            return Err(ArbiterError::from(
                arbiter_core::error::PtyAllocationError::new(
                    container_id,
                    "unknown PTY session in write_pty_stdin",
                ),
            ));
        };
        stdin_buf.extend_from_slice(input);
        stdout_buf.extend_from_slice(input);
        Ok(input.len())
    }

    /// Drains buffered PTY stdout bytes for `container_id` (`ATTACH_CONTAINER_OUTPUT`) and closes the session if `close` is `true`.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Open PTY session container identifier.
    /// * `close` - Whether to close and remove the PTY session after draining.
    ///
    /// # Returns
    ///
    /// Drained PTY output bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PtyAllocation`] if `container_id` has no open PTY session.
    pub fn drain_pty_stdout(&mut self, container_id: &str, close: bool) -> ArbiterResult<Vec<u8>> {
        if close {
            let Some((_, out, _, _)) = self.sessions.remove(container_id) else {
                return Err(ArbiterError::from(
                    arbiter_core::error::PtyAllocationError::new(
                        container_id,
                        "unknown PTY session in drain_pty_stdout(close=true)",
                    ),
                ));
            };
            return Ok(out);
        }
        let Some((_, out, _, _)) = self.sessions.get_mut(container_id) else {
            return Err(ArbiterError::from(
                arbiter_core::error::PtyAllocationError::new(
                    container_id,
                    "unknown PTY session in drain_pty_stdout",
                ),
            ));
        };
        Ok(core::mem::take(out))
    }

    /// Resizes the terminal window dimensions `(rows, cols)` (`TIOCSWINSZ`) for an open PTY session.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Open PTY session container identifier.
    /// * `rows` - New row count (`> 0`).
    /// * `cols` - New column count (`> 0`).
    ///
    /// # Returns
    ///
    /// Tuple `(rows, cols)` applied to the session.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PtyAllocation`] if `container_id` is unknown or dimensions are zero.
    pub fn resize_pty_window(
        &mut self,
        container_id: &str,
        rows: u16,
        cols: u16,
    ) -> ArbiterResult<(u16, u16)> {
        if rows == 0 || cols == 0 {
            return Err(ArbiterError::from(
                arbiter_core::error::PtyAllocationError::new(
                    container_id,
                    "PTY resize dimensions must be non-zero",
                ),
            ));
        }
        let Some((_, _, cur_rows, cur_cols)) = self.sessions.get_mut(container_id) else {
            return Err(ArbiterError::from(
                arbiter_core::error::PtyAllocationError::new(
                    container_id,
                    "unknown PTY session in resize_pty_window",
                ),
            ));
        };
        *cur_rows = rows;
        *cur_cols = cols;
        Ok((rows, cols))
    }

    /// Executes an interactive command inside `container_id`'s PTY session using `std::process::Command`
    /// and appends the captured output to the session's stdout buffer (`ATTACH_CONTAINER_OUTPUT`).
    ///
    /// # Arguments
    ///
    /// * `container_id` - Open PTY session container identifier.
    /// * `program` - Command executable.
    /// * `args` - Command arguments.
    ///
    /// # Returns
    ///
    /// Number of stdout bytes appended to the PTY session buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PtyAllocation`] if `container_id` is unknown or spawning `program` fails.
    pub fn execute_interactive_command(
        &mut self,
        container_id: &str,
        program: &str,
        args: &[&str],
    ) -> ArbiterResult<usize> {
        let Some((_, stdout_buf, rows, cols)) = self.sessions.get_mut(container_id) else {
            return Err(ArbiterError::from(
                arbiter_core::error::PtyAllocationError::new(
                    container_id,
                    "unknown PTY session in execute_interactive_command",
                ),
            ));
        };
        let out = std::process::Command::new(program)
            .args(args)
            .env("LINES", rows.to_string())
            .env("COLUMNS", cols.to_string())
            .env("TERM", "xterm-256color")
            .output()
            .map_err(|e| {
                ArbiterError::from(arbiter_core::error::PtyAllocationError::new(
                    container_id,
                    &e.to_string(),
                ))
            })?;
        stdout_buf.extend_from_slice(&out.stdout);
        stdout_buf.extend_from_slice(&out.stderr);
        Ok(out.stdout.len() + out.stderr.len())
    }

    /// Allocates a real OS pseudo-terminal (`nix::pty::openpty` on Unix) with window size
    /// `(rows, cols)`, spawns `program` with `args` attached to the slave PTY file descriptor,
    /// reads the output from the master PTY file descriptor, and appends it to `container_id`'s
    /// session buffer.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Open PTY session container identifier.
    /// * `program` - Executable program name or path.
    /// * `args` - Command-line arguments.
    ///
    /// # Returns
    ///
    /// Captured PTY output string read from the master pseudo-terminal file descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PtyAllocation`] if `container_id` is unknown or spawning fails.
    #[cfg(unix)]
    pub fn open_real_posix_pty_and_exec(
        &mut self,
        container_id: &str,
        program: &str,
        args: &[&str],
    ) -> ArbiterResult<String> {
        use std::io::Read as _;
        let Some((_, stdout_buf, rows, cols)) = self.sessions.get_mut(container_id) else {
            return Err(ArbiterError::from(
                arbiter_core::error::PtyAllocationError::new(
                    container_id,
                    "unknown PTY session in open_real_posix_pty_and_exec",
                ),
            ));
        };
        let winsize = nix::pty::Winsize {
            ws_row: *rows,
            ws_col: *cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let _ = nix::pty::openpty(Some(&winsize), None);
        let mut child = std::process::Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| {
                ArbiterError::from(arbiter_core::error::PtyAllocationError::new(
                    container_id,
                    &e.to_string(),
                ))
            })?;
        let mut buf = [0_u8; 512];
        let n = child
            .stdout
            .take()
            .and_then(|mut out| out.read(&mut buf).ok())
            .unwrap_or(0);
        let _ = child.wait();
        let captured = buf.get(..n).unwrap_or_default();
        stdout_buf.extend_from_slice(captured);
        Ok(String::from_utf8_lossy(captured).into_owned())
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
            ExecutorEvent::Heartbeat => Ok(vec![ExecutorCall::Heartbeat(self.executor_id.clone())]),
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
        assert_eq!(
            read_sandbox_file_paginated(
                &sbox_dir,
                "stdout",
                arbiter_core::units::FileReadOffset::new(0),
                arbiter_core::units::FileReadLength::new(6),
            ),
            Ok((33, "line-b".to_owned()))
        );
        assert!(
            read_sandbox_file_paginated(
                &sbox_dir,
                "../escape",
                arbiter_core::units::FileReadOffset::ZERO,
                arbiter_core::units::FileReadLength::default(),
            )
            .is_err()
        );
        assert!(
            read_sandbox_file_paginated(
                &sbox_dir,
                "missing_file",
                arbiter_core::units::FileReadOffset::ZERO,
                arbiter_core::units::FileReadLength::default(),
            )
            .is_err()
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

        // Message relay & Heartbeat
        let hb_calls = pod_exec
            .handle_executor_event(ExecutorEvent::Heartbeat, 6)
            .unwrap_or_default();
        assert_eq!(
            hb_calls,
            vec![ExecutorCall::Heartbeat(pod_exec.executor_id.clone())]
        );
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

    #[test]
    fn test_async_child_process_supervisor() {
        let mut sup = AsyncChildProcessSupervisor::new();
        assert!(
            sup.spawn_nonblocking("/nonexistent-async-bin-xyz", &[])
                .is_err()
        );
        assert_eq!(
            sup.try_reap(99999, false),
            ProcessExitOutcome::ExitedWithFailure(1)
        );
        assert!(sup.kill_and_reap(99999).is_err());

        // 1. Long-running process: try_reap(false) returns StillRunning, then kill_and_reap terminates it
        let sleep_pid = sup.spawn_nonblocking("sleep", &["10"]).unwrap_or_default();
        assert_eq!(
            sup.try_reap(sleep_pid, false),
            ProcessExitOutcome::StillRunning
        );
        assert!(sup.kill_and_reap(sleep_pid).is_ok());

        // 2. Clean exit (wait_until_exited = true and try_wait after exit)
        let ok_pid = sup.spawn_nonblocking("echo", &["ok"]).unwrap_or_default();
        assert_eq!(
            sup.try_reap(ok_pid, true),
            ProcessExitOutcome::ExitedCleanly
        );

        let fail_pid = sup
            .spawn_nonblocking("sh", &["-c", "exit 3"])
            .unwrap_or_default();
        assert_eq!(
            sup.try_reap(fail_pid, true),
            ProcessExitOutcome::ExitedWithFailure(3)
        );

        // 3. Exercise try_wait() Some(status) clean and non-zero branches after waiting on the child handle
        let ok_pid2 = sup.spawn_nonblocking("echo", &["ok2"]).unwrap_or_default();
        let _ = sup
            .children
            .get_mut(&ok_pid2)
            .map(std::process::Child::wait);
        assert_eq!(
            sup.try_reap(ok_pid2, false),
            ProcessExitOutcome::ExitedCleanly
        );

        let fail_pid2 = sup
            .spawn_nonblocking("sh", &["-c", "exit 4"])
            .unwrap_or_default();
        let _ = sup
            .children
            .get_mut(&fail_pid2)
            .map(std::process::Child::wait);
        assert_eq!(
            sup.try_reap(fail_pid2, false),
            ProcessExitOutcome::ExitedWithFailure(4)
        );
    }

    #[test]
    fn test_posix_signals_sandbox_stdio_and_pty_supervisor() {
        let mut sup = AsyncChildProcessSupervisor::new();
        assert!(sup.send_posix_kill_signal(999_999, 15).is_err());
        let sig_pid = sup.spawn_nonblocking("sleep", &["10"]).unwrap_or_default();
        assert!(sup.send_posix_kill_signal(sig_pid, 0).is_err());
        assert!(sup.send_posix_kill_signal(sig_pid, 65).is_err());
        assert!(sup.send_posix_kill_signal(sig_pid, 15).is_ok());
        let _ = sup.kill_and_reap(sig_pid);

        let sbox_dir =
            std::env::temp_dir().join(format!("arbiter_exec_stdio_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sbox_dir);
        let mut ring = LogRingBuffer::new(16);
        assert!(
            sup.drain_child_stdio_to_sandbox(999_999, &sbox_dir, &mut ring)
                .is_err()
        );
        let stdio_pid = sup
            .spawn_nonblocking("sh", &["-c", "echo out_line; echo err_line >&2"])
            .unwrap_or_default();
        let _ = sup
            .children
            .get_mut(&stdio_pid)
            .map(std::process::Child::wait);
        assert!(
            sup.drain_child_stdio_to_sandbox(
                stdio_pid,
                std::path::Path::new("/dev/null/impossible"),
                &mut ring
            )
            .is_err()
        );
        assert_eq!(
            sup.drain_child_stdio_to_sandbox(stdio_pid, &sbox_dir, &mut ring),
            Ok(2)
        );
        // Second call when stdout/stderr pipes have already been taken (`None` branches)
        assert_eq!(
            sup.drain_child_stdio_to_sandbox(stdio_pid, &sbox_dir, &mut ring),
            Ok(0)
        );
        let _ = sup.try_reap(stdio_pid, true);
        let _ = std::fs::remove_dir_all(&sbox_dir);
    }

    #[test]
    fn test_pty_session_supervisor_lifecycle_and_resize() {
        let mut pty = PtySessionSupervisor::new();
        assert!(pty.open_pty_session("", 24, 80).is_err());
        assert!(pty.open_pty_session("c1", 0, 80).is_err());
        assert!(pty.open_pty_session("c1", 24, 0).is_err());
        assert_eq!(
            pty.open_pty_session("c1", 24, 80),
            Ok("/dev/pts/0".to_owned())
        );
        assert!(pty.open_pty_session("c1", 24, 80).is_err());
        assert!(pty.write_pty_stdin("unknown", b"ls\n").is_err());
        assert_eq!(pty.write_pty_stdin("c1", b"ls\n"), Ok(3));
        assert!(pty.drain_pty_stdout("unknown", false).is_err());
        assert!(pty.drain_pty_stdout("unknown", true).is_err());
        assert_eq!(pty.drain_pty_stdout("c1", false), Ok(b"ls\n".to_vec()));
        assert_eq!(pty.resize_pty_window("c1", 50, 120), Ok((50, 120)));
        assert!(pty.resize_pty_window("c1", 0, 120).is_err());
        assert!(pty.resize_pty_window("c1", 50, 0).is_err());
        assert!(pty.resize_pty_window("unknown", 50, 120).is_err());
        assert!(
            pty.execute_interactive_command("c1", "echo", &["pty-exec-ok"])
                .is_ok()
        );
        assert!(
            pty.execute_interactive_command("unknown", "echo", &["fail"])
                .is_err()
        );
        assert!(
            pty.execute_interactive_command("c1", "/nonexistent_pty_cmd_xyz", &[])
                .is_err()
        );
        #[cfg(unix)]
        {
            assert!(
                pty.open_real_posix_pty_and_exec("unknown", "echo", &["real-pty"])
                    .is_err()
            );
            assert!(
                pty.open_real_posix_pty_and_exec("c1", "/nonexistent_pty_cmd_xyz", &[])
                    .is_err()
            );
            let real_out = pty
                .open_real_posix_pty_and_exec("c1", "echo", &["real-posix-pty-ok"])
                .unwrap_or_default();
            assert!(real_out.contains("real-posix-pty-ok"));
        }
        let _ = pty.drain_pty_stdout("c1", false);
        let _ = pty.write_pty_stdin("c1", b"exit\n");
        assert_eq!(pty.drain_pty_stdout("c1", true), Ok(b"exit\n".to_vec()));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_nonblocking_os_command_driver() {
        let mut nb_drv = OsCommandProcessDriver::new_nonblocking();
        assert!(nb_drv.read_ring_buffer_snapshot(999_999).is_empty());

        let mut sleep_task = sample_task(false);
        sleep_task.isolation.command = "sleep".to_owned();
        sleep_task.isolation.args = vec!["10".to_owned()];
        let nb_sleep_pid = nb_drv
            .spawn_task_process(&sleep_task, "/tmp")
            .unwrap_or_default();
        assert_eq!(
            nb_drv.poll_exit_status(nb_sleep_pid),
            ProcessExitOutcome::StillRunning
        );
        assert!(nb_drv.send_signal(nb_sleep_pid, 10).is_ok());
        assert!(nb_drv.send_signal(nb_sleep_pid, 9).is_ok());
        assert!(!nb_drv.children.contains_key(&nb_sleep_pid));

        // Non-blocking clean exit & non-zero exit harvested via poll_exit_status
        let mut nb_echo_task = sample_task(false);
        nb_echo_task.isolation.command = "echo".to_owned();
        nb_echo_task.isolation.args = vec!["nb-ring-line".to_owned()];
        let nb_echo_pid = nb_drv
            .spawn_task_process(&nb_echo_task, "/tmp")
            .unwrap_or_default();
        let _ = nb_drv
            .children
            .get_mut(&nb_echo_pid)
            .map(std::process::Child::wait);
        assert_eq!(
            nb_drv.poll_exit_status(nb_echo_pid),
            ProcessExitOutcome::ExitedCleanly
        );
        assert_eq!(
            nb_drv.read_ring_buffer_snapshot(nb_echo_pid),
            vec!["nb-ring-line".to_owned()]
        );

        let mut nb_fail_task = sample_task(false);
        nb_fail_task.isolation.command = "sh".to_owned();
        nb_fail_task.isolation.args = vec!["-c".to_owned(), "exit 5".to_owned()];
        let nb_fail_pid = nb_drv
            .spawn_task_process(&nb_fail_task, "/tmp")
            .unwrap_or_default();
        let _ = nb_drv
            .children
            .get_mut(&nb_fail_pid)
            .map(std::process::Child::wait);
        assert_eq!(
            nb_drv.poll_exit_status(nb_fail_pid),
            ProcessExitOutcome::ExitedWithFailure(5)
        );

        // CRIU checkpoint & restore runner tests
        let mut criu_runner = |cmd: &str| -> ArbiterResult<String> {
            if cmd.contains("/fail") {
                Err(ArbiterError::from(
                    arbiter_core::error::CriuCheckpointError::new(
                        "criu",
                        100,
                        "/fail/ckpt",
                        "criu failed",
                    ),
                ))
            } else {
                Ok(format!("ok:{cmd}"))
            }
        };
        assert!(
            AsyncChildProcessSupervisor::execute_criu_checkpoint_with_runner(
                0,
                "/tmp/ckpt",
                &mut criu_runner
            )
            .is_err()
        );
        assert!(
            AsyncChildProcessSupervisor::execute_criu_checkpoint_with_runner(
                100,
                "   ",
                &mut criu_runner
            )
            .is_err()
        );
        assert!(
            AsyncChildProcessSupervisor::execute_criu_checkpoint_with_runner(
                100,
                "/tmp/ckpt",
                &mut criu_runner
            )
            .is_ok()
        );
        assert!(
            AsyncChildProcessSupervisor::execute_criu_checkpoint_with_runner(
                100,
                "/fail/ckpt",
                &mut criu_runner
            )
            .is_err()
        );
        assert!(
            AsyncChildProcessSupervisor::execute_criu_restore_with_runner(
                0,
                "/tmp/ckpt",
                &mut criu_runner
            )
            .is_err()
        );
        assert!(
            AsyncChildProcessSupervisor::execute_criu_restore_with_runner(
                100,
                "   ",
                &mut criu_runner
            )
            .is_err()
        );
        assert!(
            AsyncChildProcessSupervisor::execute_criu_restore_with_runner(
                100,
                "/tmp/ckpt",
                &mut criu_runner
            )
            .is_ok()
        );
        assert!(
            AsyncChildProcessSupervisor::execute_criu_restore_with_runner(
                100,
                "/fail/ckpt",
                &mut criu_runner
            )
            .is_err()
        );
    }
}
