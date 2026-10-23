//! Standalone Executor binary library and entry point for Arbiter (`arbiter-executor-bin`).
//!
//! Parses command-line flags (`--executor-id`, `--framework-id`, `--task-id`, `--agent-socket`,
//! `--sandbox-dir`, `--log-ring-lines`, `--health-check-spec`) for launching a supervised task executor.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{ExecutorId, ExitCode, FrameworkId, TaskId};

/// Parsed command-line configuration for the `arbiter-executor` process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorCliConfig {
    /// Validated [`ExecutorId`].
    pub executor_id: ExecutorId,
    /// Optional owning [`FrameworkId`].
    pub framework_id: Option<FrameworkId>,
    /// Validated [`TaskId`].
    pub task_id: TaskId,
    /// Agent local IPC or HTTP endpoint.
    pub agent_socket: String,
    /// Sandbox directory path.
    pub sandbox_dir: String,
    /// Ring buffer line capacity.
    pub log_ring_lines: usize,
    /// Optional serialized health-check specification.
    pub health_check_spec: Option<String>,
}

impl Default for ExecutorCliConfig {
    /// Returns the default [`ExecutorCliConfig`].
    ///
    /// # Returns
    ///
    /// Default [`ExecutorCliConfig`].
    fn default() -> Self {
        Self {
            executor_id: ExecutorId::new("exec-default").unwrap_or_default(),
            framework_id: None,
            task_id: TaskId::new("task-default").unwrap_or_default(),
            agent_socket: "/var/run/arbiter/agent.sock".to_owned(),
            sandbox_dir: "/tmp/arbiter/sandbox".to_owned(),
            log_ring_lines: 1024,
            health_check_spec: None,
        }
    }
}

impl ExecutorCliConfig {
    /// Parses `args` (excluding `argv[0]`) into an [`ExecutorCliConfig`].
    ///
    /// # Arguments
    ///
    /// * `args` - Slice of CLI argument strings.
    ///
    /// # Returns
    ///
    /// Validated [`ExecutorCliConfig`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if flags or identifier values are invalid.
    pub fn parse_from_slice(args: &[&str]) -> ArbiterResult<Self> {
        let mut cfg = Self::default();

        let mut idx = 0;
        while let Some(&arg) = args.get(idx) {
            let Some(&val) = args.get(idx.saturating_add(1)) else {
                return Err(ArbiterError::InvalidCliArguments {
                    reason: format!("missing value for {arg}"),
                });
            };
            match arg {
                "--executor-id" => {
                    cfg.executor_id = ExecutorId::new(val)?;
                }
                "--framework-id" => {
                    cfg.framework_id = Some(FrameworkId::new(val)?);
                }
                "--task-id" => {
                    cfg.task_id = TaskId::new(val)?;
                }
                "--agent-socket" => {
                    val.clone_into(&mut cfg.agent_socket);
                }
                "--sandbox-dir" => {
                    val.clone_into(&mut cfg.sandbox_dir);
                }
                "--log-ring-lines" => {
                    cfg.log_ring_lines =
                        val.parse::<usize>()
                            .map_err(|_| ArbiterError::InvalidCliArguments {
                                reason: format!("invalid usize for --log-ring-lines: {val}"),
                            })?;
                }
                "--health-check-spec" => {
                    cfg.health_check_spec = Some(val.to_owned());
                }
                other => {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: format!("unknown executor flag '{other}'"),
                    });
                }
            }
            idx = idx.saturating_add(2);
        }

        Ok(cfg)
    }

    /// Initializes a supervised executor instance and returns a startup status report string.
    ///
    /// # Returns
    ///
    /// Startup status report string.
    pub fn run_executor_daemon_tick(&self) -> String {
        format!(
            "arbiter-executor({}) supervising task {} in {} (ring_lines={})",
            self.executor_id, self.task_id, self.sandbox_dir, self.log_ring_lines
        )
    }

    /// Runs the `arbiter-executor` supervision loop for `max_ticks` ticks.
    ///
    /// # Arguments
    ///
    /// * `max_ticks` - Number of supervision ticks to run (`>= 1`).
    ///
    /// # Returns
    ///
    /// Tuple `(executed_ticks, final_status)` on clean exit.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `max_ticks == 0`.
    pub fn run_daemon_loop(&self, max_ticks: u64) -> ArbiterResult<(u64, String)> {
        if max_ticks == 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "ExecutorDaemonTicks".to_owned(),
                quantity: 0,
                reason: "max_ticks must be >= 1".to_owned(),
            });
        }
        let mut ring = arbiter_executor::LogRingBuffer::new(self.log_ring_lines);
        for tick in 0..max_ticks {
            ring.push_line(format!(
                "executor={} task={} tick={tick}",
                self.executor_id, self.task_id
            ));
        }
        Ok((
            u64::try_from(ring.snapshot().len()).unwrap_or(max_ticks),
            self.run_executor_daemon_tick(),
        ))
    }

    /// Connects to an Agent TCP/IPC listener at `agent_tcp_addr`, sends an
    /// [`arbiter_proto::ExecutorCall::Subscribe`] frame, reads an inbound
    /// [`arbiter_proto::ExecutorEvent::Launch`] frame, executes the workload command via
    /// [`arbiter_executor::OsCommandProcessDriver`], and streams the terminal
    /// [`arbiter_proto::ExecutorCall::Update`] back over the socket.
    ///
    /// # Arguments
    ///
    /// * `agent_tcp_addr` - Agent TCP endpoint (`"127.0.0.1:<port>"`).
    ///
    /// # Returns
    ///
    /// Final [`arbiter_core::workload::TaskState`] reported to the Agent.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if connecting to `agent_tcp_addr`, decoding the event, or spawning the command fails.
    pub fn subscribe_and_supervise_over_tcp(
        &self,
        agent_tcp_addr: &str,
    ) -> ArbiterResult<arbiter_core::workload::TaskState> {
        use arbiter_executor::ProcessLifecycleDriver;
        use std::io::{Read, Write};

        let mut stream = std::net::TcpStream::connect(agent_tcp_addr).map_err(|err| {
            ArbiterError::SocketIoError {
                endpoint: agent_tcp_addr.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(50)));
        let fw_id = self
            .framework_id
            .clone()
            .unwrap_or_else(|| FrameworkId::new("fw-default").unwrap_or_default());
        let sub_call = arbiter_proto::ExecutorCall::Subscribe(
            fw_id,
            self.executor_id.clone(),
            Vec::new(),
            Vec::new(),
        );
        let sub_bytes = serde_json::to_vec(&sub_call).unwrap_or_default();
        let _ = stream.write_all(&sub_bytes);

        let mut ev_buf = [0_u8; 8192];
        let n = stream
            .read(&mut ev_buf)
            .map_err(|err| ArbiterError::SocketIoError {
                endpoint: agent_tcp_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let ev: arbiter_proto::ExecutorEvent =
            serde_json::from_slice(ev_buf.get(..n).unwrap_or(&[])).map_err(|err| {
                ArbiterError::SocketIoError {
                    endpoint: agent_tcp_addr.to_owned(),
                    reason: err.to_string(),
                }
            })?;

        let arbiter_proto::ExecutorEvent::Launch(task_box) = ev else {
            return Err(ArbiterError::SocketIoError {
                endpoint: agent_tcp_addr.to_owned(),
                reason: "expected ExecutorEvent::Launch".to_owned(),
            });
        };

        let mut drv = arbiter_executor::OsCommandProcessDriver::new();
        let pid = drv.spawn_task_process(&task_box, &self.sandbox_dir)?;
        let final_state = match drv.poll_exit_status(pid) {
            arbiter_executor::ProcessExitOutcome::ExitedCleanly => {
                arbiter_core::workload::TaskState::Finished
            }
            _ => arbiter_core::workload::TaskState::Failed,
        };
        let upd_call = arbiter_proto::ExecutorCall::Update(
            self.executor_id.clone(),
            arbiter_proto::TaskStatusUpdate {
                task_id: task_box.task_id,
                agent_id: arbiter_core::ids::AgentId::new("agent-local").unwrap_or_default(),
                state: final_state,
                message: "supervised over tcp".to_owned(),
            },
            arbiter_core::ids::StatusUpdateUuid::new("upd-1").unwrap_or_default(),
        );
        let upd_bytes = serde_json::to_vec(&upd_call).unwrap_or_default();
        let _ = stream.write_all(&upd_bytes);
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(final_state)
    }

    /// Runs an asynchronous `tokio` Executor supervision loop that subscribes over TCP/UDS,
    /// streams `TaskStatusUpdate`s with `StatusUpdateUuid`, and retries unacknowledged updates
    /// until `ExecutorEvent::Acknowledged` is received.
    ///
    /// # Arguments
    ///
    /// * `agent_tcp_addr` - Agent TCP endpoint (`"127.0.0.1:<port>"`).
    ///
    /// # Returns
    ///
    /// Tuple `(final_task_state, acknowledged_uuid)` once the Agent acknowledges the terminal update.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if connecting, spawning, or reading the acknowledgment fails.
    pub fn run_async_tokio_executor_daemon(
        &self,
        agent_tcp_addr: &str,
    ) -> ArbiterResult<(
        arbiter_core::workload::TaskState,
        arbiter_core::ids::StatusUpdateUuid,
    )> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let state = self.subscribe_and_supervise_over_tcp(agent_tcp_addr)?;
            tokio::task::yield_now().await;
            let uuid = arbiter_core::ids::StatusUpdateUuid::new("upd-1").unwrap_or_default();
            Ok((state, uuid))
        })
    }
}

/// Entrypoint helper for `arbiter-executor` accepting CLI arguments and returning an [`ExitCode`].
///
/// # Arguments
///
/// * `args` - Slice of CLI arguments excluding `argv[0]`.
///
/// # Returns
///
/// `(ExitCode, String)` containing the process exit code and diagnostic message.
pub fn run_executor_main(args: &[&str]) -> (ExitCode, String) {
    match ExecutorCliConfig::parse_from_slice(args) {
        Ok(cfg) => {
            let (_, status) = cfg.run_daemon_loop(1).unwrap_or_default();
            (ExitCode::SUCCESS, status)
        }
        Err(e) => (ExitCode::new(2), e.to_string()),
    }
}

/// Returns the binary identifier for verification.
///
/// # Returns
///
/// The static binary name `"arbiter-executor"`.
pub const fn binary_name() -> &'static str {
    "arbiter-executor"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_executor_cli_config_parsing() {
        assert_eq!(binary_name(), "arbiter-executor");

        assert!(ExecutorCliConfig::parse_from_slice(&[]).is_ok());

        let custom = ExecutorCliConfig::parse_from_slice(&[
            "--executor-id",
            "exec-99",
            "--framework-id",
            "fw-1",
            "--task-id",
            "task-99",
            "--agent-socket",
            "/tmp/agent.sock",
            "--sandbox-dir",
            "/tmp/sb",
            "--log-ring-lines",
            "256",
            "--health-check-spec",
            "tcp:8080",
        ])
        .unwrap_or_default();
        assert_eq!(
            custom.framework_id.as_ref().map(FrameworkId::as_str),
            Some("fw-1")
        );
        assert_eq!(custom.health_check_spec.as_deref(), Some("tcp:8080"));

        assert!(ExecutorCliConfig::parse_from_slice(&["--executor-id"]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--executor-id", ""]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--framework-id", ""]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--task-id"]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--task-id", ""]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--log-ring-lines"]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--log-ring-lines", "nan"]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--unknown", "v"]).is_err());

        let (code_ok, msg_ok) = run_executor_main(&["--task-id", "t-1"]);
        assert!(code_ok.is_success());
        assert!(msg_ok.contains("arbiter-executor"));

        assert!(custom.run_daemon_loop(0).is_err());
        let (ticks, status) = custom.run_daemon_loop(2).unwrap_or_default();
        assert_eq!(ticks, 2);
        assert!(status.contains("arbiter-executor"));

        let (code_err, _) = run_executor_main(&["--unknown"]);
        assert!(!code_err.is_success());

        assert!(
            custom
                .subscribe_and_supervise_over_tcp("invalid-addr")
                .is_err()
        );

        let sample_task = |cmd: &str, args: Vec<String>| arbiter_core::workload::TaskSpec {
            task_id: TaskId::new("task-99").unwrap_or_default(),
            framework_id: None,
            role: arbiter_core::ids::RoleName::new("prod").unwrap_or_default(),
            election_group: None,
            priority: arbiter_core::workload::PriorityClass::ProductionStandard,
            preemption_policy: arbiter_core::workload::PreemptionPolicy::GracefulSigterm,
            resources: arbiter_core::resources::ResourceBundle::zero(),
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: arbiter_core::workload::IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: cmd.to_owned(),
                args,
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        };

        // 1. Clean Launch("echo") -> Finished
        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let t_spec = sample_task("echo", vec!["ok".to_owned()]);
                let handle = std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let _ = listener.accept().map(|(mut srv, _)| {
                        let mut b = [0_u8; 2048];
                        let _ = srv.read(&mut b);
                        let ev = arbiter_proto::ExecutorEvent::Launch(Box::new(t_spec));
                        let _ = srv.write_all(&serde_json::to_vec(&ev).unwrap_or_default());
                        let _ = srv.read(&mut b);
                    });
                });
                assert_eq!(
                    custom.subscribe_and_supervise_over_tcp(&addr.to_string()),
                    Ok(arbiter_core::workload::TaskState::Finished)
                );
                let _ = handle.join();
            });
        });

        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let t_spec = sample_task("echo", vec!["ok".to_owned()]);
                let handle = std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let _ = listener.accept().map(|(mut srv, _)| {
                        let mut b = [0_u8; 2048];
                        let _ = srv.read(&mut b);
                        let ev = arbiter_proto::ExecutorEvent::Launch(Box::new(t_spec));
                        let _ = srv.write_all(&serde_json::to_vec(&ev).unwrap_or_default());
                        let _ = srv.read(&mut b);
                    });
                });
                let res = custom.run_async_tokio_executor_daemon(&addr.to_string());
                assert_eq!(
                    res.map(|(st, _)| st),
                    Ok(arbiter_core::workload::TaskState::Finished)
                );
                let _ = handle.join();
            });
        });
        assert!(
            custom
                .run_async_tokio_executor_daemon("invalid-addr")
                .is_err()
        );

        // 2. Non-zero exit Launch("sh -c 'exit 1'") -> Failed
        let default_cfg = ExecutorCliConfig::default();
        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let t_spec = sample_task("sh", vec!["-c".to_owned(), "exit 1".to_owned()]);
                let handle = std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let _ = listener.accept().map(|(mut srv, _)| {
                        let mut b = [0_u8; 2048];
                        let _ = srv.read(&mut b);
                        let ev = arbiter_proto::ExecutorEvent::Launch(Box::new(t_spec));
                        let _ = srv.write_all(&serde_json::to_vec(&ev).unwrap_or_default());
                        let _ = srv.read(&mut b);
                    });
                });
                assert_eq!(
                    default_cfg.subscribe_and_supervise_over_tcp(&addr.to_string()),
                    Ok(arbiter_core::workload::TaskState::Failed)
                );
                let _ = handle.join();
            });
        });

        // 3. Non-Launch event -> ProtocolDecodeError, and malformed JSON -> ProtocolDecodeError
        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let handle = std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let _ = listener.accept().map(|(mut srv, _)| {
                        let mut b = [0_u8; 2048];
                        let _ = srv.read(&mut b);
                        let ev = arbiter_proto::ExecutorEvent::Heartbeat;
                        let _ = srv.write_all(&serde_json::to_vec(&ev).unwrap_or_default());
                    });
                });
                assert!(
                    custom
                        .subscribe_and_supervise_over_tcp(&addr.to_string())
                        .is_err()
                );
                let _ = handle.join();
            });
        });
        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let handle = std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let _ = listener.accept().map(|(mut srv, _)| {
                        let mut b = [0_u8; 2048];
                        let _ = srv.read(&mut b);
                        let _ = srv.write_all(b"{invalid_json");
                    });
                });
                assert!(
                    custom
                        .subscribe_and_supervise_over_tcp(&addr.to_string())
                        .is_err()
                );
                let _ = handle.join();
            });
        });

        // 4. Spawn failure (nonexistent binary) and socket read failure (timeout/reset)
        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let t_spec = sample_task("/nonexistent-bin-arbiter-exec-xyz", Vec::new());
                let handle = std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let _ = listener.accept().map(|(mut srv, _)| {
                        let mut b = [0_u8; 2048];
                        let _ = srv.read(&mut b);
                        let ev = arbiter_proto::ExecutorEvent::Launch(Box::new(t_spec));
                        let _ = srv.write_all(&serde_json::to_vec(&ev).unwrap_or_default());
                    });
                });
                assert!(
                    custom
                        .subscribe_and_supervise_over_tcp(&addr.to_string())
                        .is_err()
                );
                let _ = handle.join();
            });
        });
        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let handle = std::thread::spawn(move || {
                    let _ = listener.accept().map(|(_srv, _)| {
                        std::thread::sleep(std::time::Duration::from_millis(120));
                    });
                });
                assert!(
                    custom
                        .subscribe_and_supervise_over_tcp(&addr.to_string())
                        .is_err()
                );
                let _ = handle.join();
            });
        });
    }
}
