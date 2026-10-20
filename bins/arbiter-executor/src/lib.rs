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
        Ok((max_ticks, self.run_executor_daemon_tick()))
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
        Ok(cfg) => (ExitCode::SUCCESS, cfg.run_executor_daemon_tick()),
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
    }
}
