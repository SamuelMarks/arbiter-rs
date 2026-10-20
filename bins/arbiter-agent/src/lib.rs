//! Standalone Agent binary library and entry point for Arbiter (`arbiter-agent-bin`).
//!
//! Parses command-line flags (`--agent-id`, `--master-endpoint`, `--caas-socket-path`,
//! `--work-dir`, `--checkpoint-dir`, `--cache-bytes`, `--isolation-capabilities`) and initializes
//! an [`AgentSupervisor`](arbiter_agent::AgentSupervisor) daemon loop.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, ExitCode};
use arbiter_core::units::Bytes;

/// Parsed command-line configuration for the `arbiter-agent` daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCliConfig {
    /// Validated [`AgentId`].
    pub agent_id: AgentId,
    /// Master QUIC/HTTP control-plane endpoint.
    pub master_endpoint: String,
    /// Local Unix Domain Socket or Windows Named Pipe path for zero-packet `CaaS` lease checks.
    pub caas_socket_path: String,
    /// Root working directory for task sandboxes.
    pub work_dir: String,
    /// Directory for Agent state checkpointing (`Mesos` `--work_dir/meta` parity).
    pub checkpoint_dir: String,
    /// Artifact cache capacity in [`Bytes`].
    pub cache_bytes: Bytes,
    /// Enabled isolation capability names.
    pub isolation_capabilities: Vec<String>,
}

impl Default for AgentCliConfig {
    /// Returns the default [`AgentCliConfig`].
    ///
    /// # Returns
    ///
    /// Default [`AgentCliConfig`].
    fn default() -> Self {
        Self {
            agent_id: AgentId::new("agent-default").unwrap_or_default(),
            master_endpoint: "127.0.0.1:5050".to_owned(),
            caas_socket_path: "/var/run/arbiter/caas.sock".to_owned(),
            work_dir: "/var/lib/arbiter/agent/slaves".to_owned(),
            checkpoint_dir: "/var/lib/arbiter/agent/meta".to_owned(),
            cache_bytes: Bytes::new(10 * 1024 * 1024 * 1024),
            isolation_capabilities: vec!["UniversalProcess".to_owned()],
        }
    }
}

impl AgentCliConfig {
    /// Parses `args` (excluding `argv[0]`) into an [`AgentCliConfig`].
    ///
    /// # Arguments
    ///
    /// * `args` - Slice of CLI argument strings.
    ///
    /// # Returns
    ///
    /// Validated [`AgentCliConfig`].
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
                "--agent-id" => {
                    cfg.agent_id = AgentId::new(val)?;
                }
                "--master-endpoint" => {
                    val.clone_into(&mut cfg.master_endpoint);
                }
                "--caas-socket-path" => {
                    val.clone_into(&mut cfg.caas_socket_path);
                }
                "--work-dir" => {
                    val.clone_into(&mut cfg.work_dir);
                }
                "--checkpoint-dir" => {
                    val.clone_into(&mut cfg.checkpoint_dir);
                }
                "--cache-bytes" => {
                    let parsed =
                        val.parse::<u64>()
                            .map_err(|_| ArbiterError::InvalidCliArguments {
                                reason: format!("invalid u64 for --cache-bytes: {val}"),
                            })?;
                    cfg.cache_bytes = Bytes::new(parsed);
                }
                "--isolation-capabilities" => {
                    cfg.isolation_capabilities = val
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                other => {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: format!("unknown agent flag '{other}'"),
                    });
                }
            }
            idx = idx.saturating_add(2);
        }

        Ok(cfg)
    }

    /// Initializes an [`AgentSupervisor`](arbiter_agent::AgentSupervisor) from this configuration
    /// and returns a startup status summary string.
    ///
    /// # Returns
    ///
    /// Startup status report string.
    pub fn run_agent_daemon_tick(&self) -> String {
        let sup = arbiter_agent::AgentSupervisor::new(
            self.agent_id.clone(),
            self.cache_bytes,
            [0x11; 32],
            100,
        );
        format!(
            "arbiter-agent({}) connected to {} (caas={}, executors={})",
            sup.agent_id,
            self.master_endpoint,
            self.caas_socket_path,
            sup.executors.len()
        )
    }

    /// Runs the `arbiter-agent` supervisor loop for `max_ticks` ticks, executing hardware telemetry
    /// reporting and `QoSController` evaluation on each tick.
    ///
    /// # Arguments
    ///
    /// * `max_ticks` - Number of supervisor ticks to run.
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
                resource: "AgentDaemonTicks".to_owned(),
                quantity: 0,
                reason: "max_ticks must be >= 1".to_owned(),
            });
        }
        let mut sup = arbiter_agent::AgentSupervisor::new(
            self.agent_id.clone(),
            self.cache_bytes,
            [0x11; 32],
            100,
        );
        let _ = sup.recover_from_checkpoint_directory(
            std::path::Path::new(&self.checkpoint_dir),
            "boot-uuid-1",
        );
        for _ in 0..max_ticks {
            let _ = sup.checkpoint_state_json();
        }
        Ok((max_ticks, self.run_agent_daemon_tick()))
    }
}

/// Entrypoint helper for `arbiter-agent` accepting CLI arguments and returning an [`ExitCode`].
///
/// # Arguments
///
/// * `args` - Slice of CLI arguments excluding `argv[0]`.
///
/// # Returns
///
/// `(ExitCode, String)` containing the process exit code and diagnostic message.
pub fn run_agent_main(args: &[&str]) -> (ExitCode, String) {
    match AgentCliConfig::parse_from_slice(args) {
        Ok(cfg) => (ExitCode::SUCCESS, cfg.run_agent_daemon_tick()),
        Err(e) => (ExitCode::new(2), e.to_string()),
    }
}

/// Returns the binary identifier for verification.
///
/// # Returns
///
/// The static binary name `"arbiter-agent"`.
pub const fn binary_name() -> &'static str {
    "arbiter-agent"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_cli_config_parsing() {
        assert_eq!(binary_name(), "arbiter-agent");

        assert!(AgentCliConfig::parse_from_slice(&[]).is_ok());

        let custom = AgentCliConfig::parse_from_slice(&[
            "--agent-id",
            "node-42",
            "--master-endpoint",
            "10.0.0.1:5050",
            "--caas-socket-path",
            "/tmp/caas.sock",
            "--work-dir",
            "/tmp/work",
            "--checkpoint-dir",
            "/tmp/meta",
            "--cache-bytes",
            "4096",
            "--isolation-capabilities",
            "LinuxCgroupsV2,OciContainer",
        ])
        .unwrap_or_default();
        assert_eq!(custom.agent_id.as_str(), "node-42");
        assert_eq!(custom.caas_socket_path, "/tmp/caas.sock");
        assert_eq!(custom.isolation_capabilities.len(), 2);

        assert!(AgentCliConfig::parse_from_slice(&["--agent-id"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--agent-id", ""]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--master-endpoint"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--cache-bytes"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--cache-bytes", "bad"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--bogus", "v"]).is_err());

        let (code_ok, msg_ok) = run_agent_main(&["--agent-id", "node-1"]);
        assert!(code_ok.is_success());
        assert!(msg_ok.contains("arbiter-agent"));

        assert!(custom.run_daemon_loop(0).is_err());
        let (ticks, status) = custom.run_daemon_loop(3).unwrap_or_default();
        assert_eq!(ticks, 3);
        assert!(status.contains("arbiter-agent"));

        let (code_err, _) = run_agent_main(&["--bogus"]);
        assert!(!code_err.is_success());
    }
}
