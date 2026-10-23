//! Multicall umbrella binary library and entry point for Arbiter (`arbiter`).
//!
//! Dispatches execution either by `argv[0]` binary basename (`arbiter-master`, `arbiter-agent`,
//! `arbiter-executor`, `arbiter-cli`) or by explicit first subcommand (`master`, `agent`,
//! `executor`, `cli`).

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_agent_bin::AgentCliConfig;
use arbiter_cli::CliSubcommand;
use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_executor_bin::ExecutorCliConfig;
use arbiter_master_bin::MasterCliConfig;

/// Resolved target mode of the `arbiter` multicall binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MulticallTarget {
    /// Master control-plane daemon.
    Master(MasterCliConfig),
    /// Agent node supervisor daemon.
    Agent(AgentCliConfig),
    /// Task process executor.
    Executor(ExecutorCliConfig),
    /// Operator CLI / TUI client.
    Cli(CliSubcommand),
}

impl MulticallTarget {
    /// Executes the resolved [`MulticallTarget`] persona and returns its formatted output report.
    ///
    /// # Returns
    ///
    /// Execution summary string.
    pub fn execute_target(&self) -> String {
        match self {
            Self::Master(cfg) => {
                if cfg.signal_mode == arbiter_master_bin::SignalSourceMode::ContinuousDaemon {
                    cfg.run_async_tokio_daemon()
                        .map(|(_, s)| s)
                        .unwrap_or_default()
                } else {
                    cfg.run_master_daemon_tick()
                }
            }
            Self::Agent(cfg) => {
                if cfg.daemon_mode {
                    cfg.run_async_tokio_supervisor_daemon(cfg.max_ticks.max(1))
                        .map(|(_, _, s)| s)
                        .unwrap_or_default()
                } else {
                    cfg.run_agent_daemon_tick()
                }
            }
            Self::Executor(cfg) => cfg.run_executor_daemon_tick(),
            Self::Cli(sub) => sub.execute_report(),
        }
    }
}

/// Dispatches an `argv` slice (including `argv[0]`) to the appropriate [`MulticallTarget`].
///
/// Inspects the basename of `argv[0]` (stripping any directory prefix and optional `.exe` suffix).
/// If `argv[0]` is `"arbiter"`, inspects `argv[1]` for the subcommand (`"master"`, `"agent"`,
/// `"executor"`, or `"cli"`).
///
/// # Arguments
///
/// * `argv` - Full argument vector starting with `argv[0]`.
///
/// # Returns
///
/// Resolved [`MulticallTarget`] with parsed configuration.
///
/// # Errors
///
/// Returns [`ArbiterError::InvalidCliArguments`] if `argv` is empty, the multicall persona is unknown,
/// or downstream flag parsing fails.
pub fn dispatch_multicall(argv: &[&str]) -> ArbiterResult<MulticallTarget> {
    let Some(&program_path) = argv.first() else {
        return Err(ArbiterError::InvalidCliArguments {
            reason: "empty argv slice".to_owned(),
        });
    };

    let filename = program_path
        .rsplit(['/', ':'])
        .next()
        .unwrap_or(program_path);
    let basename = filename.strip_suffix(".exe").unwrap_or(filename);
    let rest = argv.get(1..).unwrap_or(&[]);

    match basename {
        "arbiter-master" => Ok(MulticallTarget::Master(MasterCliConfig::parse_from_slice(
            rest,
        )?)),
        "arbiter-agent" => Ok(MulticallTarget::Agent(AgentCliConfig::parse_from_slice(
            rest,
        )?)),
        "arbiter-executor" => Ok(MulticallTarget::Executor(
            ExecutorCliConfig::parse_from_slice(rest)?,
        )),
        "arbiter-cli" => Ok(MulticallTarget::Cli(CliSubcommand::parse_from_slice(rest)?)),
        "arbiter" => {
            let Some(&sub) = rest.first() else {
                return Err(ArbiterError::InvalidCliArguments {
                    reason: "missing subcommand for 'arbiter' multicall binary (expected 'master', 'agent', 'executor', or 'cli')".to_owned(),
                });
            };
            let sub_args = rest.get(1..).unwrap_or(&[]);
            match sub {
                "master" => Ok(MulticallTarget::Master(MasterCliConfig::parse_from_slice(
                    sub_args,
                )?)),
                "agent" => Ok(MulticallTarget::Agent(AgentCliConfig::parse_from_slice(
                    sub_args,
                )?)),
                "executor" => Ok(MulticallTarget::Executor(
                    ExecutorCliConfig::parse_from_slice(sub_args)?,
                )),
                "cli" => Ok(MulticallTarget::Cli(CliSubcommand::parse_from_slice(
                    sub_args,
                )?)),
                other => Err(ArbiterError::InvalidCliArguments {
                    reason: format!("unknown multicall subcommand '{other}'"),
                }),
            }
        }
        other => Err(ArbiterError::InvalidCliArguments {
            reason: format!("unrecognized multicall binary name '{other}'"),
        }),
    }
}

/// Returns the binary identifier for verification.
///
/// # Returns
///
/// The static binary name `"arbiter"`.
pub const fn binary_name() -> &'static str {
    "arbiter"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multicall_argv0_dispatch() {
        assert_eq!(binary_name(), "arbiter");

        assert!(dispatch_multicall(&[]).is_err());

        assert!(
            dispatch_multicall(&["/usr/local/bin/arbiter-master", "--raft-node-id", "2"]).is_ok()
        );
        assert!(dispatch_multicall(&["C:/bin/arbiter-agent.exe", "--agent-id", "node-1"]).is_ok());
        assert!(dispatch_multicall(&["arbiter-executor", "--task-id", "t-1"]).is_ok());
        assert!(dispatch_multicall(&["arbiter-cli", "status"]).is_ok());

        assert!(dispatch_multicall(&["arbiter-master", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter-agent", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter-executor", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter-cli", "unknown"]).is_err());
    }

    #[test]
    fn test_multicall_subcommand_dispatch() {
        for args in [
            &["arbiter", "master"][..],
            &[
                "arbiter",
                "master",
                "--bind-addr",
                "127.0.0.1:0",
                "--http-addr",
                "127.0.0.1:0",
                "--dns-addr",
                "127.0.0.1:0",
                "--max-ticks",
                "1",
                "--daemon",
            ][..],
            &["arbiter", "agent"][..],
            &["arbiter", "agent", "--max-ticks", "1", "--daemon"][..],
            &["arbiter", "executor"][..],
            &["arbiter", "cli", "tui"][..],
            &["arbiter"][..],
        ] {
            if let Ok(t) = dispatch_multicall(args) {
                assert!(!t.execute_target().is_empty());
            }
        }

        assert!(dispatch_multicall(&["arbiter"]).is_err());
        assert!(dispatch_multicall(&["arbiter", "master", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter", "agent", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter", "executor", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter", "cli"]).is_err());
        assert!(dispatch_multicall(&["arbiter", "bogus"]).is_err());
        assert!(dispatch_multicall(&["unknown-binary"]).is_err());
    }

    #[test]
    fn test_end_to_end_multi_persona_cluster_roundtrip() {
        let e2e_dir = std::env::temp_dir().join("arbiter_e2e_multicall_test");
        let wal_dir = e2e_dir.join("wal");
        let ckpt_dir = e2e_dir.join("ckpt");
        let sbox_dir = e2e_dir.join("sbox");
        let _ = std::fs::create_dir_all(&wal_dir);
        let _ = std::fs::create_dir_all(&ckpt_dir);
        let _ = std::fs::create_dir_all(&sbox_dir);

        let master_cfg = MasterCliConfig::parse_from_slice(&[
            "--bind-addr",
            "127.0.0.1:0",
            "--http-addr",
            "127.0.0.1:0",
            "--state-store",
            "raft",
            "--wal-dir",
            wal_dir.to_str().unwrap_or("/tmp"),
        ])
        .unwrap_or_default();
        assert_eq!(
            master_cfg.run_live_network_daemon_once("agent-e2e-1"),
            Ok(2)
        );

        let agent_cfg = AgentCliConfig::parse_from_slice(&[
            "--agent-id",
            "agent-e2e-1",
            "--work-dir",
            sbox_dir.to_str().unwrap_or("/tmp"),
            "--checkpoint-dir",
            ckpt_dir.to_str().unwrap_or("/tmp"),
        ])
        .unwrap_or_default();
        assert_eq!(
            agent_cfg.run_live_network_daemon_once("127.0.0.1:0"),
            Ok("MASTER_ACK:agent-e2e-1".to_owned())
        );

        let exec_cfg = ExecutorCliConfig::parse_from_slice(&[
            "--executor-id",
            "exec-e2e-1",
            "--task-id",
            "task-e2e-1",
            "--sandbox-dir",
            sbox_dir.to_str().unwrap_or("/tmp"),
        ])
        .unwrap_or_default();
        assert_eq!(exec_cfg.run_daemon_loop(2).map(|(t, _)| t), Ok(2));

        let cli_sub = CliSubcommand::parse_from_slice(&["status"]).unwrap_or(CliSubcommand::Status);
        assert!(
            cli_sub
                .execute_remote_http_operator_call("127.0.0.1:0")
                .is_ok()
        );

        let _ = std::fs::remove_dir_all(&e2e_dir);
    }
}
