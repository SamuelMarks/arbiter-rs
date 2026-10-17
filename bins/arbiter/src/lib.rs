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

        assert!(matches!(
            dispatch_multicall(&["/usr/local/bin/arbiter-master", "--raft-node-id", "2"]),
            Ok(MulticallTarget::Master(_))
        ));
        assert!(matches!(
            dispatch_multicall(&["C:/bin/arbiter-agent.exe", "--agent-id", "node-1"]),
            Ok(MulticallTarget::Agent(_))
        ));
        assert!(matches!(
            dispatch_multicall(&["arbiter-executor", "--task-id", "t-1"]),
            Ok(MulticallTarget::Executor(_))
        ));
        assert!(matches!(
            dispatch_multicall(&["arbiter-cli", "status"]),
            Ok(MulticallTarget::Cli(CliSubcommand::Status))
        ));

        assert!(dispatch_multicall(&["arbiter-master", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter-agent", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter-executor", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter-cli", "unknown"]).is_err());
    }

    #[test]
    fn test_multicall_subcommand_dispatch() {
        assert!(matches!(
            dispatch_multicall(&["arbiter", "master"]),
            Ok(MulticallTarget::Master(_))
        ));
        assert!(matches!(
            dispatch_multicall(&["arbiter", "agent"]),
            Ok(MulticallTarget::Agent(_))
        ));
        assert!(matches!(
            dispatch_multicall(&["arbiter", "executor"]),
            Ok(MulticallTarget::Executor(_))
        ));
        assert!(matches!(
            dispatch_multicall(&["arbiter", "cli", "tui"]),
            Ok(MulticallTarget::Cli(CliSubcommand::Tui))
        ));

        assert!(dispatch_multicall(&["arbiter"]).is_err());
        assert!(dispatch_multicall(&["arbiter", "master", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter", "agent", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter", "executor", "--unknown"]).is_err());
        assert!(dispatch_multicall(&["arbiter", "cli"]).is_err());
        assert!(dispatch_multicall(&["arbiter", "bogus"]).is_err());
        assert!(dispatch_multicall(&["unknown-binary"]).is_err());
    }
}
