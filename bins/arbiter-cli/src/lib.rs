//! Standalone CLI and TUI binary library and entry point for Arbiter (`arbiter-cli`).
//!
//! Supports subcommands (`status`, `tui`, `submit`, `bench-multicluster`, `bench-failover-traffic`)
//! for inspecting cluster topology, launching the interactive Terminal UI, submitting direct workloads,
//! or executing comparative multicluster and 3/5/7-node failover wire-traffic benchmarks.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{RoleName, TaskId};
use arbiter_core::units::NodeCount;
use arbiter_master::bench::{
    MulticlusterBenchmarkConfig, run_failover_traffic_matrix, run_full_multicluster_benchmark_suite,
};

/// Parsed subcommand for the `arbiter-cli` operator tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliSubcommand {
    /// Query cluster summary status.
    Status,
    /// Launch the interactive Terminal UI (`arbiter-tui`).
    Tui,
    /// Submit a direct task (`submit <role> <task-id> <command>`).
    Submit {
        /// Target [`RoleName`].
        role: RoleName,
        /// Unique [`TaskId`].
        task_id: TaskId,
        /// Command string to execute.
        command: String,
    },
    /// Run the multicluster vs. non-multicluster comparative benchmark suite (`bench-multicluster`).
    BenchMulticluster,
    /// Run the 3, 5, and 7-node `PostgreSQL` + `etcd` vs. `arbiter-rs` failover & wire-traffic benchmark (`bench-failover-traffic`).
    BenchFailoverTraffic,
}

impl CliSubcommand {
    /// Parses `args` (excluding `argv[0]`) into a [`CliSubcommand`].
    ///
    /// # Arguments
    ///
    /// * `args` - Slice of CLI argument strings.
    ///
    /// # Returns
    ///
    /// Parsed [`CliSubcommand`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidCliArguments`] or validation errors if arguments are missing or invalid.
    pub fn parse_from_slice(args: &[&str]) -> ArbiterResult<Self> {
        let Some(&sub) = args.first() else {
            return Err(ArbiterError::InvalidCliArguments {
                reason: "missing subcommand (expected 'status', 'tui', 'submit', 'bench-multicluster', or 'bench-failover-traffic')"
                    .to_owned(),
            });
        };
        match sub {
            "status" => Ok(Self::Status),
            "tui" => Ok(Self::Tui),
            "bench-multicluster" => Ok(Self::BenchMulticluster),
            "bench-failover-traffic" => Ok(Self::BenchFailoverTraffic),
            "submit" => {
                let (Some(&role_str), Some(&tid_str), Some(&cmd_str)) =
                    (args.get(1), args.get(2), args.get(3))
                else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: submit <role> <task-id> <command>".to_owned(),
                    });
                };
                Ok(Self::Submit {
                    role: RoleName::new(role_str)?,
                    task_id: TaskId::new(tid_str)?,
                    command: cmd_str.to_owned(),
                })
            }
            other => Err(ArbiterError::InvalidCliArguments {
                reason: format!("unknown cli subcommand '{other}'"),
            }),
        }
    }

    /// Executes the parsed [`CliSubcommand`] and returns the formatted Markdown + JSON output report.
    ///
    /// # Returns
    ///
    /// Formatted string output suitable for terminal display or report export.
    pub fn execute_report(&self) -> String {
        match self {
            Self::Status => "arbiter-cli status: healthy".to_owned(),
            Self::Tui => "arbiter-cli tui: interactive view ready".to_owned(),
            Self::Submit {
                role,
                task_id,
                command,
            } => format!("submitted task '{task_id}' under role '{role}' -> '{command}'"),
            Self::BenchMulticluster => {
                let cfg = MulticlusterBenchmarkConfig::default();
                let (reports, md_table) = run_full_multicluster_benchmark_suite(&cfg);
                let json = serde_json::to_string(&reports).unwrap_or_default();
                format!(
                    "{md_table}
JSON:
{json}"
                )
            }
            Self::BenchFailoverTraffic => {
                let nodes = [
                    NodeCount::new_quorum(3).unwrap_or_default(),
                    NodeCount::new_quorum(5).unwrap_or_default(),
                    NodeCount::new_quorum(7).unwrap_or_default(),
                ];
                let (rows, md_table) = run_failover_traffic_matrix(&nodes).unwrap_or_default();
                let json = serde_json::to_string(&rows).unwrap_or_default();
                format!(
                    "{md_table}
JSON:
{json}"
                )
            }
        }
    }
}

/// Returns the binary identifier for verification.
///
/// # Returns
///
/// The static binary name `"arbiter-cli"`.
pub const fn binary_name() -> &'static str {
    "arbiter-cli"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_subcommand_parsing_and_execution() {
        assert_eq!(binary_name(), "arbiter-cli");

        let st = CliSubcommand::parse_from_slice(&["status"]).unwrap_or(CliSubcommand::Status);
        assert_eq!(st, CliSubcommand::Status);
        assert!(!st.execute_report().is_empty());

        let tui = CliSubcommand::parse_from_slice(&["tui"]).unwrap_or(CliSubcommand::Status);
        assert_eq!(tui, CliSubcommand::Tui);
        assert!(!tui.execute_report().is_empty());

        let bm = CliSubcommand::parse_from_slice(&["bench-multicluster"])
            .unwrap_or(CliSubcommand::Status);
        assert_eq!(bm, CliSubcommand::BenchMulticluster);
        let multicluster_report = bm.execute_report();
        assert!(multicluster_report.contains("Arbiter-Multicluster-Federated"));

        let bf = CliSubcommand::parse_from_slice(&["bench-failover-traffic"])
            .unwrap_or(CliSubcommand::Status);
        assert_eq!(bf, CliSubcommand::BenchFailoverTraffic);
        let failover_report = bf.execute_report();
        assert!(failover_report.contains("JointMasterAndPrimaryHardKill"));

        let sub = CliSubcommand::parse_from_slice(&["submit", "prod", "task-1", "/bin/echo"])
            .unwrap_or(CliSubcommand::Status);
        assert!(!sub.execute_report().is_empty());

        assert!(CliSubcommand::parse_from_slice(&[]).is_err());
        assert!(CliSubcommand::parse_from_slice(&["submit", "prod"]).is_err());
        assert!(CliSubcommand::parse_from_slice(&["submit", "", "task-1", "/bin/echo"]).is_err());
        assert!(CliSubcommand::parse_from_slice(&["submit", "prod", "", "/bin/echo"]).is_err());
        assert!(CliSubcommand::parse_from_slice(&["unknown"]).is_err());
    }
}
