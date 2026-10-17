//! Standalone Executor binary library and entry point for Arbiter (`arbiter-executor-bin`).
//!
//! Parses command-line flags (`--executor-id`, `--task-id`, `--log-ring-lines`) for launching a
//! supervised task executor.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{ExecutorId, TaskId};

/// Parsed command-line configuration for the `arbiter-executor` process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorCliConfig {
    /// Validated [`ExecutorId`].
    pub executor_id: ExecutorId,
    /// Validated [`TaskId`].
    pub task_id: TaskId,
    /// Ring buffer line capacity.
    pub log_ring_lines: usize,
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
        let mut executor_id = ExecutorId::default();
        let mut task_id = TaskId::default();
        let mut log_ring_lines = 1024_usize;

        let mut idx = 0;
        while let Some(&arg) = args.get(idx) {
            match arg {
                "--executor-id" => {
                    let Some(&val) = args.get(idx.saturating_add(1)) else {
                        return Err(ArbiterError::InvalidCliArguments {
                            reason: "missing value for --executor-id".to_owned(),
                        });
                    };
                    executor_id = ExecutorId::new(val)?;
                    idx = idx.saturating_add(2);
                }
                "--task-id" => {
                    let Some(&val) = args.get(idx.saturating_add(1)) else {
                        return Err(ArbiterError::InvalidCliArguments {
                            reason: "missing value for --task-id".to_owned(),
                        });
                    };
                    task_id = TaskId::new(val)?;
                    idx = idx.saturating_add(2);
                }
                "--log-ring-lines" => {
                    let Some(&val) = args.get(idx.saturating_add(1)) else {
                        return Err(ArbiterError::InvalidCliArguments {
                            reason: "missing value for --log-ring-lines".to_owned(),
                        });
                    };
                    log_ring_lines =
                        val.parse::<usize>()
                            .map_err(|_| ArbiterError::InvalidCliArguments {
                                reason: format!("invalid usize for --log-ring-lines: {val}"),
                            })?;
                    idx = idx.saturating_add(2);
                }
                other => {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: format!("unknown executor flag '{other}'"),
                    });
                }
            }
        }

        Ok(Self {
            executor_id,
            task_id,
            log_ring_lines,
        })
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
            "--task-id",
            "task-99",
            "--log-ring-lines",
            "256",
        ]);
        assert!(custom.is_ok());

        assert!(ExecutorCliConfig::parse_from_slice(&["--executor-id"]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--executor-id", ""]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--task-id"]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--task-id", ""]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--log-ring-lines"]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--log-ring-lines", "nan"]).is_err());
        assert!(ExecutorCliConfig::parse_from_slice(&["--unknown"]).is_err());
    }
}
