//! Standalone Agent binary library and entry point for Arbiter (`arbiter-agent-bin`).
//!
//! Parses command-line flags (`--agent-id`, `--master-endpoint`, `--cache-bytes`) and initializes
//! an [`AgentSupervisor`](arbiter_agent::AgentSupervisor).

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::AgentId;
use arbiter_core::units::Bytes;

/// Parsed command-line configuration for the `arbiter-agent` daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCliConfig {
    /// Validated [`AgentId`].
    pub agent_id: AgentId,
    /// Master QUIC/HTTP control-plane endpoint.
    pub master_endpoint: String,
    /// Artifact cache capacity in [`Bytes`].
    pub cache_bytes: Bytes,
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
        let mut agent_id = AgentId::default();
        let mut master_endpoint = "127.0.0.1:5050".to_owned();
        let mut cache_bytes = Bytes::new(10 * 1024 * 1024 * 1024);

        let mut idx = 0;
        while let Some(&arg) = args.get(idx) {
            match arg {
                "--agent-id" => {
                    let Some(&val) = args.get(idx.saturating_add(1)) else {
                        return Err(ArbiterError::InvalidCliArguments {
                            reason: "missing value for --agent-id".to_owned(),
                        });
                    };
                    agent_id = AgentId::new(val)?;
                    idx = idx.saturating_add(2);
                }
                "--master-endpoint" => {
                    let Some(&val) = args.get(idx.saturating_add(1)) else {
                        return Err(ArbiterError::InvalidCliArguments {
                            reason: "missing value for --master-endpoint".to_owned(),
                        });
                    };
                    val.clone_into(&mut master_endpoint);
                    idx = idx.saturating_add(2);
                }
                "--cache-bytes" => {
                    let Some(&val) = args.get(idx.saturating_add(1)) else {
                        return Err(ArbiterError::InvalidCliArguments {
                            reason: "missing value for --cache-bytes".to_owned(),
                        });
                    };
                    let parsed =
                        val.parse::<u64>()
                            .map_err(|_| ArbiterError::InvalidCliArguments {
                                reason: format!("invalid u64 for --cache-bytes: {val}"),
                            })?;
                    cache_bytes = Bytes::new(parsed);
                    idx = idx.saturating_add(2);
                }
                other => {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: format!("unknown agent flag '{other}'"),
                    });
                }
            }
        }

        Ok(Self {
            agent_id,
            master_endpoint,
            cache_bytes,
        })
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
            "--cache-bytes",
            "4096",
        ]);
        assert!(custom.is_ok());

        assert!(AgentCliConfig::parse_from_slice(&["--agent-id"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--agent-id", ""]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--master-endpoint"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--cache-bytes"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--cache-bytes", "bad"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--bogus"]).is_err());
    }
}
