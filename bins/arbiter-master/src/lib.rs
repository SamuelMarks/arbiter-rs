//! Standalone Master binary library and entry point for Arbiter (`arbiter-master-bin`).
//!
//! Parses command-line flags (`--bind-addr`, `--raft-node-id`, `--offer-ttl-ticks`) and initializes
//! a [`MasterNode`](arbiter_master::MasterNode) instance.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult};

/// Parsed command-line configuration for the `arbiter-master` daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterCliConfig {
    /// Listen address for QUIC & HTTP/SSE control-plane traffic.
    pub bind_addr: String,
    /// Raft consensus node identifier.
    pub raft_node_id: u64,
    /// Offer TTL in scheduler ticks.
    pub offer_ttl_ticks: u64,
}

impl MasterCliConfig {
    /// Parses `args` (excluding `argv[0]`) into a [`MasterCliConfig`].
    ///
    /// # Arguments
    ///
    /// * `args` - Slice of CLI argument strings.
    ///
    /// # Returns
    ///
    /// Validated [`MasterCliConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidCliArguments`] if an unknown flag or invalid value is supplied.
    pub fn parse_from_slice(args: &[&str]) -> ArbiterResult<Self> {
        let mut bind_addr = "0.0.0.0:5050".to_owned();
        let mut raft_node_id = 1_u64;
        let mut offer_ttl_ticks = 50_u64;

        let mut idx = 0;
        while let Some(&arg) = args.get(idx) {
            match arg {
                "--bind-addr" => {
                    let Some(&val) = args.get(idx.saturating_add(1)) else {
                        return Err(ArbiterError::InvalidCliArguments {
                            reason: "missing value for --bind-addr".to_owned(),
                        });
                    };
                    val.clone_into(&mut bind_addr);
                    idx = idx.saturating_add(2);
                }
                "--raft-node-id" => {
                    let Some(&val) = args.get(idx.saturating_add(1)) else {
                        return Err(ArbiterError::InvalidCliArguments {
                            reason: "missing value for --raft-node-id".to_owned(),
                        });
                    };
                    raft_node_id =
                        val.parse::<u64>()
                            .map_err(|_| ArbiterError::InvalidCliArguments {
                                reason: format!("invalid u64 for --raft-node-id: {val}"),
                            })?;
                    idx = idx.saturating_add(2);
                }
                "--offer-ttl-ticks" => {
                    let Some(&val) = args.get(idx.saturating_add(1)) else {
                        return Err(ArbiterError::InvalidCliArguments {
                            reason: "missing value for --offer-ttl-ticks".to_owned(),
                        });
                    };
                    offer_ttl_ticks =
                        val.parse::<u64>()
                            .map_err(|_| ArbiterError::InvalidCliArguments {
                                reason: format!("invalid u64 for --offer-ttl-ticks: {val}"),
                            })?;
                    idx = idx.saturating_add(2);
                }
                other => {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: format!("unknown master flag '{other}'"),
                    });
                }
            }
        }

        Ok(Self {
            bind_addr,
            raft_node_id,
            offer_ttl_ticks,
        })
    }
}

/// Returns the binary identifier for verification.
///
/// # Returns
///
/// The static binary name `"arbiter-master"`.
pub const fn binary_name() -> &'static str {
    "arbiter-master"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_cli_config_parsing() {
        assert_eq!(binary_name(), "arbiter-master");

        let default_cfg = MasterCliConfig::parse_from_slice(&[]);
        assert_eq!(
            default_cfg,
            Ok(MasterCliConfig {
                bind_addr: "0.0.0.0:5050".to_owned(),
                raft_node_id: 1,
                offer_ttl_ticks: 50,
            })
        );

        let custom = MasterCliConfig::parse_from_slice(&[
            "--bind-addr",
            "127.0.0.1:6060",
            "--raft-node-id",
            "3",
            "--offer-ttl-ticks",
            "100",
        ]);
        assert_eq!(
            custom,
            Ok(MasterCliConfig {
                bind_addr: "127.0.0.1:6060".to_owned(),
                raft_node_id: 3,
                offer_ttl_ticks: 100,
            })
        );

        assert!(MasterCliConfig::parse_from_slice(&["--bind-addr"]).is_err());
        assert!(MasterCliConfig::parse_from_slice(&["--raft-node-id"]).is_err());
        assert!(MasterCliConfig::parse_from_slice(&["--raft-node-id", "abc"]).is_err());
        assert!(MasterCliConfig::parse_from_slice(&["--offer-ttl-ticks"]).is_err());
        assert!(MasterCliConfig::parse_from_slice(&["--offer-ttl-ticks", "xyz"]).is_err());
        assert!(MasterCliConfig::parse_from_slice(&["--unknown"]).is_err());
    }
}
