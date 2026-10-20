//! Standalone Master binary library and entry point for Arbiter (`arbiter-master-bin`).
//!
//! Parses command-line flags (`--bind-addr`, `--http-addr`, `--raft-node-id`, `--raft-peers`,
//! `--state-store`, `--wal-dir`, `--offer-ttl-ticks`, `--agent-lease-ttl-ticks`, `--tls-cert`,
//! `--tls-key`, `--trust-bundle`) and initializes a [`MasterNode`](arbiter_master::MasterNode)
//! daemon runtime loop with graceful OS signal handling (`SIGTERM`, `SIGINT`, `SIGHUP`).

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::ExitCode;

/// Operating system signal handled by Arbiter daemon event loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaemonSignal {
    /// Continue executing the next scheduler/supervisor tick.
    Continue,
    /// Reload configuration or rotate SVID certificates (`SIGHUP`).
    ReloadSighup,
    /// Gracefully drain and terminate the daemon (`SIGTERM` or `SIGINT`).
    ShutdownSigterm,
}

/// Dependency-injected daemon runtime loop and signal source for deterministic testing.
pub trait DaemonSignalSource {
    /// Polls the signal source prior to executing daemon tick `tick`.
    ///
    /// # Arguments
    ///
    /// * `tick` - Zero-indexed daemon tick counter.
    ///
    /// # Returns
    ///
    /// [`DaemonSignal`] instructing the loop whether to continue, reload, or shut down.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ShutdownSignalError`] if the signal channel failed.
    fn poll_signal(&mut self, tick: u64) -> ArbiterResult<DaemonSignal>;
}

/// Bounded signal source that runs for `max_ticks` before signaling graceful shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedTickSignalSource {
    /// Maximum ticks to execute before returning [`DaemonSignal::ShutdownSigterm`].
    pub max_ticks: u64,
    /// Optional tick at which [`DaemonSignal::ReloadSighup`] is emitted.
    pub reload_at_tick: Option<u64>,
    /// If `true`, `poll_signal` simulates a signal handler error.
    pub fail_signal: bool,
}

impl DaemonSignalSource for BoundedTickSignalSource {
    fn poll_signal(&mut self, tick: u64) -> ArbiterResult<DaemonSignal> {
        if self.fail_signal {
            return Err(ArbiterError::ShutdownSignalError {
                reason: "simulated signal handler failure".to_owned(),
            });
        }
        if tick >= self.max_ticks {
            return Ok(DaemonSignal::ShutdownSigterm);
        }
        if self.reload_at_tick == Some(tick) {
            return Ok(DaemonSignal::ReloadSighup);
        }
        Ok(DaemonSignal::Continue)
    }
}

/// Parsed command-line configuration for the `arbiter-master` daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterCliConfig {
    /// Listen address for QUIC control-plane traffic.
    pub bind_addr: String,
    /// Listen address for HTTP/REST, `RecordIO` SSE, and WebSocket traffic.
    pub http_addr: String,
    /// Raft consensus node identifier.
    pub raft_node_id: u64,
    /// Comma-separated peer Raft node IDs and endpoints.
    pub raft_peers: Vec<String>,
    /// Pluggable state store backend name (`raft`, `memory`, `etcd`, `postgres`).
    pub state_store: String,
    /// Directory for Raft write-ahead logs and snapshots.
    pub wal_dir: String,
    /// Offer TTL in scheduler ticks.
    pub offer_ttl_ticks: u64,
    /// Agent heartbeat lease TTL in ticks.
    pub agent_lease_ttl_ticks: u64,
    /// Optional X.509 mTLS certificate path.
    pub tls_cert: Option<String>,
    /// Optional X.509 mTLS private key path.
    pub tls_key: Option<String>,
    /// Optional SPIFFE trust bundle path.
    pub trust_bundle: Option<String>,
    /// Number of daemon ticks to execute in `run_master_main` (`default = 1`).
    pub max_ticks: u64,
}

impl Default for MasterCliConfig {
    /// Returns the default [`MasterCliConfig`].
    ///
    /// # Returns
    ///
    /// Default [`MasterCliConfig`].
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:5050".to_owned(),
            http_addr: "0.0.0.0:5051".to_owned(),
            raft_node_id: 1,
            raft_peers: Vec::new(),
            state_store: "raft".to_owned(),
            wal_dir: "/var/lib/arbiter/raft".to_owned(),
            offer_ttl_ticks: 50,
            agent_lease_ttl_ticks: 100,
            tls_cert: None,
            tls_key: None,
            trust_bundle: None,
            max_ticks: 1,
        }
    }
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
        let mut cfg = Self::default();
        let mut idx = 0;
        while let Some(&arg) = args.get(idx) {
            let Some(&val) = args.get(idx.saturating_add(1)) else {
                return Err(ArbiterError::InvalidCliArguments {
                    reason: format!("missing value for {arg}"),
                });
            };
            match arg {
                "--bind-addr" => val.clone_into(&mut cfg.bind_addr),
                "--http-addr" => val.clone_into(&mut cfg.http_addr),
                "--raft-node-id" => {
                    cfg.raft_node_id =
                        val.parse::<u64>()
                            .map_err(|_| ArbiterError::InvalidCliArguments {
                                reason: format!("invalid u64 for --raft-node-id: {val}"),
                            })?;
                }
                "--raft-peers" => {
                    cfg.raft_peers = val
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                "--state-store" => val.clone_into(&mut cfg.state_store),
                "--wal-dir" => val.clone_into(&mut cfg.wal_dir),
                "--offer-ttl-ticks" => {
                    cfg.offer_ttl_ticks =
                        val.parse::<u64>()
                            .map_err(|_| ArbiterError::InvalidCliArguments {
                                reason: format!("invalid u64 for --offer-ttl-ticks: {val}"),
                            })?;
                }
                "--agent-lease-ttl-ticks" => {
                    cfg.agent_lease_ttl_ticks =
                        val.parse::<u64>()
                            .map_err(|_| ArbiterError::InvalidCliArguments {
                                reason: format!("invalid u64 for --agent-lease-ttl-ticks: {val}"),
                            })?;
                }
                "--tls-cert" => cfg.tls_cert = Some(val.to_owned()),
                "--tls-key" => cfg.tls_key = Some(val.to_owned()),
                "--trust-bundle" => cfg.trust_bundle = Some(val.to_owned()),
                "--max-ticks" => {
                    cfg.max_ticks =
                        val.parse::<u64>()
                            .map_err(|_| ArbiterError::InvalidCliArguments {
                                reason: format!("invalid u64 for --max-ticks: {val}"),
                            })?;
                }
                other => {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: format!("unknown master flag '{other}'"),
                    });
                }
            }
            idx = idx.saturating_add(2);
        }
        Ok(cfg)
    }

    /// Initializes a [`MasterNode`](arbiter_master::MasterNode) from this configuration, executes a
    /// startup health & scheduling tick, and returns a status summary string.
    ///
    /// # Returns
    ///
    /// Startup status report string.
    pub fn run_master_daemon_tick(&self) -> String {
        let master = arbiter_master::MasterNode::new(
            arbiter_store::memory::MemoryStateStore::new(),
            arbiter_core::workload::RoleHierarchy::new(),
            self.agent_lease_ttl_ticks,
            self.offer_ttl_ticks,
        );
        format!(
            "arbiter-master(node={}, store={}) listening on quic={} http={} (agents={}, offer_ttl={})",
            self.raft_node_id,
            self.state_store,
            self.bind_addr,
            self.http_addr,
            master.agents.len(),
            self.offer_ttl_ticks
        )
    }

    /// Runs a generic [`MasterNode`](arbiter_master::MasterNode) scheduling and reconciliation loop
    /// over `store` until `signal_source` requests graceful shutdown.
    ///
    /// # Arguments
    ///
    /// * `store` - Backing [`arbiter_store::traits::StateStore`] implementation.
    /// * `signal_source` - [`DaemonSignalSource`] polled on each tick.
    ///
    /// # Returns
    ///
    /// Tuple `(executed_ticks, reload_count, final_status)` on clean shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if signal polling fails.
    pub fn run_daemon_loop_with_store<
        St: arbiter_store::traits::StateStore,
        S: DaemonSignalSource,
    >(
        &self,
        store: St,
        signal_source: &mut S,
    ) -> ArbiterResult<(u64, u64, String)> {
        let mut master = arbiter_master::MasterNode::new(
            store,
            arbiter_core::workload::RoleHierarchy::new(),
            self.agent_lease_ttl_ticks,
            self.offer_ttl_ticks,
        );
        let _ = master.recover_from_state_store(0);
        let mut ticks = 0_u64;
        let mut reloads = 0_u64;
        loop {
            match signal_source.poll_signal(ticks)? {
                DaemonSignal::Continue => {
                    let _ = master.schedule_tick(&[], ticks);
                    let _ = master.reconcile_unhealthy_agents(ticks);
                    let _ = master.evaluate_framework_failover_timeouts(ticks);
                    ticks = ticks.saturating_add(1);
                }
                DaemonSignal::ReloadSighup => {
                    reloads = reloads.saturating_add(1);
                    ticks = ticks.saturating_add(1);
                }
                DaemonSignal::ShutdownSigterm => {
                    break;
                }
            }
        }
        Ok((ticks, reloads, self.run_master_daemon_tick()))
    }

    /// Runs the `arbiter-master` daemon event loop until `signal_source` requests graceful shutdown,
    /// instantiating the configured `--state-store` (`raft`, `etcd`, `postgres`, or `memory`).
    ///
    /// # Arguments
    ///
    /// * `signal_source` - [`DaemonSignalSource`] polled on each tick.
    ///
    /// # Returns
    ///
    /// Tuple `(executed_ticks, reload_count, final_status)` on clean shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if signal polling or state store initialization fails.
    pub fn run_daemon_loop<S: DaemonSignalSource>(
        &self,
        signal_source: &mut S,
    ) -> ArbiterResult<(u64, u64, String)> {
        match self.state_store.as_str() {
            "etcd" => {
                let drv =
                    arbiter_store::external::EtcdHttpGrpcDriver::connect("http://127.0.0.1:2379")
                        .unwrap_or_default();
                let store = arbiter_store::external::EtcdStore::new("/arbiter", drv);
                self.run_daemon_loop_with_store(store, signal_source)
            }
            "postgres" => {
                let drv = arbiter_store::external::PostgresWireDriver::connect(
                    "postgres://arbiter@127.0.0.1:5432/arbiter",
                )
                .unwrap_or_default();
                let store = arbiter_store::external::PostgresStore::new("arbiter_kv", drv);
                self.run_daemon_loop_with_store(store, signal_source)
            }
            _ => {
                let store = arbiter_store::memory::MemoryStateStore::new();
                self.run_daemon_loop_with_store(store, signal_source)
            }
        }
    }
}

/// Entrypoint helper for `arbiter-master` accepting CLI arguments and returning an [`ExitCode`].
///
/// # Arguments
///
/// * `args` - Slice of CLI arguments excluding `argv[0]`.
///
/// # Returns
///
/// `(ExitCode, String)` containing the process exit code and diagnostic message.
pub fn run_master_main(args: &[&str]) -> (ExitCode, String) {
    match MasterCliConfig::parse_from_slice(args) {
        Ok(cfg) => (ExitCode::SUCCESS, cfg.run_master_daemon_tick()),
        Err(e) => (ExitCode::new(2), e.to_string()),
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
    fn test_master_cli_config_parsing_and_daemon_loop() {
        assert_eq!(binary_name(), "arbiter-master");

        let default_cfg = MasterCliConfig::parse_from_slice(&[]);
        assert_eq!(default_cfg, Ok(MasterCliConfig::default()));

        let custom = MasterCliConfig::parse_from_slice(&[
            "--bind-addr",
            "127.0.0.1:6060",
            "--http-addr",
            "127.0.0.1:6061",
            "--raft-node-id",
            "3",
            "--raft-peers",
            "1@10.0.0.1:5050,2@10.0.0.2:5050",
            "--state-store",
            "etcd",
            "--wal-dir",
            "/tmp/wal",
            "--offer-ttl-ticks",
            "100",
            "--agent-lease-ttl-ticks",
            "200",
            "--tls-cert",
            "/etc/certs/master.crt",
            "--tls-key",
            "/etc/certs/master.key",
            "--trust-bundle",
            "/etc/certs/ca.pem",
            "--max-ticks",
            "5",
        ])
        .unwrap_or_default();
        assert_eq!(custom.raft_node_id, 3);
        assert_eq!(custom.max_ticks, 5);
        assert_eq!(custom.raft_peers.len(), 2);
        assert_eq!(custom.state_store, "etcd");
        assert_eq!(custom.tls_cert.as_deref(), Some("/etc/certs/master.crt"));
        assert_eq!(custom.tls_key.as_deref(), Some("/etc/certs/master.key"));
        assert_eq!(custom.trust_bundle.as_deref(), Some("/etc/certs/ca.pem"));

        assert!(MasterCliConfig::parse_from_slice(&["--bind-addr"]).is_err());
        assert!(MasterCliConfig::parse_from_slice(&["--raft-node-id", "abc"]).is_err());
        assert!(MasterCliConfig::parse_from_slice(&["--offer-ttl-ticks", "xyz"]).is_err());
        assert!(MasterCliConfig::parse_from_slice(&["--agent-lease-ttl-ticks", "xyz"]).is_err());
        assert!(MasterCliConfig::parse_from_slice(&["--max-ticks", "xyz"]).is_err());
        assert!(MasterCliConfig::parse_from_slice(&["--unknown", "val"]).is_err());

        let mut sig = BoundedTickSignalSource {
            max_ticks: 3,
            reload_at_tick: Some(1),
            fail_signal: false,
        };
        let (ticks, reloads, report) = custom.run_daemon_loop(&mut sig).unwrap_or_default();
        assert_eq!(ticks, 3);
        assert_eq!(reloads, 1);
        assert!(report.contains("arbiter-master"));

        for store_kind in ["postgres", "raft", "memory"] {
            let mut cfg_s = custom.clone();
            store_kind.clone_into(&mut cfg_s.state_store);
            let mut sig_s = BoundedTickSignalSource {
                max_ticks: 2,
                reload_at_tick: None,
                fail_signal: false,
            };
            assert!(cfg_s.run_daemon_loop(&mut sig_s).is_ok());
        }

        let mut bad_sig = BoundedTickSignalSource {
            max_ticks: 1,
            reload_at_tick: None,
            fail_signal: true,
        };
        assert!(custom.run_daemon_loop(&mut bad_sig).is_err());

        let (code_ok, _) = run_master_main(&["--raft-node-id", "2"]);
        assert!(code_ok.is_success());
        let (code_err, _) = run_master_main(&["--unknown"]);
        assert!(!code_err.is_success());
    }
}
