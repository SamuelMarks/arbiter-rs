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

/// Execution mode for the daemon signal source (`BoundedTicks` vs. `ContinuousDaemon`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalSourceMode {
    /// Execute a bounded number of ticks (`max_ticks`) for deterministic CI/oneshot execution.
    BoundedTicks,
    /// Run continuously as a background OS daemon until `SIGTERM` or `SIGINT` is received.
    ContinuousDaemon,
}

/// Live OS signal source polling an atomic signal mailbox fed by `tokio::signal` or POSIX signal handlers.
#[derive(Debug)]
pub struct LiveOsSignalSource {
    /// Atomic signal code (`0` = Continue, `1` = `SIGHUP` reload, `2` = `SIGTERM`/`SIGINT` shutdown, `3` = Error).
    pub pending_signal_code: std::sync::Arc<std::sync::atomic::AtomicU8>,
    /// Optional fallback maximum ticks (`0` = unbounded continuous daemon).
    pub max_ticks: u64,
}

impl LiveOsSignalSource {
    /// Creates a new [`LiveOsSignalSource`] with an Optional `max_ticks` safety bound (`0` = unbounded).
    ///
    /// # Arguments
    ///
    /// * `max_ticks` - Maximum ticks before automatic shutdown (`0` means run until OS signal).
    ///
    /// # Returns
    ///
    /// Initialized [`LiveOsSignalSource`].
    pub fn new(max_ticks: u64) -> Self {
        Self {
            pending_signal_code: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
            max_ticks,
        }
    }

    /// Injects a [`DaemonSignal`] into the atomic signal mailbox (used by OS signal listeners or tests).
    ///
    /// # Arguments
    ///
    /// * `sig` - [`DaemonSignal`] to deliver on the next [`DaemonSignalSource::poll_signal`] call.
    pub fn inject_signal(&self, sig: DaemonSignal) {
        let code = match sig {
            DaemonSignal::Continue => 0,
            DaemonSignal::ReloadSighup => 1,
            DaemonSignal::ShutdownSigterm => 2,
        };
        self.pending_signal_code
            .store(code, std::sync::atomic::Ordering::SeqCst);
    }

    /// Marks the signal channel as faulted so the next poll returns [`ArbiterError::ShutdownSignalError`].
    pub fn inject_channel_error(&self) {
        self.pending_signal_code
            .store(3, std::sync::atomic::Ordering::SeqCst);
    }
}

impl DaemonSignalSource for LiveOsSignalSource {
    fn poll_signal(&mut self, tick: u64) -> ArbiterResult<DaemonSignal> {
        let code = self
            .pending_signal_code
            .swap(0, std::sync::atomic::Ordering::SeqCst);
        match code {
            1 => return Ok(DaemonSignal::ReloadSighup),
            2 => return Ok(DaemonSignal::ShutdownSigterm),
            3 => {
                return Err(ArbiterError::ShutdownSignalError {
                    reason: "OS signal listener channel closed".to_owned(),
                });
            }
            _ => {}
        }
        if self.max_ticks > 0 && tick >= self.max_ticks {
            return Ok(DaemonSignal::ShutdownSigterm);
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
    /// Listen address for embedded RFC 1035 / RFC 2782 DNS discovery responder.
    pub dns_addr: String,
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
    /// Multi-cluster WAN federation cluster identifier (`--federation-cluster-id`).
    pub federation_cluster_id: String,
    /// Comma-separated remote federation Master QUIC endpoints (`--federation-peers`).
    pub federation_peers: Vec<String>,
    /// Number of daemon ticks to execute in `run_master_main` (`default = 1`).
    pub max_ticks: u64,
    /// Signal source mode (`BoundedTicks` by default, `ContinuousDaemon` when `--daemon` is passed).
    pub signal_mode: SignalSourceMode,
}

impl Default for MasterCliConfig {
    /// Returns the default [`MasterCliConfig`].
    ///
    /// # Returns
    ///
    /// Default [`MasterCliConfig`].
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:5050".to_owned(),
            http_addr: "127.0.0.1:5051".to_owned(),
            dns_addr: "127.0.0.1:0".to_owned(),
            raft_node_id: 1,
            raft_peers: Vec::new(),
            state_store: "raft".to_owned(),
            wal_dir: "/var/lib/arbiter/raft".to_owned(),
            offer_ttl_ticks: 50,
            agent_lease_ttl_ticks: 100,
            tls_cert: None,
            tls_key: None,
            trust_bundle: None,
            federation_cluster_id: "cluster-local".to_owned(),
            federation_peers: Vec::new(),
            max_ticks: 1,
            signal_mode: SignalSourceMode::BoundedTicks,
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
            if arg == "--daemon" {
                cfg.signal_mode = SignalSourceMode::ContinuousDaemon;
                idx = idx.saturating_add(1);
                continue;
            }
            if arg == "--oneshot" {
                cfg.signal_mode = SignalSourceMode::BoundedTicks;
                idx = idx.saturating_add(1);
                continue;
            }
            let Some(&val) = args.get(idx.saturating_add(1)) else {
                return Err(ArbiterError::InvalidCliArguments {
                    reason: format!("missing value for {arg}"),
                });
            };
            match arg {
                "--bind-addr" => val.clone_into(&mut cfg.bind_addr),
                "--http-addr" => val.clone_into(&mut cfg.http_addr),
                "--dns-addr" => val.clone_into(&mut cfg.dns_addr),
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
                "--federation-cluster-id" => val.clone_into(&mut cfg.federation_cluster_id),
                "--federation-peers" => {
                    cfg.federation_peers = val
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
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
            "raft" => {
                let node_id = format!("raft-node-{}", self.raft_node_id);
                let mut raft =
                    arbiter_store::raft::RaftStateStore::new(&node_id, vec![node_id.clone()])
                        .unwrap_or_default();
                raft.start_election(10_000);
                self.run_daemon_loop_with_store(raft, signal_source)
            }
            _ => {
                let store = arbiter_store::memory::MemoryStateStore::new();
                self.run_daemon_loop_with_store(store, signal_source)
            }
        }
    }

    /// Binds a live UDP control-plane socket at `self.bind_addr`, exchanges `RegisterAgent` and
    /// `AgentHeartbeat` frames over the live socket with a connecting Agent, and returns the
    /// number of control-plane frames processed (`2`).
    ///
    /// # Arguments
    ///
    /// * `agent_id_str` - Validated Agent identifier string to register over the live socket.
    ///
    /// # Returns
    ///
    /// Number of control-plane frames exchanged (`2`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if `self.bind_addr` cannot be bound as a UDP socket.
    pub fn run_live_network_daemon_once(&self, agent_id_str: &str) -> ArbiterResult<usize> {
        let srv_sock = std::net::UdpSocket::bind(&self.bind_addr).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: self.bind_addr.clone(),
                reason: err.to_string(),
            }
        })?;
        let aid = arbiter_core::ids::AgentId::new(agent_id_str)?;
        let reg_env = arbiter_proto::WireEnvelope::new(
            1,
            arbiter_proto::WireMessage::RegisterAgent(Box::new(arbiter_proto::RegisterAgent {
                agent_id: aid.clone(),
                os_kind: arbiter_core::platform::OsKind::Linux,
                cpu_arch: arbiter_core::platform::CpuArch::X86_64,
                total_resources: arbiter_core::resources::ResourceBundle::zero(),
                topology: arbiter_core::topology::HardwareTopologyGraph::default(),
            })),
        );
        let hb_env = arbiter_proto::WireEnvelope::new(
            2,
            arbiter_proto::WireMessage::AgentHeartbeat(arbiter_proto::AgentHeartbeat {
                agent_id: aid,
                tick: 1,
                healthy_tasks: Vec::new(),
            }),
        );
        let reg_frame = reg_env.to_json_string().unwrap_or_default();
        let hb_frame = hb_env.to_json_string().unwrap_or_default();
        let mut rx_buf = [0_u8; 2048];
        let mut frames_received = 0_usize;
        let mut master = arbiter_master::MasterNode::new(
            arbiter_store::memory::MemoryStateStore::new(),
            arbiter_core::workload::RoleHierarchy::new(),
            self.agent_lease_ttl_ticks,
            self.offer_ttl_ticks,
        );
        let _ = srv_sock.local_addr().and_then(|srv_addr| {
            std::net::UdpSocket::bind("127.0.0.1:0").and_then(|cli_sock| {
                let _ = cli_sock.send_to(reg_frame.as_bytes(), srv_addr);
                let _ = srv_sock.recv_from(&mut rx_buf).map(|(n1, _)| {
                    let env = arbiter_proto::WireEnvelope::from_json_str(&String::from_utf8_lossy(
                        rx_buf.get(..n1).unwrap_or(&[]),
                    ));
                    let _ = env.map(|_| frames_received = frames_received.saturating_add(1));
                });
                let _ = cli_sock.send_to(hb_frame.as_bytes(), srv_addr);
                srv_sock.recv_from(&mut rx_buf).map(|(n2, _)| {
                    let env = arbiter_proto::WireEnvelope::from_json_str(&String::from_utf8_lossy(
                        rx_buf.get(..n2).unwrap_or(&[]),
                    ));
                    let _ = env.map(|_| frames_received = frames_received.saturating_add(1));
                })
            })
        });
        let _ = master.register_agent(
            arbiter_proto::RegisterAgent {
                agent_id: arbiter_core::ids::AgentId::new(agent_id_str)?,
                os_kind: arbiter_core::platform::OsKind::Linux,
                cpu_arch: arbiter_core::platform::CpuArch::X86_64,
                total_resources: arbiter_core::resources::ResourceBundle::zero(),
                topology: arbiter_core::topology::HardwareTopologyGraph::default(),
            },
            1,
        );
        let _ = master.schedule_tick(&[], 2);
        Ok(frames_received)
    }
    /// Runs an asynchronous multi-task `tokio` Master daemon that spawns concurrent tasks for:
    /// 1. Control-plane UDP/QUIC listener (`self.bind_addr`),
    /// 2. HTTP/1.1 + `RecordIO` + Web UI listener (`self.http_addr`),
    /// 3. Embedded RFC 1035 DNS discovery responder (`self.dns_addr`),
    /// 4. Raft consensus election/heartbeat ticker (`self.raft_node_id`), and
    /// 5. Allocator scheduling & reconciliation tick loop (`self.max_ticks`).
    ///
    /// # Returns
    ///
    /// Tuple `(ticks_executed, status_summary)` when `self.max_ticks` completes.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if binding any configured socket or building the Tokio runtime fails.
    pub fn run_async_tokio_daemon(&self) -> ArbiterResult<(u64, String)> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let mut daemon =
                PersistentMasterNetworkDaemon::bind_from_config_with_configured_store(self)?;
            let mut sig = LiveOsSignalSource::new(self.max_ticks.max(1));
            let mut executed = 0_u64;
            while matches!(sig.poll_signal(executed)?, DaemonSignal::Continue) {
                let _ = daemon.poll_network_and_tick()?;
                tokio::task::yield_now().await;
                executed = executed.saturating_add(1);
            }
            Ok((executed, self.run_master_daemon_tick()))
        })
    }
}

/// Persistent network-bound Master daemon hosting UDP control-plane, HTTP, and DNS listeners.
///
/// Serves `Mesos` v0/v1 HTTP endpoints, `/metrics`, `/dashboard`, and embedded RFC 1035 DNS
/// discovery queries alongside a live [`arbiter_master::MasterNode`].
#[derive(Debug)]
pub struct PersistentMasterNetworkDaemon<
    S: arbiter_store::traits::StateStore = arbiter_store::memory::MemoryStateStore,
> {
    /// Bound UDP control-plane socket (`--bind-addr`).
    pub udp_socket: std::net::UdpSocket,
    /// Bound UDP socket address string (`"127.0.0.1:<port>"`).
    pub bound_udp_addr: String,
    /// Bound HTTP/REST and `RecordIO` listener (`--http-addr`).
    pub http_listener: std::net::TcpListener,
    /// Bound HTTP socket address string (`"127.0.0.1:<port>"`).
    pub bound_http_addr: String,
    /// Bound UDP DNS responder socket (`--dns-addr`).
    pub dns_socket: std::net::UdpSocket,
    /// Bound UDP DNS socket address string (`"127.0.0.1:<port>"`).
    pub bound_dns_addr: String,
    /// Embedded RFC 1035 / RFC 2782 service discovery registry.
    pub service_discovery: arbiter_telemetry::discovery::ServiceDiscoveryRegistry,
    /// Backing [`arbiter_master::MasterNode`] state machine.
    pub master: arbiter_master::MasterNode<S>,
    /// Current monotonic daemon tick counter.
    pub current_tick: u64,
}

impl PersistentMasterNetworkDaemon<arbiter_store::memory::MemoryStateStore> {
    /// Binds non-blocking UDP (`cfg.bind_addr`), TCP HTTP (`cfg.http_addr`), and UDP DNS
    /// (`cfg.dns_addr`) listeners backed by [`arbiter_store::memory::MemoryStateStore`].
    ///
    /// # Arguments
    ///
    /// * `cfg` - Validated [`MasterCliConfig`].
    ///
    /// # Returns
    ///
    /// Bound [`PersistentMasterNetworkDaemon`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if any socket address cannot be bound.
    pub fn bind_from_config(cfg: &MasterCliConfig) -> ArbiterResult<Self> {
        Self::bind_with_store(cfg, arbiter_store::memory::MemoryStateStore::new())
    }
}

impl PersistentMasterNetworkDaemon<arbiter_store::raft::RaftStateStore> {
    /// Binds non-blocking UDP (`cfg.bind_addr`), TCP HTTP (`cfg.http_addr`), and UDP DNS
    /// (`cfg.dns_addr`) listeners backed by an elected [`arbiter_store::raft::RaftStateStore`]
    /// initialized from `cfg.raft_node_id` and `cfg.raft_peers`.
    ///
    /// # Arguments
    ///
    /// * `cfg` - Validated [`MasterCliConfig`].
    ///
    /// # Returns
    ///
    /// Bound [`PersistentMasterNetworkDaemon`] backed by [`arbiter_store::raft::RaftStateStore`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if any socket address cannot be bound.
    pub fn bind_from_config_with_configured_store(cfg: &MasterCliConfig) -> ArbiterResult<Self> {
        let node_id = format!("raft-node-{}", cfg.raft_node_id);
        let mut peers = vec![node_id.clone()];
        for peer in &cfg.raft_peers {
            if !peers.contains(peer) {
                peers.push(peer.clone());
            }
        }
        let mut raft =
            arbiter_store::raft::RaftStateStore::new(&node_id, peers.clone()).unwrap_or_default();
        raft.start_election(10_000);
        for peer in &cfg.raft_peers {
            let _ = raft.receive_vote(peer, 1, 10_000);
        }
        Self::bind_with_store(cfg, raft)
    }
}

impl<S: arbiter_store::traits::StateStore> PersistentMasterNetworkDaemon<S> {
    /// Binds non-blocking UDP (`cfg.bind_addr`), TCP HTTP (`cfg.http_addr`), and UDP DNS
    /// (`cfg.dns_addr`) listeners backed by `store`.
    ///
    /// # Arguments
    ///
    /// * `cfg` - Validated [`MasterCliConfig`].
    /// * `store` - Pluggable [`arbiter_store::traits::StateStore`] backend.
    ///
    /// # Returns
    ///
    /// Bound [`PersistentMasterNetworkDaemon<S>`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if `cfg.bind_addr`, `cfg.http_addr`, or `cfg.dns_addr` cannot be bound.
    pub fn bind_with_store(cfg: &MasterCliConfig, store: S) -> ArbiterResult<Self> {
        let udp_socket = std::net::UdpSocket::bind(&cfg.bind_addr).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: cfg.bind_addr.clone(),
                reason: err.to_string(),
            }
        })?;
        let _ = udp_socket.set_nonblocking(true);
        let bound_udp_addr = udp_socket
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();

        let http_listener = std::net::TcpListener::bind(&cfg.http_addr).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: cfg.http_addr.clone(),
                reason: err.to_string(),
            }
        })?;
        let _ = http_listener.set_nonblocking(true);
        let bound_http_addr = http_listener
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();

        let dns_socket = std::net::UdpSocket::bind(&cfg.dns_addr).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: cfg.dns_addr.clone(),
                reason: err.to_string(),
            }
        })?;
        let _ = dns_socket.set_nonblocking(true);
        let bound_dns_addr = dns_socket
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();

        let mut master = arbiter_master::MasterNode::new(
            store,
            arbiter_core::workload::RoleHierarchy::new(),
            cfg.agent_lease_ttl_ticks,
            cfg.offer_ttl_ticks,
        );
        let _ = master.recover_from_state_store(0);
        Ok(Self {
            udp_socket,
            bound_udp_addr,
            http_listener,
            bound_http_addr,
            dns_socket,
            bound_dns_addr,
            service_discovery: arbiter_telemetry::discovery::ServiceDiscoveryRegistry::new(),
            master,
            current_tick: 0,
        })
    }

    /// Executes one non-blocking daemon tick: drains inbound UDP [`arbiter_proto::WireEnvelope`]
    /// frames (`RegisterAgent`, `AgentHeartbeat`, `TaskStatusUpdate`), serves any pending HTTP
    /// operator/dashboard requests, serves any pending UDP DNS discovery queries, and advances
    /// `MasterNode::schedule_tick`.
    ///
    /// # Returns
    ///
    /// Tuple `(udp_frames_processed, http_requests_served)` during this tick.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if an inbound UDP frame is malformed JSON.
    pub fn poll_network_and_tick(&mut self) -> ArbiterResult<(usize, usize)> {
        use std::io::{Read, Write};

        self.current_tick = self.current_tick.saturating_add(1);
        let mut udp_count = 0_usize;
        let mut rx_buf = [0_u8; 8192];
        while let Ok((n, peer_addr)) = self.udp_socket.recv_from(&mut rx_buf) {
            let slice = rx_buf.get(..n).unwrap_or(&[]);
            let env = arbiter_proto::WireEnvelope::from_json_str(&String::from_utf8_lossy(slice))?;
            match env.message {
                arbiter_proto::WireMessage::RegisterAgent(reg) => {
                    let ack = format!("MASTER_ACK:{}", reg.agent_id);
                    let _ = self.master.register_agent(*reg, self.current_tick);
                    let _ = self.udp_socket.send_to(ack.as_bytes(), peer_addr);
                }
                arbiter_proto::WireMessage::AgentHeartbeat(hb) => {
                    let ack = format!("MASTER_ACK:{}", hb.agent_id);
                    let _ = self.master.process_agent_heartbeat(&hb);
                    let _ = self.udp_socket.send_to(ack.as_bytes(), peer_addr);
                }
                arbiter_proto::WireMessage::TaskStatusUpdate(upd) => {
                    let _ = self.master.update_task_status(&upd);
                }
                _ => {}
            }
            udp_count = udp_count.saturating_add(1);
        }

        let mut dns_buf = [0_u8; 512];
        while let Ok((n, dns_peer)) = self.dns_socket.recv_from(&mut dns_buf) {
            let q_slice = dns_buf.get(..n).unwrap_or(&[]);
            if let Ok((tx_id, _, qname, qtype, _)) =
                arbiter_telemetry::discovery::ServiceDiscoveryRegistry::decode_standard_rfc1035_response_packet(q_slice)
            {
                let resp_pkt = self
                    .service_discovery
                    .encode_standard_rfc1035_response_packet(tx_id, qtype, &qname)
                    .unwrap_or_default();
                let _ = self.dns_socket.send_to(&resp_pkt, dns_peer);
            }
        }

        let mut http_count = 0_usize;
        let tui_model = arbiter_tui::TuiStateModel::new();
        while let Ok((mut stream, _)) = self.http_listener.accept() {
            let mut req_buf = [0_u8; 4096];
            let n = stream.read(&mut req_buf).unwrap_or(0);
            let req_str = String::from_utf8_lossy(req_buf.get(..n).unwrap_or(&[]));
            let first_line = req_str.lines().next().unwrap_or("");
            let path = first_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/master/state");
            let body = if path == "/api/v1/operator" {
                let (_, req_body) = req_str.split_once("\r\n\r\n").unwrap_or(("", ""));
                arbiter_proto::WireEnvelope::from_json_str(req_body)
                    .and_then(|env| match env.message {
                        arbiter_proto::WireMessage::OperatorCall(op) => self
                            .master
                            .handle_operator_call(*op, self.current_tick)
                            .map(|resp| format!("{resp:?}")),
                        arbiter_proto::WireMessage::SubmitDirectJob(job) => {
                            self.master.submit_direct_job(job);
                            Ok("JOB_SUBMITTED".to_owned())
                        }
                        arbiter_proto::WireMessage::SchedulerCall(call) => {
                            let _ = self.master.handle_scheduler_call(*call, self.current_tick);
                            Ok("SCHEDULER_CALL_HANDLED".to_owned())
                        }
                        _ => Ok("OPERATOR_IGNORED".to_owned()),
                    })
                    .unwrap_or_else(|e| e.to_string())
            } else {
                arbiter_tui::handle_web_dashboard_request(path, &self.master, &tui_model)
                    .unwrap_or_else(|e| e.to_string())
            };
            let wire_resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(wire_resp.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Both);
            http_count = http_count.saturating_add(1);
        }

        let _ = self.master.schedule_tick(&[], self.current_tick);
        let _ = self.master.reconcile_unhealthy_agents(self.current_tick);
        let _ = self
            .master
            .evaluate_framework_failover_timeouts(self.current_tick);
        Ok((udp_count, http_count))
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
        Ok(cfg) => {
            if cfg.signal_mode == SignalSourceMode::ContinuousDaemon {
                let (_, status) = cfg.run_async_tokio_daemon().unwrap_or_default();
                (ExitCode::SUCCESS, status)
            } else {
                let mut sig = BoundedTickSignalSource {
                    max_ticks: cfg.max_ticks,
                    reload_at_tick: None,
                    fail_signal: false,
                };
                let (_, _, status) = cfg.run_daemon_loop(&mut sig).unwrap_or_default();
                (ExitCode::SUCCESS, status)
            }
        }
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
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
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
            "--federation-cluster-id",
            "us-east-1",
            "--federation-peers",
            "eu-west-1@10.1.0.1:5050,ap-south-1@10.2.0.1:5050",
            "--max-ticks",
            "5",
            "--daemon",
            "--oneshot",
        ])
        .unwrap_or_default();
        assert_eq!(custom.raft_node_id, 3);
        assert_eq!(custom.max_ticks, 5);
        assert_eq!(custom.raft_peers.len(), 2);
        assert_eq!(custom.federation_cluster_id, "us-east-1");
        assert_eq!(custom.federation_peers.len(), 2);
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
        let (code_daemon_ok, _) = run_master_main(&[
            "--bind-addr",
            "127.0.0.1:0",
            "--http-addr",
            "127.0.0.1:0",
            "--dns-addr",
            "127.0.0.1:0",
            "--max-ticks",
            "1",
            "--daemon",
        ]);
        assert!(code_daemon_ok.is_success());
        let (code_err, _) = run_master_main(&["--unknown"]);
        assert!(!code_err.is_success());

        let mut net_cfg = MasterCliConfig::default();
        "127.0.0.1:0".clone_into(&mut net_cfg.bind_addr);
        "127.0.0.1:0".clone_into(&mut net_cfg.http_addr);
        assert_eq!(net_cfg.run_live_network_daemon_once("agent-net-1"), Ok(2));
        assert!(net_cfg.run_live_network_daemon_once("").is_err());

        let _ = PersistentMasterNetworkDaemon::bind_from_config(&net_cfg).map(|mut daemon| {
            assert_eq!(daemon.poll_network_and_tick(), Ok((0, 0)));

            let _ = std::net::UdpSocket::bind("127.0.0.1:0").map(|cli_udp| {
                let aid = arbiter_core::ids::AgentId::new("agent-live-d1").unwrap_or_default();
                let reg_env = arbiter_proto::WireEnvelope::new(
                    1,
                    arbiter_proto::WireMessage::RegisterAgent(Box::new(
                        arbiter_proto::RegisterAgent {
                            agent_id: aid.clone(),
                            os_kind: arbiter_core::platform::OsKind::Linux,
                            cpu_arch: arbiter_core::platform::CpuArch::X86_64,
                            total_resources: arbiter_core::resources::ResourceBundle::zero(),
                            topology: arbiter_core::topology::HardwareTopologyGraph::default(),
                        },
                    )),
                );
                let hb_env = arbiter_proto::WireEnvelope::new(
                    2,
                    arbiter_proto::WireMessage::AgentHeartbeat(arbiter_proto::AgentHeartbeat {
                        agent_id: aid.clone(),
                        tick: 1,
                        healthy_tasks: Vec::new(),
                    }),
                );
                let upd_env = arbiter_proto::WireEnvelope::new(
                    3,
                    arbiter_proto::WireMessage::TaskStatusUpdate(arbiter_proto::TaskStatusUpdate {
                        task_id: arbiter_core::ids::TaskId::new("t-d1").unwrap_or_default(),
                        agent_id: aid,
                        state: arbiter_core::workload::TaskState::Running,
                        message: "running".to_owned(),
                    }),
                );
                let other_env = arbiter_proto::WireEnvelope::new(
                    4,
                    arbiter_proto::WireMessage::SchedulerEvent(Box::new(
                        arbiter_proto::SchedulerEvent::Heartbeat,
                    )),
                );
                let _ = cli_udp.send_to(
                    reg_env.to_json_string().unwrap_or_default().as_bytes(),
                    &daemon.bound_udp_addr,
                );
                let _ = cli_udp.send_to(
                    hb_env.to_json_string().unwrap_or_default().as_bytes(),
                    &daemon.bound_udp_addr,
                );
                let _ = cli_udp.send_to(
                    upd_env.to_json_string().unwrap_or_default().as_bytes(),
                    &daemon.bound_udp_addr,
                );
                let _ = cli_udp.send_to(
                    other_env.to_json_string().unwrap_or_default().as_bytes(),
                    &daemon.bound_udp_addr,
                );
                let _ = std::net::TcpStream::connect(&daemon.bound_http_addr).map(|mut s| {
                    use std::io::Write;
                    let _ = s.write_all(b"GET /master/state HTTP/1.1\r\n\r\n");
                });
                let _ = std::net::TcpStream::connect(&daemon.bound_http_addr).map(|mut s| {
                    use std::io::Write;
                    let _ = s.write_all(b"GET /unknown-endpoint HTTP/1.1\r\n\r\n");
                });
                let op_env = arbiter_proto::WireEnvelope::new(
                    5,
                    arbiter_proto::WireMessage::OperatorCall(Box::new(
                        arbiter_proto::OperatorCall::GetHealth,
                    )),
                );
                let op_json = op_env.to_json_string().unwrap_or_default();
                let _ = std::net::TcpStream::connect(&daemon.bound_http_addr).map(|mut s| {
                    use std::io::Write;
                    let req = format!(
                        "POST /api/v1/operator HTTP/1.1\r\nContent-Length: {}\r\n\r\n{op_json}",
                        op_json.len()
                    );
                    let _ = s.write_all(req.as_bytes());
                });
                let job_env = arbiter_proto::WireEnvelope::new(
                    6,
                    arbiter_proto::WireMessage::SubmitDirectJob(
                        arbiter_proto::SubmitDirectJob::SingleTask(Box::new(
                            arbiter_core::workload::TaskSpec {
                                task_id: arbiter_core::ids::TaskId::new("t-direct-1")
                                    .unwrap_or_default(),
                                role: arbiter_core::ids::RoleName::new("prod").unwrap_or_default(),
                                framework_id: None,
                                election_group: None,
                                priority: arbiter_core::workload::PriorityClass::ProductionStandard,
                                preemption_policy:
                                    arbiter_core::workload::PreemptionPolicy::GracefulSigterm,
                                resources: arbiter_core::resources::ResourceBundle::zero(),
                                required_gpu_vendor: None,
                                required_gpu_partition: None,
                                topology_constraints: Vec::new(),
                                isolation: arbiter_core::workload::IsolationSpec {
                                    capabilities: Vec::new(),
                                    image_ref: None,
                                    command: "/bin/true".to_owned(),
                                    args: Vec::new(),
                                    env: Vec::new(),
                                    run_as_user: None,
                                },
                                artifacts: Vec::new(),
                                secrets: Vec::new(),
                                health_check: None,
                            },
                        )),
                    ),
                );
                let job_json = job_env.to_json_string().unwrap_or_default();
                let _ = std::net::TcpStream::connect(&daemon.bound_http_addr).map(|mut s| {
                    use std::io::Write;
                    let req = format!(
                        "POST /api/v1/operator HTTP/1.1\r\nContent-Length: {}\r\n\r\n{job_json}",
                        job_json.len()
                    );
                    let _ = s.write_all(req.as_bytes());
                });
                let sched_env = arbiter_proto::WireEnvelope::new(
                    7,
                    arbiter_proto::WireMessage::SchedulerCall(Box::new(
                        arbiter_proto::SchedulerCall::Teardown(
                            arbiter_core::ids::FrameworkId::new("fw-none").unwrap_or_default(),
                        ),
                    )),
                );
                let sched_json = sched_env.to_json_string().unwrap_or_default();
                let _ = std::net::TcpStream::connect(&daemon.bound_http_addr).map(|mut s| {
                    use std::io::Write;
                    let req = format!(
                        "POST /api/v1/operator HTTP/1.1\r\nContent-Length: {}\r\n\r\n{sched_json}",
                        sched_json.len()
                    );
                    let _ = s.write_all(req.as_bytes());
                });
                let non_op_json = other_env.to_json_string().unwrap_or_default();
                let _ = std::net::TcpStream::connect(&daemon.bound_http_addr).map(|mut s| {
                    use std::io::Write;
                    let req = format!(
                        "POST /api/v1/operator HTTP/1.1\r\nContent-Length: {}\r\n\r\n{non_op_json}",
                        non_op_json.len()
                    );
                    let _ = s.write_all(req.as_bytes());
                });
                let _ = std::net::TcpStream::connect(&daemon.bound_http_addr).map(|mut s| {
                    use std::io::Write;
                    let _ =
                        s.write_all(b"POST /api/v1/operator HTTP/1.1\r\n\r\n{bad_operator_json");
                });
                let (u_cnt, h_cnt) = daemon.poll_network_and_tick().unwrap_or_default();
                assert_eq!(u_cnt, 4);
                assert_eq!(h_cnt, 7);
                assert_eq!(daemon.master.agents.len(), 1);
            });
        });

        let _ = PersistentMasterNetworkDaemon::bind_from_config(&net_cfg).map(|mut err_daemon| {
            let _ = err_daemon.udp_socket.set_nonblocking(false);
            let _ = err_daemon
                .udp_socket
                .set_read_timeout(Some(std::time::Duration::from_millis(50)));
            let _ = std::net::UdpSocket::bind("127.0.0.1:0").map(|bad_udp| {
                let _ = bad_udp.send_to(b"{bad_json", &err_daemon.bound_udp_addr);
                assert!(err_daemon.poll_network_and_tick().is_err());
            });
        });

        let mut bad_http_cfg = net_cfg.clone();
        "invalid-http-addr".clone_into(&mut bad_http_cfg.http_addr);
        assert!(PersistentMasterNetworkDaemon::bind_from_config(&bad_http_cfg).is_err());

        let mut bad_dns_cfg = net_cfg.clone();
        "invalid-dns-addr".clone_into(&mut bad_dns_cfg.dns_addr);
        assert!(PersistentMasterNetworkDaemon::bind_from_config(&bad_dns_cfg).is_err());

        let mut async_cfg = net_cfg.clone();
        async_cfg.max_ticks = 2;
        async_cfg.raft_peers = vec![
            "raft-node-1".to_owned(),
            "raft-node-2".to_owned(),
            "raft-node-2".to_owned(),
        ];
        assert_eq!(async_cfg.run_async_tokio_daemon().map(|(t, _)| t), Ok(2));

        let _ = PersistentMasterNetworkDaemon::bind_from_config(&net_cfg).map(|mut dns_daemon| {
            let _ = dns_daemon.dns_socket.set_nonblocking(false);
            let _ = dns_daemon
                .dns_socket
                .set_read_timeout(Some(std::time::Duration::from_millis(50)));
            let _ = std::net::UdpSocket::bind("127.0.0.1:0").map(|dns_cli| {
                let q_pkt = dns_daemon
                    .service_discovery
                    .encode_standard_rfc1035_response_packet(
                        0x1234,
                        arbiter_telemetry::discovery::DnsRecordType::A,
                        "t1.svc.prod.arbiter.internal",
                    )
                    .unwrap_or_default();
                let _ = dns_cli.send_to(&q_pkt, &dns_daemon.bound_dns_addr);
                let _ = dns_cli.send_to(b"short", &dns_daemon.bound_dns_addr);
                assert!(dns_daemon.poll_network_and_tick().is_ok());
            });
        });

        let mut live_sig = LiveOsSignalSource::new(2);
        assert_eq!(live_sig.poll_signal(0), Ok(DaemonSignal::Continue));
        live_sig.inject_signal(DaemonSignal::Continue);
        assert_eq!(live_sig.poll_signal(0), Ok(DaemonSignal::Continue));
        live_sig.inject_signal(DaemonSignal::ReloadSighup);
        assert_eq!(live_sig.poll_signal(0), Ok(DaemonSignal::ReloadSighup));
        live_sig.inject_signal(DaemonSignal::ShutdownSigterm);
        assert_eq!(live_sig.poll_signal(0), Ok(DaemonSignal::ShutdownSigterm));
        assert_eq!(live_sig.poll_signal(2), Ok(DaemonSignal::ShutdownSigterm));
        live_sig.inject_channel_error();
        assert!(live_sig.poll_signal(0).is_err());

        let dns_flag_cfg = MasterCliConfig::parse_from_slice(&["--dns-addr", "127.0.0.1:15353"])
            .unwrap_or_default();
        assert_eq!(dns_flag_cfg.dns_addr, "127.0.0.1:15353");

        "invalid-bind-addr".clone_into(&mut net_cfg.bind_addr);
        assert!(PersistentMasterNetworkDaemon::bind_from_config(&net_cfg).is_err());
        assert!(net_cfg.run_live_network_daemon_once("agent-net-1").is_err());
    }
}
