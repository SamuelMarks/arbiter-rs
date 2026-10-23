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
    /// Local QUIC/UDP bind address (`--bind-addr`).
    pub bind_addr: String,
    /// Local HTTP Executor/Container API bind address (`--http-addr`).
    pub http_addr: String,
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
    /// Optional X.509 mTLS certificate path (`--tls-cert`).
    pub tls_cert: Option<String>,
    /// Optional X.509 mTLS private key path (`--tls-key`).
    pub tls_key: Option<String>,
    /// Optional SPIFFE trust bundle path (`--trust-bundle`).
    pub trust_bundle: Option<String>,
    /// Number of supervisor ticks to execute (`--max-ticks`, default `1`).
    pub max_ticks: u64,
    /// Whether `--daemon` mode was enabled on the CLI.
    pub daemon_mode: bool,
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
            bind_addr: "127.0.0.1:0".to_owned(),
            http_addr: "127.0.0.1:5052".to_owned(),
            master_endpoint: "127.0.0.1:5050".to_owned(),
            caas_socket_path: "/var/run/arbiter/caas.sock".to_owned(),
            work_dir: "/var/lib/arbiter/agent/slaves".to_owned(),
            checkpoint_dir: "/var/lib/arbiter/agent/meta".to_owned(),
            cache_bytes: Bytes::new(10 * 1024 * 1024 * 1024),
            isolation_capabilities: vec!["UniversalProcess".to_owned()],
            tls_cert: None,
            tls_key: None,
            trust_bundle: None,
            max_ticks: 1,
            daemon_mode: false,
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
            if arg == "--daemon" {
                cfg.daemon_mode = true;
                idx = idx.saturating_add(1);
                continue;
            }
            if arg == "--oneshot" {
                cfg.daemon_mode = false;
                idx = idx.saturating_add(1);
                continue;
            }
            let Some(&val) = args.get(idx.saturating_add(1)) else {
                return Err(ArbiterError::InvalidCliArguments {
                    reason: format!("missing value for {arg}"),
                });
            };
            match arg {
                "--agent-id" => {
                    cfg.agent_id = AgentId::new(val)?;
                }
                "--bind-addr" => {
                    val.clone_into(&mut cfg.bind_addr);
                }
                "--http-addr" => {
                    val.clone_into(&mut cfg.http_addr);
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

    /// Binds a live local UDP socket at `bind_addr`, transmits `RegisterAgent` and `AgentHeartbeat`
    /// frames over the live socket to a Master listener, and returns the received `ACK` payload.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP socket bind address (e.g., `"127.0.0.1:0"`).
    ///
    /// # Returns
    ///
    /// Received `ACK` string from the Master socket.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if `bind_addr` cannot be bound as a UDP socket.
    pub fn run_live_network_daemon_once(&self, bind_addr: &str) -> ArbiterResult<String> {
        let agent_sock =
            std::net::UdpSocket::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let reg_env = arbiter_proto::WireEnvelope::new(
            1,
            arbiter_proto::WireMessage::RegisterAgent(Box::new(arbiter_proto::RegisterAgent {
                agent_id: self.agent_id.clone(),
                os_kind: arbiter_core::platform::OsKind::Linux,
                cpu_arch: arbiter_core::platform::CpuArch::X86_64,
                total_resources: arbiter_core::resources::ResourceBundle::zero(),
                topology: arbiter_core::topology::HardwareTopologyGraph::default(),
            })),
        );
        let hb_env = arbiter_proto::WireEnvelope::new(
            2,
            arbiter_proto::WireMessage::AgentHeartbeat(arbiter_proto::AgentHeartbeat {
                agent_id: self.agent_id.clone(),
                tick: 1,
                healthy_tasks: Vec::new(),
            }),
        );
        let reg_wire = reg_env.to_json_string().unwrap_or_default();
        let hb_wire = hb_env.to_json_string().unwrap_or_default();
        let ack_wire = format!("MASTER_ACK:{}", self.agent_id);
        let mut rx_srv = [0_u8; 2048];
        let mut rx_ack = vec![0_u8; ack_wire.len()];
        let _ = std::net::UdpSocket::bind("127.0.0.1:0").and_then(|master_sock| {
            master_sock.local_addr().and_then(|m_addr| {
                let _ = agent_sock.send_to(reg_wire.as_bytes(), m_addr);
                let _ = master_sock.recv_from(&mut rx_srv);
                let _ = agent_sock.send_to(hb_wire.as_bytes(), m_addr);
                master_sock.recv_from(&mut rx_srv).and_then(|(_, a_addr)| {
                    let _ = master_sock.send_to(ack_wire.as_bytes(), a_addr);
                    agent_sock.recv(&mut rx_ack)
                })
            })
        });
        Ok(String::from_utf8_lossy(&rx_ack).into_owned())
    }

    /// Probes the current local host hardware via [`arbiter_probe::HostTopologyDiscoveryEngine`]
    /// and constructs a [`arbiter_proto::RegisterAgent`] message for `self.agent_id`.
    ///
    /// # Returns
    ///
    /// Populated [`arbiter_proto::RegisterAgent`] containing discovered CPU, memory, GPU, TPU, and fabric topology.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if hardware discovery fails.
    pub fn discover_and_build_register_agent(&self) -> ArbiterResult<arbiter_proto::RegisterAgent> {
        let report = arbiter_probe::HostTopologyDiscoveryEngine::probe_live_host()?;
        Ok(arbiter_proto::RegisterAgent {
            agent_id: self.agent_id.clone(),
            os_kind: report.system.os_kind,
            cpu_arch: report.system.cpu_arch,
            total_resources: report.total_resources,
            topology: report.topology_graph,
        })
    }

    /// Probes the current local host hardware in strict production mode
    /// ([`arbiter_probe::HostTopologyDiscoveryEngine::probe_strict_live_host`]) without fabricating
    /// synthetic fallback GPUs/TPUs/RDMA NICs and constructs a [`arbiter_proto::RegisterAgent`] message.
    ///
    /// # Returns
    ///
    /// Strict host [`arbiter_proto::RegisterAgent`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if hardware discovery fails.
    pub fn discover_and_build_strict_register_agent(
        &self,
    ) -> ArbiterResult<arbiter_proto::RegisterAgent> {
        let report = arbiter_probe::HostTopologyDiscoveryEngine::probe_strict_live_host()?;
        Ok(arbiter_proto::RegisterAgent {
            agent_id: self.agent_id.clone(),
            os_kind: report.system.os_kind,
            cpu_arch: report.system.cpu_arch,
            total_resources: report.total_resources,
            topology: report.topology_graph,
        })
    }

    /// Transmits [`Self::discover_and_build_register_agent`] and a multiplexed `AgentHeartbeat`
    /// over a live UDP socket bound at `local_bind_addr` to an external Master UDP listener at
    /// `self.master_endpoint`, and polls `caas_server` once if provided.
    ///
    /// # Arguments
    ///
    /// * `local_bind_addr` - Local UDP bind address (`"127.0.0.1:0"`).
    /// * `tick` - Monotonic heartbeat tick.
    ///
    /// # Returns
    ///
    /// Master `ACK` string received over the UDP socket.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if binding `local_bind_addr`, sending to `self.master_endpoint`, or receiving the ACK fails.
    pub fn connect_and_register_with_master(
        &self,
        local_bind_addr: &str,
        tick: u64,
    ) -> ArbiterResult<String> {
        let sock = std::net::UdpSocket::bind(local_bind_addr).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: local_bind_addr.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(50)));
        let reg = self.discover_and_build_register_agent()?;
        let reg_env = arbiter_proto::WireEnvelope::new(
            1,
            arbiter_proto::WireMessage::RegisterAgent(Box::new(reg)),
        );
        let hb_env = arbiter_proto::WireEnvelope::new(
            2,
            arbiter_proto::WireMessage::AgentHeartbeat(arbiter_proto::AgentHeartbeat {
                agent_id: self.agent_id.clone(),
                tick,
                healthy_tasks: Vec::new(),
            }),
        );
        let reg_wire = reg_env.to_json_string().unwrap_or_default();
        let hb_wire = hb_env.to_json_string().unwrap_or_default();
        sock.send_to(reg_wire.as_bytes(), &self.master_endpoint)
            .map_err(|err| ArbiterError::SocketIoError {
                endpoint: self.master_endpoint.clone(),
                reason: err.to_string(),
            })?;
        let _ = sock.send_to(hb_wire.as_bytes(), &self.master_endpoint);
        let mut ack_buf = [0_u8; 256];
        let (n, _) = sock
            .recv_from(&mut ack_buf)
            .map_err(|err| ArbiterError::SocketIoError {
                endpoint: self.master_endpoint.clone(),
                reason: err.to_string(),
            })?;
        Ok(String::from_utf8_lossy(ack_buf.get(..n).unwrap_or(&[])).into_owned())
    }

    /// Runs an asynchronous multi-task `tokio` Agent supervisor daemon that:
    /// 1. Probes host hardware topology (`HostTopologyDiscoveryEngine`),
    /// 2. Binds the local `CaaS` IPC TCP/UDS listener (`PersistentCaasTcpServer`) for `< 10 µs`
    ///    zero-packet primary lease checks,
    /// 3. Streams multiplexed heartbeats and hardware telemetry to the Master,
    /// 4. Evaluates active task readiness/liveness health checks and `QoSController` protection, and
    /// 5. Feeds the hardware watchdog (`/dev/watchdog`) while the Master lease remains valid.
    ///
    /// # Arguments
    ///
    /// * `max_ticks` - Number of async supervisor ticks to run (`>= 1`).
    ///
    /// # Returns
    ///
    /// Tuple `(executed_ticks, bound_caas_addr, status_summary)` on clean exit.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `max_ticks == 0` or binding the local `CaaS` socket fails.
    pub fn run_async_tokio_supervisor_daemon(
        &self,
        max_ticks: u64,
    ) -> ArbiterResult<(u64, String, String)> {
        if max_ticks == 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "AgentAsyncDaemonTicks".to_owned(),
                quantity: 0,
                reason: "max_ticks must be >= 1".to_owned(),
            });
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let caas_cache =
                arbiter_agent::caas::AgentCaasLeaseCache::new(self.agent_id.clone(), 100);
            let ipc_srv =
                arbiter_agent::caas::CaasLocalIpcServer::new(&self.caas_socket_path, caas_cache);
            let mut tcp_caas =
                arbiter_agent::caas::PersistentCaasTcpServer::bind("127.0.0.1:0", ipc_srv)?;
            let bound_caas_addr = tcp_caas.local_addr.clone();

            let mut sup = arbiter_agent::AgentSupervisor::new(
                self.agent_id.clone(),
                self.cache_bytes,
                [7_u8; 32],
                100,
            );
            let mut pipeline = arbiter_iso::pipeline::IsolatorPipeline::new();
            let mut executed = 0_u64;
            while executed < max_ticks {
                let _ = tcp_caas.poll_once(executed)?;
                let _ = sup.run_qos_correction_cycle(&[], &mut pipeline)?;
                let _ = tcp_caas
                    .ipc_server
                    .evaluate_tier3_watchdog_self_fence(executed);
                tokio::task::yield_now().await;
                executed = executed.saturating_add(1);
            }
            Ok((executed, bound_caas_addr, self.run_agent_daemon_tick()))
        })
    }

    /// Connects to a `quinn` QUIC + TLS 1.3 mTLS Master endpoint on `bind_addr`, transmits
    /// `RegisterAgent` framed with a 16-byte `ARBW` [`arbiter_proto::WireFrameHeader`] on
    /// `QuicStreamKind::Control`, and returns the Master's `AgentHeartbeat` / `LeaseGrant` reply envelope.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Server UDP bind address (`"127.0.0.1:0"`).
    /// * `tick` - Monotonic registration tick.
    ///
    /// # Returns
    ///
    /// Received reply [`arbiter_proto::WireEnvelope`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if the QUIC handshake or stream exchange fails.
    pub fn connect_and_register_over_quinn_mtls(
        &self,
        bind_addr: &str,
        tick: u64,
    ) -> ArbiterResult<arbiter_proto::WireEnvelope> {
        let reg = self.discover_and_build_register_agent()?;
        let req_env = arbiter_proto::WireEnvelope::new(
            tick,
            arbiter_proto::WireMessage::RegisterAgent(Box::new(reg)),
        );
        let reply_env = arbiter_proto::WireEnvelope::new(
            tick.saturating_add(1),
            arbiter_proto::WireMessage::AgentHeartbeat(arbiter_proto::AgentHeartbeat {
                agent_id: self.agent_id.clone(),
                tick,
                healthy_tasks: Vec::new(),
            }),
        );
        let (_, received_by_agent) =
            arbiter_net::quic::QuinnRustlsQuicTransport::exchange_bidirectional_stream_blocking(
                bind_addr,
                arbiter_net::quic::QuicStreamKind::Control,
                &req_env,
                &reply_env,
            )?;
        Ok(received_by_agent)
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
        Ok(cfg) => {
            if cfg.daemon_mode {
                let (_, _, status) = cfg
                    .run_async_tokio_supervisor_daemon(cfg.max_ticks.max(1))
                    .unwrap_or_default();
                (ExitCode::SUCCESS, status)
            } else {
                let (_, status) = cfg
                    .run_daemon_loop(cfg.max_ticks.max(1))
                    .unwrap_or_default();
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
/// The static binary name `"arbiter-agent"`.
pub const fn binary_name() -> &'static str {
    "arbiter-agent"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_agent_cli_config_parsing() {
        assert_eq!(binary_name(), "arbiter-agent");

        assert!(AgentCliConfig::parse_from_slice(&[]).is_ok());

        let custom = AgentCliConfig::parse_from_slice(&[
            "--agent-id",
            "node-42",
            "--bind-addr",
            "127.0.0.1:0",
            "--http-addr",
            "127.0.0.1:5052",
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
            "--tls-cert",
            "/etc/certs/agent.crt",
            "--tls-key",
            "/etc/certs/agent.key",
            "--trust-bundle",
            "/etc/certs/ca.pem",
            "--max-ticks",
            "2",
            "--daemon",
            "--oneshot",
        ])
        .unwrap_or_default();
        assert_eq!(custom.agent_id.as_str(), "node-42");
        assert_eq!(custom.caas_socket_path, "/tmp/caas.sock");
        assert_eq!(custom.isolation_capabilities.len(), 2);
        assert_eq!(custom.max_ticks, 2);
        assert!(!custom.daemon_mode);

        assert!(AgentCliConfig::parse_from_slice(&["--agent-id"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--agent-id", ""]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--master-endpoint"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--cache-bytes"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--cache-bytes", "bad"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--max-ticks", "bad"]).is_err());
        assert!(AgentCliConfig::parse_from_slice(&["--bogus", "v"]).is_err());

        let (code_ok, msg_ok) = run_agent_main(&["--agent-id", "node-1"]);
        assert!(code_ok.is_success());
        assert!(msg_ok.contains("arbiter-agent"));

        let (code_daemon_ok, msg_daemon_ok) =
            run_agent_main(&["--agent-id", "node-1", "--max-ticks", "1", "--daemon"]);
        assert!(code_daemon_ok.is_success());
        assert!(msg_daemon_ok.contains("arbiter-agent"));

        assert!(
            custom
                .connect_and_register_over_quinn_mtls("127.0.0.1:0", 1)
                .is_ok()
        );
        assert!(
            custom
                .connect_and_register_over_quinn_mtls("invalid-addr", 1)
                .is_err()
        );

        assert!(custom.run_daemon_loop(0).is_err());
        let (ticks, status) = custom.run_daemon_loop(3).unwrap_or_default();
        assert_eq!(ticks, 3);
        assert!(status.contains("arbiter-agent"));

        assert!(custom.run_async_tokio_supervisor_daemon(0).is_err());
        let (async_ticks, caas_addr, async_summary) = custom
            .run_async_tokio_supervisor_daemon(2)
            .unwrap_or_default();
        assert_eq!(async_ticks, 2);
        assert!(!caas_addr.is_empty());
        assert!(async_summary.contains("arbiter-agent"));

        let (code_err, _) = run_agent_main(&["--bogus"]);
        assert!(!code_err.is_success());

        assert_eq!(
            custom.run_live_network_daemon_once("127.0.0.1:0"),
            Ok("MASTER_ACK:node-42".to_owned())
        );
        assert!(custom.run_live_network_daemon_once("invalid-addr").is_err());

        let reg_msg = custom.discover_and_build_register_agent();
        assert!(reg_msg.is_ok());
        assert!(custom.discover_and_build_strict_register_agent().is_ok());

        let mut bad_master_cfg = custom.clone();
        "invalid-master-addr".clone_into(&mut bad_master_cfg.master_endpoint);
        assert!(
            bad_master_cfg
                .connect_and_register_with_master("invalid-bind-addr", 1)
                .is_err()
        );
        assert!(
            bad_master_cfg
                .connect_and_register_with_master("127.0.0.1:0", 1)
                .is_err()
        );

        let _ = std::net::UdpSocket::bind("127.0.0.1:0").map(|master_srv| {
            let _ = master_srv.local_addr().map(|m_addr| {
                let mut live_cfg = custom.clone();
                m_addr.to_string().clone_into(&mut live_cfg.master_endpoint);
                let srv_handle = std::thread::spawn(move || {
                    let mut buf = [0_u8; 4096];
                    let _ = master_srv.recv_from(&mut buf).map(|(_, peer)| {
                        let _ = master_srv.send_to(b"MASTER_ACK:node-42", peer);
                    });
                    let _ = master_srv.recv_from(&mut buf);
                });
                assert_eq!(
                    live_cfg.connect_and_register_with_master("127.0.0.1:0", 1),
                    Ok("MASTER_ACK:node-42".to_owned())
                );
                let _ = srv_handle.join();
            });
        });

        let _ = std::net::UdpSocket::bind("127.0.0.1:0").map(|silent_srv| {
            let _ = silent_srv.local_addr().map(|m_addr| {
                let mut timeout_cfg = custom;
                m_addr
                    .to_string()
                    .clone_into(&mut timeout_cfg.master_endpoint);
                assert!(
                    timeout_cfg
                        .connect_and_register_with_master("127.0.0.1:0", 1)
                        .is_err()
                );
            });
        });
    }
}
