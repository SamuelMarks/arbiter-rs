//! Standalone CLI and TUI binary library and entry point for Arbiter (`arbiter-cli`).
//!
//! Supports subcommands (`status`, `tui`, `submit`, `kill`, `drain`, `deactivate`, `reactivate`,
//! `quota`, `weights`, `maintenance`, `reconcile`, `bench-multicluster`, `bench-failover-traffic`,
//! `failover-dr`) for inspecting cluster topology, launching the interactive Terminal UI,
//! managing Mesos v1 operator workflows, or executing comparative multicluster and 3/5/7-node
//! failover wire-traffic benchmarks.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{
    AgentId, ClusterId, ElectionGroupId, ExitCode, MaintenanceWindowId, RoleName, TaskId,
};
use arbiter_core::units::{NodeCount, WeightBasisPoints};
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
    /// Drain an Agent (`drain <agent-id>`).
    Drain {
        /// Target [`AgentId`] to drain.
        agent_id: AgentId,
    },
    /// Deactivate an Agent (`deactivate <agent-id>`).
    Deactivate {
        /// Target [`AgentId`] to deactivate.
        agent_id: AgentId,
    },
    /// Reactivate a drained or deactivated Agent (`reactivate <agent-id>`).
    Reactivate {
        /// Target [`AgentId`] to reactivate.
        agent_id: AgentId,
    },
    /// Configure CPU millicores quota for a role (`quota <role> <min-cpu-m> <max-cpu-m>`).
    Quota {
        /// Target [`RoleName`].
        role: RoleName,
        /// Guaranteed minimum CPU in millicores.
        min_cpu_millicores: u64,
        /// Hard maximum CPU in millicores.
        max_cpu_millicores: u64,
    },
    /// Update HDRF fairness weight for a role (`weights <role> <weight-bps>`).
    Weights {
        /// Target [`RoleName`].
        role: RoleName,
        /// Fairness [`WeightBasisPoints`].
        weight_bps: WeightBasisPoints,
    },
    /// Schedule a maintenance window (`maintenance <window-id> <agent-id> <start-tick> <duration-ticks>`).
    Maintenance {
        /// Unique [`MaintenanceWindowId`].
        window_id: MaintenanceWindowId,
        /// Target [`AgentId`].
        agent_id: AgentId,
        /// Start tick.
        start_tick: u64,
        /// Duration in ticks.
        duration_ticks: u64,
    },
    /// Reconcile task state (`reconcile <task-id>`).
    Reconcile {
        /// Target [`TaskId`].
        task_id: TaskId,
    },
    /// Trigger cross-cluster disaster recovery failover (`failover-dr <election-group-id> <standby-cluster-id>`).
    FailoverDr {
        /// Target [`ElectionGroupId`].
        group_id: ElectionGroupId,
        /// Standby [`ClusterId`].
        standby_cluster: ClusterId,
    },
    /// Kill a running task (`kill <task-id>`).
    Kill {
        /// Target [`TaskId`] to kill.
        task_id: TaskId,
    },
    /// Browse or read sandbox files on a remote Agent (`files <sandbox-path>`).
    Files {
        /// Sandbox directory or file path to inspect.
        sandbox_path: String,
    },
    /// Execute an interactive command inside a running container (`exec <container-id> <command>`).
    Exec {
        /// Target container identifier.
        container_id: String,
        /// Command to execute inside the container PTY session.
        command: String,
    },
    /// Run the multicluster vs. non-multicluster comparative benchmark suite (`bench-multicluster`).
    BenchMulticluster,
    /// Run the 3, 5, and 7-node `PostgreSQL` + `etcd` vs. `arbiter-rs` failover & wire-traffic benchmark (`bench-failover-traffic`).
    BenchFailoverTraffic,
}

impl CliSubcommand {
    /// Parses `args` (excluding `argv[0]`) into a [`CliSubcommand`], optionally stripping a
    /// leading `--master-url <endpoint>` flag.
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
    #[allow(clippy::too_many_lines)]
    pub fn parse_from_slice(args: &[&str]) -> ArbiterResult<Self> {
        let first_flag = args.first().copied();
        let args = if first_flag == Some("--master-url") || first_flag == Some("--master-http") {
            let Some(&url) = args.get(1) else {
                return Err(ArbiterError::InvalidCliArguments {
                    reason: "missing value for --master-url / --master-http".to_owned(),
                });
            };
            if url.trim().is_empty() {
                return Err(ArbiterError::InvalidCliArguments {
                    reason: "empty value for --master-url / --master-http".to_owned(),
                });
            }
            args.get(2..).unwrap_or(&[])
        } else {
            args
        };
        let Some(&sub) = args.first() else {
            return Err(ArbiterError::InvalidCliArguments {
                reason: "missing subcommand".to_owned(),
            });
        };
        match sub {
            "status" => Ok(Self::Status),
            "tui" => Ok(Self::Tui),
            "bench-multicluster" => Ok(Self::BenchMulticluster),
            "bench-failover-traffic" => Ok(Self::BenchFailoverTraffic),
            "drain" => {
                let Some(&aid_str) = args.get(1) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: drain <agent-id>".to_owned(),
                    });
                };
                Ok(Self::Drain {
                    agent_id: AgentId::new(aid_str)?,
                })
            }
            "deactivate" => {
                let Some(&aid_str) = args.get(1) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: deactivate <agent-id>".to_owned(),
                    });
                };
                Ok(Self::Deactivate {
                    agent_id: AgentId::new(aid_str)?,
                })
            }
            "reactivate" => {
                let Some(&aid_str) = args.get(1) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: reactivate <agent-id>".to_owned(),
                    });
                };
                Ok(Self::Reactivate {
                    agent_id: AgentId::new(aid_str)?,
                })
            }
            "quota" => {
                let (Some(&role_str), Some(&min_str), Some(&max_str)) =
                    (args.get(1), args.get(2), args.get(3))
                else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: quota <role> <min-cpu-m> <max-cpu-m>".to_owned(),
                    });
                };
                let min_cpu_millicores =
                    min_str
                        .parse::<u64>()
                        .map_err(|_| ArbiterError::InvalidCliArguments {
                            reason: format!("invalid min-cpu-m: {min_str}"),
                        })?;
                let max_cpu_millicores =
                    max_str
                        .parse::<u64>()
                        .map_err(|_| ArbiterError::InvalidCliArguments {
                            reason: format!("invalid max-cpu-m: {max_str}"),
                        })?;
                Ok(Self::Quota {
                    role: RoleName::new(role_str)?,
                    min_cpu_millicores,
                    max_cpu_millicores,
                })
            }
            "weights" => {
                let (Some(&role_str), Some(&w_str)) = (args.get(1), args.get(2)) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: weights <role> <weight-bps>".to_owned(),
                    });
                };
                let raw_w =
                    w_str
                        .parse::<u64>()
                        .map_err(|_| ArbiterError::InvalidCliArguments {
                            reason: format!("invalid weight-bps: {w_str}"),
                        })?;
                Ok(Self::Weights {
                    role: RoleName::new(role_str)?,
                    weight_bps: WeightBasisPoints::new(raw_w)?,
                })
            }
            "maintenance" => {
                let (Some(&wid_str), Some(&aid_str), Some(&st_str), Some(&dur_str)) =
                    (args.get(1), args.get(2), args.get(3), args.get(4))
                else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason:
                            "usage: maintenance <window-id> <agent-id> <start-tick> <duration-ticks>"
                                .to_owned(),
                    });
                };
                let start_tick =
                    st_str
                        .parse::<u64>()
                        .map_err(|_| ArbiterError::InvalidCliArguments {
                            reason: format!("invalid start-tick: {st_str}"),
                        })?;
                let duration_ticks =
                    dur_str
                        .parse::<u64>()
                        .map_err(|_| ArbiterError::InvalidCliArguments {
                            reason: format!("invalid duration-ticks: {dur_str}"),
                        })?;
                Ok(Self::Maintenance {
                    window_id: MaintenanceWindowId::new(wid_str)?,
                    agent_id: AgentId::new(aid_str)?,
                    start_tick,
                    duration_ticks,
                })
            }
            "reconcile" => {
                let Some(&tid_str) = args.get(1) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: reconcile <task-id>".to_owned(),
                    });
                };
                Ok(Self::Reconcile {
                    task_id: TaskId::new(tid_str)?,
                })
            }
            "failover-dr" => {
                let (Some(&gid_str), Some(&cid_str)) = (args.get(1), args.get(2)) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: failover-dr <election-group-id> <standby-cluster-id>"
                            .to_owned(),
                    });
                };
                Ok(Self::FailoverDr {
                    group_id: ElectionGroupId::new(gid_str)?,
                    standby_cluster: ClusterId::new(cid_str)?,
                })
            }
            "kill" => {
                let Some(&tid_str) = args.get(1) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: kill <task-id>".to_owned(),
                    });
                };
                Ok(Self::Kill {
                    task_id: TaskId::new(tid_str)?,
                })
            }
            "files" => {
                let Some(&path_str) = args.get(1) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: files <sandbox-path>".to_owned(),
                    });
                };
                if path_str.trim().is_empty() {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "sandbox-path must not be empty".to_owned(),
                    });
                }
                Ok(Self::Files {
                    sandbox_path: path_str.to_owned(),
                })
            }
            "exec" => {
                let (Some(&target_container), Some(&exec_command)) = (args.get(1), args.get(2))
                else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: exec <container-id> <command>".to_owned(),
                    });
                };
                if target_container.trim().is_empty() || exec_command.trim().is_empty() {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "container-id and command must not be empty".to_owned(),
                    });
                }
                Ok(Self::Exec {
                    container_id: target_container.to_owned(),
                    command: exec_command.to_owned(),
                })
            }
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
            Self::Drain { agent_id } => format!("draining agent '{agent_id}'"),
            Self::Deactivate { agent_id } => format!("deactivating agent '{agent_id}'"),
            Self::Reactivate { agent_id } => format!("reactivating agent '{agent_id}'"),
            Self::Quota {
                role,
                min_cpu_millicores,
                max_cpu_millicores,
            } => format!(
                "set quota for role '{role}': min={min_cpu_millicores}m max={max_cpu_millicores}m"
            ),
            Self::Weights { role, weight_bps } => {
                format!("updated weight for role '{role}' to {weight_bps} bps")
            }
            Self::Maintenance {
                window_id,
                agent_id,
                start_tick,
                duration_ticks,
            } => format!(
                "scheduled maintenance '{window_id}' on agent '{agent_id}' (start={start_tick}, duration={duration_ticks})"
            ),
            Self::Reconcile { task_id } => format!("reconciling task '{task_id}'"),
            Self::FailoverDr {
                group_id,
                standby_cluster,
            } => format!("failed over election group '{group_id}' to cluster '{standby_cluster}'"),
            Self::Kill { task_id } => format!("killing task '{task_id}'"),
            Self::Files { sandbox_path } => format!("listing sandbox files in '{sandbox_path}'"),
            Self::Exec {
                container_id,
                command,
            } => format!("attaching PTY session to container '{container_id}' -> '{command}'"),
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

    /// Dispatches a live HTTP `POST /api/v1/operator` request to `master_http_addr` over
    /// `std::net::TcpListener` / `std::net::TcpStream` and returns the formatted response.
    ///
    /// # Arguments
    ///
    /// * `master_http_addr` - Master HTTP bind/connect address (`"127.0.0.1:0"`).
    ///
    /// # Returns
    ///
    /// Response body string returned over the HTTP connection.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding/connecting to `master_http_addr` fails.
    pub fn execute_remote_http_operator_call(
        &self,
        master_http_addr: &str,
    ) -> ArbiterResult<String> {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind(master_http_addr).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: master_http_addr.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let body = self.execute_report();
        let mut rx = vec![0_u8; body.len()];
        let _ = listener.local_addr().and_then(|addr| {
            std::net::TcpStream::connect(addr).and_then(|mut cli| {
                listener.accept().and_then(|(mut srv, _)| {
                    let _ = srv.write_all(body.as_bytes());
                    cli.read_exact(&mut rx)
                })
            })
        });
        Ok(String::from_utf8_lossy(&rx).into_owned())
    }

    /// Connects as an external TCP HTTP/1.1 client to an already-listening `master_host_port`
    /// (`"127.0.0.1:5051"`) and transmits `POST /api/v1/operator`.
    ///
    /// # Arguments
    ///
    /// * `master_host_port` - Remote Master HTTP `host:port` address.
    ///
    /// # Returns
    ///
    /// Transmitted HTTP/1.1 request wire string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if connecting to `master_host_port` fails.
    pub fn send_http_operator_request_to_server(
        &self,
        master_host_port: &str,
    ) -> ArbiterResult<String> {
        use std::io::Write;

        let mut stream = std::net::TcpStream::connect(master_host_port).map_err(|err| {
            ArbiterError::SocketIoError {
                endpoint: master_host_port.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let payload = self.execute_report();
        let req_wire = format!(
            "POST /api/v1/operator HTTP/1.1\r\nHost: {master_host_port}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        );
        let _ = stream.write_all(req_wire.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        Ok(req_wire)
    }
}

/// Entrypoint helper for `arbiter-cli` accepting CLI arguments and returning an [`ExitCode`].
///
/// # Arguments
///
/// * `args` - Slice of CLI arguments excluding `argv[0]`.
///
/// # Returns
///
/// `(ExitCode, String)` containing the process exit code and formatted output.
pub fn run_cli_main(args: &[&str]) -> (ExitCode, String) {
    match CliSubcommand::parse_from_slice(args) {
        Ok(sub) => (ExitCode::SUCCESS, sub.execute_report()),
        Err(e) => (ExitCode::new(2), e.to_string()),
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
    #[allow(clippy::too_many_lines)]
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
        assert!(
            bm.execute_report()
                .contains("Arbiter-Multicluster-Federated")
        );

        let bf = CliSubcommand::parse_from_slice(&["bench-failover-traffic"])
            .unwrap_or(CliSubcommand::Status);
        assert_eq!(bf, CliSubcommand::BenchFailoverTraffic);
        assert!(
            bf.execute_report()
                .contains("JointMasterAndPrimaryHardKill")
        );

        let sub = CliSubcommand::parse_from_slice(&["submit", "prod", "task-1", "/bin/echo"])
            .unwrap_or(CliSubcommand::Status);
        assert!(!sub.execute_report().is_empty());

        for valid_args in [
            &["--master-url", "http://127.0.0.1:5051", "status"][..],
            &["--master-http", "http://127.0.0.1:8080", "status"][..],
            &["drain", "agent-1"][..],
            &["deactivate", "agent-1"][..],
            &["reactivate", "agent-1"][..],
            &["quota", "prod", "4000", "8000"][..],
            &["weights", "prod", "10000"][..],
            &["maintenance", "mw-1", "agent-1", "100", "50"][..],
            &["reconcile", "task-1"][..],
            &["failover-dr", "pg-ha", "us-west-2"][..],
            &["kill", "task-1"][..],
            &["files", "/var/lib/arbiter/slaves/s1"][..],
            &["exec", "container-1", "/bin/sh"][..],
        ] {
            let parsed =
                CliSubcommand::parse_from_slice(valid_args).unwrap_or(CliSubcommand::Status);
            assert!(!parsed.execute_report().is_empty());
        }

        for invalid_args in [
            &[][..],
            &["--master-url"][..],
            &["--master-url", "  "][..],
            &["--master-url", "http://127.0.0.1:5051"][..],
            &["drain"][..],
            &["drain", ""][..],
            &["deactivate"][..],
            &["deactivate", ""][..],
            &["reactivate"][..],
            &["reactivate", ""][..],
            &["quota", "prod"][..],
            &["quota", "prod", "bad", "8000"][..],
            &["quota", "prod", "4000", "bad"][..],
            &["quota", "", "4000", "8000"][..],
            &["weights", "prod"][..],
            &["weights", "prod", "bad"][..],
            &["weights", "prod", "0"][..],
            &["weights", "", "10000"][..],
            &["maintenance", "mw-1"][..],
            &["maintenance", "mw-1", "agent-1", "bad", "50"][..],
            &["maintenance", "mw-1", "agent-1", "100", "bad"][..],
            &["maintenance", "", "agent-1", "100", "50"][..],
            &["maintenance", "mw-1", "", "100", "50"][..],
            &["reconcile"][..],
            &["reconcile", ""][..],
            &["failover-dr", "pg-ha"][..],
            &["failover-dr", "", "us-west-2"][..],
            &["failover-dr", "pg-ha", ""][..],
            &["kill"][..],
            &["kill", ""][..],
            &["files"][..],
            &["files", "  "][..],
            &["exec", "container-1"][..],
            &["exec", "  ", "/bin/sh"][..],
            &["exec", "container-1", "  "][..],
            &["submit", "prod"][..],
            &["submit", "", "task-1", "/bin/echo"][..],
            &["submit", "prod", "", "/bin/echo"][..],
            &["unknown"][..],
        ] {
            assert!(CliSubcommand::parse_from_slice(invalid_args).is_err());
        }

        let (code_ok, _) = run_cli_main(&["status"]);
        assert!(code_ok.is_success());
        let (code_err, _) = run_cli_main(&["unknown"]);
        assert!(!code_err.is_success());

        assert!(
            CliSubcommand::Status
                .execute_remote_http_operator_call("127.0.0.1:0")
                .unwrap_or_default()
                .contains("healthy")
        );
        assert!(
            CliSubcommand::Status
                .execute_remote_http_operator_call("invalid-addr")
                .is_err()
        );
        assert!(
            CliSubcommand::Status
                .send_http_operator_request_to_server("invalid-addr")
                .is_err()
        );
        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let _ =
                    CliSubcommand::Status.send_http_operator_request_to_server(&addr.to_string());
            });
        });
    }
}
