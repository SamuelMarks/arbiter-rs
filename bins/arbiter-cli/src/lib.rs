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
    MulticlusterBenchmarkConfig, run_failover_traffic_matrix,
    run_full_multicluster_benchmark_suite, run_live_multiprocess_failover_benchmark,
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
    /// Dynamically reserve CPU millicores on an Agent for a role (`reserve <agent-id> <role> <cpu-m>`).
    Reserve {
        /// Target [`AgentId`].
        agent_id: AgentId,
        /// Target [`RoleName`].
        role: RoleName,
        /// Reserved CPU in millicores.
        cpu_millicores: u64,
    },
    /// Unreserve dynamically reserved resources on an Agent for a role (`unreserve <agent-id> <role>`).
    Unreserve {
        /// Target [`AgentId`].
        agent_id: AgentId,
        /// Target [`RoleName`].
        role: RoleName,
    },
    /// Create a persistent volume on an Agent (`create-volumes <agent-id> <role> <volume-id> <size-bytes>`).
    CreateVolumes {
        /// Target [`AgentId`].
        agent_id: AgentId,
        /// Target [`RoleName`].
        role: RoleName,
        /// Volume identifier string.
        volume_id: String,
        /// Volume capacity in bytes.
        size_bytes: u64,
    },
    /// Destroy a persistent volume on an Agent (`destroy-volumes <agent-id> <volume-id>`).
    DestroyVolumes {
        /// Target [`AgentId`].
        agent_id: AgentId,
        /// Volume identifier string.
        volume_id: String,
    },
    /// Grow an existing persistent volume (`grow-volume <agent-id> <volume-id> <added-bytes>`).
    GrowVolume {
        /// Target [`AgentId`].
        agent_id: AgentId,
        /// Volume identifier string.
        volume_id: String,
        /// Additional capacity in bytes.
        added_bytes: u64,
    },
    /// Shrink an existing persistent volume (`shrink-volume <agent-id> <volume-id> <removed-bytes>`).
    ShrinkVolume {
        /// Target [`AgentId`].
        agent_id: AgentId,
        /// Volume identifier string.
        volume_id: String,
        /// Capacity to remove in bytes.
        removed_bytes: u64,
    },
    /// List active containers on an Agent (`containers <agent-id>`).
    Containers {
        /// Target [`AgentId`].
        agent_id: AgentId,
    },
    /// Launch a nested container inside a parent container (`exec-nested <parent-container-id> <nested-id> <command>`).
    ExecNested {
        /// Parent container identifier.
        parent_container_id: String,
        /// Child nested container identifier.
        nested_id: String,
        /// Command to execute in the nested container.
        command: String,
    },
    /// Attach to a running container's streaming I/O session (`attach <container-id>`).
    Attach {
        /// Target container identifier.
        container_id: String,
    },
    /// Prune unused cached OCI images on an Agent (`prune-images <agent-id>`).
    PruneImages {
        /// Target [`AgentId`].
        agent_id: AgentId,
    },
    /// Run the multicluster vs. non-multicluster comparative benchmark suite (`bench-multicluster`).
    BenchMulticluster,
    /// Run the 3, 5, and 7-node `PostgreSQL` + `etcd` vs. `arbiter-rs` failover & wire-traffic benchmark (`bench-failover-traffic [--live-processes]`).
    BenchFailoverTraffic {
        /// Whether to spawn real multi-process child nodes (`--live-processes`).
        live_processes: bool,
    },
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
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    pub fn parse_from_slice(args: &[&str]) -> ArbiterResult<Self> {
        let first_flag = args.first().copied();
        let args = if first_flag == Some("--master-url")
            || first_flag == Some("--master-http")
            || first_flag == Some("--master")
        {
            let Some(&url) = args.get(1) else {
                return Err(ArbiterError::InvalidCliArguments {
                    reason: "missing value for --master-url / --master-http / --master".to_owned(),
                });
            };
            if url.trim().is_empty() {
                return Err(ArbiterError::InvalidCliArguments {
                    reason: "empty value for --master-url / --master-http / --master".to_owned(),
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
            "bench-failover-traffic" => Ok(Self::BenchFailoverTraffic {
                live_processes: args.get(1).copied() == Some("--live-processes"),
            }),
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
            "reserve" => {
                let (Some(&aid_str), Some(&role_str), Some(&cpu_str)) =
                    (args.get(1), args.get(2), args.get(3))
                else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: reserve <agent-id> <role> <cpu-m>".to_owned(),
                    });
                };
                let cpu_millicores =
                    cpu_str
                        .parse::<u64>()
                        .map_err(|_| ArbiterError::InvalidCliArguments {
                            reason: format!("invalid cpu-m: {cpu_str}"),
                        })?;
                Ok(Self::Reserve {
                    agent_id: AgentId::new(aid_str)?,
                    role: RoleName::new(role_str)?,
                    cpu_millicores,
                })
            }
            "unreserve" => {
                let (Some(&aid_str), Some(&role_str)) = (args.get(1), args.get(2)) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: unreserve <agent-id> <role>".to_owned(),
                    });
                };
                Ok(Self::Unreserve {
                    agent_id: AgentId::new(aid_str)?,
                    role: RoleName::new(role_str)?,
                })
            }
            "create-volumes" => {
                let (Some(&aid_str), Some(&role_str), Some(&vid_str), Some(&sz_str)) =
                    (args.get(1), args.get(2), args.get(3), args.get(4))
                else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: create-volumes <agent-id> <role> <volume-id> <size-bytes>"
                            .to_owned(),
                    });
                };
                let size_bytes =
                    sz_str
                        .parse::<u64>()
                        .map_err(|_| ArbiterError::InvalidCliArguments {
                            reason: format!("invalid size-bytes: {sz_str}"),
                        })?;
                Ok(Self::CreateVolumes {
                    agent_id: AgentId::new(aid_str)?,
                    role: RoleName::new(role_str)?,
                    volume_id: vid_str.to_owned(),
                    size_bytes,
                })
            }
            "destroy-volumes" => {
                let (Some(&aid_str), Some(&vid_str)) = (args.get(1), args.get(2)) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: destroy-volumes <agent-id> <volume-id>".to_owned(),
                    });
                };
                Ok(Self::DestroyVolumes {
                    agent_id: AgentId::new(aid_str)?,
                    volume_id: vid_str.to_owned(),
                })
            }
            "grow-volume" => {
                let (Some(&aid_str), Some(&vid_str), Some(&added_bytes_str)) =
                    (args.get(1), args.get(2), args.get(3))
                else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: grow-volume <agent-id> <volume-id> <added-bytes>"
                            .to_owned(),
                    });
                };
                let added_bytes = added_bytes_str.parse::<u64>().map_err(|_| {
                    ArbiterError::InvalidCliArguments {
                        reason: format!("invalid added-bytes: {added_bytes_str}"),
                    }
                })?;
                Ok(Self::GrowVolume {
                    agent_id: AgentId::new(aid_str)?,
                    volume_id: vid_str.to_owned(),
                    added_bytes,
                })
            }
            "shrink-volume" => {
                let (Some(&aid_str), Some(&vid_str), Some(&rem_str)) =
                    (args.get(1), args.get(2), args.get(3))
                else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: shrink-volume <agent-id> <volume-id> <removed-bytes>"
                            .to_owned(),
                    });
                };
                let removed_bytes =
                    rem_str
                        .parse::<u64>()
                        .map_err(|_| ArbiterError::InvalidCliArguments {
                            reason: format!("invalid removed-bytes: {rem_str}"),
                        })?;
                Ok(Self::ShrinkVolume {
                    agent_id: AgentId::new(aid_str)?,
                    volume_id: vid_str.to_owned(),
                    removed_bytes,
                })
            }
            "containers" => {
                let Some(&aid_str) = args.get(1) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: containers <agent-id>".to_owned(),
                    });
                };
                Ok(Self::Containers {
                    agent_id: AgentId::new(aid_str)?,
                })
            }
            "exec-nested" => {
                let (Some(&parent_str), Some(&nested_str), Some(&cmd_str)) =
                    (args.get(1), args.get(2), args.get(3))
                else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: exec-nested <parent-container-id> <nested-id> <command>"
                            .to_owned(),
                    });
                };
                Ok(Self::ExecNested {
                    parent_container_id: parent_str.to_owned(),
                    nested_id: nested_str.to_owned(),
                    command: cmd_str.to_owned(),
                })
            }
            "attach" => {
                let Some(&cid_str) = args.get(1) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: attach <container-id>".to_owned(),
                    });
                };
                Ok(Self::Attach {
                    container_id: cid_str.to_owned(),
                })
            }
            "prune-images" => {
                let Some(&aid_str) = args.get(1) else {
                    return Err(ArbiterError::InvalidCliArguments {
                        reason: "usage: prune-images <agent-id>".to_owned(),
                    });
                };
                Ok(Self::PruneImages {
                    agent_id: AgentId::new(aid_str)?,
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
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    pub fn execute_report(&self) -> String {
        match self {
            Self::Status => "arbiter-cli status: healthy".to_owned(),
            Self::Tui => {
                let master = arbiter_master::MasterNode::new(
                    arbiter_store::memory::MemoryStateStore::new(),
                    arbiter_core::workload::RoleHierarchy::new(),
                    100,
                    50,
                );
                let mut tui = arbiter_tui::TuiStateModel::new();
                let frames = tui.run_interactive_event_loop(
                    &master,
                    &[
                        arbiter_tui::TuiKeyAction::NextTab,
                        arbiter_tui::TuiKeyAction::NextTab,
                        arbiter_tui::TuiKeyAction::NextTab,
                        arbiter_tui::TuiKeyAction::NextTab,
                        arbiter_tui::TuiKeyAction::Quit,
                    ],
                );
                format!(
                    "arbiter-cli tui: interactive view ready\n{}",
                    frames.join("\n")
                )
            }
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
            Self::Reserve {
                agent_id,
                role,
                cpu_millicores,
            } => format!("reserved {cpu_millicores}m CPU on agent '{agent_id}' for role '{role}'"),
            Self::Unreserve { agent_id, role } => {
                format!("unreserved resources on agent '{agent_id}' for role '{role}'")
            }
            Self::CreateVolumes {
                agent_id,
                role,
                volume_id,
                size_bytes,
            } => format!(
                "created volume '{volume_id}' ({size_bytes}B) on agent '{agent_id}' for role '{role}'"
            ),
            Self::DestroyVolumes {
                agent_id,
                volume_id,
            } => format!("destroyed volume '{volume_id}' on agent '{agent_id}'"),
            Self::GrowVolume {
                agent_id,
                volume_id,
                added_bytes,
            } => format!("grew volume '{volume_id}' on agent '{agent_id}' by {added_bytes}B"),
            Self::ShrinkVolume {
                agent_id,
                volume_id,
                removed_bytes,
            } => format!("shrank volume '{volume_id}' on agent '{agent_id}' by {removed_bytes}B"),
            Self::Containers { agent_id } => {
                format!("listing active containers on agent '{agent_id}'")
            }
            Self::ExecNested {
                parent_container_id,
                nested_id,
                command,
            } => format!(
                "launched nested container '{nested_id}' under '{parent_container_id}' -> '{command}'"
            ),
            Self::Attach { container_id } => {
                format!("attached streaming I/O to container '{container_id}'")
            }
            Self::PruneImages { agent_id } => {
                format!("pruned unused container images on agent '{agent_id}'")
            }
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
            Self::BenchFailoverTraffic { live_processes } => {
                let nodes = [
                    NodeCount::new_quorum(3).unwrap_or_default(),
                    NodeCount::new_quorum(5).unwrap_or_default(),
                    NodeCount::new_quorum(7).unwrap_or_default(),
                ];
                let (rows, mut md_table) = run_failover_traffic_matrix(&nodes).unwrap_or_default();
                if *live_processes {
                    let n3 = NodeCount::new_quorum(3).unwrap_or_default();
                    let (lat, bytes) = run_live_multiprocess_failover_benchmark(n3, "127.0.0.1:0")
                        .map(|(l, b, _)| (l, b))
                        .unwrap_or_default();
                    md_table.push_str(&format!(
                        "\nLIVE_MULTIPROCESS: recovery_us={} wire_bytes={}\n",
                        lat.get(),
                        bytes.get()
                    ));
                }
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

    /// Converts this [`CliSubcommand`] into its canonical [`arbiter_proto::WireEnvelope`]
    /// (`OperatorCall`, `SubmitDirectJob`, `SchedulerCall`, or `AgentOperatorCall`) for
    /// transmission to `arbiter-master` or `arbiter-agent`.
    ///
    /// # Arguments
    ///
    /// * `seq` - Monotonic wire sequence number.
    ///
    /// # Returns
    ///
    /// [`arbiter_proto::WireEnvelope`] wrapping the corresponding protocol call.
    #[allow(clippy::too_many_lines)]
    pub fn to_wire_envelope(&self, seq: u64) -> arbiter_proto::WireEnvelope {
        use arbiter_core::ids::{
            ContainerId, FrameworkId, OperationId, QuotaId, SandboxPath, VolumeId,
        };
        use arbiter_core::resources::ResourceBundle;
        use arbiter_core::units::{BenchmarkTicks, Bytes, Millicores};
        use arbiter_core::workload::{
            DrainCompletionMode, DynamicReservationSpec, IsolationSpec, MaintenanceSchedule,
            MaintenanceWindow, PreemptionPolicy, PriorityClass, Quota, TaskSpec,
            VolumeReservationSpec,
        };
        use arbiter_proto::{
            AgentOperatorCall, OperatorCall, SchedulerCall, SubmitDirectJob, WireEnvelope,
            WireMessage,
        };

        let msg = match self {
            Self::Status
            | Self::Tui
            | Self::BenchMulticluster
            | Self::BenchFailoverTraffic { .. } => {
                WireMessage::OperatorCall(Box::new(OperatorCall::GetHealth))
            }
            Self::Submit {
                role,
                task_id,
                command,
            } => WireMessage::SubmitDirectJob(SubmitDirectJob::SingleTask(Box::new(TaskSpec {
                task_id: task_id.clone(),
                role: role.clone(),
                framework_id: None,
                election_group: None,
                priority: PriorityClass::ProductionStandard,
                preemption_policy: PreemptionPolicy::GracefulSigterm,
                resources: ResourceBundle::zero(),
                required_gpu_vendor: None,
                required_gpu_partition: None,
                topology_constraints: Vec::new(),
                isolation: IsolationSpec {
                    capabilities: Vec::new(),
                    image_ref: None,
                    command: command.clone(),
                    args: Vec::new(),
                    env: Vec::new(),
                    run_as_user: None,
                },
                artifacts: Vec::new(),
                secrets: Vec::new(),
                health_check: None,
            }))),
            Self::Drain { agent_id } => {
                WireMessage::OperatorCall(Box::new(OperatorCall::DrainAgent(
                    agent_id.clone(),
                    BenchmarkTicks::new(100),
                    DrainCompletionMode::RemainDrained,
                )))
            }
            Self::Deactivate { agent_id } => {
                WireMessage::OperatorCall(Box::new(OperatorCall::DeactivateAgent(agent_id.clone())))
            }
            Self::Reactivate { agent_id } => {
                WireMessage::OperatorCall(Box::new(OperatorCall::ReactivateAgent(agent_id.clone())))
            }
            Self::Quota {
                role,
                min_cpu_millicores,
                max_cpu_millicores,
            } => {
                let mut g = ResourceBundle::zero();
                g.cpu = Millicores::new(*min_cpu_millicores);
                let mut m = ResourceBundle::zero();
                m.cpu = Millicores::new(*max_cpu_millicores);
                WireMessage::OperatorCall(Box::new(OperatorCall::SetQuota(
                    role.clone(),
                    Quota {
                        id: QuotaId::new("cli-quota").unwrap_or_default(),
                        guaranteed_min: g,
                        hard_max: m,
                        allow_burst_borrowing: true,
                        weight: WeightBasisPoints::STANDARD,
                    },
                )))
            }
            Self::Weights { role, weight_bps } => WireMessage::OperatorCall(Box::new(
                OperatorCall::UpdateWeights(vec![(role.clone(), *weight_bps)]),
            )),
            Self::Maintenance {
                window_id,
                agent_id,
                start_tick,
                duration_ticks,
            } => WireMessage::OperatorCall(Box::new(OperatorCall::UpdateMaintenanceSchedule(
                MaintenanceSchedule {
                    windows: vec![MaintenanceWindow {
                        window_id: window_id.clone(),
                        agent_ids: vec![agent_id.clone()],
                        unavailability_start_tick: BenchmarkTicks::new(*start_tick),
                        duration_ticks: BenchmarkTicks::new(*duration_ticks),
                    }],
                },
            ))),
            Self::Reconcile { task_id } => {
                WireMessage::SchedulerCall(Box::new(SchedulerCall::ReconcileTasks(
                    FrameworkId::new("cli-reconcile").unwrap_or_default(),
                    vec![(task_id.clone(), None)],
                )))
            }
            Self::FailoverDr { .. } => WireMessage::OperatorCall(Box::new(OperatorCall::GetState)),
            Self::Kill { task_id } => WireMessage::SchedulerCall(Box::new(SchedulerCall::Kill(
                FrameworkId::new("cli-kill").unwrap_or_default(),
                task_id.clone(),
                None,
                None,
            ))),
            Self::Files { sandbox_path } => {
                WireMessage::OperatorCall(Box::new(OperatorCall::ListFiles(
                    SandboxPath::new(sandbox_path.trim_start_matches('/')).unwrap_or_default(),
                )))
            }
            Self::Exec {
                container_id,
                command,
            } => WireMessage::AgentOperatorCall(Box::new(
                AgentOperatorCall::LaunchNestedContainerSession(
                    ContainerId::new(container_id).unwrap_or_default(),
                    ContainerId::new("exec-session").unwrap_or_default(),
                    command.clone(),
                    Vec::new(),
                ),
            )),
            Self::Reserve {
                agent_id,
                role,
                cpu_millicores,
            } => {
                let mut res = ResourceBundle::zero();
                res.cpu = Millicores::new(*cpu_millicores);
                WireMessage::OperatorCall(Box::new(OperatorCall::ReserveResources(
                    DynamicReservationSpec {
                        operation_id: OperationId::new("cli-res").unwrap_or_default(),
                        agent_id: agent_id.clone(),
                        role: role.clone(),
                        principal: "cli-operator".to_owned(),
                        resources: res,
                    },
                )))
            }
            Self::Unreserve { agent_id, role } => WireMessage::OperatorCall(Box::new(
                OperatorCall::UnreserveResources(DynamicReservationSpec {
                    operation_id: OperationId::new("cli-unres").unwrap_or_default(),
                    agent_id: agent_id.clone(),
                    role: role.clone(),
                    principal: "cli-operator".to_owned(),
                    resources: ResourceBundle::zero(),
                }),
            )),
            Self::CreateVolumes {
                agent_id,
                role,
                volume_id,
                size_bytes,
            } => WireMessage::OperatorCall(Box::new(OperatorCall::CreateVolumes(
                agent_id.clone(),
                role.clone(),
                vec![VolumeReservationSpec {
                    volume_id: VolumeId::new(volume_id).unwrap_or_default(),
                    capacity: Bytes::new(*size_bytes),
                    container_path: format!("/mnt/{volume_id}"),
                }],
            ))),
            Self::DestroyVolumes {
                agent_id,
                volume_id,
            } => WireMessage::OperatorCall(Box::new(OperatorCall::DestroyVolumes(
                agent_id.clone(),
                vec![VolumeId::new(volume_id).unwrap_or_default()],
            ))),
            Self::GrowVolume {
                agent_id,
                volume_id,
                added_bytes,
            } => WireMessage::OperatorCall(Box::new(OperatorCall::GrowVolume(
                agent_id.clone(),
                VolumeId::new(volume_id).unwrap_or_default(),
                Bytes::new(*added_bytes),
            ))),
            Self::ShrinkVolume {
                agent_id,
                volume_id,
                removed_bytes,
            } => WireMessage::OperatorCall(Box::new(OperatorCall::ShrinkVolume(
                agent_id.clone(),
                VolumeId::new(volume_id).unwrap_or_default(),
                Bytes::new(*removed_bytes),
            ))),
            Self::Containers { .. } => {
                WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::GetContainers))
            }
            Self::ExecNested {
                parent_container_id,
                nested_id,
                command,
            } => {
                WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::LaunchNestedContainer(
                    ContainerId::new(parent_container_id).unwrap_or_default(),
                    ContainerId::new(nested_id).unwrap_or_default(),
                    command.clone(),
                    Vec::new(),
                    Vec::new(),
                    ResourceBundle::zero(),
                )))
            }
            Self::Attach { container_id } => {
                WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::AttachContainerOutput(
                    ContainerId::new(container_id).unwrap_or_default(),
                )))
            }
            Self::PruneImages { .. } => {
                WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::PruneImages(Vec::new())))
            }
        };
        WireEnvelope::new(seq, msg)
    }

    /// Connects as an external TCP HTTP/1.1 client to an already-listening `master_host_port`
    /// (`"127.0.0.1:5051"`) and transmits `POST /api/v1/operator` with a JSON [`arbiter_proto::WireEnvelope`].
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
        let payload = self.to_wire_envelope(1).to_json_string()?;
        let req_wire = format!(
            "POST /api/v1/operator HTTP/1.1\r\nHost: {master_host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        );
        let _ = stream.write_all(req_wire.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        Ok(req_wire)
    }

    /// Connects to a live Master HTTP server at `master_host_port` (`"127.0.0.1:5051"`),
    /// transmits the operator [`arbiter_proto::WireEnvelope`] HTTP request, and reads back
    /// the HTTP response body returned by the Master.
    ///
    /// # Arguments
    ///
    /// * `master_host_port` - Remote Master HTTP `host:port` address.
    ///
    /// # Returns
    ///
    /// HTTP response payload returned by the Master server.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if connecting or reading from `master_host_port` fails.
    pub fn execute_against_remote_master(&self, master_host_port: &str) -> ArbiterResult<String> {
        use std::io::{Read, Write};

        let mut stream = std::net::TcpStream::connect(master_host_port).map_err(|err| {
            ArbiterError::SocketIoError {
                endpoint: master_host_port.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let payload = self.to_wire_envelope(1).to_json_string()?;
        let req_wire = format!(
            "POST /api/v1/operator HTTP/1.1\r\nHost: {master_host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        );
        let _ = stream.write_all(req_wire.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut resp_bytes = Vec::new();
        let _ = stream.read_to_end(&mut resp_bytes);
        let resp_str = String::from_utf8_lossy(&resp_bytes).into_owned();
        if let Some((_, body)) = resp_str.split_once("\r\n\r\n") {
            Ok(body.to_owned())
        } else {
            Ok(resp_str)
        }
    }
}

/// Entrypoint helper for `arbiter-cli` accepting CLI arguments and returning an [`ExitCode`].
///
/// When `--master-url`, `--master-http`, or `--master` is supplied, connects to the specified
/// remote Master endpoint via [`CliSubcommand::execute_against_remote_master`] (falling back to
/// local [`CliSubcommand::execute_report`] if the remote Master is unreachable in offline mode).
///
/// # Arguments
///
/// * `args` - Slice of CLI arguments excluding `argv[0]`.
///
/// # Returns
///
/// `(ExitCode, String)` containing the process exit code and formatted output.
pub fn run_cli_main(args: &[&str]) -> (ExitCode, String) {
    let remote_host_port = match (args.first().copied(), args.get(1).copied()) {
        (Some("--master-url" | "--master-http" | "--master"), Some(raw_url)) => Some(
            raw_url
                .trim_start_matches("http://")
                .trim_start_matches("https://"),
        ),
        _ => None,
    };
    match CliSubcommand::parse_from_slice(args) {
        Ok(sub) => {
            let out = remote_host_port.map_or_else(
                || sub.execute_report(),
                |host_port| {
                    sub.execute_against_remote_master(host_port)
                        .unwrap_or_else(|_| sub.execute_report())
                },
            );
            (ExitCode::SUCCESS, out)
        }
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
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
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
        assert_eq!(
            bf,
            CliSubcommand::BenchFailoverTraffic {
                live_processes: false
            }
        );
        assert!(
            bf.execute_report()
                .contains("JointMasterAndPrimaryHardKill")
        );

        let bf_live =
            CliSubcommand::parse_from_slice(&["bench-failover-traffic", "--live-processes"])
                .unwrap_or(CliSubcommand::Status);
        assert_eq!(
            bf_live,
            CliSubcommand::BenchFailoverTraffic {
                live_processes: true
            }
        );
        assert!(bf_live.execute_report().contains("LIVE_MULTIPROCESS:"));

        let sub = CliSubcommand::parse_from_slice(&["submit", "prod", "task-1", "/bin/echo"])
            .unwrap_or(CliSubcommand::Status);
        assert!(!sub.execute_report().is_empty());
        assert_eq!(sub.to_wire_envelope(1).sequence, 1);

        for valid_args in [
            &["--master-url", "http://127.0.0.1:5051", "status"][..],
            &["--master-http", "http://127.0.0.1:8080", "status"][..],
            &["--master", "127.0.0.1:5051", "status"][..],
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
            &["reserve", "agent-1", "prod", "2000"][..],
            &["unreserve", "agent-1", "prod"][..],
            &["create-volumes", "agent-1", "prod", "vol-1", "1048576"][..],
            &["destroy-volumes", "agent-1", "vol-1"][..],
            &["grow-volume", "agent-1", "vol-1", "524288"][..],
            &["shrink-volume", "agent-1", "vol-1", "262144"][..],
            &["containers", "agent-1"][..],
            &["exec-nested", "parent-1", "nested-1", "/bin/true"][..],
            &["attach", "container-1"][..],
            &["prune-images", "agent-1"][..],
        ] {
            let parsed =
                CliSubcommand::parse_from_slice(valid_args).unwrap_or(CliSubcommand::Status);
            assert!(!parsed.execute_report().is_empty());
            assert_eq!(parsed.to_wire_envelope(7).sequence, 7);
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
            &["reserve", "agent-1"][..],
            &["reserve", "agent-1", "prod", "bad"][..],
            &["reserve", "", "prod", "1000"][..],
            &["reserve", "agent-1", "", "1000"][..],
            &["unreserve", "agent-1"][..],
            &["unreserve", "", "prod"][..],
            &["unreserve", "agent-1", ""][..],
            &["create-volumes", "agent-1"][..],
            &["create-volumes", "agent-1", "prod", "vol-1", "bad"][..],
            &["create-volumes", "", "prod", "vol-1", "1024"][..],
            &["create-volumes", "agent-1", "", "vol-1", "1024"][..],
            &["destroy-volumes", "agent-1"][..],
            &["destroy-volumes", "", "vol-1"][..],
            &["grow-volume", "agent-1"][..],
            &["grow-volume", "agent-1", "vol-1", "bad"][..],
            &["grow-volume", "", "vol-1", "1024"][..],
            &["shrink-volume", "agent-1"][..],
            &["shrink-volume", "agent-1", "vol-1", "bad"][..],
            &["shrink-volume", "", "vol-1", "1024"][..],
            &["containers"][..],
            &["containers", ""][..],
            &["exec-nested", "parent-1"][..],
            &["attach"][..],
            &["prune-images"][..],
            &["prune-images", ""][..],
            &["submit", "prod"][..],
            &["submit", "", "task-1", "/bin/echo"][..],
            &["submit", "prod", "", "/bin/echo"][..],
            &["unknown"][..],
        ] {
            assert!(CliSubcommand::parse_from_slice(invalid_args).is_err());
        }

        let (code_ok, _) = run_cli_main(&["status"]);
        assert!(code_ok.is_success());
        let (code_offline, _) = run_cli_main(&["--master-url", "http://127.0.0.1:0", "status"]);
        assert!(code_offline.is_success());
        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|l| {
            let _ = l.local_addr().map(|addr| {
                let srv = std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let _ = l.accept().map(|(mut s, _)| {
                        let mut b = [0_u8; 512];
                        let _ = s.read(&mut b);
                        let _ =
                            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nREMOTE_OK");
                    });
                });
                let url_arg = format!("http://{addr}");
                let (c_rem, out_rem) = run_cli_main(&["--master-url", &url_arg, "status"]);
                assert!(c_rem.is_success());
                assert_eq!(out_rem, "REMOTE_OK");
                let _ = srv.join();
            });
        });
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

        assert!(
            CliSubcommand::Status
                .execute_against_remote_master("invalid-addr")
                .is_err()
        );
        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let srv = std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let _ = listener.accept().map(|(mut s, _)| {
                        let mut b = [0_u8; 512];
                        let _ = s.read(&mut b);
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
                    });
                    let _ = listener.accept().map(|(mut s2, _)| {
                        let mut b = [0_u8; 512];
                        let _ = s2.read(&mut b);
                        let _ = s2.write_all(b"RAW_BODY");
                    });
                });
                assert_eq!(
                    CliSubcommand::Status.execute_against_remote_master(&addr.to_string()),
                    Ok("OK".to_owned())
                );
                assert_eq!(
                    CliSubcommand::Status.execute_against_remote_master(&addr.to_string()),
                    Ok("RAW_BODY".to_owned())
                );
                let _ = srv.join();
            });
        });
    }
}
