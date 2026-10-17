//! Terminal UI (TUI) and embedded Web Dashboard state models, view renderers, and HTTP API handlers for Arbiter (`arbiter-tui`).
//!
//! Provides:
//! - [`TuiTab`] and [`TuiStateModel`] tracking active view tabs (`ClusterSummary`, `TopologyVisualizer`, `DrfRoleShares`, `ActiveOffers`, `TaskLogs`).
//! - Deterministic ASCII/Unicode TUI frame renderer (`render_tui_frame`).
//! - Embedded Web Dashboard HTTP API & real-time Server-Sent Events (SSE) handler (`handle_web_dashboard_request`).

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{RoleName, TaskId};
use arbiter_core::units::SharePartsPerBillion;
use arbiter_master::MasterNode;
use arbiter_store::traits::StateStore;
use serde::{Deserialize, Serialize};

/// Interactive tab views available in the Arbiter Terminal UI (`arbiter-tui`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub enum TuiTab {
    /// High-level cluster capacity, healthy agents, active frameworks, and task counts.
    #[default]
    ClusterSummary,
    /// NUMA, `PCIe`, `NVLink`, and TPU 3D torus hardware topology visualizer.
    TopologyVisualizer,
    /// Hierarchical Dominant Resource Fairness (HDRF) role shares and quotas.
    DrfRoleShares,
    /// Active 2-level resource offers awaiting Framework acceptance or decline.
    ActiveOffers,
    /// Streaming stdout/stderr ring-buffer task logs.
    TaskLogs,
}

impl TuiTab {
    /// Cycles forward to the next [`TuiTab`].
    ///
    /// # Returns
    ///
    /// Next [`TuiTab`] in cyclical order.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::ClusterSummary => Self::TopologyVisualizer,
            Self::TopologyVisualizer => Self::DrfRoleShares,
            Self::DrfRoleShares => Self::ActiveOffers,
            Self::ActiveOffers => Self::TaskLogs,
            Self::TaskLogs => Self::ClusterSummary,
        }
    }

    /// Cycles backward to the previous [`TuiTab`].
    ///
    /// # Returns
    ///
    /// Previous [`TuiTab`] in cyclical order.
    #[must_use]
    pub const fn previous(self) -> Self {
        match self {
            Self::ClusterSummary => Self::TaskLogs,
            Self::TopologyVisualizer => Self::ClusterSummary,
            Self::DrfRoleShares => Self::TopologyVisualizer,
            Self::ActiveOffers => Self::DrfRoleShares,
            Self::TaskLogs => Self::ActiveOffers,
        }
    }
}

/// State model backing the Terminal UI and embedded Web Dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TuiStateModel {
    /// Currently selected [`TuiTab`].
    pub active_tab: TuiTab,
    /// Computed DRF dominant shares per [`RoleName`].
    pub role_shares: BTreeMap<RoleName, SharePartsPerBillion>,
    /// Cached task log snapshots keyed by [`TaskId`].
    pub task_logs: BTreeMap<TaskId, Vec<String>>,
    /// Currently selected task for log inspection.
    pub selected_task: Option<TaskId>,
}

impl TuiStateModel {
    /// Creates a new [`TuiStateModel`] starting on [`TuiTab::ClusterSummary`].
    ///
    /// # Returns
    ///
    /// Initialized [`TuiStateModel`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Advances the active tab forward.
    pub fn select_next_tab(&mut self) {
        self.active_tab = self.active_tab.next();
    }

    /// Moves the active tab backward.
    pub fn select_previous_tab(&mut self) {
        self.active_tab = self.active_tab.previous();
    }

    /// Renders the current [`TuiStateModel`] and [`MasterNode`] state into a deterministic ASCII/TUI frame.
    ///
    /// # Arguments
    ///
    /// * `master` - Reference to the [`MasterNode`] state machine.
    ///
    /// # Returns
    ///
    /// Multi-line rendered TUI string.
    pub fn render_tui_frame<S: StateStore>(&self, master: &MasterNode<S>) -> String {
        let mut out = String::new();
        out.push_str(
            "=== ARBITER CLUSTER TUI ===
",
        );
        match self.active_tab {
            TuiTab::ClusterSummary => {
                let healthy_agents = master.agents.values().filter(|a| a.healthy).count();
                out.push_str(&format!(
                    "[ClusterSummary] Agents: {}/{} healthy | Frameworks: {} | Tasks: {}
",
                    healthy_agents,
                    master.agents.len(),
                    master.frameworks.len(),
                    master.tasks.len()
                ));
            }
            TuiTab::TopologyVisualizer => {
                out.push_str(
                    "[TopologyVisualizer]
",
                );
                for (aid, rec) in &master.agents {
                    out.push_str(&format!(
                        "  Agent {aid} ({:?}/{:?}): {} nodes, {} interconnect edges
",
                        rec.registration.os_kind,
                        rec.registration.cpu_arch,
                        rec.registration.topology.nodes().len(),
                        rec.registration.topology.edges().len(),
                    ));
                }
            }
            TuiTab::DrfRoleShares => {
                out.push_str(
                    "[DrfRoleShares]
",
                );
                for (role, share) in &self.role_shares {
                    out.push_str(&format!(
                        "  Role {role}: {share}
"
                    ));
                }
            }
            TuiTab::ActiveOffers => {
                out.push_str(&format!(
                    "[ActiveOffers] Count: {}
",
                    master.active_offers.len()
                ));
                for (oid, offer) in &master.active_offers {
                    out.push_str(&format!(
                        "  Offer {oid} -> Framework {} on Agent {} (CPU: {})
",
                        offer.framework_id, offer.agent_id, offer.resources.cpu
                    ));
                }
            }
            TuiTab::TaskLogs => {
                out.push_str(
                    "[TaskLogs]
",
                );
                if let Some(ref tid) = self.selected_task {
                    if let Some(lines) = self.task_logs.get(tid) {
                        for line in lines {
                            out.push_str(&format!(
                                "  [{tid}] {line}
"
                            ));
                        }
                    } else {
                        out.push_str(&format!(
                            "  [{tid}] (no logs buffered)
"
                        ));
                    }
                } else {
                    out.push_str(
                        "  (no task selected)
",
                    );
                }
            }
        }
        out
    }
}

/// JSON DTO returned by `/dashboard/summary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardSummaryDto {
    /// Total registered agents.
    pub total_agents: usize,
    /// Currently healthy agents.
    pub healthy_agents: usize,
    /// Subscribed 2-level frameworks.
    pub total_frameworks: usize,
    /// Active outstanding offers.
    pub active_offers: usize,
    /// Total tracked tasks.
    pub total_tasks: usize,
}

/// Embedded Web Dashboard HTTP/SSE endpoint router.
///
/// Supports:
/// - `GET /dashboard/summary` -> JSON summary of cluster agents, frameworks, offers, and tasks.
/// - `GET /dashboard/topology` -> JSON map of agent hardware topology graphs.
/// - `GET /dashboard/events` -> Real-time Server-Sent Events (`text/event-stream`) snapshot.
///
/// # Arguments
///
/// * `path` - Request URI path.
/// * `master` - Reference to the [`MasterNode`].
/// * `tui_state` - Reference to the [`TuiStateModel`].
///
/// # Returns
///
/// Serialized HTTP response body (JSON or SSE stream).
///
/// # Errors
///
/// Returns [`ArbiterError::HttpHandlerError`] with status `404` if `path` is unknown.
pub fn handle_web_dashboard_request<S: StateStore>(
    path: &str,
    master: &MasterNode<S>,
    tui_state: &TuiStateModel,
) -> ArbiterResult<String> {
    match path {
        "/dashboard/summary" => {
            let dto = DashboardSummaryDto {
                total_agents: master.agents.len(),
                healthy_agents: master.agents.values().filter(|a| a.healthy).count(),
                total_frameworks: master.frameworks.len(),
                active_offers: master.active_offers.len(),
                total_tasks: master.tasks.len(),
            };
            Ok(serde_json::to_string(&dto).unwrap_or_default())
        }
        "/dashboard/topology" => {
            let topo_map: BTreeMap<String, usize> = master
                .agents
                .iter()
                .map(|(aid, rec)| (aid.to_string(), rec.registration.topology.nodes().len()))
                .collect();
            Ok(serde_json::to_string(&topo_map).unwrap_or_default())
        }
        "/dashboard/events" => {
            let frame = tui_state.render_tui_frame(master);
            let single_line: String = frame.lines().collect::<Vec<&str>>().join(" | ");
            Ok(format!(
                "event: cluster_state
data: {single_line}

"
            ))
        }
        "/dashboard/benchmarks" => {
            let cfg = arbiter_master::bench::MulticlusterBenchmarkConfig::default();
            let (_, md_table) = arbiter_master::bench::run_full_multicluster_benchmark_suite(&cfg);
            Ok(md_table)
        }
        other => Err(ArbiterError::HttpHandlerError {
            status_code: 404,
            message: format!("unknown web dashboard endpoint '{other}'"),
        }),
    }
}

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-tui"`.
pub const fn crate_name() -> &'static str {
    "arbiter-tui"
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::{AgentId, FrameworkId, OfferId};
    use arbiter_core::platform::{CpuArch, OsKind};
    use arbiter_core::resources::ResourceBundle;
    use arbiter_core::topology::HardwareTopologyGraph;
    use arbiter_core::units::{Bytes, Millicores};
    use arbiter_core::workload::{ResourceOffer, RoleHierarchy, TaskState};
    use arbiter_proto::RegisterAgent;
    use arbiter_store::memory::MemoryStateStore;

    use super::*;

    fn sample_master_for_tui() -> (MasterNode<MemoryStateStore>, TaskId) {
        let mut master = MasterNode::new(MemoryStateStore::new(), RoleHierarchy::new(), 100, 50);
        let a1 = AgentId::new("agent-1").unwrap_or_default();
        let a2 = AgentId::new("agent-2").unwrap_or_default();
        for id in [a1.clone(), a2.clone()] {
            let _ = master.register_agent(
                RegisterAgent {
                    agent_id: id,
                    os_kind: OsKind::Linux,
                    cpu_arch: CpuArch::X86_64,
                    total_resources: ResourceBundle {
                        cpu: Millicores::new(8000),
                        memory: Bytes::new(8192),
                        ..ResourceBundle::zero()
                    },
                    topology: HardwareTopologyGraph::new(),
                },
                10,
            );
        }
        for (id, rec) in &mut master.agents {
            if *id == a2 {
                rec.healthy = false;
            }
        }

        let oid = OfferId::new("offer-1").unwrap_or_default();
        master.active_offers.insert(
            oid.clone(),
            ResourceOffer {
                offer_id: oid,
                framework_id: FrameworkId::new("fw-1").unwrap_or_default(),
                agent_id: a1.clone(),
                role: RoleName::new("prod").unwrap_or_default(),
                resources: ResourceBundle::zero(),
                revocable: false,
                expires_at_tick: 100,
            },
        );
        let tid = TaskId::new("task-1").unwrap_or_default();
        master.tasks.insert(
            tid.clone(),
            (TaskState::Running, a1, ResourceBundle::zero()),
        );
        (master, tid)
    }

    #[test]
    fn test_tui_tab_navigation_and_frame_rendering() {
        assert_eq!(crate_name(), "arbiter-tui");
        let (master, tid) = sample_master_for_tui();

        let mut tui = TuiStateModel::new();
        tui.role_shares.insert(
            RoleName::new("prod").unwrap_or_default(),
            SharePartsPerBillion::new(500_000_000),
        );

        assert!(tui.render_tui_frame(&master).contains("[ClusterSummary]"));

        tui.select_next_tab();
        assert!(
            tui.render_tui_frame(&master)
                .contains("[TopologyVisualizer]")
        );

        tui.select_next_tab();
        assert!(tui.render_tui_frame(&master).contains("[DrfRoleShares]"));

        tui.select_next_tab();
        assert!(tui.render_tui_frame(&master).contains("[ActiveOffers]"));

        tui.select_next_tab();
        assert!(tui.render_tui_frame(&master).contains("(no task selected)"));

        tui.selected_task = Some(tid.clone());
        assert!(tui.render_tui_frame(&master).contains("(no logs buffered)"));

        tui.task_logs
            .insert(tid, vec!["booting...".to_owned(), "ready".to_owned()]);
        assert!(tui.render_tui_frame(&master).contains("booting..."));

        tui.select_next_tab();
        assert_eq!(tui.active_tab, TuiTab::ClusterSummary);

        for _ in 0..5 {
            tui.select_previous_tab();
        }
        assert_eq!(tui.active_tab, TuiTab::ClusterSummary);
    }

    #[test]
    fn test_web_dashboard_endpoints() {
        let (master, _) = sample_master_for_tui();
        let tui = TuiStateModel::new();

        let sum_json = handle_web_dashboard_request("/dashboard/summary", &master, &tui);
        assert!(sum_json.is_ok());

        let topo_json = handle_web_dashboard_request("/dashboard/topology", &master, &tui);
        assert!(topo_json.is_ok());

        let sse = handle_web_dashboard_request("/dashboard/events", &master, &tui);
        assert!(sse.is_ok());

        let bench_md = handle_web_dashboard_request("/dashboard/benchmarks", &master, &tui);
        assert!(bench_md.is_ok());

        let not_found = handle_web_dashboard_request("/dashboard/unknown", &master, &tui);
        assert!(not_found.is_err());
    }
}
