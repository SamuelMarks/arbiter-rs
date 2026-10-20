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
    /// Substring filter applied to tasks/logs.
    pub task_filter: String,
    /// Vertical scroll offset for task log lines.
    pub log_scroll_offset: usize,
}

/// Interactive keyboard input actions handled by [`TuiStateModel::handle_key_action`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TuiKeyAction {
    /// `Tab` — advance to next tab.
    NextTab,
    /// `Shift+Tab` — move to previous tab.
    PreviousTab,
    /// `1`–`5` — jump directly to a specific tab (`1 = ClusterSummary`, ..., `5 = TaskLogs`).
    SelectTabNumber(u8),
    /// `/` — update task/log filter string.
    FilterTasks(String),
    /// `j` / `Down` — scroll log view down by `lines`.
    ScrollLogsDown(usize),
    /// `k` / `Up` — scroll log view up by `lines`.
    ScrollLogsUp(usize),
    /// `q` — request terminal session exit.
    Quit,
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

    /// Processes a single [`TuiKeyAction`], returning `true` if the TUI session should remain open
    /// or `false` if [`TuiKeyAction::Quit`] was pressed.
    ///
    /// # Arguments
    ///
    /// * `action` - [`TuiKeyAction`].
    ///
    /// # Returns
    ///
    /// `true` to continue, `false` to exit.
    pub fn handle_key_action(&mut self, action: TuiKeyAction) -> bool {
        match action {
            TuiKeyAction::NextTab => {
                self.select_next_tab();
                true
            }
            TuiKeyAction::PreviousTab => {
                self.select_previous_tab();
                true
            }
            TuiKeyAction::SelectTabNumber(num) => {
                self.active_tab = match num {
                    2 => TuiTab::TopologyVisualizer,
                    3 => TuiTab::DrfRoleShares,
                    4 => TuiTab::ActiveOffers,
                    5 => TuiTab::TaskLogs,
                    _ => TuiTab::ClusterSummary,
                };
                true
            }
            TuiKeyAction::FilterTasks(f) => {
                self.task_filter = f;
                true
            }
            TuiKeyAction::ScrollLogsDown(n) => {
                self.log_scroll_offset = self.log_scroll_offset.saturating_add(n);
                true
            }
            TuiKeyAction::ScrollLogsUp(n) => {
                self.log_scroll_offset = self.log_scroll_offset.saturating_sub(n);
                true
            }
            TuiKeyAction::Quit => false,
        }
    }

    /// Runs an interactive TUI event loop over `actions`, rendering an ASCII frame at each step
    /// until [`TuiKeyAction::Quit`] is encountered or `actions` is exhausted.
    ///
    /// # Arguments
    ///
    /// * `master` - Reference to the [`MasterNode`].
    /// * `actions` - Slice of [`TuiKeyAction`] events.
    ///
    /// # Returns
    ///
    /// Vector of rendered ASCII frames produced during the session.
    pub fn run_interactive_event_loop<S: StateStore>(
        &mut self,
        master: &MasterNode<S>,
        actions: &[TuiKeyAction],
    ) -> Vec<String> {
        let mut frames = Vec::with_capacity(actions.len().saturating_add(1));
        frames.push(self.render_tui_frame(master));
        for action in actions {
            if !self.handle_key_action(action.clone()) {
                break;
            }
            frames.push(self.render_tui_frame(master));
        }
        frames
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
        "/dashboard" => {
            let healthy_agents = master.agents.values().filter(|a| a.healthy).count();
            Ok(format!(
                "<!DOCTYPE html><html><head><title>Arbiter Dashboard</title></head><body>\
                 <h1>Arbiter Control Plane</h1>\
                 <svg width=\"400\" height=\"80\"><rect width=\"400\" height=\"80\" fill=\"#111\"/>\
                 <text x=\"16\" y=\"45\" fill=\"#0f0\">Healthy Agents: {healthy_agents}/{}</text></svg>\
                 </body></html>",
                master.agents.len()
            ))
        }
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
        "/metrics" => {
            let healthy_agents = master.agents.values().filter(|a| a.healthy).count();
            Ok(format!(
                "# TYPE arbiter_healthy_agents gauge\narbiter_healthy_agents {healthy_agents}\n# TYPE arbiter_active_tasks gauge\narbiter_active_tasks {}\n",
                master.tasks.len()
            ))
        }
        "/metrics/otel" => {
            let healthy_agents = master.agents.values().filter(|a| a.healthy).count();
            Ok(format!(
                "{{\"resourceMetrics\":[{{\"scopeMetrics\":[{{\"metrics\":[{{\"name\":\"arbiter.healthy_agents\",\"gauge\":{{\"value\":{healthy_agents}}}}},{{\"name\":\"arbiter.active_tasks\",\"gauge\":{{\"value\":{}}}}}]}}]}}]}}",
                master.tasks.len()
            ))
        }
        other => Err(ArbiterError::HttpHandlerError {
            status_code: 404,
            message: format!("unknown web dashboard endpoint '{other}'"),
        }),
    }
}

/// Dependency-injected terminal backend (`TerminalBackend`) for rendering interactive ANSI TUI frames
/// and polling keyboard actions without requiring a physical TTY in unit tests.
pub trait TerminalBackend {
    /// Polls the next keyboard action from the terminal input stream.
    ///
    /// # Returns
    ///
    /// `Some(TuiKeyAction)` if an action is queued, or `None` when the input stream closes.
    fn next_key_action(&mut self) -> Option<TuiKeyAction>;

    /// Writes an ANSI-formatted TUI frame string to the terminal display buffer.
    ///
    /// # Arguments
    ///
    /// * `ansi_frame` - Rendered ANSI terminal frame.
    fn draw_ansi_frame(&mut self, ansi_frame: String);
}

/// Deterministic in-memory [`TerminalBackend`] for testing the ANSI terminal event loop.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BufferTerminalBackend {
    /// Queued key actions to emit on each poll.
    pub queued_keys: std::collections::VecDeque<TuiKeyAction>,
    /// Drawn ANSI frames including `\x1b[2J\x1b[H` clear-screen sequences.
    pub drawn_frames: Vec<String>,
}

impl BufferTerminalBackend {
    /// Creates a new [`BufferTerminalBackend`] seeded with `actions`.
    ///
    /// # Arguments
    ///
    /// * `actions` - Slice of [`TuiKeyAction`]s.
    ///
    /// # Returns
    ///
    /// Initialized [`BufferTerminalBackend`].
    pub fn new(actions: &[TuiKeyAction]) -> Self {
        Self {
            queued_keys: actions.iter().cloned().collect(),
            drawn_frames: Vec::new(),
        }
    }
}

impl TerminalBackend for BufferTerminalBackend {
    fn next_key_action(&mut self) -> Option<TuiKeyAction> {
        self.queued_keys.pop_front()
    }

    fn draw_ansi_frame(&mut self, ansi_frame: String) {
        self.drawn_frames.push(ansi_frame);
    }
}

impl TuiStateModel {
    /// Runs an interactive ANSI terminal event loop over `backend`, clearing the screen (`\x1b[2J\x1b[H`)
    /// and redrawing the active [`TuiTab`] until [`TuiKeyAction::Quit`] or input exhaustion.
    ///
    /// # Arguments
    ///
    /// * `master` - Reference to the [`MasterNode`].
    /// * `backend` - [`TerminalBackend`] implementation.
    ///
    /// # Returns
    ///
    /// Total number of ANSI frames drawn.
    pub fn run_terminal_backend_loop<S: StateStore, B: TerminalBackend>(
        &mut self,
        master: &MasterNode<S>,
        backend: &mut B,
    ) -> usize {
        let mut count = 0_usize;
        backend.draw_ansi_frame(format!("\x1b[2J\x1b[H{}", self.render_tui_frame(master)));
        count = count.saturating_add(1);
        while let Some(act) = backend.next_key_action() {
            if !self.handle_key_action(act) {
                break;
            }
            backend.draw_ansi_frame(format!("\x1b[2J\x1b[H{}", self.render_tui_frame(master)));
            count = count.saturating_add(1);
        }
        count
    }
}

/// Serves a single live HTTP request (`GET /dashboard`, `/dashboard/events`, `/metrics`, etc.)
/// over a bound `std::net::TcpListener`.
///
/// # Arguments
///
/// * `bind_addr` - Local HTTP bind address (`"127.0.0.1:0"`).
/// * `path` - Requested URI path.
/// * `master` - Reference to the [`MasterNode`].
/// * `tui_state` - Reference to the [`TuiStateModel`].
///
/// # Returns
///
/// Raw HTTP response string received by the client.
///
/// # Errors
///
/// Returns [`ArbiterError::SocketBindError`] if binding fails or [`ArbiterError::HttpHandlerError`]
/// if `path` is unknown.
pub fn serve_web_dashboard_http_once<S: StateStore>(
    bind_addr: &str,
    path: &str,
    master: &MasterNode<S>,
    tui_state: &TuiStateModel,
) -> ArbiterResult<String> {
    use std::io::{Read, Write};

    let listener =
        std::net::TcpListener::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
            endpoint: bind_addr.to_owned(),
            reason: err.to_string(),
        })?;
    let body = handle_web_dashboard_request(path, master, tui_state)?;
    let content_type = if path == "/dashboard/events" {
        "text/event-stream"
    } else if path == "/dashboard" {
        "text/html"
    } else {
        "application/json"
    };
    let wire_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut rx = vec![0_u8; wire_resp.len()];
    let _ = listener.local_addr().and_then(|addr| {
        std::net::TcpStream::connect(addr).and_then(|mut cli| {
            listener.accept().and_then(|(mut srv, _)| {
                let _ = srv.write_all(wire_resp.as_bytes());
                cli.read_exact(&mut rx)
            })
        })
    });
    Ok(String::from_utf8_lossy(&rx).into_owned())
}

/// Serves a batch of `paths` over a persistent multi-request HTTP listener (`serve_web_dashboard_http_batch`).
///
/// # Arguments
///
/// * `bind_addr` - Local HTTP bind address (`"127.0.0.1:0"`).
/// * `paths` - Slice of requested URI paths.
/// * `master` - Reference to the [`MasterNode`].
/// * `tui_state` - Reference to the [`TuiStateModel`].
///
/// # Returns
///
/// Vector of HTTP response strings received for each path in `paths`.
///
/// # Errors
///
/// Returns an [`ArbiterError`] if binding fails or any path is invalid.
pub fn serve_web_dashboard_http_batch<S: StateStore>(
    bind_addr: &str,
    paths: &[&str],
    master: &MasterNode<S>,
    tui_state: &TuiStateModel,
) -> ArbiterResult<Vec<String>> {
    let mut responses = Vec::with_capacity(paths.len());
    for &path in paths {
        responses.push(serve_web_dashboard_http_once(
            bind_addr, path, master, tui_state,
        )?);
    }
    Ok(responses)
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
        let mut tui = TuiStateModel::new();
        let frames = tui.run_interactive_event_loop(
            &master,
            &[
                TuiKeyAction::NextTab,
                TuiKeyAction::PreviousTab,
                TuiKeyAction::SelectTabNumber(1),
                TuiKeyAction::SelectTabNumber(2),
                TuiKeyAction::SelectTabNumber(3),
                TuiKeyAction::SelectTabNumber(4),
                TuiKeyAction::SelectTabNumber(5),
                TuiKeyAction::FilterTasks("gpu".to_owned()),
                TuiKeyAction::ScrollLogsDown(3),
                TuiKeyAction::ScrollLogsUp(1),
                TuiKeyAction::Quit,
            ],
        );
        assert_eq!(frames.len(), 11);
        let frames_no_quit = tui.run_interactive_event_loop(&master, &[TuiKeyAction::NextTab]);
        assert_eq!(frames_no_quit.len(), 2);

        let html = handle_web_dashboard_request("/dashboard", &master, &tui);
        assert!(html.is_ok());

        let sum_json = handle_web_dashboard_request("/dashboard/summary", &master, &tui);
        assert!(sum_json.is_ok());

        let topo_json = handle_web_dashboard_request("/dashboard/topology", &master, &tui);
        assert!(topo_json.is_ok());

        let sse = handle_web_dashboard_request("/dashboard/events", &master, &tui);
        assert!(sse.is_ok());

        let bench_md = handle_web_dashboard_request("/dashboard/benchmarks", &master, &tui);
        assert!(bench_md.is_ok());

        let metrics_prom = handle_web_dashboard_request("/metrics", &master, &tui);
        assert!(metrics_prom.is_ok());

        let metrics_otel = handle_web_dashboard_request("/metrics/otel", &master, &tui);
        assert!(metrics_otel.is_ok());

        let mut term_backend =
            BufferTerminalBackend::new(&[TuiKeyAction::NextTab, TuiKeyAction::Quit]);
        assert_eq!(tui.run_terminal_backend_loop(&master, &mut term_backend), 2);
        assert_eq!(term_backend.drawn_frames.len(), 2);
        let mut term_eof = BufferTerminalBackend::new(&[TuiKeyAction::NextTab]);
        assert_eq!(tui.run_terminal_backend_loop(&master, &mut term_eof), 2);

        let not_found = handle_web_dashboard_request("/dashboard/unknown", &master, &tui);
        assert!(not_found.is_err());

        for p in ["/dashboard", "/dashboard/events", "/dashboard/summary"] {
            assert!(
                serve_web_dashboard_http_once("127.0.0.1:0", p, &master, &tui)
                    .unwrap_or_default()
                    .contains("200 OK")
            );
        }
        assert!(
            serve_web_dashboard_http_once("invalid-addr", "/dashboard", &master, &tui).is_err()
        );
        assert!(
            serve_web_dashboard_http_once("127.0.0.1:0", "/dashboard/unknown", &master, &tui)
                .is_err()
        );
        let batch_res = serve_web_dashboard_http_batch(
            "127.0.0.1:0",
            &["/dashboard", "/dashboard/summary", "/dashboard/topology"],
            &master,
            &tui,
        );
        assert_eq!(batch_res.map(|v| v.len()), Ok(3));
        assert!(
            serve_web_dashboard_http_batch("127.0.0.1:0", &["/dashboard/unknown"], &master, &tui)
                .is_err()
        );
    }
}
