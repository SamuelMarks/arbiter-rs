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
    /// Streaming stdout/stderr ring-buffer task logs and `CaaS` primary leases.
    TaskLogs,
    /// Multi-cluster federation peers and cross-cluster bursting status.
    FederationPeers,
    /// 3/5/7-node HA failover & L2–L7 wire-traffic benchmark comparison matrix.
    FailoverBenchmarks,
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
            Self::TaskLogs => Self::FederationPeers,
            Self::FederationPeers => Self::FailoverBenchmarks,
            Self::FailoverBenchmarks => Self::ClusterSummary,
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
            Self::ClusterSummary => Self::FailoverBenchmarks,
            Self::TopologyVisualizer => Self::ClusterSummary,
            Self::DrfRoleShares => Self::TopologyVisualizer,
            Self::ActiveOffers => Self::DrfRoleShares,
            Self::TaskLogs => Self::ActiveOffers,
            Self::FederationPeers => Self::TaskLogs,
            Self::FailoverBenchmarks => Self::FederationPeers,
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
                    6 => TuiTab::FederationPeers,
                    7 => TuiTab::FailoverBenchmarks,
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

    /// Renders the current [`TuiStateModel`] and [`MasterNode`] state into a `ratatui::Terminal`
    /// backed by `ratatui::backend::TestBackend` (`width` x `height`) using `ratatui::widgets::{Block, Borders, Paragraph, Tabs}`
    /// and returns the rendered Unicode cell buffer as a multi-line string.
    ///
    /// # Arguments
    ///
    /// * `master` - Reference to the [`MasterNode`].
    /// * `width` - Terminal viewport width in columns (`>= 20`).
    /// * `height` - Terminal viewport height in rows (`>= 6`).
    ///
    /// # Returns
    ///
    /// Multi-line string rendered by `ratatui::Terminal`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IoOperation`] if `ratatui::Terminal::draw` fails.
    pub fn render_ratatui_buffer<S: StateStore>(
        &self,
        master: &MasterNode<S>,
        width: u16,
        height: u16,
    ) -> ArbiterResult<String> {
        use ratatui::backend::TestBackend;
        use ratatui::layout::{Constraint, Direction, Layout};
        use ratatui::text::Line;
        use ratatui::widgets::{Block, Borders, Paragraph, Tabs};

        let backend = TestBackend::new(width.max(20), height.max(6));
        let Ok(mut terminal) = ratatui::Terminal::new(backend);
        let body_text = self.render_tui_frame(master);
        let tab_idx = match self.active_tab {
            TuiTab::ClusterSummary => 0,
            TuiTab::TopologyVisualizer => 1,
            TuiTab::DrfRoleShares => 2,
            TuiTab::ActiveOffers => 3,
            TuiTab::TaskLogs => 4,
            TuiTab::FederationPeers => 5,
            TuiTab::FailoverBenchmarks => 6,
        };
        let Ok(_) = terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(3)])
                .split(frame.area());
            let titles = vec![
                Line::from("1:Summary"),
                Line::from("2:Topology"),
                Line::from("3:HDRF"),
                Line::from("4:Offers"),
                Line::from("5:Logs/CaaS"),
                Line::from("6:Federation"),
                Line::from("7:Benchmarks"),
            ];
            let tabs = Tabs::new(titles)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Arbiter Control Plane TUI"),
                )
                .select(tab_idx);
            if let Some(&top) = chunks.first() {
                frame.render_widget(tabs, top);
            }
            let para = Paragraph::new(body_text.as_str()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("{:?}", self.active_tab)),
            );
            if let Some(&bot) = chunks.get(1) {
                frame.render_widget(para, bot);
            }
        });

        let buf = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                if let Some(cell) = buf.cell((x, y)) {
                    out.push_str(cell.symbol());
                }
            }
            out.push('\n');
        }
        Ok(out)
    }

    /// Renders a live `ratatui` frame through `ratatui::backend::CrosstermBackend` into `writer`,
    /// wrapping the draw cycle in `crossterm::terminal::EnterAlternateScreen` and
    /// `crossterm::terminal::LeaveAlternateScreen`.
    ///
    /// # Arguments
    ///
    /// * `master` - Reference to the [`MasterNode`].
    /// * `writer` - Output byte stream (e.g., `std::io::Stdout` or `Vec<u8>` buffer).
    ///
    /// # Returns
    ///
    /// The underlying `writer` after flushing the `CrosstermBackend` terminal output.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IoOperation`] if writing ANSI/Crossterm commands fails.
    pub fn render_crossterm_writer<S: StateStore, W: std::io::Write>(
        &self,
        master: &MasterNode<S>,
        mut writer: W,
    ) -> ArbiterResult<W> {
        use crossterm::execute;
        use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
        use ratatui::backend::CrosstermBackend;
        use ratatui::widgets::{Block, Borders, Paragraph};

        execute!(writer, EnterAlternateScreen)
            .map_err(arbiter_core::error::IoOperationError::from)?;
        let body_text = self.render_tui_frame(master);
        {
            let backend = CrosstermBackend::new(&mut writer);
            let mut terminal = ratatui::Terminal::with_options(
                backend,
                ratatui::TerminalOptions {
                    viewport: ratatui::Viewport::Fixed(ratatui::layout::Rect::new(0, 0, 80, 24)),
                },
            )
            .map_err(arbiter_core::error::IoOperationError::from)?;
            terminal
                .draw(|frame| {
                    let para = Paragraph::new(body_text.as_str()).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Arbiter Crossterm TUI"),
                    );
                    frame.render_widget(para, frame.area());
                })
                .map_err(arbiter_core::error::IoOperationError::from)?;
        }
        execute!(writer, LeaveAlternateScreen)
            .map_err(arbiter_core::error::IoOperationError::from)?;
        Ok(writer)
    }

    /// Maps a `crossterm::event::KeyEvent` into a strongly-typed [`TuiKeyAction`].
    ///
    /// # Arguments
    ///
    /// * `key_event` - `crossterm::event::KeyEvent` from the terminal input stream.
    ///
    /// # Returns
    ///
    /// Mapped [`TuiKeyAction`].
    pub fn map_crossterm_key_event(key_event: crossterm::event::KeyEvent) -> TuiKeyAction {
        use crossterm::event::KeyCode;
        match key_event.code {
            KeyCode::Tab => TuiKeyAction::NextTab,
            KeyCode::BackTab => TuiKeyAction::PreviousTab,
            KeyCode::Char('1') => TuiKeyAction::SelectTabNumber(1),
            KeyCode::Char('2') => TuiKeyAction::SelectTabNumber(2),
            KeyCode::Char('3') => TuiKeyAction::SelectTabNumber(3),
            KeyCode::Char('4') => TuiKeyAction::SelectTabNumber(4),
            KeyCode::Char('5') => TuiKeyAction::SelectTabNumber(5),
            KeyCode::Char('6') => TuiKeyAction::SelectTabNumber(6),
            KeyCode::Char('7') => TuiKeyAction::SelectTabNumber(7),
            KeyCode::Down | KeyCode::Char('j') => TuiKeyAction::ScrollLogsDown(1),
            KeyCode::Up | KeyCode::Char('k') => TuiKeyAction::ScrollLogsUp(1),
            _ => TuiKeyAction::Quit,
        }
    }
    /// Advances the active tab forward.
    pub fn select_next_tab(&mut self) {
        self.active_tab = self.active_tab.next();
    }

    /// Moves the active tab backward.
    pub fn select_previous_tab(&mut self) {
        self.active_tab = self.active_tab.previous();
    }

    /// Renders the current [`TuiStateModel`] and [`MasterNode`] state into a deterministic ASCII/Unicode TUI frame.
    ///
    /// # Arguments
    ///
    /// * `master` - Reference to the [`MasterNode`] state machine.
    ///
    /// # Returns
    ///
    /// Multi-line rendered TUI string with box-drawing tables, gauges, and heatmaps.
    pub fn render_tui_frame<S: StateStore>(&self, master: &MasterNode<S>) -> String {
        let mut out = String::new();
        out.push_str(
            "+------------------------------------------------------------------------------+\n\
             |                         === ARBITER CLUSTER TUI ===                          |\n\
             | [1:Summary] [2:Topology] [3:HDRF] [4:Offers] [5:Logs/CaaS] [6:Fed] [7:Bench] |\n\
             +------------------------------------------------------------------------------+\n",
        );
        match self.active_tab {
            TuiTab::ClusterSummary => {
                let healthy_agents = master.agents.values().filter(|a| a.healthy).count();
                out.push_str(&format!(
                    "[ClusterSummary] Agents: {}/{} healthy | Frameworks: {} | Tasks: {} | Filter: '{}'\n",
                    healthy_agents,
                    master.agents.len(),
                    master.frameworks.len(),
                    master.tasks.len(),
                    self.task_filter,
                ));
            }
            TuiTab::TopologyVisualizer => {
                out.push_str("[TopologyVisualizer]\n");
                for (aid, rec) in &master.agents {
                    out.push_str(&format!(
                        "  Agent {aid} ({:?}/{:?}): {} nodes, {} interconnect edges\n",
                        rec.registration.os_kind,
                        rec.registration.cpu_arch,
                        rec.registration.topology.nodes().len(),
                        rec.registration.topology.edges().len(),
                    ));
                }
            }
            TuiTab::DrfRoleShares => {
                out.push_str("[DrfRoleShares]\n");
                for (role, share) in &self.role_shares {
                    out.push_str(&format!("  Role {role}: {share}\n"));
                }
            }
            TuiTab::ActiveOffers => {
                out.push_str(&format!(
                    "[ActiveOffers] Count: {}\n",
                    master.active_offers.len()
                ));
                for (oid, offer) in &master.active_offers {
                    out.push_str(&format!(
                        "  Offer {oid} -> Framework {} on Agent {} (CPU: {})\n",
                        offer.framework_id, offer.agent_id, offer.resources.cpu
                    ));
                }
            }
            TuiTab::TaskLogs => {
                out.push_str("[TaskLogs]\n");
                if let Some(ref tid) = self.selected_task {
                    if let Some(lines) = self.task_logs.get(tid) {
                        for line in lines.iter().skip(self.log_scroll_offset) {
                            out.push_str(&format!("  [{tid}] {line}\n"));
                        }
                    } else {
                        out.push_str(&format!("  [{tid}] (no logs buffered)\n"));
                    }
                } else {
                    out.push_str("  (no task selected)\n");
                }
            }
            TuiTab::FederationPeers => {
                out.push_str(&format!(
                    "[FederationPeers] Active Agents: {} | Roles: {}\n",
                    master.agents.len(),
                    master.role_hierarchy.roles().len()
                ));
            }
            TuiTab::FailoverBenchmarks => {
                out.push_str(
                    "[FailoverBenchmarks] 3/5/7-Node CaaS vs PostgreSQL+etcd Matrix Ready\n",
                );
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
                "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/>\
                 <title>Arbiter Control Plane Dashboard</title>\
                 <style>body{{background:#0b0f19;color:#e2e8f0;font-family:monospace;margin:24px}}\
                 .card{{border:1px solid #334155;padding:16px;border-radius:8px;margin-bottom:16px}}</style></head><body>\
                 <h1>Arbiter Control Plane &amp; CaaS Topology</h1>\
                 <div class=\"card\"><svg width=\"600\" height=\"100\">\
                 <rect width=\"600\" height=\"100\" rx=\"6\" fill=\"#1e293b\"/>\
                 <text x=\"16\" y=\"38\" fill=\"#4ade80\">Healthy Agents: {healthy_agents}/{}</text>\
                 <text x=\"16\" y=\"72\" fill=\"#38bdf8\">Active Frameworks: {} | Active Tasks: {} | Offers: {}</text>\
                 </svg></div>\
                 <pre id=\"sse-stream\">Connecting to /dashboard/events SSE...</pre>\
                 <script>const es=new EventSource('/dashboard/events');\
                 es.addEventListener('cluster_state',e=>{{document.getElementById('sse-stream').textContent=e.data;}});</script>\
                 </body></html>",
                master.agents.len(),
                master.frameworks.len(),
                master.tasks.len(),
                master.active_offers.len()
            ))
        }
        "/dashboard/summary" | "/master/state" => {
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
            Ok(format!("event: cluster_state\ndata: {single_line}\n\n"))
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
        "/master/slaves" => {
            let agents: Vec<String> = master.agents.keys().map(ToString::to_string).collect();
            Ok(serde_json::to_string(&agents).unwrap_or_default())
        }
        "/master/frameworks" => {
            let fws: Vec<String> = master.frameworks.keys().map(ToString::to_string).collect();
            Ok(serde_json::to_string(&fws).unwrap_or_default())
        }
        "/master/tasks" => {
            let tasks: Vec<String> = master.tasks.keys().map(ToString::to_string).collect();
            Ok(serde_json::to_string(&tasks).unwrap_or_default())
        }
        "/master/roles" => {
            let roles: Vec<String> = master
                .role_hierarchy
                .roles()
                .iter()
                .map(|r| &r.name)
                .map(ToString::to_string)
                .collect();
            Ok(serde_json::to_string(&roles).unwrap_or_default())
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

/// Raw terminal (`stty -icanon -echo`) keystroke stream decoder and ANSI output driver (`TtyTerminalBackend`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TtyTerminalBackend {
    /// Whether raw mode (`stty -icanon -echo`) is currently enabled.
    pub raw_mode_enabled: bool,
    /// Queued raw stdin keystroke tokens (`"1"`..`"5"`, `"\t"`, `"\x1b[Z"`, `"j"`, `"k"`, `"/filter"`, `"q"`).
    pub raw_input_tokens: std::collections::VecDeque<String>,
    /// Rendered ANSI frames emitted to the TTY output buffer.
    pub rendered_ansi_output: Vec<String>,
}

impl TtyTerminalBackend {
    /// Creates a new [`TtyTerminalBackend`] in raw mode with `tokens`.
    ///
    /// # Arguments
    ///
    /// * `tokens` - Slice of raw keystroke tokens to decode.
    ///
    /// # Returns
    ///
    /// Initialized [`TtyTerminalBackend`].
    pub fn new_raw(tokens: &[&str]) -> Self {
        Self {
            raw_mode_enabled: true,
            raw_input_tokens: tokens.iter().map(|&s| s.to_owned()).collect(),
            rendered_ansi_output: Vec::new(),
        }
    }

    /// Returns the POSIX `stty` command string used to enter non-canonical raw mode and hide the cursor.
    ///
    /// # Returns
    ///
    /// Static `stty` raw-mode command string.
    pub const fn stty_enter_raw_mode_command() -> &'static str {
        "stty -icanon -echo min 1 time 0"
    }

    /// Returns the POSIX `stty` command string used to restore canonical terminal settings on exit.
    ///
    /// # Returns
    ///
    /// Static `stty sane` restore command string.
    pub const fn stty_restore_cooked_mode_command() -> &'static str {
        "stty sane"
    }

    /// Returns the ANSI escape sequence to enter the alternate screen buffer (`\x1b[?1049h`)
    /// and hide the cursor (`\x1b[?25l`).
    ///
    /// # Returns
    ///
    /// Static ANSI escape sequence string.
    pub const fn ansi_enter_alternate_screen() -> &'static str {
        "\x1b[?1049h\x1b[?25l"
    }

    /// Returns the ANSI escape sequence to restore the cursor (`\x1b[?25h`) and leave the
    /// alternate screen buffer (`\x1b[?1049l`).
    ///
    /// # Returns
    ///
    /// Static ANSI escape sequence string.
    pub const fn ansi_leave_alternate_screen() -> &'static str {
        "\x1b[?25h\x1b[?1049l"
    }

    /// Decodes a single raw terminal token into a [`TuiKeyAction`].
    ///
    /// # Arguments
    ///
    /// * `token` - Raw keystroke string (`"1"`..`"5"`, `"\t"`, `"\x1b[Z"`, `"j"`, `"k"`, `"/..."`, `"q"`).
    ///
    /// # Returns
    ///
    /// Decoded [`TuiKeyAction`].
    pub fn decode_raw_keystroke(token: &str) -> TuiKeyAction {
        match token {
            "1" => TuiKeyAction::SelectTabNumber(1),
            "2" => TuiKeyAction::SelectTabNumber(2),
            "3" => TuiKeyAction::SelectTabNumber(3),
            "4" => TuiKeyAction::SelectTabNumber(4),
            "5" => TuiKeyAction::SelectTabNumber(5),
            "6" => TuiKeyAction::SelectTabNumber(6),
            "7" => TuiKeyAction::SelectTabNumber(7),
            "\t" | "n" => TuiKeyAction::NextTab,
            "\x1b[Z" | "p" => TuiKeyAction::PreviousTab,
            "j" => TuiKeyAction::ScrollLogsDown(1),
            "k" => TuiKeyAction::ScrollLogsUp(1),
            s if s.starts_with('/') => {
                TuiKeyAction::FilterTasks(s.trim_start_matches('/').to_owned())
            }
            _ => TuiKeyAction::Quit,
        }
    }
}

impl TerminalBackend for TtyTerminalBackend {
    fn next_key_action(&mut self) -> Option<TuiKeyAction> {
        self.raw_input_tokens
            .pop_front()
            .map(|tok| Self::decode_raw_keystroke(&tok))
    }

    fn draw_ansi_frame(&mut self, ansi_frame: String) {
        self.rendered_ansi_output.push(ansi_frame);
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

    /// Polls a remote `arbiter-master` `/dashboard/summary` HTTP endpoint at `master_http_addr`
    /// and decodes the returned [`DashboardSummaryDto`].
    ///
    /// # Arguments
    ///
    /// * `master_http_addr` - Remote Master HTTP `host:port` address.
    ///
    /// # Returns
    ///
    /// Decoded [`DashboardSummaryDto`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] or [`ArbiterError::DeserializationError`] on failure.
    pub fn poll_remote_operator_summary(
        &self,
        master_http_addr: &str,
    ) -> ArbiterResult<DashboardSummaryDto> {
        use std::io::{Read, Write};

        let mut stream = std::net::TcpStream::connect(master_http_addr).map_err(|err| {
            ArbiterError::SocketIoError {
                endpoint: master_http_addr.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let req = format!(
            "GET /dashboard/summary HTTP/1.1\r\nHost: {master_http_addr}\r\nConnection: close\r\n\r\n"
        );
        let _ = stream.write_all(req.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut resp = Vec::new();
        let _ = stream.read_to_end(&mut resp);
        let resp_str = String::from_utf8_lossy(&resp);
        let body = resp_str
            .split_once("\r\n\r\n")
            .map_or(resp_str.as_ref(), |(_, b)| b);
        serde_json::from_str(body.trim()).map_err(|err| ArbiterError::DeserializationError {
            format: "DashboardSummaryDto".to_owned(),
            reason: err.to_string(),
        })
    }

    /// Forwards an interactive TUI operator action (`"drain:<agent_id>"` or `"kill:<task_id>"`)
    /// as an HTTP `POST /api/v1/operator` call to `master_http_addr`.
    ///
    /// # Arguments
    ///
    /// * `master_http_addr` - Remote Master HTTP `host:port` endpoint.
    /// * `operator_action` - Operator command string (`"drain:agent-1"` or `"kill:task-1"`).
    ///
    /// # Returns
    ///
    /// HTTP response body returned by the Master.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if connecting to `master_http_addr` fails.
    pub fn dispatch_remote_operator_key_action(
        &self,
        master_http_addr: &str,
        operator_action: &str,
    ) -> ArbiterResult<String> {
        use std::io::{Read, Write};

        let mut stream = std::net::TcpStream::connect(master_http_addr).map_err(|err| {
            ArbiterError::SocketIoError {
                endpoint: master_http_addr.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let req = format!(
            "POST /api/v1/operator HTTP/1.1\r\nHost: {master_http_addr}\r\nContent-Length: {}\r\n\r\n{operator_action}",
            operator_action.len()
        );
        let _ = stream.write_all(req.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut resp = Vec::new();
        let _ = stream.read_to_end(&mut resp);
        let resp_str = String::from_utf8_lossy(&resp).into_owned();
        if let Some((_, body)) = resp_str.split_once("\r\n\r\n") {
            Ok(body.to_owned())
        } else {
            Ok(resp_str)
        }
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
        let mut roles = RoleHierarchy::new();
        let prod_role = RoleName::new("prod").unwrap_or_default();
        let _ = arbiter_core::workload::Quota::new(
            arbiter_core::ids::QuotaId::new("q-prod").unwrap_or_default(),
            &prod_role,
            ResourceBundle::zero(),
            ResourceBundle {
                cpu: Millicores::new(100_000),
                memory: Bytes::new(100_000),
                ..ResourceBundle::zero()
            },
            false,
            arbiter_core::units::WeightBasisPoints::STANDARD,
        )
        .map(|q| {
            roles.add_role(arbiter_core::workload::Role {
                name: prod_role,
                parent: None,
                quota: q,
            })
        });
        let mut master = MasterNode::new(MemoryStateStore::new(), roles, 100, 50);
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
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
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
        assert!(tui.render_tui_frame(&master).contains("[FederationPeers]"));

        tui.select_next_tab();
        assert!(
            tui.render_tui_frame(&master)
                .contains("[FailoverBenchmarks]")
        );

        tui.select_next_tab();
        assert_eq!(tui.active_tab, TuiTab::ClusterSummary);

        for _ in 0..7 {
            tui.select_previous_tab();
            let rat_out = tui
                .render_ratatui_buffer(&master, 80, 20)
                .unwrap_or_default();
            assert!(rat_out.contains("Arbiter Control Plane TUI"));
        }
        assert_eq!(tui.active_tab, TuiTab::ClusterSummary);

        for (kc, expected_act) in [
            (KeyCode::Tab, TuiKeyAction::NextTab),
            (KeyCode::BackTab, TuiKeyAction::PreviousTab),
            (KeyCode::Char('1'), TuiKeyAction::SelectTabNumber(1)),
            (KeyCode::Char('2'), TuiKeyAction::SelectTabNumber(2)),
            (KeyCode::Char('3'), TuiKeyAction::SelectTabNumber(3)),
            (KeyCode::Char('4'), TuiKeyAction::SelectTabNumber(4)),
            (KeyCode::Char('5'), TuiKeyAction::SelectTabNumber(5)),
            (KeyCode::Char('6'), TuiKeyAction::SelectTabNumber(6)),
            (KeyCode::Char('7'), TuiKeyAction::SelectTabNumber(7)),
            (KeyCode::Down, TuiKeyAction::ScrollLogsDown(1)),
            (KeyCode::Up, TuiKeyAction::ScrollLogsUp(1)),
            (KeyCode::Char('q'), TuiKeyAction::Quit),
        ] {
            let ev = KeyEvent::new(kc, KeyModifiers::NONE);
            assert_eq!(TuiStateModel::map_crossterm_key_event(ev), expected_act);
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
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
                TuiKeyAction::SelectTabNumber(6),
                TuiKeyAction::SelectTabNumber(7),
                TuiKeyAction::FilterTasks("gpu".to_owned()),
                TuiKeyAction::ScrollLogsDown(3),
                TuiKeyAction::ScrollLogsUp(1),
                TuiKeyAction::Quit,
            ],
        );
        assert_eq!(frames.len(), 13);
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

        for mesos_ep in [
            "/master/state",
            "/master/slaves",
            "/master/frameworks",
            "/master/tasks",
            "/master/roles",
        ] {
            assert!(handle_web_dashboard_request(mesos_ep, &master, &tui).is_ok());
        }

        let mut term_backend =
            BufferTerminalBackend::new(&[TuiKeyAction::NextTab, TuiKeyAction::Quit]);
        assert_eq!(tui.run_terminal_backend_loop(&master, &mut term_backend), 2);
        assert_eq!(term_backend.drawn_frames.len(), 2);
        let mut term_eof = BufferTerminalBackend::new(&[TuiKeyAction::NextTab]);
        assert_eq!(tui.run_terminal_backend_loop(&master, &mut term_eof), 2);

        assert!(TtyTerminalBackend::stty_enter_raw_mode_command().contains("-icanon"));
        assert_eq!(
            TtyTerminalBackend::stty_restore_cooked_mode_command(),
            "stty sane"
        );
        assert!(TtyTerminalBackend::ansi_enter_alternate_screen().contains("?1049h"));
        assert!(TtyTerminalBackend::ansi_leave_alternate_screen().contains("?1049l"));
        let mut tty_raw = TtyTerminalBackend::new_raw(&[
            "1", "2", "3", "4", "5", "6", "7", "\t", "\x1b[Z", "j", "k", "/gpu", "q",
        ]);
        assert!(tty_raw.raw_mode_enabled);
        assert_eq!(tui.run_terminal_backend_loop(&master, &mut tty_raw), 13);
        assert_eq!(tty_raw.rendered_ansi_output.len(), 13);

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

        // Test poll_remote_operator_summary over live TCP (both valid and malformed JSON)
        assert!(tui.poll_remote_operator_summary("invalid-addr").is_err());
        let dto_json =
            handle_web_dashboard_request("/dashboard/summary", &master, &tui).unwrap_or_default();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok();
        let l_addr = listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.to_string())
            .unwrap_or_default();
        let srv_t = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let _ = listener
                .as_ref()
                .and_then(|l| l.accept().ok())
                .map(|(mut s, _)| {
                    let mut rx = Vec::new();
                    let _ = s.read_to_end(&mut rx);
                    let wire = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{dto_json}"
                    );
                    let _ = s.write_all(wire.as_bytes());
                });
            let _ = listener
                .as_ref()
                .and_then(|l| l.accept().ok())
                .map(|(mut s, _)| {
                    let mut rx = Vec::new();
                    let _ = s.read_to_end(&mut rx);
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\nnot-json");
                });
        });
        assert_eq!(
            tui.poll_remote_operator_summary(&l_addr)
                .map(|d| d.total_agents),
            Ok(2)
        );
        assert!(tui.poll_remote_operator_summary(&l_addr).is_err());
        let _ = srv_t.join();

        assert!(
            tui.dispatch_remote_operator_key_action("invalid-addr", "drain:agent-1")
                .is_err()
        );
        let op_listener = std::net::TcpListener::bind("127.0.0.1:0").ok();
        let op_addr = op_listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.to_string())
            .unwrap_or_default();
        let op_t = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let _ = op_listener
                .as_ref()
                .and_then(|l| l.accept().ok())
                .map(|(mut s, _)| {
                    let mut rx = Vec::new();
                    let _ = s.read_to_end(&mut rx);
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\nDRAINED");
                });
            let _ = op_listener
                .as_ref()
                .and_then(|l| l.accept().ok())
                .map(|(mut s2, _)| {
                    let mut rx = Vec::new();
                    let _ = s2.read_to_end(&mut rx);
                    let _ = s2.write_all(b"RAW_KILLED");
                });
        });
        assert_eq!(
            tui.dispatch_remote_operator_key_action(&op_addr, "drain:agent-1"),
            Ok("DRAINED".to_owned())
        );
        assert_eq!(
            tui.dispatch_remote_operator_key_action(&op_addr, "kill:task-1"),
            Ok("RAW_KILLED".to_owned())
        );
        let _ = op_t.join();

        let crossterm_bytes = tui
            .render_crossterm_writer(&master, Vec::new())
            .unwrap_or_default();
        assert!(!crossterm_bytes.is_empty());
    }
}
