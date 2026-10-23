//! Composable isolator pipeline and lifecycle trait (`arbiter-iso::pipeline`).
//!
//! Defines the [`Isolator`] trait (`prepare`, `isolate`, `update_limits`, `usage`, `checkpoint`, `cleanup`)
//! and [`IsolatorPipeline`] which chains OS-specific, accelerator, network, and storage isolators
//! atomically, rolling back already-prepared stages if any downstream stage fails.

use arbiter_core::error::ArbiterResult;
use arbiter_core::ids::TaskId;
use arbiter_core::resources::ResourceBundle;
use serde::{Deserialize, Serialize};

/// Sandbox preparation output produced by an [`Isolator::prepare`] stage.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPreparation {
    /// Whitelisted device paths to expose inside the sandbox (e.g., `"/dev/nvidia0"`).
    pub device_mounts: Vec<String>,
    /// Environment variables to inject into the task process.
    pub injected_env: Vec<(String, String)>,
    /// OS-specific enforcement commands or config files applied during preparation.
    pub applied_commands: Vec<String>,
}

/// Live resource usage snapshot reported by an [`Isolator::usage`] hook.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolatorUsageReport {
    /// Task identifier.
    pub task_id: TaskId,
    /// Measured resource consumption.
    pub consumed: ResourceBundle,
}

/// Pluggable task isolation stage interface.
pub trait Isolator {
    /// Returns the name of this isolator stage.
    ///
    /// # Returns
    ///
    /// Static isolator stage name.
    fn name(&self) -> &'static str;

    /// Prepares the isolation environment (e.g., creating `cgroups`, Jails, Zones, Job Objects)
    /// prior to process spawning.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `limits` - Initial resource limits.
    ///
    /// # Returns
    ///
    /// [`SandboxPreparation`] directives.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if preparation fails.
    fn prepare(
        &mut self,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<SandboxPreparation>;

    /// Binds a spawned OS process (`pid`) into the prepared isolation container/sandbox.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `pid` - OS process identifier.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful process attachment.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if process attachment fails.
    fn isolate(&mut self, task_id: &TaskId, pid: u32) -> ArbiterResult<()>;

    /// Dynamically updates resource limits for a running task in-place.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `new_limits` - Updated [`ResourceBundle`] limits.
    ///
    /// # Returns
    ///
    /// `Ok(())` on update.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if limit update fails.
    fn update_limits(&mut self, task_id: &TaskId, new_limits: &ResourceBundle)
    -> ArbiterResult<()>;

    /// Queries live resource consumption of the isolated task.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    ///
    /// # Returns
    ///
    /// [`IsolatorUsageReport`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if usage collection fails.
    fn usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport>;

    /// Checkpoints the running task state to `checkpoint_dir` prior to preemption/migration.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `checkpoint_dir` - Target filesystem path for checkpoint image.
    ///
    /// # Returns
    ///
    /// `Ok(())` on checkpoint completion.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if checkpointing fails.
    fn checkpoint(&mut self, task_id: &TaskId, checkpoint_dir: &str) -> ArbiterResult<()>;

    /// Tears down and cleans up all kernel/OS isolation state for `task_id` (also used for STONITH fencing).
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    ///
    /// # Returns
    ///
    /// `Ok(())` on cleanup completion.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if cleanup fails.
    fn cleanup(&mut self, task_id: &TaskId) -> ArbiterResult<()>;
}

/// Atomic pipeline chaining multiple [`Isolator`] stages with automatic rollback on partial preparation failure.
pub struct IsolatorPipeline {
    /// Ordered isolator stages.
    stages: Vec<Box<dyn Isolator>>,
}

impl IsolatorPipeline {
    /// Creates an empty [`IsolatorPipeline`].
    ///
    /// # Returns
    ///
    /// Empty [`IsolatorPipeline`].
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    /// Appends an [`Isolator`] stage to the pipeline.
    ///
    /// # Arguments
    ///
    /// * `stage` - Boxed [`Isolator`] implementation.
    pub fn add_stage(&mut self, stage: Box<dyn Isolator>) {
        self.stages.push(stage);
    }

    /// Returns the number of stages in the pipeline.
    ///
    /// # Returns
    ///
    /// Stage count.
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    /// Runs `prepare` across all stages in order. If stage `k` fails, automatically calls
    /// `cleanup` in reverse order on stages `0..k` before returning the error.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `limits` - Initial resource bundle.
    ///
    /// # Returns
    ///
    /// Merged [`SandboxPreparation`] across all stages.
    ///
    /// # Errors
    ///
    /// Returns the [`ArbiterError`](arbiter_core::error::ArbiterError) from the failing stage after rolling back earlier stages.
    pub fn prepare_all(
        &mut self,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<SandboxPreparation> {
        let mut combined = SandboxPreparation::default();
        let mut prepared_count = 0_usize;
        let mut prepare_err = None;

        for stage in &mut self.stages {
            match stage.prepare(task_id, limits) {
                Ok(prep) => {
                    combined.device_mounts.extend(prep.device_mounts);
                    combined.injected_env.extend(prep.injected_env);
                    combined.applied_commands.extend(prep.applied_commands);
                    prepared_count += 1;
                }
                Err(err) => {
                    prepare_err = Some(err);
                    break;
                }
            }
        }

        if let Some(err) = prepare_err {
            for stage in self.stages.iter_mut().take(prepared_count).rev() {
                let _ = stage.cleanup(task_id);
            }
            return Err(err);
        }

        Ok(combined)
    }

    /// Binds `pid` across all stages in order.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `pid` - OS process ID.
    ///
    /// # Returns
    ///
    /// `Ok(())` when all stages have isolated `pid`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if any stage fails.
    pub fn isolate_all(&mut self, task_id: &TaskId, pid: u32) -> ArbiterResult<()> {
        for stage in &mut self.stages {
            stage.isolate(task_id, pid)?;
        }
        Ok(())
    }

    /// Updates limits across all stages in order.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `new_limits` - Updated resource limits.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if any stage fails.
    pub fn update_limits_all(
        &mut self,
        task_id: &TaskId,
        new_limits: &ResourceBundle,
    ) -> ArbiterResult<()> {
        for stage in &mut self.stages {
            stage.update_limits(task_id, new_limits)?;
        }
        Ok(())
    }

    /// Aggregates resource usage across all stages.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    ///
    /// # Returns
    ///
    /// Combined [`IsolatorUsageReport`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if any stage fails.
    pub fn usage_all(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
        let mut total = ResourceBundle::zero();
        for stage in &self.stages {
            let report = stage.usage(task_id)?;
            total = total.try_add(&report.consumed)?;
        }
        Ok(IsolatorUsageReport {
            task_id: task_id.clone(),
            consumed: total,
        })
    }

    /// Checkpoints the task across all stages in order.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `checkpoint_dir` - Target checkpoint directory.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if any stage fails.
    pub fn checkpoint_all(&mut self, task_id: &TaskId, checkpoint_dir: &str) -> ArbiterResult<()> {
        for stage in &mut self.stages {
            stage.checkpoint(task_id, checkpoint_dir)?;
        }
        Ok(())
    }

    /// Cleans up all stages in reverse order.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    ///
    /// # Returns
    ///
    /// `Ok(())` when all stages have cleaned up.
    ///
    /// # Errors
    ///
    /// Returns the first [`ArbiterError`](arbiter_core::error::ArbiterError) encountered after attempting cleanup on all stages.
    pub fn cleanup_all(&mut self, task_id: &TaskId) -> ArbiterResult<()> {
        let mut first_err = None;
        for stage in self.stages.iter_mut().rev() {
            if let Err(err) = stage.cleanup(task_id) {
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        Ok(())
    }
}

impl Default for IsolatorPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard Apache Mesos Containerizer `--isolation` plugin identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MesosIsolatorPlugin {
    /// `posix/cpu` POSIX rlimit CPU isolator.
    PosixCpu,
    /// `posix/mem` POSIX rlimit memory isolator.
    PosixMem,
    /// `posix/disk` POSIX du/prjquota disk isolator.
    PosixDisk,
    /// `cgroups/cpu` Linux cgroups v2 CPU isolator.
    CgroupsCpu,
    /// `cgroups/mem` Linux cgroups v2 memory isolator.
    CgroupsMem,
    /// `cgroups/devices` Linux cgroups v2 eBPF device whitelist isolator.
    CgroupsDevices,
    /// `gpu/nvidia` NVIDIA GPU/MIG/MPS isolator.
    GpuNvidia,
    /// `network/cni` Container Network Interface (`CNI`) plugin isolator.
    NetworkCni,
    /// `volume/sandbox_path` sandbox volume bind-mount isolator.
    VolumeSandboxPath,
    /// `volume/image` OCI image rootfs volume isolator.
    VolumeImage,
    /// `volume/secret` in-memory `tmpfs` secret volume isolator.
    VolumeSecret,
    /// `namespaces/pid` Linux PID namespace isolator.
    NamespacesPid,
    /// `namespaces/ipc` Linux IPC namespace isolator.
    NamespacesIpc,
    /// `docker/runtime` Docker/OCI runtime manifest configuration isolator.
    DockerRuntime,
}

impl MesosIsolatorPlugin {
    /// Parses a comma-separated `--isolation="cgroups/cpu,cgroups/mem,network/cni,..."` flag string
    /// into a vector of [`MesosIsolatorPlugin`]s.
    ///
    /// # Arguments
    ///
    /// * `isolation_flag` - Comma-separated Mesos isolator names.
    ///
    /// # Returns
    ///
    /// Ordered vector of parsed [`MesosIsolatorPlugin`]s.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SandboxError`](arbiter_core::error::ArbiterError::SandboxError) if any plugin name is unrecognized.
    pub fn parse_isolation_flag(isolation_flag: &str) -> ArbiterResult<Vec<Self>> {
        let mut out = Vec::new();
        for token in isolation_flag.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            let plugin = match trimmed {
                "posix/cpu" => Self::PosixCpu,
                "posix/mem" => Self::PosixMem,
                "posix/disk" => Self::PosixDisk,
                "cgroups/cpu" => Self::CgroupsCpu,
                "cgroups/mem" => Self::CgroupsMem,
                "cgroups/devices" => Self::CgroupsDevices,
                "gpu/nvidia" => Self::GpuNvidia,
                "network/cni" => Self::NetworkCni,
                "volume/sandbox_path" => Self::VolumeSandboxPath,
                "volume/image" => Self::VolumeImage,
                "volume/secret" => Self::VolumeSecret,
                "namespaces/pid" => Self::NamespacesPid,
                "namespaces/ipc" => Self::NamespacesIpc,
                "docker/runtime" => Self::DockerRuntime,
                _ => {
                    return Err(arbiter_core::error::ArbiterError::SandboxError {
                        mechanism: "mesos-isolation-flag".to_owned(),
                        reason: format!("unknown Mesos isolator plugin '{trimmed}'"),
                    });
                }
            };
            out.push(plugin);
        }
        Ok(out)
    }

    /// Returns the canonical Mesos `--isolation` flag token for this plugin.
    ///
    /// # Returns
    ///
    /// Static Mesos isolator name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PosixCpu => "posix/cpu",
            Self::PosixMem => "posix/mem",
            Self::PosixDisk => "posix/disk",
            Self::CgroupsCpu => "cgroups/cpu",
            Self::CgroupsMem => "cgroups/mem",
            Self::CgroupsDevices => "cgroups/devices",
            Self::GpuNvidia => "gpu/nvidia",
            Self::NetworkCni => "network/cni",
            Self::VolumeSandboxPath => "volume/sandbox_path",
            Self::VolumeImage => "volume/image",
            Self::VolumeSecret => "volume/secret",
            Self::NamespacesPid => "namespaces/pid",
            Self::NamespacesIpc => "namespaces/ipc",
            Self::DockerRuntime => "docker/runtime",
        }
    }
}

/// Standard CNI (`Container Network Interface`) command operation (`CNI_COMMAND`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CniCommand {
    /// `ADD` — attach container network namespace to CNI network.
    Add,
    /// `DEL` — detach container network namespace from CNI network.
    Del,
    /// `CHECK` — verify container network attachment health.
    Check,
}

impl CniCommand {
    /// Returns the `CNI_COMMAND` environment variable value.
    ///
    /// # Returns
    ///
    /// `"ADD"`, `"DEL"`, or `"CHECK"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "ADD",
            Self::Del => "DEL",
            Self::Check => "CHECK",
        }
    }
}

/// Mesos `network/cni` Container Network Interface (`CNI`) isolator (`CniPluginIsolator`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CniPluginIsolator {
    /// CNI network name (e.g., `"arbiter-br0"`).
    pub network_name: String,
    /// CNI plugin binary name (`"bridge"`, `"macvlan"`, `"calico"`, `"cilium"`).
    pub plugin_bin: String,
    /// Subnet CIDR assigned by IPAM (e.g., `"10.42.0.0/16"`).
    pub subnet_cidr: String,
    /// Assigned container interface name (e.g., `"eth0"`).
    pub ifname: String,
    /// Active CNI attachments keyed by [`TaskId`] storing `(pid, assigned_ip)`.
    #[serde(default)]
    pub active_attachments: std::collections::BTreeMap<TaskId, (u32, String)>,
}

impl CniPluginIsolator {
    /// Formats the CNI environment variables (`CNI_COMMAND`, `CNI_CONTAINERID`, `CNI_NETNS`,
    /// `CNI_IFNAME`, `CNI_PATH`) and JSON stdin configuration for `cmd`.
    ///
    /// # Arguments
    ///
    /// * `cmd` - [`CniCommand`] (`Add`, `Del`, `Check`).
    /// * `task_id` - Container [`TaskId`].
    /// * `pid` - Target container PID (`0` before isolate).
    ///
    /// # Returns
    ///
    /// Tuple `(env_vars, cni_config_json)`.
    pub fn format_cni_invocation(
        &self,
        cmd: CniCommand,
        task_id: &TaskId,
        pid: u32,
    ) -> (Vec<(String, String)>, String) {
        let env = vec![
            ("CNI_COMMAND".to_owned(), cmd.as_str().to_owned()),
            ("CNI_CONTAINERID".to_owned(), task_id.to_string()),
            ("CNI_NETNS".to_owned(), format!("/proc/{pid}/ns/net")),
            ("CNI_IFNAME".to_owned(), self.ifname.clone()),
            ("CNI_PATH".to_owned(), "/opt/cni/bin".to_owned()),
        ];
        let cfg_json = format!(
            r#"{{"cniVersion":"1.0.0","name":"{}","type":"{}","ipam":{{"type":"host-local","subnet":"{}"}}}}"#,
            self.network_name, self.plugin_bin, self.subnet_cidr
        );
        (env, cfg_json)
    }

    /// Executes a CNI plugin operation (`ADD`, `CHECK`, or `DEL`) by passing the CNI environment
    /// variables and JSON configuration stdin to `runner`, returning the parsed IPv4 address.
    ///
    /// # Arguments
    ///
    /// * `cmd` - [`CniCommand`] (`Add`, `Del`, or `Check`).
    /// * `task_id` - Container [`TaskId`].
    /// * `pid` - Container OS PID.
    /// * `runner` - Injected CNI plugin execution closure `FnMut(&[(String, String)], &str) -> ArbiterResult<String>`.
    ///
    /// # Returns
    ///
    /// Assigned container IPv4/IPv6 address returned by the CNI plugin.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CniPlugin`](arbiter_core::error::ArbiterError::CniPlugin) if the CNI plugin execution fails.
    pub fn execute_cni_command_with_runner<F>(
        &mut self,
        cmd: CniCommand,
        task_id: &TaskId,
        pid: u32,
        mut runner: F,
    ) -> ArbiterResult<String>
    where
        F: FnMut(&[(String, String)], &str) -> ArbiterResult<String>,
    {
        let (env, cfg_json) = self.format_cni_invocation(cmd, task_id, pid);
        let output = runner(&env, &cfg_json)?;
        if cmd == CniCommand::Add {
            self.active_attachments
                .insert(task_id.clone(), (pid, output.clone()));
        } else if cmd == CniCommand::Del {
            self.active_attachments.remove(task_id);
        }
        Ok(output)
    }
}

impl Isolator for CniPluginIsolator {
    fn name(&self) -> &'static str {
        "network/cni"
    }

    fn prepare(
        &mut self,
        task_id: &TaskId,
        _limits: &ResourceBundle,
    ) -> ArbiterResult<SandboxPreparation> {
        if self.network_name.trim().is_empty() || self.plugin_bin.trim().is_empty() {
            return Err(arbiter_core::error::ArbiterError::SandboxError {
                mechanism: "network/cni".to_owned(),
                reason: "CNI network_name and plugin_bin must not be empty".to_owned(),
            });
        }
        let (env, cfg) = self.format_cni_invocation(CniCommand::Add, task_id, 1);
        Ok(SandboxPreparation {
            device_mounts: Vec::new(),
            injected_env: env,
            applied_commands: vec![format!("cni:{}:{cfg}", self.plugin_bin)],
        })
    }

    fn isolate(&mut self, task_id: &TaskId, pid: u32) -> ArbiterResult<()> {
        if pid == 0 {
            return Err(arbiter_core::error::ArbiterError::from(
                arbiter_core::error::CniPluginError::new(
                    &self.plugin_bin,
                    task_id.as_str(),
                    "CNI netns isolate requires non-zero PID",
                ),
            ));
        }
        let (_, _) = self.format_cni_invocation(CniCommand::Add, task_id, pid);
        let (_, _) = self.format_cni_invocation(CniCommand::Check, task_id, pid);
        let prefix = self
            .subnet_cidr
            .split('/')
            .next()
            .unwrap_or("10.42.0.0")
            .trim_end_matches(".0");
        let assigned_ip = format!("{prefix}.2");
        self.active_attachments
            .insert(task_id.clone(), (pid, assigned_ip));
        Ok(())
    }

    fn update_limits(
        &mut self,
        _task_id: &TaskId,
        _new_limits: &ResourceBundle,
    ) -> ArbiterResult<()> {
        Ok(())
    }

    fn usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
        Ok(IsolatorUsageReport {
            task_id: task_id.clone(),
            consumed: ResourceBundle::zero(),
        })
    }

    fn checkpoint(&mut self, _task_id: &TaskId, _checkpoint_dir: &str) -> ArbiterResult<()> {
        Ok(())
    }

    fn cleanup(&mut self, task_id: &TaskId) -> ArbiterResult<()> {
        let removed = self.active_attachments.remove(task_id);
        let pid = match removed {
            Some((p, _)) => p,
            None => 0,
        };
        let (_, _) = self.format_cni_invocation(CniCommand::Del, task_id, pid);
        Ok(())
    }
}

/// Mesos `network/port_mapping` isolator (`PortMappingIsolator`).
///
/// Configures host-to-container DNAT/SNAT port forwarding (`nftables` / `pfctl`) and
/// eBPF Earliest Departure Time (`EDT`) / `tc qdisc fq` egress bandwidth shaping.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMappingIsolator {
    /// Host-to-container `(host_port, container_port)` mappings.
    pub port_mappings: Vec<(u16, u16)>,
    /// Container IPv4 address target for DNAT rules.
    pub container_ip: String,
    /// Recorded `nftables` / `pfctl` / `tc` EDT commands executed across lifecycle stages.
    #[serde(default)]
    pub applied_rules: Vec<String>,
}

impl PortMappingIsolator {
    /// Creates a new [`PortMappingIsolator`].
    ///
    /// # Arguments
    ///
    /// * `container_ip` - Assigned container IPv4 address.
    /// * `port_mappings` - Vector of `(host_port, container_port)` pairs.
    ///
    /// # Returns
    ///
    /// Initialized [`PortMappingIsolator`].
    pub fn new(container_ip: &str, port_mappings: Vec<(u16, u16)>) -> Self {
        Self {
            port_mappings,
            container_ip: container_ip.to_owned(),
            applied_rules: Vec::new(),
        }
    }

    /// Formats `nftables` DNAT (`prerouting`) and eBPF EDT / `tc qdisc fq` egress shaping rules.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `egress_bps` - Egress bandwidth cap in bits per second.
    ///
    /// # Returns
    ///
    /// Vector of formatted `nft` and `tc` commands.
    pub fn format_dnat_and_edt_commands(&self, task_id: &TaskId, egress_bps: u64) -> Vec<String> {
        let mut cmds = Vec::with_capacity(self.port_mappings.len().saturating_add(1));
        for &(host_port, container_port) in &self.port_mappings {
            cmds.push(format!(
                "nft add rule ip arbiter_nat prerouting tcp dport {host_port} dnat to {}:{container_port}",
                self.container_ip
            ));
        }
        let maxrate = egress_bps.max(1_000_000);
        cmds.push(format!(
            "tc qdisc replace dev veth_{task_id} root fq maxrate {maxrate}bit"
        ));
        cmds
    }
}

impl Isolator for PortMappingIsolator {
    fn name(&self) -> &'static str {
        "network/port_mapping"
    }

    fn prepare(
        &mut self,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<SandboxPreparation> {
        if self.container_ip.trim().is_empty() {
            return Err(arbiter_core::error::ArbiterError::SandboxError {
                mechanism: "network/port_mapping".to_owned(),
                reason: "container_ip must not be empty".to_owned(),
            });
        }
        let cmds = self.format_dnat_and_edt_commands(task_id, limits.network_bandwidth.get());
        self.applied_rules.extend(cmds.clone());
        Ok(SandboxPreparation {
            device_mounts: Vec::new(),
            injected_env: Vec::new(),
            applied_commands: cmds,
        })
    }

    fn isolate(&mut self, task_id: &TaskId, pid: u32) -> ArbiterResult<()> {
        if pid == 0 {
            return Err(arbiter_core::error::ArbiterError::SandboxError {
                mechanism: "network/port_mapping".to_owned(),
                reason: "pid must be non-zero".to_owned(),
            });
        }
        self.applied_rules
            .push(format!("ebpf_edt_attach:{task_id}:{pid}"));
        Ok(())
    }

    fn update_limits(
        &mut self,
        task_id: &TaskId,
        new_limits: &ResourceBundle,
    ) -> ArbiterResult<()> {
        let maxrate = new_limits.network_bandwidth.get().max(1_000_000);
        self.applied_rules.push(format!(
            "tc qdisc change dev veth_{task_id} root fq maxrate {maxrate}bit"
        ));
        Ok(())
    }

    fn usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
        Ok(IsolatorUsageReport {
            task_id: task_id.clone(),
            consumed: ResourceBundle::zero(),
        })
    }

    fn checkpoint(&mut self, _task_id: &TaskId, _checkpoint_dir: &str) -> ArbiterResult<()> {
        Ok(())
    }

    fn cleanup(&mut self, task_id: &TaskId) -> ArbiterResult<()> {
        self.applied_rules
            .push(format!("nft flush chain ip arbiter_nat task_{task_id}"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::error::ArbiterError;
    use arbiter_core::units::Millicores;

    use super::*;

    #[derive(Clone, Copy)]
    enum MockStageMode {
        Healthy(u64),
        FailPrepare,
        FailAllOps,
    }

    struct MockStage {
        mode: MockStageMode,
    }

    impl MockStage {
        const fn ok() -> Self {
            Self {
                mode: MockStageMode::Healthy(500),
            }
        }
    }

    impl Isolator for MockStage {
        fn name(&self) -> &'static str {
            "MockStage"
        }

        fn prepare(
            &mut self,
            _task_id: &TaskId,
            _limits: &ResourceBundle,
        ) -> ArbiterResult<SandboxPreparation> {
            if matches!(
                self.mode,
                MockStageMode::FailPrepare | MockStageMode::FailAllOps
            ) {
                return Err(ArbiterError::SandboxError {
                    mechanism: self.name().to_owned(),
                    reason: "prepare failed".to_owned(),
                });
            }
            Ok(SandboxPreparation {
                device_mounts: vec!["/dev/null".to_owned()],
                injected_env: vec![("K".to_owned(), "V".to_owned())],
                applied_commands: vec!["prepare".to_owned()],
            })
        }

        fn isolate(&mut self, _task_id: &TaskId, _pid: u32) -> ArbiterResult<()> {
            if matches!(self.mode, MockStageMode::FailAllOps) {
                return Err(ArbiterError::SandboxError {
                    mechanism: self.name().to_owned(),
                    reason: "isolate failed".to_owned(),
                });
            }
            Ok(())
        }

        fn update_limits(
            &mut self,
            _task_id: &TaskId,
            _new_limits: &ResourceBundle,
        ) -> ArbiterResult<()> {
            if matches!(self.mode, MockStageMode::FailAllOps) {
                return Err(ArbiterError::SandboxError {
                    mechanism: self.name().to_owned(),
                    reason: "update failed".to_owned(),
                });
            }
            Ok(())
        }

        fn usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
            match self.mode {
                MockStageMode::Healthy(cpu_val) => {
                    let mut b = ResourceBundle::zero();
                    b.cpu = Millicores::new(cpu_val);
                    Ok(IsolatorUsageReport {
                        task_id: task_id.clone(),
                        consumed: b,
                    })
                }
                MockStageMode::FailPrepare | MockStageMode::FailAllOps => {
                    Err(ArbiterError::SandboxError {
                        mechanism: self.name().to_owned(),
                        reason: "usage failed".to_owned(),
                    })
                }
            }
        }

        fn checkpoint(&mut self, _task_id: &TaskId, _checkpoint_dir: &str) -> ArbiterResult<()> {
            if matches!(self.mode, MockStageMode::FailAllOps) {
                return Err(ArbiterError::SandboxError {
                    mechanism: self.name().to_owned(),
                    reason: "checkpoint failed".to_owned(),
                });
            }
            Ok(())
        }

        fn cleanup(&mut self, _task_id: &TaskId) -> ArbiterResult<()> {
            if matches!(self.mode, MockStageMode::FailAllOps) {
                return Err(ArbiterError::SandboxError {
                    mechanism: self.name().to_owned(),
                    reason: "cleanup failed".to_owned(),
                });
            }
            Ok(())
        }
    }

    #[test]
    fn test_isolator_pipeline_lifecycle_and_atomic_rollback() {
        let tid = TaskId::new("task-iso-1").unwrap_or_default();
        let limits = ResourceBundle::zero();

        let mut pipeline = IsolatorPipeline::default();
        pipeline.add_stage(Box::new(MockStage::ok()));
        pipeline.add_stage(Box::new(MockStage::ok()));
        assert_eq!(pipeline.stage_count(), 2);

        let prep = pipeline.prepare_all(&tid, &limits).unwrap_or_default();
        assert_eq!(prep.applied_commands.len(), 2);
        assert!(pipeline.isolate_all(&tid, 1234).is_ok());
        assert!(pipeline.update_limits_all(&tid, &limits).is_ok());
        let usage = pipeline.usage_all(&tid).unwrap_or_default();
        assert_eq!(usage.consumed.cpu, Millicores::new(1000));
        assert!(pipeline.checkpoint_all(&tid, "/tmp/ckpt").is_ok());
        assert!(pipeline.cleanup_all(&tid).is_ok());

        // Atomic rollback when stage 2 prepare fails: stage 1 cleanup is invoked
        let mut p_rollback = IsolatorPipeline::new();
        p_rollback.add_stage(Box::new(MockStage::ok()));
        p_rollback.add_stage(Box::new(MockStage {
            mode: MockStageMode::FailPrepare,
        }));
        assert!(p_rollback.prepare_all(&tid, &limits).is_err());

        // Overflow in usage_all try_add
        let mut p_ovf = IsolatorPipeline::new();
        p_ovf.add_stage(Box::new(MockStage {
            mode: MockStageMode::Healthy(u64::MAX),
        }));
        p_ovf.add_stage(Box::new(MockStage::ok()));
        assert!(p_ovf.usage_all(&tid).is_err());

        // Error propagation on isolate, update_limits, usage, checkpoint, and cleanup (2 failing cleanup stages)
        let mut p_err = IsolatorPipeline::new();
        p_err.add_stage(Box::new(MockStage {
            mode: MockStageMode::FailAllOps,
        }));
        p_err.add_stage(Box::new(MockStage {
            mode: MockStageMode::FailAllOps,
        }));
        assert!(p_err.isolate_all(&tid, 1).is_err());
        assert!(p_err.update_limits_all(&tid, &limits).is_err());
        assert!(p_err.usage_all(&tid).is_err());
        assert!(p_err.checkpoint_all(&tid, "/tmp").is_err());
        assert!(p_err.cleanup_all(&tid).is_err());
    }

    #[test]
    fn test_mesos_isolator_plugins_and_cni_isolator() {
        let all_flag = "posix/cpu, posix/mem, posix/disk, cgroups/cpu, cgroups/mem, cgroups/devices, gpu/nvidia, network/cni, volume/sandbox_path, volume/image, volume/secret, namespaces/pid, namespaces/ipc, docker/runtime, ";
        let parsed = MesosIsolatorPlugin::parse_isolation_flag(all_flag).unwrap_or_default();
        assert_eq!(parsed.len(), 14);
        for p in parsed {
            let s = std::hint::black_box(p.as_str());
            assert!(!s.is_empty());
        }
        assert!(MesosIsolatorPlugin::parse_isolation_flag("unknown/plugin").is_err());

        let tid = TaskId::new("task-cni-1").unwrap_or_default();
        let limits = ResourceBundle::zero();
        let mut cni = CniPluginIsolator {
            network_name: "arbiter-net0".to_owned(),
            plugin_bin: "bridge".to_owned(),
            subnet_cidr: "10.42.0.0/16".to_owned(),
            ifname: "eth0".to_owned(),
            active_attachments: std::collections::BTreeMap::new(),
        };
        assert_eq!(cni.name(), "network/cni");
        let prep = cni.prepare(&tid, &limits).unwrap_or_default();
        assert_eq!(prep.injected_env.len(), 5);
        assert!(cni.isolate(&tid, 0).is_err());
        assert!(cni.isolate(&tid, 4242).is_ok());
        assert!(cni.active_attachments.contains_key(&tid));
        assert!(cni.update_limits(&tid, &limits).is_ok());
        assert!(cni.usage(&tid).is_ok());
        assert!(cni.checkpoint(&tid, "/tmp").is_ok());
        assert!(cni.cleanup(&tid).is_ok());
        assert!(cni.cleanup(&tid).is_ok());
        assert!(!cni.active_attachments.contains_key(&tid));

        let mut cni_runner = |env: &[(String, String)], _cfg: &str| -> ArbiterResult<String> {
            let is_fail = env.iter().any(|(k, v)| k == "CNI_IFNAME" && v == "fail");
            if is_fail {
                Err(ArbiterError::SandboxError {
                    mechanism: "cni".to_owned(),
                    reason: "failed".to_owned(),
                })
            } else {
                Ok("10.42.0.9".to_owned())
            }
        };
        assert_eq!(
            cni.execute_cni_command_with_runner(CniCommand::Add, &tid, 4242, &mut cni_runner),
            Ok("10.42.0.9".to_owned())
        );
        assert!(cni.active_attachments.contains_key(&tid));
        assert_eq!(
            cni.execute_cni_command_with_runner(CniCommand::Del, &tid, 4242, &mut cni_runner),
            Ok("10.42.0.9".to_owned())
        );
        assert!(!cni.active_attachments.contains_key(&tid));
        assert_eq!(
            cni.execute_cni_command_with_runner(CniCommand::Check, &tid, 4242, &mut cni_runner),
            Ok("10.42.0.9".to_owned())
        );
        cni.ifname = "fail".to_owned();
        assert!(
            cni.execute_cni_command_with_runner(CniCommand::Check, &tid, 4242, &mut cni_runner)
                .is_err()
        );

        let mut bad_cni1 = cni.clone();
        bad_cni1.network_name = "  ".to_owned();
        assert!(bad_cni1.prepare(&tid, &limits).is_err());
        let mut bad_cni2 = cni;
        bad_cni2.plugin_bin = String::new();
        assert!(bad_cni2.prepare(&tid, &limits).is_err());
    }

    #[test]
    fn test_port_mapping_isolator() {
        let tid = TaskId::new("task-pmap-1").unwrap_or_default();
        let limits = ResourceBundle::zero();
        let mut pmap = PortMappingIsolator::new("10.42.0.2", vec![(8080, 80), (8443, 443)]);
        assert_eq!(pmap.name(), "network/port_mapping");
        assert!(pmap.prepare(&tid, &limits).is_ok());
        assert!(pmap.isolate(&tid, 0).is_err());
        assert!(pmap.isolate(&tid, 4242).is_ok());
        assert!(pmap.update_limits(&tid, &limits).is_ok());
        assert!(pmap.usage(&tid).is_ok());
        assert!(pmap.checkpoint(&tid, "/tmp").is_ok());
        assert!(pmap.cleanup(&tid).is_ok());
        assert_eq!(pmap.applied_rules.len(), 6);
        let mut bad_pmap = PortMappingIsolator::new("   ", Vec::new());
        assert!(bad_pmap.prepare(&tid, &limits).is_err());
    }
}
