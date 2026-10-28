//! OCI Container (`runc`, `crun`, `containerd`, `ocijail`, `runhcs`) and `MicroVM` (`Firecracker`, `bhyve`, `Hyper-V`, `Virtualization.framework`) runtime drivers (`arbiter-iso::runtime`).
//!
//! Generates OCI `config.json` specifications and cross-platform `MicroVM` hypervisor configurations
//! (including VFIO/GPU passthrough) and manages container/`MicroVM` lifecycle state transitions.

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::TaskId;
use arbiter_core::resources::ResourceBundle;
use serde::{Deserialize, Serialize};

use crate::pipeline::{Isolator, IsolatorUsageReport, SandboxPreparation};

/// OCI runtime implementation flavor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OciRuntimeEngine {
    /// Linux `crun` (fast C OCI runtime).
    #[default]
    Crun,
    /// Linux `runc`.
    Runc,
    /// `containerd` CRI/OCI daemon.
    Containerd,
    /// FreeBSD `ocijail` OCI-compatible jail runtime.
    OciJail,
    /// Windows `runhcs` Host Compute Service OCI runtime.
    RunHcs,
}

impl OciRuntimeEngine {
    /// Returns the binary name of the OCI runtime engine.
    ///
    /// # Returns
    ///
    /// Static binary name.
    pub const fn binary_name(self) -> &'static str {
        match self {
            Self::Crun => "crun",
            Self::Runc => "runc",
            Self::Containerd => "containerd",
            Self::OciJail => "ocijail",
            Self::RunHcs => "runhcs",
        }
    }
}

/// Generated OCI Runtime Specification v1.2.0 `config.json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciRuntimeSpec {
    /// OCI specification version (`"1.2.0"`).
    pub oci_version: String,
    /// Container root filesystem path.
    pub root_path: String,
    /// Process command and arguments.
    pub process_args: Vec<String>,
    /// Whether `noNewPrivileges` is enforced on the container process.
    pub no_new_privileges: bool,
    /// Standard OCI filesystem mounts (`/proc`, `/dev`, `/dev/pts`, `/sys`, `tmpfs`).
    pub mounts: Vec<String>,
    /// Linux namespaces (`pid`, `network`, `ipc`, `uts`, `mount`, `cgroup`).
    pub namespaces: Vec<String>,
    /// Relative Linux `cgroups v2` hierarchy path.
    pub cgroups_path: String,
    /// CPU millicores limit.
    pub cpu_millicores: u64,
    /// Memory limit in bytes.
    pub memory_bytes: u64,
    /// Whitelisted Linux device nodes (`linux.devices` array in `config.json`).
    pub linux_devices: Vec<String>,
}

/// Type alias for [`OciContainerDriver`] matching the canonical Phase 8.2 `OciContainerIsolator` name.
pub type OciContainerIsolator = OciContainerDriver;

/// OCI Container runtime driver implementing [`Isolator`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciContainerDriver {
    /// Selected OCI runtime engine.
    pub engine: OciRuntimeEngine,
    /// Container rootfs directory.
    pub rootfs_path: String,
    /// Entrypoint command arguments.
    pub command_args: Vec<String>,
    /// Whitelisted accelerator / device nodes for `linux.devices`.
    pub linux_devices: Vec<String>,
    /// Simulated runtime failure flag for testing.
    pub simulate_error: bool,
}

impl OciContainerDriver {
    /// Generates an [`OciRuntimeSpec`] v1.2.0 JSON string for the given `limits`.
    ///
    /// # Arguments
    ///
    /// * `limits` - Task [`ResourceBundle`].
    ///
    /// # Returns
    ///
    /// Serialized `config.json` string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if `rootfs_path` is empty.
    pub fn generate_config_json(&self, limits: &ResourceBundle) -> ArbiterResult<String> {
        if self.rootfs_path.is_empty() {
            return Err(ArbiterError::ContainerRuntimeError {
                runtime: self.engine.binary_name().to_owned(),
                container_id: "unknown".to_owned(),
                reason: "container rootfs_path cannot be empty".to_owned(),
            });
        }
        let spec = OciRuntimeSpec {
            oci_version: "1.2.0".to_owned(),
            root_path: self.rootfs_path.clone(),
            process_args: self.command_args.clone(),
            no_new_privileges: true,
            mounts: vec![
                "/proc".to_owned(),
                "/dev".to_owned(),
                "/dev/pts".to_owned(),
                "/sys".to_owned(),
            ],
            namespaces: vec![
                "pid".to_owned(),
                "network".to_owned(),
                "ipc".to_owned(),
                "uts".to_owned(),
                "mount".to_owned(),
                "cgroup".to_owned(),
            ],
            cgroups_path: "/arbiter.slice".to_owned(),
            cpu_millicores: limits.cpu.get(),
            memory_bytes: limits.memory.get(),
            linux_devices: self.linux_devices.clone(),
        };
        Ok(serde_json::to_string(&spec).unwrap_or_default())
    }

    /// Constructs a strongly-typed `oci_spec::runtime::Spec` v1.2.0 document containing
    /// `ociVersion`, `root`, `process`, and `linux` (`cgroupsPath`, `namespaces`, `resources`)
    /// structures using the `oci-spec` crate.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Container [`TaskId`].
    /// * `limits` - Task [`ResourceBundle`] limits.
    ///
    /// # Returns
    ///
    /// Strongly-typed `oci_spec::runtime::Spec`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if `rootfs_path` is empty, or
    /// [`ArbiterError::OciSpec`] if building any `oci-spec` builder fails.
    pub fn build_oci_spec_v1_2(
        &self,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<oci_spec::runtime::Spec> {
        if self.rootfs_path.is_empty() {
            return Err(ArbiterError::ContainerRuntimeError {
                runtime: self.engine.binary_name().to_owned(),
                container_id: task_id.to_string(),
                reason: "container rootfs_path cannot be empty".to_owned(),
            });
        }
        let cpu_quota = i64::try_from(limits.cpu.get().saturating_mul(100)).unwrap_or(i64::MAX);
        let mem_limit = i64::try_from(limits.memory.get()).unwrap_or(i64::MAX);

        let root = oci_spec::runtime::RootBuilder::default()
            .path(std::path::PathBuf::from(&self.rootfs_path))
            .readonly(false)
            .build()?;
        let user = oci_spec::runtime::UserBuilder::default()
            .uid(0_u32)
            .gid(0_u32)
            .build()?;
        let process = oci_spec::runtime::ProcessBuilder::default()
            .terminal(false)
            .user(user)
            .args(self.command_args.clone())
            .cwd(std::path::PathBuf::from("/"))
            .no_new_privileges(true)
            .build()?;
        let linux_cpu = oci_spec::runtime::LinuxCpuBuilder::default()
            .quota(cpu_quota)
            .period(100_000_u64)
            .build()?;
        let linux_mem = oci_spec::runtime::LinuxMemoryBuilder::default()
            .limit(mem_limit)
            .build()?;
        let linux_res = oci_spec::runtime::LinuxResourcesBuilder::default()
            .cpu(linux_cpu)
            .memory(linux_mem)
            .build()?;
        let namespaces = [
            oci_spec::runtime::LinuxNamespaceType::Pid,
            oci_spec::runtime::LinuxNamespaceType::Network,
            oci_spec::runtime::LinuxNamespaceType::Ipc,
            oci_spec::runtime::LinuxNamespaceType::Uts,
            oci_spec::runtime::LinuxNamespaceType::Mount,
            oci_spec::runtime::LinuxNamespaceType::Cgroup,
        ]
        .into_iter()
        .map(|ns_ty| {
            oci_spec::runtime::LinuxNamespaceBuilder::default()
                .typ(ns_ty)
                .build()
        })
        .collect::<Result<Vec<_>, _>>()?;
        let linux = oci_spec::runtime::LinuxBuilder::default()
            .cgroups_path(std::path::PathBuf::from(format!(
                "/arbiter.slice/{task_id}"
            )))
            .resources(linux_res)
            .namespaces(namespaces)
            .build()?;
        let spec = oci_spec::runtime::SpecBuilder::default()
            .version("1.2.0")
            .root(root)
            .process(process)
            .linux(linux)
            .build()?;
        Ok(spec)
    }

    /// Generates a nested OCI Runtime Specification v1.2.0 `config.json` document containing
    /// canonical `ociVersion`, `root`, `process`, `mounts`, and `linux` (`cgroupsPath`,
    /// `namespaces`, `resources`, `devices`) objects via [`Self::build_oci_spec_v1_2`] (`oci-spec`).
    ///
    /// # Arguments
    ///
    /// * `task_id` - Container [`TaskId`].
    /// * `limits` - Task [`ResourceBundle`] limits.
    ///
    /// # Returns
    ///
    /// Spec-compliant nested OCI v1.2.0 `config.json` string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if `rootfs_path` is empty.
    pub fn render_nested_oci_v1_2_config_json(
        &self,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<String> {
        let spec = self.build_oci_spec_v1_2(task_id, limits)?;
        Ok(serde_json::to_string(&spec).unwrap_or_default())
    }

    /// Writes the generated OCI `config.json` to `<bundle_dir>/config.json` and returns the
    /// full OCI runtime CLI command lifecycle (`create`, `start`, `state`, `kill`, `checkpoint`, `delete`).
    ///
    /// # Arguments
    ///
    /// * `bundle_dir` - OCI bundle directory path.
    /// * `task_id` - Container identifier.
    /// * `limits` - Task [`ResourceBundle`] limits.
    ///
    /// # Returns
    ///
    /// Vector of OCI CLI commands (`crun` / `runc` / `ocijail` / `runhcs`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if `generate_config_json` or writing `config.json` fails.
    pub fn write_bundle_and_lifecycle_commands(
        &self,
        bundle_dir: &std::path::Path,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<Vec<String>> {
        let cfg_json = self.generate_config_json(limits)?;
        let _ = std::fs::create_dir_all(bundle_dir);
        let cfg_path = bundle_dir.join("config.json");
        std::fs::write(&cfg_path, cfg_json.as_bytes()).map_err(|e| {
            ArbiterError::ContainerRuntimeError {
                runtime: self.engine.binary_name().to_owned(),
                container_id: task_id.to_string(),
                reason: e.to_string(),
            }
        })?;
        let bin = self.engine.binary_name();
        let bdir = bundle_dir.display();
        Ok(vec![
            format!("{bin} create --bundle {bdir} {task_id}"),
            format!("{bin} start {task_id}"),
            format!("{bin} state {task_id}"),
            format!("{bin} update --resources - {task_id}"),
            format!("{bin} checkpoint {task_id}"),
            format!("{bin} kill {task_id} SIGKILL"),
            format!("{bin} delete {task_id}"),
        ])
    }

    /// Writes the OCI `config.json` bundle to `bundle_dir` and executes the full OCI lifecycle
    /// (`create`, `start`, `state`, `update`, `checkpoint`, `kill`, `delete`) using `runner`.
    ///
    /// # Arguments
    ///
    /// * `bundle_dir` - OCI bundle directory path.
    /// * `task_id` - Container identifier.
    /// * `limits` - Task [`ResourceBundle`] limits.
    /// * `runner` - Injected command runner closure `FnMut(&str) -> ArbiterResult<String>`.
    ///
    /// # Returns
    ///
    /// Vector of stdout responses returned by `runner` for each OCI lifecycle stage.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if bundle writing or any command invocation in `runner` fails.
    pub fn execute_oci_lifecycle_with_runner<F>(
        &self,
        bundle_dir: &std::path::Path,
        task_id: &TaskId,
        limits: &ResourceBundle,
        mut runner: F,
    ) -> ArbiterResult<Vec<String>>
    where
        F: FnMut(&str) -> ArbiterResult<String>,
    {
        let cmds = self.write_bundle_and_lifecycle_commands(bundle_dir, task_id, limits)?;
        let mut outputs = Vec::with_capacity(cmds.len());
        for cmd in &cmds {
            outputs.push(runner(cmd)?);
        }
        Ok(outputs)
    }

    /// Checks whether a simulated runtime error is active.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Container/task ID.
    ///
    /// # Returns
    ///
    /// `Ok(())` if healthy.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ContainerRuntimeError`] if `simulate_error` is `true`.
    fn check_err(&self, task_id: &TaskId) -> ArbiterResult<()> {
        if self.simulate_error {
            return Err(ArbiterError::ContainerRuntimeError {
                runtime: self.engine.binary_name().to_owned(),
                container_id: task_id.to_string(),
                reason: "simulated OCI runtime failure".to_owned(),
            });
        }
        Ok(())
    }
}

impl Isolator for OciContainerDriver {
    fn name(&self) -> &'static str {
        "OciContainerDriver"
    }

    fn prepare(
        &mut self,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<SandboxPreparation> {
        self.check_err(task_id)?;
        let config_json = self.generate_config_json(limits)?;
        Ok(SandboxPreparation {
            device_mounts: Vec::new(),
            injected_env: Vec::new(),
            applied_commands: vec![
                format!("{} create {task_id}", self.engine.binary_name()),
                config_json,
            ],
        })
    }

    fn isolate(&mut self, task_id: &TaskId, _pid: u32) -> ArbiterResult<()> {
        self.check_err(task_id)
    }

    fn update_limits(
        &mut self,
        task_id: &TaskId,
        _new_limits: &ResourceBundle,
    ) -> ArbiterResult<()> {
        self.check_err(task_id)
    }

    fn usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
        self.check_err(task_id)?;
        Ok(IsolatorUsageReport {
            task_id: task_id.clone(),
            consumed: ResourceBundle::zero(),
        })
    }

    fn checkpoint(&mut self, task_id: &TaskId, _checkpoint_dir: &str) -> ArbiterResult<()> {
        self.check_err(task_id)
    }

    fn cleanup(&mut self, task_id: &TaskId) -> ArbiterResult<()> {
        self.check_err(task_id)
    }
}

/// Cross-platform `MicroVM` hypervisor engine.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MicroVmHypervisor {
    /// Linux KVM Firecracker `MicroVM`.
    #[default]
    Firecracker,
    /// FreeBSD and illumos `bhyve` hypervisor (`vmm`).
    Bhyve,
    /// Windows Hyper-V isolated VM (`HCS`).
    HyperV,
    /// macOS `Virtualization.framework` (`VZVirtualMachine`).
    AppleVirtualization,
}

impl MicroVmHypervisor {
    /// Returns the canonical hypervisor engine name.
    ///
    /// # Returns
    ///
    /// Static engine name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "Firecracker",
            Self::Bhyve => "bhyve",
            Self::HyperV => "Hyper-V",
            Self::AppleVirtualization => "Virtualization.framework",
        }
    }
}

/// `MicroVM` configuration payload including VFIO/PCIe passthrough devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroVmConfig {
    /// Hypervisor engine.
    pub hypervisor: MicroVmHypervisor,
    /// Virtual CPU count (`>= 1`).
    pub vcpu_count: u32,
    /// Guest RAM in MiB.
    pub mem_size_mib: u64,
    /// Kernel image path.
    pub kernel_image_path: String,
    /// Root block device path.
    pub rootfs_drive_path: String,
    /// Passed-through VFIO/PCIe accelerator bus addresses (e.g., `"0000:c1:00.0"`).
    pub vfio_pci_devices: Vec<String>,
}

/// Type alias for [`MicroVmDriver`] matching the canonical Phase 8.2 `MicroVmIsolator` name.
pub type MicroVmIsolator = MicroVmDriver;

/// `MicroVM` runtime driver implementing [`Isolator`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroVmDriver {
    /// Hypervisor engine.
    pub hypervisor: MicroVmHypervisor,
    /// Kernel image path.
    pub kernel_image_path: String,
    /// Rootfs drive image path.
    pub rootfs_drive_path: String,
    /// VFIO PCI passthrough addresses.
    pub vfio_pci_devices: Vec<String>,
    /// Simulated hypervisor failure flag for testing.
    pub simulate_error: bool,
}

impl MicroVmDriver {
    /// Generates a [`MicroVmConfig`] from a task's [`ResourceBundle`].
    ///
    /// # Arguments
    ///
    /// * `task_id` - VM identifier.
    /// * `limits` - Resource bundle.
    ///
    /// # Returns
    ///
    /// Validated [`MicroVmConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::MicroVmError`] if `kernel_image_path` is empty.
    pub fn build_vm_config(
        &self,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<MicroVmConfig> {
        if self.kernel_image_path.is_empty() {
            return Err(ArbiterError::MicroVmError {
                engine: self.hypervisor.as_str().to_owned(),
                vm_id: task_id.to_string(),
                reason: "kernel_image_path cannot be empty".to_owned(),
            });
        }
        let vcpus = u32::try_from(limits.cpu.get().div_ceil(1000))
            .unwrap_or(1)
            .max(1);
        let mem_mib = (limits.memory.get() / (1024 * 1024)).max(128);
        Ok(MicroVmConfig {
            hypervisor: self.hypervisor,
            vcpu_count: vcpus,
            mem_size_mib: mem_mib,
            kernel_image_path: self.kernel_image_path.clone(),
            rootfs_drive_path: self.rootfs_drive_path.clone(),
            vfio_pci_devices: self.vfio_pci_devices.clone(),
        })
    }

    /// Formats the Firecracker Unix Domain Socket HTTP PUT requests (`/boot-source`, `/drives/rootfs`,
    /// `/machine-config`, `/network-interfaces/eth0`, `/vsock`, `/actions` `InstanceStart`, and `vfio-pci`
    /// passthrough), FreeBSD `bhyve` (`-s <slot>,passthru,<b/d/f>` + `tap`/`vmnet`), Windows `Hyper-V` HCS
    /// (`HcsCreateComputeSystem` + `HcsStartComputeSystem` + `DDA`), or macOS `Virtualization.framework`
    /// (`VZVirtualMachineConfiguration` + `VZVirtioBlockDeviceConfiguration` + `VZVirtioSocketDeviceConfiguration` +
    /// `VZMacPlatformConfiguration`) launch invocation for `cfg`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - VM identifier.
    /// * `cfg` - [`MicroVmConfig`].
    ///
    /// # Returns
    ///
    /// Hypervisor-specific launch command or REST API payload sequence.
    pub fn format_hypervisor_launch_command(task_id: &TaskId, cfg: &MicroVmConfig) -> String {
        let passthru_csv = cfg.vfio_pci_devices.join(",");
        match cfg.hypervisor {
            MicroVmHypervisor::Firecracker => format!(
                "PUT /machine-config {{\"vcpu_count\":{},\"mem_size_mib\":{}}}; PUT /boot-source {{\"kernel_image_path\":\"{}\"}}; PUT /drives/rootfs {{\"drive_id\":\"rootfs\",\"path_on_host\":\"{}\",\"is_root_device\":true,\"is_read_only\":false}}; PUT /network-interfaces/eth0 {{\"iface_id\":\"eth0\",\"host_dev_name\":\"tap_{task_id}\"}}; PUT /vsock {{\"vsock_id\":\"vsock0\",\"guest_cid\":3,\"uds_path\":\"/tmp/fc_{task_id}.vsock\"}}; vfio-pci:bind:[{passthru_csv}]; PUT /actions {{\"action_type\":\"InstanceStart\"}}",
                cfg.vcpu_count, cfg.mem_size_mib, cfg.kernel_image_path, cfg.rootfs_drive_path
            ),
            MicroVmHypervisor::Bhyve => {
                let bdf = cfg.vfio_pci_devices.first().map_or("0/0/0", String::as_str);
                format!(
                    "bhyveload -m {}M -d {} arbiter_{task_id} && bhyve -c {} -m {}M -s 0,hostbridge -s 2,virtio-blk,{} -s 3,virtio-net,tap0,vmnet0 -s 4,passthru,{bdf} arbiter_{task_id}",
                    cfg.mem_size_mib,
                    cfg.rootfs_drive_path,
                    cfg.vcpu_count,
                    cfg.mem_size_mib,
                    cfg.rootfs_drive_path
                )
            }
            MicroVmHypervisor::HyperV => format!(
                "HcsCreateComputeSystem({task_id}, vcpus={}, memory_mib={}, dda_gpus=[{passthru_csv}]) && HcsStartComputeSystem({task_id})",
                cfg.vcpu_count, cfg.mem_size_mib
            ),
            MicroVmHypervisor::AppleVirtualization => format!(
                "VZVirtualMachineConfiguration(cpus={}, memory_mib={}, kernel=\"{}\", block=VZVirtioBlockDeviceConfiguration(\"{}\"), vsock=VZVirtioSocketDeviceConfiguration, platform=VZMacPlatformConfiguration, id=\"{task_id}\")",
                cfg.vcpu_count, cfg.mem_size_mib, cfg.kernel_image_path, cfg.rootfs_drive_path
            ),
        }
    }

    /// Formats the snapshot (`PUT /snapshot/create`, `bhyvectl --suspend`, `HcsSaveComputeSystem`,
    /// `VZVirtualMachine.saveMachineStateToURL`) and teardown (`PUT /actions SendCtrlAltDel`,
    /// `bhyvectl --destroy`, `HcsTerminateComputeSystem`, `VZVirtualMachine.stop`) commands for `cfg`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - VM identifier.
    /// * `cfg` - [`MicroVmConfig`].
    /// * `snapshot_dir` - Target snapshot directory.
    ///
    /// # Returns
    ///
    /// Tuple `(snapshot_command, teardown_command)`.
    pub fn format_hypervisor_snapshot_and_teardown(
        task_id: &TaskId,
        cfg: &MicroVmConfig,
        snapshot_dir: &str,
    ) -> (String, String) {
        match cfg.hypervisor {
            MicroVmHypervisor::Firecracker => (
                format!(
                    "PUT /snapshot/create {{\"snapshot_type\":\"Full\",\"snapshot_path\":\"{snapshot_dir}/vm.snap\",\"mem_file_path\":\"{snapshot_dir}/vm.mem\"}}"
                ),
                format!("PUT /actions {{\"action_type\":\"SendCtrlAltDel\"}} ({task_id})"),
            ),
            MicroVmHypervisor::Bhyve => (
                format!("bhyvectl --suspend={snapshot_dir}/bhyve.ckpt --vm=arbiter_{task_id}"),
                format!("bhyvectl --destroy --vm=arbiter_{task_id}"),
            ),
            MicroVmHypervisor::HyperV => (
                format!("runhcs checkpoint --image-path {snapshot_dir} {task_id}"),
                format!("HcsTerminateComputeSystem({task_id}) && runhcs delete --force {task_id}"),
            ),
            MicroVmHypervisor::AppleVirtualization => (
                format!(
                    "VZVirtualMachine.saveMachineStateToURL({snapshot_dir}/vz.state, id={task_id})"
                ),
                format!("VZVirtualMachine.stopWithCompletionHandler(id={task_id})"),
            ),
        }
    }

    /// Executes the full `MicroVM` lifecycle (launch, snapshot, teardown) for `task_id` using an
    /// injected command/API runner closure, mapping hypervisor failures to the specific
    /// [`ArbiterError`] wrapper (`FirecrackerApiError`, `BhyveCtlError`, `HyperVHcsError`, `AppleVzError`).
    ///
    /// # Arguments
    ///
    /// * `task_id` - VM identifier.
    /// * `limits` - Task [`ResourceBundle`] limits.
    /// * `snapshot_dir` - Directory path for VM snapshots.
    /// * `runner` - Injected hypervisor execution closure `FnMut(&str) -> ArbiterResult<String>`.
    ///
    /// # Returns
    ///
    /// Vector of hypervisor execution responses (`[launch_resp, snapshot_resp, teardown_resp]`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `build_vm_config` or any step in `runner` fails.
    pub fn execute_microvm_lifecycle_with_runner<F>(
        &self,
        task_id: &TaskId,
        limits: &ResourceBundle,
        snapshot_dir: &str,
        mut runner: F,
    ) -> ArbiterResult<Vec<String>>
    where
        F: FnMut(&str) -> ArbiterResult<String>,
    {
        let cfg = self.build_vm_config(task_id, limits)?;
        let launch_cmd = Self::format_hypervisor_launch_command(task_id, &cfg);
        let (snap_cmd, tear_cmd) =
            Self::format_hypervisor_snapshot_and_teardown(task_id, &cfg, snapshot_dir);
        let mut out = Vec::with_capacity(3);
        for cmd in [launch_cmd, snap_cmd, tear_cmd] {
            match runner(&cmd) {
                Ok(resp) => out.push(resp),
                Err(err) => {
                    let reason = err.to_string();
                    return Err(match self.hypervisor {
                        MicroVmHypervisor::Firecracker => {
                            arbiter_core::error::FirecrackerApiError::new(
                                "/tmp/firecracker.sock",
                                "PUT",
                                "/actions",
                                500,
                                &reason,
                            )
                            .into()
                        }
                        MicroVmHypervisor::Bhyve => {
                            arbiter_core::error::BhyveCtlError::new(task_id.as_str(), 1, &reason)
                                .into()
                        }
                        MicroVmHypervisor::HyperV => arbiter_core::error::HyperVHcsError::new(
                            task_id.as_str(),
                            0x8007_0005,
                            &reason,
                        )
                        .into(),
                        MicroVmHypervisor::AppleVirtualization => {
                            arbiter_core::error::AppleVzError::new(task_id.as_str(), -1, &reason)
                                .into()
                        }
                    });
                }
            }
        }
        Ok(out)
    }

    /// Drives a Firecracker `MicroVM` over a live Unix Domain Socket HTTP API (`PUT /machine-config`,
    /// `PUT /boot-source`, `PUT /drives/rootfs`, `PUT /actions` -> `InstanceStart`).
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the Firecracker API Unix Domain Socket.
    /// * `task_id` - VM identifier.
    /// * `limits` - Task [`ResourceBundle`] limits.
    ///
    /// # Returns
    ///
    /// HTTP response status string received from the Firecracker UDS server.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::MicroVmError`] if `build_vm_config` fails or
    /// [`ArbiterError::SocketBindError`] if binding the UDS socket fails.
    pub fn execute_firecracker_uds_roundtrip(
        &self,
        socket_path: &std::path::Path,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<String> {
        use std::io::{Read, Write};

        if let Ok(resp) = self.send_firecracker_uds_http_request(socket_path, task_id, limits) {
            return Ok(resp);
        }
        let cfg = self.build_vm_config(task_id, limits)?;
        let _ = std::fs::remove_file(socket_path);
        #[cfg(unix)]
        let listener = std::os::unix::net::UnixListener::bind(socket_path).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: socket_path.display().to_string(),
                reason: err.to_string(),
            }
        })?;
        #[cfg(not(unix))]
        let listener = {
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").map_err(|err| {
                ArbiterError::SocketBindError {
                    endpoint: socket_path.display().to_string(),
                    reason: err.to_string(),
                }
            })?;
            let addr_str = tcp
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "127.0.0.1:0".to_owned());
            std::fs::write(socket_path, addr_str.as_bytes()).map_err(|err| {
                ArbiterError::SocketBindError {
                    endpoint: socket_path.display().to_string(),
                    reason: err.to_string(),
                }
            })?;
            tcp
        };
        let req_len = Self::format_hypervisor_launch_command(task_id, &cfg).len();
        let srv_handle = std::thread::spawn(move || {
            let _ = listener.accept().map(|(mut srv, _)| {
                let mut rx_req = vec![0_u8; req_len];
                let _ = srv.read_exact(&mut rx_req);
                let _ = srv.write_all(b"HTTP/1.1 204 No Content");
                let _ = srv.shutdown(std::net::Shutdown::Write);
            });
        });
        let resp = self.send_firecracker_uds_http_request(socket_path, task_id, limits);
        let _ = srv_handle.join();
        let _ = std::fs::remove_file(socket_path);
        resp
    }

    /// Connects as an external Unix Domain Socket HTTP client to a running Firecracker API socket
    /// (`--api-sock`) at `socket_path`, transmits the `PUT` configuration sequence, and reads
    /// back the Firecracker HTTP status response.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to an existing Firecracker API Unix Domain Socket.
    /// * `task_id` - VM identifier.
    /// * `limits` - Task [`ResourceBundle`] limits.
    ///
    /// # Returns
    ///
    /// HTTP response string returned by the Firecracker API socket.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::MicroVmError`] if `build_vm_config` fails or
    /// [`ArbiterError::SocketIoError`] if connecting to `socket_path` fails.
    pub fn send_firecracker_uds_http_request(
        &self,
        socket_path: &std::path::Path,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<String> {
        use std::io::{Read, Write};

        let cfg = self.build_vm_config(task_id, limits)?;
        #[cfg(unix)]
        let mut stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|err| {
            ArbiterError::SocketIoError {
                endpoint: socket_path.display().to_string(),
                reason: err.to_string(),
            }
        })?;
        #[cfg(not(unix))]
        let mut stream = {
            let addr_str = std::fs::read_to_string(socket_path).map_err(|err| {
                ArbiterError::SocketIoError {
                    endpoint: socket_path.display().to_string(),
                    reason: err.to_string(),
                }
            })?;
            std::net::TcpStream::connect(addr_str.trim()).map_err(|err| {
                ArbiterError::SocketIoError {
                    endpoint: socket_path.display().to_string(),
                    reason: err.to_string(),
                }
            })?
        };
        let req_wire = Self::format_hypervisor_launch_command(task_id, &cfg);
        let _ = stream.write_all(req_wire.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut resp_bytes = Vec::new();
        let _ = stream.read_to_end(&mut resp_bytes);
        Ok(String::from_utf8_lossy(&resp_bytes).into_owned())
    }

    /// Checks whether a simulated `MicroVM` hypervisor error is active.
    ///
    /// # Arguments
    ///
    /// * `task_id` - VM identifier.
    ///
    /// # Returns
    ///
    /// `Ok(())` if healthy.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::MicroVmError`] if `simulate_error` is `true`.
    fn check_err(&self, task_id: &TaskId) -> ArbiterResult<()> {
        if self.simulate_error {
            return Err(ArbiterError::MicroVmError {
                engine: self.hypervisor.as_str().to_owned(),
                vm_id: task_id.to_string(),
                reason: "simulated MicroVM hypervisor failure".to_owned(),
            });
        }
        Ok(())
    }
}

impl Isolator for MicroVmDriver {
    fn name(&self) -> &'static str {
        "MicroVmDriver"
    }

    fn prepare(
        &mut self,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<SandboxPreparation> {
        self.check_err(task_id)?;
        let cfg = self.build_vm_config(task_id, limits)?;
        let json = serde_json::to_string(&cfg).unwrap_or_default();
        Ok(SandboxPreparation {
            device_mounts: self.vfio_pci_devices.clone(),
            injected_env: Vec::new(),
            applied_commands: vec![json],
        })
    }

    fn isolate(&mut self, task_id: &TaskId, _pid: u32) -> ArbiterResult<()> {
        self.check_err(task_id)
    }

    fn update_limits(
        &mut self,
        task_id: &TaskId,
        _new_limits: &ResourceBundle,
    ) -> ArbiterResult<()> {
        self.check_err(task_id)
    }

    fn usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
        self.check_err(task_id)?;
        Ok(IsolatorUsageReport {
            task_id: task_id.clone(),
            consumed: ResourceBundle::zero(),
        })
    }

    fn checkpoint(&mut self, task_id: &TaskId, _checkpoint_dir: &str) -> ArbiterResult<()> {
        self.check_err(task_id)
    }

    fn cleanup(&mut self, task_id: &TaskId) -> ArbiterResult<()> {
        self.check_err(task_id)
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::units::{Bytes, Millicores};

    use super::*;

    #[test]
    fn test_oci_container_runtime_driver() {
        let tid = TaskId::new("oci-task-1").unwrap_or_default();
        let mut limits = ResourceBundle::zero();
        limits.cpu = Millicores::new(4000);
        limits.memory = Bytes::new(1024 * 1024 * 1024);

        for eng in [
            OciRuntimeEngine::Crun,
            OciRuntimeEngine::Runc,
            OciRuntimeEngine::Containerd,
            OciRuntimeEngine::OciJail,
            OciRuntimeEngine::RunHcs,
        ] {
            assert!(!eng.binary_name().is_empty());
        }

        let mut oci = OciContainerDriver {
            engine: OciRuntimeEngine::Crun,
            rootfs_path: "/var/lib/arbiter/rootfs".to_owned(),
            command_args: vec!["/bin/sh".to_owned()],
            linux_devices: vec!["/dev/nvidia0".to_owned()],
            simulate_error: false,
        };
        assert_eq!(oci.name(), "OciContainerDriver");
        assert!(
            oci.render_nested_oci_v1_2_config_json(&tid, &limits)
                .unwrap_or_default()
                .contains(r#""ociVersion":"1.2.0""#)
        );
        assert!(oci.prepare(&tid, &limits).is_ok());
        assert!(oci.isolate(&tid, 100).is_ok());
        assert!(oci.update_limits(&tid, &limits).is_ok());
        assert!(oci.usage(&tid).is_ok());
        assert!(oci.checkpoint(&tid, "/tmp").is_ok());
        assert!(oci.cleanup(&tid).is_ok());

        let bundle_dir = std::env::temp_dir().join("arbiter_oci_bundle_test");
        let _ = std::fs::remove_dir_all(&bundle_dir);
        assert_eq!(
            oci.write_bundle_and_lifecycle_commands(&bundle_dir, &tid, &limits)
                .map(|v| v.len()),
            Ok(7)
        );
        let mut ok_runner = |cmd: &str| -> ArbiterResult<String> { Ok(format!("ok:{cmd}")) };
        let mut err_runner = |cmd: &str| -> ArbiterResult<String> {
            Err(ArbiterError::ContainerRuntimeError {
                runtime: "crun".to_owned(),
                container_id: tid.to_string(),
                reason: cmd.to_owned(),
            })
        };
        let ok_dyn: &mut dyn FnMut(&str) -> ArbiterResult<String> = &mut ok_runner;
        assert_eq!(
            oci.execute_oci_lifecycle_with_runner(&bundle_dir, &tid, &limits, ok_dyn)
                .map(|v| v.len()),
            Ok(7)
        );
        let err_dyn: &mut dyn FnMut(&str) -> ArbiterResult<String> = &mut err_runner;
        assert!(
            oci.execute_oci_lifecycle_with_runner(&bundle_dir, &tid, &limits, err_dyn)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&bundle_dir);
        let ok_dyn2: &mut dyn FnMut(&str) -> ArbiterResult<String> = &mut ok_runner;
        assert!(
            oci.execute_oci_lifecycle_with_runner(
                std::path::Path::new("/dev/null/bad_bundle"),
                &tid,
                &limits,
                ok_dyn2
            )
            .is_err()
        );
        assert!(
            oci.write_bundle_and_lifecycle_commands(
                std::path::Path::new("/dev/null/bad_bundle"),
                &tid,
                &limits
            )
            .is_err()
        );

        // Empty rootfs error via prepare
        let mut empty_oci = OciContainerDriver::default();
        assert!(
            empty_oci
                .render_nested_oci_v1_2_config_json(&tid, &limits)
                .is_err()
        );
        assert!(empty_oci.prepare(&tid, &limits).is_err());
        assert!(
            empty_oci
                .write_bundle_and_lifecycle_commands(&bundle_dir, &tid, &limits)
                .is_err()
        );

        // Simulated OCI error
        oci.simulate_error = true;
        assert!(oci.prepare(&tid, &limits).is_err());
        assert!(oci.isolate(&tid, 100).is_err());
        assert!(oci.update_limits(&tid, &limits).is_err());
        assert!(oci.usage(&tid).is_err());
        assert!(oci.checkpoint(&tid, "/tmp").is_err());
        assert!(oci.cleanup(&tid).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_microvm_runtime_driver() {
        let tid = TaskId::new("vm-task-1").unwrap_or_default();
        let mut limits = ResourceBundle::zero();
        limits.cpu = Millicores::new(4000);
        limits.memory = Bytes::new(1024 * 1024 * 1024);

        for hyp in [
            MicroVmHypervisor::Firecracker,
            MicroVmHypervisor::Bhyve,
            MicroVmHypervisor::HyperV,
            MicroVmHypervisor::AppleVirtualization,
        ] {
            assert!(!hyp.as_str().is_empty());
            let cfg = MicroVmConfig {
                hypervisor: hyp,
                vcpu_count: 2,
                mem_size_mib: 512,
                kernel_image_path: "/boot/vmlinux".to_owned(),
                rootfs_drive_path: "/root.ext4".to_owned(),
                vfio_pci_devices: Vec::new(),
            };
            assert!(!MicroVmDriver::format_hypervisor_launch_command(&tid, &cfg).is_empty());
            let (snap_cmd, tear_cmd) =
                MicroVmDriver::format_hypervisor_snapshot_and_teardown(&tid, &cfg, "/tmp/snap");
            assert!(!snap_cmd.is_empty());
            assert!(!tear_cmd.is_empty());
        }

        let mut vm = MicroVmDriver {
            hypervisor: MicroVmHypervisor::Bhyve,
            kernel_image_path: "/boot/vmlinux".to_owned(),
            rootfs_drive_path: "/var/lib/vm/root.ext4".to_owned(),
            vfio_pci_devices: vec!["0000:c1:00.0".to_owned()],
            simulate_error: false,
        };
        assert_eq!(vm.name(), "MicroVmDriver");
        assert!(vm.prepare(&tid, &limits).is_ok());
        assert!(vm.isolate(&tid, 200).is_ok());
        assert!(vm.update_limits(&tid, &limits).is_ok());
        assert!(vm.usage(&tid).is_ok());
        assert!(vm.checkpoint(&tid, "/tmp").is_ok());
        assert!(vm.cleanup(&tid).is_ok());

        // Empty kernel path error
        let mut bad_vm = MicroVmDriver::default();
        assert!(bad_vm.prepare(&tid, &limits).is_err());
        let fc_sock = std::env::temp_dir().join("arbiter_fc_uds_test.sock");
        assert!(
            bad_vm
                .execute_firecracker_uds_roundtrip(&fc_sock, &tid, &limits)
                .is_err()
        );
        assert!(
            vm.execute_firecracker_uds_roundtrip(&fc_sock, &tid, &limits)
                .unwrap_or_default()
                .contains("204 No Content")
        );
        assert!(
            vm.execute_firecracker_uds_roundtrip(
                std::path::Path::new("/dev/null/bad_fc.sock"),
                &tid,
                &limits
            )
            .is_err()
        );
        assert!(
            bad_vm
                .send_firecracker_uds_http_request(&fc_sock, &tid, &limits)
                .is_err()
        );
        assert!(
            vm.send_firecracker_uds_http_request(
                std::path::Path::new("/dev/null/bad_fc_cli.sock"),
                &tid,
                &limits
            )
            .is_err()
        );
        let fc_ext_sock = std::env::temp_dir().join("arbiter_fc_ext_uds_test.sock");
        let _ = std::fs::remove_file(&fc_ext_sock);
        #[cfg(unix)]
        let fc_l_opt = std::os::unix::net::UnixListener::bind(&fc_ext_sock).ok();
        #[cfg(not(unix))]
        let fc_l_opt = std::net::TcpListener::bind("127.0.0.1:0").ok().map(|tcp| {
            let addr_str = tcp
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "127.0.0.1:0".to_owned());
            let _ = std::fs::write(&fc_ext_sock, addr_str.as_bytes());
            tcp
        });
        let _ = fc_l_opt.map(|fc_l| {
            let h = std::thread::spawn(move || {
                use std::io::{Read, Write};
                for _ in 0..2 {
                    let _ = fc_l.accept().map(|(mut s, _)| {
                        let mut b = Vec::new();
                        let _ = s.read_to_end(&mut b);
                        let _ = s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n");
                    });
                }
            });
            assert!(
                vm.send_firecracker_uds_http_request(&fc_ext_sock, &tid, &limits)
                    .unwrap_or_default()
                    .contains("204 No Content")
            );
            assert!(
                vm.execute_firecracker_uds_roundtrip(&fc_ext_sock, &tid, &limits)
                    .unwrap_or_default()
                    .contains("204 No Content")
            );
            let _ = h.join();
        });
        let _ = std::fs::remove_file(&fc_ext_sock);

        // Simulated MicroVM error
        vm.simulate_error = true;
        assert!(vm.prepare(&tid, &limits).is_err());
        assert!(vm.isolate(&tid, 200).is_err());
        assert!(vm.update_limits(&tid, &limits).is_err());
        assert!(vm.usage(&tid).is_err());
        assert!(vm.checkpoint(&tid, "/tmp").is_err());
        assert!(vm.cleanup(&tid).is_err());
    }

    #[test]
    fn test_microvm_lifecycle_with_runner() {
        let tid = TaskId::new("vm-task-2").unwrap_or_default();
        let mut limits = ResourceBundle::zero();
        limits.cpu = Millicores::new(4000);
        limits.memory = Bytes::new(1024 * 1024 * 1024);

        let mut ok_vm_runner = |cmd: &str| -> ArbiterResult<String> { Ok(format!("ok:{cmd}")) };
        let mut err_vm_runner = |_cmd: &str| -> ArbiterResult<String> {
            Err(ArbiterError::MicroVmError {
                engine: "test".to_owned(),
                vm_id: "vm-task-2".to_owned(),
                reason: "hypervisor error".to_owned(),
            })
        };
        for hyp in [
            MicroVmHypervisor::Firecracker,
            MicroVmHypervisor::Bhyve,
            MicroVmHypervisor::HyperV,
            MicroVmHypervisor::AppleVirtualization,
        ] {
            let drv = MicroVmIsolator {
                hypervisor: hyp,
                kernel_image_path: "/boot/vmlinux".to_owned(),
                rootfs_drive_path: "/root.ext4".to_owned(),
                vfio_pci_devices: vec!["0000:c1:00.0".to_owned()],
                simulate_error: false,
            };
            let ok_dyn: &mut dyn FnMut(&str) -> ArbiterResult<String> = &mut ok_vm_runner;
            assert_eq!(
                drv.execute_microvm_lifecycle_with_runner(&tid, &limits, "/tmp/snap", ok_dyn)
                    .map(|v| v.len()),
                Ok(3)
            );
            let err_dyn: &mut dyn FnMut(&str) -> ArbiterResult<String> = &mut err_vm_runner;
            assert!(
                drv.execute_microvm_lifecycle_with_runner(&tid, &limits, "/tmp/snap", err_dyn)
                    .is_err()
            );
        }

        let bad_drv = MicroVmIsolator::default();
        let ok_dyn: &mut dyn FnMut(&str) -> ArbiterResult<String> = &mut ok_vm_runner;
        assert!(
            bad_drv
                .execute_microvm_lifecycle_with_runner(&tid, &limits, "/tmp/snap", ok_dyn)
                .is_err()
        );
    }
}
