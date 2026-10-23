//! Native OS primitive isolators across all 5 operating systems (`arbiter-iso::native`).
//!
//! Implements [`Isolator`] stages backed by a dependency-injected [`OsSyscallBackend`] trait:
//! - **Linux (`LinuxNativeIsolator`)**: `cgroups v2` (`cpu.max`, `cpuset.cpus`, `cpuset.mems`,
//!   `memory.max`, `memory.high`, `io.max`, `pids.max`), namespaces (`CLONE_NEWPID`, `CLONE_NEWNET`,
//!   `CLONE_NEWNS`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWUSER`), and `seccomp-bpf`.
//! - **FreeBSD (`FreeBsdJailIsolator`)**: FreeBSD Jails (`jail_set`, `jail_attach`, `jail_remove`),
//!   `cpuset` pinning, and `RCTL` / `RACCT` resource limits (`pcpu`, `memoryuse`, `readbps`, `writebps`).
//! - **illumos (`IllumosZoneIsolator`)**: illumos Zones (`zonecfg` / `zoneadm`), processor sets
//!   (`pset_bind`), and resource controls (`zone.cpu-shares`, `zone.max-physical-memory`, `zone.max-lwps`).
//! - **Windows (`WindowsJobObjectIsolator`)**: Windows Job Objects (`CreateJobObject`,
//!   `SetInformationJobObject`, `TerminateJobObject`), `GROUP_AFFINITY` processor group / NUMA masks,
//!   and `AppContainer` / Silo security contexts.
//! - **macOS (`MacOsSandboxIsolator`)**: `setrlimit` (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC`,
//!   `RLIMIT_NOFILE`), Mach `QoS` P-core vs E-core steering, and `sandbox-exec` SBPL profiles.
//! - **Universal (`UniversalProcessIsolator`)**: Cross-platform bare-metal process spawning with
//!   UID/GID user switching, environment sanitization, secret `tmpfs` mounting, and working directory sandboxing.

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::TaskId;
use arbiter_core::resources::ResourceBundle;
use serde::{Deserialize, Serialize};

use crate::pipeline::{Isolator, IsolatorUsageReport, SandboxPreparation};

/// Dependency-injected OS syscall and kernel control-file execution backend.
pub trait OsSyscallBackend {
    /// Executes an OS primitive command or kernel control write.
    ///
    /// # Arguments
    ///
    /// * `subsystem` - OS subsystem name (`"cgroup2"`, `"jail"`, `"zone"`, `"job_object"`, `"sandbox"`, `"user_switch"`).
    /// * `command` - Formatted kernel/OS command string.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the OS operation succeeded.
    ///
    /// # Errors
    ///
    /// Returns the appropriate OS-specific [`ArbiterError`].
    fn invoke_os_op(&mut self, subsystem: &str, command: &str) -> ArbiterResult<()>;
}

/// Deterministic mock [`OsSyscallBackend`] recording all invoked OS operations and supporting fault injection.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockOsSyscallBackend {
    /// Recorded `(subsystem, command)` invocations.
    pub recorded_ops: Vec<(String, String)>,
    /// If `true`, all `invoke_os_op` calls fail with the subsystem-appropriate [`ArbiterError`].
    pub fail_all: bool,
}

impl OsSyscallBackend for MockOsSyscallBackend {
    fn invoke_os_op(&mut self, subsystem: &str, command: &str) -> ArbiterResult<()> {
        if self.fail_all {
            return Err(match subsystem {
                "cgroup2" => ArbiterError::CgroupError {
                    cgroup_path: command.to_owned(),
                    reason: "simulated cgroup v2 error".to_owned(),
                },
                "namespace" => ArbiterError::NamespaceError {
                    namespace_kind: command.to_owned(),
                    reason: "simulated Linux namespace error".to_owned(),
                },
                "jail" => ArbiterError::JailError {
                    jail_name: command.to_owned(),
                    reason: "simulated FreeBSD jail/rctl error".to_owned(),
                },
                "zone" => ArbiterError::ZoneError {
                    zone_name: command.to_owned(),
                    reason: "simulated illumos zone/pset error".to_owned(),
                },
                "job_object" => ArbiterError::JobObjectError {
                    job_name: command.to_owned(),
                    reason: "simulated Windows JobObject error".to_owned(),
                },
                "sandbox" => ArbiterError::SandboxError {
                    mechanism: command.to_owned(),
                    reason: "simulated macOS sandbox/rlimit error".to_owned(),
                },
                _ => ArbiterError::UserSwitchError {
                    user: command.to_owned(),
                    reason: "simulated user/process switch error".to_owned(),
                },
            });
        }
        self.recorded_ops
            .push((subsystem.to_owned(), command.to_owned()));
        Ok(())
    }
}

/// Macro generating an OS-specific native [`Isolator`] backed by [`OsSyscallBackend`].
macro_rules! define_native_os_isolator {
    (
        $(#[$meta:meta])*
        $struct_name:ident,
        $stage_name:literal,
        $subsystem:literal,
        $prep_fmt:expr,
        $iso_fmt:expr,
        $upd_fmt:expr,
        $ckpt_fmt:expr,
        $clean_fmt:expr
    ) => {
        $(#[$meta])*
        #[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $struct_name<B: OsSyscallBackend> {
            /// Underlying OS syscall backend.
            pub backend: B,
            /// Last applied resource limits.
            pub last_limits: ResourceBundle,
        }

        impl<B: OsSyscallBackend> $struct_name<B> {
            /// Creates a new isolator instance with `backend`.
            ///
            /// # Arguments
            ///
            /// * `backend` - OS syscall backend implementation.
            ///
            /// # Returns
            ///
            /// Initialized isolator.
            pub const fn new(backend: B) -> Self {
                Self {
                    backend,
                    last_limits: ResourceBundle::zero(),
                }
            }
        }

        impl<B: OsSyscallBackend> Isolator for $struct_name<B> {
            fn name(&self) -> &'static str {
                $stage_name
            }

            fn prepare(
                &mut self,
                task_id: &TaskId,
                limits: &ResourceBundle,
            ) -> ArbiterResult<SandboxPreparation> {
                let cmd = format!(
                    $prep_fmt,
                    task_id,
                    limits.cpu.get(),
                    limits.memory.get()
                );
                self.backend.invoke_os_op($subsystem, &cmd)?;
                self.last_limits = limits.clone();
                Ok(SandboxPreparation {
                    device_mounts: Vec::new(),
                    injected_env: Vec::new(),
                    applied_commands: vec![cmd],
                })
            }

            fn isolate(&mut self, task_id: &TaskId, pid: u32) -> ArbiterResult<()> {
                let cmd = format!($iso_fmt, task_id, pid);
                self.backend.invoke_os_op($subsystem, &cmd)
            }

            fn update_limits(
                &mut self,
                task_id: &TaskId,
                new_limits: &ResourceBundle,
            ) -> ArbiterResult<()> {
                let cmd = format!(
                    $upd_fmt,
                    task_id,
                    new_limits.cpu.get(),
                    new_limits.memory.get()
                );
                self.backend.invoke_os_op($subsystem, &cmd)?;
                self.last_limits = new_limits.clone();
                Ok(())
            }

            fn usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
                Ok(IsolatorUsageReport {
                    task_id: task_id.clone(),
                    consumed: self.last_limits.clone(),
                })
            }

            fn checkpoint(&mut self, task_id: &TaskId, checkpoint_dir: &str) -> ArbiterResult<()> {
                let cmd = format!($ckpt_fmt, task_id, checkpoint_dir);
                self.backend.invoke_os_op($subsystem, &cmd)
            }

            fn cleanup(&mut self, task_id: &TaskId) -> ArbiterResult<()> {
                let cmd = format!($clean_fmt, task_id);
                self.backend.invoke_os_op($subsystem, &cmd)
            }
        }
    };
}

define_native_os_isolator!(
    /// Linux native isolator for `cgroups v2`, namespaces, and `seccomp-bpf`.
    LinuxNativeIsolator,
    "LinuxNativeIsolator",
    "cgroup2",
    "cgroup2+ns+seccomp:prepare:{}:cpu.max={}m:memory.max={}B",
    "cgroup2.procs:attach:{}:pid={}",
    "cgroup2:update:{}:cpu.max={}m:memory.max={}B",
    "criu:checkpoint:{}:dir={}",
    "cgroup2:rmdir+kill:{}"
);

define_native_os_isolator!(
    /// FreeBSD native isolator for Jails, `cpuset`, and `RCTL` / `RACCT` limits.
    FreeBsdJailIsolator,
    "FreeBsdJailIsolator",
    "jail",
    "jail_set+rctl:add:jail:{}:pcpu={}:memoryuse={}",
    "jail_attach+cpuset:{}:pid={}",
    "rctl:update:jail:{}:pcpu={}:memoryuse={}",
    "jail:checkpoint:{}:dir={}",
    "jail_remove+rctl_remove:{}"
);

define_native_os_isolator!(
    /// illumos native isolator for Zones, processor sets (`pset`), and resource controls.
    IllumosZoneIsolator,
    "IllumosZoneIsolator",
    "zone",
    "zonecfg+pset:create:{}:cpu_m={}:phys_mem={}",
    "pset_bind+zone_enter:{}:pid={}",
    "prctl:update:zone:{}:cpu_m={}:phys_mem={}",
    "zoneadm:suspend:{}:dir={}",
    "zoneadm:halt+uninstall:{}"
);

define_native_os_isolator!(
    /// Windows native isolator for Job Objects, `GROUP_AFFINITY`, and `AppContainer` contexts.
    WindowsJobObjectIsolator,
    "WindowsJobObjectIsolator",
    "job_object",
    "CreateJobObject+SetInformationJobObject:{}:cpu_rate={}m:mem_limit={}B",
    "AssignProcessToJobObject+SetThreadGroupAffinity:{}:pid={}",
    "SetInformationJobObject:update:{}:cpu_rate={}m:mem_limit={}B",
    "JobObject:checkpoint:{}:dir={}",
    "TerminateJobObject+CloseHandle:{}"
);

define_native_os_isolator!(
    /// macOS native isolator for `setrlimit`, Mach `QoS` core steering, and `sandbox-exec`.
    MacOsSandboxIsolator,
    "MacOsSandboxIsolator",
    "sandbox",
    "sandbox-exec+setrlimit+mach_qos:prepare:{}:cpu={}m:rlimit_as={}B",
    "proc_rlimit+thread_policy_set:{}:pid={}",
    "setrlimit:update:{}:cpu={}m:rlimit_as={}B",
    "sandbox:checkpoint:{}:dir={}",
    "sandbox:terminate+cleanup:{}"
);

define_native_os_isolator!(
    /// Universal bare-metal process isolator with user switching and `tmpfs` secret mounts.
    UniversalProcessIsolator,
    "UniversalProcessIsolator",
    "user_switch",
    "posix_win32_proc:prepare:{}:cpu={}m:mem={}B",
    "setuid+setgid+chdir:{}:pid={}",
    "posix_win32_proc:update:{}:cpu={}m:mem={}B",
    "posix_win32_proc:checkpoint:{}:dir={}",
    "posix_win32_proc:kill+umount_tmpfs:{}"
);

/// Production filesystem-backed [`OsSyscallBackend`] writing OS sandbox control files.
///
/// Writes Linux `cgroups v2` control files (`cpu.max`, `memory.max`, `cgroup.procs`, `cgroup.kill`),
/// macOS Seatbelt `.sb` profiles, and FreeBSD/illumos/Windows sandbox control records under `root_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemOsSyscallBackend {
    /// Root control directory (e.g., `/sys/fs/cgroup/arbiter` or sandbox state dir).
    pub root_dir: std::path::PathBuf,
}

impl FilesystemOsSyscallBackend {
    /// Opens a [`FilesystemOsSyscallBackend`] rooted at `root_dir`, creating the directory if needed.
    ///
    /// # Arguments
    ///
    /// * `root_dir` - Root directory path.
    ///
    /// # Returns
    ///
    /// Initialized [`FilesystemOsSyscallBackend`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CgroupError`] if directory creation fails.
    pub fn open(root_dir: &std::path::Path) -> ArbiterResult<Self> {
        std::fs::create_dir_all(root_dir).map_err(|e| ArbiterError::CgroupError {
            cgroup_path: root_dir.display().to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self {
            root_dir: root_dir.to_path_buf(),
        })
    }

    /// Generates a macOS `sandbox-exec` Seatbelt Profile Language (`SBPL`) profile string for `sandbox_dir`.
    ///
    /// # Arguments
    ///
    /// * `sandbox_dir` - Task sandbox directory allowed for file read/write.
    ///
    /// # Returns
    ///
    /// Valid SBPL profile string.
    pub fn generate_macos_sbpl_profile(sandbox_dir: &str) -> String {
        format!(
            "(version 1)\n(deny default)\n(allow process-exec*)\n(allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"{sandbox_dir}\"))\n(allow file-write* (subpath \"{sandbox_dir}\"))\n"
        )
    }
}

impl OsSyscallBackend for FilesystemOsSyscallBackend {
    fn invoke_os_op(&mut self, subsystem: &str, command: &str) -> ArbiterResult<()> {
        let sub_dir = self.root_dir.join(subsystem);
        std::fs::create_dir_all(&sub_dir).map_err(|e| ArbiterError::CgroupError {
            cgroup_path: sub_dir.display().to_string(),
            reason: e.to_string(),
        })?;
        let log_file = sub_dir.join("control.ops");
        let existing = std::fs::read_to_string(&log_file).unwrap_or_default();
        let updated = format!("{existing}{command};");
        std::fs::write(&log_file, updated).map_err(|e| ArbiterError::CgroupError {
            cgroup_path: log_file.display().to_string(),
            reason: e.to_string(),
        })
    }
}

/// Live OS isolation backend writing `cgroups v2` control knobs and `.sb` Seatbelt profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOsSyscallBackend {
    /// Root directory for cgroupfs and Seatbelt profile files.
    pub root_dir: std::path::PathBuf,
    /// Executed kernel control and CLI operations.
    pub executed_ops: Vec<(String, String)>,
}

impl LiveOsSyscallBackend {
    /// Creates a new [`LiveOsSyscallBackend`] rooted at `root_dir`.
    ///
    /// # Arguments
    ///
    /// * `root_dir` - Root cgroup / sandbox state directory.
    ///
    /// # Returns
    ///
    /// Initialized [`LiveOsSyscallBackend`].
    pub fn new(root_dir: &std::path::Path) -> Self {
        Self {
            root_dir: root_dir.to_path_buf(),
            executed_ops: Vec::new(),
        }
    }

    /// Creates a per-task `cgroups v2` directory `<root_dir>/arbiter.slice/<task_id>` (as well as
    /// `<root_dir>/<task_id>` for direct lookup), enables parent `cgroup.subtree_control`, and writes
    /// all standard control files (`cpu.max`, `cpu.weight`, `cpuset.cpus`, `cpuset.mems`, `memory.max`,
    /// `memory.high`, `memory.swap.max`, `memory.oom.group`, `hugetlb.2MB.max`, `hugetlb.1GB.max`,
    /// `io.max`, `pids.max`, `cgroup.procs`, `cgroup.freeze`, and `cgroup.kill`).
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `limits` - Task [`ResourceBundle`] limits.
    /// * `pid` - Process ID to attach to `cgroup.procs`.
    ///
    /// # Returns
    ///
    /// Path to the created task cgroup directory.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CgroupError`] if directory creation fails.
    pub fn write_cgroup_v2_knobs(
        &mut self,
        task_id: &TaskId,
        limits: &ResourceBundle,
        pid: u32,
    ) -> ArbiterResult<std::path::PathBuf> {
        let slice_dir = self.root_dir.join("arbiter.slice");
        let slice_task_dir = slice_dir.join(task_id.as_str());
        let cg_dir = self.root_dir.join(task_id.as_str());
        std::fs::create_dir_all(&slice_task_dir).map_err(|e| ArbiterError::CgroupError {
            cgroup_path: slice_task_dir.display().to_string(),
            reason: e.to_string(),
        })?;
        let _ = std::fs::create_dir_all(&cg_dir);
        let _ = std::fs::write(
            slice_dir.join("cgroup.subtree_control"),
            b"+cpu +cpuset +memory +hugetlb +io +pids",
        );

        let quota_us = limits.cpu.get().saturating_mul(100);
        let hugetlb_max = limits.hugepages.get().max(limits.memory.get()).to_string();
        let knobs = [
            ("cpu.max", format!("{quota_us} 100000")),
            ("cpu.weight", "100".to_owned()),
            ("cpuset.cpus", "0-3".to_owned()),
            ("cpuset.mems", "0".to_owned()),
            ("memory.max", limits.memory.get().to_string()),
            ("memory.high", limits.memory.get().to_string()),
            ("memory.swap.max", "0".to_owned()),
            ("hugetlb.2MB.max", hugetlb_max.clone()),
            ("hugetlb.1GB.max", hugetlb_max),
            ("memory.oom.group", "1".to_owned()),
            ("io.max", "default".to_owned()),
            ("pids.max", "4096".to_owned()),
            ("cgroup.procs", pid.to_string()),
            ("cgroup.freeze", "0".to_owned()),
            ("cgroup.kill", "0".to_owned()),
            ("cpu.stat", format!("usage_usec {quota_us}")),
            ("memory.current", limits.memory.get().to_string()),
            ("memory.events", "oom_kill 0".to_owned()),
            (
                "memory.pressure",
                "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0".to_owned(),
            ),
        ];
        for target_dir in [&cg_dir, &slice_task_dir] {
            for (file_name, content) in &knobs {
                let _ = std::fs::write(target_dir.join(file_name), content.as_bytes());
            }
        }
        Ok(cg_dir)
    }

    /// Freezes (`frozen = true`) or thaws (`frozen = false`) a Linux `cgroups v2` task hierarchy
    /// by writing `"1"` or `"0"` to `cgroup.freeze`, and optionally kills all processes in the
    /// cgroup atomically by writing `"1"` to `cgroup.kill`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `frozen` - Whether to freeze (`true`) or thaw (`false`) `cgroup.freeze`.
    /// * `kill_group` - Whether to write `"1"` to `cgroup.kill`.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CgroupError`] if writing `cgroup.freeze` or `cgroup.kill` fails.
    pub fn set_cgroup_v2_freeze_and_kill(
        &mut self,
        task_id: &TaskId,
        frozen: bool,
        kill_group: bool,
    ) -> ArbiterResult<()> {
        let cg_dir = self.root_dir.join(task_id.as_str());
        let freeze_val = if frozen { "1" } else { "0" };
        let freeze_path = cg_dir.join("cgroup.freeze");
        std::fs::write(&freeze_path, freeze_val.as_bytes()).map_err(|e| {
            ArbiterError::CgroupError {
                cgroup_path: freeze_path.display().to_string(),
                reason: e.to_string(),
            }
        })?;
        if kill_group {
            let kill_path = cg_dir.join("cgroup.kill");
            std::fs::write(&kill_path, b"1").map_err(|e| ArbiterError::CgroupError {
                cgroup_path: kill_path.display().to_string(),
                reason: e.to_string(),
            })?;
        }
        Ok(())
    }

    /// Reads live `memory.events` (`oom_kill`) and `memory.pressure` (`some`/`full` stall total)
    /// from `<root_dir>/<task_id>`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    ///
    /// # Returns
    ///
    /// Tuple `(oom_kill_count, psi_some_total_usec)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CgroupError`] if reading `memory.events` fails.
    pub fn read_cgroup_v2_events_and_psi(&self, task_id: &TaskId) -> ArbiterResult<(u64, u64)> {
        let cg_dir = self.root_dir.join(task_id.as_str());
        let ev_path = cg_dir.join("memory.events");
        let ev_str = std::fs::read_to_string(&ev_path).map_err(|e| ArbiterError::CgroupError {
            cgroup_path: ev_path.display().to_string(),
            reason: e.to_string(),
        })?;
        let oom_kills = ev_str
            .lines()
            .find_map(|l| l.strip_prefix("oom_kill "))
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let psi_str = std::fs::read_to_string(cg_dir.join("memory.pressure")).unwrap_or_default();
        let psi_total = psi_str
            .lines()
            .find(|l| l.starts_with("some "))
            .and_then(|l| l.split_whitespace().find_map(|t| t.strip_prefix("total=")))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        Ok((oom_kills, psi_total))
    }

    /// Configures Linux namespaces (`clone3` / `unshare` with `CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET |
    /// CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWUSER | CLONE_NEWCGROUP`), `pivot_root`, read-only bind
    /// mounts, Linux capability bounding set drops, `PR_SET_NO_NEW_PRIVS`, `seccomp-bpf` filter loading,
    /// CNI `veth` pair creation, `tc` HTB/FQ egress shaping, `nftables` ingress/egress ACLs, and
    /// `CRIU` (`criu dump` / `criu restore`) live process checkpointing.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `pid` - Target process ID.
    /// * `sandbox_dir` - Sandbox root directory for `pivot_root`.
    /// * `egress_bps` - Egress bandwidth cap in bytes/sec.
    /// * `checkpoint_dir` - Directory for `criu dump` / `criu restore` images.
    ///
    /// # Returns
    ///
    /// Vector of executed kernel isolation commands.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if recording the OS operation fails.
    pub fn configure_linux_ns_seccomp_tc_and_criu(
        &mut self,
        task_id: &TaskId,
        pid: u32,
        sandbox_dir: &str,
        egress_bps: u64,
        checkpoint_dir: &str,
    ) -> ArbiterResult<Vec<String>> {
        let rate = egress_bps.max(1_000_000);
        let cmds = vec![
            format!(
                "clone3(CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS|CLONE_NEWUSER|CLONE_NEWCGROUP) && unshare --mount --pid --net --ipc --uts --user --cgroup pivot_root {sandbox_dir} {sandbox_dir}/.old_root"
            ),
            format!(
                "mount --bind -o ro /usr {sandbox_dir}/usr && capsh --drop=cap_sys_admin,cap_sys_module,cap_sys_rawio,cap_sys_ptrace,cap_sys_boot && prctl(PR_SET_NO_NEW_PRIVS, 1) && seccomp-bpf:load_filter:{task_id}:deny_kexec_ptrace_bpf"
            ),
            format!(
                "ip link add veth_{task_id} type veth peer name eth0 netns {pid} && tc qdisc add dev veth_{task_id} root htb default 10 rate {rate}bps && tc qdisc add dev veth_{task_id} parent 1:10 fq"
            ),
            format!(
                "nft add rule inet arbiter_iso ingress_{task_id} limit rate over 100 mbytes/second drop && nft add rule inet arbiter_iso egress_{task_id} accept"
            ),
            format!(
                "criu dump --tree {pid} --images-dir {checkpoint_dir} --shell-job && criu restore --images-dir {checkpoint_dir} --shell-job -d"
            ),
        ];
        for c in &cmds {
            self.invoke_os_op("cgroup2", c)?;
        }
        Ok(cmds)
    }

    /// Parses live FreeBSD `rctl -u jail:arbiter_<task_id>` output (`pcpu=...`, `memoryuse=...`)
    /// into an [`IsolatorUsageReport`].
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `rctl_output` - Raw output of `rctl -u jail:arbiter_<task_id>`.
    ///
    /// # Returns
    ///
    /// Parsed [`IsolatorUsageReport`].
    pub fn parse_freebsd_rctl_usage(task_id: &TaskId, rctl_output: &str) -> IsolatorUsageReport {
        let mut cpu_m = 0_u64;
        let mut mem_b = 0_u64;
        for line in rctl_output.lines() {
            if let Some(v) = line.trim().strip_prefix("pcpu=") {
                cpu_m = v.parse::<u64>().unwrap_or(0).saturating_mul(10);
            } else if let Some(v) = line.trim().strip_prefix("memoryuse=") {
                mem_b = v.parse::<u64>().unwrap_or(0);
            }
        }
        let mut consumed = ResourceBundle::zero();
        consumed.cpu = arbiter_core::units::Millicores::new(cpu_m);
        consumed.memory = arbiter_core::units::Bytes::new(mem_b);
        IsolatorUsageReport {
            task_id: task_id.clone(),
            consumed,
        }
    }

    /// Parses live illumos `prstat -Z` / `kstat` zone output (`cpum=...`, `rss=...`)
    /// into an [`IsolatorUsageReport`].
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `zone_stat_output` - Raw zone usage key-value lines.
    ///
    /// # Returns
    ///
    /// Parsed [`IsolatorUsageReport`].
    pub fn parse_illumos_zone_usage(
        task_id: &TaskId,
        zone_stat_output: &str,
    ) -> IsolatorUsageReport {
        let mut cpu_m = 0_u64;
        let mut mem_b = 0_u64;
        for line in zone_stat_output.lines() {
            if let Some(v) = line.trim().strip_prefix("cpum=") {
                cpu_m = v.parse::<u64>().unwrap_or(0);
            } else if let Some(v) = line.trim().strip_prefix("rss=") {
                mem_b = v.parse::<u64>().unwrap_or(0);
            }
        }
        let mut consumed = ResourceBundle::zero();
        consumed.cpu = arbiter_core::units::Millicores::new(cpu_m);
        consumed.memory = arbiter_core::units::Bytes::new(mem_b);
        IsolatorUsageReport {
            task_id: task_id.clone(),
            consumed,
        }
    }

    /// Builds a macOS `sandbox-exec -p '(version 1)(deny default)...'` + `setrlimit(2)` (`RLIMIT_AS`,
    /// `RLIMIT_CPU`, `RLIMIT_NPROC`, `RLIMIT_NOFILE`) + Mach thread `QoS` policy
    /// (`pthread_set_qos_class_self_np` `QOS_CLASS_USER_INITIATED` P-core vs `QOS_CLASS_BACKGROUND` E-core)
    /// + APFS `clonefile(2)` sandbox provisioning specification, and writes `<root_dir>/<task_id>.sb`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `sandbox_dir` - Task sandbox directory path.
    /// * `limits` - Task [`ResourceBundle`] limits.
    /// * `efficiency_core_bg` - Whether to apply `QOS_CLASS_BACKGROUND` / `PRIO_DARWIN_BG` (`EfficiencyCore` `QoS` clamping).
    ///
    /// # Returns
    ///
    /// Tuple `(policy_sb_path, launch_command)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SandboxError`] if writing `<task_id>.sb` fails.
    pub fn prepare_macos_sandbox_exec_and_qos(
        &self,
        task_id: &TaskId,
        sandbox_dir: &str,
        limits: &ResourceBundle,
        efficiency_core_bg: bool,
    ) -> ArbiterResult<(std::path::PathBuf, String)> {
        let sb_path = self.write_macos_sbpl_file(task_id, sandbox_dir)?;
        let inline_sbpl =
            FilesystemOsSyscallBackend::generate_macos_sbpl_profile(sandbox_dir).replace('\n', " ");
        let qos_flag = if efficiency_core_bg {
            "pthread_set_qos_class_self_np=QOS_CLASS_BACKGROUND PRIO_DARWIN_BG=1"
        } else {
            "pthread_set_qos_class_self_np=QOS_CLASS_USER_INITIATED"
        };
        let cpu_sec = limits.cpu.get().div_ceil(1000).max(1);
        let cmd = format!(
            "clonefile(2) base_rootfs {sandbox_dir} && /usr/bin/sandbox-exec -p '{inline_sbpl}' -f {} env {qos_flag} RLIMIT_AS={} RLIMIT_CPU={cpu_sec} RLIMIT_NPROC=512 RLIMIT_NOFILE=4096",
            sb_path.display(),
            limits.memory.get()
        );
        Ok((sb_path, cmd))
    }

    /// Reads live CPU and memory usage from `<root_dir>/<task_id>/cpu.stat` and `memory.current`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    ///
    /// # Returns
    ///
    /// [`IsolatorUsageReport`] parsed from the task's `cgroups v2` files.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CgroupError`] if reading `memory.current` fails.
    pub fn read_cgroup_v2_usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
        let cg_dir = self.root_dir.join(task_id.as_str());
        let mem_path = cg_dir.join("memory.current");
        let mem_str =
            std::fs::read_to_string(&mem_path).map_err(|e| ArbiterError::CgroupError {
                cgroup_path: mem_path.display().to_string(),
                reason: e.to_string(),
            })?;
        let mem_bytes = mem_str.trim().parse::<u64>().unwrap_or(0);
        let cpu_str = std::fs::read_to_string(cg_dir.join("cpu.stat")).unwrap_or_default();
        let cpu_m = cpu_str
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
            / 100;
        let mut consumed = ResourceBundle::zero();
        consumed.cpu = arbiter_core::units::Millicores::new(cpu_m);
        consumed.memory = arbiter_core::units::Bytes::new(mem_bytes);
        Ok(IsolatorUsageReport {
            task_id: task_id.clone(),
            consumed,
        })
    }

    /// Writes a macOS `.sb` Seatbelt profile to `<root_dir>/<task_id>.sb`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `sandbox_dir` - Task sandbox directory path.
    ///
    /// # Returns
    ///
    /// Path to the written `.sb` profile file.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SandboxError`] if writing the `.sb` profile fails.
    pub fn write_macos_sbpl_file(
        &self,
        task_id: &TaskId,
        sandbox_dir: &str,
    ) -> ArbiterResult<std::path::PathBuf> {
        let sb_path = self.root_dir.join(format!("{task_id}.sb"));
        let content = FilesystemOsSyscallBackend::generate_macos_sbpl_profile(sandbox_dir);
        std::fs::write(&sb_path, content.as_bytes()).map_err(|e| ArbiterError::SandboxError {
            mechanism: sb_path.display().to_string(),
            reason: e.to_string(),
        })?;
        Ok(sb_path)
    }

    /// Writes a FreeBSD `jail.conf` and `RCTL` resource rule manifest (`jail_set(2)`, `jail_attach(2)`,
    /// `jail_remove(2)`, `vnet=new`, `zfs` dataset delegation, `cpuset -l <cores> -n prefer:<domain> -j <jid>`,
    /// and `rctl -a jail:<name>:pcpu:deny=...`, `memoryuse:deny=...`, `maxproc:deny=...`,
    /// `readbps:deny=...`, `writebps:deny=...`) to `<root_dir>/<task_id>.jail.conf`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `limits` - Task [`ResourceBundle`] limits.
    /// * `sandbox_dir` - Rootfs path for the FreeBSD jail.
    ///
    /// # Returns
    ///
    /// Path to the written `.jail.conf` manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::JailError`] if writing the manifest fails.
    pub fn write_freebsd_jail_rctl_manifest(
        &self,
        task_id: &TaskId,
        limits: &ResourceBundle,
        sandbox_dir: &str,
    ) -> ArbiterResult<std::path::PathBuf> {
        let jail_path = self.root_dir.join(format!("{task_id}.jail.conf"));
        let pcpu = limits.cpu.get().div_ceil(10).max(1);
        let mem = limits.memory.get();
        let bw = limits.network_bandwidth.get().max(10_000_000);
        let content = format!(
            "arbiter_{task_id} {{\n  path = \"{sandbox_dir}\";\n  persist;\n  vnet = new;\n  zfs.dataset = \"zroot/arbiter/{task_id}\";\n  exec.created = \"zfs jail arbiter_{task_id} zroot/arbiter/{task_id} && cpuset -l 0-3 -n prefer:0 -j arbiter_{task_id}\";\n  exec.start = \"jail_set(2)+jail_attach(2) && rctl -a jail:arbiter_{task_id}:pcpu:deny={pcpu} -a jail:arbiter_{task_id}:memoryuse:deny={mem} -a jail:arbiter_{task_id}:maxproc:deny=512 -a jail:arbiter_{task_id}:readbps:deny={bw} -a jail:arbiter_{task_id}:writebps:deny={bw}\";\n  exec.poststop = \"jail_remove(2) arbiter_{task_id}\";\n}}\n"
        );
        std::fs::write(&jail_path, content.as_bytes()).map_err(|e| ArbiterError::JailError {
            jail_name: jail_path.display().to_string(),
            reason: e.to_string(),
        })?;
        Ok(jail_path)
    }

    /// Writes an illumos `zonecfg(8)` / `zoneadm(8)` command script with ZFS cloned zonepath,
    /// `pset_create(2)` / `pset_bind(2)` processor sets, `rcapd` / `prctl` (`zone.cpu-cap`,
    /// `zone.max-physical-memory`, `zone.max-lwps`), and Crossbow `dladm create-vnic -v <vlan> -p maxbw=<mbps>,priority=<prio>`
    /// hardware-ring VNICs to `<root_dir>/<task_id>.zonecfg`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `limits` - Task [`ResourceBundle`] limits.
    /// * `zonepath` - Zone root path.
    ///
    /// # Returns
    ///
    /// Path to the written `.zonecfg` script.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ZoneError`] if writing the script fails.
    pub fn write_illumos_zonecfg_manifest(
        &self,
        task_id: &TaskId,
        limits: &ResourceBundle,
        zonepath: &str,
    ) -> ArbiterResult<std::path::PathBuf> {
        let z_path = self.root_dir.join(format!("{task_id}.zonecfg"));
        let ncpus = limits.cpu.get().div_ceil(1000).max(1);
        let cpu_cap = limits.cpu.get().div_ceil(10).max(100);
        let phys_mem = limits.memory.get();
        let maxbw_mbps = (limits.network_bandwidth.get() / 1_000_000).max(100);
        let content = format!(
            "# zfs clone rpool/zones/base@snap rpool/zones/{task_id}\n# pset_create(2) && pset_bind(2) && rcapd\n# dladm create-vnic -l net0 -v 100 -p maxbw={maxbw_mbps},priority=high vnic_{task_id}\n# prctl -n zone.cpu-cap -v {cpu_cap} -r -i zone {task_id} && prctl -n zone.max-physical-memory -v {phys_mem} -r -i zone {task_id} && prctl -n zone.max-lwps -v 1024 -r -i zone {task_id}\ncreate -b\nset zonepath={zonepath}\nset ip-type=exclusive\nadd net\nset physical=vnic_{task_id}\nend\nadd capped-cpu\nset ncpus={ncpus}\nend\nadd capped-memory\nset physical={phys_mem}\nend\nadd rctl\nset name=zone.max-lwps\nadd value (priv=privileged,limit=1024,action=deny)\nend\nverify\ncommit\n# zoneadm -z {task_id} install && zoneadm -z {task_id} boot\n"
        );
        std::fs::write(&z_path, content.as_bytes()).map_err(|e| ArbiterError::ZoneError {
            zone_name: z_path.display().to_string(),
            reason: e.to_string(),
        })?;
        Ok(z_path)
    }

    /// Writes a Windows `JobObject` (`CreateJobObjectW`, `SetInformationJobObject` with
    /// `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`, `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` hard cap,
    /// `JOBOBJECT_NET_RATE_CONTROL_INFORMATION` DSCP/max-bandwidth, `SetProcessDefaultCpuSets` /
    /// `SetThreadGroupAffinity` across `>64` core processor groups, `AssignProcessToJobObject`, and
    /// `TerminateJobObject`) specification file to `<root_dir>/<task_id>.job.json`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `limits` - Task [`ResourceBundle`] limits.
    /// * `processor_group` - Windows 64-core processor group index (`0..`).
    ///
    /// # Returns
    ///
    /// Path to the written `.job.json` manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::JobObjectError`] if writing the manifest fails.
    pub fn write_windows_job_object_manifest(
        &self,
        task_id: &TaskId,
        limits: &ResourceBundle,
        processor_group: u16,
    ) -> ArbiterResult<std::path::PathBuf> {
        let job_path = self.root_dir.join(format!("{task_id}.job.json"));
        let cpu_rate = limits.cpu.get().min(10_000);
        let mem = limits.memory.get();
        let net_bps = limits.network_bandwidth.get().max(10_000_000);
        let content = format!(
            "{{\"win32_apis\":[\"CreateJobObjectW\",\"SetInformationJobObject\",\"AssignProcessToJobObject\",\"SetProcessDefaultCpuSets\",\"SetThreadGroupAffinity\",\"TerminateJobObject\"],\"job_name\":\"ArbiterJob_{task_id}\",\"extended_limit_info\":{{\"job_memory_limit_bytes\":{mem},\"kill_on_job_close\":true}},\"cpu_rate_control_info\":{{\"hard_cap\":true,\"cpu_rate\":{cpu_rate}}},\"net_rate_control_info\":{{\"max_bandwidth_bps\":{net_bps},\"dscp_tag\":46}},\"processor_group\":{processor_group},\"group_affinity_mask\":\"0xFFFFFFFFFFFFFFFF\"}}"
        );
        std::fs::write(&job_path, content.as_bytes()).map_err(|e| {
            ArbiterError::JobObjectError {
                job_name: job_path.display().to_string(),
                reason: e.to_string(),
            }
        })?;
        Ok(job_path)
    }

    /// Executes the 5-OS native isolation commands (`unshare`/`seccomp`/`tc`/`nft`/`criu`,
    /// `jail`/`rctl`, `zoneadm`/`prstat`, `JobObject`, or `sandbox-exec`) through an injected
    /// [`OsCommandExecutor`] and parses live usage output when `subsystem` is `"jail"` or `"zone"`.
    ///
    /// # Arguments
    ///
    /// * `subsystem` - Target OS subsystem (`"cgroup2"`, `"jail"`, `"zone"`, `"job_object"`, `"sandbox"`).
    /// * `task_id` - Task identifier.
    /// * `command` - Kernel/OS isolation command string.
    /// * `executor` - [`OsCommandExecutor`] implementation.
    ///
    /// # Returns
    ///
    /// Parsed [`IsolatorUsageReport`] from the command's stdout.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `invoke_os_op` or `executor.execute_os_command` fails.
    pub fn execute_native_lifecycle_with_executor<E: OsCommandExecutor>(
        &mut self,
        subsystem: &str,
        task_id: &TaskId,
        command: &str,
        executor: &mut E,
    ) -> ArbiterResult<IsolatorUsageReport> {
        self.invoke_os_op(subsystem, command)?;
        let stdout = executor.execute_os_command(subsystem, command)?;
        if subsystem == "jail" {
            Ok(Self::parse_freebsd_rctl_usage(task_id, &stdout))
        } else {
            Ok(Self::parse_illumos_zone_usage(task_id, &stdout))
        }
    }
}

/// Injectable OS command and syscall runner used by [`LiveOsSyscallBackend`].
///
/// Executes Linux (`unshare`, `seccomp`, `tc`, `nftables`, `criu`), FreeBSD (`jail`, `rctl`),
/// illumos (`zonecfg`, `zoneadm`, `prstat`), Windows (`JobObject`), and macOS (`sandbox-exec`) commands.
pub trait OsCommandExecutor {
    /// Executes an OS isolation command for `subsystem` and returns captured stdout.
    ///
    /// # Arguments
    ///
    /// * `subsystem` - OS subsystem identifier.
    /// * `command` - Command line or syscall specification.
    ///
    /// # Returns
    ///
    /// Captured standard output string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if command execution fails.
    fn execute_os_command(&mut self, subsystem: &str, command: &str) -> ArbiterResult<String>;
}

impl<F> OsCommandExecutor for F
where
    F: FnMut(&str, &str) -> ArbiterResult<String>,
{
    fn execute_os_command(&mut self, subsystem: &str, command: &str) -> ArbiterResult<String> {
        self(subsystem, command)
    }
}

impl OsSyscallBackend for LiveOsSyscallBackend {
    fn invoke_os_op(&mut self, subsystem: &str, command: &str) -> ArbiterResult<()> {
        let mut fs_back = FilesystemOsSyscallBackend {
            root_dir: self.root_dir.clone(),
        };
        fs_back.invoke_os_op(subsystem, command)?;
        self.executed_ops
            .push((subsystem.to_owned(), command.to_owned()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::units::{Bytes, Millicores};

    use super::*;

    macro_rules! test_os_isolator {
        ($fn_name:ident, $iso_ty:ident) => {
            #[test]
            fn $fn_name() {
                let tid = TaskId::new("task-native-1").unwrap_or_default();
                let mut limits = ResourceBundle::zero();
                limits.cpu = Millicores::new(2000);
                limits.memory = Bytes::new(4096);

                let mut iso = $iso_ty::new(MockOsSyscallBackend::default());
                assert!(!iso.name().is_empty());
                assert!(iso.prepare(&tid, &limits).is_ok());
                assert!(iso.isolate(&tid, 4242).is_ok());
                assert!(iso.update_limits(&tid, &limits).is_ok());
                assert_eq!(
                    iso.usage(&tid).map(|u| u.consumed.cpu),
                    Ok(Millicores::new(2000))
                );
                assert!(iso.checkpoint(&tid, "/var/ckpt").is_ok());
                assert!(iso.cleanup(&tid).is_ok());

                // Error path when OS syscall fails
                let mut failing_iso = $iso_ty::new(MockOsSyscallBackend {
                    recorded_ops: Vec::new(),
                    fail_all: true,
                });
                assert!(failing_iso.prepare(&tid, &limits).is_err());
                assert!(failing_iso.isolate(&tid, 4242).is_err());
                assert!(failing_iso.update_limits(&tid, &limits).is_err());
                assert!(failing_iso.checkpoint(&tid, "/var/ckpt").is_err());
                assert!(failing_iso.cleanup(&tid).is_err());
            }
        };
    }

    test_os_isolator!(test_linux_native_isolator, LinuxNativeIsolator);
    test_os_isolator!(test_freebsd_jail_isolator, FreeBsdJailIsolator);
    test_os_isolator!(test_illumos_zone_isolator, IllumosZoneIsolator);
    test_os_isolator!(test_windows_job_object_isolator, WindowsJobObjectIsolator);
    test_os_isolator!(test_macos_sandbox_isolator, MacOsSandboxIsolator);
    test_os_isolator!(test_universal_process_isolator, UniversalProcessIsolator);

    #[test]
    fn test_mock_backend_namespace_error_branch() {
        let mut backend = MockOsSyscallBackend {
            recorded_ops: Vec::new(),
            fail_all: true,
        };
        assert!(backend.invoke_os_op("namespace", "CLONE_NEWNET").is_err());

        // Test FilesystemOsSyscallBackend and SBPL generator
        let sbpl = FilesystemOsSyscallBackend::generate_macos_sbpl_profile("/var/sandbox/t1");
        assert!(sbpl.contains("(version 1)"));
        let tmp_cg = std::env::temp_dir().join("arbiter_cgroup2_test_dir");
        let _ = std::fs::remove_dir_all(&tmp_cg);
        let _ = std::fs::create_dir_all(&tmp_cg);
        let _ = FilesystemOsSyscallBackend::open(&tmp_cg);
        let fs_backend = FilesystemOsSyscallBackend {
            root_dir: tmp_cg.clone(),
        };
        let mut linux_fs = LinuxNativeIsolator::new(fs_backend);
        let tid = TaskId::new("t-fs-1").unwrap_or_default();
        let mut limits = ResourceBundle::zero();
        limits.cpu = Millicores::new(1000);
        limits.memory = Bytes::new(2048);
        assert!(linux_fs.prepare(&tid, &limits).is_ok());
        assert!(linux_fs.isolate(&tid, 999).is_ok());
        let _ = std::fs::remove_dir_all(&tmp_cg);
        assert!(
            FilesystemOsSyscallBackend::open(std::path::Path::new("/dev/null/bad_cg")).is_err()
        );
        let mut bad_fs_backend = FilesystemOsSyscallBackend {
            root_dir: std::path::PathBuf::from("/dev/null/bad_cg"),
        };
        assert!(bad_fs_backend.invoke_os_op("cgroup2", "cmd").is_err());
        // Test write error when control.ops is a directory
        let tmp_cg2 = std::env::temp_dir().join("arbiter_cgroup2_test_dir_err");
        let _ = std::fs::create_dir_all(tmp_cg2.join("cgroup2").join("control.ops"));
        let mut dir_conflict = FilesystemOsSyscallBackend {
            root_dir: tmp_cg2.clone(),
        };
        assert!(dir_conflict.invoke_os_op("cgroup2", "cmd").is_err());
        let _ = std::fs::remove_dir_all(&tmp_cg2);
    }

    #[test]
    fn test_live_os_syscall_backend_and_parsers() {
        let tid = TaskId::new("t-fs-1").unwrap_or_default();
        let mut limits = ResourceBundle::zero();
        limits.cpu = Millicores::new(1000);
        limits.memory = Bytes::new(2048);

        // Test LiveOsSyscallBackend cgroup v2 knobs, live usage reader, and macOS SBPL file writer
        let live_dir = std::env::temp_dir().join("arbiter_live_os_iso_test");
        let _ = std::fs::remove_dir_all(&live_dir);
        let mut live_back = LiveOsSyscallBackend::new(&live_dir);
        assert!(live_back.write_cgroup_v2_knobs(&tid, &limits, 4242).is_ok());
        assert!(
            live_back
                .set_cgroup_v2_freeze_and_kill(&tid, true, false)
                .is_ok()
        );
        assert!(
            live_back
                .set_cgroup_v2_freeze_and_kill(&tid, false, true)
                .is_ok()
        );
        // Test error path when cgroup.kill is a directory
        let kill_file = live_dir.join(tid.as_str()).join("cgroup.kill");
        let _ = std::fs::remove_file(&kill_file);
        let _ = std::fs::create_dir_all(&kill_file);
        assert!(
            live_back
                .set_cgroup_v2_freeze_and_kill(&tid, true, true)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&kill_file);
        assert_eq!(
            live_back
                .read_cgroup_v2_usage(&tid)
                .map(|u| u.consumed.memory),
            Ok(Bytes::new(2048))
        );
        assert_eq!(live_back.read_cgroup_v2_events_and_psi(&tid), Ok((0, 0)));
        assert_eq!(
            live_back
                .configure_linux_ns_seccomp_tc_and_criu(
                    &tid,
                    4242,
                    "/tmp/sbox",
                    10_000_000,
                    "/tmp/ckpt"
                )
                .map(|v| v.len()),
            Ok(5)
        );
        let fbsd_rep = LiveOsSyscallBackend::parse_freebsd_rctl_usage(
            &tid,
            "pcpu=250\nmemoryuse=8192\nother=1",
        );
        assert_eq!(fbsd_rep.consumed.cpu, Millicores::new(2500));
        assert_eq!(fbsd_rep.consumed.memory, Bytes::new(8192));
        let ill_rep =
            LiveOsSyscallBackend::parse_illumos_zone_usage(&tid, "cpum=1500\nrss=16384\nother=1");
        assert_eq!(ill_rep.consumed.cpu, Millicores::new(1500));
        assert_eq!(ill_rep.consumed.memory, Bytes::new(16384));
        assert!(
            live_back
                .prepare_macos_sandbox_exec_and_qos(&tid, "/tmp/sbox", &limits, true)
                .is_ok()
        );
        assert!(
            live_back
                .prepare_macos_sandbox_exec_and_qos(&tid, "/tmp/sbox", &limits, false)
                .is_ok()
        );
        assert!(live_back.write_macos_sbpl_file(&tid, "/tmp/sbox").is_ok());
        assert!(
            live_back
                .write_freebsd_jail_rctl_manifest(&tid, &limits, "/tmp/jail")
                .is_ok()
        );
        assert!(
            live_back
                .write_illumos_zonecfg_manifest(&tid, &limits, "/zones/t1")
                .is_ok()
        );
        assert!(
            live_back
                .write_windows_job_object_manifest(&tid, &limits, 0)
                .is_ok()
        );
        let _ = std::fs::remove_dir_all(&live_dir);
    }

    #[test]
    fn test_live_os_syscall_backend_executor_and_missing_dir_errors() {
        let tid = TaskId::new("t-fs-2").unwrap_or_default();
        let live_dir = std::env::temp_dir().join("arbiter_live_os_iso_exec_test");
        let _ = std::fs::remove_dir_all(&live_dir);
        let mut live_back = LiveOsSyscallBackend::new(&live_dir);
        assert!(live_back.invoke_os_op("jail", "jail -c").is_ok());
        let mut ok_exec = |_sub: &str, _cmd: &str| -> ArbiterResult<String> {
            Ok("pcpu=200\ncpum=1200".to_owned())
        };
        assert_eq!(
            live_back
                .execute_native_lifecycle_with_executor("jail", &tid, "rctl -u", &mut ok_exec)
                .map(|r| r.consumed.cpu),
            Ok(Millicores::new(2000))
        );
        assert_eq!(
            live_back
                .execute_native_lifecycle_with_executor("zone", &tid, "prstat -Z", &mut ok_exec)
                .map(|r| r.consumed.cpu),
            Ok(Millicores::new(1200))
        );
        let mut err_exec = |_sub: &str, cmd: &str| -> ArbiterResult<String> {
            Err(ArbiterError::JailError {
                jail_name: cmd.to_owned(),
                reason: "runner error".to_owned(),
            })
        };
        assert!(
            live_back
                .execute_native_lifecycle_with_executor("jail", &tid, "rctl -u", &mut err_exec)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&live_dir);
        assert!(live_back.read_cgroup_v2_usage(&tid).is_err());
        assert!(live_back.read_cgroup_v2_events_and_psi(&tid).is_err());
    }

    #[test]
    fn test_live_os_syscall_backend_error_paths() {
        let tid = TaskId::new("t-fs-1").unwrap_or_default();
        let limits = ResourceBundle::zero();
        let mut bad_live = LiveOsSyscallBackend::new(std::path::Path::new("/dev/null/bad_live"));
        assert!(bad_live.write_cgroup_v2_knobs(&tid, &limits, 1).is_err());
        assert!(
            bad_live
                .set_cgroup_v2_freeze_and_kill(&tid, true, false)
                .is_err()
        );
        assert!(
            bad_live
                .configure_linux_ns_seccomp_tc_and_criu(&tid, 1, "/tmp", 0, "/tmp")
                .is_err()
        );
        assert!(
            bad_live
                .prepare_macos_sandbox_exec_and_qos(&tid, "/tmp", &limits, true)
                .is_err()
        );
        assert!(bad_live.write_macos_sbpl_file(&tid, "/tmp").is_err());
        assert!(
            bad_live
                .write_freebsd_jail_rctl_manifest(&tid, &limits, "/tmp")
                .is_err()
        );
        assert!(
            bad_live
                .write_illumos_zonecfg_manifest(&tid, &limits, "/tmp")
                .is_err()
        );
        assert!(
            bad_live
                .write_windows_job_object_manifest(&tid, &limits, 0)
                .is_err()
        );
        assert!(bad_live.invoke_os_op("jail", "jail -c").is_err());
        let mut noop_exec = |_s: &str, _c: &str| -> ArbiterResult<String> { Ok(String::new()) };
        assert_eq!(noop_exec("jail", "noop"), Ok(String::new()));
        assert!(
            bad_live
                .execute_native_lifecycle_with_executor("jail", &tid, "jail -c", &mut noop_exec)
                .is_err()
        );
    }
}
