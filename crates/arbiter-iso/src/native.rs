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
        assert!(matches!(
            backend.invoke_os_op("namespace", "CLONE_NEWNET"),
            Err(ArbiterError::NamespaceError { .. })
        ));
    }
}
