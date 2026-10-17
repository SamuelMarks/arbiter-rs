//! Operating system, CPU architecture, and isolation capability taxonomy for Arbiter.
//!
//! Models cross-platform compatibility rules across Linux, Windows, macOS, FreeBSD, and illumos.

use core::fmt;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{ArbiterError, ArbiterResult};

/// Operating system families supported by Arbiter.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum OsKind {
    /// Linux kernel (`x86_64`, `aarch64`, `riscv64`).
    #[default]
    Linux,
    /// Microsoft Windows NT kernel (`x86_64`, `aarch64`).
    Windows,
    /// Apple macOS / Darwin (`x86_64`, `aarch64`).
    MacOs,
    /// FreeBSD kernel (`x86_64`, `aarch64`, `riscv64`).
    FreeBsd,
    /// illumos kernel (`OmniOS`, `SmartOS`, `OpenIndiana`).
    Illumos,
}

impl OsKind {
    /// Returns the canonical lowercase identifier for the operating system.
    ///
    /// # Returns
    ///
    /// Static string slice representing the OS.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::FreeBsd => "freebsd",
            Self::Illumos => "illumos",
        }
    }

    /// Checks whether the operating system natively supports ZFS datasets and `CoW` clones.
    ///
    /// # Returns
    ///
    /// `true` for `FreeBsd`, `Illumos`, and `Linux` (via ZFS-on-Linux).
    pub const fn supports_zfs(self) -> bool {
        matches!(self, Self::FreeBsd | Self::Illumos | Self::Linux)
    }
}

impl fmt::Display for OsKind {
    /// Formats the operating system kind.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CPU instruction set architectures supported by Arbiter.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum CpuArch {
    /// 64-bit x86 (`amd64` / `x86_64`).
    #[default]
    X86_64,
    /// 64-bit ARM (`aarch64` / `arm64`).
    Aarch64,
    /// 64-bit RISC-V (`riscv64gc`).
    Riscv64,
}

impl CpuArch {
    /// Returns the canonical target architecture string.
    ///
    /// # Returns
    ///
    /// Static architecture name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Riscv64 => "riscv64",
        }
    }
}

impl fmt::Display for CpuArch {
    /// Formats the CPU architecture.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Isolation and virtualization engines supported across the Arbiter Agent fleet.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum IsolationCapability {
    /// Universal bare-metal OS process spawning with UID/GID and working directory isolation.
    PosixOrWin32Process,
    /// Linux `cgroups v2` resource controller hierarchy.
    LinuxCgroupsV2,
    /// Linux namespaces (`pid`, `net`, `mnt`, `uts`, `ipc`, `user`) + `seccomp-bpf`.
    LinuxNamespaces,
    /// FreeBSD Jails (`jail_set` / `jail_attach`) + `RCTL`/`RACCT` + `VNET`.
    FreeBsdJail,
    /// illumos Zones (`zonecfg` / `zoneadm`) + processor sets (`pset`) + Crossbow VNICs.
    IllumosZone,
    /// Windows Job Objects (`CreateJobObject`) + Processor Group affinity + AppContainer/Silo.
    WindowsJobObject,
    /// macOS `sandbox-exec` SBPL + `setrlimit` + Mach `QoS` core steering.
    MacOsSandbox,
    /// Open Container Initiative (OCI) container runtime (`runc`, `crun`, `containerd`, `ocijail`, `runhcs`).
    OciContainer,
    /// Linux Firecracker `MicroVM`.
    FirecrackerMicroVm,
    /// FreeBSD and illumos `bhyve` `MicroVM`.
    BhyveMicroVm,
    /// Windows Hyper-V isolated VM / container.
    HyperVMicroVm,
    /// macOS `Virtualization.framework` lightweight VM.
    AppleVirtualizationMicroVm,
}

impl IsolationCapability {
    /// Returns the human-readable name of the isolation capability.
    ///
    /// # Returns
    ///
    /// Static capability name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PosixOrWin32Process => "PosixOrWin32Process",
            Self::LinuxCgroupsV2 => "LinuxCgroupsV2",
            Self::LinuxNamespaces => "LinuxNamespaces",
            Self::FreeBsdJail => "FreeBsdJail",
            Self::IllumosZone => "IllumosZone",
            Self::WindowsJobObject => "WindowsJobObject",
            Self::MacOsSandbox => "MacOsSandbox",
            Self::OciContainer => "OciContainer",
            Self::FirecrackerMicroVm => "FirecrackerMicroVm",
            Self::BhyveMicroVm => "BhyveMicroVm",
            Self::HyperVMicroVm => "HyperVMicroVm",
            Self::AppleVirtualizationMicroVm => "AppleVirtualizationMicroVm",
        }
    }

    /// Checks whether this isolation capability is supported on the given [`OsKind`].
    ///
    /// # Arguments
    ///
    /// * `os` - Target operating system.
    ///
    /// # Returns
    ///
    /// `true` if the isolator can run on `os`.
    pub const fn is_supported_on(self, os: OsKind) -> bool {
        match self {
            Self::PosixOrWin32Process => true,
            Self::LinuxCgroupsV2 | Self::LinuxNamespaces | Self::FirecrackerMicroVm => {
                matches!(os, OsKind::Linux)
            }
            Self::FreeBsdJail => matches!(os, OsKind::FreeBsd),
            Self::IllumosZone => matches!(os, OsKind::Illumos),
            Self::WindowsJobObject | Self::HyperVMicroVm => matches!(os, OsKind::Windows),
            Self::MacOsSandbox | Self::AppleVirtualizationMicroVm => matches!(os, OsKind::MacOs),
            Self::OciContainer => matches!(
                os,
                OsKind::Linux | OsKind::FreeBsd | OsKind::Windows | OsKind::Illumos
            ),
            Self::BhyveMicroVm => matches!(os, OsKind::FreeBsd | OsKind::Illumos),
        }
    }

    /// Validates that this isolation capability is supported on `os`, returning an error otherwise.
    ///
    /// # Arguments
    ///
    /// * `os` - Target operating system.
    ///
    /// # Returns
    ///
    /// `Ok(())` if supported.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IsolatorUnsupportedOnOs`] if incompatible.
    pub fn validate_for_os(self, os: OsKind) -> ArbiterResult<()> {
        if !self.is_supported_on(os) {
            return Err(ArbiterError::IsolatorUnsupportedOnOs {
                isolator: self.as_str().to_owned(),
                os: os.as_str().to_owned(),
            });
        }
        Ok(())
    }
}

impl fmt::Display for IsolationCapability {
    /// Formats the isolation capability.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_kind_and_cpu_arch() {
        let os_list = [
            (OsKind::Linux, "linux", true),
            (OsKind::Windows, "windows", false),
            (OsKind::MacOs, "macos", false),
            (OsKind::FreeBsd, "freebsd", true),
            (OsKind::Illumos, "illumos", true),
        ];
        for (os, name, zfs) in os_list {
            assert_eq!(os.as_str(), name);
            assert_eq!(os.to_string(), name);
            assert_eq!(os.supports_zfs(), zfs);
        }

        let arches = [
            (CpuArch::X86_64, "x86_64"),
            (CpuArch::Aarch64, "aarch64"),
            (CpuArch::Riscv64, "riscv64"),
        ];
        for (arch, name) in arches {
            assert_eq!(arch.as_str(), name);
            assert_eq!(arch.to_string(), name);
        }
    }

    #[test]
    fn test_isolation_capability_matrix() {
        let all_caps = [
            IsolationCapability::PosixOrWin32Process,
            IsolationCapability::LinuxCgroupsV2,
            IsolationCapability::LinuxNamespaces,
            IsolationCapability::FreeBsdJail,
            IsolationCapability::IllumosZone,
            IsolationCapability::WindowsJobObject,
            IsolationCapability::MacOsSandbox,
            IsolationCapability::OciContainer,
            IsolationCapability::FirecrackerMicroVm,
            IsolationCapability::BhyveMicroVm,
            IsolationCapability::HyperVMicroVm,
            IsolationCapability::AppleVirtualizationMicroVm,
        ];
        for cap in all_caps {
            assert!(!cap.as_str().is_empty());
            assert_eq!(cap.to_string(), cap.as_str());
            assert!(IsolationCapability::PosixOrWin32Process.is_supported_on(OsKind::Linux));
        }

        // Linux checks
        assert!(
            IsolationCapability::LinuxCgroupsV2
                .validate_for_os(OsKind::Linux)
                .is_ok()
        );
        assert!(
            IsolationCapability::LinuxNamespaces
                .validate_for_os(OsKind::Linux)
                .is_ok()
        );
        assert!(
            IsolationCapability::FirecrackerMicroVm
                .validate_for_os(OsKind::Linux)
                .is_ok()
        );
        assert!(
            IsolationCapability::FreeBsdJail
                .validate_for_os(OsKind::Linux)
                .is_err()
        );

        // FreeBSD checks
        assert!(
            IsolationCapability::FreeBsdJail
                .validate_for_os(OsKind::FreeBsd)
                .is_ok()
        );
        assert!(
            IsolationCapability::BhyveMicroVm
                .validate_for_os(OsKind::FreeBsd)
                .is_ok()
        );
        assert!(
            IsolationCapability::OciContainer
                .validate_for_os(OsKind::FreeBsd)
                .is_ok()
        );
        assert!(
            IsolationCapability::IllumosZone
                .validate_for_os(OsKind::FreeBsd)
                .is_err()
        );

        // illumos checks
        assert!(
            IsolationCapability::IllumosZone
                .validate_for_os(OsKind::Illumos)
                .is_ok()
        );
        assert!(
            IsolationCapability::BhyveMicroVm
                .validate_for_os(OsKind::Illumos)
                .is_ok()
        );
        assert!(
            IsolationCapability::WindowsJobObject
                .validate_for_os(OsKind::Illumos)
                .is_err()
        );
    }

    #[test]
    fn test_isolation_capability_windows_and_macos() {
        // Windows checks
        assert!(
            IsolationCapability::WindowsJobObject
                .validate_for_os(OsKind::Windows)
                .is_ok()
        );
        assert!(
            IsolationCapability::HyperVMicroVm
                .validate_for_os(OsKind::Windows)
                .is_ok()
        );
        assert!(
            IsolationCapability::MacOsSandbox
                .validate_for_os(OsKind::Windows)
                .is_err()
        );

        // macOS checks
        assert!(
            IsolationCapability::MacOsSandbox
                .validate_for_os(OsKind::MacOs)
                .is_ok()
        );
        assert!(
            IsolationCapability::AppleVirtualizationMicroVm
                .validate_for_os(OsKind::MacOs)
                .is_ok()
        );
        assert!(
            IsolationCapability::OciContainer
                .validate_for_os(OsKind::MacOs)
                .is_err()
        );
        assert!(
            IsolationCapability::LinuxCgroupsV2
                .validate_for_os(OsKind::MacOs)
                .is_err()
        );
        assert!(
            IsolationCapability::BhyveMicroVm
                .validate_for_os(OsKind::MacOs)
                .is_err()
        );
    }
}
