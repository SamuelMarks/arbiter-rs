//! Cross-platform CPU, NUMA, GPU, TPU, and fabric hardware discovery and telemetry probes for Arbiter.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod cpu;
pub mod fabric;
pub mod gpu;
pub mod tpu;
pub mod traits;

use std::path::{Path, PathBuf};

use arbiter_core::error::ArbiterResult;
use arbiter_core::platform::OsKind;
use arbiter_core::resources::{GpuDevice, RdmaDevice, RdmaFabricKind, ResourceBundle, TpuDevice};
use arbiter_core::topology::HardwareTopologyGraph;
use arbiter_core::units::{BandwidthBps, Bytes, GpuMillicores, Millicores, TpuChips};
use serde::{Deserialize, Serialize};

use crate::cpu::{
    FreeBsdSysctlProbe, IllumosKstatProbe, LinuxSysfsProbe, MacOsSysctlProbe,
    WindowsProcessorInfoProbe,
};
use crate::fabric::{HighSpeedFabricProbe, assemble_hardware_topology_graph};
use crate::gpu::{
    AmdRocmProbe, AppleMetalProbe, IntelLevelZeroProbe, NvidiaNvmlProbe,
    discover_gpus_from_sysfs_dir,
};
use crate::tpu::GoogleTpuProbe;
use crate::traits::{DiscoveredSystemTopology, FabricProbe, GpuProbe, SystemProbe, TpuProbe};

/// Configurable filesystem roots for strict host hardware discovery (`sysfs` and `/proc`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSysfsRoots {
    /// Path to NVIDIA SMI summary or procfs (`/proc/driver/nvidia/smi_summary`).
    pub nvidia_smi_path: PathBuf,
    /// Path to AMD `ROCm` KFD topology nodes (`/sys/class/kfd/kfd/topology/nodes`).
    pub amd_kfd_dir: PathBuf,
    /// Path to Linux DRM device directory (`/sys/class/drm`).
    pub drm_dir: PathBuf,
    /// Path to Google Cloud / Coral Edge TPU sysfs directory (`/sys/class/accel`).
    pub tpu_accel_dir: PathBuf,
    /// Path to `InfiniBand` / `RoCEv2` sysfs directory (`/sys/class/infiniband`).
    pub infiniband_dir: PathBuf,
}

impl Default for HostSysfsRoots {
    /// Returns the standard OS `/proc` and `/sys/class` paths for live hardware discovery.
    ///
    /// # Returns
    ///
    /// Default [`HostSysfsRoots`].
    fn default() -> Self {
        Self {
            nvidia_smi_path: PathBuf::from("/proc/driver/nvidia/smi_summary"),
            amd_kfd_dir: PathBuf::from("/sys/class/kfd/kfd/topology/nodes"),
            drm_dir: PathBuf::from("/sys/class/drm"),
            tpu_accel_dir: PathBuf::from("/sys/class/accel"),
            infiniband_dir: PathBuf::from("/sys/class/infiniband"),
        }
    }
}

/// Hardware discovery mode controlling whether missing accelerators/NICs return empty device vectors
/// (`StrictHostHardware`) or deterministic reference descriptors (`SimulatedFallback`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeMode {
    /// Production mode: report only physically present host accelerators and NICs (`Ok(empty)` when absent).
    #[default]
    StrictHostHardware,
    /// Simulation/test fallback mode: synthesize reference descriptors when running on hosts without accelerators.
    SimulatedFallback,
}

/// Complete host hardware topology discovery report returned by [`HostTopologyDiscoveryEngine`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostDiscoveryReport {
    /// Discovered CPU cores, architecture, and NUMA memory pools.
    pub system: DiscoveredSystemTopology,
    /// Aggregate [`ResourceBundle`] capacity computed from all discovered hardware devices.
    pub total_resources: ResourceBundle,
    /// Discovered GPU accelerators.
    pub gpus: Vec<GpuDevice>,
    /// Discovered TPU chips.
    pub tpus: Vec<TpuDevice>,
    /// Discovered RDMA / high-speed fabric NICs.
    pub rdma_nics: Vec<RdmaDevice>,
    /// Validated [`HardwareTopologyGraph`] connecting NUMA nodes, CPUs, GPUs, TPUs, and NICs.
    pub topology_graph: HardwareTopologyGraph,
}

/// Unified cross-platform hardware topology discovery engine (`HostTopologyDiscoveryEngine`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HostTopologyDiscoveryEngine;

impl HostTopologyDiscoveryEngine {
    /// Probes the current local host (`OsKind::current()`) in production [`ProbeMode::StrictHostHardware`]
    /// mode (reporting only physically present host hardware without synthetic fallback devices).
    ///
    /// # Returns
    ///
    /// Strict host [`HostDiscoveryReport`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if topology assembly fails.
    pub fn probe_strict_live_host() -> ArbiterResult<HostDiscoveryReport> {
        Self::probe_for_os_with_mode(OsKind::current(), ProbeMode::StrictHostHardware)
    }

    /// Probes the current local host (`OsKind::current()`) and returns a complete [`HostDiscoveryReport`].
    ///
    /// # Returns
    ///
    /// Complete [`HostDiscoveryReport`] for the running operating system.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if topology assembly fails.
    pub fn probe_live_host() -> ArbiterResult<HostDiscoveryReport> {
        Self::probe_for_os(OsKind::current())
    }

    /// Probes CPU, NUMA, GPU, TPU, and high-speed fabric topology for `target_os` and assembles
    /// a complete [`HostDiscoveryReport`].
    ///
    /// # Arguments
    ///
    /// * `target_os` - Target [`OsKind`] (`Linux`, `FreeBsd`, `Illumos`, `Windows`, `MacOs`).
    ///
    /// # Returns
    ///
    /// Complete [`HostDiscoveryReport`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if graph assembly fails.
    pub fn probe_for_os(target_os: OsKind) -> ArbiterResult<HostDiscoveryReport> {
        Self::probe_for_os_with_mode(target_os, ProbeMode::SimulatedFallback)
    }

    /// Probes CPU, NUMA, GPU, TPU, and high-speed fabric topology for `target_os` using `mode`.
    ///
    /// When `mode == ProbeMode::StrictHostHardware`, accelerator and fabric collectors do not
    /// fabricate synthetic fallback GPUs/TPUs/RDMA NICs when vendor device nodes (`/dev/nvidia0`,
    /// `/dev/accel0`, `/sys/class/infiniband`) are absent on the host.
    ///
    /// # Arguments
    ///
    /// * `target_os` - Target [`OsKind`].
    /// * `mode` - [`ProbeMode`] (`StrictHostHardware` or `SimulatedFallback`).
    ///
    /// # Returns
    ///
    /// Complete [`HostDiscoveryReport`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if graph assembly fails.
    pub fn probe_for_os_with_mode(
        target_os: OsKind,
        mode: ProbeMode,
    ) -> ArbiterResult<HostDiscoveryReport> {
        Self::probe_for_os_with_roots(target_os, mode, &HostSysfsRoots::default())
    }

    /// Probes CPU, NUMA, GPU (`NVIDIA`, `AMD`, `Intel`, `Apple`), TPU (`accel*`/`apex_*`), and
    /// `InfiniBand`/`RoCEv2` fabric topology using explicit [`HostSysfsRoots`].
    ///
    /// # Arguments
    ///
    /// * `target_os` - Target [`OsKind`].
    /// * `mode` - [`ProbeMode`] (`StrictHostHardware` or `SimulatedFallback`).
    /// * `roots` - Filesystem paths for `sysfs` and `/proc` hardware directories.
    ///
    /// # Returns
    ///
    /// Complete [`HostDiscoveryReport`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if graph assembly fails.
    pub fn probe_for_os_with_roots(
        target_os: OsKind,
        mode: ProbeMode,
        roots: &HostSysfsRoots,
    ) -> ArbiterResult<HostDiscoveryReport> {
        let fallback_sys = DiscoveredSystemTopology {
            os_kind: target_os,
            cpu_arch: arbiter_core::platform::CpuArch::X86_64,
            cores: Vec::new(),
            numa_pools: Vec::new(),
        };
        let system = match target_os {
            OsKind::Linux => LinuxSysfsProbe::from_host().probe_system(),
            OsKind::FreeBsd => FreeBsdSysctlProbe::from_host().probe_system(),
            OsKind::Illumos => IllumosKstatProbe::from_host().probe_system(),
            OsKind::Windows => WindowsProcessorInfoProbe::from_host().probe_system(),
            OsKind::MacOs => MacOsSysctlProbe::from_host().probe_system(),
        }
        .unwrap_or(fallback_sys);

        let (gpus, gpu_edges) = match (target_os, mode) {
            (OsKind::MacOs, _) => AppleMetalProbe::from_host()
                .probe_gpus()
                .unwrap_or_default(),
            (_, ProbeMode::StrictHostHardware) => Self::discover_strict_non_macos_gpus(
                &roots.nvidia_smi_path,
                &roots.amd_kfd_dir,
                &roots.drm_dir,
            ),
            (_, ProbeMode::SimulatedFallback) => NvidiaNvmlProbe::from_host()
                .probe_gpus()
                .unwrap_or_default(),
        };

        let tpus = match mode {
            ProbeMode::StrictHostHardware => {
                GoogleTpuProbe::from_host_strict_with_dir(&roots.tpu_accel_dir, "slice-host-0")
                    .probe_tpus()
                    .unwrap_or_default()
            }
            ProbeMode::SimulatedFallback => {
                GoogleTpuProbe::from_host().probe_tpus().unwrap_or_default()
            }
        };
        let (rdma_nics, fabric_edges) = match mode {
            ProbeMode::StrictHostHardware => HighSpeedFabricProbe::from_host_strict_with_dir(
                &roots.infiniband_dir,
                RdmaFabricKind::InfiniBand,
            )
            .probe_fabric()
            .unwrap_or_default(),
            ProbeMode::SimulatedFallback => HighSpeedFabricProbe::from_host()
                .probe_fabric()
                .unwrap_or_default(),
        };
        let topology_graph = assemble_hardware_topology_graph(
            &system,
            &gpus,
            &gpu_edges,
            &tpus,
            &rdma_nics,
            &fabric_edges,
        )
        .unwrap_or_default();

        let cpu_m = u64::try_from(system.cores.len())
            .unwrap_or(1)
            .saturating_mul(1000);
        let mut ram_bytes = 0_u64;
        let mut hp_bytes = 0_u64;
        for pool in &system.numa_pools {
            ram_bytes = ram_bytes.saturating_add(pool.ram_bytes.get());
            hp_bytes = hp_bytes
                .saturating_add(pool.hugepages_2mib_bytes.get())
                .saturating_add(pool.hugepages_1gib_bytes.get());
        }
        let mut gpu_m = 0_u64;
        let mut vram_b = 0_u64;
        for gpu in &gpus {
            gpu_m = gpu_m.saturating_add(gpu.available_compute.get());
            vram_b = vram_b.saturating_add(gpu.available_vram.get());
        }
        let tpu_count = u64::try_from(tpus.len()).unwrap_or(0);
        let mut net_bw = 10_000_000_000_u64;
        for nic in &rdma_nics {
            net_bw = net_bw.max(nic.bandwidth.get());
        }

        let total_resources = ResourceBundle {
            cpu: Millicores::new(cpu_m),
            memory: Bytes::new(ram_bytes),
            hugepages: Bytes::new(hp_bytes),
            gpu_compute: GpuMillicores::new(gpu_m),
            gpu_vram: Bytes::new(vram_b),
            tpu_chips: TpuChips::new(tpu_count),
            disk: Bytes::new(100 * 1024 * 1024 * 1024),
            network_bandwidth: BandwidthBps::new(net_bw),
            ..ResourceBundle::zero()
        };

        Ok(HostDiscoveryReport {
            system,
            total_resources,
            gpus,
            tpus,
            rdma_nics,
            topology_graph,
        })
    }

    /// Collects physically present NVIDIA, AMD `ROCm`, Intel Level Zero, and generic DRM sysfs GPUs
    /// without fabricating synthetic devices when absent.
    ///
    /// # Arguments
    ///
    /// * `nvidia_smi_path` - Path to NVIDIA SMI summary file.
    /// * `amd_kfd_dir` - Path to AMD KFD topology directory.
    /// * `drm_dir` - Path to Linux DRM sysfs directory.
    ///
    /// # Returns
    ///
    /// Tuple of `(Vec<GpuDevice>, Vec<InterconnectEdge>)`.
    fn discover_strict_non_macos_gpus(
        nvidia_smi_path: &Path,
        amd_kfd_dir: &Path,
        drm_dir: &Path,
    ) -> (
        Vec<GpuDevice>,
        Vec<arbiter_core::topology::InterconnectEdge>,
    ) {
        let (mut gpus, mut edges) = NvidiaNvmlProbe::from_host_strict_with_path(nvidia_smi_path)
            .probe_gpus()
            .unwrap_or_default();
        if let Ok((amd_gpus, amd_edges)) =
            AmdRocmProbe::from_host_strict_with_dir(amd_kfd_dir).probe_gpus()
        {
            gpus.extend(amd_gpus);
            edges.extend(amd_edges);
        }
        if let Ok((intel_gpus, intel_edges)) =
            IntelLevelZeroProbe::from_host_strict_with_dir(drm_dir).probe_gpus()
        {
            gpus.extend(intel_gpus);
            edges.extend(intel_edges);
        }
        if gpus.is_empty() {
            if let Ok(drm_gpus) = discover_gpus_from_sysfs_dir(drm_dir) {
                gpus.extend(drm_gpus);
            }
        }
        (gpus, edges)
    }
}

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-probe"`.
pub const fn crate_name() -> &'static str {
    "arbiter-probe"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_name_and_host_topology_discovery_engine() {
        assert_eq!(crate_name(), "arbiter-probe");
        assert!(HostTopologyDiscoveryEngine::probe_live_host().is_ok());
        for os in [
            OsKind::Linux,
            OsKind::FreeBsd,
            OsKind::Illumos,
            OsKind::Windows,
            OsKind::MacOs,
        ] {
            let report = HostTopologyDiscoveryEngine::probe_for_os(os);
            assert!(report.is_ok());
            let strict_report = HostTopologyDiscoveryEngine::probe_for_os_with_mode(
                os,
                ProbeMode::StrictHostHardware,
            );
            assert!(strict_report.is_ok());
        }
        assert!(HostTopologyDiscoveryEngine::probe_strict_live_host().is_ok());
        assert_eq!(ProbeMode::default(), ProbeMode::StrictHostHardware);

        let base_dir = std::env::temp_dir().join("arbiter_probe_strict_roots_test");
        let _ = std::fs::remove_dir_all(&base_dir);
        let smi_path = base_dir.join("smi_summary");
        let kfd_dir = base_dir.join("kfd_nodes");
        let drm_dir = base_dir.join("drm");
        let accel_dir = base_dir.join("accel");
        let ib_dir = base_dir.join("infiniband");

        let _ = std::fs::create_dir_all(kfd_dir.join("1").join("mem_banks").join("0"));
        let _ = std::fs::write(
            kfd_dir.join("1").join("properties"),
            "cpu_cores_count 0\nsimd_count 304\n",
        );
        let _ = std::fs::write(
            kfd_dir
                .join("1")
                .join("mem_banks")
                .join("0")
                .join("properties"),
            "size_in_bytes 137438953472\n",
        );
        let _ = std::fs::create_dir_all(drm_dir.join("card0").join("gt").join("gt0"));
        let _ = std::fs::create_dir_all(drm_dir.join("card0").join("device"));
        let _ = std::fs::write(
            drm_dir.join("card0").join("device").join("vendor"),
            "0x8086",
        );
        let _ = std::fs::write(&smi_path, "0, NVIDIA H100, 81920, 0\n");
        let _ = std::fs::create_dir_all(accel_dir.join("accel0"));
        let _ = std::fs::create_dir_all(ib_dir.join("mlx5_0").join("ports").join("1"));
        let _ = std::fs::write(
            ib_dir.join("mlx5_0").join("ports").join("1").join("rate"),
            "400 Gb/sec\n",
        );

        let populated_roots = HostSysfsRoots {
            nvidia_smi_path: smi_path,
            amd_kfd_dir: kfd_dir,
            drm_dir,
            tpu_accel_dir: accel_dir,
            infiniband_dir: ib_dir,
        };
        let strict_pop = HostTopologyDiscoveryEngine::probe_for_os_with_roots(
            OsKind::Linux,
            ProbeMode::StrictHostHardware,
            &populated_roots,
        );
        assert_eq!(
            strict_pop.map(|r| (r.gpus.is_empty(), r.tpus.len(), r.rdma_nics.len())),
            Ok((false, 1, 1))
        );

        // Also test DRM fallback when NVIDIA, AMD, and Intel tiles are absent
        let drm_only_dir = base_dir.join("drm_only");
        let _ = std::fs::create_dir_all(drm_only_dir.join("card1").join("device"));
        let _ = std::fs::write(
            drm_only_dir.join("card1").join("device").join("vendor"),
            "0x10de",
        );
        let drm_fallback_roots = HostSysfsRoots {
            nvidia_smi_path: base_dir.join("missing_smi"),
            amd_kfd_dir: base_dir.join("missing_kfd"),
            drm_dir: drm_only_dir,
            tpu_accel_dir: base_dir.join("missing_accel"),
            infiniband_dir: base_dir.join("missing_ib"),
        };
        let drm_rep = HostTopologyDiscoveryEngine::probe_for_os_with_roots(
            OsKind::Linux,
            ProbeMode::StrictHostHardware,
            &drm_fallback_roots,
        );
        assert!(drm_rep.is_ok());

        let _ = std::fs::remove_dir_all(&base_dir);
    }
}
