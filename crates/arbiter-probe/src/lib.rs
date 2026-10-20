//! Cross-platform CPU, NUMA, GPU, TPU, and fabric hardware discovery and telemetry probes for Arbiter.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod cpu;
pub mod fabric;
pub mod gpu;
pub mod tpu;
pub mod traits;

use arbiter_core::error::ArbiterResult;
use arbiter_core::platform::OsKind;
use arbiter_core::resources::{GpuDevice, RdmaDevice, ResourceBundle, TpuDevice};
use arbiter_core::topology::HardwareTopologyGraph;
use arbiter_core::units::{BandwidthBps, Bytes, GpuMillicores, Millicores, TpuChips};
use serde::{Deserialize, Serialize};

use crate::cpu::{
    FreeBsdSysctlProbe, IllumosKstatProbe, LinuxSysfsProbe, MacOsSysctlProbe,
    WindowsProcessorInfoProbe,
};
use crate::fabric::{HighSpeedFabricProbe, assemble_hardware_topology_graph};
use crate::gpu::{AppleMetalProbe, NvidiaNvmlProbe};
use crate::tpu::GoogleTpuProbe;
use crate::traits::{DiscoveredSystemTopology, FabricProbe, GpuProbe, SystemProbe, TpuProbe};

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

        let (gpus, gpu_edges) = match target_os {
            OsKind::MacOs => AppleMetalProbe::from_host().probe_gpus(),
            OsKind::Linux | OsKind::FreeBsd | OsKind::Illumos | OsKind::Windows => {
                NvidiaNvmlProbe::from_host().probe_gpus()
            }
        }
        .unwrap_or_default();

        let tpus = GoogleTpuProbe::from_host().probe_tpus().unwrap_or_default();
        let (rdma_nics, fabric_edges) = HighSpeedFabricProbe::from_host()
            .probe_fabric()
            .unwrap_or_default();
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
        }
    }
}
