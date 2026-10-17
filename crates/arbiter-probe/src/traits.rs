//! Pluggable hardware discovery and deep telemetry probe traits (`arbiter-probe::traits`).
//!
//! Defines [`SystemProbe`], [`GpuProbe`], [`TpuProbe`], and [`FabricProbe`] traits so OS/driver
//! collectors and deterministic synthetic test topologies are interchangeable across all 5 OSes.

use arbiter_core::error::ArbiterResult;
use arbiter_core::platform::{CpuArch, OsKind};
use arbiter_core::resources::{CoreDescriptor, GpuDevice, NumaMemoryPool, RdmaDevice, TpuDevice};
use arbiter_core::topology::InterconnectEdge;
use serde::{Deserialize, Serialize};

/// Discovered host CPU, NUMA, and memory topology snapshot.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredSystemTopology {
    /// Detected operating system kind.
    pub os_kind: OsKind,
    /// Detected CPU architecture.
    pub cpu_arch: CpuArch,
    /// Discovered physical/logical CPU cores and cache groups.
    pub cores: Vec<CoreDescriptor>,
    /// Discovered NUMA memory pools (including `HugePages` and unified memory flags).
    pub numa_pools: Vec<NumaMemoryPool>,
}

/// Pluggable host CPU, NUMA, and memory discovery probe interface.
pub trait SystemProbe {
    /// Probes the host OS for CPU cores, cache groups, NUMA domains, and memory pools.
    ///
    /// # Returns
    ///
    /// [`DiscoveredSystemTopology`] snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`](arbiter_core::error::ArbiterError::ProbeFailed) on collection or parse failure.
    fn probe_system(&self) -> ArbiterResult<DiscoveredSystemTopology>;
}

/// Pluggable multi-vendor GPU discovery and telemetry probe interface (`NVIDIA`, `AMD`, `Apple`, `Intel`).
pub trait GpuProbe {
    /// Probes available GPU devices, partitions, VRAM, and interconnect links.
    ///
    /// # Returns
    ///
    /// Tuple of `(Vec<GpuDevice>, Vec<InterconnectEdge>)` representing discovered GPUs and their
    /// `NVLink`/`NVSwitch`/Infinity Fabric edges.
    ///
    /// # Errors
    ///
    /// Returns vendor-specific probe errors (`NvmlError`, `RocmError`, `MetalError`, `LevelZeroError`).
    fn probe_gpus(&self) -> ArbiterResult<(Vec<GpuDevice>, Vec<InterconnectEdge>)>;
}

/// Pluggable Google Cloud TPU and Coral Edge TPU discovery probe interface.
pub trait TpuProbe {
    /// Probes `/dev/accel*` / `/dev/vfio/*` TPU chips, HBM memory, and 2D/3D ICI torus coordinates.
    ///
    /// # Returns
    ///
    /// Vector of discovered [`TpuDevice`]s.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::TpuDriverError`](arbiter_core::error::ArbiterError::TpuDriverError) on driver error.
    fn probe_tpus(&self) -> ArbiterResult<Vec<TpuDevice>>;
}

/// Pluggable high-speed interconnect and RDMA NIC discovery probe interface.
pub trait FabricProbe {
    /// Probes `PCIe` switches, `InfiniBand`/`RoCE` (`ibverbs`), FreeBSD `VNET`, and illumos Crossbow (`dladm`) links.
    ///
    /// # Returns
    ///
    /// Tuple `(Vec<RdmaDevice>, Vec<InterconnectEdge>)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`](arbiter_core::error::ArbiterError::ProbeFailed) on discovery failure.
    fn probe_fabric(&self) -> ArbiterResult<(Vec<RdmaDevice>, Vec<InterconnectEdge>)>;
}
