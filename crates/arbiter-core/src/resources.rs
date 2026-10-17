//! CPU, Memory, Multi-Vendor GPU, Cloud/Edge TPU, Storage, Network, and aggregate `ResourceBundle` models.
//!
//! Provides exact, checked fixed-point resource algebra across scalar resources, port ranges,
//! GPU partitions (Whole, NVIDIA MIG, MPS/Time-Sliced, AMD XCD/NPS, Intel Tile, Apple Metal/ANE),
//! and 2D/3D torus TPU slices.

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{ArbiterError, ArbiterResult};
use crate::ids::{DeviceId, SliceId};
use crate::units::{
    BandwidthBps, Bytes, FrequencyMegahertz, GpuMillicores, Millicores, PortSet, TpuChips,
    WeightBasisPoints,
};

/// Heterogeneous CPU core microarchitecture classification.
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
pub enum CpuCoreClass {
    /// High-performance core (e.g., Apple Silicon P-core, Intel P-core).
    PerformanceCore,
    /// Energy-efficient core (e.g., Apple Silicon E-core, Intel E-core).
    EfficiencyCore,
    /// Homogeneous server/workstation core (e.g., AMD EPYC, Xeon SP, Ampere Altra).
    StandardCore,
}

/// Hardware vector or matrix instruction set extensions supported by a CPU core.
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
pub enum CpuInstructionExtension {
    /// x86 256-bit Advanced Vector Extensions 2.
    Avx2,
    /// x86 512-bit Advanced Vector Extensions.
    Avx512,
    /// Intel Advanced Matrix Extensions.
    Amx,
    /// ARM Advanced SIMD (`NEON`).
    Neon,
    /// ARM Scalable Vector Extension (`SVE` / `SVE2`).
    Sve,
}

/// Hardware topology and capability descriptor for an individual CPU core/thread.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct CoreDescriptor {
    /// Logical OS hardware thread ID.
    pub hardware_thread_id: u32,
    /// Physical core ID on the socket.
    pub physical_core_id: u32,
    /// NUMA node index owning this core.
    pub numa_node_id: u32,
    /// L1 cache group identifier.
    pub l1_cache_group_id: u32,
    /// L2 cache group identifier.
    pub l2_cache_group_id: u32,
    /// L3 / LLC cache group identifier.
    pub l3_cache_group_id: u32,
    /// Microarchitectural performance class.
    pub core_class: CpuCoreClass,
    /// Base clock frequency in MHz.
    pub base_frequency: FrequencyMegahertz,
    /// Max turbo/boost clock frequency in MHz.
    pub boost_frequency: FrequencyMegahertz,
    /// Supported SIMD/matrix instruction extensions.
    pub extensions: Vec<CpuInstructionExtension>,
}

/// Aggregate CPU compute resource specification or capacity.
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct CpuResource {
    /// Total compute capacity in millicores.
    pub millicores: Millicores,
    /// Optional preferred core class filter (`PerformanceCore` vs `EfficiencyCore`).
    pub preferred_core_class: Option<CpuCoreClass>,
    /// Required CPU instruction set extensions.
    pub required_extensions: Vec<CpuInstructionExtension>,
}

/// `HugePage` size classes for TLB-optimized memory allocations.
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
pub enum HugePageSize {
    /// 2 MiB huge pages.
    Size2MiB,
    /// 1 GiB huge pages.
    Size1GiB,
}

/// Per-NUMA-node memory pool capacity and bandwidth descriptor.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct NumaMemoryPool {
    /// NUMA domain identifier.
    pub numa_node_id: u32,
    /// Regular page RAM capacity in bytes.
    pub ram_bytes: Bytes,
    /// 2 MiB hugepage pool capacity in bytes.
    pub hugepages_2mib_bytes: Bytes,
    /// 1 GiB hugepage pool capacity in bytes.
    pub hugepages_1gib_bytes: Bytes,
    /// Peak memory controller bandwidth in bits per second.
    pub bandwidth: BandwidthBps,
    /// Whether this pool is unified with GPU/NPU memory (e.g., Apple Silicon or AMD APU).
    pub unified_memory: bool,
}

/// Memory resource requirement or capacity summary.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct MemoryResource {
    /// Standard system RAM in bytes.
    pub ram_bytes: Bytes,
    /// 2 MiB hugepages in bytes.
    pub hugepages_2mib_bytes: Bytes,
    /// 1 GiB hugepages in bytes.
    pub hugepages_1gib_bytes: Bytes,
    /// Whether unified CPU/GPU memory is required.
    pub require_unified_memory: bool,
}

/// Hardware GPU vendor taxonomy.
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
pub enum GpuVendor {
    /// NVIDIA Data Center / Workstation GPUs (`H100`, `H200`, `B200`, `A100`, `L40S`).
    Nvidia,
    /// AMD Instinct / Radeon GPUs (`MI300X`, `MI325X`, `MI250X`).
    Amd,
    /// Apple Silicon Integrated GPUs (`M1`..`M4 Max/Ultra`).
    Apple,
    /// Intel Data Center GPU Max / Arc (`Ponte Vecchio`, `Gaudi`).
    Intel,
}

/// Hardware-isolated NVIDIA Multi-Instance GPU (MIG) profile taxonomy.
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
pub enum NvidiaMigProfile {
    /// 1 compute slice (1/7), 5 GB VRAM (`A100 40GB`).
    Mig1g5gb,
    /// 2 compute slices (2/7), 10 GB VRAM (`A100 40GB`).
    Mig2g10gb,
    /// 3 compute slices (3/7), 20 GB VRAM (`A100 40GB`).
    Mig3g20gb,
    /// 4 compute slices (4/7), 20 GB VRAM (`A100 40GB`).
    Mig4g20gb,
    /// 7 compute slices (7/7), 40 GB VRAM (`A100 40GB`).
    Mig7g40gb,
    /// 1 compute slice (1/7), 10 GB VRAM (`A100 80GB` / `H100 80GB`).
    Mig1g10gb,
    /// 2 compute slices (2/7), 20 GB VRAM (`A100 80GB` / `H100 80GB`).
    Mig2g20gb,
    /// 3 compute slices (3/7), 40 GB VRAM (`A100 80GB` / `H100 80GB`).
    Mig3g40gb,
    /// 4 compute slices (4/7), 40 GB VRAM (`A100 80GB` / `H100 80GB`).
    Mig4g40gb,
    /// 7 compute slices (7/7), 80 GB VRAM (`A100 80GB` / `H100 80GB`).
    Mig7g80gb,
}

impl NvidiaMigProfile {
    /// Parses a canonical MIG profile string (e.g., `"1g.10gb"`, `"3g.40gb"`) into an [`NvidiaMigProfile`].
    ///
    /// # Arguments
    ///
    /// * `profile` - Canonical NVIDIA MIG profile string.
    ///
    /// # Returns
    ///
    /// Validated [`NvidiaMigProfile`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidMigProfile`] if the profile name is unrecognized.
    pub fn parse(profile: &str) -> ArbiterResult<Self> {
        match profile {
            "1g.5gb" => Ok(Self::Mig1g5gb),
            "2g.10gb" => Ok(Self::Mig2g10gb),
            "3g.20gb" => Ok(Self::Mig3g20gb),
            "4g.20gb" => Ok(Self::Mig4g20gb),
            "7g.40gb" => Ok(Self::Mig7g40gb),
            "1g.10gb" => Ok(Self::Mig1g10gb),
            "2g.20gb" => Ok(Self::Mig2g20gb),
            "3g.40gb" => Ok(Self::Mig3g40gb),
            "4g.40gb" => Ok(Self::Mig4g40gb),
            "7g.80gb" => Ok(Self::Mig7g80gb),
            _ => Err(ArbiterError::InvalidMigProfile {
                profile: profile.to_owned(),
                reason: "unsupported NVIDIA MIG profile identifier".to_owned(),
            }),
        }
    }

    /// Returns the canonical string representation of this MIG profile.
    ///
    /// # Returns
    ///
    /// Static MIG profile string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mig1g5gb => "1g.5gb",
            Self::Mig2g10gb => "2g.10gb",
            Self::Mig3g20gb => "3g.20gb",
            Self::Mig4g20gb => "4g.20gb",
            Self::Mig7g40gb => "7g.40gb",
            Self::Mig1g10gb => "1g.10gb",
            Self::Mig2g20gb => "2g.20gb",
            Self::Mig3g40gb => "3g.40gb",
            Self::Mig4g40gb => "4g.40gb",
            Self::Mig7g80gb => "7g.80gb",
        }
    }

    /// Returns the number of MIG compute slices (`1..=7`) consumed by this profile.
    ///
    /// # Returns
    ///
    /// Compute slice count (`u32`).
    pub const fn compute_slices(self) -> u32 {
        match self {
            Self::Mig1g5gb | Self::Mig1g10gb => 1,
            Self::Mig2g10gb | Self::Mig2g20gb => 2,
            Self::Mig3g20gb | Self::Mig3g40gb => 3,
            Self::Mig4g20gb | Self::Mig4g40gb => 4,
            Self::Mig7g40gb | Self::Mig7g80gb => 7,
        }
    }

    /// Returns the approximate GPU millicores equivalent for this MIG slice (out of `1000gm`).
    ///
    /// # Returns
    ///
    /// [`GpuMillicores`] equivalent.
    pub const fn gpu_millicores(self) -> GpuMillicores {
        match self {
            Self::Mig1g5gb | Self::Mig1g10gb => GpuMillicores::new(142),
            Self::Mig2g10gb | Self::Mig2g20gb => GpuMillicores::new(285),
            Self::Mig3g20gb | Self::Mig3g40gb => GpuMillicores::new(428),
            Self::Mig4g20gb | Self::Mig4g40gb => GpuMillicores::new(571),
            Self::Mig7g40gb | Self::Mig7g80gb => GpuMillicores::new(1000),
        }
    }

    /// Returns the dedicated VRAM capacity in bytes for this MIG profile.
    ///
    /// # Returns
    ///
    /// [`Bytes`] of VRAM.
    pub const fn vram_bytes(self) -> Bytes {
        const GIB: u64 = 1024 * 1024 * 1024;
        match self {
            Self::Mig1g5gb => Bytes::new(5 * GIB),
            Self::Mig2g10gb | Self::Mig1g10gb => Bytes::new(10 * GIB),
            Self::Mig3g20gb | Self::Mig4g20gb | Self::Mig2g20gb => Bytes::new(20 * GIB),
            Self::Mig7g40gb | Self::Mig3g40gb | Self::Mig4g40gb => Bytes::new(40 * GIB),
            Self::Mig7g80gb => Bytes::new(80 * GIB),
        }
    }
}

/// AMD Instinct spatial compute partition mode (`SPX`, `DPX`, `TPX`, `QPX`, `CPX`).
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
pub enum AmdComputePartitionMode {
    /// Single Partition Accelerator (`SPX` - 1 logical device).
    Spx,
    /// Dual Partition Accelerator (`DPX` - 2 logical devices).
    Dpx,
    /// Triple Partition Accelerator (`TPX` - 3 logical devices).
    Tpx,
    /// Quad Partition Accelerator (`QPX` - 4 logical devices).
    Qpx,
    /// Core Partitioned Accelerator (`CPX` - 8 logical XCD devices on MI300X).
    Cpx,
}

/// AMD Instinct memory NUMA partition mode (`NPS1`, `NPS2`, `NPS4`).
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
pub enum AmdMemoryPartitionMode {
    /// Single memory NUMA domain across all HBM stacks.
    Nps1,
    /// Two memory NUMA domains.
    Nps2,
    /// Four memory NUMA domains.
    Nps4,
}

/// Hardware-isolated NVIDIA MIG instance partition specification.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct NvidiaMigPartition {
    /// MIG profile specification.
    pub profile: NvidiaMigProfile,
    /// Hardware MIG instance index (`0..7`).
    pub instance_index: u32,
}

/// Fractional NVIDIA MPS or time-sliced compute + strict VRAM limit.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct NvidiaMpsPartition {
    /// Compute weight share in basis points (`1..=10_000`).
    pub compute_share: WeightBasisPoints,
    /// Hard VRAM cap in bytes.
    pub vram_cap: Bytes,
}

/// AMD Instinct spatial XCD and NPS memory partition slice.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AmdPartitionSlice {
    /// Spatial compute mode.
    pub compute_mode: AmdComputePartitionMode,
    /// Memory NUMA mode.
    pub memory_mode: AmdMemoryPartitionMode,
    /// Partition index.
    pub partition_index: u32,
}

/// Intel Level Zero sub-device tile allocation.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IntelTilePartition {
    /// Tile index (`0` or `1` on PVC).
    pub tile_index: u32,
    /// Dedicated HBM capacity on the tile.
    pub vram_bytes: Bytes,
}

/// Apple Silicon Metal GPU core slice + optional Neural Engine (ANE) co-allocation.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AppleMetalPartition {
    /// Number of Apple GPU cores reserved.
    pub gpu_cores: u32,
    /// Unified memory reservation in bytes.
    pub unified_memory_bytes: Bytes,
    /// Whether the 16/32-core Apple Neural Engine (ANE) is co-allocated.
    pub include_neural_engine: bool,
}

/// GPU partitioning and isolation mode for a device or task allocation.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum GpuPartition {
    /// Exclusive allocation of the entire physical GPU.
    WholeDevice,
    /// Hardware-isolated NVIDIA MIG instance.
    NvidiaMig(NvidiaMigPartition),
    /// Fractional NVIDIA MPS or time-sliced compute + strict VRAM limit.
    NvidiaMps(NvidiaMpsPartition),
    /// AMD Instinct spatial XCD and NPS memory partition slice.
    AmdComputePartition(AmdPartitionSlice),
    /// Intel Level Zero sub-device tile allocation.
    IntelTile(IntelTilePartition),
    /// Apple Silicon Metal GPU core slice + optional Neural Engine (ANE) co-allocation.
    AppleMetalSlice(AppleMetalPartition),
}

/// Physical or logical GPU device descriptor tracked by an Agent.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct GpuDevice {
    /// Unique hardware device identifier.
    pub device_id: DeviceId,
    /// GPU hardware vendor.
    pub vendor: GpuVendor,
    /// Model name (e.g., `"NVIDIA H100 80GB HBM3"`, `"AMD Instinct MI300X"`).
    pub model_name: String,
    /// Affinitized CPU NUMA node index.
    pub numa_node_id: u32,
    /// Total available GPU compute millicores (`1000gm` for a full unallocated GPU).
    pub available_compute: GpuMillicores,
    /// Total available VRAM in bytes.
    pub available_vram: Bytes,
    /// Active or supported partition configuration.
    pub partition: GpuPartition,
}

/// Google Cloud TPU and Coral Edge TPU hardware generation taxonomy.
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
pub enum TpuGeneration {
    /// Google Cloud TPU v4 (3D optical circuit switched torus).
    CloudTpuV4,
    /// Google Cloud TPU v5litePod (`v5e` 2D torus).
    CloudTpuV5litePod,
    /// Google Cloud TPU v5p (high-performance 3D torus).
    CloudTpuV5p,
    /// Google Cloud TPU v6e (`Trillium` 2D torus).
    CloudTpuV6e,
    /// Coral Edge TPU PCIe/USB accelerator.
    EdgeTpu,
}

impl TpuGeneration {
    /// Returns the number of `TensorCores` per physical TPU chip for this generation.
    ///
    /// # Returns
    ///
    /// Number of `TensorCores` (`1` or `2`).
    pub const fn tensor_cores_per_chip(self) -> u32 {
        match self {
            Self::CloudTpuV4 | Self::CloudTpuV5p => 2,
            Self::CloudTpuV5litePod | Self::CloudTpuV6e | Self::EdgeTpu => 1,
        }
    }
}

/// 3D torus coordinates `(x, y, z)` for a TPU chip within a Pod slice.
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
pub struct TorusCoordinate {
    /// X coordinate on the ICI torus.
    pub x: u32,
    /// Y coordinate on the ICI torus.
    pub y: u32,
    /// Z coordinate on the ICI torus (`0` for 2D slices).
    pub z: u32,
}

/// Physical TPU chip descriptor tracked by an Agent.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct TpuDevice {
    /// Unique TPU chip device ID.
    pub device_id: DeviceId,
    /// Hardware TPU generation.
    pub generation: TpuGeneration,
    /// Chip index on the host (`0..8`).
    pub chip_index: u32,
    /// High-Bandwidth Memory (HBM) capacity in bytes.
    pub hbm_bytes: Bytes,
    /// 3D torus coordinate of this chip inside its TPU Pod.
    pub coordinate: TorusCoordinate,
    /// Whether all Inter-Chip Interconnect (ICI) optical/copper links on this chip are healthy.
    pub ici_links_healthy: bool,
    /// Whether wrap-around torus links are enabled on this chip's axes.
    pub wrap_around_links: bool,
    /// Multi-host TPU Pod slice identifier.
    pub slice_id: SliceId,
}

/// Contiguous 2D/3D torus TPU Pod slice requirement or reservation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct TpuTopologySlice {
    /// Identifier of the TPU slice.
    pub slice_id: SliceId,
    /// Required TPU hardware generation.
    pub generation: TpuGeneration,
    /// Torus X dimension (`>= 1`).
    pub dim_x: u32,
    /// Torus Y dimension (`>= 1`).
    pub dim_y: u32,
    /// Torus Z dimension (`>= 1`).
    pub dim_z: u32,
    /// Whether wrap-around ICI links are required (for full torus dimensions).
    pub require_wrap_around: bool,
}

impl TpuTopologySlice {
    /// Validates and constructs a new [`TpuTopologySlice`].
    ///
    /// # Arguments
    ///
    /// * `slice_id` - Unique slice identifier.
    /// * `generation` - TPU hardware generation.
    /// * `dims` - Tuple `(dim_x, dim_y, dim_z)` of torus dimensions.
    /// * `require_wrap_around` - Whether wrap-around torus links are required.
    ///
    /// # Returns
    ///
    /// A validated [`TpuTopologySlice`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidTpuTopologySlice`] if any dimension is `0` or if
    /// a 2D-only generation (`CloudTpuV5litePod`, `CloudTpuV6e`, `EdgeTpu`) specifies `dim_z > 1`.
    pub fn new(
        slice_id: SliceId,
        generation: TpuGeneration,
        dims: (u32, u32, u32),
        require_wrap_around: bool,
    ) -> ArbiterResult<Self> {
        let (dim_x, dim_y, dim_z) = dims;
        if dim_x == 0 || dim_y == 0 || dim_z == 0 {
            return Err(ArbiterError::InvalidTpuTopologySlice {
                slice: slice_id.to_string(),
                reason: "torus dimensions (x, y, z) must all be >= 1".to_owned(),
            });
        }
        let is_2d_only = matches!(
            generation,
            TpuGeneration::CloudTpuV5litePod | TpuGeneration::CloudTpuV6e | TpuGeneration::EdgeTpu
        );
        if is_2d_only && dim_z > 1 {
            return Err(ArbiterError::InvalidTpuTopologySlice {
                slice: slice_id.to_string(),
                reason: "2D TPU generation cannot have dim_z > 1".to_owned(),
            });
        }
        Ok(Self {
            slice_id,
            generation,
            dim_x,
            dim_y,
            dim_z,
            require_wrap_around,
        })
    }

    /// Computes the total number of TPU chips in this 3D torus (`dim_x * dim_y * dim_z`).
    ///
    /// Since each dimension is a `u32`, their product is at most `(2^32 - 1)^3`, so we
    /// compute in `u128` and convert to `u64`.
    ///
    /// # Returns
    ///
    /// Total [`TpuChips`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArithmeticOverflow`] if the product exceeds `u64::MAX`.
    pub fn total_chips(&self) -> ArbiterResult<TpuChips> {
        let product = u128::from(self.dim_x) * u128::from(self.dim_y) * u128::from(self.dim_z);
        let chips = u64::try_from(product).map_err(|_| ArbiterError::ArithmeticOverflow {
            operation: "TpuTopologySlice::total_chips".to_owned(),
        })?;
        Ok(TpuChips::new(chips))
    }
}

/// Storage media and ZFS dataset classification.
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
pub enum DiskClass {
    /// Local `PCIe` `NVMe` flash drive.
    Nvme,
    /// SATA/SAS solid-state drive.
    Ssd,
    /// Rotational hard disk drive.
    Hdd,
    /// Delegated or cloned ZFS dataset (`FreeBSD`, `illumos`, `Linux`).
    ZfsDataset,
    /// Ephemeral in-memory `tmpfs` / `ramdisk`.
    RamDisk,
}

/// Storage capacity and I/O throughput resource descriptor.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct StorageResource {
    /// Disk capacity in bytes.
    pub capacity_bytes: Bytes,
    /// Maximum read/write IOPS cap (`0` if unlimited).
    pub max_iops: u64,
    /// Maximum sequential throughput in bits per second.
    pub throughput_bps: BandwidthBps,
    /// Optional required storage media class.
    pub disk_class: Option<DiskClass>,
}

/// High-speed RDMA and OS virtualized network interface fabric kinds.
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
pub enum RdmaFabricKind {
    /// Native `InfiniBand` (`NDR` / `HDR` / `EDR`).
    InfiniBand,
    /// RDMA over Converged Ethernet v2 (`RoCEv2`).
    RoCEv2,
    /// AWS Elastic Fabric Adapter (`EFA`).
    Efa,
    /// illumos Crossbow hardware-ring virtual NIC (`dladm`).
    CrossbowVnic,
    /// FreeBSD `VNET` virtualized network stack interface.
    FreeBsdVnet,
}

/// RDMA or high-speed fabric network device descriptor.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct RdmaDevice {
    /// Hardware device identifier (e.g., `mlx5_0`).
    pub device_id: DeviceId,
    /// Fabric technology kind.
    pub fabric_kind: RdmaFabricKind,
    /// Affinitized NUMA node index.
    pub numa_node_id: u32,
    /// Line-rate bandwidth in bits per second.
    pub bandwidth: BandwidthBps,
    /// Number of available SR-IOV virtual functions (`VFs`).
    pub sriov_vfs: u32,
}

/// Network bandwidth, port set, and RDMA fabric resource descriptor.
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct NetworkResource {
    /// Allocated or available network port ranges.
    pub ports: PortSet,
    /// Ingress bandwidth capacity or cap in bits per second.
    pub ingress_bps: BandwidthBps,
    /// Egress bandwidth capacity or cap in bits per second.
    pub egress_bps: BandwidthBps,
    /// Number of SR-IOV / RDMA virtual functions required or available.
    pub rdma_vfs: u32,
}

/// Aggregate multi-dimensional resource bundle supporting exact checked resource algebra.
///
/// Tracks CPU millicores, RAM, `HugePages`, GPU compute millicores, GPU VRAM, TPU chips,
/// disk storage capacity, network ingress/egress bandwidth, and discrete [`PortSet`]s.
#[must_use]
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ResourceBundle {
    /// CPU compute capacity in millicores.
    pub cpu: Millicores,
    /// System RAM capacity in bytes.
    pub memory: Bytes,
    /// `HugePage` memory capacity in bytes.
    pub hugepages: Bytes,
    /// Aggregate GPU compute capacity in GPU millicores (`1000gm = 1 whole GPU`).
    pub gpu_compute: GpuMillicores,
    /// Aggregate GPU VRAM capacity in bytes.
    pub gpu_vram: Bytes,
    /// Aggregate TPU chip count.
    pub tpu_chips: TpuChips,
    /// Local storage capacity in bytes.
    pub disk: Bytes,
    /// Network bandwidth capacity in bits per second.
    pub network_bandwidth: BandwidthBps,
    /// Discrete network port ranges.
    pub ports: PortSet,
}

impl ResourceBundle {
    /// Creates an empty [`ResourceBundle`] with all zero quantities.
    ///
    /// # Returns
    ///
    /// Zeroed [`ResourceBundle`].
    pub const fn zero() -> Self {
        Self {
            cpu: Millicores::ZERO,
            memory: Bytes::ZERO,
            hugepages: Bytes::ZERO,
            gpu_compute: GpuMillicores::ZERO,
            gpu_vram: Bytes::ZERO,
            tpu_chips: TpuChips::ZERO,
            disk: Bytes::ZERO,
            network_bandwidth: BandwidthBps::ZERO,
            ports: PortSet::empty(),
        }
    }

    /// Returns `true` if every scalar resource and port set in this bundle is zero/empty.
    ///
    /// # Returns
    ///
    /// `true` if completely empty.
    pub fn is_empty(&self) -> bool {
        self.cpu.is_zero()
            && self.memory.is_zero()
            && self.hugepages.is_zero()
            && self.gpu_compute.is_zero()
            && self.gpu_vram.is_zero()
            && self.tpu_chips.is_zero()
            && self.disk.is_zero()
            && self.network_bandwidth.is_zero()
            && self.ports.total_ports() == 0
    }

    /// Checks whether `self` has at least as much of every resource dimension as `other`.
    ///
    /// # Arguments
    ///
    /// * `other` - Requested or subset resource bundle.
    ///
    /// # Returns
    ///
    /// `true` if `self` can satisfy `other`.
    pub fn contains(&self, other: &Self) -> bool {
        self.cpu >= other.cpu
            && self.memory >= other.memory
            && self.hugepages >= other.hugepages
            && self.gpu_compute >= other.gpu_compute
            && self.gpu_vram >= other.gpu_vram
            && self.tpu_chips >= other.tpu_chips
            && self.disk >= other.disk
            && self.network_bandwidth >= other.network_bandwidth
            && self.ports.contains(&other.ports)
    }

    /// Checked addition of two [`ResourceBundle`]s.
    ///
    /// # Arguments
    ///
    /// * `other` - Bundle to add to `self`.
    ///
    /// # Returns
    ///
    /// Combined [`ResourceBundle`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArithmeticOverflow`] if any scalar dimension overflows `u64::MAX`.
    pub fn try_add(&self, other: &Self) -> ArbiterResult<Self> {
        Ok(Self {
            cpu: self.cpu.checked_add(other.cpu)?,
            memory: self.memory.checked_add(other.memory)?,
            hugepages: self.hugepages.checked_add(other.hugepages)?,
            gpu_compute: self.gpu_compute.checked_add(other.gpu_compute)?,
            gpu_vram: self.gpu_vram.checked_add(other.gpu_vram)?,
            tpu_chips: self.tpu_chips.checked_add(other.tpu_chips)?,
            disk: self.disk.checked_add(other.disk)?,
            network_bandwidth: self
                .network_bandwidth
                .checked_add(other.network_bandwidth)?,
            ports: self.ports.union(&other.ports),
        })
    }

    /// Checked subtraction of `other` from `self`.
    ///
    /// # Arguments
    ///
    /// * `other` - Bundle to subtract from `self`.
    ///
    /// # Returns
    ///
    /// Remaining [`ResourceBundle`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InsufficientResources`] if any resource in `self` is smaller
    /// than `other`.
    pub fn try_sub(&self, other: &Self) -> ArbiterResult<Self> {
        if self.cpu < other.cpu {
            return Err(ArbiterError::InsufficientResources {
                resource: "cpu".to_owned(),
                requested: other.cpu.get(),
                available: self.cpu.get(),
            });
        }
        if self.memory < other.memory {
            return Err(ArbiterError::InsufficientResources {
                resource: "memory".to_owned(),
                requested: other.memory.get(),
                available: self.memory.get(),
            });
        }
        if self.hugepages < other.hugepages {
            return Err(ArbiterError::InsufficientResources {
                resource: "hugepages".to_owned(),
                requested: other.hugepages.get(),
                available: self.hugepages.get(),
            });
        }
        if self.gpu_compute < other.gpu_compute {
            return Err(ArbiterError::InsufficientResources {
                resource: "gpu_compute".to_owned(),
                requested: other.gpu_compute.get(),
                available: self.gpu_compute.get(),
            });
        }
        if self.gpu_vram < other.gpu_vram {
            return Err(ArbiterError::InsufficientResources {
                resource: "gpu_vram".to_owned(),
                requested: other.gpu_vram.get(),
                available: self.gpu_vram.get(),
            });
        }
        if self.tpu_chips < other.tpu_chips {
            return Err(ArbiterError::InsufficientResources {
                resource: "tpu_chips".to_owned(),
                requested: other.tpu_chips.get(),
                available: self.tpu_chips.get(),
            });
        }
        if self.disk < other.disk {
            return Err(ArbiterError::InsufficientResources {
                resource: "disk".to_owned(),
                requested: other.disk.get(),
                available: self.disk.get(),
            });
        }
        if self.network_bandwidth < other.network_bandwidth {
            return Err(ArbiterError::InsufficientResources {
                resource: "network_bandwidth".to_owned(),
                requested: other.network_bandwidth.get(),
                available: self.network_bandwidth.get(),
            });
        }
        let ports = self.ports.try_sub(&other.ports)?;
        Ok(Self {
            cpu: self.cpu.saturating_sub(other.cpu),
            memory: self.memory.saturating_sub(other.memory),
            hugepages: self.hugepages.saturating_sub(other.hugepages),
            gpu_compute: self.gpu_compute.saturating_sub(other.gpu_compute),
            gpu_vram: self.gpu_vram.saturating_sub(other.gpu_vram),
            tpu_chips: self.tpu_chips.saturating_sub(other.tpu_chips),
            disk: self.disk.saturating_sub(other.disk),
            network_bandwidth: self
                .network_bandwidth
                .saturating_sub(other.network_bandwidth),
            ports,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::units::{PortNumber, PortRange};

    #[test]
    fn test_nvidia_mig_profiles() {
        let cases = [
            ("1g.5gb", NvidiaMigProfile::Mig1g5gb, 1, 142, 5),
            ("2g.10gb", NvidiaMigProfile::Mig2g10gb, 2, 285, 10),
            ("3g.20gb", NvidiaMigProfile::Mig3g20gb, 3, 428, 20),
            ("4g.20gb", NvidiaMigProfile::Mig4g20gb, 4, 571, 20),
            ("7g.40gb", NvidiaMigProfile::Mig7g40gb, 7, 1000, 40),
            ("1g.10gb", NvidiaMigProfile::Mig1g10gb, 1, 142, 10),
            ("2g.20gb", NvidiaMigProfile::Mig2g20gb, 2, 285, 20),
            ("3g.40gb", NvidiaMigProfile::Mig3g40gb, 3, 428, 40),
            ("4g.40gb", NvidiaMigProfile::Mig4g40gb, 4, 571, 40),
            ("7g.80gb", NvidiaMigProfile::Mig7g80gb, 7, 1000, 80),
        ];

        for (name, expected, slices, gm, gib) in cases {
            assert_eq!(NvidiaMigProfile::parse(name), Ok(expected));
            assert_eq!(expected.as_str(), name);
            assert_eq!(expected.compute_slices(), slices);
            assert_eq!(expected.gpu_millicores(), GpuMillicores::new(gm));
            assert_eq!(expected.vram_bytes(), Bytes::new(gib * 1024 * 1024 * 1024));
        }

        assert!(NvidiaMigProfile::parse("invalid.profile").is_err());
    }

    #[test]
    fn test_tpu_generation_and_topology_slice() {
        assert_eq!(TpuGeneration::CloudTpuV4.tensor_cores_per_chip(), 2);
        assert_eq!(TpuGeneration::CloudTpuV5p.tensor_cores_per_chip(), 2);
        assert_eq!(TpuGeneration::CloudTpuV5litePod.tensor_cores_per_chip(), 1);
        assert_eq!(TpuGeneration::CloudTpuV6e.tensor_cores_per_chip(), 1);
        assert_eq!(TpuGeneration::EdgeTpu.tensor_cores_per_chip(), 1);

        let slice_id = SliceId(String::from("slice-v5p-4x4x4"));

        assert!(
            TpuTopologySlice::new(
                slice_id.clone(),
                TpuGeneration::CloudTpuV5p,
                (0, 4, 4),
                true
            )
            .is_err()
        );
        assert!(
            TpuTopologySlice::new(
                slice_id.clone(),
                TpuGeneration::CloudTpuV5p,
                (4, 0, 4),
                true
            )
            .is_err()
        );
        assert!(
            TpuTopologySlice::new(
                slice_id.clone(),
                TpuGeneration::CloudTpuV5p,
                (4, 4, 0),
                true
            )
            .is_err()
        );

        // 2D generation with dim_z > 1 must fail
        assert!(
            TpuTopologySlice::new(
                slice_id.clone(),
                TpuGeneration::CloudTpuV6e,
                (4, 4, 2),
                false
            )
            .is_err()
        );

        // Valid 2D generation with dim_z == 1
        assert!(
            TpuTopologySlice::new(
                slice_id.clone(),
                TpuGeneration::CloudTpuV6e,
                (4, 4, 1),
                false
            )
            .is_ok()
        );

        // Valid 3D generation via TpuTopologySlice::new
        let valid_3d_res = TpuTopologySlice::new(
            slice_id.clone(),
            TpuGeneration::CloudTpuV5p,
            (4, 4, 4),
            true,
        );
        let valid_3d = TpuTopologySlice {
            slice_id: slice_id.clone(),
            generation: TpuGeneration::CloudTpuV5p,
            dim_x: 4,
            dim_y: 4,
            dim_z: 4,
            require_wrap_around: true,
        };
        assert_eq!(valid_3d_res, Ok(valid_3d.clone()));
        assert_eq!(valid_3d.total_chips(), Ok(TpuChips::new(64)));

        // Overflow u64 when dim_x * dim_y * dim_z > u64::MAX
        let overflow_slice = TpuTopologySlice {
            slice_id,
            generation: TpuGeneration::CloudTpuV5p,
            dim_x: u32::MAX,
            dim_y: u32::MAX,
            dim_z: u32::MAX,
            require_wrap_around: false,
        };
        assert!(overflow_slice.total_chips().is_err());
    }

    #[test]
    fn test_resource_bundle_add_sub_and_empty() {
        let empty = ResourceBundle::zero();
        assert!(empty.is_empty());

        let ports_a = PortSet::from_ranges(vec![PortRange {
            start: PortNumber(8000),
            end: PortNumber(8010),
        }]);
        let ports_b = PortSet::from_ranges(vec![PortRange {
            start: PortNumber(8000),
            end: PortNumber(8005),
        }]);

        let bundle_a = ResourceBundle {
            cpu: Millicores::new(4000),
            memory: Bytes::new(16_000),
            hugepages: Bytes::new(2_000),
            gpu_compute: GpuMillicores::new(2000),
            gpu_vram: Bytes::new(80_000),
            tpu_chips: TpuChips::new(4),
            disk: Bytes::new(100_000),
            network_bandwidth: BandwidthBps::new(10_000),
            ports: ports_a.clone(),
        };
        assert!(!bundle_a.is_empty());

        let bundle_b = ResourceBundle {
            cpu: Millicores::new(1000),
            memory: Bytes::new(4_000),
            hugepages: Bytes::new(1_000),
            gpu_compute: GpuMillicores::new(500),
            gpu_vram: Bytes::new(20_000),
            tpu_chips: TpuChips::new(2),
            disk: Bytes::new(25_000),
            network_bandwidth: BandwidthBps::new(2_500),
            ports: ports_b,
        };

        assert!(bundle_a.contains(&bundle_b));
        assert!(!bundle_b.contains(&bundle_a));

        let diff = bundle_a.try_sub(&bundle_b).unwrap_or_default();
        assert_eq!(diff.try_add(&bundle_b), Ok(bundle_a));

        let mut partial = ResourceBundle::zero();
        partial.ports = ports_a;
        assert!(!partial.is_empty());
        partial.network_bandwidth = BandwidthBps::new(1);
        assert!(!partial.is_empty());
        partial.disk = Bytes::new(1);
        assert!(!partial.is_empty());
        partial.tpu_chips = TpuChips::new(1);
        assert!(!partial.is_empty());
        partial.gpu_vram = Bytes::new(1);
        assert!(!partial.is_empty());
        partial.gpu_compute = GpuMillicores::new(1);
        assert!(!partial.is_empty());
        partial.hugepages = Bytes::new(1);
        assert!(!partial.is_empty());
        partial.memory = Bytes::new(1);
        assert!(!partial.is_empty());
    }

    #[test]
    fn test_resource_bundle_insufficient() {
        let base = ResourceBundle::zero();

        let mut req = ResourceBundle::zero();
        req.cpu = Millicores::new(1);
        assert!(!base.contains(&req));
        assert!(base.try_sub(&req).is_err());

        req = ResourceBundle::zero();
        req.memory = Bytes::new(1);
        assert!(!base.contains(&req));
        assert!(base.try_sub(&req).is_err());

        req = ResourceBundle::zero();
        req.hugepages = Bytes::new(1);
        assert!(!base.contains(&req));
        assert!(base.try_sub(&req).is_err());

        req = ResourceBundle::zero();
        req.gpu_compute = GpuMillicores::new(1);
        assert!(!base.contains(&req));
        assert!(base.try_sub(&req).is_err());

        req = ResourceBundle::zero();
        req.gpu_vram = Bytes::new(1);
        assert!(!base.contains(&req));
        assert!(base.try_sub(&req).is_err());

        req = ResourceBundle::zero();
        req.tpu_chips = TpuChips::new(1);
        assert!(!base.contains(&req));
        assert!(base.try_sub(&req).is_err());

        req = ResourceBundle::zero();
        req.disk = Bytes::new(1);
        assert!(!base.contains(&req));
        assert!(base.try_sub(&req).is_err());

        req = ResourceBundle::zero();
        req.network_bandwidth = BandwidthBps::new(1);
        assert!(!base.contains(&req));
        assert!(base.try_sub(&req).is_err());

        req = ResourceBundle::zero();
        req.ports = PortSet::from_ranges(vec![PortRange {
            start: PortNumber(80),
            end: PortNumber(80),
        }]);
        assert!(!base.contains(&req));
        assert!(base.try_sub(&req).is_err());
    }

    #[test]
    fn test_resource_bundle_overflow() {
        let unit = ResourceBundle {
            cpu: Millicores::new(1),
            memory: Bytes::new(1),
            hugepages: Bytes::new(1),
            gpu_compute: GpuMillicores::new(1),
            gpu_vram: Bytes::new(1),
            tpu_chips: TpuChips::new(1),
            disk: Bytes::new(1),
            network_bandwidth: BandwidthBps::new(1),
            ports: PortSet::empty(),
        };

        let mut max_b = ResourceBundle::zero();
        max_b.cpu = Millicores::MAX;
        assert!(max_b.try_add(&unit).is_err());

        max_b = ResourceBundle::zero();
        max_b.memory = Bytes::MAX;
        assert!(max_b.try_add(&unit).is_err());

        max_b = ResourceBundle::zero();
        max_b.hugepages = Bytes::MAX;
        assert!(max_b.try_add(&unit).is_err());

        max_b = ResourceBundle::zero();
        max_b.gpu_compute = GpuMillicores::MAX;
        assert!(max_b.try_add(&unit).is_err());

        max_b = ResourceBundle::zero();
        max_b.gpu_vram = Bytes::MAX;
        assert!(max_b.try_add(&unit).is_err());

        max_b = ResourceBundle::zero();
        max_b.tpu_chips = TpuChips::MAX;
        assert!(max_b.try_add(&unit).is_err());

        max_b = ResourceBundle::zero();
        max_b.disk = Bytes::MAX;
        assert!(max_b.try_add(&unit).is_err());

        max_b = ResourceBundle::zero();
        max_b.network_bandwidth = BandwidthBps::MAX;
        assert!(max_b.try_add(&unit).is_err());
    }

    proptest! {
        #[test]
        fn prop_resource_bundle_conservation(
            cpu_a in 0..=1_000_000_u64,
            mem_a in 0..=1_000_000_000_u64,
            cpu_b in 0..=1_000_000_u64,
            mem_b in 0..=1_000_000_000_u64,
        ) {
            let a = ResourceBundle {
                cpu: Millicores::new(cpu_a),
                memory: Bytes::new(mem_a),
                ..ResourceBundle::zero()
            };
            let b = ResourceBundle {
                cpu: Millicores::new(cpu_b),
                memory: Bytes::new(mem_b),
                ..ResourceBundle::zero()
            };
            let sum = a.try_add(&b).unwrap_or_default();
            prop_assert!(sum.contains(&a));
            prop_assert!(sum.contains(&b));
            prop_assert_eq!(sum.try_sub(&b), Ok(a));
        }
    }
}
