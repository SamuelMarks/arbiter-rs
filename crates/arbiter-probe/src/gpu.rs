//! Multi-vendor GPU discovery and deep telemetry probes (`NVIDIA`, `AMD`, `Apple`, `Intel`) (`arbiter-probe::gpu`).
//!
//! Implements [`GpuProbe`] collectors and telemetry structures for:
//! - **NVIDIA (`NvidiaNvmlProbe`)**: UUIDs, VRAM, MIG profiles/instances, `NVLink` topology links,
//!   utilization, ECC error counts, temperature, and power draw.
//! - **AMD `ROCm` (`AmdRocmProbe`)**: GPUs, XCD/NPS spatial/memory partitions, VRAM, Infinity Fabric links.
//! - **Apple Silicon (`AppleMetalProbe`)**: Apple GPU core counts, Metal unified memory reservation, Neural Engine (`ANE`).
//! - **Intel Level Zero (`IntelLevelZeroProbe`)**: `Xe` devices, sub-device tiles, HBM memory.

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::DeviceId;
use arbiter_core::resources::{
    AmdComputePartitionMode, AmdMemoryPartitionMode, AmdPartitionSlice, AppleMetalPartition,
    GpuDevice, GpuPartition, GpuVendor, IntelTilePartition, NvidiaMigPartition, NvidiaMigProfile,
};
use arbiter_core::topology::{InterconnectEdge, InterconnectKind};
use arbiter_core::units::{
    BandwidthBps, Bytes, GpuMillicores, LatencyNanoseconds, PowerMilliwatts,
    TemperatureMilliCelsius,
};
use serde::{Deserialize, Serialize};

use crate::traits::GpuProbe;

/// Real-time hardware telemetry sample for a single NVIDIA GPU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvidiaDeviceRecord {
    /// Device identifier (e.g., `"gpu-0"`).
    pub device_id: String,
    /// Model name (e.g., `"NVIDIA H100 80GB HBM3"`).
    pub model_name: String,
    /// Affinitized NUMA node.
    pub numa_node_id: u32,
    /// Total VRAM in bytes.
    pub vram_bytes: u64,
    /// Optional active MIG profile name (e.g., `"1g.10gb"`).
    pub active_mig_profile: Option<String>,
    /// Uncorrectable ECC memory error count (if `> 0`, probe rejects unhealthy GPU).
    pub uncorrectable_ecc_errors: u64,
    /// Core temperature in millicelsius.
    pub temperature: TemperatureMilliCelsius,
    /// Power draw in milliwatts.
    pub power_draw: PowerMilliwatts,
}

/// NVIDIA Management Library (`NVML`) GPU discovery and telemetry probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvidiaNvmlProbe {
    /// Whether the NVML driver initialized cleanly.
    pub driver_initialized: bool,
    /// Discovered raw NVIDIA device records.
    pub devices: Vec<NvidiaDeviceRecord>,
    /// Discovered `NVLink` peer pairs `(source_device_id, target_device_id)`.
    pub nvlink_pairs: Vec<(String, String)>,
}

impl GpuProbe for NvidiaNvmlProbe {
    fn probe_gpus(&self) -> ArbiterResult<(Vec<GpuDevice>, Vec<InterconnectEdge>)> {
        if !self.driver_initialized {
            return Err(ArbiterError::NvmlError {
                device: "nvml".to_owned(),
                reason: "NVML driver not loaded or initialization failed".to_owned(),
            });
        }

        let mut gpus = Vec::with_capacity(self.devices.len());
        for rec in &self.devices {
            if rec.uncorrectable_ecc_errors > 0 {
                return Err(ArbiterError::NvmlError {
                    device: rec.device_id.clone(),
                    reason: format!(
                        "unhealthy GPU: {} uncorrectable double-bit ECC errors detected",
                        rec.uncorrectable_ecc_errors
                    ),
                });
            }
            let dev_id = DeviceId::new(&rec.device_id).map_err(|_| ArbiterError::NvmlError {
                device: rec.device_id.clone(),
                reason: "invalid GPU device ID".to_owned(),
            })?;

            let (partition, compute_m, vram) = if let Some(ref mig_str) = rec.active_mig_profile {
                let profile = NvidiaMigProfile::parse(mig_str)?;
                (
                    GpuPartition::NvidiaMig(NvidiaMigPartition {
                        profile,
                        instance_index: 0,
                    }),
                    profile.gpu_millicores(),
                    profile.vram_bytes(),
                )
            } else {
                (
                    GpuPartition::WholeDevice,
                    GpuMillicores::new(1000),
                    Bytes::new(rec.vram_bytes),
                )
            };

            gpus.push(GpuDevice {
                device_id: dev_id,
                vendor: GpuVendor::Nvidia,
                model_name: rec.model_name.clone(),
                numa_node_id: rec.numa_node_id,
                available_compute: compute_m,
                available_vram: vram,
                partition,
            });
        }

        let mut edges = Vec::with_capacity(self.nvlink_pairs.len());
        for (src, dst) in &self.nvlink_pairs {
            let s_id = DeviceId::new(src)?;
            let d_id = DeviceId::new(dst)?;
            edges.push(InterconnectEdge {
                source: s_id,
                target: d_id,
                kind: InterconnectKind::NvLink,
                bandwidth: BandwidthBps::new(7_200_000_000_000),
                latency: LatencyNanoseconds::new(40),
            });
        }

        Ok((gpus, edges))
    }
}

/// AMD `ROCm` / SMI GPU discovery probe (`MI300X` / `MI250X`, XCD/NPS partitions, Infinity Fabric).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmdRocmProbe {
    /// Whether the `/dev/kfd` and `ROCm` SMI runtime is available.
    pub rocm_available: bool,
    /// Number of AMD GPUs or XCD partitions discovered.
    pub device_count: u32,
    /// VRAM per device in bytes.
    pub vram_per_device_bytes: u64,
    /// Spatial compute partition mode (`SPX`, `CPX`, etc.).
    pub compute_mode: AmdComputePartitionMode,
    /// Memory partition mode (`NPS1`, `NPS4`, etc.).
    pub memory_mode: AmdMemoryPartitionMode,
}

impl GpuProbe for AmdRocmProbe {
    fn probe_gpus(&self) -> ArbiterResult<(Vec<GpuDevice>, Vec<InterconnectEdge>)> {
        if !self.rocm_available || self.device_count == 0 {
            return Err(ArbiterError::RocmError {
                device: "kfd".to_owned(),
                reason: "ROCm /dev/kfd unavailable or zero devices found".to_owned(),
            });
        }

        let mut gpus = Vec::with_capacity(self.device_count as usize);
        let mut edges = Vec::new();

        for idx in 0..self.device_count {
            let dev_id = DeviceId::new(&format!("amd-gpu-{idx}")).unwrap_or_default();
            gpus.push(GpuDevice {
                device_id: dev_id.clone(),
                vendor: GpuVendor::Amd,
                model_name: "AMD Instinct MI300X".to_owned(),
                numa_node_id: 0,
                available_compute: GpuMillicores::new(1000),
                available_vram: Bytes::new(self.vram_per_device_bytes),
                partition: GpuPartition::AmdComputePartition(AmdPartitionSlice {
                    compute_mode: self.compute_mode,
                    memory_mode: self.memory_mode,
                    partition_index: idx,
                }),
            });
            if idx > 0 {
                let prev_id = DeviceId::new(&format!("amd-gpu-{}", idx - 1)).unwrap_or_default();
                edges.push(InterconnectEdge {
                    source: prev_id,
                    target: dev_id,
                    kind: InterconnectKind::AmdInfinityFabric,
                    bandwidth: BandwidthBps::new(7_168_000_000_000),
                    latency: LatencyNanoseconds::new(45),
                });
            }
        }

        Ok((gpus, edges))
    }
}

/// Apple Silicon Metal GPU and Neural Engine (`ANE`) probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleMetalProbe {
    /// Whether an Apple Silicon Metal device was detected.
    pub metal_available: bool,
    /// Number of integrated GPU cores (e.g., `40` on M3 Max, `80` on M3 Ultra).
    pub gpu_cores: u32,
    /// Unified memory available for Metal command buffers in bytes.
    pub unified_vram_bytes: u64,
    /// Whether the Apple Neural Engine (`ANE`) is present.
    pub neural_engine_present: bool,
}

impl GpuProbe for AppleMetalProbe {
    fn probe_gpus(&self) -> ArbiterResult<(Vec<GpuDevice>, Vec<InterconnectEdge>)> {
        if !self.metal_available || self.gpu_cores == 0 {
            return Err(ArbiterError::MetalError {
                reason: "Apple Metal device unavailable or zero GPU cores".to_owned(),
            });
        }

        let gpu = GpuDevice {
            device_id: DeviceId::new("apple-metal-0").unwrap_or_default(),
            vendor: GpuVendor::Apple,
            model_name: "Apple Silicon Metal GPU".to_owned(),
            numa_node_id: 0,
            available_compute: GpuMillicores::new(1000),
            available_vram: Bytes::new(self.unified_vram_bytes),
            partition: GpuPartition::AppleMetalSlice(AppleMetalPartition {
                gpu_cores: self.gpu_cores,
                unified_memory_bytes: Bytes::new(self.unified_vram_bytes),
                include_neural_engine: self.neural_engine_present,
            }),
        };

        Ok((vec![gpu], Vec::new()))
    }
}

/// Intel Level Zero (`Xe` / Data Center GPU Max) sub-device tile probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntelLevelZeroProbe {
    /// Whether `zeInit` succeeded.
    pub level_zero_initialized: bool,
    /// Number of Xe tiles discovered (`1` or `2` per PVC package).
    pub tile_count: u32,
    /// HBM memory per tile in bytes.
    pub hbm_per_tile_bytes: u64,
}

impl GpuProbe for IntelLevelZeroProbe {
    fn probe_gpus(&self) -> ArbiterResult<(Vec<GpuDevice>, Vec<InterconnectEdge>)> {
        if !self.level_zero_initialized || self.tile_count == 0 {
            return Err(ArbiterError::LevelZeroError {
                device: "ze0".to_owned(),
                reason: "Intel Level Zero zeInit failed or zero tiles found".to_owned(),
            });
        }

        let gpus = (0..self.tile_count)
            .map(|tile_idx| GpuDevice {
                device_id: DeviceId::new(&format!("intel-xe-tile-{tile_idx}")).unwrap_or_default(),
                vendor: GpuVendor::Intel,
                model_name: "Intel Data Center GPU Max 1550".to_owned(),
                numa_node_id: 0,
                available_compute: GpuMillicores::new(1000),
                available_vram: Bytes::new(self.hbm_per_tile_bytes),
                partition: GpuPartition::IntelTile(IntelTilePartition {
                    tile_index: tile_idx,
                    vram_bytes: Bytes::new(self.hbm_per_tile_bytes),
                }),
            })
            .collect();

        Ok((gpus, Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvidia_nvml_probe() {
        let nv = NvidiaNvmlProbe {
            driver_initialized: true,
            devices: vec![
                NvidiaDeviceRecord {
                    device_id: "gpu-0".to_owned(),
                    model_name: "NVIDIA H100".to_owned(),
                    numa_node_id: 0,
                    vram_bytes: 80 * 1024 * 1024 * 1024,
                    active_mig_profile: None,
                    uncorrectable_ecc_errors: 0,
                    temperature: TemperatureMilliCelsius::new(52_000),
                    power_draw: PowerMilliwatts::new(350_000),
                },
                NvidiaDeviceRecord {
                    device_id: "gpu-1".to_owned(),
                    model_name: "NVIDIA H100".to_owned(),
                    numa_node_id: 0,
                    vram_bytes: 80 * 1024 * 1024 * 1024,
                    active_mig_profile: Some("1g.10gb".to_owned()),
                    uncorrectable_ecc_errors: 0,
                    temperature: TemperatureMilliCelsius::new(48_000),
                    power_draw: PowerMilliwatts::new(120_000),
                },
            ],
            nvlink_pairs: vec![("gpu-0".to_owned(), "gpu-1".to_owned())],
        };
        let (gpus, edges) = nv.probe_gpus().unwrap_or_default();
        assert_eq!(gpus.len(), 2);
        assert_eq!(edges.len(), 1);

        // Driver not initialized
        assert!(
            NvidiaNvmlProbe {
                driver_initialized: false,
                ..nv.clone()
            }
            .probe_gpus()
            .is_err()
        );

        // ECC error rejection
        let mut ecc_nv = nv.clone();
        for d in &mut ecc_nv.devices {
            d.uncorrectable_ecc_errors = 2;
        }
        assert!(ecc_nv.probe_gpus().is_err());

        // Invalid device ID
        let mut bad_id_nv = nv.clone();
        for d in &mut bad_id_nv.devices {
            d.device_id = String::new();
        }
        assert!(bad_id_nv.probe_gpus().is_err());

        // Invalid MIG profile
        let mut bad_mig_nv = nv.clone();
        for d in &mut bad_mig_nv.devices {
            d.active_mig_profile = Some("99g.999gb".to_owned());
        }
        assert!(bad_mig_nv.probe_gpus().is_err());

        // Invalid NVLink source or target ID
        let mut bad_src_nv = nv.clone();
        bad_src_nv.nvlink_pairs = vec![(String::new(), "gpu-1".to_owned())];
        assert!(bad_src_nv.probe_gpus().is_err());

        let mut bad_dst_nv = nv;
        bad_dst_nv.nvlink_pairs = vec![("gpu-0".to_owned(), String::new())];
        assert!(bad_dst_nv.probe_gpus().is_err());
    }

    #[test]
    fn test_amd_apple_and_intel_gpu_probes() {
        // AMD ROCm
        let amd = AmdRocmProbe {
            rocm_available: true,
            device_count: 2,
            vram_per_device_bytes: 192 * 1024 * 1024 * 1024,
            compute_mode: AmdComputePartitionMode::Cpx,
            memory_mode: AmdMemoryPartitionMode::Nps4,
        };
        let (amd_gpus, amd_edges) = amd.probe_gpus().unwrap_or_default();
        assert_eq!(amd_gpus.len(), 2);
        assert_eq!(amd_edges.len(), 1);
        assert!(
            AmdRocmProbe {
                rocm_available: false,
                ..amd
            }
            .probe_gpus()
            .is_err()
        );
        assert!(
            AmdRocmProbe {
                device_count: 0,
                ..amd
            }
            .probe_gpus()
            .is_err()
        );

        // Apple Metal
        let apple = AppleMetalProbe {
            metal_available: true,
            gpu_cores: 40,
            unified_vram_bytes: 96 * 1024 * 1024 * 1024,
            neural_engine_present: true,
        };
        assert!(apple.probe_gpus().is_ok());
        assert!(
            AppleMetalProbe {
                metal_available: false,
                ..apple
            }
            .probe_gpus()
            .is_err()
        );
        assert!(
            AppleMetalProbe {
                gpu_cores: 0,
                ..apple
            }
            .probe_gpus()
            .is_err()
        );

        // Intel Level Zero
        let intel = IntelLevelZeroProbe {
            level_zero_initialized: true,
            tile_count: 2,
            hbm_per_tile_bytes: 64 * 1024 * 1024 * 1024,
        };
        assert!(intel.probe_gpus().is_ok());
        assert!(
            IntelLevelZeroProbe {
                level_zero_initialized: false,
                ..intel
            }
            .probe_gpus()
            .is_err()
        );
        assert!(
            IntelLevelZeroProbe {
                tile_count: 0,
                ..intel
            }
            .probe_gpus()
            .is_err()
        );
    }
}
