//! Google Cloud TPU (`v4`/`v5e`/`v5p`/`v6e`) and Coral Edge TPU discovery probe (`arbiter-probe::tpu`).
//!
//! Discovers `/dev/accel*` and `/dev/vfio/*` TPU devices, HBM memory capacity, 2D/3D ICI torus
//! coordinates, wrap-around link states, and slice health.

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{DeviceId, SliceId};
use arbiter_core::resources::{TorusCoordinate, TpuDevice, TpuGeneration};
use arbiter_core::units::Bytes;
use serde::{Deserialize, Serialize};

use crate::traits::TpuProbe;

/// Raw TPU device node record discovered from `/dev/accel*` or `/dev/vfio/*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpuAccelRecord {
    /// Device node name (e.g., `"accel0"`).
    pub dev_name: String,
    /// TPU hardware generation.
    pub generation: TpuGeneration,
    /// Chip index on the host (`0..8`).
    pub chip_index: u32,
    /// HBM capacity in bytes.
    pub hbm_bytes: u64,
    /// 3D torus coordinate `(x, y, z)`.
    pub coordinate: TorusCoordinate,
    /// Whether ICI optical/copper links are healthy.
    pub ici_healthy: bool,
    /// Whether wrap-around torus links are enabled.
    pub wrap_around: bool,
    /// Multi-host TPU Pod slice identifier string.
    pub slice_id: String,
}

/// Google Cloud TPU and Coral Edge TPU discovery collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleTpuProbe {
    /// Whether the TPU `/dev/accel*` or `vfio` driver is accessible.
    pub driver_ready: bool,
    /// Discovered raw TPU chip records.
    pub records: Vec<TpuAccelRecord>,
}

impl TpuProbe for GoogleTpuProbe {
    fn probe_tpus(&self) -> ArbiterResult<Vec<TpuDevice>> {
        if !self.driver_ready {
            return Err(ArbiterError::TpuDriverError {
                device: "/dev/accel0".to_owned(),
                reason: "TPU kernel driver or VFIO group not ready".to_owned(),
            });
        }

        let mut devices = Vec::with_capacity(self.records.len());
        for rec in &self.records {
            let device_id =
                DeviceId::new(&rec.dev_name).map_err(|_| ArbiterError::TpuDriverError {
                    device: rec.dev_name.clone(),
                    reason: "invalid TPU device node identifier".to_owned(),
                })?;
            let slice_id =
                SliceId::new(&rec.slice_id).map_err(|_| ArbiterError::TpuDriverError {
                    device: rec.dev_name.clone(),
                    reason: "invalid TPU slice identifier".to_owned(),
                })?;

            devices.push(TpuDevice {
                device_id,
                generation: rec.generation,
                chip_index: rec.chip_index,
                hbm_bytes: Bytes::new(rec.hbm_bytes),
                coordinate: rec.coordinate,
                ici_links_healthy: rec.ici_healthy,
                wrap_around_links: rec.wrap_around,
                slice_id,
            });
        }

        Ok(devices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_tpu_probe_valid_and_errors() {
        let probe = GoogleTpuProbe {
            driver_ready: true,
            records: vec![TpuAccelRecord {
                dev_name: "accel0".to_owned(),
                generation: TpuGeneration::CloudTpuV5p,
                chip_index: 0,
                hbm_bytes: 96 * 1024 * 1024 * 1024,
                coordinate: TorusCoordinate { x: 0, y: 0, z: 0 },
                ici_healthy: true,
                wrap_around: true,
                slice_id: "slice-v5p-pod-1".to_owned(),
            }],
        };

        let tpus = probe.probe_tpus().unwrap_or_default();
        assert_eq!(tpus.len(), 1);

        // Driver not ready
        assert!(
            GoogleTpuProbe {
                driver_ready: false,
                ..probe.clone()
            }
            .probe_tpus()
            .is_err()
        );

        // Invalid dev_name
        let mut bad_dev = probe.clone();
        for r in &mut bad_dev.records {
            r.dev_name = String::new();
        }
        assert!(bad_dev.probe_tpus().is_err());

        // Invalid slice_id
        let mut bad_slice = probe;
        for r in &mut bad_slice.records {
            r.slice_id = String::new();
        }
        assert!(bad_slice.probe_tpus().is_err());
    }
}
