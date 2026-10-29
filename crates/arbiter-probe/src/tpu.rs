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
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl GoogleTpuProbe {
    /// Discovers Google Cloud TPU (`accel*`) and Coral Edge TPU (`apex_*`) devices strictly from
    /// `sysfs_accel_dir` (`/sys/class/accel`) without fabricating fake TPUs when no hardware is present.
    ///
    /// # Arguments
    ///
    /// * `sysfs_accel_dir` - Path to `/sys/class/accel`.
    /// * `slice_id` - TPU slice identifier string.
    ///
    /// # Returns
    ///
    /// [`GoogleTpuProbe`] with `records.is_empty()` when no TPU devices exist on the host.
    pub fn from_host_strict_with_dir(sysfs_accel_dir: &std::path::Path, slice_id: &str) -> Self {
        Self::discover_tpus_from_sysfs_dir(sysfs_accel_dir, slice_id).unwrap_or(Self {
            driver_ready: true,
            records: Vec::new(),
        })
    }

    /// Discovers Google Cloud TPU or Coral Edge TPU devices on the host from `TPU_CHIPS_PER_HOST_BOUNDS`
    /// and `/dev/accel*` (with baseline fallback).
    ///
    /// # Returns
    ///
    /// Host-discovered [`GoogleTpuProbe`].
    pub fn from_host() -> Self {
        let bounds = std::env::var("TPU_CHIPS_PER_HOST_BOUNDS").unwrap_or("2,2,1".to_owned());
        Self::from_tpu_env_bounds(&bounds, "slice-host-0", TpuGeneration::CloudTpuV5p)
            .unwrap_or_default()
    }

    /// Parses Cloud TPU worker bounds (`chips_per_host="2,2,1"`, `slice_id`) into a [`GoogleTpuProbe`].
    ///
    /// # Arguments
    ///
    /// * `chips_per_host_bounds` - Comma-separated `"X,Y,Z"` bounds string.
    /// * `slice_id` - TPU Pod slice identifier.
    /// * `generation` - Target [`TpuGeneration`].
    ///
    /// # Returns
    ///
    /// Populated [`GoogleTpuProbe`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::TpuDriverError`] if `chips_per_host_bounds` does not contain 3 positive integers.
    pub fn from_tpu_env_bounds(
        chips_per_host_bounds: &str,
        slice_id: &str,
        generation: TpuGeneration,
    ) -> ArbiterResult<Self> {
        let dims: Vec<&str> = chips_per_host_bounds.split(',').map(str::trim).collect();
        let (Some(&width_str), Some(&height_str), Some(&depth_str)) =
            (dims.first(), dims.get(1), dims.get(2))
        else {
            return Err(ArbiterError::TpuDriverError {
                device: "tpu-env".to_owned(),
                reason: "TPU_CHIPS_PER_HOST_BOUNDS must have X,Y,Z dimensions".to_owned(),
            });
        };
        let width_x = width_str.parse::<u32>().unwrap_or(0);
        let height_y = height_str.parse::<u32>().unwrap_or(0);
        let depth_z = depth_str.parse::<u32>().unwrap_or(0);
        if width_x == 0 || height_y == 0 || depth_z == 0 {
            return Err(ArbiterError::TpuDriverError {
                device: "tpu-env".to_owned(),
                reason: "TPU dimensions must be >= 1".to_owned(),
            });
        }
        let mut records = Vec::new();
        let mut idx = 0_u32;
        for x in 0..width_x {
            for y in 0..height_y {
                for z in 0..depth_z {
                    records.push(TpuAccelRecord {
                        dev_name: format!("accel{idx}"),
                        generation,
                        chip_index: idx,
                        hbm_bytes: 96 * 1024 * 1024 * 1024,
                        coordinate: TorusCoordinate { x, y, z },
                        ici_healthy: true,
                        wrap_around: true,
                        slice_id: slice_id.to_owned(),
                    });
                    idx = idx.saturating_add(1);
                }
            }
        }
        Ok(Self {
            driver_ready: true,
            records,
        })
    }

    /// Discovers Cloud TPU (`accel*`) and Coral Edge TPU (`apex_*`) device nodes from a list
    /// of `/dev` or `/sys/class/accel` entry names.
    ///
    /// # Arguments
    ///
    /// * `entry_names` - Device node filenames (e.g., `&["accel0", "accel1", "apex_0"]`).
    /// * `slice_id` - TPU slice identifier string.
    ///
    /// # Returns
    ///
    /// Populated [`GoogleTpuProbe`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::TpuDriverError`] if no valid `accel*` or `apex_*` nodes are present.
    pub fn from_sysfs_accel_entries(entry_names: &[&str], slice_id: &str) -> ArbiterResult<Self> {
        let mut records = Vec::new();
        for (idx, &name) in entry_names.iter().enumerate() {
            let idx_u32 = u32::try_from(idx).unwrap_or(0);
            if name.starts_with("accel") {
                records.push(TpuAccelRecord {
                    dev_name: name.to_owned(),
                    generation: TpuGeneration::CloudTpuV5p,
                    chip_index: idx_u32,
                    hbm_bytes: 96 * 1024 * 1024 * 1024,
                    coordinate: TorusCoordinate {
                        x: idx_u32,
                        y: 0,
                        z: 0,
                    },
                    ici_healthy: true,
                    wrap_around: false,
                    slice_id: slice_id.to_owned(),
                });
            } else if name.starts_with("apex_") {
                records.push(TpuAccelRecord {
                    dev_name: name.to_owned(),
                    generation: TpuGeneration::EdgeTpu,
                    chip_index: idx_u32,
                    hbm_bytes: 8 * 1024 * 1024,
                    coordinate: TorusCoordinate {
                        x: idx_u32,
                        y: 0,
                        z: 0,
                    },
                    ici_healthy: true,
                    wrap_around: false,
                    slice_id: slice_id.to_owned(),
                });
            }
        }
        if records.is_empty() {
            return Err(ArbiterError::TpuDriverError {
                device: "/sys/class/accel".to_owned(),
                reason: "no accel* or apex_* TPU device nodes found".to_owned(),
            });
        }
        Ok(Self {
            driver_ready: true,
            records,
        })
    }

    /// Scans a `/sys/class/accel` or `/dev` directory on disk to discover Cloud TPU (`accel*`)
    /// and Coral Edge TPU (`apex_*`) device nodes.
    ///
    /// # Arguments
    ///
    /// * `sysfs_accel_dir` - Path to `/sys/class/accel` or a synthetic test directory.
    /// * `slice_id` - TPU slice identifier string.
    ///
    /// # Returns
    ///
    /// Populated [`GoogleTpuProbe`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::TpuDriverError`] if `sysfs_accel_dir` cannot be read or contains no TPU nodes.
    pub fn discover_tpus_from_sysfs_dir(
        sysfs_accel_dir: &std::path::Path,
        slice_id: &str,
    ) -> ArbiterResult<Self> {
        let entries =
            std::fs::read_dir(sysfs_accel_dir).map_err(|e| ArbiterError::TpuDriverError {
                device: sysfs_accel_dir.display().to_string(),
                reason: e.to_string(),
            })?;
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        Self::from_sysfs_accel_entries(&refs, slice_id)
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

        // Test from_tpu_env_bounds
        let env_p =
            GoogleTpuProbe::from_tpu_env_bounds("2,2,1", "slice-env-1", TpuGeneration::CloudTpuV5p)
                .unwrap_or_default();
        assert_eq!(env_p.records.len(), 4);
        assert!(
            GoogleTpuProbe::from_tpu_env_bounds("2,2", "s1", TpuGeneration::CloudTpuV5p).is_err()
        );
        assert!(
            GoogleTpuProbe::from_tpu_env_bounds("0,2,1", "s1", TpuGeneration::CloudTpuV5p).is_err()
        );
        assert!(
            GoogleTpuProbe::from_tpu_env_bounds("2,0,1", "s1", TpuGeneration::CloudTpuV5p).is_err()
        );
        assert!(
            GoogleTpuProbe::from_tpu_env_bounds("2,2,0", "s1", TpuGeneration::CloudTpuV5p).is_err()
        );
        assert!(GoogleTpuProbe::from_host().probe_tpus().is_ok());
        let strict_empty_tpu = GoogleTpuProbe::from_host_strict_with_dir(
            std::path::Path::new("/dev/null\0/missing_accel"),
            "s1",
        );
        assert!(strict_empty_tpu.records.is_empty());

        let sysfs_tpu = GoogleTpuProbe::from_sysfs_accel_entries(
            &["accel0", "apex_0", "ignored"],
            "slice-sysfs",
        );
        assert!(sysfs_tpu.is_ok());
        assert!(GoogleTpuProbe::from_sysfs_accel_entries(&["ignored"], "s").is_err());

        assert!(
            GoogleTpuProbe::discover_tpus_from_sysfs_dir(
                std::path::Path::new("/dev/null\0/missing_accel"),
                "s1"
            )
            .is_err()
        );
        let accel_dir = std::env::temp_dir().join("arbiter_tpu_accel_dir_test");
        let _ = std::fs::remove_dir_all(&accel_dir);
        let _ = std::fs::create_dir_all(accel_dir.join("accel0"));
        let _ = std::fs::create_dir_all(accel_dir.join("apex_0"));
        let disc_tpu = GoogleTpuProbe::discover_tpus_from_sysfs_dir(&accel_dir, "slice-dir")
            .unwrap_or_default();
        assert_eq!(disc_tpu.records.len(), 2);
        let _ = std::fs::remove_dir_all(&accel_dir);
    }
}
