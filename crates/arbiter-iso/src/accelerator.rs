//! Multi-vendor GPU and Google Cloud/Edge TPU accelerator isolator (`arbiter-iso::accelerator`).
//!
//! Generates device node whitelists (`/dev/nvidia*`, `/dev/dri/*`, `/dev/kfd`, `/dev/accel*`, `/dev/vfio/*`)
//! and vendor environment variable injections (`CUDA_VISIBLE_DEVICES`, `NVIDIA_MIG_CONFIG_DEVICES`,
//! `ROCR_VISIBLE_DEVICES`, `HIP_VISIBLE_DEVICES`, `ZE_AFFINITY_MASK`, `TPU_VISIBLE_DEVICES`,
//! `TPU_CHIPS_PER_HOST_BOUNDS`) across whole GPUs, MIG slices, AMD partitions, Intel tiles,
//! Apple Metal/ANE slices, and multi-host TPU torus slices.

use arbiter_core::error::ArbiterResult;
use arbiter_core::ids::{DeviceId, TaskId};
use arbiter_core::resources::{GpuPartition, GpuVendor, ResourceBundle, TpuTopologySlice};
use serde::{Deserialize, Serialize};

use crate::pipeline::{Isolator, IsolatorUsageReport, SandboxPreparation};

/// Accelerator allocation binding passed to [`AcceleratorIsolator`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceleratorIsolator {
    /// Target GPU vendor if GPUs are allocated.
    pub gpu_vendor: Option<GpuVendor>,
    /// Assigned GPU device IDs and partitions.
    pub assigned_gpus: Vec<(DeviceId, GpuPartition)>,
    /// Assigned TPU device IDs.
    pub assigned_tpus: Vec<DeviceId>,
    /// Optional TPU topology slice bounds.
    pub tpu_slice: Option<TpuTopologySlice>,
}

impl AcceleratorIsolator {
    /// Creates a new [`AcceleratorIsolator`].
    ///
    /// # Arguments
    ///
    /// * `gpu_vendor` - Optional GPU vendor.
    /// * `gpu_allocations` - Assigned `(DeviceId, GpuPartition)` pairs.
    /// * `tpu_devices` - Assigned TPU [`DeviceId`]s.
    /// * `tpu_slice` - Optional [`TpuTopologySlice`].
    ///
    /// # Returns
    ///
    /// Initialized [`AcceleratorIsolator`].
    pub const fn new(
        gpu_vendor: Option<GpuVendor>,
        gpu_allocations: Vec<(DeviceId, GpuPartition)>,
        tpu_devices: Vec<DeviceId>,
        tpu_slice: Option<TpuTopologySlice>,
    ) -> Self {
        Self {
            gpu_vendor,
            assigned_gpus: gpu_allocations,
            assigned_tpus: tpu_devices,
            tpu_slice,
        }
    }

    /// Formats NVIDIA Dynamic MIG instance creation (`nvidia-smi mig -cgi <profile> -C`) and
    /// CUDA MPS daemon (`CUDA_MPS_ACTIVE_THREAD_PERCENTAGE`) configuration commands.
    ///
    /// # Arguments
    ///
    /// * `mps_thread_pct` - Optional CUDA MPS active thread percentage (`1..=100`).
    ///
    /// # Returns
    ///
    /// Vector of MIG/MPS setup commands and environment pairs.
    pub fn format_mig_and_mps_commands(&self, mps_thread_pct: Option<u32>) -> Vec<String> {
        let mut cmds = Vec::new();
        for (id, part) in &self.assigned_gpus {
            if let GpuPartition::NvidiaMig(mig) = part {
                cmds.push(format!(
                    "nvidia-smi mig -i {id} -cgi {} -C",
                    mig.profile.as_str()
                ));
            }
        }
        if let Some(pct) = mps_thread_pct {
            cmds.push(format!("CUDA_MPS_ACTIVE_THREAD_PERCENTAGE={pct}"));
        }
        cmds
    }

    /// Generates RDMA / `InfiniBand` / `RoCEv2` device cgroup whitelist paths (`/dev/infiniband/uverbs*`,
    /// `/dev/infiniband/rdma_cm`) and SR-IOV VF netns attachment commands.
    ///
    /// # Arguments
    ///
    /// * `uverbs_index` - `uverbs` device index (`0` for `/dev/infiniband/uverbs0`).
    /// * `sriov_pf_vf` - Optional `(pf_name, vf_index, target_pid)` for SR-IOV VF namespace move.
    ///
    /// # Returns
    ///
    /// Vector of device paths and `ip link` commands.
    pub fn format_rdma_device_whitelist(
        uverbs_index: u32,
        sriov_pf_vf: Option<(&str, u32, u32)>,
    ) -> Vec<String> {
        let mut out = vec![
            "/dev/infiniband/rdma_cm".to_owned(),
            format!("/dev/infiniband/uverbs{uverbs_index}"),
            "ulimit -l unlimited".to_owned(),
        ];
        if let Some((pf, vf, pid)) = sriov_pf_vf {
            out.push(format!("ip link set {pf} vf {vf} netns {pid}"));
        }
        out
    }
    /// Generates `cgroups v2` BPF device controller (`BPF_PROG_TYPE_CGROUP_DEVICE`) allowlist rules
    /// (`c *:* rwm`) for the whitelisted `device_mounts`.
    ///
    /// # Arguments
    ///
    /// * `device_mounts` - Slice of device paths (e.g., `"/dev/nvidia0"`, `"/dev/kfd"`).
    ///
    /// # Returns
    ///
    /// Vector of BPF cgroup device allowlist rule strings.
    pub fn format_cgroup_bpf_device_allowlist(device_mounts: &[String]) -> Vec<String> {
        device_mounts
            .iter()
            .map(|dev| format!("bpf_cgroup_device:allow:c {dev} rwm"))
            .collect()
    }
}

impl Isolator for AcceleratorIsolator {
    fn name(&self) -> &'static str {
        "AcceleratorIsolator"
    }

    fn prepare(
        &mut self,
        _task_id: &TaskId,
        _limits: &ResourceBundle,
    ) -> ArbiterResult<SandboxPreparation> {
        let mut mounts = Vec::new();
        let mut env = Vec::new();

        if !self.assigned_gpus.is_empty() {
            let dev_list: String = self
                .assigned_gpus
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>()
                .join(",");

            match self.gpu_vendor.unwrap_or(GpuVendor::Nvidia) {
                GpuVendor::Nvidia => {
                    mounts.push("/dev/nvidiactl".to_owned());
                    mounts.push("/dev/nvidia-uvm".to_owned());
                    env.push(("CUDA_VISIBLE_DEVICES".to_owned(), dev_list));
                    for (id, part) in &self.assigned_gpus {
                        mounts.push(format!("/dev/{id}"));
                        if let GpuPartition::NvidiaMig(mig) = part {
                            mounts
                                .push(format!("/dev/nvidia-caps/nvidia-cap{}", mig.instance_index));
                            env.push((
                                "NVIDIA_MIG_CONFIG_DEVICES".to_owned(),
                                format!("{}:{}", mig.profile.as_str(), mig.instance_index),
                            ));
                        }
                    }
                }
                GpuVendor::Amd => {
                    mounts.push("/dev/kfd".to_owned());
                    for (id, _) in &self.assigned_gpus {
                        mounts.push(format!("/dev/dri/{id}"));
                    }
                    env.push(("ROCR_VISIBLE_DEVICES".to_owned(), dev_list.clone()));
                    env.push(("HIP_VISIBLE_DEVICES".to_owned(), dev_list));
                }
                GpuVendor::Intel => {
                    for (id, part) in &self.assigned_gpus {
                        mounts.push(format!("/dev/dri/{id}"));
                        if let GpuPartition::IntelTile(tile) = part {
                            env.push((
                                "ZE_AFFINITY_MASK".to_owned(),
                                format!("{}.{}", id, tile.tile_index),
                            ));
                        }
                    }
                }
                GpuVendor::Apple => {
                    env.push(("METAL_DEVICE_WRAPPER_TYPE".to_owned(), "1".to_owned()));
                }
            }
        }

        if !self.assigned_tpus.is_empty() {
            let tpu_list: String = self
                .assigned_tpus
                .iter()
                .map(DeviceId::as_str)
                .collect::<Vec<_>>()
                .join(",");
            for id in &self.assigned_tpus {
                mounts.push(format!("/dev/{id}"));
                mounts.push(format!("/dev/vfio/{id}"));
            }
            env.push(("TPU_VISIBLE_DEVICES".to_owned(), tpu_list));
            if let Some(ref slice) = self.tpu_slice {
                env.push((
                    "TPU_CHIPS_PER_HOST_BOUNDS".to_owned(),
                    format!("{},{},{}", slice.dim_x, slice.dim_y, slice.dim_z),
                ));
            }
        }

        Ok(SandboxPreparation {
            device_mounts: mounts,
            injected_env: env,
            applied_commands: vec!["device_whitelist_configured".to_owned()],
        })
    }

    fn isolate(&mut self, _task_id: &TaskId, _pid: u32) -> ArbiterResult<()> {
        Ok(())
    }

    fn update_limits(
        &mut self,
        _task_id: &TaskId,
        _new_limits: &ResourceBundle,
    ) -> ArbiterResult<()> {
        Ok(())
    }

    fn usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
        Ok(IsolatorUsageReport {
            task_id: task_id.clone(),
            consumed: ResourceBundle::zero(),
        })
    }

    fn checkpoint(&mut self, _task_id: &TaskId, _checkpoint_dir: &str) -> ArbiterResult<()> {
        Ok(())
    }

    fn cleanup(&mut self, _task_id: &TaskId) -> ArbiterResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::SliceId;
    use arbiter_core::resources::{
        IntelTilePartition, NvidiaMigPartition, NvidiaMigProfile, TpuGeneration,
    };
    use arbiter_core::units::Bytes;

    use super::*;

    #[test]
    fn test_accelerator_isolator_nvidia_and_amd() {
        let tid = TaskId::new("task-acc-1").unwrap_or_default();
        let limits = ResourceBundle::zero();

        let mut nv_iso = AcceleratorIsolator::new(
            Some(GpuVendor::Nvidia),
            vec![
                (
                    DeviceId::new("nvidia0").unwrap_or_default(),
                    GpuPartition::WholeDevice,
                ),
                (
                    DeviceId::new("nvidia1").unwrap_or_default(),
                    GpuPartition::NvidiaMig(NvidiaMigPartition {
                        profile: NvidiaMigProfile::Mig1g10gb,
                        instance_index: 2,
                    }),
                ),
            ],
            Vec::new(),
            None,
        );
        assert_eq!(nv_iso.name(), "AcceleratorIsolator");
        let nv_prep = nv_iso.prepare(&tid, &limits).unwrap_or_default();
        assert!(
            nv_prep
                .injected_env
                .iter()
                .any(|(k, _)| k == "CUDA_VISIBLE_DEVICES")
        );
        assert!(
            nv_prep
                .injected_env
                .iter()
                .any(|(k, _)| k == "NVIDIA_MIG_CONFIG_DEVICES")
        );
        assert!(
            nv_prep
                .device_mounts
                .iter()
                .any(|m| m.starts_with("/dev/nvidia-caps/"))
        );
        assert_eq!(
            AcceleratorIsolator::format_cgroup_bpf_device_allowlist(&nv_prep.device_mounts).len(),
            nv_prep.device_mounts.len()
        );
        assert!(nv_iso.isolate(&tid, 100).is_ok());
        assert!(nv_iso.update_limits(&tid, &limits).is_ok());
        assert!(nv_iso.usage(&tid).is_ok());
        assert!(nv_iso.checkpoint(&tid, "/tmp").is_ok());
        assert!(nv_iso.cleanup(&tid,).is_ok());
        assert_eq!(nv_iso.format_mig_and_mps_commands(Some(50)).len(), 2);
        assert_eq!(nv_iso.format_mig_and_mps_commands(None).len(), 1);
        assert_eq!(
            AcceleratorIsolator::format_rdma_device_whitelist(0, Some(("mlx5_0", 1, 999))).len(),
            4
        );
        assert_eq!(
            AcceleratorIsolator::format_rdma_device_whitelist(0, None).len(),
            3
        );

        let mut amd_iso = AcceleratorIsolator::new(
            Some(GpuVendor::Amd),
            vec![(
                DeviceId::new("renderD128").unwrap_or_default(),
                GpuPartition::WholeDevice,
            )],
            Vec::new(),
            None,
        );
        let amd_prep = amd_iso.prepare(&tid, &limits).unwrap_or_default();
        assert!(
            amd_prep
                .injected_env
                .iter()
                .any(|(k, _)| k == "ROCR_VISIBLE_DEVICES")
        );
    }

    #[test]
    fn test_accelerator_isolator_intel_apple_and_tpus() {
        let tid = TaskId::new("task-acc-2").unwrap_or_default();
        let limits = ResourceBundle::zero();

        let mut intel_iso = AcceleratorIsolator::new(
            Some(GpuVendor::Intel),
            vec![
                (
                    DeviceId::new("card0").unwrap_or_default(),
                    GpuPartition::IntelTile(IntelTilePartition {
                        tile_index: 1,
                        vram_bytes: Bytes::new(64),
                    }),
                ),
                (
                    DeviceId::new("card1").unwrap_or_default(),
                    GpuPartition::WholeDevice,
                ),
            ],
            Vec::new(),
            None,
        );
        let intel_prep = intel_iso.prepare(&tid, &limits).unwrap_or_default();
        assert!(
            intel_prep
                .injected_env
                .iter()
                .any(|(k, _)| k == "ZE_AFFINITY_MASK")
        );

        let slice = TpuTopologySlice {
            slice_id: SliceId::new("s-1").unwrap_or_default(),
            generation: TpuGeneration::CloudTpuV5p,
            dim_x: 2,
            dim_y: 2,
            dim_z: 1,
            require_wrap_around: false,
        };
        let mut apple_tpu_iso = AcceleratorIsolator::new(
            Some(GpuVendor::Apple),
            vec![(
                DeviceId::new("metal0").unwrap_or_default(),
                GpuPartition::WholeDevice,
            )],
            vec![DeviceId::new("accel0").unwrap_or_default()],
            Some(slice),
        );
        let apple_prep = apple_tpu_iso.prepare(&tid, &limits).unwrap_or_default();
        assert!(
            apple_prep
                .injected_env
                .iter()
                .any(|(k, _)| k == "TPU_CHIPS_PER_HOST_BOUNDS")
        );

        let mut tpu_no_slice = AcceleratorIsolator::new(
            None,
            Vec::new(),
            vec![DeviceId::new("accel0").unwrap_or_default()],
            None,
        );
        assert!(tpu_no_slice.prepare(&tid, &limits).is_ok());
    }
}
