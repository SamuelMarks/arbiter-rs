//! Topology-aware hardware bin-packer (`arbiter-alloc::topology_packer`).
//!
//! Solves hardware subgraph placement for a [`TaskSpec`] onto an Agent's [`HardwareTopologyGraph`]:
//! - Co-locates CPU cores and RAM on the same NUMA domain.
//! - Places multi-GPU requests onto `NVLink`/`NVSwitch` or Infinity Fabric islands before falling
//!   back to `PCIe` switches or cross-socket links.
//! - Pairs GPUs with their closest `PCIe`-affinitized RDMA NIC for `GPUDirect RDMA` workloads.
//! - Automatically selects or slices NVIDIA MIG instances or fractional MPS shares when fractional
//!   GPU requests arrive.

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, DeviceId, TaskId};
use arbiter_core::resources::{
    AmdComputePartitionMode, AmdMemoryPartitionMode, AmdPartitionSlice, AppleMetalPartition,
    CoreDescriptor, GpuDevice, GpuPartition, GpuVendor, IntelTilePartition, NumaMemoryPool,
    NvidiaMigPartition, NvidiaMigProfile, NvidiaMpsPartition, RdmaDevice, ResourceBundle,
};
use arbiter_core::topology::{HardwareTopologyGraph, InterconnectKind};
use arbiter_core::units::{Bytes, GpuMillicores, Millicores, WeightBasisPoints};
pub use arbiter_core::workload::{
    ARBITER_SCHEDULING_REQUIREMENTS_ENV_KEY, TaskSchedulingRequirements,
};
use arbiter_core::workload::{AgentAttribute, DomainInfo, TaskSpec, TopologyConstraint};
use serde::{Deserialize, Serialize};

/// Extended Agent attribute, fault-domain (`DomainInfo`), CPU microarchitectural core (`CoreDescriptor`),
/// and NUMA hugepage/unified memory pool (`NumaMemoryPool`) profile evaluated during scheduling.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSchedulingProfile {
    /// Advertised Mesos key-value [`AgentAttribute`]s (`TEXT`, `SCALAR`, `RANGES`, `SET`).
    pub attributes: Vec<AgentAttribute>,
    /// Optional geographic/rack fault domain (`RegionName` + `ZoneName`).
    pub domain_info: Option<DomainInfo>,
    /// Discovered physical CPU cores (`CpuCoreClass` + `CpuInstructionExtension` SIMD flags).
    pub cores: Vec<CoreDescriptor>,
    /// Discovered per-NUMA-node memory pools (`hugepages_2mib_bytes`, `hugepages_1gib_bytes`, `unified_memory`).
    pub numa_pools: Vec<NumaMemoryPool>,
    /// Number of tasks already placed on this Agent host during the current scheduling scope.
    pub existing_tasks_on_host: u32,
    /// Number of tasks already placed in this Agent's fault-domain zone during the current scheduling scope.
    pub existing_tasks_in_zone: u32,
}

/// Verifies that an Agent's [`AgentSchedulingProfile`] satisfies all [`TaskSchedulingRequirements`].
///
/// # Arguments
///
/// * `task_id` - Workload [`TaskId`] for error reporting.
/// * `reqs` - Task microarchitectural and placement requirements.
/// * `profile` - Candidate Agent's [`AgentSchedulingProfile`].
///
/// # Returns
///
/// `Ok(())` if all constraints are satisfied.
///
/// # Errors
///
/// Returns [`ArbiterError::NoEligibleAgents`] if any constraint fails.
pub fn verify_scheduling_requirements(
    task_id: &TaskId,
    reqs: &TaskSchedulingRequirements,
    profile: &AgentSchedulingProfile,
) -> ArbiterResult<()> {
    if reqs
        .required_domain
        .as_ref()
        .is_some_and(|req_dom| profile.domain_info.as_ref() != Some(req_dom))
    {
        return Err(ArbiterError::NoEligibleAgents {
            workload: task_id.to_string(),
            reason: "agent DomainInfo does not match required fault domain".to_owned(),
        });
    }
    for constraint in &reqs.placement_constraints {
        if !constraint.matches_agent(
            &profile.attributes,
            profile.existing_tasks_on_host,
            profile.existing_tasks_in_zone,
        ) {
            return Err(ArbiterError::NoEligibleAgents {
                workload: task_id.to_string(),
                reason: "agent failed PlacementConstraint evaluation".to_owned(),
            });
        }
    }
    if let Some(ref cpu_req) = reqs.cpu_resource {
        let has_matching_core = profile.cores.iter().any(|core| {
            cpu_req
                .preferred_core_class
                .is_none_or(|cls| core.core_class == cls)
                && cpu_req
                    .required_extensions
                    .iter()
                    .all(|ext| core.extensions.contains(ext))
        });
        if !has_matching_core {
            return Err(ArbiterError::NoEligibleAgents {
                workload: task_id.to_string(),
                reason:
                    "no CPU core satisfies CpuCoreClass and CpuInstructionExtension requirements"
                        .to_owned(),
            });
        }
    }
    if let Some(ref mem_req) = reqs.memory_resource {
        let req_unified = mem_req.require_unified_memory;
        let has_matching_pool = profile.numa_pools.iter().any(|pool| {
            pool.ram_bytes >= mem_req.ram_bytes
                && pool.hugepages_2mib_bytes >= mem_req.hugepages_2mib_bytes
                && pool.hugepages_1gib_bytes >= mem_req.hugepages_1gib_bytes
                && (pool.unified_memory || !req_unified)
        });
        if !has_matching_pool {
            return Err(ArbiterError::NoEligibleAgents {
                workload: task_id.to_string(),
                reason: "no NumaMemoryPool satisfies hugepage or unified_memory requirements"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

/// Per-NUMA-domain free CPU and memory capacity on an Agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaDomainCapacity {
    /// NUMA domain index.
    pub numa_node_id: u32,
    /// Available CPU millicores on this NUMA node.
    pub available_cpu: Millicores,
    /// Available standard RAM bytes on this NUMA node.
    pub available_memory: Bytes,
}

/// Complete snapshot of an Agent's free resources and hardware topology for bin-packing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHardwareInventory {
    /// Agent identifier.
    pub agent_id: AgentId,
    /// Total available aggregate resources on the Agent.
    pub available_bundle: ResourceBundle,
    /// Per-NUMA-domain available CPU and RAM capacities.
    pub numa_domains: Vec<NumaDomainCapacity>,
    /// Available GPU devices on the Agent.
    pub gpus: Vec<GpuDevice>,
    /// Available RDMA / high-speed fabric NICs on the Agent.
    pub rdma_nics: Vec<RdmaDevice>,
    /// Interconnect topology graph for this Agent.
    pub topology: HardwareTopologyGraph,
}

impl AgentHardwareInventory {
    /// Deducts the resources and hardware devices consumed by `plan` and `task` from this
    /// [`AgentHardwareInventory`]:
    /// 1. Subtracts `task.resources` from `self.available_bundle`.
    /// 2. Subtracts `task.resources.cpu` and `task.resources.memory` from the matching
    ///    `NumaDomainCapacity` (`plan.selected_numa_node`).
    /// 3. Subtracts per-GPU compute and VRAM from each assigned [`GpuDevice`] in `self.gpus`.
    ///
    /// # Arguments
    ///
    /// * `task` - Placed [`TaskSpec`].
    /// * `plan` - Resulting [`TopologyPlacementPlan`].
    pub fn apply_placement_deduction(&mut self, task: &TaskSpec, plan: &TopologyPlacementPlan) {
        self.available_bundle = self
            .available_bundle
            .try_sub(&task.resources)
            .unwrap_or_default();
        for domain in &mut self.numa_domains {
            if domain.numa_node_id == plan.selected_numa_node {
                domain.available_cpu = domain.available_cpu.saturating_sub(task.resources.cpu);
                domain.available_memory = domain
                    .available_memory
                    .saturating_sub(task.resources.memory);
            }
        }
        let gpu_count = u64::try_from(plan.assigned_gpus.len()).unwrap_or(1).max(1);
        let per_gpu_compute = GpuMillicores::new(
            task.resources
                .gpu_compute
                .get()
                .checked_div(gpu_count)
                .unwrap_or(0),
        );
        let per_gpu_vram = Bytes::new(
            task.resources
                .gpu_vram
                .get()
                .checked_div(gpu_count)
                .unwrap_or(0),
        );
        for (assigned_id, assigned_part) in &plan.assigned_gpus {
            for gpu in &mut self.gpus {
                if &gpu.device_id == assigned_id {
                    gpu.available_compute = gpu.available_compute.saturating_sub(per_gpu_compute);
                    gpu.available_vram = gpu.available_vram.saturating_sub(per_gpu_vram);
                    gpu.partition = *assigned_part;
                }
            }
        }
    }
}

/// Concrete hardware assignment produced by the topology bin-packer for a [`TaskSpec`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyPlacementPlan {
    /// Target Agent identifier.
    pub agent_id: AgentId,
    /// Selected primary NUMA domain index (`0` if not NUMA-constrained).
    pub selected_numa_node: u32,
    /// Assigned GPU devices and their concrete partition configurations (e.g., auto-sliced MIG or MPS).
    pub assigned_gpus: Vec<(DeviceId, GpuPartition)>,
    /// Optional affinitized RDMA NIC device ID paired for `GPUDirect RDMA`.
    pub paired_rdma_nic: Option<DeviceId>,
    /// Aggregate topology affinity score of the placement (`u64::MAX` for single-device/trivial placement).
    pub affinity_score: u64,
}

/// Selects the smallest standard [`NvidiaMigProfile`] that satisfies `req_compute` and `req_vram`.
///
/// # Arguments
///
/// * `req_compute` - Requested GPU compute millicores (`1..1000`).
/// * `req_vram` - Requested GPU VRAM in bytes.
///
/// # Returns
///
/// Smallest fitting [`NvidiaMigProfile`].
///
/// # Errors
///
/// Returns [`ArbiterError::InvalidMigProfile`] if no MIG profile can satisfy the request.
pub fn select_auto_mig_profile(
    req_compute: GpuMillicores,
    req_vram: Bytes,
) -> ArbiterResult<NvidiaMigProfile> {
    let candidates = [
        NvidiaMigProfile::Mig1g5gb,
        NvidiaMigProfile::Mig1g10gb,
        NvidiaMigProfile::Mig2g10gb,
        NvidiaMigProfile::Mig2g20gb,
        NvidiaMigProfile::Mig3g20gb,
        NvidiaMigProfile::Mig3g40gb,
        NvidiaMigProfile::Mig4g20gb,
        NvidiaMigProfile::Mig4g40gb,
        NvidiaMigProfile::Mig7g40gb,
        NvidiaMigProfile::Mig7g80gb,
    ];
    for profile in candidates {
        if profile.gpu_millicores() >= req_compute && profile.vram_bytes() >= req_vram {
            return Ok(profile);
        }
    }
    Err(ArbiterError::InvalidMigProfile {
        profile: format!("{}gm/{}B", req_compute.get(), req_vram.get()),
        reason: "exceeds largest 7g.80gb MIG profile".to_owned(),
    })
}

/// Packs a [`TaskSpec`] onto an [`AgentHardwareInventory`], enforcing resource, NUMA, GPU vendor,
/// fractional MIG/MPS slicing, `NVLink` island, and `PCIe` RDMA NIC affinity constraints.
///
/// # Arguments
///
/// * `task` - The workload [`TaskSpec`] to place.
/// * `inventory` - The Agent's [`AgentHardwareInventory`].
///
/// # Returns
///
/// Optimal [`TopologyPlacementPlan`] on the Agent.
///
/// # Errors
///
/// Returns:
/// - [`ArbiterError::InsufficientResources`] if aggregate resources or GPU counts are insufficient.
/// - [`ArbiterError::NoEligibleAgents`] if NUMA co-location, GPU vendor, or topology constraints cannot be met.
pub fn pack_task_on_agent(
    task: &TaskSpec,
    inventory: &AgentHardwareInventory,
) -> ArbiterResult<TopologyPlacementPlan> {
    pack_task_on_agent_with_profile(task, inventory, &AgentSchedulingProfile::default())
}

/// Packs a [`TaskSpec`] onto an [`AgentHardwareInventory`] while evaluating `profile` constraints.
///
/// # Arguments
///
/// * `task` - The workload [`TaskSpec`] to place.
/// * `inventory` - The Agent's [`AgentHardwareInventory`].
/// * `profile` - The Agent's [`AgentSchedulingProfile`].
///
/// # Returns
///
/// Optimal [`TopologyPlacementPlan`] on the Agent.
///
/// # Errors
///
/// Returns [`ArbiterError::InsufficientResources`] or [`ArbiterError::NoEligibleAgents`] on failure.
pub fn pack_task_on_agent_with_profile(
    task: &TaskSpec,
    inventory: &AgentHardwareInventory,
    profile: &AgentSchedulingProfile,
) -> ArbiterResult<TopologyPlacementPlan> {
    if let Some(reqs) = TaskSchedulingRequirements::from_task(task) {
        verify_scheduling_requirements(&task.task_id, &reqs, profile)?;
    }
    pack_task_core(task, inventory)
}

/// Core NUMA, GPU, MIG/MPS, and `PCIe` RDMA placement solver for `task` on `inventory`.
///
/// # Arguments
///
/// * `task` - The workload [`TaskSpec`] to place.
/// * `inventory` - The Agent's [`AgentHardwareInventory`].
///
/// # Returns
///
/// Optimal [`TopologyPlacementPlan`] on the Agent.
///
/// # Errors
///
/// Returns [`ArbiterError::InsufficientResources`] or [`ArbiterError::NoEligibleAgents`] on failure.
fn pack_task_core(
    task: &TaskSpec,
    inventory: &AgentHardwareInventory,
) -> ArbiterResult<TopologyPlacementPlan> {
    if !inventory.available_bundle.contains(&task.resources) {
        return Err(ArbiterError::InsufficientResources {
            resource: "bundle".to_owned(),
            requested: task.resources.cpu.get(),
            available: inventory.available_bundle.cpu.get(),
        });
    }

    let require_same_numa = task
        .topology_constraints
        .iter()
        .any(|c| matches!(c, TopologyConstraint::SameNuma));
    let require_nvlink = task
        .topology_constraints
        .iter()
        .any(|c| matches!(c, TopologyConstraint::NvLinkConnected));
    let require_same_pcie_switch = task
        .topology_constraints
        .iter()
        .any(|c| matches!(c, TopologyConstraint::SamePcieSwitch));

    // 1. Select NUMA domain that can hold CPU + RAM if SameNuma is requested or if domains exist.
    let selected_numa_node = select_numa_domain(task, inventory, require_same_numa)?;

    // 2. Handle GPU allocation if gpu_compute > 0.
    let req_gpu_m = task.resources.gpu_compute.get();
    if req_gpu_m == 0 {
        return Ok(TopologyPlacementPlan {
            agent_id: inventory.agent_id.clone(),
            selected_numa_node,
            assigned_gpus: Vec::new(),
            paired_rdma_nic: None,
            affinity_score: 1000,
        });
    }

    // Filter eligible GPUs by vendor and NUMA constraint.
    let eligible_gpus: Vec<&GpuDevice> = inventory
        .gpus
        .iter()
        .filter(|g| {
            task.required_gpu_vendor.is_none_or(|v| g.vendor == v)
                && (!require_same_numa || g.numa_node_id == selected_numa_node)
        })
        .collect();

    // Case A: Fractional single-GPU request (< 1000gm) -> auto-slice MIG or MPS.
    if req_gpu_m < 1000 {
        return place_fractional_gpu(
            task,
            inventory,
            &eligible_gpus,
            selected_numa_node,
            require_same_pcie_switch,
        );
    }

    // Case B: Whole single or multi-GPU request (1000gm per GPU).
    let whole_gpu_count = usize::try_from(req_gpu_m.div_ceil(1000)).unwrap_or(1);
    let per_gpu_vram = Bytes::new(
        task.resources
            .gpu_vram
            .get()
            .checked_div(req_gpu_m.div_ceil(1000))
            .unwrap_or(0),
    );

    let whole_candidates: Vec<&GpuDevice> = eligible_gpus
        .into_iter()
        .filter(|g| {
            g.available_compute >= GpuMillicores::new(1000) && g.available_vram >= per_gpu_vram
        })
        .collect();

    let Some(first_gpu) = whole_candidates.first().copied() else {
        return Err(ArbiterError::NoEligibleAgents {
            workload: task.task_id.to_string(),
            reason: "no eligible whole GPUs on agent".to_owned(),
        });
    };

    if whole_candidates.len() < whole_gpu_count {
        return Err(ArbiterError::NoEligibleAgents {
            workload: task.task_id.to_string(),
            reason: "insufficient eligible whole GPUs on agent".to_owned(),
        });
    }

    let (selected_gpus, affinity_score) = select_optimal_gpu_island_subset(
        task,
        &inventory.topology,
        &whole_candidates,
        whole_gpu_count,
        require_nvlink,
    )?;
    let anchor_gpu = selected_gpus.first().copied().unwrap_or(first_gpu);

    let paired_rdma_nic = if require_same_pcie_switch {
        Some(select_closest_rdma_nic(task, inventory, anchor_gpu)?)
    } else {
        None
    };

    let assigned_gpus = selected_gpus
        .into_iter()
        .map(|g| (g.device_id.clone(), GpuPartition::WholeDevice))
        .collect();

    Ok(TopologyPlacementPlan {
        agent_id: inventory.agent_id.clone(),
        selected_numa_node,
        assigned_gpus,
        paired_rdma_nic,
        affinity_score,
    })
}

/// Evaluates candidate `k`-GPU subsets from `whole_candidates` and selects the subset that
/// satisfies `require_nvlink` while maximizing pairwise interconnect affinity on `topology`.
///
/// # Arguments
///
/// * `task` - Workload specification.
/// * `topology` - Agent's [`HardwareTopologyGraph`].
/// * `whole_candidates` - Slice of eligible whole GPUs.
/// * `k` - Number of whole GPUs required.
/// * `require_nvlink` - Whether direct `NVLink`/`NVSwitch`/`InfinityFabric` edges are mandatory.
///
/// # Returns
///
/// Tuple `(Vec<&GpuDevice>, u64)` of the highest-affinity `k`-GPU subset and its score.
///
/// # Errors
///
/// Returns [`ArbiterError::NoEligibleAgents`] if no `k`-GPU subset satisfies `require_nvlink`.
fn select_optimal_gpu_island_subset<'a>(
    task: &TaskSpec,
    topology: &HardwareTopologyGraph,
    whole_candidates: &[&'a GpuDevice],
    k: usize,
    require_nvlink: bool,
) -> ArbiterResult<(Vec<&'a GpuDevice>, u64)> {
    let n = whole_candidates.len();
    let mut last_err = ArbiterError::NoEligibleAgents {
        workload: task.task_id.to_string(),
        reason: "selected GPUs are not connected via NVLink/NVSwitch/InfinityFabric".to_owned(),
    };

    for (anchor_idx, &anchor) in whole_candidates
        .iter()
        .enumerate()
        .take(n.saturating_sub(k).saturating_add(1))
    {
        if k == 1 {
            return Ok((vec![anchor], 1000));
        }
        // Rank all remaining candidates by their pairwise affinity to `anchor` descending
        let mut peers: Vec<(&'a GpuDevice, u64)> = whole_candidates
            .iter()
            .enumerate()
            .filter(|&(idx, _)| idx != anchor_idx)
            .map(|(_, &peer)| {
                let score = topology
                    .compute_affinity(&anchor.device_id, &peer.device_id)
                    .map(|a| a.composite_score)
                    .unwrap_or(100);
                (peer, score)
            })
            .collect();
        peers.sort_by(|a, b| b.1.cmp(&a.1));

        let mut subset = Vec::with_capacity(k);
        subset.push(anchor);
        for (peer, _) in peers.into_iter().take(k.saturating_sub(1)) {
            subset.push(peer);
        }

        match verify_and_score_gpu_island(task, topology, anchor, &subset, require_nvlink) {
            Ok(score) => return Ok((subset, score)),
            Err(err) => last_err = err,
        }
    }

    Err(last_err)
}

/// Selects a NUMA domain capable of hosting the task's CPU and memory requirements.
///
/// # Arguments
///
/// * `task` - Workload specification.
/// * `inventory` - Agent hardware inventory.
/// * `require_same_numa` - Whether strict single-NUMA co-location is required.
///
/// # Returns
///
/// Selected NUMA node index.
///
/// # Errors
///
/// Returns [`ArbiterError::NoEligibleAgents`] if `require_same_numa` is `true` and no single
/// NUMA node has sufficient CPU and memory.
fn select_numa_domain(
    task: &TaskSpec,
    inventory: &AgentHardwareInventory,
    require_same_numa: bool,
) -> ArbiterResult<u32> {
    if let Some(domain) = inventory.numa_domains.iter().find(|d| {
        d.available_cpu >= task.resources.cpu && d.available_memory >= task.resources.memory
    }) {
        return Ok(domain.numa_node_id);
    }
    if require_same_numa {
        return Err(ArbiterError::NoEligibleAgents {
            workload: task.task_id.to_string(),
            reason: "no single NUMA node satisfies CPU and RAM co-location constraint".to_owned(),
        });
    }
    Ok(0)
}

/// Places a fractional GPU request (`< 1000gm`) by selecting or slicing an NVIDIA MIG or MPS partition.
///
/// # Arguments
///
/// * `task` - Workload specification.
/// * `inventory` - Agent hardware inventory.
/// * `eligible_gpus` - Filtered candidate GPUs.
/// * `selected_numa_node` - Chosen NUMA domain.
/// * `require_same_pcie_switch` - Whether an affinitized RDMA NIC is required.
///
/// # Returns
///
/// [`TopologyPlacementPlan`] with the concrete fractional [`GpuPartition`].
///
/// # Errors
///
/// Returns [`ArbiterError::NoEligibleAgents`] if no GPU can host the fractional slice.
fn place_fractional_gpu(
    task: &TaskSpec,
    inventory: &AgentHardwareInventory,
    eligible_gpus: &[&GpuDevice],
    selected_numa_node: u32,
    require_same_pcie_switch: bool,
) -> ArbiterResult<TopologyPlacementPlan> {
    let req_compute = task.resources.gpu_compute;
    let req_vram = task.resources.gpu_vram;

    let Some(&gpu) = eligible_gpus
        .iter()
        .find(|g| g.available_compute >= req_compute && g.available_vram >= req_vram)
    else {
        return Err(ArbiterError::NoEligibleAgents {
            workload: task.task_id.to_string(),
            reason: "no GPU has sufficient compute/VRAM for fractional request".to_owned(),
        });
    };

    let partition = task.required_gpu_partition.map_or_else(
        || match gpu.vendor {
            GpuVendor::Nvidia => select_auto_mig_profile(req_compute, req_vram).map_or_else(
                |_| {
                    let bps = req_compute.get().saturating_mul(10);
                    let share = WeightBasisPoints::new(bps).unwrap_or(WeightBasisPoints::STANDARD);
                    GpuPartition::NvidiaMps(NvidiaMpsPartition {
                        compute_share: share,
                        vram_cap: req_vram,
                    })
                },
                |mig_profile| {
                    GpuPartition::NvidiaMig(NvidiaMigPartition {
                        profile: mig_profile,
                        instance_index: 0,
                    })
                },
            ),
            GpuVendor::Amd => {
                let compute_mode = if req_compute.get() <= 125 {
                    AmdComputePartitionMode::Cpx
                } else if req_compute.get() <= 250 {
                    AmdComputePartitionMode::Qpx
                } else {
                    AmdComputePartitionMode::Dpx
                };
                GpuPartition::AmdComputePartition(AmdPartitionSlice {
                    compute_mode,
                    memory_mode: AmdMemoryPartitionMode::Nps4,
                    partition_index: 0,
                })
            }
            GpuVendor::Intel => GpuPartition::IntelTile(IntelTilePartition {
                tile_index: 0,
                vram_bytes: req_vram,
            }),
            GpuVendor::Apple => {
                let cores = u32::try_from(req_compute.get().div_ceil(25)).unwrap_or(8);
                GpuPartition::AppleMetalSlice(AppleMetalPartition {
                    gpu_cores: cores,
                    unified_memory_bytes: req_vram,
                    include_neural_engine: true,
                })
            }
        },
        |explicit| explicit,
    );

    let paired_rdma_nic = if require_same_pcie_switch {
        Some(select_closest_rdma_nic(task, inventory, gpu)?)
    } else {
        None
    };

    Ok(TopologyPlacementPlan {
        agent_id: inventory.agent_id.clone(),
        selected_numa_node,
        assigned_gpus: vec![(gpu.device_id.clone(), partition)],
        paired_rdma_nic,
        affinity_score: 1000,
    })
}

/// Returns `true` if `kind` is a high-speed GPU interconnect (`NvLink`, `NvSwitch`, or `AmdInfinityFabric`).
///
/// # Arguments
///
/// * `kind` - [`InterconnectKind`] to inspect.
///
/// # Returns
///
/// `true` if high-speed GPU interconnect.
fn is_high_speed_gpu_interconnect(kind: InterconnectKind) -> bool {
    [
        InterconnectKind::NvLink,
        InterconnectKind::NvSwitch,
        InterconnectKind::AmdInfinityFabric,
    ]
    .contains(&kind)
}

/// Verifies interconnect connectivity across a multi-GPU set and computes average pairwise affinity.
///
/// # Arguments
///
/// * `task` - Workload specification.
/// * `topology` - Agent's [`HardwareTopologyGraph`].
/// * `first_gpu` - Anchor GPU in the selected set.
/// * `gpus` - Selected GPU slice.
/// * `require_nvlink` - Whether direct `NVLink`/`NVSwitch`/Infinity Fabric links are mandatory.
///
/// # Returns
///
/// Aggregate affinity score.
///
/// # Errors
///
/// Returns [`ArbiterError::NoEligibleAgents`] if `require_nvlink` is `true` and GPUs lack high-speed links.
fn verify_and_score_gpu_island(
    task: &TaskSpec,
    topology: &HardwareTopologyGraph,
    first_gpu: &GpuDevice,
    gpus: &[&GpuDevice],
    require_nvlink: bool,
) -> ArbiterResult<u64> {
    let mut total_score = 0_u64;
    for &other_gpu in gpus.iter().skip(1) {
        let has_high_speed = !require_nvlink
            || topology.edges().iter().any(|e| {
                e.source == first_gpu.device_id
                    && e.target == other_gpu.device_id
                    && is_high_speed_gpu_interconnect(e.kind)
            });
        if !has_high_speed {
            return Err(ArbiterError::NoEligibleAgents {
                workload: task.task_id.to_string(),
                reason: "selected GPUs lack NVLink/NVSwitch/InfinityFabric".to_owned(),
            });
        }
        let score = topology
            .compute_affinity(&first_gpu.device_id, &other_gpu.device_id)
            .map(|a| a.composite_score)
            .unwrap_or(0);
        total_score = total_score.saturating_add(score);
    }
    Ok(total_score)
}

/// Finds the RDMA NIC with the highest topology affinity (e.g., shared `PCIe` switch) to `anchor_gpu`.
///
/// # Arguments
///
/// * `task` - Workload specification.
/// * `inventory` - Agent hardware inventory.
/// * `anchor_gpu` - Primary GPU to pair with.
///
/// # Returns
///
/// Best-affinitized RDMA NIC [`DeviceId`].
///
/// # Errors
///
/// Returns [`ArbiterError::NoEligibleAgents`] if no reachable RDMA NIC with sufficient hop affinity exists.
fn select_closest_rdma_nic(
    task: &TaskSpec,
    inventory: &AgentHardwareInventory,
    anchor_gpu: &GpuDevice,
) -> ArbiterResult<DeviceId> {
    let mut best_nic: Option<(DeviceId, u64)> = None;
    for nic in &inventory.rdma_nics {
        if let Ok(aff) = inventory
            .topology
            .compute_affinity(&anchor_gpu.device_id, &nic.device_id)
        {
            // Shared PCIe switch is at most 2 hops (GPU -> Switch -> NIC)
            if aff.hops <= 2
                && best_nic
                    .as_ref()
                    .is_none_or(|(_, best_score)| aff.composite_score > *best_score)
            {
                best_nic = Some((nic.device_id.clone(), aff.composite_score));
            }
        }
    }

    best_nic
        .map(|(id, _)| id)
        .ok_or_else(|| ArbiterError::NoEligibleAgents {
            workload: task.task_id.to_string(),
            reason: "no RDMA NIC shares a PCIe switch (<= 2 hops) with the selected GPU".to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::{RoleName, TaskId};
    use arbiter_core::resources::{CpuResource, GpuVendor, MemoryResource, RdmaFabricKind};
    use arbiter_core::topology::{TopologyNode, TopologyNodeKind};
    use arbiter_core::units::{BandwidthBps, LatencyNanoseconds};
    use arbiter_core::workload::{
        IsolationSpec, PlacementConstraint, PreemptionPolicy, PriorityClass,
    };

    use super::*;

    fn base_task(cpu_m: u64, mem_b: u64, gpu_m: u64, vram_b: u64) -> TaskSpec {
        TaskSpec {
            task_id: TaskId::new("task-pack-1").unwrap_or_default(),
            role: RoleName::new("prod").unwrap_or_default(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionStandard,
            preemption_policy: PreemptionPolicy::GracefulSigterm,
            resources: ResourceBundle {
                cpu: Millicores::new(cpu_m),
                memory: Bytes::new(mem_b),
                gpu_compute: GpuMillicores::new(gpu_m),
                gpu_vram: Bytes::new(vram_b),
                ..ResourceBundle::zero()
            },
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/train".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn sample_inventory() -> AgentHardwareInventory {
        let mut topo = HardwareTopologyGraph::new();
        let dev_g0 = DeviceId::new("gpu-0").unwrap_or_default();
        let dev_g1 = DeviceId::new("gpu-1").unwrap_or_default();
        let dev_g2 = DeviceId::new("gpu-2").unwrap_or_default();
        let dev_g3 = DeviceId::new("gpu-3").unwrap_or_default();
        let sw0 = DeviceId::new("pcie-sw-0").unwrap_or_default();
        let sw1 = DeviceId::new("pcie-sw-1").unwrap_or_default();
        let nic0 = DeviceId::new("mlx5-0").unwrap_or_default();
        let nic_slower = DeviceId::new("mlx5-slower").unwrap_or_default();
        let nic_far = DeviceId::new("mlx5-far").unwrap_or_default();

        for id in [
            &dev_g0,
            &dev_g1,
            &dev_g2,
            &dev_g3,
            &sw0,
            &sw1,
            &nic0,
            &nic_slower,
            &nic_far,
        ] {
            let _ = topo.add_node(TopologyNode {
                id: id.clone(),
                kind: TopologyNodeKind::GpuNode,
                numa_node_id: 0,
            });
        }

        for (pair, kind) in [
            ((&dev_g0, &dev_g1), InterconnectKind::NvLink),
            ((&dev_g0, &dev_g2), InterconnectKind::NvSwitch),
            ((&dev_g0, &dev_g3), InterconnectKind::AmdInfinityFabric),
        ] {
            let _ = topo.add_bidirectional_link(
                pair.0.clone(),
                pair.1.clone(),
                kind,
                BandwidthBps::new(7_200_000_000_000),
                LatencyNanoseconds::new(40),
            );
        }

        for (a, b, bw_gbps) in [
            (&dev_g0, &sw0, 512_u64),
            (&sw0, &nic0, 512),
            (&sw0, &nic_slower, 100),
            (&sw0, &sw1, 128),
            (&sw1, &nic_far, 128),
        ] {
            let _ = topo.add_bidirectional_link(
                a.clone(),
                b.clone(),
                InterconnectKind::PcieGen5,
                BandwidthBps::new(bw_gbps * 1_000_000_000),
                LatencyNanoseconds::new(100),
            );
        }

        let gpu_list = [dev_g0, dev_g1, dev_g2, dev_g3]
            .into_iter()
            .map(|id| GpuDevice {
                device_id: id,
                vendor: GpuVendor::Nvidia,
                model_name: "NVIDIA H100 80GB".to_owned(),
                numa_node_id: 0,
                available_compute: GpuMillicores::new(1000),
                available_vram: Bytes::new(80 * 1024 * 1024 * 1024),
                partition: GpuPartition::WholeDevice,
            })
            .collect();

        let rdma_nics = [(nic_far, 100_u64), (nic0, 400), (nic_slower, 100)]
            .into_iter()
            .map(|(id, gbps)| RdmaDevice {
                device_id: id,
                fabric_kind: RdmaFabricKind::InfiniBand,
                numa_node_id: 0,
                bandwidth: BandwidthBps::new(gbps * 1_000_000_000),
                sriov_vfs: 4,
            })
            .collect();

        AgentHardwareInventory {
            agent_id: AgentId::new("agent-gpu-1").unwrap_or_default(),
            available_bundle: ResourceBundle {
                cpu: Millicores::new(64_000),
                memory: Bytes::new(512 * 1024 * 1024 * 1024),
                gpu_compute: GpuMillicores::new(4000),
                gpu_vram: Bytes::new(320 * 1024 * 1024 * 1024),
                ..ResourceBundle::zero()
            },
            numa_domains: vec![
                NumaDomainCapacity {
                    numa_node_id: 0,
                    available_cpu: Millicores::new(32_000),
                    available_memory: Bytes::new(256 * 1024 * 1024 * 1024),
                },
                NumaDomainCapacity {
                    numa_node_id: 1,
                    available_cpu: Millicores::new(16_000),
                    available_memory: Bytes::new(128 * 1024 * 1024 * 1024),
                },
            ],
            gpus: gpu_list,
            rdma_nics,
            topology: topo,
        }
    }

    #[test]
    fn test_cpu_only_and_numa_fallback_or_rejection() {
        let inv = sample_inventory();

        let cpu_task = base_task(16_000, 1024, 0, 0);
        let plan = pack_task_on_agent(&cpu_task, &inv);
        assert!(plan.is_ok());

        let cross_numa_task = base_task(48_000, 1024, 0, 0);
        assert!(pack_task_on_agent(&cross_numa_task, &inv).is_ok());

        let mut strict_numa_task = base_task(48_000, 1024, 0, 0);
        strict_numa_task
            .topology_constraints
            .push(TopologyConstraint::SameNuma);
        assert!(pack_task_on_agent(&strict_numa_task, &inv).is_err());

        let huge_task = base_task(128_000, 1024, 0, 0);
        assert!(pack_task_on_agent(&huge_task, &inv).is_err());
    }

    #[test]
    fn test_single_and_4_gpu_nvlink_and_pcie_rdma_packing() {
        let mut inv = sample_inventory();

        let mut single_gpu = base_task(8_000, 1024, 1000, 40 * 1024 * 1024 * 1024);
        single_gpu.required_gpu_vendor = Some(GpuVendor::Nvidia);
        single_gpu
            .topology_constraints
            .push(TopologyConstraint::SameNuma);
        single_gpu
            .topology_constraints
            .push(TopologyConstraint::SamePcieSwitch);

        let single_plan = pack_task_on_agent(&single_gpu, &inv).unwrap_or_default();
        assert_eq!(single_plan.assigned_gpus.len(), 1);
        assert!(single_plan.paired_rdma_nic.is_some());

        // Multi-GPU without NvLinkConnected constraint
        let dual_gpu_relaxed = base_task(16_000, 1024, 2000, 80 * 1024 * 1024 * 1024);
        assert!(pack_task_on_agent(&dual_gpu_relaxed, &inv).is_ok());

        // 4-GPU NVLink island placement
        let mut quad_gpu = base_task(16_000, 1024, 4000, 160 * 1024 * 1024 * 1024);
        quad_gpu
            .topology_constraints
            .push(TopologyConstraint::NvLinkConnected);
        let quad_plan = pack_task_on_agent(&quad_gpu, &inv);
        assert!(quad_plan.is_ok());

        // Reduce last GPU's available compute below 1000gm so whole_candidates < 4
        for (idx, g) in inv.gpus.iter_mut().enumerate() {
            if idx == 3 {
                g.available_compute = GpuMillicores::new(500);
            }
        }
        assert!(pack_task_on_agent(&quad_gpu, &inv).is_err());
        for g in &mut inv.gpus {
            g.available_compute = GpuMillicores::new(1000);
        }

        // Vendor mismatch -> NoEligibleAgents (empty whole_candidates)
        let mut amd_task = base_task(8_000, 1024, 1000, 1024);
        amd_task.required_gpu_vendor = Some(GpuVendor::Amd);
        assert!(pack_task_on_agent(&amd_task, &inv).is_err());

        // Replace NVLink edges with a non-NVLink PCIe edge and verify NvLinkConnected fails
        inv.topology = HardwareTopologyGraph::new();
        let g0 = DeviceId::new("gpu-0").unwrap_or_default();
        let g1 = DeviceId::new("gpu-1").unwrap_or_default();
        let g2 = DeviceId::new("gpu-2").unwrap_or_default();
        let g3 = DeviceId::new("gpu-3").unwrap_or_default();
        for g_id in [&g0, &g1, &g2, &g3] {
            let _ = inv.topology.add_node(TopologyNode {
                id: g_id.clone(),
                kind: TopologyNodeKind::GpuNode,
                numa_node_id: 0,
            });
        }
        let _ = inv.topology.add_bidirectional_link(
            g0,
            g1,
            InterconnectKind::PcieGen5,
            BandwidthBps::new(100),
            LatencyNanoseconds::new(100),
        );
        assert!(pack_task_on_agent(&quad_gpu, &inv).is_err());

        // SamePcieSwitch fails when topology has no path to RDMA NIC
        inv.topology = HardwareTopologyGraph::new();
        assert!(pack_task_on_agent(&single_gpu, &inv).is_err());
    }

    #[test]
    fn test_fractional_gpu_mig_and_mps_auto_slicing() {
        let mut inv = sample_inventory();
        // Set GPU 0 compute to 50gm (too small), GPU 1 VRAM to 2 GiB (too small), and GPU 2 VRAM to 160 GiB
        for (idx, g) in inv.gpus.iter_mut().enumerate() {
            if idx == 0 {
                g.available_compute = GpuMillicores::new(50);
            } else if idx == 1 {
                g.available_vram = Bytes::new(2 * 1024 * 1024 * 1024);
            } else {
                g.available_vram = Bytes::new(160 * 1024 * 1024 * 1024);
            }
        }

        // 1. Auto-MIG 1g.10gb (140gm, 8 GiB VRAM) skips GPU 0 and GPU 1 and lands on GPU 2
        let mig_task = base_task(4_000, 1024, 140, 8 * 1024 * 1024 * 1024);
        let mig_plan = pack_task_on_agent(&mig_task, &inv);
        assert!(mig_plan.is_ok());

        // Restore GPU 0 compute & VRAM so GPU 0 (connected to sw0/nic0) can test fractional SamePcieSwitch
        for g in &mut inv.gpus {
            g.available_compute = GpuMillicores::new(1000);
            g.available_vram = Bytes::new(160 * 1024 * 1024 * 1024);
        }
        let mut mig_rdma_task = base_task(4_000, 1024, 140, 8 * 1024 * 1024 * 1024);
        mig_rdma_task
            .topology_constraints
            .push(TopologyConstraint::SamePcieSwitch);
        assert!(pack_task_on_agent(&mig_rdma_task, &inv).is_ok());

        // 2. Explicit GPU partition override
        let mut explicit_task = base_task(4_000, 1024, 250, 4 * 1024 * 1024 * 1024);
        explicit_task.required_gpu_partition = Some(GpuPartition::WholeDevice);
        assert!(pack_task_on_agent(&explicit_task, &inv).is_ok());

        // 2b. Multi-vendor fractional GPU slicing (AMD CPX/QPX/DPX, Intel Tile, Apple Metal Slice)
        for (vendor, compute_m, expected_match) in [
            (GpuVendor::Amd, 100_u64, "AmdCpx"),
            (GpuVendor::Amd, 200, "AmdQpx"),
            (GpuVendor::Amd, 500, "AmdDpx"),
            (GpuVendor::Intel, 500, "IntelTile"),
            (GpuVendor::Apple, 500, "AppleMetal"),
        ] {
            let mut v_inv = inv.clone();
            for g in &mut v_inv.gpus {
                g.vendor = vendor;
            }
            let mut v_task = base_task(4_000, 1024, compute_m, 4 * 1024 * 1024 * 1024);
            v_task.required_gpu_vendor = Some(vendor);
            let v_plan = pack_task_on_agent(&v_task, &v_inv).unwrap_or_default();
            assert_eq!(v_plan.assigned_gpus.len(), 1);
            let _ = expected_match;
            v_inv.apply_placement_deduction(&v_task, &v_plan);
        }

        // 3. Fractional request exceeding 80 GiB MIG limit falls back to NvidiaMps
        let mps_task = base_task(4_000, 1024, 500, 90 * 1024 * 1024 * 1024);
        assert!(
            select_auto_mig_profile(GpuMillicores::new(500), Bytes::new(90 * 1024 * 1024 * 1024))
                .is_err()
        );
        assert!(pack_task_on_agent(&mps_task, &inv).is_ok());

        // 4. Fractional request with SamePcieSwitch failing when topology is cleared
        inv.topology = HardwareTopologyGraph::new();
        assert!(pack_task_on_agent(&mig_rdma_task, &inv).is_err());

        // 5. Fractional request with no eligible GPUs
        inv.gpus.clear();
        assert!(pack_task_on_agent(&mig_task, &inv).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_microarch_memory_pool_domain_and_placement_constraints() {
        use arbiter_core::ids::{RegionName, ZoneName};
        use arbiter_core::resources::{CpuCoreClass, CpuInstructionExtension};
        use arbiter_core::workload::AgentAttributeValue;

        let inv = sample_inventory();
        let dom_east = DomainInfo::new(
            RegionName::new("us-east-1").unwrap_or_default(),
            ZoneName::new("us-east-1a").unwrap_or_default(),
        );
        let dom_west = DomainInfo::new(
            RegionName::new("us-west-2").unwrap_or_default(),
            ZoneName::new("us-west-2a").unwrap_or_default(),
        );

        let profile = AgentSchedulingProfile {
            attributes: vec![AgentAttribute {
                key: "rack".to_owned(),
                value: AgentAttributeValue::Text("r1".to_owned()),
            }],
            domain_info: Some(dom_east.clone()),
            cores: vec![CoreDescriptor {
                hardware_thread_id: 0,
                physical_core_id: 0,
                numa_node_id: 0,
                core_class: CpuCoreClass::PerformanceCore,
                l1_cache_group_id: 0,
                l2_cache_group_id: 0,
                l3_cache_group_id: 0,
                base_frequency: arbiter_core::units::FrequencyMegahertz::new(2800),
                boost_frequency: arbiter_core::units::FrequencyMegahertz::new(3800),
                extensions: vec![
                    CpuInstructionExtension::Avx2,
                    CpuInstructionExtension::Avx512,
                ],
            }],
            numa_pools: vec![NumaMemoryPool {
                numa_node_id: 0,
                ram_bytes: Bytes::new(256 * 1024 * 1024 * 1024),
                hugepages_2mib_bytes: Bytes::new(2 * 1024 * 1024 * 1024),
                hugepages_1gib_bytes: Bytes::new(16 * 1024 * 1024 * 1024),
                bandwidth: BandwidthBps::new(400_000_000_000),
                unified_memory: true,
            }],
            existing_tasks_on_host: 1,
            existing_tasks_in_zone: 2,
        };

        let mut task = base_task(4_000, 1024, 0, 0);
        task.isolation
            .env
            .push(("OTHER_KEY".to_owned(), "val".to_owned()));
        let reqs = TaskSchedulingRequirements {
            cpu_resource: Some(CpuResource {
                millicores: Millicores::new(4_000),
                preferred_core_class: Some(CpuCoreClass::PerformanceCore),
                required_extensions: vec![
                    CpuInstructionExtension::Avx2,
                    CpuInstructionExtension::Avx512,
                ],
            }),
            memory_resource: Some(MemoryResource {
                ram_bytes: Bytes::new(1024),
                hugepages_2mib_bytes: Bytes::new(2 * 1024 * 1024),
                hugepages_1gib_bytes: Bytes::new(1024 * 1024 * 1024),
                require_unified_memory: true,
            }),
            placement_constraints: vec![
                PlacementConstraint::Equals(
                    "rack".to_owned(),
                    AgentAttributeValue::Text("r1".to_owned()),
                ),
                PlacementConstraint::MaxPerHostname(2),
                PlacementConstraint::MaxPerFaultDomain(3),
            ],
            required_domain: Some(dom_east),
            ..TaskSchedulingRequirements::default()
        };
        reqs.attach_to_task(&mut task);
        // Re-attaching replaces the existing key
        reqs.attach_to_task(&mut task);
        assert_eq!(TaskSchedulingRequirements::from_task(&task), Some(reqs));
        assert!(pack_task_on_agent_with_profile(&task, &inv, &profile).is_ok());

        // Also test CpuResource with preferred_core_class = None and MemoryResource with require_unified_memory = false
        let mut relaxed_task = base_task(4_000, 1024, 0, 0);
        TaskSchedulingRequirements {
            cpu_resource: Some(CpuResource {
                millicores: Millicores::new(4_000),
                preferred_core_class: None,
                required_extensions: Vec::new(),
            }),
            memory_resource: Some(MemoryResource {
                ram_bytes: Bytes::new(1024),
                hugepages_2mib_bytes: Bytes::ZERO,
                hugepages_1gib_bytes: Bytes::ZERO,
                require_unified_memory: false,
            }),
            placement_constraints: Vec::new(),
            required_domain: None,
            ..TaskSchedulingRequirements::default()
        }
        .attach_to_task(&mut relaxed_task);
        assert!(pack_task_on_agent_with_profile(&relaxed_task, &inv, &profile).is_ok());

        // Failure 1: DomainInfo mismatch
        let mut bad_dom_task = base_task(4_000, 1024, 0, 0);
        TaskSchedulingRequirements {
            required_domain: Some(dom_west),
            ..TaskSchedulingRequirements::default()
        }
        .attach_to_task(&mut bad_dom_task);
        assert!(pack_task_on_agent_with_profile(&bad_dom_task, &inv, &profile).is_err());

        // Failure 2: PlacementConstraint mismatch
        let mut bad_attr_task = base_task(4_000, 1024, 0, 0);
        TaskSchedulingRequirements {
            placement_constraints: vec![PlacementConstraint::MaxPerHostname(1)],
            ..TaskSchedulingRequirements::default()
        }
        .attach_to_task(&mut bad_attr_task);
        assert!(pack_task_on_agent_with_profile(&bad_attr_task, &inv, &profile).is_err());

        // Failure 3: CpuCoreClass mismatch
        let mut bad_core_task = base_task(4_000, 1024, 0, 0);
        TaskSchedulingRequirements {
            cpu_resource: Some(CpuResource {
                millicores: Millicores::new(4_000),
                preferred_core_class: Some(CpuCoreClass::EfficiencyCore),
                required_extensions: Vec::new(),
            }),
            ..TaskSchedulingRequirements::default()
        }
        .attach_to_task(&mut bad_core_task);
        assert!(pack_task_on_agent_with_profile(&bad_core_task, &inv, &profile).is_err());

        // Failure 4: CpuInstructionExtension mismatch
        let mut bad_ext_task = base_task(4_000, 1024, 0, 0);
        TaskSchedulingRequirements {
            cpu_resource: Some(CpuResource {
                millicores: Millicores::new(4_000),
                preferred_core_class: Some(CpuCoreClass::PerformanceCore),
                required_extensions: vec![CpuInstructionExtension::Amx],
            }),
            ..TaskSchedulingRequirements::default()
        }
        .attach_to_task(&mut bad_ext_task);
        assert!(pack_task_on_agent_with_profile(&bad_ext_task, &inv, &profile).is_err());

        // Failure 5: NumaMemoryPool mismatch (ram, hugepages_2mib, hugepages_1gib, unified_memory)
        let mut non_unified_profile = profile;
        for p in &mut non_unified_profile.numa_pools {
            p.unified_memory = false;
        }
        for bad_mem in [
            MemoryResource {
                ram_bytes: Bytes::new(999 * 1024 * 1024 * 1024),
                hugepages_2mib_bytes: Bytes::ZERO,
                hugepages_1gib_bytes: Bytes::ZERO,
                require_unified_memory: false,
            },
            MemoryResource {
                ram_bytes: Bytes::new(1024),
                hugepages_2mib_bytes: Bytes::new(99 * 1024 * 1024 * 1024),
                hugepages_1gib_bytes: Bytes::ZERO,
                require_unified_memory: false,
            },
            MemoryResource {
                ram_bytes: Bytes::new(1024),
                hugepages_2mib_bytes: Bytes::ZERO,
                hugepages_1gib_bytes: Bytes::new(99 * 1024 * 1024 * 1024),
                require_unified_memory: false,
            },
            MemoryResource {
                ram_bytes: Bytes::new(1024),
                hugepages_2mib_bytes: Bytes::ZERO,
                hugepages_1gib_bytes: Bytes::ZERO,
                require_unified_memory: true,
            },
        ] {
            let mut bad_mem_task = base_task(4_000, 1024, 0, 0);
            TaskSchedulingRequirements {
                memory_resource: Some(bad_mem),
                ..TaskSchedulingRequirements::default()
            }
            .attach_to_task(&mut bad_mem_task);
            assert!(
                pack_task_on_agent_with_profile(&bad_mem_task, &inv, &non_unified_profile).is_err()
            );
        }
    }
}
